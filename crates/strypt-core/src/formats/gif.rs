//! GIF.
//!
//! The format a screen recording, a leaked chat clip, or a reaction image arrives in — and the
//! one whose metadata people are least likely to suspect exists, because a GIF looks like a toy.
//! It is not: `ImageMagick` writes whole 8BIM and IPTC blocks into GIFs as application
//! extensions, Adobe writes XMP packets into them, and a comment extension will hold whatever the
//! producing tool felt like putting there, including a filename or an author.
//!
//! # Block surgery, never re-encoding
//!
//! A GIF is a fixed header, a logical screen descriptor, an optional global colour table, and
//! then a flat sequence of blocks terminated by a single `0x3B` byte (`GIF89a` §17–§27). The
//! picture lives in image blocks; everything identifying lives in extension blocks beside them.
//! This handler walks that sequence, drops the extensions that carry metadata, and copies
//! everything else through **as raw bytes**. A clean file therefore strips to a byte-identical
//! copy of itself, and idempotence follows from the design rather than from a test passing —
//! the same property PNG has, and the opposite of TIFF, which is rebuilt because its metadata
//! *is* its structure (ADR-0033).
//!
//! The LZW-compressed image data is never decoded. Nothing here needs to know what the picture
//! looks like in order to know that a comment extension is not part of it.
//!
//! # The application extension is an allow-list, and that direction is deliberate
//!
//! An application extension declares an eleven-byte identifier and then carries arbitrary
//! payload (§26). Two of those identifiers are not metadata at all: `NETSCAPE2.0` and its older
//! spelling `ANIMEXTS1.0` carry the **loop count**, which is why an animation repeats instead of
//! playing once. Dropping them would silently change what the user's file *does* — a visible
//! payload change, which `docs/PRD.md` §8.1 forbids.
//!
//! So those two are copied through and every other application extension is removed, including
//! ones this code has never heard of. Running the rule the other way — deny a list of known-bad
//! identifiers — would carry an unknown vendor block through precisely because it was unknown,
//! which is the failure the TIFF allow-list exists to prevent and is no less a failure here.
//!
//! # A plain-text extension takes its graphic control block with it
//!
//! A graphic control extension applies to *the next graphic-rendering block* (§23), setting its
//! delay, its disposal method, and its transparent colour index. Removing a plain-text extension
//! while leaving the control block in front of it would hand that block's timing to the next
//! image instead, which is a rendering change nobody asked for. The pair is removed together.

use crate::bytes::Reader;
use crate::detect::Format;
use crate::error::{MalformedDetail, ResourceLimit, Result, StryptError};
use crate::formats::{MetadataHandler, ParseLimits, StripOptions, Stripped, xmp};
use crate::report::{
    Finding, InspectOptions, MetadataKind, MetadataReport, MetadataValue, Note, Retained,
    RetentionReason, StripReport,
};

/// Removal of metadata from GIF images.
#[derive(Debug, Clone, Copy, Default)]
pub struct GifHandler;

impl MetadataHandler for GifHandler {
    fn name(&self) -> &'static str {
        Format::Gif.id()
    }

    fn format(&self) -> Format {
        Format::Gif
    }

    fn inspect(&self, input: &[u8], options: &InspectOptions) -> Result<MetadataReport> {
        // Inspection runs the identical pass that stripping does and discards the output, so
        // "everything `strip` removes is something `inspect` can see" holds by construction
        // rather than by two code paths agreeing to stay in step — which is what makes the
        // pipeline's verification pass mean anything (`docs/ARCHITECTURE.md` §3).
        let processed = process(input, options, &ParseLimits::default())?;
        Ok(MetadataReport {
            format: Format::Gif,
            findings: processed.findings,
            notes: processed.notes,
        })
    }

    fn strip(&self, input: &[u8], options: &StripOptions) -> Result<Stripped> {
        let processed = process(input, &options.inspect, &options.limits)?;
        Ok(Stripped {
            report: StripReport {
                format: Format::Gif,
                removed: processed.findings,
                retained: processed.retained,
                notes: processed.notes,
                input_bytes: as_u64(input.len()),
                output_bytes: as_u64(processed.output.len()),
            },
            bytes: processed.output,
        })
    }
}

/// The two signatures §17 permits. `87a` predates extensions entirely; files spelling it while
/// carrying them are common, and are handled the same way rather than refused on a version
/// string no decoder enforces either.
const SIGNATURES: [&[u8; 6]; 2] = [b"GIF87a", b"GIF89a"];

/// End of the block sequence (§27).
const TRAILER: u8 = 0x3B;
/// Introduces an extension block (§23–§26).
const EXTENSION_INTRODUCER: u8 = 0x21;
/// Introduces an image descriptor (§20).
const IMAGE_SEPARATOR: u8 = 0x2C;

/// Extension labels §23–§26 define. Everything else is unrecognised and is removed.
const LABEL_PLAIN_TEXT: u8 = 0x01;
const LABEL_GRAPHIC_CONTROL: u8 = 0xF9;
const LABEL_COMMENT: u8 = 0xFE;
const LABEL_APPLICATION: u8 = 0xFF;

/// Length of the eleven-byte application identifier and authentication code (§26).
const APPLICATION_IDENTIFIER_LEN: usize = 11;

/// The application extensions that are kept, because they are rendering instructions rather than
/// metadata.
///
/// Both carry a loop count and nothing else. `NETSCAPE2.0` is what every tool writes today;
/// `ANIMEXTS1.0` is the earlier spelling of the same thing, still found in older files. Neither
/// names a person, a device, a place, or a time, and neither differs between two files that loop
/// — so there is nothing in them to identify anyone with, and removing them would stop an
/// animation looping.
const LOOP_EXTENSIONS: [&[u8; APPLICATION_IDENTIFIER_LEN]; 2] = [b"NETSCAPE2.0", b"ANIMEXTS1.0"];

/// The identifier under which XMP is carried, per the XMP specification part 3 §1.1.2.
///
/// Its payload is **not** really a sub-block chain: the packet's own bytes are laid down raw and
/// a 258-byte magic trailer makes the length bytes fall where the chain needs them. Walking it as
/// an ordinary chain still finds the end, which is all this handler needs — and scanning the raw
/// span still finds the property names, because they are intact in those bytes.
const XMP_IDENTIFIER: &[u8] = b"XMP DataXMP";

/// Application identifiers worth classifying by name, so the report ranks them the way the threat
/// model does rather than filing everything under "an application extension".
///
/// These are what real tools actually write. `ImageMagick` puts whole Photoshop 8BIM and IPTC
/// blocks in here — the IPTC one carries a by-line, which is a person's name.
const APPLICATION_KINDS: &[(&[u8], MetadataKind)] = &[
    (b"ICCRGBG1012", MetadataKind::ColourProfile),
    (b"MGK8BIM0000", MetadataKind::SoftwareFingerprint),
    (b"MGKIPTC0000", MetadataKind::PersonalIdentity),
    (b"ImageMagick", MetadataKind::SoftwareFingerprint),
    (b"Adobe Gif", MetadataKind::SoftwareFingerprint),
];

/// One block, and the exact bytes it occupied.
struct Block<'a> {
    kind: BlockKind,
    /// The sub-block chain's raw span, without the terminating zero byte. Empty for an image
    /// block, whose payload this handler never looks inside.
    body: &'a [u8],
    /// The first sub-block's contents, which is where an extension puts its fixed-shape fields —
    /// for an application extension, the eleven-byte identifier.
    head: &'a [u8],
    /// The whole block as it appeared. Kept blocks are written out from this, which is what makes
    /// the copy exact.
    raw: &'a [u8],
}

/// What sort of block it is.
#[derive(Clone, Copy, PartialEq, Eq)]
enum BlockKind {
    /// An extension, with its label byte.
    Extension(u8),
    /// An image descriptor and its compressed data.
    Image,
}

/// The result of one pass over a file: what was found, and what the sanitised file looks like.
struct Processed {
    findings: Vec<Finding>,
    retained: Vec<Retained>,
    notes: Vec<Note>,
    output: Vec<u8>,
}

/// Split `input` into its fixed prefix, its blocks, and anything after the trailer.
///
/// Every length in the file was chosen by whoever made it, so every one is read through
/// [`Reader`] and every failure is a typed error rather than a panic. A file that does not parse
/// is refused whole: there is no path here that returns a partial block list for a caller to
/// strip and write out.
fn walk<'a>(input: &'a [u8], limits: &ParseLimits) -> Result<(&'a [u8], Vec<Block<'a>>, &'a [u8])> {
    let mut r = Reader::new(input);
    let signature = r
        .take(6)
        .ok_or_else(|| malformed(MalformedDetail::Truncated, Some(0)))?;
    if !SIGNATURES.iter().any(|candidate| *candidate == signature) {
        return Err(malformed(MalformedDetail::MissingMarker, Some(0)));
    }

    // Logical screen descriptor: width, height, a packed field, the background colour index, and
    // the pixel aspect ratio (§18). Seven bytes, always present.
    let descriptor = r
        .take(7)
        .ok_or_else(|| malformed(MalformedDetail::Truncated, as_offset(6)))?;
    // Bit 7 of the packed field says a global colour table follows; bits 0–2 give its size as
    // 3 × 2^(N+1) bytes (§18). The table is part of the picture, not of its metadata.
    let packed = descriptor.get(4).copied().unwrap_or_default();
    if packed & 0x80 != 0 {
        let entries = colour_table_bytes(packed);
        r.skip(entries)
            .ok_or_else(|| malformed(MalformedDetail::LengthOutOfRange, as_offset(13)))?;
    }
    let prefix = input.get(0..r.position()).unwrap_or_default();

    let mut blocks: Vec<Block<'a>> = Vec::new();
    let mut budget = limits.max_items;

    loop {
        let start = r.position();
        let introducer = r
            .u8()
            .ok_or_else(|| malformed(MalformedDetail::Truncated, as_offset(start)))?;
        if introducer == TRAILER {
            break;
        }
        spend(&mut budget)?;

        let (kind, head, body) = match introducer {
            EXTENSION_INTRODUCER => {
                let label = r
                    .u8()
                    .ok_or_else(|| malformed(MalformedDetail::Truncated, as_offset(start)))?;
                let (head, body) = sub_blocks(&mut r, input, &mut budget, start)?;
                (BlockKind::Extension(label), head, body)
            }
            IMAGE_SEPARATOR => {
                // Image descriptor: position, size, and a packed field (§20).
                let descriptor = r
                    .take(9)
                    .ok_or_else(|| malformed(MalformedDetail::Truncated, as_offset(start)))?;
                let packed = descriptor.get(8).copied().unwrap_or_default();
                if packed & 0x80 != 0 {
                    // A local colour table, sized the same way the global one is (§20).
                    r.skip(colour_table_bytes(packed)).ok_or_else(|| {
                        malformed(MalformedDetail::LengthOutOfRange, as_offset(start))
                    })?;
                }
                // The LZW minimum code size, then the compressed data as a sub-block chain
                // (§22). Never decoded: nothing here needs to know what the picture shows.
                r.skip(1)
                    .ok_or_else(|| malformed(MalformedDetail::Truncated, as_offset(start)))?;
                let _ = sub_blocks(&mut r, input, &mut budget, start)?;
                (BlockKind::Image, &[][..], &[][..])
            }
            _ => {
                // §17 admits exactly three things here. Anything else means the walk is no longer
                // where it thinks it is, and continuing would be slicing arbitrary bytes out of a
                // file while reporting confidently about them.
                return Err(malformed(
                    MalformedDetail::UnexpectedMarker,
                    as_offset(start),
                ));
            }
        };

        blocks.push(Block {
            kind,
            body,
            head,
            raw: input.get(start..r.position()).unwrap_or_default(),
        });
    }

    Ok((prefix, blocks, r.take_rest()))
}

/// Size of a colour table in bytes, from the packed field that declares it: 3 × 2^(N+1) (§18).
///
/// `N` is three bits, so the largest table is 768 bytes and this cannot overflow.
fn colour_table_bytes(packed: u8) -> usize {
    let n = u32::from(packed & 0b0000_0111);
    3usize.saturating_mul(1usize << n.saturating_add(1))
}

/// Walk a sub-block chain: a length byte, that many bytes, repeated until a zero length (§15).
///
/// Returns the first sub-block's contents and the chain's whole span excluding the terminator.
/// Each sub-block is charged against the item budget, so a file that is nothing but a very long
/// chain is bounded like everything else.
fn sub_blocks<'a>(
    r: &mut Reader<'a>,
    input: &'a [u8],
    budget: &mut u32,
    block_start: usize,
) -> Result<(&'a [u8], &'a [u8])> {
    let span_start = r.position();
    let mut head: &[u8] = &[];
    loop {
        spend(budget)?;
        let at = r.position();
        let length = r
            .u8()
            .ok_or_else(|| malformed(MalformedDetail::Truncated, as_offset(block_start)))?;
        if length == 0 {
            let span = input.get(span_start..at).unwrap_or_default();
            return Ok((head, span));
        }
        let data = r
            .take(usize::from(length))
            .ok_or_else(|| malformed(MalformedDetail::LengthOutOfRange, as_offset(at)))?;
        if head.is_empty() {
            head = data;
        }
    }
}

/// Charge one structural item against the budget.
fn spend(budget: &mut u32) -> Result<()> {
    if *budget == 0 {
        return Err(StryptError::LimitExceeded {
            format: Format::Gif,
            limit: ResourceLimit::ItemCount,
        });
    }
    *budget = budget.saturating_sub(1);
    Ok(())
}

/// What to do with one block.
enum Outcome {
    /// Copy it through unchanged.
    Keep,
    /// Remove it entirely.
    Drop,
}

/// A decision about one block, with what to tell the user about it.
struct Decision {
    outcome: Outcome,
    findings: Vec<Finding>,
    /// Anything kept on purpose. Separate from `findings` because the verification pass requires
    /// that nothing `inspect` reports as a finding survives a strip — a block that is deliberately
    /// kept has to be declared, not reported as removed.
    retained: Vec<Retained>,
}

impl Decision {
    const fn keep() -> Self {
        Self {
            outcome: Outcome::Keep,
            findings: Vec::new(),
            retained: Vec::new(),
        }
    }

    /// Copy the block through, and say in the report that it was a deliberate choice.
    fn kept_on_purpose(location: &'static str, reason: RetentionReason) -> Self {
        Self {
            outcome: Outcome::Keep,
            findings: Vec::new(),
            retained: vec![Retained {
                location: location.to_owned(),
                reason,
            }],
        }
    }

    fn drop_with(findings: Vec<Finding>) -> Self {
        Self {
            outcome: Outcome::Drop,
            findings,
            retained: Vec::new(),
        }
    }

    /// Removed, with nothing to report about it: the graphic control block that belonged to a
    /// plain-text extension going out with it. It is not metadata, so it is not a finding; it
    /// cannot stay, because it would retime the next image.
    const fn drop_silently() -> Self {
        Self {
            outcome: Outcome::Drop,
            findings: Vec::new(),
            retained: Vec::new(),
        }
    }
}

/// Walk `input`, decide about every block, and build the sanitised file.
fn process(input: &[u8], options: &InspectOptions, limits: &ParseLimits) -> Result<Processed> {
    let (prefix, blocks, trailing) = walk(input, limits)?;
    let mut out = Processed {
        findings: Vec::new(),
        retained: Vec::new(),
        notes: Vec::new(),
        output: Vec::with_capacity(input.len()),
    };
    out.output.extend_from_slice(prefix);

    for (index, block) in blocks.iter().enumerate() {
        let next = blocks.get(index.saturating_add(1));
        let decision = decide(block, next, options);
        out.retained.extend(decision.retained);
        match decision.outcome {
            Outcome::Keep => out.output.extend_from_slice(block.raw),
            Outcome::Drop => out.findings.extend(decision.findings),
        }
    }
    out.output.push(TRAILER);

    if !trailing.is_empty() {
        // Nothing reads past the trailer, and few users know anything can be there. It is a
        // convenient place to keep a second copy of an image whose visible version was cropped.
        let kind = if SIGNATURES
            .iter()
            .any(|signature| trailing.starts_with(signature.as_slice()))
        {
            MetadataKind::Thumbnail
        } else {
            MetadataKind::Other
        };
        out.findings.push(Finding::new(
            kind,
            "trailing data after the trailer",
            as_u64(trailing.len()),
        ));
    }

    Ok(out)
}

/// Decide about one block. `next` is the block that follows it, which a graphic control extension
/// needs in order to know what it is controlling.
fn decide(block: &Block<'_>, next: Option<&Block<'_>>, options: &InspectOptions) -> Decision {
    let size = as_u64(block.body.len());
    match block.kind {
        BlockKind::Image => Decision::keep(),
        BlockKind::Extension(LABEL_GRAPHIC_CONTROL) => {
            // Delay, disposal method, and transparent colour index: rendering, not identity. It
            // goes only when the graphic it controls goes (§23).
            if matches!(
                next.map(|b| b.kind),
                Some(BlockKind::Extension(LABEL_PLAIN_TEXT))
            ) {
                return Decision::drop_silently();
            }
            Decision::keep()
        }
        BlockKind::Extension(LABEL_COMMENT) => Decision::drop_with(vec![
            Finding::new(MetadataKind::Comment, "Comment Extension", size)
                .with_field("Comment")
                .with_value(options, || MetadataValue::Text(xmp::name_of(block.body))),
        ]),
        BlockKind::Extension(LABEL_PLAIN_TEXT) => Decision::drop_with(vec![
            Finding::new(MetadataKind::Comment, "Plain Text Extension", size)
                .with_field("PlainText"),
        ]),
        BlockKind::Extension(LABEL_APPLICATION) => application(block, size, options),
        BlockKind::Extension(label) => {
            // §23–§26 define four labels and no more. A block under any other label was put there
            // by something whose intentions this code cannot know, and a scrubber that copies
            // through what it does not understand is not scrubbing.
            Decision::drop_with(vec![Finding::new(
                MetadataKind::Other,
                format!("Extension 0x{label:02X}"),
                size,
            )])
        }
    }
}

/// An application extension: eleven bytes of identifier, then whatever that application wanted.
fn application(block: &Block<'_>, size: u64, options: &InspectOptions) -> Decision {
    let identifier = block
        .head
        .get(0..APPLICATION_IDENTIFIER_LEN)
        .unwrap_or(block.head);

    if LOOP_EXTENSIONS
        .iter()
        .any(|candidate| candidate.as_slice() == identifier)
    {
        // The loop count. See this module's header for why an allow-list of exactly two entries
        // is the right shape here.
        return Decision::kept_on_purpose(
            "Application Extension (loop count)",
            RetentionReason::RemovalWouldAlterPayload,
        );
    }

    if identifier == XMP_IDENTIFIER {
        return Decision::drop_with(xmp::scan(
            block.body,
            "Application Extension (XMP)",
            options,
        ));
    }

    let kind = APPLICATION_KINDS
        .iter()
        .find(|(candidate, _)| *candidate == identifier)
        .map_or(MetadataKind::Other, |(_, kind)| *kind);
    Decision::drop_with(vec![
        Finding::new(kind, "Application Extension", size).with_field(xmp::name_of(identifier)),
    ])
}

/// A malformed-file error for this format.
fn malformed(detail: MalformedDetail, offset: Option<u64>) -> StryptError {
    StryptError::Malformed {
        format: Format::Gif,
        offset,
        detail,
    }
}

/// A byte position as a reportable offset.
fn as_offset(position: usize) -> Option<u64> {
    u64::try_from(position).ok()
}

/// Widen a length for reporting. Saturating: a report field is not worth failing a strip over.
fn as_u64(value: usize) -> u64 {
    u64::try_from(value).unwrap_or(u64::MAX)
}

#[cfg(test)]
mod tests {
    // Test code is never reachable from untrusted bytes, which is the boundary the
    // panic-freedom lints exist to police (ADR-0006).
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::indexing_slicing,
        clippy::arithmetic_side_effects
    )]

    use super::*;

    /// A sub-block chain: 255 bytes at a time, then the terminating zero (§15).
    fn chain(payload: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        for part in payload.chunks(255) {
            out.push(u8::try_from(part.len()).unwrap());
            out.extend_from_slice(part);
        }
        out.push(0);
        out
    }

    fn extension(label: u8, payload: &[u8]) -> Vec<u8> {
        let mut out = vec![EXTENSION_INTRODUCER, label];
        out.extend_from_slice(&chain(payload));
        out
    }

    /// An application extension: the eleven-byte identifier as its own sub-block, then the data.
    fn application_extension(identifier: &[u8], data: &[u8]) -> Vec<u8> {
        let mut out = vec![EXTENSION_INTRODUCER, LABEL_APPLICATION, 11];
        out.extend_from_slice(identifier);
        out.extend_from_slice(&chain(data));
        out
    }

    /// A one-pixel image block: descriptor, LZW minimum code size, and its data.
    fn image() -> Vec<u8> {
        let mut out = vec![IMAGE_SEPARATOR];
        out.extend_from_slice(&[0, 0, 0, 0, 1, 0, 1, 0, 0]);
        out.push(2);
        out.extend_from_slice(&chain(b"SYNTHETIC-PIXELS"));
        out
    }

    /// A graphic control extension: four bytes of disposal, delay, and transparency (§23).
    fn graphic_control() -> Vec<u8> {
        extension(LABEL_GRAPHIC_CONTROL, &[0x04, 0x0A, 0x00, 0x00])
    }

    /// Header, logical screen descriptor without a colour table, the given blocks, and the
    /// trailer.
    fn gif(blocks: &[Vec<u8>]) -> Vec<u8> {
        let mut out = b"GIF89a".to_vec();
        out.extend_from_slice(&[1, 0, 1, 0, 0x00, 0, 0]);
        for block in blocks {
            out.extend_from_slice(block);
        }
        out.push(TRAILER);
        out
    }

    fn strip_ok(data: &[u8]) -> Stripped {
        GifHandler
            .strip(data, &StripOptions::default())
            .expect("strip failed")
    }

    fn findings(data: &[u8]) -> Vec<Finding> {
        GifHandler
            .inspect(data, &InspectOptions::names_only())
            .expect("inspect failed")
            .findings
    }

    fn contains(haystack: &[u8], needle: &[u8]) -> bool {
        haystack.windows(needle.len()).any(|w| w == needle)
    }

    #[test]
    fn the_picture_is_never_touched() {
        let input = gif(&[extension(LABEL_COMMENT, b"SYNTHETIC-COMMENT-0001"), image()]);
        let output = strip_ok(&input).bytes;
        assert!(
            contains(&output, b"SYNTHETIC-PIXELS"),
            "the compressed image data did not survive byte for byte"
        );
    }

    #[test]
    fn a_clean_file_strips_to_a_byte_identical_copy() {
        // Stronger than "no findings": kept blocks are copied raw, so nothing is re-serialised
        // and a file that had nothing wrong with it comes back unchanged. TIFF cannot make this
        // promise (ADR-0033); a block-list format can, and so it must.
        let input = gif(&[image()]);
        let stripped = strip_ok(&input);
        assert!(stripped.report.removed.is_empty());
        assert_eq!(stripped.bytes, input);
    }

    #[test]
    fn a_global_colour_table_is_carried_across() {
        // The table is the picture's palette. Losing it would leave the image undecodable, which
        // is the failure direction the TIFF allow-list has to watch for as well.
        let mut input = b"GIF89a".to_vec();
        input.extend_from_slice(&[1, 0, 1, 0, 0x80, 0, 0]); // global table, two entries
        input.extend_from_slice(&[0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]);
        input.extend_from_slice(&extension(LABEL_COMMENT, b"SYNTHETIC-COMMENT-0002"));
        input.extend_from_slice(&image());
        input.push(TRAILER);

        let output = strip_ok(&input).bytes;
        assert!(contains(&output, &[0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]));
        assert!(!contains(&output, b"SYNTHETIC-COMMENT-0002"));
    }

    #[test]
    fn a_comment_is_reported_and_removed_and_its_text_withheld_by_default() {
        let input = gif(&[extension(LABEL_COMMENT, b"SYNTHETIC-COMMENT-0003"), image()]);
        let found = findings(&input);
        assert_eq!(found[0].kind, MetadataKind::Comment);
        assert_eq!(found[0].field.as_deref(), Some("Comment"));
        assert_eq!(
            found[0].value, None,
            "a default inspection withholds values"
        );

        let with_values = GifHandler
            .inspect(&input, &InspectOptions::with_values())
            .unwrap();
        assert_eq!(
            with_values.findings[0].value,
            Some(MetadataValue::Text("SYNTHETIC-COMMENT-0003".to_owned()))
        );
        assert!(!contains(
            &strip_ok(&input).bytes,
            b"SYNTHETIC-COMMENT-0003"
        ));
    }

    #[test]
    fn the_loop_extension_survives_and_says_so() {
        // The decision this handler turns on: a looping animation must still loop. The block
        // carries a loop count and nothing else, so there is nothing in it to identify anyone
        // with — and removing it would change what the user's file does.
        let input = gif(&[
            application_extension(b"NETSCAPE2.0", &[0x01, 0x00, 0x00]),
            image(),
        ]);
        let stripped = strip_ok(&input);
        assert!(contains(&stripped.bytes, b"NETSCAPE2.0"));
        assert!(stripped.report.removed.is_empty());
        assert_eq!(
            stripped.report.retained[0].location,
            "Application Extension (loop count)"
        );
    }

    #[test]
    fn the_older_loop_spelling_survives_too() {
        let input = gif(&[
            application_extension(b"ANIMEXTS1.0", &[0x01, 0x00, 0x00]),
            image(),
        ]);
        assert!(contains(&strip_ok(&input).bytes, b"ANIMEXTS1.0"));
    }

    #[test]
    fn an_unknown_application_extension_does_not_survive_by_being_unknown() {
        // The allow-list's direction, and the reason for it. Under a deny-list a vendor block
        // nobody has a name for survives precisely because nothing recognised it.
        let input = gif(&[
            application_extension(b"VENDORX1.0\0", b"SYNTHETIC-VENDOR-0004"),
            image(),
        ]);
        let found = findings(&input);
        assert_eq!(found[0].kind, MetadataKind::Other);
        assert_eq!(found[0].location, "Application Extension");
        assert!(!contains(&strip_ok(&input).bytes, b"SYNTHETIC-VENDOR-0004"));
    }

    #[test]
    fn an_imagemagick_iptc_block_is_ranked_as_naming_a_person() {
        // `MGKIPTC0000` carries an IPTC record, and its by-line field is somebody's name.
        let input = gif(&[
            application_extension(b"MGKIPTC0000", b"\x1c\x02\x50SYNTHETIC-BYLINE-0005"),
            image(),
        ]);
        assert_eq!(findings(&input)[0].kind, MetadataKind::PersonalIdentity);
        assert!(!contains(&strip_ok(&input).bytes, b"SYNTHETIC-BYLINE-0005"));
    }

    #[test]
    fn an_xmp_packet_is_itemised_by_property() {
        // XMP in a GIF is laid down raw with a magic trailer that makes the packet's own bytes
        // serve as sub-block lengths (XMP part 3 §1.1.2). Scanning the raw span still finds the
        // property names, because they are intact in those bytes.
        let mut packet = b"<x:xmpmeta><dc:creator>SYNTHETIC-XMP-0006</dc:creator>".to_vec();
        packet.extend_from_slice(b"<xmp:CreatorTool>SYNTHETIC-TOOL</xmp:CreatorTool></x:xmpmeta>");
        let input = gif(&[application_extension(b"XMP DataXMP", &packet), image()]);

        let fields: Vec<String> = findings(&input)
            .into_iter()
            .filter_map(|f| f.field)
            .collect();
        assert!(fields.iter().any(|f| f == "dc:creator"));
        assert!(fields.iter().any(|f| f == "xmp:CreatorTool"));
        assert!(!contains(&strip_ok(&input).bytes, b"SYNTHETIC-XMP-0006"));
    }

    #[test]
    fn a_graphic_control_block_stays_with_its_image_and_goes_with_its_plain_text() {
        // §23: the block applies to whatever graphic follows it. Leaving one in front of an image
        // it was never meant for would hand that image somebody else's delay and transparency.
        let kept = gif(&[graphic_control(), image()]);
        assert_eq!(strip_ok(&kept).bytes, kept);

        let mut plain_text = vec![EXTENSION_INTRODUCER, LABEL_PLAIN_TEXT, 12];
        plain_text.extend_from_slice(&[0; 12]);
        plain_text.extend_from_slice(&chain(b"SYNTHETIC-PLAINTEXT-0007"));
        let input = gif(&[graphic_control(), plain_text, image()]);

        let stripped = strip_ok(&input);
        assert!(!contains(&stripped.bytes, b"SYNTHETIC-PLAINTEXT-0007"));
        assert_eq!(
            stripped.bytes,
            gif(&[image()]),
            "the orphaned graphic control block was left behind"
        );
        assert_eq!(stripped.report.removed.len(), 1);
        assert_eq!(stripped.report.removed[0].location, "Plain Text Extension");
    }

    #[test]
    fn an_extension_under_an_undefined_label_is_removed() {
        let input = gif(&[extension(0x42, b"SYNTHETIC-UNKNOWN-0008"), image()]);
        let found = findings(&input);
        assert_eq!(found[0].location, "Extension 0x42");
        assert!(!contains(
            &strip_ok(&input).bytes,
            b"SYNTHETIC-UNKNOWN-0008"
        ));
    }

    #[test]
    fn data_hidden_after_the_trailer_is_removed() {
        let mut input = gif(&[image()]);
        input.extend_from_slice(b"SYNTHETIC-APPENDED-0009");
        let stripped = strip_ok(&input);
        assert!(!contains(&stripped.bytes, b"SYNTHETIC-APPENDED-0009"));
        assert_eq!(
            stripped.report.removed[0].location,
            "trailing data after the trailer"
        );
    }

    #[test]
    fn a_second_image_after_the_trailer_is_reported_as_a_thumbnail() {
        let mut input = gif(&[image()]);
        input.extend_from_slice(&gif(&[image()]));
        assert_eq!(
            strip_ok(&input).report.removed[0].kind,
            MetadataKind::Thumbnail
        );
    }

    #[test]
    fn stripping_twice_changes_nothing() {
        let input = gif(&[
            extension(LABEL_COMMENT, b"SYNTHETIC-COMMENT-0010"),
            application_extension(b"NETSCAPE2.0", &[0x01, 0x00, 0x00]),
            graphic_control(),
            image(),
        ]);
        let once = strip_ok(&input).bytes;
        let twice = strip_ok(&once).bytes;
        assert_eq!(once, twice, "strip is not idempotent");
    }

    #[test]
    fn a_file_without_a_trailer_is_refused() {
        // Fail closed. Completing a damaged file would hand the user something that is not what
        // they gave us, presented as a clean version of it.
        let input = gif(&[image()]);
        let truncated = &input[0..input.len() - 1];
        assert!(matches!(
            GifHandler.strip(truncated, &StripOptions::default()),
            Err(StryptError::Malformed {
                detail: MalformedDetail::Truncated,
                ..
            })
        ));
    }

    #[test]
    fn a_block_introducer_the_format_does_not_define_is_refused() {
        let input = gif(&[vec![0x99, 0x00]]);
        assert!(matches!(
            GifHandler.inspect(&input, &InspectOptions::names_only()),
            Err(StryptError::Malformed {
                detail: MalformedDetail::UnexpectedMarker,
                ..
            })
        ));
    }

    #[test]
    fn a_sub_block_length_running_past_the_end_of_the_file_is_refused() {
        let mut input = gif(&[extension(LABEL_COMMENT, b"short"), image()]);
        // The comment's first length byte sits directly after the introducer and label.
        let at = 13 + 2;
        input[at] = 0xFF;
        assert!(matches!(
            GifHandler.inspect(&input, &InspectOptions::names_only()),
            Err(StryptError::Malformed {
                detail: MalformedDetail::LengthOutOfRange,
                ..
            })
        ));
    }

    #[test]
    fn a_header_that_is_not_a_gif_signature_is_refused() {
        assert!(matches!(
            GifHandler.inspect(
                b"GIF88a\x01\x00\x01\x00\x00\x00\x00\x3B",
                &InspectOptions::names_only()
            ),
            Err(StryptError::Malformed {
                detail: MalformedDetail::MissingMarker,
                ..
            })
        ));
    }

    #[test]
    fn a_block_count_beyond_the_limit_is_refused() {
        let mut blocks: Vec<Vec<u8>> = (0..64).map(|_| extension(LABEL_COMMENT, b"x")).collect();
        blocks.push(image());
        let input = gif(&blocks);
        let options = StripOptions {
            limits: ParseLimits {
                max_items: 8,
                ..ParseLimits::default()
            },
            ..StripOptions::default()
        };
        assert!(matches!(
            GifHandler.strip(&input, &options),
            Err(StryptError::LimitExceeded { .. })
        ));
    }

    #[test]
    fn truncation_at_every_length_is_refused_or_survived_but_never_panics() {
        let input = gif(&[
            extension(LABEL_COMMENT, b"SYNTHETIC-COMMENT-0011"),
            application_extension(b"XMP DataXMP", b"<x:xmpmeta><dc:creator>x</dc:creator>"),
            graphic_control(),
            image(),
        ]);
        for n in 0..=input.len() {
            let prefix = &input[0..n];
            let _ = GifHandler.inspect(prefix, &InspectOptions::names_only());
            let _ = GifHandler.strip(prefix, &StripOptions::default());
        }
    }
}
