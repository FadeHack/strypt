//! PNG.
//!
//! The format screenshots arrive in, which is why it matters more than its reputation
//! suggests. A screenshot is taken on the machine that took it, by software that frequently
//! writes its own name into the file, and thumbnailers write the *full path of the original*
//! into a `tEXt` chunk — `Thumb::URI` names a home directory, and a home directory names a
//! person.
//!
//! # Chunk surgery, never re-encoding
//!
//! A PNG is an eight-byte signature followed by a flat list of chunks, each carrying its own
//! length, four-byte type, payload, and CRC (ISO/IEC 15948 §5). The picture is in `IDAT`;
//! everything identifying is in ancillary chunks around it. This handler walks that list,
//! drops the chunks that carry metadata, and copies the rest through **as raw bytes** —
//! length, type, payload, and CRC verbatim. A clean file therefore strips to a byte-identical
//! copy of itself, and idempotence follows from the design rather than from a test passing.
//!
//! Re-encoding would be indefensible here in a way it is not even for JPEG: PNG is lossless,
//! so a user who chose it chose exactness.
//!
//! # Compressed text is removed, not inflated
//!
//! `zTXt` is compressed by definition and `iTXt` is compressed when its flag says so, and
//! **this handler still contains no decompressor** (ADR-0022). Everything that decides what
//! goes is outside the compression: the keyword, the compression flag, the language tag, and
//! the translated keyword are all uncompressed (W3C PNG Third Edition §11.3.3.3, §11.3.3.4),
//! `iCCP`'s profile name is uncompressed, and `eXIf` is a raw TIFF block the shared reader in
//! [`crate::formats::exif`] handles directly. The chunk is removed whole either way.
//!
//! What is lost is report *granularity*: an XMP packet in an uncompressed `iTXt` is broken
//! down by property, and the same packet compressed is one finding. That is the same trade
//! the PDF handler already makes for a `FlateDecode`d metadata stream, and taking a
//! decompression-bomb surface to improve a listing was not worth it in either place.
//!
//! # CRCs are copied, never recomputed
//!
//! A chunk's CRC covers only its own type and payload, and no chunk that survives here is
//! ever altered — so every CRC written out is still the one that was correct on the way in,
//! and nothing in this crate needs a CRC implementation. They are not *checked* either:
//! strypt is not a decoder, and refusing a file because some earlier tool left a stale CRC
//! would help nobody. What is checked on every chunk is its declared length, because that is
//! the field a hostile file lies about.

use crate::bytes::{Reader, u32_to_usize};
use crate::detect::Format;
use crate::error::{MalformedDetail, ResourceLimit, Result, StryptError};
use crate::formats::{MetadataHandler, ParseLimits, StripOptions, Stripped, exif, xmp};
use crate::report::{
    Finding, InspectOptions, MetadataKind, MetadataReport, MetadataValue, Note, Retained,
    RetentionReason, StripReport,
};

/// Removal of metadata from PNG images.
#[derive(Debug, Clone, Copy, Default)]
pub struct PngHandler;

impl MetadataHandler for PngHandler {
    fn name(&self) -> &'static str {
        Format::Png.id()
    }

    fn format(&self) -> Format {
        Format::Png
    }

    fn inspect(&self, input: &[u8], options: &InspectOptions) -> Result<MetadataReport> {
        // Inspection runs the identical pass that stripping does and throws the output away,
        // so "everything `strip` removes is something `inspect` can see" is true by
        // construction rather than by two code paths agreeing to stay in step — which is what
        // makes the pipeline's verification pass mean anything (`docs/ARCHITECTURE.md` §3).
        let processed = process(input, options, &ParseLimits::default())?;
        Ok(MetadataReport {
            format: Format::Png,
            findings: processed.findings,
            notes: processed.notes,
        })
    }

    fn strip(&self, input: &[u8], options: &StripOptions) -> Result<Stripped> {
        let processed = process(input, &options.inspect, &options.limits)?;
        Ok(Stripped {
            report: StripReport {
                format: Format::Png,
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

/// The PNG signature. The CR-LF-EOF-LF tail exists to catch exactly the transfer corruption
/// that would otherwise truncate a file silently (ISO/IEC 15948 §5.2).
const SIGNATURE: [u8; 8] = [0x89, b'P', b'N', b'G', 0x0D, 0x0A, 0x1A, 0x0A];

/// The largest a chunk may declare itself to be: §5.3 caps a chunk's length at 2³¹−1, so the
/// high bit being set is a lying length field rather than a very large chunk.
const MAX_CHUNK_LENGTH: u32 = 0x7FFF_FFFF;

/// One chunk, and the exact bytes it occupied.
struct Chunk<'a> {
    /// The four-byte type code.
    kind: [u8; 4],
    /// The payload, without the length, type, or CRC around it.
    data: &'a [u8],
    /// The whole chunk as it appeared, including its length and CRC. Kept chunks are written
    /// out from this, which is what makes the copy exact.
    raw: &'a [u8],
}

impl Chunk<'_> {
    /// True when the chunk is ancillary: §5.4 puts that in bit 5 of the first type byte, so a
    /// lowercase first letter means "a decoder that does not understand this may drop it".
    const fn is_ancillary(&self) -> bool {
        matches!(self.kind.first(), Some(b) if b.is_ascii_lowercase())
    }
}

/// The result of one pass over a file: what was found, and what the sanitised file looks like.
struct Processed {
    findings: Vec<Finding>,
    retained: Vec<Retained>,
    notes: Vec<Note>,
    output: Vec<u8>,
}

/// Split `input` into its chunks, plus anything after the final `IEND`.
///
/// Every length in the file was chosen by whoever made it, so every one is read through
/// [`Reader`] and every failure is a typed error rather than a panic. A file that does not
/// parse is refused whole: there is no path here that returns a partial chunk list for a
/// caller to strip and write out.
fn walk<'a>(input: &'a [u8], limits: &ParseLimits) -> Result<(Vec<Chunk<'a>>, &'a [u8])> {
    let mut r = Reader::new(input);
    if r.take(SIGNATURE.len()) != Some(&SIGNATURE) {
        return Err(malformed(MalformedDetail::MissingMarker, Some(0)));
    }

    let mut chunks: Vec<Chunk<'a>> = Vec::new();
    let mut budget = limits.max_items;

    loop {
        if budget == 0 {
            return Err(StryptError::LimitExceeded {
                format: Format::Png,
                limit: ResourceLimit::ItemCount,
            });
        }
        budget = budget.saturating_sub(1);

        let start = r.position();
        if r.is_empty() {
            // The file ran out before `IEND`. Refused rather than completed: emitting a
            // repaired copy of a damaged file would hand the user something that is not what
            // they gave us, presented as a clean version of it.
            return Err(malformed(MalformedDetail::Truncated, as_offset(start)));
        }

        let declared = r
            .u32_be()
            .ok_or_else(|| malformed(MalformedDetail::Truncated, as_offset(start)))?;
        if declared > MAX_CHUNK_LENGTH {
            return Err(malformed(
                MalformedDetail::LengthOutOfRange,
                as_offset(start),
            ));
        }
        let length = u32_to_usize(declared)
            .ok_or_else(|| malformed(MalformedDetail::LengthOutOfRange, as_offset(start)))?;

        let kind: [u8; 4] = r
            .take(4)
            .and_then(|k| k.try_into().ok())
            .ok_or_else(|| malformed(MalformedDetail::Truncated, as_offset(start)))?;
        if !kind.iter().all(u8::is_ascii_alphabetic) {
            // §5.4 makes every type byte a letter. A non-letter here means the walk is no
            // longer where it thinks it is, and continuing would be slicing arbitrary bytes
            // out of a file while reporting confidently about them.
            return Err(malformed(
                MalformedDetail::UnexpectedMarker,
                as_offset(start),
            ));
        }

        let data = r
            .take(length)
            .ok_or_else(|| malformed(MalformedDetail::LengthOutOfRange, as_offset(start)))?;
        r.skip(4)
            .ok_or_else(|| malformed(MalformedDetail::Truncated, as_offset(start)))?;
        let raw = input.get(start..r.position()).unwrap_or_default();

        if chunks.is_empty() && &kind != b"IHDR" {
            // §5.6: `IHDR` is first. Anything else means this is not a PNG whose structure we
            // have understood, and a "cleaned" copy of it would be a guess.
            return Err(malformed(MalformedDetail::MissingMarker, as_offset(start)));
        }

        chunks.push(Chunk { kind, data, raw });
        if &kind == b"IEND" {
            break;
        }
    }

    Ok((chunks, r.take_rest()))
}

/// What to do with one chunk.
enum Outcome {
    /// Copy it through unchanged.
    Keep,
    /// Remove it entirely.
    Drop,
}

/// A decision about one chunk, with what to tell the user about it.
struct Decision {
    outcome: Outcome,
    findings: Vec<Finding>,
    /// Anything kept on purpose. Separate from `findings` because the verification pass
    /// requires that nothing `inspect` reports as a finding survives a strip — a chunk that is
    /// deliberately kept has to be declared, not reported as removed.
    retained: Vec<Retained>,
    notes: Vec<Note>,
}

impl Decision {
    const fn keep() -> Self {
        Self {
            outcome: Outcome::Keep,
            findings: Vec::new(),
            retained: Vec::new(),
            notes: Vec::new(),
        }
    }

    /// Copy the chunk through, and say in the report that it was a deliberate choice.
    fn kept_on_purpose(location: &'static str, reason: RetentionReason) -> Self {
        Self {
            outcome: Outcome::Keep,
            findings: Vec::new(),
            retained: vec![Retained {
                location: location.to_owned(),
                reason,
            }],
            notes: Vec::new(),
        }
    }

    fn drop_with(findings: Vec<Finding>) -> Self {
        Self {
            outcome: Outcome::Drop,
            findings,
            retained: Vec::new(),
            notes: Vec::new(),
        }
    }

    fn drop_one(kind: MetadataKind, location: impl Into<String>, bytes: u64) -> Self {
        Self::drop_with(vec![Finding::new(kind, location, bytes)])
    }
}

/// Walk `input`, decide about every chunk, and build the sanitised file.
fn process(input: &[u8], options: &InspectOptions, limits: &ParseLimits) -> Result<Processed> {
    let (chunks, trailing) = walk(input, limits)?;
    let mut out = Processed {
        findings: Vec::new(),
        retained: Vec::new(),
        notes: Vec::new(),
        output: Vec::with_capacity(input.len()),
    };
    out.output.extend_from_slice(&SIGNATURE);

    for chunk in chunks {
        let decision = decide(&chunk, options, limits);
        out.notes.extend(decision.notes);
        out.retained.extend(decision.retained);
        match decision.outcome {
            Outcome::Keep => out.output.extend_from_slice(chunk.raw),
            Outcome::Drop => out.findings.extend(decision.findings),
        }
    }

    if !trailing.is_empty() {
        // Nothing reads past `IEND`, and few users know anything can be there. It is a
        // convenient place to keep a second copy of an image whose visible version was
        // cropped.
        let kind = if trailing.starts_with(&SIGNATURE) {
            MetadataKind::Thumbnail
        } else {
            MetadataKind::Other
        };
        out.findings.push(Finding::new(
            kind,
            "trailing data after IEND",
            as_u64(trailing.len()),
        ));
    }

    Ok(out)
}

/// Decide about one chunk.
fn decide(chunk: &Chunk<'_>, options: &InspectOptions, limits: &ParseLimits) -> Decision {
    let size = as_u64(chunk.data.len());
    match &chunk.kind {
        // Three groups, all copied through byte for byte:
        //
        // - the image itself, its palette, and the two chunks that delimit the file;
        // - rendering — transparency, the colour-space description, the bit-depth hint, the
        //   background colour, the palette histogram, and the HDR mastering chunks. Every one
        //   is a fixed-shape structure that names no person, no place, and no device, and
        //   several of them change how the image looks if they go;
        // - APNG, where `fdAT` holds every frame after the first. These three *are* the
        //   payload for an animation, and dropping them would turn it silently into a still.
        b"IHDR" | b"PLTE" | b"IDAT" | b"IEND" | b"tRNS" | b"gAMA" | b"cHRM" | b"sRGB" | b"sBIT"
        | b"bKGD" | b"hIST" | b"cICP" | b"mDCV" | b"cLLI" | b"acTL" | b"fcTL" | b"fdAT" => {
            Decision::keep()
        }
        // Physical pixel dimensions — the aspect ratio and the DPI. Kept for the reason the
        // JPEG handler keeps `APP0`, and declared for the same reason: it is the chunk a
        // careful user is most likely to expect to have gone.
        b"pHYs" => Decision::kept_on_purpose("pHYs", RetentionReason::RemovalWouldAlterPayload),
        b"tEXt" => text(chunk.data, "tEXt", options),
        b"zTXt" => compressed_text(chunk.data, size),
        b"iTXt" => international_text(chunk.data, size, options),
        b"tIME" => time(chunk.data, size, options),
        b"eXIf" => exif_chunk(chunk.data, size, options, limits),
        b"iCCP" => icc_profile(chunk.data, size),
        // The one standard rendering chunk that is removed: a suggested palette's *name* is
        // arbitrary text, so the chunk is a text carrier, and the palette itself is advisory
        // data used only by decoders that cannot display the image at full depth.
        b"sPLT" => Decision::drop_one(MetadataKind::Other, "sPLT", size),
        _ if chunk.is_ancillary() => {
            // A private ancillary chunk can hold anything at all, and a scrubber that copies
            // through what it does not understand is not scrubbing.
            Decision::drop_one(MetadataKind::Other, xmp::name_of(&chunk.kind), size)
        }
        _ => {
            // An unknown *critical* chunk: whoever wrote the file marked it as needed in
            // order to interpret the image (§5.4). We cannot know what it holds or what
            // depends on it, so it stays and the report says plainly that its bytes went by
            // unexamined. A conforming decoder already refuses a file like this, so keeping
            // the chunk leaves it exactly as unreadable as it arrived — and dropping it to
            // make the file open would be deciding what the document is on the user's
            // behalf.
            Decision {
                outcome: Outcome::Keep,
                findings: Vec::new(),
                retained: Vec::new(),
                notes: vec![Note::UnparsedRegion {
                    location: xmp::name_of(&chunk.kind),
                    bytes: size,
                }],
            }
        }
    }
}

/// Keywords worth classifying by name, so that the report ranks them the way the threat model
/// does rather than filing everything under "text".
///
/// The first block is the set §11.3.3.1 registers. The rest are what real tools actually
/// write: `ImageMagick` stores whole Exif and IPTC blocks as hex text under `Raw profile type`
/// keywords, and freedesktop thumbnailers write the **full path of the original file** into
/// `Thumb::URI` — a home directory names a person.
const KEYWORDS: &[(&[u8], MetadataKind)] = &[
    (b"Author", MetadataKind::PersonalIdentity),
    (b"Copyright", MetadataKind::PersonalIdentity),
    (b"Creation Time", MetadataKind::Timestamp),
    (b"Software", MetadataKind::SoftwareFingerprint),
    (b"Source", MetadataKind::DeviceIdentity),
    (b"Title", MetadataKind::Comment),
    (b"Description", MetadataKind::Comment),
    (b"Comment", MetadataKind::Comment),
    (b"Disclaimer", MetadataKind::Comment),
    (b"Warning", MetadataKind::Comment),
    (b"Raw profile type exif", MetadataKind::DeviceIdentity),
    (b"Raw profile type APP1", MetadataKind::DeviceIdentity),
    (b"Raw profile type iptc", MetadataKind::PersonalIdentity),
    (b"Raw profile type 8bim", MetadataKind::SoftwareFingerprint),
    (b"Raw profile type icc", MetadataKind::ColourProfile),
    (b"Raw profile type xmp", MetadataKind::Other),
    (b"Thumb::URI", MetadataKind::PersonalIdentity),
    (b"Thumb::MTime", MetadataKind::Timestamp),
    (b"date:create", MetadataKind::Timestamp),
    (b"date:modify", MetadataKind::Timestamp),
    (b"date:timestamp", MetadataKind::Timestamp),
];

/// The keyword under which XMP is stored in a text chunk, per the XMP specification part 3.
const XMP_KEYWORD: &[u8] = b"XML:com.adobe.xmp";

/// What a keyword says the chunk is. Unrecognised keywords are still removed — a
/// vendor-invented key is no less identifying for being non-standard.
fn kind_of(keyword: &[u8]) -> MetadataKind {
    KEYWORDS
        .iter()
        .find(|(name, _)| *name == keyword)
        .map_or(MetadataKind::Other, |(_, kind)| *kind)
}

/// Split a chunk payload at its first NUL: the keyword, and everything after it.
///
/// A payload with no NUL at all is malformed, and is treated as all keyword and no text. It is
/// being removed either way, so refusing the file over it would cost the user their strip to
/// make a point about a chunk that is already going.
fn split_keyword(data: &[u8]) -> (&[u8], &[u8]) {
    match data.iter().position(|&b| b == 0) {
        Some(at) => (
            data.get(..at).unwrap_or_default(),
            data.get(at.saturating_add(1)..).unwrap_or_default(),
        ),
        None => (data, &[]),
    }
}

/// `tEXt`: an uncompressed keyword and its Latin-1 text.
fn text(data: &[u8], location: &'static str, options: &InspectOptions) -> Decision {
    let (keyword, value) = split_keyword(data);
    if keyword == XMP_KEYWORD {
        return Decision::drop_with(xmp::scan(value, "tEXt (XMP)", options));
    }
    Decision::drop_with(vec![
        Finding::new(kind_of(keyword), location, as_u64(value.len()))
            .with_field(xmp::name_of(keyword))
            .with_value(options, || MetadataValue::Text(xmp::name_of(value))),
    ])
}

/// `zTXt`: a keyword, a compression method, and compressed text.
///
/// The text is never inflated (ADR-0022). The keyword is uncompressed and says what the chunk
/// is, which is what the report needs; the chunk goes whole regardless.
fn compressed_text(data: &[u8], size: u64) -> Decision {
    let (keyword, _) = split_keyword(data);
    Decision::drop_with(vec![
        Finding::new(kind_of(keyword), "zTXt", size).with_field(xmp::name_of(keyword)), // No `with_value`: the value is behind the compression, and the report says so by
                                                                                        // naming the field rather than by pretending the value was not there.
    ])
}

/// `iTXt`: a keyword, a compression flag and method, a language tag, a translated keyword, and
/// UTF-8 text that is compressed only when the flag says so (§11.3.3.4).
fn international_text(data: &[u8], size: u64, options: &InspectOptions) -> Decision {
    let (keyword, rest) = split_keyword(data);
    let compressed = matches!(rest.first(), Some(1));
    // Compression flag, compression method, then two NUL-terminated strings.
    let after_flags = rest.get(2..).unwrap_or_default();
    let (_language, rest) = split_keyword(after_flags);
    let (_translated, value) = split_keyword(rest);

    if keyword == XMP_KEYWORD {
        if compressed {
            // The packet is found and removed; only the itemisation is lost. Named the way the
            // PDF handler names a `FlateDecode`d metadata stream, so the two read alike.
            return Decision::drop_with(vec![
                Finding::new(MetadataKind::Other, "iTXt (XMP)", size)
                    .with_field("Metadata (compressed)"),
            ]);
        }
        return Decision::drop_with(xmp::scan(value, "iTXt (XMP)", options));
    }

    let finding = Finding::new(kind_of(keyword), "iTXt", size).with_field(xmp::name_of(keyword));
    Decision::drop_with(vec![if compressed {
        finding
    } else {
        finding.with_value(options, || MetadataValue::Text(xmp::name_of(value)))
    }])
}

/// `tIME`: the moment the image was last changed, to the second (§11.3.5.1).
fn time(data: &[u8], size: u64, options: &InspectOptions) -> Decision {
    let mut r = Reader::new(data);
    let stamp = (|| {
        let year = r.u16_be()?;
        let (month, day) = (r.u8()?, r.u8()?);
        let (hour, minute, second) = (r.u8()?, r.u8()?, r.u8()?);
        Some(format!(
            "{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}Z"
        ))
    })();
    Decision::drop_with(vec![
        Finding::new(MetadataKind::Timestamp, "tIME", size)
            .with_field("tIME")
            .with_value(options, || match stamp {
                Some(text) => MetadataValue::Text(text),
                None => MetadataValue::Opaque { bytes: size },
            }),
    ])
}

/// `eXIf`: a raw TIFF block, byte-order mark first, with no `Exif\0\0` introducer.
fn exif_chunk(data: &[u8], size: u64, options: &InspectOptions, limits: &ParseLimits) -> Decision {
    let scanned = exif::scan(data, "eXIf", options, limits);
    let findings = if scanned.findings.is_empty() {
        // An Exif block that named nothing is still an Exif block, and it is still going.
        vec![Finding::new(MetadataKind::Other, "eXIf", size)]
    } else {
        scanned.findings
    };
    Decision {
        outcome: Outcome::Drop,
        findings,
        retained: Vec::new(),
        notes: scanned.notes,
    }
}

/// `iCCP`: an embedded ICC colour profile, named in the clear and compressed after that.
fn icc_profile(data: &[u8], size: u64) -> Decision {
    let (name, _) = split_keyword(data);
    // The profile name is the identifying part and it is not compressed: a per-device profile
    // is a fingerprint, and its name routinely carries the vendor or the model.
    Decision::drop_with(vec![
        Finding::new(MetadataKind::ColourProfile, "iCCP", size).with_field(xmp::name_of(name)),
    ])
}

/// A malformed-file error for this format.
fn malformed(detail: MalformedDetail, offset: Option<u64>) -> StryptError {
    StryptError::Malformed {
        format: Format::Png,
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

    /// The CRC-32 of a chunk's type and data, as §5.5 defines it.
    ///
    /// Present only in the tests: the handler never needs one, because it never alters a chunk
    /// it keeps. Written the slow bitwise way — this is test scaffolding, not a hot path.
    fn crc32(bytes: &[u8]) -> u32 {
        let mut crc = 0xFFFF_FFFFu32;
        for byte in bytes {
            crc ^= u32::from(*byte);
            for _ in 0..8 {
                crc = if crc & 1 == 1 {
                    (crc >> 1) ^ 0xEDB8_8320
                } else {
                    crc >> 1
                };
            }
        }
        crc ^ 0xFFFF_FFFF
    }

    fn chunk(kind: [u8; 4], data: &[u8]) -> Vec<u8> {
        let mut out = u32::try_from(data.len()).unwrap().to_be_bytes().to_vec();
        let mut body = kind.to_vec();
        body.extend_from_slice(data);
        out.extend_from_slice(&body);
        out.extend_from_slice(&crc32(&body).to_be_bytes());
        out
    }

    /// A minimal but structurally real PNG: signature, IHDR, the given chunks, IDAT, IEND.
    fn png(extra: &[Vec<u8>]) -> Vec<u8> {
        let mut ihdr = 1u32.to_be_bytes().to_vec();
        ihdr.extend_from_slice(&1u32.to_be_bytes());
        ihdr.extend_from_slice(&[8, 0, 0, 0, 0]);

        let mut out = SIGNATURE.to_vec();
        out.extend_from_slice(&chunk(*b"IHDR", &ihdr));
        for c in extra {
            out.extend_from_slice(c);
        }
        out.extend_from_slice(&chunk(*b"IDAT", b"SYNTHETIC-PIXELS"));
        out.extend_from_slice(&chunk(*b"IEND", b""));
        out
    }

    fn text_chunk(kind: [u8; 4], keyword: &str, value: &[u8]) -> Vec<u8> {
        let mut data = keyword.as_bytes().to_vec();
        data.push(0);
        data.extend_from_slice(value);
        chunk(kind, &data)
    }

    fn strip_ok(data: &[u8]) -> Stripped {
        PngHandler
            .strip(data, &StripOptions::default())
            .expect("strip failed")
    }

    fn findings(data: &[u8]) -> Vec<Finding> {
        PngHandler
            .inspect(data, &InspectOptions::names_only())
            .expect("inspect failed")
            .findings
    }

    fn contains(haystack: &[u8], needle: &[u8]) -> bool {
        haystack.windows(needle.len()).any(|w| w == needle)
    }

    #[test]
    fn the_picture_is_never_touched() {
        let input = png(&[text_chunk(*b"tEXt", "Author", b"SYNTHETIC-AUTHOR")]);
        let output = strip_ok(&input).bytes;
        assert!(
            contains(&output, b"SYNTHETIC-PIXELS"),
            "the image data did not survive byte for byte"
        );
    }

    #[test]
    fn a_clean_file_strips_to_a_byte_identical_copy() {
        // Stronger than "no findings": kept chunks are copied raw, so nothing is re-serialised
        // and there is no opportunity for a rewrite to change a file that had nothing wrong.
        let input = png(&[]);
        let stripped = strip_ok(&input);
        assert!(stripped.report.removed.is_empty());
        assert_eq!(stripped.bytes, input);
    }

    #[test]
    fn text_chunks_are_reported_by_keyword_and_removed() {
        let input = png(&[
            text_chunk(*b"tEXt", "Author", b"SYNTHETIC-AUTHOR-0001"),
            text_chunk(*b"tEXt", "Software", b"SYNTHETIC-SOFTWARE-0002"),
        ]);
        let found = findings(&input);
        assert_eq!(found[0].field.as_deref(), Some("Author"));
        assert_eq!(found[0].kind, MetadataKind::PersonalIdentity);
        assert_eq!(found[1].kind, MetadataKind::SoftwareFingerprint);

        let output = strip_ok(&input).bytes;
        assert!(!contains(&output, b"SYNTHETIC-AUTHOR-0001"));
        assert!(findings(&output).is_empty());
    }

    #[test]
    fn a_thumbnailers_source_path_is_reported_as_identifying() {
        // `Thumb::URI` holds the full path of the original file, so it names a home directory,
        // and a home directory names a person. Ranking it as "other text" would bury it.
        let input = png(&[text_chunk(
            *b"tEXt",
            "Thumb::URI",
            b"file:///home/SYNTHETIC-USER-0003/photo.png",
        )]);
        let found = findings(&input);
        assert_eq!(found[0].kind, MetadataKind::PersonalIdentity);
        assert!(!contains(&strip_ok(&input).bytes, b"SYNTHETIC-USER-0003"));
    }

    #[test]
    fn compressed_text_is_removed_without_being_inflated() {
        // The point of ADR-0022: the keyword is readable, the chunk goes, and no decompressor
        // is involved anywhere in reaching that outcome.
        let mut data = b"Comment".to_vec();
        data.push(0);
        data.push(0); // compression method: zlib
        data.extend_from_slice(&[0x78, 0x9C, 0xFF, 0xFF, 0xFF, 0xFF]);
        let input = png(&[chunk(*b"zTXt", &data)]);

        let found = findings(&input);
        assert_eq!(found[0].field.as_deref(), Some("Comment"));
        assert_eq!(found[0].value, None);
        assert!(!contains(&strip_ok(&input).bytes, b"zTXt"));
    }

    #[test]
    fn an_uncompressed_xmp_packet_is_itemised_and_a_compressed_one_is_not() {
        let packet = b"<x:xmpmeta><dc:creator>SYNTHETIC-XMP-0004</dc:creator></x:xmpmeta>";
        let mut uncompressed = b"XML:com.adobe.xmp".to_vec();
        uncompressed.extend_from_slice(&[0, 0, 0, 0, 0]); // flag 0, method, empty tags
        uncompressed.extend_from_slice(packet);
        let itemised = findings(&png(&[chunk(*b"iTXt", &uncompressed)]));
        assert_eq!(itemised[0].field.as_deref(), Some("dc:creator"));
        assert_eq!(itemised[0].kind, MetadataKind::PersonalIdentity);

        let mut compressed = b"XML:com.adobe.xmp".to_vec();
        compressed.extend_from_slice(&[0, 1, 0, 0, 0]); // flag 1: the text is deflated
        compressed.extend_from_slice(&[0x78, 0x9C, 0x01]);
        let lumped = findings(&png(&[chunk(*b"iTXt", &compressed)]));
        assert_eq!(lumped.len(), 1);
        assert_eq!(lumped[0].field.as_deref(), Some("Metadata (compressed)"));
    }

    #[test]
    fn rendering_chunks_stay_and_the_physical_size_is_declared() {
        // A handler that dropped every ancillary chunk would break transparency and colour.
        let input = png(&[
            chunk(*b"gAMA", &45455u32.to_be_bytes()),
            chunk(*b"tRNS", &[0, 0, 0]),
            chunk(*b"pHYs", &[0, 0, 0x0B, 0x13, 0, 0, 0x0B, 0x13, 1]),
        ]);
        let stripped = strip_ok(&input);
        assert!(contains(&stripped.bytes, b"gAMA"));
        assert!(contains(&stripped.bytes, b"tRNS"));
        assert!(contains(&stripped.bytes, b"pHYs"));
        assert_eq!(stripped.report.retained.len(), 1);
        assert_eq!(stripped.report.retained[0].location, "pHYs");
    }

    #[test]
    fn an_unknown_ancillary_chunk_goes_and_an_unknown_critical_one_is_declared() {
        let input = png(&[
            chunk(*b"prVW", b"SYNTHETIC-PREVIEW-0005"),
            chunk(*b"VeND", b"SYNTHETIC-CRITICAL-0006"),
        ]);
        let stripped = strip_ok(&input);
        assert!(!contains(&stripped.bytes, b"SYNTHETIC-PREVIEW-0005"));
        assert!(
            contains(&stripped.bytes, b"SYNTHETIC-CRITICAL-0006"),
            "an unknown critical chunk must be copied through, not decided about"
        );
        assert!(matches!(
            stripped.report.notes.first(),
            Some(Note::UnparsedRegion { location, .. }) if location == "VeND"
        ));
    }

    #[test]
    fn data_hidden_after_the_end_chunk_is_removed() {
        let mut input = png(&[]);
        input.extend_from_slice(b"SYNTHETIC-APPENDED-0007");
        let stripped = strip_ok(&input);
        assert!(!contains(&stripped.bytes, b"SYNTHETIC-APPENDED-0007"));
        assert_eq!(
            stripped.report.removed[0].location,
            "trailing data after IEND"
        );
    }

    #[test]
    fn a_second_image_after_the_end_chunk_is_reported_as_a_thumbnail() {
        let mut input = png(&[]);
        input.extend_from_slice(&png(&[]));
        assert_eq!(
            strip_ok(&input).report.removed[0].kind,
            MetadataKind::Thumbnail
        );
    }

    #[test]
    fn the_time_chunk_is_removed_and_its_value_withheld_by_default() {
        let input = png(&[chunk(*b"tIME", &[0x07, 0xEA, 8, 19, 12, 30, 45])]);
        let named = findings(&input);
        assert_eq!(named[0].kind, MetadataKind::Timestamp);
        assert_eq!(
            named[0].value, None,
            "a default inspection withholds values"
        );

        let with_values = PngHandler
            .inspect(&input, &InspectOptions::with_values())
            .unwrap();
        assert_eq!(
            with_values.findings[0].value,
            Some(MetadataValue::Text("2026-08-19T12:30:45Z".to_owned()))
        );
    }

    #[test]
    fn the_exif_chunk_goes_through_the_shared_reader() {
        let mut tiff = b"II\x2A\x00\x08\x00\x00\x00".to_vec();
        tiff.extend_from_slice(&1u16.to_le_bytes());
        tiff.extend_from_slice(&0x010Fu16.to_le_bytes()); // Make
        tiff.extend_from_slice(&2u16.to_le_bytes()); // ASCII
        tiff.extend_from_slice(&4u32.to_le_bytes());
        tiff.extend_from_slice(b"ACME");
        tiff.extend_from_slice(&0u32.to_le_bytes());
        let input = png(&[chunk(*b"eXIf", &tiff)]);

        let found = findings(&input);
        assert_eq!(found[0].field.as_deref(), Some("Make"));
        assert!(!contains(&strip_ok(&input).bytes, b"ACME"));
    }

    #[test]
    fn stripping_twice_changes_nothing() {
        let input = png(&[
            text_chunk(*b"tEXt", "Author", b"SYNTHETIC-AUTHOR-0001"),
            chunk(*b"tIME", &[0x07, 0xEA, 8, 19, 12, 30, 45]),
        ]);
        let once = strip_ok(&input).bytes;
        let twice = strip_ok(&once).bytes;
        assert_eq!(once, twice, "strip is not idempotent");
    }

    #[test]
    fn a_file_without_an_end_chunk_is_refused() {
        // Fail closed. Completing a damaged file would hand the user something that is not
        // what they gave us, presented as a clean version of it.
        let input = png(&[]);
        let truncated = &input[0..input.len() - 12];
        assert!(matches!(
            PngHandler.strip(truncated, &StripOptions::default()),
            Err(StryptError::Malformed { .. })
        ));
    }

    #[test]
    fn a_file_that_does_not_begin_with_the_header_chunk_is_refused() {
        let mut input = SIGNATURE.to_vec();
        input.extend_from_slice(&text_chunk(*b"tEXt", "Author", b"first"));
        input.extend_from_slice(&chunk(*b"IEND", b""));
        assert!(matches!(
            PngHandler.inspect(&input, &InspectOptions::names_only()),
            Err(StryptError::Malformed {
                detail: MalformedDetail::MissingMarker,
                ..
            })
        ));
    }

    #[test]
    fn a_length_beyond_the_end_of_the_file_is_refused_rather_than_clamped() {
        let mut input = png(&[]);
        // Overwrite the IHDR length with one that runs past the end of the file.
        input[8..12].copy_from_slice(&0x7FFF_0000u32.to_be_bytes());
        assert!(matches!(
            PngHandler.inspect(&input, &InspectOptions::names_only()),
            Err(StryptError::Malformed {
                detail: MalformedDetail::LengthOutOfRange,
                ..
            })
        ));
    }

    #[test]
    fn a_length_with_the_high_bit_set_is_refused() {
        // §5.3 caps a chunk at 2³¹−1, so this is a lying length field, not a large chunk.
        let mut input = png(&[]);
        input[8..12].copy_from_slice(&0xFFFF_FFFFu32.to_be_bytes());
        assert!(matches!(
            PngHandler.inspect(&input, &InspectOptions::names_only()),
            Err(StryptError::Malformed {
                detail: MalformedDetail::LengthOutOfRange,
                ..
            })
        ));
    }

    #[test]
    fn a_chunk_type_that_is_not_letters_is_refused() {
        let input = png(&[chunk(*b"\x00\x01\x02\x03", b"")]);
        assert!(matches!(
            PngHandler.inspect(&input, &InspectOptions::names_only()),
            Err(StryptError::Malformed {
                detail: MalformedDetail::UnexpectedMarker,
                ..
            })
        ));
    }

    #[test]
    fn truncation_at_every_length_is_refused_or_survived_but_never_panics() {
        let input = png(&[
            text_chunk(*b"tEXt", "Author", b"SYNTHETIC-AUTHOR-0001"),
            chunk(*b"tIME", &[0x07, 0xEA, 8, 19, 12, 30, 45]),
        ]);
        for n in 0..=input.len() {
            let prefix = &input[0..n];
            let _ = PngHandler.inspect(prefix, &InspectOptions::names_only());
            let _ = PngHandler.strip(prefix, &StripOptions::default());
        }
    }

    #[test]
    fn a_chunk_count_beyond_the_limit_is_refused() {
        let extra: Vec<Vec<u8>> = (0..64)
            .map(|_| text_chunk(*b"tEXt", "Comment", b"x"))
            .collect();
        let input = png(&extra);
        let options = StripOptions {
            limits: ParseLimits {
                max_items: 8,
                ..ParseLimits::default()
            },
            ..StripOptions::default()
        };
        assert!(matches!(
            PngHandler.strip(&input, &options),
            Err(StryptError::LimitExceeded { .. })
        ));
    }

    #[test]
    fn a_text_chunk_with_no_null_separator_is_removed_rather_than_refused() {
        // Malformed, and already going. Refusing the whole file over it would cost the user
        // their strip to make a point about a chunk that is on its way out.
        let input = png(&[chunk(*b"tEXt", b"SYNTHETIC-NO-SEPARATOR-0008")]);
        let stripped = strip_ok(&input);
        assert!(!contains(&stripped.bytes, b"SYNTHETIC-NO-SEPARATOR-0008"));
    }
}
