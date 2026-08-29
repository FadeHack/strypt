//! JPEG XL, in both of its spellings: a bare codestream and an ISO-BMFF container.
//!
//! The fifth tranche of Phase 2's third group (ADR-0032), and **ADR-0036 is required reading
//! before touching it.**
//!
//! # The same container as HEIF, and the opposite conclusion
//!
//! ADR-0034 rebuilds a HEIF because its Exif and XMP are *items* located by `iloc` as absolute
//! file offsets, so removing one moves every surviving one. JPEG XL spells the same box grammar
//! and needs none of that: ISO/IEC 18181-2 puts Exif, XMP and JUMBF in top-level boxes of their
//! own, and no box's contents are addressed by a file offset. So this handler edits by deletion —
//! output is the input's bytes with whole boxes cut out — and a clean file comes back
//! byte-identical, as GIF and SVG do.
//!
//! # What is removed, and what refuses the file
//!
//! `Exif`, `xml ` (XMP), `jumb` (JUMBF, which is where C2PA provenance arrives), `brob`, `jbrd`,
//! `jxli`, `free` and `skip` are deleted. Everything reaching the output does so from an
//! allow-list — signature, `ftyp`, `jxll`, `jxlc`, `jxlp` — so an unknown top-level box refuses
//! the file rather than surviving by going unrecognised (ADR-0033's direction, ADR-0035's rule).
//!
//! **`brob` is dropped without being decompressed**, which is why no Brotli decompressor is in
//! this tree: removal does not need to read what is being removed (ADR-0022 made the same
//! argument for PNG's compressed text chunks).
//!
//! **`jbrd` is dropped and the cost is declared.** It holds the original JPEG's marker segments
//! verbatim, so it is a copy of that file's headers; deleting it means the picture still decodes
//! identically but bit-exact JPEG reconstruction stops working.
//!
//! # The codestream is never entered
//!
//! Not in either spelling. A bare codestream has no box layer, so it is reported clean and
//! returned untouched — but its `ImageMetadata` carries an ICC profile, whose description and
//! manufacturer fields name a device or an application, and may carry a preview frame. Both are
//! entropy-coded inside the image data and out of reach without a decoder. Every report says so,
//! and `docs/THREAT_MODEL.md` §7.12 says it at length.

use crate::bytes::Reader;
use crate::container::bmff::{self, Box as Bmff, BoxType, WalkError};
use crate::detect::Format;
use crate::error::{MalformedDetail, Result, StryptError, UnsupportedKind};
use crate::formats::{MetadataHandler, ParseLimits, StripOptions, Stripped, exif, xmp};
use crate::report::{
    Finding, InspectOptions, MetadataKind, MetadataReport, MetadataValue, Note, StripReport,
};

/// Removal of metadata from JPEG XL images.
#[derive(Debug, Clone, Copy, Default)]
pub struct JxlHandler;

impl MetadataHandler for JxlHandler {
    fn name(&self) -> &'static str {
        Format::Jxl.id()
    }

    fn format(&self) -> Format {
        Format::Jxl
    }

    fn inspect(&self, input: &[u8], options: &InspectOptions) -> Result<MetadataReport> {
        // One pass serves both entry points, with the output discarded here, so nothing `strip`
        // removes can be invisible to `inspect` (`docs/ARCHITECTURE.md` §3).
        let processed = process(input, options, &ParseLimits::default())?;
        Ok(MetadataReport {
            format: Format::Jxl,
            findings: processed.findings,
            notes: processed.notes,
        })
    }

    fn strip(&self, input: &[u8], options: &StripOptions) -> Result<Stripped> {
        let processed = process(input, &options.inspect, &options.limits)?;
        Ok(Stripped {
            report: StripReport {
                format: Format::Jxl,
                removed: processed.findings,
                retained: Vec::new(),
                notes: processed.notes,
                input_bytes: as_u64(input.len()),
                output_bytes: as_u64(processed.output.len()),
            },
            bytes: processed.output,
        })
    }
}

/// The signature box, whole: length 12, type `JXL `, then the same CR-LF-EOF-LF tail PNG uses to
/// catch transfer corruption (ISO/IEC 18181-2 §5.2).
pub(crate) const SIGNATURE_BOX: [u8; 12] = [
    0x00, 0x00, 0x00, 0x0C, b'J', b'X', b'L', b' ', 0x0D, 0x0A, 0x87, 0x0A,
];

/// A bare codestream's first two bytes (ISO/IEC 18181-1 §9.1).
pub(crate) const CODESTREAM_MAGIC: [u8; 2] = [0xFF, 0x0A];

/// The brand a JPEG XL file's `ftyp` declares.
const BRAND: [u8; 4] = *b"jxl ";

/// Boxes that reach the output. Everything not named here is either deleted by [`DELETED`] or
/// refuses the file — the allow-list direction ADR-0033 established.
const KEPT: [BoxType; 5] = [*b"JXL ", *b"ftyp", *b"jxll", *b"jxlc", *b"jxlp"];

/// Boxes that are deleted, and how each is reported.
///
/// `free` and `skip` are padding by definition and free to hold anything; nothing depends on
/// them. `jxli` is an optional seek index for an animation — libjxl's own overview says it is not
/// needed to display one — and it is the only retained candidate that indexes positions in a file
/// this handler edits, so it goes rather than being trusted (ADR-0036 §6).
const DELETED: [(BoxType, MetadataKind, &str); 8] = [
    (*b"Exif", MetadataKind::Other, "Exif box"),
    (*b"xml ", MetadataKind::Other, "xml box (XMP)"),
    (
        *b"jumb",
        MetadataKind::EditingHistory,
        "jumb box (JUMBF, C2PA provenance)",
    ),
    (
        *b"brob",
        MetadataKind::Other,
        "brob box (Brotli-compressed metadata)",
    ),
    (
        *b"jbrd",
        MetadataKind::Other,
        "jbrd box (JPEG reconstruction data)",
    ),
    (*b"jxli", MetadataKind::Other, "jxli box (frame index)"),
    (*b"free", MetadataKind::Other, "free box (padding)"),
    (*b"skip", MetadataKind::Other, "skip box (padding)"),
];

/// The result of one pass over a file.
struct Processed {
    findings: Vec<Finding>,
    notes: Vec<Note>,
    output: Vec<u8>,
}

/// Walk `input`, decide about every box, and build the sanitised file.
fn process(input: &[u8], options: &InspectOptions, limits: &ParseLimits) -> Result<Processed> {
    let mut out = Processed {
        findings: Vec::new(),
        notes: vec![Note::OutOfScopeContent {
            // Said on every file, clean ones included: the verdict covers the box layer and
            // nothing inside the coded image (ADR-0036 §2).
            location: "a JPEG XL codestream, whose ICC profile and preview frame are coded \
                       inside the image data"
                .to_owned(),
        }],
        output: Vec::with_capacity(input.len()),
    };

    if input.starts_with(&CODESTREAM_MAGIC) {
        // No box layer exists in this spelling, so there is nothing to remove and nothing to
        // rewrite. Returning the input unchanged is the claim, and the note above is its scope.
        out.output.extend_from_slice(input);
        return Ok(out);
    }

    let mut budget = limits.max_items;
    let (boxes, trailing) = bmff::top_level(input, &mut budget).map_err(from_walk)?;
    check_prefix(&boxes)?;

    for b in &boxes {
        if KEPT.contains(&b.kind) {
            let raw = raw_of(input, b).ok_or_else(|| malformed(MalformedDetail::Truncated))?;
            out.output.extend_from_slice(raw);
            continue;
        }
        let Some(entry) = DELETED.iter().find(|(kind, _, _)| *kind == b.kind) else {
            // An unknown top-level box in a metadata format is more likely to be metadata than
            // not, and keeping it would be the survival-by-being-unrecognised failure the
            // allow-list exists to prevent (ADR-0036 §7).
            return Err(StryptError::UnsupportedFormat {
                format: UnsupportedKind::UnknownJxlBox,
            });
        };
        out.findings.extend(describe(b, entry, options));
        if b.is(*b"jbrd") {
            out.notes.push(Note::CapabilityRemoved {
                location: "the jbrd box (JPEG bitstream reconstruction data)".to_owned(),
                capability: "be converted back to the original JPEG bit-for-bit".to_owned(),
            });
        }
    }

    if !trailing.is_empty() {
        // The format has no terminator, so "after the last box" is not a place it defines: bytes
        // there mean either a truncated box or something appended, and neither is a file to
        // report success on. GIF reports and drops its trailing data because §27 gives it an
        // explicit end; this one is refused.
        return Err(malformed(MalformedDetail::Truncated));
    }
    if !boxes.iter().any(|b| b.is(*b"jxlc") || b.is(*b"jxlp")) {
        // No codestream is no image. Worth its own check because deletion cannot produce this
        // and a truncated file can: emitting a container with nothing in it would be a success
        // message about a file that no longer holds a picture.
        return Err(malformed(MalformedDetail::MissingMarker));
    }

    Ok(out)
}

/// Require the two boxes ISO/IEC 18181-2 §5.2 fixes: the signature, then an `ftyp` branding the
/// file `jxl `.
///
/// Checked before anything is removed. A file that fails here is refused rather than scanned for
/// boxes on a guess about what it is.
fn check_prefix(boxes: &[Bmff<'_>]) -> Result<()> {
    let signature = boxes
        .first()
        .ok_or_else(|| malformed(MalformedDetail::Truncated))?;
    // The whole box is fixed, tail bytes included: they are the CR-LF-EOF-LF transfer-corruption
    // check, so a file that fails them is one that arrived damaged.
    if !signature.is(*b"JXL ")
        || signature.size != as_u64(SIGNATURE_BOX.len())
        || signature.payload != &SIGNATURE_BOX[8..]
    {
        return Err(malformed(MalformedDetail::MissingMarker));
    }
    let ftyp = boxes
        .get(1)
        .ok_or_else(|| malformed(MalformedDetail::Truncated))?;
    if !ftyp.is(*b"ftyp") || ftyp.payload.get(..4) != Some(&BRAND) {
        return Err(malformed(MalformedDetail::MissingMarker));
    }
    Ok(())
}

/// The bytes a box occupied, which is what a kept box is written out from. Copying the original
/// span rather than re-emitting a header is what makes a clean file byte-identical.
fn raw_of<'a>(input: &'a [u8], b: &Bmff<'a>) -> Option<&'a [u8]> {
    let start = usize::try_from(b.offset).ok()?;
    let len = usize::try_from(b.size).ok()?;
    input.get(start..start.checked_add(len)?)
}

/// Name what is inside a box that is about to be deleted.
fn describe(
    b: &Bmff<'_>,
    entry: &(BoxType, MetadataKind, &str),
    options: &InspectOptions,
) -> Vec<Finding> {
    let (_, kind, location) = *entry;

    if b.is(*b"Exif") {
        // §5.3: the payload opens with a four-byte offset to the TIFF header, so a scan starting
        // at the payload would read the byte-order mark four bytes early and produce a confident
        // parse of the wrong bytes — the mistake `exif::scan`'s header warns about.
        // An Exif block that does not parse is still an Exif block that is about to be removed
        // whole, so the scan's own caveats are not carried: nothing is left behind to caveat.
        if let Some(tiff) = exif_payload(b.payload) {
            let scanned = exif::scan(tiff, location, options, &ParseLimits::default());
            if !scanned.findings.is_empty() {
                return scanned.findings;
            }
        }
    }
    if b.is(*b"xml ") {
        let findings = xmp::scan(b.payload, location, options);
        if !findings.is_empty() {
            return findings;
        }
    }

    let finding = Finding::new(kind, location, b.size);
    if b.is(*b"brob") {
        // The compressed box names what it wraps in its first four bytes. That name is reported;
        // the Brotli behind it is never inflated, because the box is being deleted either way.
        let inner = b.payload.get(..4).unwrap_or_default();
        return vec![
            finding
                .with_field(xmp::name_of(inner))
                .with_value(options, || MetadataValue::Text(xmp::name_of(inner))),
        ];
    }
    vec![finding]
}

/// The TIFF structure inside an Exif box, past the four-byte header offset (§5.3).
fn exif_payload(payload: &[u8]) -> Option<&[u8]> {
    let mut r = Reader::new(payload);
    let skip = crate::bytes::u32_to_usize(r.u32_be()?)?;
    r.skip(skip)?;
    Some(r.take_rest())
}

fn from_walk(e: WalkError) -> StryptError {
    match e {
        WalkError::Malformed(detail) => malformed(detail),
        WalkError::Limit(limit) => StryptError::LimitExceeded {
            format: Format::Jxl,
            limit,
        },
    }
}

fn malformed(detail: MalformedDetail) -> StryptError {
    StryptError::Malformed {
        format: Format::Jxl,
        offset: None,
        detail,
    }
}

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

    fn boxed(kind: BoxType, payload: &[u8]) -> Vec<u8> {
        let size = u32::try_from(payload.len() + 8).unwrap();
        let mut out = size.to_be_bytes().to_vec();
        out.extend_from_slice(&kind);
        out.extend_from_slice(payload);
        out
    }

    fn ftyp() -> Vec<u8> {
        boxed(*b"ftyp", b"jxl \0\0\0\0jxl ")
    }

    /// A codestream box holding a header stub, not a picture: nothing here enters it.
    fn jxlc() -> Vec<u8> {
        boxed(*b"jxlc", &[0xFF, 0x0A, 0x38, 0x00, 0x10, 0x00])
    }

    fn container(extra: &[Vec<u8>]) -> Vec<u8> {
        let mut out = SIGNATURE_BOX.to_vec();
        out.extend_from_slice(&ftyp());
        for b in extra {
            out.extend_from_slice(b);
        }
        out.extend_from_slice(&jxlc());
        out
    }

    fn strip(input: &[u8]) -> Result<Stripped> {
        JxlHandler.strip(input, &StripOptions::default())
    }

    #[test]
    fn a_clean_container_comes_back_byte_identical() {
        let input = container(&[]);
        let out = strip(&input).unwrap();
        assert_eq!(out.bytes, input);
        assert!(out.report.removed.is_empty());
    }

    #[test]
    fn a_bare_codestream_is_returned_unchanged() {
        let input = [0xFF, 0x0A, 0x38, 0x00, 0x10, 0x00];
        let out = strip(&input).unwrap();
        assert_eq!(out.bytes, input);
        assert!(out.report.removed.is_empty());
    }

    #[test]
    fn every_report_notes_the_codestream() {
        for input in [container(&[]).as_slice(), &[0xFF, 0x0A, 0x38]] {
            let out = strip(input).unwrap();
            assert!(
                out.report
                    .notes
                    .iter()
                    .any(|n| matches!(n, Note::OutOfScopeContent { .. }))
            );
        }
    }

    #[test]
    fn each_deleted_box_type_is_removed_and_reported() {
        for (kind, _, location) in DELETED {
            let input = container(&[boxed(kind, b"SYNTHETIC-PAYLOAD")]);
            let out = strip(&input).unwrap();
            assert_eq!(out.report.removed.len(), 1, "{location}");
            assert_eq!(out.bytes, container(&[]), "{location}");
        }
    }

    #[test]
    fn a_brob_box_is_reported_by_the_type_it_wraps() {
        let input = container(&[boxed(*b"brob", b"xml \x0b\x00compressed")]);
        let out = strip(&input).unwrap();
        assert_eq!(out.report.removed[0].field.as_deref(), Some("xml "));
    }

    #[test]
    fn a_jbrd_box_leaves_a_capability_note() {
        let input = container(&[boxed(*b"jbrd", b"reconstruction")]);
        let out = strip(&input).unwrap();
        assert!(
            out.report
                .notes
                .iter()
                .any(|n| matches!(n, Note::CapabilityRemoved { .. }))
        );
    }

    #[test]
    fn an_unknown_top_level_box_refuses_the_file() {
        let input = container(&[boxed(*b"zzzz", b"who knows")]);
        assert!(matches!(
            strip(&input),
            Err(StryptError::UnsupportedFormat {
                format: UnsupportedKind::UnknownJxlBox
            })
        ));
    }

    #[test]
    fn the_prefix_the_spec_fixes_is_required() {
        let bad_signature = {
            let mut v = SIGNATURE_BOX.to_vec();
            v[11] = 0x00;
            v.extend_from_slice(&ftyp());
            v.extend_from_slice(&jxlc());
            v
        };
        let no_signature = [ftyp(), jxlc()].concat();
        let wrong_brand = {
            let mut v = SIGNATURE_BOX.to_vec();
            v.extend_from_slice(&boxed(*b"ftyp", b"heic\0\0\0\0heic"));
            v.extend_from_slice(&jxlc());
            v
        };
        for input in [bad_signature, no_signature, wrong_brand] {
            assert!(strip(&input).is_err());
        }
    }

    #[test]
    fn trailing_bytes_are_refused() {
        let mut input = container(&[]);
        input.extend_from_slice(b"appended");
        assert!(strip(&input).is_err());
    }

    #[test]
    fn a_container_with_no_codestream_is_refused() {
        let input = [SIGNATURE_BOX.to_vec(), ftyp()].concat();
        assert!(matches!(
            strip(&input),
            Err(StryptError::Malformed {
                detail: MalformedDetail::MissingMarker,
                ..
            })
        ));
    }

    #[test]
    fn a_size_zero_final_box_is_copied_through() {
        // Size 0 means "to the end of the file" (ISO/IEC 14496-12 §4.2), legal for the last box.
        let mut input = [SIGNATURE_BOX.to_vec(), ftyp()].concat();
        input.extend_from_slice(&[0, 0, 0, 0]);
        input.extend_from_slice(b"jxlc");
        input.extend_from_slice(&[0xFF, 0x0A, 0x38, 0x00]);
        let out = strip(&input).unwrap();
        assert_eq!(out.bytes, input);
    }

    #[test]
    fn exif_findings_name_the_tags_behind_the_header_offset() {
        // Payload: the four-byte offset, then a little-endian TIFF header with one Artist tag.
        let mut tiff = b"II\x2a\x00\x08\x00\x00\x00".to_vec();
        tiff.extend_from_slice(&1u16.to_le_bytes());
        tiff.extend_from_slice(&0x013Bu16.to_le_bytes()); // Artist
        tiff.extend_from_slice(&2u16.to_le_bytes()); // ASCII
        tiff.extend_from_slice(&10u32.to_le_bytes());
        tiff.extend_from_slice(&26u32.to_le_bytes());
        tiff.extend_from_slice(&0u32.to_le_bytes());
        tiff.extend_from_slice(b"SYNTHETIC\0");
        let mut payload = 0u32.to_be_bytes().to_vec();
        payload.extend_from_slice(&tiff);

        let input = container(&[boxed(*b"Exif", &payload)]);
        let out = strip(&input).unwrap();
        assert!(out.report.removed.iter().any(|f| f.field.is_some()));
        assert_eq!(out.bytes, container(&[]));
    }

    #[test]
    fn an_exif_box_that_does_not_parse_is_still_removed() {
        let input = container(&[boxed(*b"Exif", b"\xff\xff\xff\xffnot a tiff")]);
        let out = strip(&input).unwrap();
        assert_eq!(out.report.removed.len(), 1);
        assert_eq!(out.bytes, container(&[]));
    }

    #[test]
    fn exif_payload_steps_over_the_tiff_header_offset() {
        assert_eq!(exif_payload(b"\0\0\0\x02..II*\0"), Some(&b"II*\0"[..]));
        assert_eq!(exif_payload(b"\0\0\0\xff"), None);
        assert_eq!(exif_payload(b"\0\0"), None);
    }

    #[test]
    fn inspect_and_strip_agree() {
        let input = container(&[boxed(*b"jumb", b"SYNTHETIC-C2PA"), boxed(*b"free", b"pad")]);
        let inspected = JxlHandler
            .inspect(&input, &InspectOptions::default())
            .unwrap();
        let stripped = strip(&input).unwrap();
        assert_eq!(inspected.findings, stripped.report.removed);
    }
}
