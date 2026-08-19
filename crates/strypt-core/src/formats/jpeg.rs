//! JPEG.
//!
//! The format most likely to be handed to this tool by someone in danger. A photograph taken
//! on a phone and sent to a newsroom carries, by default, the coordinates it was taken at, the
//! serial number of the device that took it, the moment it was taken to the second, and a
//! thumbnail that predates whatever cropping was done afterwards.
//!
//! # Segment surgery, never re-encoding
//!
//! A JPEG is a sequence of marker segments — two-byte marker, two-byte length, payload —
//! wrapped around entropy-coded scan data that holds the actual picture. Everything
//! identifying lives in the `APPn` and `COM` segments; none of it lives in the scan data.
//!
//! So this handler never decodes an image and never re-encodes one. It walks the segment list,
//! drops the segments that carry metadata, and copies the scan data through byte for byte. A
//! decode-and-re-encode round trip would be far less code and would quietly destroy image
//! quality on every pass — for a photojournalist whose picture is the evidence, that is
//! damage, not a side effect (`docs/PRD.md` §8.1). It would also change the pixels of a file
//! that someone may need to demonstrate is unaltered.
//!
//! # What is deliberately kept
//!
//! Two segments survive, and both are reported in the strip report's `retained` list rather
//! than left to be noticed:
//!
//! - **`APP0` (JFIF)**, minus any thumbnail inside it. It carries the pixel aspect ratio, and
//!   dropping it silently changes how a non-square-pixel image displays.
//! - **`APP14` (Adobe)**, which declares the colour transform. A CMYK or YCCK JPEG whose
//!   `APP14` has been removed is rendered with inverted or wrong colours by many decoders.
//!
//! Both are fixed-shape structures that name no person, no place, and no device.
//!
//! # What is removed even though it affects rendering
//!
//! Exif `Orientation` and the `APP2` ICC colour profile both go. Each changes how the image
//! displays: an image that relied on `Orientation` may appear rotated afterwards, and a
//! wide-gamut image without its profile is interpreted as sRGB. They are removed anyway,
//! because both are also identifying — a profile routinely names the device or vendor that
//! made it — and because leaving them would make strypt remove less than mat2 does for the
//! same file. The limitation is documented rather than hidden; see `CHANGELOG.md`.

use crate::bytes::Reader;
use crate::detect::Format;
use crate::error::{MalformedDetail, ResourceLimit, Result, StryptError};
use crate::formats::{MetadataHandler, ParseLimits, StripOptions, Stripped, exif, xmp};
use crate::report::{
    Finding, InspectOptions, MetadataKind, MetadataReport, MetadataValue, Note, Retained,
    RetentionReason, StripReport,
};

/// Removal of metadata from JPEG images.
#[derive(Debug, Clone, Copy, Default)]
pub struct JpegHandler;

impl MetadataHandler for JpegHandler {
    fn name(&self) -> &'static str {
        Format::Jpeg.id()
    }

    fn format(&self) -> Format {
        Format::Jpeg
    }

    fn inspect(&self, input: &[u8], options: &InspectOptions) -> Result<MetadataReport> {
        // Inspection runs the identical pass that stripping does and throws the output away.
        // That makes "everything `strip` removes is something `inspect` can see" true by
        // construction rather than by two code paths agreeing to stay in step — which is the
        // only thing that makes the pipeline's verification pass meaningful
        // (`docs/ARCHITECTURE.md` §3).
        let processed = process(input, options, &ParseLimits::default())?;
        Ok(MetadataReport {
            format: Format::Jpeg,
            findings: processed.findings,
            notes: processed.notes,
        })
    }

    fn strip(&self, input: &[u8], options: &StripOptions) -> Result<Stripped> {
        let processed = process(input, &options.inspect, &options.limits)?;
        Ok(Stripped {
            report: StripReport {
                format: Format::Jpeg,
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

/// The result of one pass over a file: what was found, and what the sanitised file looks like.
struct Processed {
    findings: Vec<Finding>,
    retained: Vec<Retained>,
    notes: Vec<Note>,
    output: Vec<u8>,
}

/// Markers that stand alone: no length field and no payload follows them.
///
/// ITU-T T.81 §B.1.1.3. `RST0`–`RST7` appear *inside* entropy-coded data rather than between
/// segments, and are consumed by the scan walker; they are listed here so that a stray one
/// between segments is copied through rather than read as a segment with a length.
const fn is_standalone(marker: u8) -> bool {
    matches!(marker, 0x01 | 0xD0..=0xD7 | 0xD8)
}

/// One structural piece of the file, in the order it appears.
enum Piece<'a> {
    /// A marker with no payload.
    Standalone(u8),
    /// A marker, its length, and its payload — the payload only, without the length field.
    Segment { marker: u8, payload: &'a [u8] },
    /// Entropy-coded scan data. Copied through untouched; the picture lives here.
    Entropy(&'a [u8]),
    /// Bytes after the final `EOI` marker.
    Trailing(&'a [u8]),
}

/// Start of image.
const SOI: u8 = 0xD8;
/// End of image.
const EOI: u8 = 0xD9;
/// Start of scan: the last segment before entropy-coded data.
const SOS: u8 = 0xDA;
/// Comment.
const COM: u8 = 0xFE;

/// Split `input` into its pieces.
///
/// Every length in the file was chosen by whoever made it, so every one is read through
/// [`Reader`] and every failure is a typed error rather than a panic. A file that does not
/// parse is refused whole: there is no path here that returns a partial piece list for a
/// caller to strip and write out.
fn walk<'a>(input: &'a [u8], limits: &ParseLimits) -> Result<Vec<Piece<'a>>> {
    let mut r = Reader::new(input);
    let mut pieces = Vec::new();

    if r.take(2) != Some(&[0xFF, SOI]) {
        return Err(malformed(MalformedDetail::MissingMarker, Some(0)));
    }
    pieces.push(Piece::Standalone(SOI));

    let mut budget = limits.max_items;
    let mut saw_scan = false;

    loop {
        if budget == 0 {
            return Err(StryptError::LimitExceeded {
                format: Format::Jpeg,
                limit: ResourceLimit::ItemCount,
            });
        }
        budget = budget.saturating_sub(1);

        let at = r.position();
        // A marker may be preceded by any number of 0xFF fill bytes (T.81 §B.1.1.2). Real
        // encoders rarely emit them; some hardware ones do, and a decoder that refuses is
        // simply wrong about the file.
        let mut marker = match r.take(2) {
            Some([0xFF, m]) => *m,
            // Running out here means the file ended without an EOI. It is refused rather than
            // completed: emitting a repaired copy of a damaged file would hand the user
            // something that is not what they gave us, presented as a clean version of it.
            Some(_) | None => return Err(malformed(MalformedDetail::Truncated, as_offset(at))),
        };
        while marker == 0xFF {
            marker = match r.u8() {
                Some(m) => m,
                None => return Err(malformed(MalformedDetail::Truncated, as_offset(at))),
            };
        }
        if marker == 0x00 {
            // A stuffed byte outside entropy-coded data: this is not where we think we are.
            return Err(malformed(MalformedDetail::UnexpectedMarker, as_offset(at)));
        }

        if marker == EOI {
            pieces.push(Piece::Standalone(EOI));
            break;
        }
        if is_standalone(marker) {
            pieces.push(Piece::Standalone(marker));
            continue;
        }

        // T.81 §B.1.1.4: the length field counts itself, so it can never be less than two.
        let declared = r
            .u16_be()
            .ok_or_else(|| malformed(MalformedDetail::Truncated, as_offset(at)))?;
        let length = declared
            .checked_sub(2)
            .ok_or_else(|| malformed(MalformedDetail::LengthOutOfRange, as_offset(at)))?;
        let payload = r
            .take(usize::from(length))
            .ok_or_else(|| malformed(MalformedDetail::LengthOutOfRange, as_offset(at)))?;
        pieces.push(Piece::Segment { marker, payload });

        if marker == SOS {
            saw_scan = true;
            let start = r.position();
            let consumed = scan_length(r.peek(r.remaining()).unwrap_or_default());
            r.skip(consumed)
                .ok_or_else(|| malformed(MalformedDetail::Truncated, as_offset(start)))?;
            let end = r.position();
            pieces.push(Piece::Entropy(input.get(start..end).unwrap_or_default()));
        }
    }

    if !saw_scan {
        // No scan means no picture. Something that parses as a marker list but contains no
        // image is not a file this handler should be emitting a "cleaned" version of.
        return Err(malformed(MalformedDetail::MissingMarker, None));
    }

    let rest = r.take_rest();
    if !rest.is_empty() {
        pieces.push(Piece::Trailing(rest));
    }
    Ok(pieces)
}

/// How many bytes of entropy-coded data follow, up to the next real marker.
///
/// Inside the scan, `0xFF` is escaped as `0xFF 0x00`, restart markers `0xFF 0xD0`–`0xFF 0xD7`
/// are part of the stream, and runs of `0xFF` are fill. Anything else after an `0xFF` ends the
/// scan — which is how a progressive JPEG's several scans, with their tables in between, are
/// walked without special-casing progressive mode at all.
fn scan_length(rest: &[u8]) -> usize {
    let mut i = 0usize;
    loop {
        let Some(offset) = rest
            .get(i..)
            .and_then(|s| s.iter().position(|&b| b == 0xFF))
        else {
            return rest.len();
        };
        let at = i.saturating_add(offset);
        match rest.get(at.saturating_add(1)) {
            // Truncated after a trailing 0xFF: let the caller run out and report it.
            None => return rest.len(),
            // A stuffed 0xFF, or a restart marker: both are part of the stream, and both are
            // two bytes long.
            Some(0x00 | 0xD0..=0xD7) => i = at.saturating_add(2),
            // Fill byte; the next byte may still be the marker.
            Some(0xFF) => i = at.saturating_add(1),
            Some(_) => return at,
        }
    }
}

/// What to do with one segment.
enum Outcome {
    /// Copy it through unchanged, silently. Structural segments: tables, frame headers, scans.
    Keep,
    /// Remove it entirely.
    Drop,
    /// Copy it through with a different payload.
    Replace(Vec<u8>),
}

/// A decision about one segment, with what to tell the user about it.
struct Decision {
    outcome: Outcome,
    findings: Vec<Finding>,
    /// Anything kept on purpose. Separate from `findings` because the verification pass
    /// requires that nothing `inspect` reports as a finding survives a strip — a segment that
    /// is deliberately kept has to be declared, not reported as removed.
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

    /// Copy the segment through, and say in the report that it was a deliberate choice.
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

    fn drop_one(kind: MetadataKind, location: &str, bytes: u64) -> Self {
        Self::drop_with(vec![Finding::new(kind, location.to_owned(), bytes)])
    }
}

/// Walk `input`, decide about every piece, and build the sanitised file.
fn process(input: &[u8], options: &InspectOptions, limits: &ParseLimits) -> Result<Processed> {
    let pieces = walk(input, limits)?;
    let mut out = Processed {
        findings: Vec::new(),
        retained: Vec::new(),
        notes: Vec::new(),
        output: Vec::with_capacity(input.len()),
    };

    for piece in pieces {
        match piece {
            Piece::Standalone(marker) => {
                out.output.push(0xFF);
                out.output.push(marker);
            }
            Piece::Entropy(data) => out.output.extend_from_slice(data),
            Piece::Trailing(data) => {
                // Everything after EOI is data no decoder reads and no user knows is there.
                // In practice it is where a phone's multi-picture extension keeps a second
                // full-resolution frame — an unredacted copy of the picture, past the end of
                // the picture.
                let kind = if data.starts_with(&[0xFF, SOI]) {
                    MetadataKind::Thumbnail
                } else {
                    MetadataKind::Other
                };
                out.findings.push(Finding::new(
                    kind,
                    "trailing data after EOI",
                    as_u64(data.len()),
                ));
            }
            Piece::Segment { marker, payload } => {
                let decision = decide(marker, payload, options, limits);
                out.notes.extend(decision.notes);
                out.retained.extend(decision.retained);
                match decision.outcome {
                    Outcome::Keep => emit(&mut out.output, marker, payload),
                    Outcome::Drop => out.findings.extend(decision.findings),
                    Outcome::Replace(new_payload) => {
                        out.findings.extend(decision.findings);
                        emit(&mut out.output, marker, &new_payload);
                    }
                }
            }
        }
    }
    Ok(out)
}

/// Write one segment: marker, length including itself, payload.
///
/// The length cannot overflow: a payload only ever arrives here having come out of a `u16`
/// length field, or having been shortened from one.
fn emit(output: &mut Vec<u8>, marker: u8, payload: &[u8]) {
    let Ok(length) = u16::try_from(payload.len().saturating_add(2)) else {
        return;
    };
    output.push(0xFF);
    output.push(marker);
    output.extend_from_slice(&length.to_be_bytes());
    output.extend_from_slice(payload);
}

/// Decide about one segment.
fn decide(marker: u8, payload: &[u8], options: &InspectOptions, limits: &ParseLimits) -> Decision {
    let size = as_u64(payload.len());
    match marker {
        0xE0 => app0(payload, size),
        0xE1 => app1(payload, size, options, limits),
        0xE2 => app2(payload, size),
        0xE3 => Decision::drop_one(MetadataKind::Other, "APP3 (Meta)", size),
        0xE4 => Decision::drop_one(MetadataKind::Other, "APP4", size),
        0xE5 => Decision::drop_one(MetadataKind::Other, "APP5", size),
        0xE6 => Decision::drop_one(MetadataKind::Other, "APP6", size),
        0xE7 => Decision::drop_one(MetadataKind::Other, "APP7", size),
        0xE8 => Decision::drop_one(MetadataKind::Other, "APP8", size),
        0xE9 => Decision::drop_one(MetadataKind::Other, "APP9", size),
        // APP10 is the Active Pictures comment segment; APP12 is where several camera makers
        // put "Ducky" and "PictureInfo" blocks, which name the camera and its settings.
        0xEA => Decision::drop_one(MetadataKind::Comment, "APP10", size),
        0xEB => Decision::drop_one(MetadataKind::Other, "APP11", size),
        0xEC => Decision::drop_one(MetadataKind::SoftwareFingerprint, "APP12 (Ducky)", size),
        0xED => app13(payload, size),
        0xEE => app14(payload, size),
        0xEF => Decision::drop_one(MetadataKind::Other, "APP15", size),
        COM => comment(payload, size, options),
        // Quantisation and Huffman tables, frame headers, scan headers, restart intervals:
        // the file is not an image without them, and none of them names anybody.
        _ => Decision::keep(),
    }
}

/// `APP0`: the JFIF header, and its optional embedded thumbnail.
fn app0(payload: &[u8], size: u64) -> Decision {
    if payload.starts_with(b"JFXX\0") {
        // The JFIF extension segment exists to carry a thumbnail and nothing else.
        return Decision::drop_one(MetadataKind::Thumbnail, "APP0 (JFXX thumbnail)", size);
    }
    if !payload.starts_with(b"JFIF\0") {
        return Decision::drop_one(MetadataKind::Other, "APP0", size);
    }

    // JFIF 1.02 §3: the thumbnail dimensions are the thirteenth and fourteenth bytes of the
    // payload, followed by 3·X·Y bytes of uncompressed RGB. A JFIF thumbnail is rare and, when
    // present, is a pre-crop copy of the image like any other.
    let (Some(&x), Some(&y)) = (payload.get(12), payload.get(13)) else {
        return Decision::drop_one(MetadataKind::Other, "APP0 (JFIF, malformed)", size);
    };
    let pixels = u64::from(x).saturating_mul(u64::from(y));
    if pixels == 0 {
        return Decision::kept_on_purpose("APP0 (JFIF)", RetentionReason::RemovalWouldAlterPayload);
    }

    let mut header = payload.get(0..14).unwrap_or_default().to_vec();
    // Zero the dimensions rather than merely truncating the segment: a reader that trusted
    // them would walk off the end of what is left otherwise.
    zero_thumbnail_dimensions(&mut header);
    Decision {
        outcome: Outcome::Replace(header),
        findings: vec![Finding::new(
            MetadataKind::Thumbnail,
            "APP0 (JFIF thumbnail)",
            pixels.saturating_mul(3),
        )],
        // The header that is left behind is still a deliberate retention, and is reported as
        // one — otherwise a file whose JFIF segment held a thumbnail would say less about what
        // was kept than a file whose JFIF segment did not.
        retained: vec![Retained {
            location: "APP0 (JFIF)".to_owned(),
            reason: RetentionReason::RemovalWouldAlterPayload,
        }],
        notes: Vec::new(),
    }
}

/// Set the JFIF thumbnail dimensions to zero, in a header already known to be 14 bytes.
fn zero_thumbnail_dimensions(header: &mut [u8]) {
    if let Some(slot) = header.get_mut(12) {
        *slot = 0;
    }
    if let Some(slot) = header.get_mut(13) {
        *slot = 0;
    }
}

/// `APP1`: Exif, XMP, and anything else that claimed the segment.
fn app1(payload: &[u8], size: u64, options: &InspectOptions, limits: &ParseLimits) -> Decision {
    if let Some(tiff) = payload.strip_prefix(b"Exif\0\0") {
        let scanned = exif::scan(tiff, "APP1 (Exif)", options, limits);
        let findings = if scanned.findings.is_empty() {
            // An Exif block that named nothing is still an Exif block, and it is still going.
            vec![Finding::new(MetadataKind::Other, "APP1 (Exif)", size)]
        } else {
            scanned.findings
        };
        return Decision {
            outcome: Outcome::Drop,
            findings,
            retained: Vec::new(),
            notes: scanned.notes,
        };
    }
    // The XMP packet is introduced by a namespace URI and a NUL. The extension segment carries
    // packets too large for one APP1 and is handled the same way.
    for prefix in [
        b"http://ns.adobe.com/xap/1.0/\0".as_slice(),
        b"http://ns.adobe.com/xmp/extension/\0".as_slice(),
    ] {
        if let Some(packet) = payload.strip_prefix(prefix) {
            return Decision::drop_with(xmp::scan(packet, "APP1 (XMP)", options));
        }
    }
    Decision::drop_one(MetadataKind::Other, "APP1", size)
}

/// `APP2`: ICC colour profiles, `FlashPix`, and the multi-picture extension.
fn app2(payload: &[u8], size: u64) -> Decision {
    if payload.starts_with(b"ICC_PROFILE\0") {
        // An ICC profile names the device or vendor it was made for in its description tag,
        // and many phones embed a per-device profile.
        return Decision::drop_one(MetadataKind::ColourProfile, "APP2 (ICC profile)", size);
    }
    if payload.starts_with(b"MPF\0") {
        // Multi-Picture Format: an index of *further whole images* stored in the same file,
        // typically a full-resolution frame the camera kept alongside the one you can see.
        return Decision::drop_one(MetadataKind::Thumbnail, "APP2 (MPF)", size);
    }
    if payload.starts_with(b"FPXR") {
        return Decision::drop_one(MetadataKind::Other, "APP2 (FlashPix)", size);
    }
    Decision::drop_one(MetadataKind::Other, "APP2", size)
}

/// `APP13`: Photoshop image resource blocks, which is where IPTC captions live.
fn app13(payload: &[u8], size: u64) -> Decision {
    if payload.starts_with(b"Photoshop 3.0\0") {
        // The IPTC block inside carries by-line, credit, city, and country fields — written by
        // a person, about a person, and frequently the most directly identifying thing in a
        // press photograph.
        return Decision::drop_one(
            MetadataKind::PersonalIdentity,
            "APP13 (Photoshop/IPTC)",
            size,
        );
    }
    Decision::drop_one(MetadataKind::Other, "APP13", size)
}

/// `APP14`: the Adobe colour-transform marker.
fn app14(payload: &[u8], size: u64) -> Decision {
    if payload.starts_with(b"Adobe") {
        // Kept: it declares whether the components are YCbCr, YCCK, or CMYK. Remove it from a
        // CMYK file and many decoders render it inverted. It names no person and no device.
        return Decision::kept_on_purpose(
            "APP14 (Adobe)",
            RetentionReason::RemovalWouldAlterPayload,
        );
    }
    Decision::drop_one(MetadataKind::Other, "APP14", size)
}

/// `COM`: a free-text comment, which is exactly as free as it sounds.
fn comment(payload: &[u8], size: u64, options: &InspectOptions) -> Decision {
    Decision::drop_with(vec![
        Finding::new(MetadataKind::Comment, "COM", size).with_value(options, || {
            MetadataValue::Text(
                String::from_utf8_lossy(payload)
                    .chars()
                    .filter(|c| !c.is_control())
                    .collect(),
            )
        }),
    ])
}

/// A malformed-file error for this format.
fn malformed(detail: MalformedDetail, offset: Option<u64>) -> StryptError {
    StryptError::Malformed {
        format: Format::Jpeg,
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

    /// A minimal but structurally real JPEG: SOI, the given segments, a scan, EOI.
    fn jpeg(segments: &[(u8, Vec<u8>)]) -> Vec<u8> {
        let mut out = vec![0xFF, SOI];
        for (marker, payload) in segments {
            out.push(0xFF);
            out.push(*marker);
            out.extend_from_slice(&u16::try_from(payload.len() + 2).unwrap().to_be_bytes());
            out.extend_from_slice(payload);
        }
        // SOS with a two-byte header, then entropy data containing a stuffed 0xFF and a
        // restart marker, so that the scan walker is actually exercised.
        out.extend_from_slice(&[0xFF, SOS, 0x00, 0x04, 0x01, 0x00]);
        out.extend_from_slice(&[0x12, 0xFF, 0x00, 0x34, 0xFF, 0xD0, 0x56]);
        out.extend_from_slice(&[0xFF, EOI]);
        out
    }

    fn strip_ok(data: &[u8]) -> Stripped {
        JpegHandler
            .strip(data, &StripOptions::default())
            .expect("strip failed")
    }

    fn findings(data: &[u8]) -> Vec<Finding> {
        JpegHandler
            .inspect(data, &InspectOptions::names_only())
            .expect("inspect failed")
            .findings
    }

    fn exif_app1(tag: u16, value: [u8; 4]) -> Vec<u8> {
        let mut payload = b"Exif\0\0".to_vec();
        payload.extend_from_slice(b"II\x2A\x00\x08\x00\x00\x00");
        payload.extend_from_slice(&1u16.to_le_bytes());
        payload.extend_from_slice(&tag.to_le_bytes());
        payload.extend_from_slice(&2u16.to_le_bytes()); // ASCII
        payload.extend_from_slice(&4u32.to_le_bytes());
        payload.extend_from_slice(&value);
        payload.extend_from_slice(&0u32.to_le_bytes());
        payload
    }

    #[test]
    fn the_picture_is_never_touched() {
        // The entropy-coded data is the photograph. If a byte of it ever changes, the handler
        // has re-encoded something, and the promise in this module's header is broken.
        let input = jpeg(&[(0xE1, exif_app1(0x010F, *b"ACME"))]);
        let output = strip_ok(&input).bytes;
        let scan_bytes: &[u8] = &[0x12, 0xFF, 0x00, 0x34, 0xFF, 0xD0, 0x56];
        assert!(
            output.windows(scan_bytes.len()).any(|w| w == scan_bytes),
            "entropy-coded data did not survive byte for byte"
        );
    }

    #[test]
    fn exif_is_reported_by_tag_and_removed() {
        let input = jpeg(&[(0xE1, exif_app1(0x010F, *b"ACME"))]);
        let found = findings(&input);
        assert_eq!(found[0].field.as_deref(), Some("Make"));
        assert_eq!(found[0].kind, MetadataKind::DeviceIdentity);

        let output = strip_ok(&input).bytes;
        assert!(
            !output.windows(4).any(|w| w == b"ACME"),
            "the camera make survived the strip"
        );
        assert!(findings(&output).is_empty());
    }

    #[test]
    fn a_comment_goes_and_the_tables_stay() {
        // 0xDB is a quantisation table: structural, unidentifying, and required for the image
        // to decode. A handler that dropped every segment it did not recognise would break it.
        let input = jpeg(&[(COM, b"SYNTHETIC-COMMENT".to_vec()), (0xDB, vec![0u8; 8])]);
        let output = strip_ok(&input).bytes;
        assert!(!output.windows(9).any(|w| w == b"SYNTHETIC"));
        assert!(
            output.windows(2).any(|w| w == [0xFF, 0xDB]),
            "the quantisation table was dropped along with the comment"
        );
    }

    #[test]
    fn the_jfif_header_stays_and_its_thumbnail_does_not() {
        let mut jfif = b"JFIF\0\x01\x02\x00\x00\x01\x00\x01".to_vec();
        jfif.push(2); // thumbnail width
        jfif.push(2); // thumbnail height
        jfif.extend_from_slice(&[0xAB; 12]); // 3 · 2 · 2 bytes of RGB
        let input = jpeg(&[(0xE0, jfif)]);

        let stripped = strip_ok(&input);
        assert!(
            stripped
                .report
                .removed
                .iter()
                .any(|f| f.kind == MetadataKind::Thumbnail)
        );
        assert!(
            stripped
                .report
                .retained
                .iter()
                .any(|r| r.location == "APP0 (JFIF)"),
            "the JFIF header should be kept, and the report should say it was"
        );
        assert!(!stripped.bytes.windows(4).any(|w| w == [0xAB; 4]));
        assert!(findings(&stripped.bytes).is_empty());
    }

    #[test]
    fn the_adobe_colour_transform_marker_is_kept_and_declared() {
        // Removing it renders CMYK files with inverted colours. Keeping it silently would be
        // the wrong half of the trade: the user is told.
        let input = jpeg(&[(0xEE, b"Adobe\0\x64\x00\x00\x00\x00\x02".to_vec())]);
        let stripped = strip_ok(&input);
        assert!(stripped.bytes.windows(2).any(|w| w == [0xFF, 0xEE]));
        assert_eq!(stripped.report.retained.len(), 1);
        assert_eq!(
            stripped.report.retained[0].reason,
            RetentionReason::RemovalWouldAlterPayload
        );
    }

    #[test]
    fn data_hidden_after_the_end_of_image_marker_is_removed() {
        // Where a phone's multi-picture extension keeps a second full-resolution frame. No
        // decoder shows it; every forensic tool finds it.
        let mut input = jpeg(&[]);
        input.extend_from_slice(&[0xFF, SOI]);
        input.extend_from_slice(b"SYNTHETIC-SECOND-IMAGE");
        let stripped = strip_ok(&input);
        assert!(!stripped.bytes.windows(9).any(|w| w == b"SYNTHETIC"));
        assert_eq!(stripped.report.removed[0].kind, MetadataKind::Thumbnail);
    }

    #[test]
    fn stripping_twice_changes_nothing() {
        let input = jpeg(&[
            (0xE1, exif_app1(0x010F, *b"ACME")),
            (COM, b"SYNTHETIC-COMMENT".to_vec()),
        ]);
        let once = strip_ok(&input).bytes;
        let twice = strip_ok(&once).bytes;
        assert_eq!(once, twice, "strip is not idempotent");
    }

    #[test]
    fn a_clean_file_produces_no_findings_and_no_edits() {
        let input = jpeg(&[(0xDB, vec![0u8; 8])]);
        let stripped = strip_ok(&input);
        assert!(stripped.report.removed.is_empty());
        assert_eq!(stripped.bytes, input);
    }

    #[test]
    fn a_file_that_ends_without_eoi_is_refused() {
        // Fail closed. Completing a damaged file would hand the user something that is not
        // what they gave us, presented as a clean version of it.
        let input = jpeg(&[]);
        let truncated = &input[0..input.len() - 2];
        assert!(matches!(
            JpegHandler.strip(truncated, &StripOptions::default()),
            Err(StryptError::Malformed { .. })
        ));
    }

    #[test]
    fn truncation_at_every_length_is_refused_or_survived_but_never_panics() {
        let input = jpeg(&[
            (0xE1, exif_app1(0x8825, [26, 0, 0, 0])),
            (COM, b"comment".to_vec()),
        ]);
        for n in 0..=input.len() {
            let prefix = &input[0..n];
            let _ = JpegHandler.inspect(prefix, &InspectOptions::names_only());
            let _ = JpegHandler.strip(prefix, &StripOptions::default());
        }
    }

    #[test]
    fn a_segment_length_of_zero_is_refused_rather_than_wrapping() {
        // Declared length below the two bytes the field itself occupies. Subtracting without a
        // check would wrap to 65534 on a release build without overflow checks.
        let input = vec![0xFF, SOI, 0xFF, 0xE1, 0x00, 0x00, 0xFF, EOI];
        assert!(matches!(
            JpegHandler.inspect(&input, &InspectOptions::names_only()),
            Err(StryptError::Malformed {
                detail: MalformedDetail::LengthOutOfRange,
                ..
            })
        ));
    }

    #[test]
    fn a_segment_count_beyond_the_limit_is_refused() {
        let segments: Vec<(u8, Vec<u8>)> = (0..64).map(|_| (0xDB, vec![0u8; 4])).collect();
        let input = jpeg(&segments);
        let options = StripOptions {
            limits: ParseLimits {
                max_items: 8,
                ..ParseLimits::default()
            },
            ..StripOptions::default()
        };
        assert!(matches!(
            JpegHandler.strip(&input, &options),
            Err(StryptError::LimitExceeded { .. })
        ));
    }
}
