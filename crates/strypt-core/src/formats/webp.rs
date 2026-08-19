//! WebP.
//!
//! A RIFF container, so structurally the closest thing in this crate to the PNG handler: a
//! flat list of chunks, each with a four-character code and its own length, walked once and
//! filtered. Where PNG puts its metadata in `tEXt`, `zTXt`, `iTXt`, `tIME`, `eXIf`, and
//! `iCCP`, WebP puts all of it in exactly three chunks — `ICCP`, `EXIF`, and `XMP ` — plus
//! whatever a producer left in an unknown chunk.
//!
//! Everything here follows RFC 9649, which is the WebP container's authoritative
//! specification (verified 2026-08-19); section numbers below refer to it.
//!
//! # Chunk surgery, never re-encoding, and no checksums anywhere
//!
//! Kept chunks are copied through **as raw bytes** — code, length, payload, and RIFF padding
//! byte verbatim. WebP carries no per-chunk CRC at all (§2.3), so unlike PNG there is not even
//! a checksum to preserve, and the only field in the whole file that has to be recomputed is
//! the RIFF chunk's own size. A file with nothing to remove therefore strips to a
//! byte-identical copy of itself, and idempotence follows from the design rather than from a
//! test passing.
//!
//! # `VP8X` is the one chunk this handler rewrites
//!
//! An extended-format file opens with a `VP8X` chunk whose flags byte declares which optional
//! parts the file has: an ICC profile, an alpha channel, Exif metadata, XMP metadata, an
//! animation (§2.7, Figure 7). Remove the `ICCP`, `EXIF`, or `XMP ` chunk and leave the
//! matching bit set, and the file now lies about itself — some decoders warn, some refuse.
//!
//! So those three bits are cleared, and nothing else in the chunk is touched: the alpha and
//! animation bits, the reserved bits, and the canvas dimensions are copied byte for byte
//! (ADR-0023). This is the same trade the JPEG handler already makes when it rewrites `APP0`
//! to zero a thumbnail's dimensions (ADR-0021) — a kept structure is corrected rather than
//! left inconsistent with what was removed. A `VP8X` whose metadata bits are already clear is
//! copied through untouched, so the rewrite happens only where it changes something.
//!
//! # No decompressor, again
//!
//! Nothing WebP puts metadata in is compressed at the container level: `ICCP` holds a profile,
//! `EXIF` holds a TIFF block the shared reader in [`crate::formats::exif`] handles directly,
//! and `XMP ` holds a plain XML packet. As with PNG (ADR-0022), `strypt-core` gains no
//! dependency and no inflate path for this format.
//!
//! # What is checked, and what is not
//!
//! Every length in the file was chosen by whoever made it, so every one is read through
//! [`Reader`] and every failure is a typed error rather than a panic. The declared RIFF size
//! bounds the walk: bytes beyond it are trailing data and go, and a RIFF size that runs past
//! the end of the file is a lie and the file is refused rather than clamped.

use crate::bytes::{Reader, u32_to_usize};
use crate::detect::Format;
use crate::error::{MalformedDetail, ResourceLimit, Result, StryptError};
use crate::formats::{MetadataHandler, ParseLimits, StripOptions, Stripped, exif, xmp};
use crate::report::{
    Finding, InspectOptions, MetadataKind, MetadataReport, Note, Retained, StripReport,
};

/// Removal of metadata from WebP images.
#[derive(Debug, Clone, Copy, Default)]
pub struct WebpHandler;

impl MetadataHandler for WebpHandler {
    fn name(&self) -> &'static str {
        Format::Webp.id()
    }

    fn format(&self) -> Format {
        Format::Webp
    }

    fn inspect(&self, input: &[u8], options: &InspectOptions) -> Result<MetadataReport> {
        // Inspection runs the identical pass that stripping does and throws the output away,
        // so "everything `strip` removes is something `inspect` can see" is true by
        // construction rather than by two code paths agreeing to stay in step — which is what
        // makes the pipeline's verification pass mean anything (`docs/ARCHITECTURE.md` §3).
        let processed = process(input, options, &ParseLimits::default())?;
        Ok(MetadataReport {
            format: Format::Webp,
            findings: processed.findings,
            notes: processed.notes,
        })
    }

    fn strip(&self, input: &[u8], options: &StripOptions) -> Result<Stripped> {
        let processed = process(input, &options.inspect, &options.limits)?;
        Ok(Stripped {
            report: StripReport {
                format: Format::Webp,
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

/// The RIFF container's code, and the form type that makes it a WebP file (§2.3).
const RIFF: &[u8; 4] = b"RIFF";
const WEBP: &[u8; 4] = b"WEBP";

/// Bytes in a chunk header: the four-character code and a 32-bit little-endian size (§2.3).
const CHUNK_HEADER_BYTES: usize = 8;

/// `VP8X`'s payload is exactly ten bytes — one of flags, three reserved, and the canvas width
/// and height each as a 24-bit value, both stored minus one (§2.7).
const VP8X_PAYLOAD_BYTES: u32 = 10;

/// Bytes of frame geometry, duration, and flags at the front of an `ANMF` payload, before the
/// frame's own sub-chunks begin (§2.7.1.1, Figure 9).
const ANMF_HEADER_BYTES: usize = 16;

/// The bits of `VP8X`'s flags byte that declare a metadata chunk is present.
///
/// §2.7 numbers the flags from the most significant bit: two reserved bits, then ICC profile,
/// alpha, Exif, XMP, animation, and one more reserved bit. This mask is ICC, Exif, and XMP —
/// the three whose chunks this handler removes. Alpha and animation describe the picture, not
/// the metadata, and are left exactly as they were.
const METADATA_FLAGS: u8 = 0b0010_1100;

/// A JPEG `APP1` Exif payload begins with this introducer; a WebP `EXIF` chunk's payload does
/// not — §2.7.1.5 says the payload is the Exif metadata itself. It is tolerated anyway,
/// because a producer that copies a JPEG's `APP1` payload across verbatim brings the
/// introducer with it, and feeding those six bytes to the TIFF reader shifts every offset
/// inside the block and yields a confident parse of the wrong bytes.
const EXIF_INTRODUCER: &[u8] = b"Exif\x00\x00";

/// Chunks that carry the picture itself, in a still image or in one animation frame.
///
/// Copied through byte for byte wherever they appear. `ALPH` is the alpha channel, `VP8 ` and
/// `VP8L` are the lossy and lossless bitstreams (§2.7.1.2–§2.7.1.4).
const IMAGE_CHUNKS: [&[u8; 4]; 3] = [b"ALPH", b"VP8 ", b"VP8L"];

/// One chunk, and the exact bytes it occupied.
struct Chunk<'a> {
    /// The four-character code.
    kind: [u8; 4],
    /// The payload, without the header or the RIFF padding byte around it.
    data: &'a [u8],
    /// The whole chunk as it appeared, header and padding included. Kept chunks are written
    /// out from this, which is what makes the copy exact.
    raw: &'a [u8],
}

/// The result of one pass over a file: what was found, and what the sanitised file looks like.
struct Processed {
    findings: Vec<Finding>,
    retained: Vec<Retained>,
    notes: Vec<Note>,
    output: Vec<u8>,
}

/// Split `input` into its chunks, plus anything after the RIFF chunk the header declared.
///
/// A file that does not parse is refused whole: there is no path here that returns a partial
/// chunk list for a caller to strip and write out.
fn walk<'a>(input: &'a [u8], limits: &ParseLimits) -> Result<(Vec<Chunk<'a>>, &'a [u8])> {
    let mut r = Reader::new(input);
    if r.take(RIFF.len()) != Some(RIFF.as_slice()) {
        return Err(malformed(MalformedDetail::MissingMarker, Some(0)));
    }

    // §2.3: the size counts the `WEBP` form type and every chunk after it, but not the eight
    // bytes of the RIFF header itself.
    let declared = r
        .u32_le()
        .ok_or_else(|| malformed(MalformedDetail::Truncated, Some(0)))?;
    let size = u32_to_usize(declared)
        .ok_or_else(|| malformed(MalformedDetail::LengthOutOfRange, as_offset(4)))?;
    if size < WEBP.len() || size > r.remaining() {
        // Refused rather than clamped to the real file length. A clamp turns a lying size
        // field into a silent parse of the wrong extent, and a "cleaned" copy of a truncated
        // file would be a repair the user never asked for, presented as a clean version.
        return Err(malformed(MalformedDetail::LengthOutOfRange, as_offset(4)));
    }

    let body_start = r.position();
    if r.take(WEBP.len()) != Some(WEBP.as_slice()) {
        return Err(malformed(
            MalformedDetail::MissingMarker,
            as_offset(body_start),
        ));
    }
    // Cannot overflow: `size <= r.remaining()` was checked at `body_start`.
    let end = body_start.saturating_add(size);

    let mut chunks: Vec<Chunk<'a>> = Vec::new();
    let mut budget = limits.max_items;

    while r.position() < end {
        if budget == 0 {
            return Err(StryptError::LimitExceeded {
                format: Format::Webp,
                limit: ResourceLimit::ItemCount,
            });
        }
        budget = budget.saturating_sub(1);

        let start = r.position();
        let kind: [u8; 4] = r
            .take(4)
            .and_then(|k| k.try_into().ok())
            .ok_or_else(|| malformed(MalformedDetail::Truncated, as_offset(start)))?;
        if !kind.iter().all(|b| b.is_ascii_graphic() || *b == b' ') {
            // A four-character code is ASCII by definition, and the defined ones include a
            // space (`VP8 `, `XMP `). Anything else means the walk is no longer where it
            // thinks it is, and continuing would be slicing arbitrary bytes out of a file
            // while reporting confidently about them.
            return Err(malformed(
                MalformedDetail::UnexpectedMarker,
                as_offset(start),
            ));
        }

        let declared = r
            .u32_le()
            .ok_or_else(|| malformed(MalformedDetail::Truncated, as_offset(start)))?;
        if &kind == b"VP8X" && declared != VP8X_PAYLOAD_BYTES {
            // §2.7 fixes this chunk's length. A different one means the flags byte and the
            // canvas dimensions are not where the specification puts them, so the handler
            // cannot correct the flags and must not guess.
            return Err(malformed(
                MalformedDetail::LengthOutOfRange,
                as_offset(start),
            ));
        }
        let length = u32_to_usize(declared)
            .ok_or_else(|| malformed(MalformedDetail::LengthOutOfRange, as_offset(start)))?;

        // §2.3: an odd-length payload is followed by one padding byte, which must be zero.
        let padding = length & 1;
        let padded = length
            .checked_add(padding)
            .ok_or_else(|| malformed(MalformedDetail::LengthOutOfRange, as_offset(start)))?;
        if padded > end.saturating_sub(r.position()) {
            // The chunk claims more than the RIFF size says is left, which is the field a
            // hostile file lies about.
            return Err(malformed(
                MalformedDetail::LengthOutOfRange,
                as_offset(start),
            ));
        }

        let data = r
            .take(length)
            .ok_or_else(|| malformed(MalformedDetail::LengthOutOfRange, as_offset(start)))?;
        r.skip(padding)
            .ok_or_else(|| malformed(MalformedDetail::Truncated, as_offset(start)))?;
        let raw = input.get(start..r.position()).unwrap_or_default();

        chunks.push(Chunk { kind, data, raw });
    }

    validate_shape(&chunks, body_start)?;
    Ok((chunks, input.get(end..).unwrap_or_default()))
}

/// Refuse a chunk list that is not a shape this handler has understood.
///
/// Both checks exist to stop the handler emitting something that passes for a WebP file and is
/// not one. The second matters most: a file consisting of nothing but a `VP8X` and an `EXIF`
/// chunk would otherwise strip to a container with no picture in it, and be reported as a
/// success.
fn validate_shape(chunks: &[Chunk<'_>], body_start: usize) -> Result<()> {
    // §2.7: an extended file opens with `VP8X`, and a simple file is one bitstream chunk.
    let opens_correctly =
        matches!(chunks.first(), Some(c) if matches!(&c.kind, b"VP8X" | b"VP8 " | b"VP8L"));
    if !opens_correctly {
        return Err(malformed(
            MalformedDetail::MissingMarker,
            as_offset(body_start),
        ));
    }
    let has_picture = chunks
        .iter()
        .any(|c| matches!(&c.kind, b"VP8 " | b"VP8L" | b"ANMF"));
    if !has_picture {
        return Err(malformed(
            MalformedDetail::MissingMarker,
            as_offset(body_start),
        ));
    }
    Ok(())
}

/// What to do with one chunk.
enum Outcome {
    /// Copy it through unchanged.
    Keep,
    /// Copy it through with the given bytes in its place. Used only by `VP8X`, and only when
    /// its flags no longer match what the file contains.
    Replace(Vec<u8>),
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

    let mut findings = Vec::new();
    let mut retained = Vec::new();
    let mut notes = Vec::new();

    // The RIFF payload is assembled first, because the size field in front of it is the one
    // field in a WebP file that cannot be copied and has to be computed.
    let mut body: Vec<u8> = Vec::with_capacity(input.len());
    body.extend_from_slice(WEBP);

    for chunk in &chunks {
        let decision = decide(chunk, options, limits);
        notes.extend(decision.notes);
        retained.extend(decision.retained);
        findings.extend(decision.findings);
        match decision.outcome {
            Outcome::Keep => body.extend_from_slice(chunk.raw),
            Outcome::Replace(bytes) => body.extend_from_slice(&bytes),
            Outcome::Drop => {}
        }
    }

    if !trailing.is_empty() {
        // Nothing reads past the length the RIFF header declares, and few users know anything
        // can be there. It is a convenient place to keep a second copy of an image whose
        // visible version was cropped.
        let kind = if trailing.starts_with(RIFF) {
            MetadataKind::Thumbnail
        } else {
            MetadataKind::Other
        };
        findings.push(Finding::new(
            kind,
            "trailing data after the RIFF chunk",
            as_u64(trailing.len()),
        ));
    }

    // Unreachable in practice: the output body is never larger than the input's declared RIFF
    // size, which was itself read as a `u32`. Written as a refusal rather than a saturating
    // cast because the alternative is a file whose size field lies.
    let size = u32::try_from(body.len())
        .map_err(|_| malformed(MalformedDetail::LengthOutOfRange, None))?;

    let mut output = Vec::with_capacity(body.len().saturating_add(CHUNK_HEADER_BYTES));
    output.extend_from_slice(RIFF);
    output.extend_from_slice(&size.to_le_bytes());
    output.extend_from_slice(&body);

    Ok(Processed {
        findings,
        retained,
        notes,
        output,
    })
}

/// Decide about one chunk.
fn decide(chunk: &Chunk<'_>, options: &InspectOptions, limits: &ParseLimits) -> Decision {
    let size = as_u64(chunk.data.len());
    match &chunk.kind {
        // The extended-format header. Kept, with its metadata flags corrected to match the
        // file it now describes.
        b"VP8X" => extended_header(chunk),
        // The picture, the alpha channel, and the animation's global parameters — background
        // colour and loop count, neither of which names anyone.
        b"VP8 " | b"VP8L" | b"ALPH" | b"ANIM" => Decision::keep(),
        // One animation frame, which is a container of its own.
        b"ANMF" => animation_frame(chunk),
        // An embedded ICC colour profile. A per-device profile is a fingerprint, and its
        // internal tags routinely carry the vendor, the model, and the calibration date.
        b"ICCP" => Decision::drop_one(MetadataKind::ColourProfile, "ICCP", size),
        b"EXIF" => exif_chunk(chunk.data, size, options, limits),
        b"XMP " => Decision::drop_with(xmp::scan(chunk.data, "XMP", options)),
        _ => {
            // §2.7.1.6 tells readers to ignore an unknown chunk and writers to preserve it.
            // strypt deliberately does the opposite of the second half: it is not a general
            // WebP writer, and an unknown chunk is precisely where a producer or an attacker
            // puts something they do not want a metadata tool to look at. A scrubber that
            // copies through what it does not understand is not scrubbing. Because the same
            // section makes unknown chunks ignorable, dropping one cannot break a decoder —
            // which is why this handler has no equivalent of PNG's unknown-critical-chunk
            // dilemma (ADR-0022).
            Decision::drop_one(MetadataKind::Other, name_of(&chunk.kind), size)
        }
    }
}

/// `VP8X`: the extended-format header, whose flags declare what else the file contains.
///
/// Copied byte for byte when its metadata bits are already clear, so an extended file with
/// nothing to remove still strips to an identical copy of itself. Otherwise the flags byte is
/// rewritten with those three bits cleared and every other byte of the chunk carried across
/// unchanged (ADR-0023).
fn extended_header(chunk: &Chunk<'_>) -> Decision {
    let Some(flags) = chunk.data.first().copied() else {
        // Unreachable: `walk` refuses a `VP8X` that is not exactly ten bytes long.
        return Decision::keep();
    };
    if flags & METADATA_FLAGS == 0 {
        return Decision::keep();
    }

    let mut rewritten = Vec::with_capacity(chunk.raw.len());
    rewritten.extend_from_slice(b"VP8X");
    rewritten.extend_from_slice(&VP8X_PAYLOAD_BYTES.to_le_bytes());
    rewritten.push(flags & !METADATA_FLAGS);
    // The reserved bits and the canvas dimensions. The payload is ten bytes, so it is even
    // and there is no padding byte to reproduce.
    rewritten.extend_from_slice(chunk.data.get(1..).unwrap_or_default());
    Decision {
        outcome: Outcome::Replace(rewritten),
        findings: Vec::new(),
        retained: Vec::new(),
        notes: Vec::new(),
    }
}

/// `ANMF`: one animation frame — a fixed header, then the frame's own sub-chunks.
///
/// §2.7.1.1 allows a frame to carry an optional list of *unknown* chunks alongside its alpha
/// and bitstream sub-chunks, which makes the inside of a frame a hiding place with the
/// specification's blessing. So the sub-chunk area is walked and filtered the same way the
/// top level is: the picture chunks are copied through byte for byte, anything else is
/// removed and reported.
///
/// The frame header is copied verbatim. Nothing in it depends on the sub-chunks that follow —
/// the frame's position, size, duration, and blending flags are all self-contained — so
/// dropping a sub-chunk cannot leave the header describing something that is no longer there.
///
/// A sub-chunk area that does not parse is left exactly as it arrived, with a note saying so.
/// Refusing the whole file would be the wrong call for a frame strypt only partly understands,
/// and silently keeping it would let the user believe the frame had been scrubbed.
fn animation_frame(chunk: &Chunk<'_>) -> Decision {
    let Some(header) = chunk.data.get(0..ANMF_HEADER_BYTES) else {
        return unexamined("ANMF", as_u64(chunk.data.len()));
    };
    let Some(rest) = chunk.data.get(ANMF_HEADER_BYTES..) else {
        return unexamined("ANMF", as_u64(chunk.data.len()));
    };

    let Some(sub_chunks) = walk_sub_chunks(rest) else {
        return unexamined("ANMF", as_u64(chunk.data.len()));
    };

    let mut findings = Vec::new();
    let mut payload = Vec::with_capacity(chunk.data.len());
    payload.extend_from_slice(header);
    for sub in &sub_chunks {
        if IMAGE_CHUNKS.contains(&&sub.kind) {
            payload.extend_from_slice(sub.raw);
        } else {
            findings.push(Finding::new(
                MetadataKind::Other,
                format!("ANMF {}", name_of(&sub.kind)),
                as_u64(sub.data.len()),
            ));
        }
    }

    if findings.is_empty() {
        // Nothing was dropped, so the frame is copied rather than reassembled — which keeps
        // an ordinary animation byte-identical through a strip.
        return Decision::keep();
    }

    let Ok(size) = u32::try_from(payload.len()) else {
        // Unreachable: the rebuilt payload is never larger than the one that was parsed.
        return unexamined("ANMF", as_u64(chunk.data.len()));
    };
    let mut rewritten = Vec::with_capacity(payload.len().saturating_add(CHUNK_HEADER_BYTES + 1));
    rewritten.extend_from_slice(b"ANMF");
    rewritten.extend_from_slice(&size.to_le_bytes());
    rewritten.extend_from_slice(&payload);
    if payload.len() & 1 == 1 {
        rewritten.push(0);
    }

    Decision {
        outcome: Outcome::Replace(rewritten),
        findings,
        retained: Vec::new(),
        notes: Vec::new(),
    }
}

/// Walk the sub-chunk area inside an `ANMF` payload, or [`None`] if it does not parse cleanly.
///
/// Deliberately total and deliberately strict: any short read, any lying length, and the whole
/// area is declared not understood rather than half-parsed.
fn walk_sub_chunks(data: &[u8]) -> Option<Vec<Chunk<'_>>> {
    let mut r = Reader::new(data);
    let mut out = Vec::new();
    while !r.is_empty() {
        let start = r.position();
        let kind: [u8; 4] = r.take(4)?.try_into().ok()?;
        if !kind.iter().all(|b| b.is_ascii_graphic() || *b == b' ') {
            return None;
        }
        let length = u32_to_usize(r.u32_le()?)?;
        let payload = r.take(length)?;
        r.skip(length & 1)?;
        out.push(Chunk {
            kind,
            data: payload,
            // Every iteration consumes at least the eight bytes of a header, so this loop
            // cannot spin on a zero-length chunk.
            raw: data.get(start..r.position())?,
        });
    }
    Some(out)
}

/// `EXIF`: a raw TIFF block, byte-order mark first.
fn exif_chunk(data: &[u8], size: u64, options: &InspectOptions, limits: &ParseLimits) -> Decision {
    let tiff = if data.starts_with(EXIF_INTRODUCER) {
        data.get(EXIF_INTRODUCER.len()..).unwrap_or_default()
    } else {
        data
    };
    let scanned = exif::scan(tiff, "EXIF", options, limits);
    let findings = if scanned.findings.is_empty() {
        // An Exif block that named nothing is still an Exif block, and it is still going.
        vec![Finding::new(MetadataKind::Other, "EXIF", size)]
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

/// Keep a region untouched and say plainly that its bytes went by unexamined.
fn unexamined(location: &'static str, bytes: u64) -> Decision {
    Decision {
        outcome: Outcome::Keep,
        findings: Vec::new(),
        retained: Vec::new(),
        notes: vec![Note::UnparsedRegion {
            location: location.to_owned(),
            bytes,
        }],
    }
}

/// A four-character code as a reportable name.
///
/// Trailing spaces are padding, not part of the name — the defined codes include `VP8 ` and
/// `XMP ` — and a report reads better without them.
fn name_of(kind: &[u8]) -> String {
    xmp::name_of(kind).trim_end().to_owned()
}

/// A malformed-file error for this format.
fn malformed(detail: MalformedDetail, offset: Option<u64>) -> StryptError {
    StryptError::Malformed {
        format: Format::Webp,
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
    use crate::report::MetadataValue;

    /// One chunk: code, little-endian size, payload, and a padding byte when the size is odd.
    fn chunk(kind: &[u8], data: &[u8]) -> Vec<u8> {
        let mut out = kind.to_vec();
        out.extend_from_slice(&u32::try_from(data.len()).unwrap().to_le_bytes());
        out.extend_from_slice(data);
        if data.len() % 2 == 1 {
            out.push(0);
        }
        out
    }

    /// A RIFF/WEBP container around the given chunks, with a correct size field.
    fn webp(chunks: &[Vec<u8>]) -> Vec<u8> {
        let mut body = WEBP.to_vec();
        for c in chunks {
            body.extend_from_slice(c);
        }
        let mut out = RIFF.to_vec();
        out.extend_from_slice(&u32::try_from(body.len()).unwrap().to_le_bytes());
        out.extend_from_slice(&body);
        out
    }

    /// A `VP8X` payload with the given flags and a 16x16 canvas.
    fn vp8x(flags: u8) -> Vec<u8> {
        let mut data = vec![flags, 0, 0, 0];
        data.extend_from_slice(&15u32.to_le_bytes()[0..3]);
        data.extend_from_slice(&15u32.to_le_bytes()[0..3]);
        chunk(b"VP8X", &data)
    }

    /// A stand-in lossless bitstream. Its contents are never parsed by this handler.
    fn bitstream() -> Vec<u8> {
        chunk(b"VP8L", b"SYNTHETIC-PIXELS")
    }

    fn strip_ok(data: &[u8]) -> Stripped {
        WebpHandler
            .strip(data, &StripOptions::default())
            .expect("strip failed")
    }

    fn findings(data: &[u8]) -> Vec<Finding> {
        WebpHandler
            .inspect(data, &InspectOptions::names_only())
            .expect("inspect failed")
            .findings
    }

    fn contains(haystack: &[u8], needle: &[u8]) -> bool {
        haystack.windows(needle.len()).any(|w| w == needle)
    }

    #[test]
    fn the_picture_is_never_touched() {
        let input = webp(&[
            vp8x(0b0000_1000),
            bitstream(),
            chunk(b"EXIF", b"II\x2A\x00\x08\x00\x00\x00\x00\x00"),
        ]);
        let output = strip_ok(&input).bytes;
        assert!(
            contains(&output, b"SYNTHETIC-PIXELS"),
            "the image data did not survive byte for byte"
        );
    }

    #[test]
    fn a_simple_file_cannot_carry_metadata_and_comes_back_byte_identical() {
        // A file with no `VP8X` has nowhere to put an ICC profile, Exif, or XMP: §2.7 requires
        // the extended header before any of them. So this is not merely "nothing was found" —
        // it is a guaranteed pass-through, and asserting it keeps that guarantee honest.
        for payload in [chunk(b"VP8L", b"SYNTHETIC-PIXELS"), chunk(b"VP8 ", b"ODD")] {
            let input = webp(&[payload]);
            let stripped = strip_ok(&input);
            assert!(stripped.report.removed.is_empty());
            assert_eq!(
                stripped.bytes, input,
                "a simple WebP was not passed through"
            );
        }
    }

    #[test]
    fn a_clean_extended_file_comes_back_byte_identical_too() {
        // The alpha and animation bits are not metadata flags, so a `VP8X` carrying only those
        // is copied rather than rewritten.
        let input = webp(&[vp8x(0b0001_0000), chunk(b"ALPH", b"A"), bitstream()]);
        let stripped = strip_ok(&input);
        assert!(stripped.report.removed.is_empty());
        assert_eq!(stripped.bytes, input);
    }

    #[test]
    fn the_metadata_chunks_are_removed_and_the_header_flags_follow() {
        let mut tiff = b"II\x2A\x00\x08\x00\x00\x00".to_vec();
        tiff.extend_from_slice(&1u16.to_le_bytes());
        tiff.extend_from_slice(&0x010Fu16.to_le_bytes()); // Make
        tiff.extend_from_slice(&2u16.to_le_bytes()); // ASCII
        tiff.extend_from_slice(&4u32.to_le_bytes());
        tiff.extend_from_slice(b"ACME");
        tiff.extend_from_slice(&0u32.to_le_bytes());

        // ICC, alpha, Exif, and XMP all declared.
        let input = webp(&[
            vp8x(0b0011_1100),
            chunk(b"ICCP", b"SYNTHETIC-PROFILE-0001"),
            chunk(b"ALPH", b"A"),
            bitstream(),
            chunk(b"EXIF", &tiff),
            chunk(
                b"XMP ",
                b"<x:xmpmeta><dc:creator>SYNTHETIC-0002</dc:creator></x:xmpmeta>",
            ),
        ]);

        let found = findings(&input);
        let kinds: Vec<MetadataKind> = found.iter().map(|f| f.kind).collect();
        assert!(kinds.contains(&MetadataKind::ColourProfile));
        assert!(kinds.contains(&MetadataKind::DeviceIdentity));
        assert!(kinds.contains(&MetadataKind::PersonalIdentity));

        let output = strip_ok(&input).bytes;
        assert!(!contains(&output, b"SYNTHETIC-PROFILE-0001"));
        assert!(!contains(&output, b"ACME"));
        assert!(!contains(&output, b"SYNTHETIC-0002"));
        assert!(findings(&output).is_empty());

        // The header now describes the file it is actually in: ICC, Exif, and XMP cleared,
        // alpha untouched.
        let flags = output[20];
        assert_eq!(
            flags, 0b0001_0000,
            "the VP8X flags still claim metadata that is gone"
        );
    }

    #[test]
    fn flags_that_were_already_lying_are_corrected_even_with_nothing_to_remove() {
        // A file whose header claims an Exif chunk it does not have. Nothing is removable, so
        // `show` reports nothing — and `strip` still hands back a file that tells the truth.
        let input = webp(&[vp8x(0b0000_1100), bitstream()]);
        let stripped = strip_ok(&input);
        assert!(stripped.report.removed.is_empty());
        assert_eq!(stripped.bytes[20], 0);
        assert_ne!(stripped.bytes, input);
    }

    #[test]
    fn an_exif_chunk_written_with_a_jpeg_introducer_is_still_read() {
        // The container specification puts no introducer here, but a producer copying a JPEG
        // `APP1` payload across brings one. Feeding those six bytes to the TIFF reader would
        // shift every offset in the block.
        let mut tiff = b"II\x2A\x00\x08\x00\x00\x00".to_vec();
        tiff.extend_from_slice(&1u16.to_le_bytes());
        tiff.extend_from_slice(&0x0110u16.to_le_bytes()); // Model
        tiff.extend_from_slice(&2u16.to_le_bytes());
        tiff.extend_from_slice(&4u32.to_le_bytes());
        tiff.extend_from_slice(b"MDL1");
        tiff.extend_from_slice(&0u32.to_le_bytes());

        let mut payload = EXIF_INTRODUCER.to_vec();
        payload.extend_from_slice(&tiff);
        let input = webp(&[vp8x(0b0000_1000), bitstream(), chunk(b"EXIF", &payload)]);

        let found = findings(&input);
        assert_eq!(found[0].field.as_deref(), Some("Model"));
    }

    #[test]
    fn an_unknown_chunk_is_removed_rather_than_preserved() {
        // §2.7.1.6 asks writers to preserve unknown chunks. strypt is not a general writer,
        // and an unknown chunk can hold anything at all.
        let input = webp(&[
            vp8x(0),
            bitstream(),
            chunk(b"PRVW", b"SYNTHETIC-PREVIEW-0003"),
        ]);
        let stripped = strip_ok(&input);
        assert!(!contains(&stripped.bytes, b"SYNTHETIC-PREVIEW-0003"));
        assert_eq!(stripped.report.removed[0].location, "PRVW");
    }

    #[test]
    fn an_animation_survives_and_a_chunk_hidden_in_a_frame_does_not() {
        let mut frame = vec![0u8; ANMF_HEADER_BYTES];
        frame.extend_from_slice(&chunk(b"VP8L", b"SYNTHETIC-FRAME-PIXELS"));
        let clean = webp(&[
            vp8x(0b0000_0010),
            chunk(b"ANIM", &[0, 0, 0, 0, 0, 0]),
            chunk(b"ANMF", &frame),
        ]);
        assert_eq!(strip_ok(&clean).bytes, clean, "an animation was rewritten");

        let mut hostile = vec![0u8; ANMF_HEADER_BYTES];
        hostile.extend_from_slice(&chunk(b"VP8L", b"SYNTHETIC-FRAME-PIXELS"));
        hostile.extend_from_slice(&chunk(b"JUNK", b"SYNTHETIC-IN-FRAME-0004"));
        let input = webp(&[
            vp8x(0b0000_0010),
            chunk(b"ANIM", &[0, 0, 0, 0, 0, 0]),
            chunk(b"ANMF", &hostile),
        ]);
        let stripped = strip_ok(&input);
        assert!(!contains(&stripped.bytes, b"SYNTHETIC-IN-FRAME-0004"));
        assert!(
            contains(&stripped.bytes, b"SYNTHETIC-FRAME-PIXELS"),
            "the frame's picture did not survive"
        );
        assert_eq!(stripped.report.removed[0].location, "ANMF JUNK");
    }

    #[test]
    fn a_frame_that_does_not_parse_is_kept_and_declared_unexamined() {
        let mut frame = vec![0u8; ANMF_HEADER_BYTES];
        frame.extend_from_slice(b"VP8L\xff\xff\xff\xffPRESERVED-0005");
        let input = webp(&[
            vp8x(0b0000_0010),
            chunk(b"ANIM", &[0, 0, 0, 0, 0, 0]),
            chunk(b"ANMF", &frame),
        ]);
        let stripped = strip_ok(&input);
        assert!(contains(&stripped.bytes, b"PRESERVED-0005"));
        assert!(matches!(
            stripped.report.notes.first(),
            Some(Note::UnparsedRegion { location, .. }) if location == "ANMF"
        ));
    }

    #[test]
    fn data_after_the_riff_chunk_is_removed() {
        let mut input = webp(&[vp8x(0), bitstream()]);
        input.extend_from_slice(b"SYNTHETIC-APPENDED-0006");
        let stripped = strip_ok(&input);
        assert!(!contains(&stripped.bytes, b"SYNTHETIC-APPENDED-0006"));
        assert_eq!(
            stripped.report.removed[0].location,
            "trailing data after the RIFF chunk"
        );
    }

    #[test]
    fn a_second_file_after_the_riff_chunk_is_reported_as_a_thumbnail() {
        let mut input = webp(&[vp8x(0), bitstream()]);
        input.extend_from_slice(&webp(&[bitstream()]));
        assert_eq!(
            strip_ok(&input).report.removed[0].kind,
            MetadataKind::Thumbnail
        );
    }

    #[test]
    fn an_xmp_packet_is_itemised_by_property() {
        let input = webp(&[
            vp8x(0b0000_0100),
            bitstream(),
            chunk(
                b"XMP ",
                br#"<x:xmpmeta xmpMM:DocumentID="uuid:1" xmp:CreatorTool="SYNTHETIC"/>"#,
            ),
        ]);
        let found = findings(&input);
        let fields: Vec<&str> = found.iter().filter_map(|f| f.field.as_deref()).collect();
        assert!(fields.contains(&"xmpMM:DocumentID"), "{fields:?}");
        assert!(fields.contains(&"xmp:CreatorTool"), "{fields:?}");
    }

    #[test]
    fn values_are_withheld_from_a_default_inspection() {
        let mut tiff = b"II\x2A\x00\x08\x00\x00\x00".to_vec();
        tiff.extend_from_slice(&1u16.to_le_bytes());
        tiff.extend_from_slice(&0x010Fu16.to_le_bytes());
        tiff.extend_from_slice(&2u16.to_le_bytes());
        tiff.extend_from_slice(&4u32.to_le_bytes());
        tiff.extend_from_slice(b"ACME");
        tiff.extend_from_slice(&0u32.to_le_bytes());
        let input = webp(&[vp8x(0b0000_1000), bitstream(), chunk(b"EXIF", &tiff)]);

        assert_eq!(findings(&input)[0].value, None);
        let with_values = WebpHandler
            .inspect(&input, &InspectOptions::with_values())
            .unwrap();
        assert_eq!(
            with_values.findings[0].value,
            Some(MetadataValue::Text("ACME".to_owned()))
        );
    }

    #[test]
    fn stripping_twice_changes_nothing() {
        let input = webp(&[
            vp8x(0b0011_1100),
            chunk(b"ICCP", b"SYNTHETIC-PROFILE-0001"),
            bitstream(),
            chunk(b"XMP ", b"<x:xmpmeta/>"),
        ]);
        let once = strip_ok(&input).bytes;
        let twice = strip_ok(&once).bytes;
        assert_eq!(once, twice, "strip is not idempotent");
    }

    #[test]
    fn a_riff_size_beyond_the_end_of_the_file_is_refused_rather_than_clamped() {
        let mut input = webp(&[vp8x(0), bitstream()]);
        input[4..8].copy_from_slice(&0x00FF_FFFFu32.to_le_bytes());
        assert!(matches!(
            WebpHandler.inspect(&input, &InspectOptions::names_only()),
            Err(StryptError::Malformed {
                detail: MalformedDetail::LengthOutOfRange,
                ..
            })
        ));
    }

    #[test]
    fn a_chunk_size_beyond_the_riff_extent_is_refused() {
        let input = webp(&[vp8x(0), bitstream(), {
            let mut lying = b"EXIF".to_vec();
            lying.extend_from_slice(&0x0010_0000u32.to_le_bytes());
            lying.extend_from_slice(b"II\x2A\x00");
            lying
        }]);
        assert!(matches!(
            WebpHandler.inspect(&input, &InspectOptions::names_only()),
            Err(StryptError::Malformed {
                detail: MalformedDetail::LengthOutOfRange,
                ..
            })
        ));
    }

    #[test]
    fn a_file_with_no_picture_chunk_is_refused_rather_than_emptied() {
        // Otherwise this strips to a valid-looking container with no image in it, and the user
        // is told it succeeded.
        let input = webp(&[
            vp8x(0b0000_1000),
            chunk(b"EXIF", b"II\x2A\x00\x08\x00\x00\x00"),
        ]);
        assert!(matches!(
            WebpHandler.strip(&input, &StripOptions::default()),
            Err(StryptError::Malformed {
                detail: MalformedDetail::MissingMarker,
                ..
            })
        ));
    }

    #[test]
    fn a_file_that_does_not_open_with_a_header_or_bitstream_chunk_is_refused() {
        let input = webp(&[chunk(b"EXIF", b"II\x2A\x00\x08\x00\x00\x00"), bitstream()]);
        assert!(matches!(
            WebpHandler.inspect(&input, &InspectOptions::names_only()),
            Err(StryptError::Malformed {
                detail: MalformedDetail::MissingMarker,
                ..
            })
        ));
    }

    #[test]
    fn a_vp8x_of_the_wrong_length_is_refused() {
        let input = webp(&[chunk(b"VP8X", &[0u8; 8]), bitstream()]);
        assert!(matches!(
            WebpHandler.inspect(&input, &InspectOptions::names_only()),
            Err(StryptError::Malformed {
                detail: MalformedDetail::LengthOutOfRange,
                ..
            })
        ));
    }

    #[test]
    fn a_four_character_code_that_is_not_ascii_is_refused() {
        let input = webp(&[vp8x(0), bitstream(), chunk(b"\x00\x01\x02\x03", b"")]);
        assert!(matches!(
            WebpHandler.inspect(&input, &InspectOptions::names_only()),
            Err(StryptError::Malformed {
                detail: MalformedDetail::UnexpectedMarker,
                ..
            })
        ));
    }

    #[test]
    fn a_file_that_is_not_riff_or_not_webp_is_refused() {
        assert!(matches!(
            WebpHandler.inspect(b"RIFX\x04\x00\x00\x00WEBP", &InspectOptions::names_only()),
            Err(StryptError::Malformed { .. })
        ));
        assert!(matches!(
            WebpHandler.inspect(b"RIFF\x04\x00\x00\x00WAVE", &InspectOptions::names_only()),
            Err(StryptError::Malformed {
                detail: MalformedDetail::MissingMarker,
                ..
            })
        ));
    }

    #[test]
    fn truncation_at_every_length_is_refused_or_survived_but_never_panics() {
        let input = webp(&[
            vp8x(0b0011_1100),
            chunk(b"ICCP", b"SYNTHETIC-PROFILE-0001"),
            bitstream(),
            chunk(b"EXIF", b"II\x2A\x00\x08\x00\x00\x00\x00\x00"),
            chunk(b"XMP ", b"<x:xmpmeta/>"),
        ]);
        for n in 0..=input.len() {
            let prefix = &input[0..n];
            let _ = WebpHandler.inspect(prefix, &InspectOptions::names_only());
            let _ = WebpHandler.strip(prefix, &StripOptions::default());
        }
    }

    #[test]
    fn a_chunk_count_beyond_the_limit_is_refused() {
        let mut chunks = vec![vp8x(0), bitstream()];
        chunks.extend((0..64).map(|_| chunk(b"JUNK", b"x")));
        let input = webp(&chunks);
        let options = StripOptions {
            limits: ParseLimits {
                max_items: 8,
                ..ParseLimits::default()
            },
            ..StripOptions::default()
        };
        assert!(matches!(
            WebpHandler.strip(&input, &options),
            Err(StryptError::LimitExceeded { .. })
        ));
    }

    #[test]
    fn an_odd_length_chunk_keeps_its_padding_byte() {
        // §2.3 pads an odd payload to an even boundary. A handler that dropped the pad when
        // copying a chunk through would shift every chunk after it by one byte.
        let input = webp(&[vp8x(0), chunk(b"VP8 ", b"ODD")]);
        let stripped = strip_ok(&input);
        assert_eq!(stripped.bytes, input);
        assert_eq!(stripped.bytes.len() % 2, 0);
    }
}
