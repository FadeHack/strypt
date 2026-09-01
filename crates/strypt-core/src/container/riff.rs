//! RIFF: a four-character code, a 32-bit little-endian size, a payload, and a pad byte when that
//! size is odd. The container under WebP and WAV, specified by "Multimedia Programming Interface
//! and Data Specifications 1.0" (IBM/Microsoft, 1991) and by RFC 9649 §2.3 for WebP.
//!
//! Generic, like [`super::bmff`]: nothing here knows that `EXIF` is metadata or what a `bext` is.
//! That lives in [`crate::formats::webp`] and [`crate::formats::wav`] (ADR-0039).
//!
//! Every length in a RIFF file was chosen by whoever wrote it. An overrun is refused rather than
//! clamped — a clamp turns a lying size field into a silent parse of the wrong extent — and the
//! pad byte is charged against the remaining extent before the payload is taken, so an odd length
//! at the very end of a file cannot walk past it.

use crate::bytes::{Reader, u32_to_usize};
use crate::error::{MalformedDetail, ResourceLimit};

/// A four-character code. Compared as bytes; the defined ones include a space (`VP8 `, `fmt `).
pub(crate) type FourCc = [u8; 4];

/// The code every RIFF file opens with.
pub(crate) const RIFF: FourCc = *b"RIFF";

/// A chunk header: the code and a 32-bit little-endian size.
pub(crate) const HEADER_BYTES: usize = 8;

/// Where a RIFF file's chunks begin: the header, then the four-byte form type.
pub(crate) const BODY_START: usize = HEADER_BYTES + 4;

/// One chunk, and the exact bytes it occupied.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Chunk<'a> {
    /// The four-character code.
    pub(crate) kind: FourCc,
    /// The payload, without the header or the pad byte around it.
    pub(crate) data: &'a [u8],
    /// The whole chunk as it appeared, header and pad byte included. Kept chunks are written out
    /// from this, which is what makes the copy exact.
    pub(crate) raw: &'a [u8],
    /// Where the chunk started, for reports only.
    pub(crate) offset: usize,
}

/// Why a walk stopped early.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum WalkError {
    /// The file violates the container's structure.
    Malformed {
        detail: MalformedDetail,
        offset: usize,
    },
    /// The file hit a parser ceiling.
    Limit(ResourceLimit),
}

impl WalkError {
    const fn at(detail: MalformedDetail, offset: usize) -> Self {
        Self::Malformed { detail, offset }
    }
}

/// Read a RIFF file of form type `form`: its chunks, plus anything past the declared extent.
///
/// Trailing data is handed back rather than parsed. Nothing reads past the length the header
/// declares, which makes it a convenient place to keep a second copy of something.
///
/// # Errors
///
/// [`WalkError`] if the magic or form type is wrong, if any declared size runs past the extent
/// that contains it, or if `budget` is exhausted.
pub(crate) fn read<'a>(
    input: &'a [u8],
    form: FourCc,
    budget: &mut u32,
) -> Result<(Vec<Chunk<'a>>, &'a [u8]), WalkError> {
    let mut r = Reader::new(input);
    if r.take(RIFF.len()) != Some(RIFF.as_slice()) {
        return Err(WalkError::at(MalformedDetail::MissingMarker, 0));
    }

    // The size counts the form type and every chunk after it, but not the eight bytes of header.
    let declared = r
        .u32_le()
        .ok_or(WalkError::at(MalformedDetail::Truncated, 0))?;
    let size = u32_to_usize(declared).ok_or(WalkError::at(MalformedDetail::LengthOutOfRange, 4))?;
    if size < form.len() || size > r.remaining() {
        return Err(WalkError::at(MalformedDetail::LengthOutOfRange, 4));
    }

    if r.take(form.len()) != Some(form.as_slice()) {
        return Err(WalkError::at(MalformedDetail::MissingMarker, HEADER_BYTES));
    }
    // Cannot overflow: `size <= r.remaining()` was checked at `HEADER_BYTES`.
    let end = HEADER_BYTES.saturating_add(size);

    let chunks = walk(input, BODY_START, end, 0, budget)?;
    Ok((chunks, input.get(end..).unwrap_or_default()))
}

/// Read a bare chunk sequence that fills `data` — a `LIST` body, or an animation frame's
/// sub-chunk area. `base` is `data`'s offset within the file, for reporting.
///
/// # Errors
///
/// As [`read`], minus the header checks.
pub(crate) fn chunks<'a>(
    data: &'a [u8],
    base: usize,
    budget: &mut u32,
) -> Result<Vec<Chunk<'a>>, WalkError> {
    walk(data, 0, data.len(), base, budget)
}

/// The shared walk: chunks tiling `input[start..end]` exactly.
fn walk<'a>(
    input: &'a [u8],
    start: usize,
    end: usize,
    base: usize,
    budget: &mut u32,
) -> Result<Vec<Chunk<'a>>, WalkError> {
    let mut r = Reader::new(input);
    r.skip(start)
        .ok_or(WalkError::at(MalformedDetail::Truncated, base))?;
    let mut out = Vec::new();

    while r.position() < end {
        let at = r.position();
        let offset = base.saturating_add(at);
        *budget = budget
            .checked_sub(1)
            .ok_or(WalkError::Limit(ResourceLimit::ItemCount))?;

        let kind: FourCc = r
            .take(4)
            .and_then(|k| k.try_into().ok())
            .ok_or(WalkError::at(MalformedDetail::Truncated, offset))?;
        if !kind.iter().all(|b| b.is_ascii_graphic() || *b == b' ') {
            // A four-character code is ASCII by definition. Anything else means the walk is no
            // longer where it thinks it is, and continuing would be slicing arbitrary bytes out
            // of a file while reporting confidently about them.
            return Err(WalkError::at(MalformedDetail::UnexpectedMarker, offset));
        }

        let declared = r
            .u32_le()
            .ok_or(WalkError::at(MalformedDetail::Truncated, offset))?;
        let length = u32_to_usize(declared)
            .ok_or(WalkError::at(MalformedDetail::LengthOutOfRange, offset))?;

        // An odd-length payload is followed by one pad byte, which must be zero.
        let padding = length & 1;
        let padded = length
            .checked_add(padding)
            .ok_or(WalkError::at(MalformedDetail::LengthOutOfRange, offset))?;
        if padded > end.saturating_sub(r.position()) {
            // The chunk claims more than the enclosing extent says is left, which is the field a
            // hostile file lies about.
            return Err(WalkError::at(MalformedDetail::LengthOutOfRange, offset));
        }

        let data = r
            .take(length)
            .ok_or(WalkError::at(MalformedDetail::LengthOutOfRange, offset))?;
        r.skip(padding)
            .ok_or(WalkError::at(MalformedDetail::Truncated, offset))?;

        out.push(Chunk {
            kind,
            data,
            // Every iteration consumes at least a header, so this loop cannot spin on a
            // zero-length chunk.
            raw: input.get(at..r.position()).unwrap_or_default(),
            offset,
        });
    }

    Ok(out)
}

/// A `LIST` chunk's form type and the chunk sequence after it, or [`None`] if it is too short.
pub(crate) fn list_form(data: &[u8]) -> Option<(FourCc, &[u8])> {
    let form: FourCc = data.get(..4)?.try_into().ok()?;
    Some((form, data.get(4..)?))
}

/// Write one chunk: code, little-endian size, payload, and a pad byte when the size is odd.
///
/// # Errors
///
/// [`MalformedDetail::LengthOutOfRange`] past what a 32-bit size can express.
pub(crate) fn write_chunk(
    out: &mut Vec<u8>,
    kind: FourCc,
    payload: &[u8],
) -> Result<(), MalformedDetail> {
    let size = u32::try_from(payload.len()).map_err(|_| MalformedDetail::LengthOutOfRange)?;
    out.extend_from_slice(&kind);
    out.extend_from_slice(&size.to_le_bytes());
    out.extend_from_slice(payload);
    if payload.len() & 1 == 1 {
        out.push(0);
    }
    Ok(())
}

/// Wrap `body` — everything after the form type — in a RIFF header.
///
/// The size field is the one field in a RIFF file that cannot be copied and has to be computed.
///
/// # Errors
///
/// As [`write_chunk`]. Written as a refusal rather than a saturating cast because the alternative
/// is a file whose size field lies.
pub(crate) fn write(form: FourCc, body: &[u8]) -> Result<Vec<u8>, MalformedDetail> {
    let size = body
        .len()
        .checked_add(form.len())
        .and_then(|n| u32::try_from(n).ok())
        .ok_or(MalformedDetail::LengthOutOfRange)?;
    let mut out = Vec::with_capacity(body.len().saturating_add(BODY_START));
    out.extend_from_slice(&RIFF);
    out.extend_from_slice(&size.to_le_bytes());
    out.extend_from_slice(&form);
    out.extend_from_slice(body);
    Ok(out)
}

/// A four-character code as a reportable name.
///
/// Trailing spaces are padding, not part of the name — the defined codes include `VP8 ` and
/// `fmt ` — and a report reads better without them.
pub(crate) fn name_of(kind: &[u8]) -> String {
    crate::formats::xmp::name_of(kind).trim_end().to_owned()
}

#[cfg(test)]
mod tests {
    // Test code is never reachable from untrusted bytes, which is the boundary the panic-freedom
    // lints police (ADR-0006).
    #![allow(
        clippy::unwrap_used,
        clippy::indexing_slicing,
        clippy::arithmetic_side_effects
    )]

    use super::*;

    fn chunk(kind: FourCc, payload: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        write_chunk(&mut out, kind, payload).unwrap();
        out
    }

    fn file(form: FourCc, parts: &[Vec<u8>]) -> Vec<u8> {
        let body: Vec<u8> = parts.concat();
        write(form, &body).unwrap()
    }

    #[test]
    fn a_flat_sequence_is_read_in_order() {
        let data = file(
            *b"WAVE",
            &[chunk(*b"fmt ", b"0123456789abcdef"), chunk(*b"data", b"AB")],
        );
        let mut budget = 64;
        let (chunks, trailing) = read(&data, *b"WAVE", &mut budget).unwrap();
        assert_eq!(chunks.len(), 2);
        assert_eq!(chunks[0].kind, *b"fmt ");
        assert_eq!(chunks[1].data, b"AB");
        assert_eq!(chunks[1].offset, BODY_START + 8 + 16);
        assert!(trailing.is_empty());
    }

    #[test]
    fn an_odd_payload_carries_a_pad_byte_that_the_raw_slice_includes() {
        let data = file(*b"WAVE", &[chunk(*b"data", b"ODD")]);
        let mut budget = 64;
        let (chunks, _) = read(&data, *b"WAVE", &mut budget).unwrap();
        assert_eq!(chunks[0].data, b"ODD");
        assert_eq!(chunks[0].raw.len(), HEADER_BYTES + 4);
    }

    #[test]
    fn a_declared_size_past_the_end_is_refused_not_clamped() {
        let mut data = file(*b"WAVE", &[chunk(*b"data", b"AB")]);
        data[4..8].copy_from_slice(&0x00FF_FFFFu32.to_le_bytes());
        let mut budget = 64;
        assert_eq!(
            read(&data, *b"WAVE", &mut budget),
            Err(WalkError::at(MalformedDetail::LengthOutOfRange, 4))
        );
    }

    #[test]
    fn a_chunk_overrunning_the_riff_extent_is_refused() {
        let mut lying = b"data".to_vec();
        lying.extend_from_slice(&0x0010_0000u32.to_le_bytes());
        lying.extend_from_slice(b"AB");
        let data = file(*b"WAVE", &[lying]);
        let mut budget = 64;
        assert!(matches!(
            read(&data, *b"WAVE", &mut budget),
            Err(WalkError::Malformed {
                detail: MalformedDetail::LengthOutOfRange,
                ..
            })
        ));
    }

    #[test]
    fn the_wrong_magic_or_form_type_is_refused() {
        let mut budget = 64;
        assert_eq!(
            read(b"RIFX\x04\x00\x00\x00WAVE", *b"WAVE", &mut budget),
            Err(WalkError::at(MalformedDetail::MissingMarker, 0))
        );
        assert_eq!(
            read(b"RIFF\x04\x00\x00\x00WEBP", *b"WAVE", &mut budget),
            Err(WalkError::at(MalformedDetail::MissingMarker, HEADER_BYTES))
        );
    }

    #[test]
    fn a_code_that_is_not_ascii_is_refused() {
        let mut raw = b"\x00\x01\x02\x03".to_vec();
        raw.extend_from_slice(&0u32.to_le_bytes());
        let data = file(*b"WAVE", &[raw]);
        let mut budget = 64;
        assert_eq!(
            read(&data, *b"WAVE", &mut budget),
            Err(WalkError::at(MalformedDetail::UnexpectedMarker, BODY_START))
        );
    }

    #[test]
    fn the_item_budget_is_shared_across_the_walk() {
        let parts: Vec<Vec<u8>> = (0..5).map(|_| chunk(*b"JUNK", b"xx")).collect();
        let data = file(*b"WAVE", &parts);
        let mut budget = 3;
        assert_eq!(
            read(&data, *b"WAVE", &mut budget),
            Err(WalkError::Limit(ResourceLimit::ItemCount))
        );
    }

    #[test]
    fn bytes_past_the_declared_extent_are_handed_back() {
        let mut data = file(*b"WAVE", &[chunk(*b"data", b"AB")]);
        data.extend_from_slice(b"APPENDED");
        let mut budget = 64;
        let (chunks, trailing) = read(&data, *b"WAVE", &mut budget).unwrap();
        assert_eq!(chunks.len(), 1);
        assert_eq!(trailing, b"APPENDED");
    }

    #[test]
    fn a_list_body_walks_as_a_bare_sequence() {
        let mut body = b"INFO".to_vec();
        body.extend_from_slice(&chunk(*b"ISFT", b"SYNTHETIC\0"));
        let (form, rest) = list_form(&body).unwrap();
        assert_eq!(form, *b"INFO");
        let mut budget = 64;
        let inner = chunks(rest, 100, &mut budget).unwrap();
        assert_eq!(inner[0].kind, *b"ISFT");
        assert_eq!(inner[0].offset, 100);
    }

    #[test]
    fn what_this_module_writes_it_can_read_back() {
        // A writer that emits something its own reader refuses is a defect worth catching cheaply.
        let data = file(
            *b"WAVE",
            &[chunk(*b"fmt ", &[0u8; 16]), chunk(*b"data", b"ODD")],
        );
        let mut budget = 64;
        let (chunks, trailing) = read(&data, *b"WAVE", &mut budget).unwrap();
        assert_eq!(chunks.len(), 2);
        assert!(trailing.is_empty());
        let rebuilt: Vec<u8> = chunks.iter().flat_map(|c| c.raw.to_vec()).collect();
        assert_eq!(write(*b"WAVE", &rebuilt).unwrap(), data);
    }

    #[test]
    fn names_drop_the_padding_space() {
        assert_eq!(name_of(b"fmt "), "fmt");
        assert_eq!(name_of(b"bext"), "bext");
    }
}
