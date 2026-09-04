//! The ISO base media file format's box tree (ISO/IEC 14496-12): a size, a four-character type,
//! a payload, some types containing further boxes.
//!
//! Generic, like [`super::zip`]: nothing here knows what `iloc` is for or that `Exif` is metadata.
//! That lives in [`crate::formats::heif`]. Group 4's MP4 and ADR-0032's JPEG XL tranche spell the
//! same container, so a second caller is expected.
//!
//! Not a general-purpose implementation — it exists to get safely through a container (ADR-0028's
//! framing, applied to a second one). Sizes are attacker-chosen: an overrun is refused rather than
//! clamped, a box smaller than its own header is refused rather than looping forever, and descent
//! is bounded because stack overflow aborts the process and cannot be caught.

use crate::bytes::Reader;
use crate::error::{MalformedDetail, ResourceLimit};

/// A four-character box type. Compared as bytes: several real ones are not printable ASCII.
pub(crate) type BoxType = [u8; 4];

/// How many bytes a box header occupies before its payload.
const SHORT_HEADER: u64 = 8;
/// The same, when the size field is the 64-bit escape.
const LONG_HEADER: u64 = 16;
/// A full box carries a one-byte version and three flag bytes before its payload.
pub(crate) const FULL_BOX_PREFIX: usize = 4;

/// One box, located within the slice it was read from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Box<'a> {
    /// The four-character type.
    pub(crate) kind: BoxType,
    /// Everything after the header. A full box's version and flags are still at the front; use
    /// [`Box::full`] to split them off.
    pub(crate) payload: &'a [u8],
    /// Offset from the start of the file, for reports only — no output offset derives from it.
    pub(crate) offset: u64,
    /// The box's total size including its header.
    pub(crate) size: u64,
    /// How many bytes the header took: 8, or 16 for the 64-bit escape. Recorded so a caller can
    /// re-emit a box in the form it arrived in — [`write_box`] only ever writes the short one
    /// (ADR-0042).
    pub(crate) header: u64,
}

impl<'a> Box<'a> {
    /// Split a full box's version and flags off its payload. [`None`] if it is too short.
    pub(crate) fn full(&self) -> Option<(u8, u32, &'a [u8])> {
        let head = self.payload.get(..FULL_BOX_PREFIX)?;
        let rest = self.payload.get(FULL_BOX_PREFIX..)?;
        let version = *head.first()?;
        // Three bytes, big-endian, widened into the low 24 bits.
        let flags = u32::from(*head.get(1)?) << 16
            | u32::from(*head.get(2)?) << 8
            | u32::from(*head.get(3)?);
        Some((version, flags, rest))
    }

    /// True when this box's type is `kind`.
    pub(crate) fn is(&self, kind: BoxType) -> bool {
        self.kind == kind
    }
}

/// Why a walk stopped early.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum WalkError {
    /// The tree violates the format's structure.
    Malformed(MalformedDetail),
    /// The tree hit a parser ceiling.
    Limit(ResourceLimit),
}

/// Read the boxes directly inside `data`. `base` is its offset within the file, for reporting.
///
/// Trailing bytes too short for a header are an error here, not a clean parse — see [`top_level`],
/// which treats them differently.
///
/// # Errors
///
/// [`WalkError`] on an inconsistent size, a box smaller than its own header, or an exhausted
/// `budget`.
pub(crate) fn children<'a>(
    data: &'a [u8],
    base: u64,
    budget: &mut u32,
) -> Result<Vec<Box<'a>>, WalkError> {
    let mut r = Reader::new(data);
    let mut out = Vec::new();

    while !r.is_empty() {
        let start = r.position();
        // Fewer than eight bytes left cannot be a box. This is the trailing-garbage case.
        if r.remaining() < 8 {
            return Err(WalkError::Malformed(MalformedDetail::Truncated));
        }
        *budget = budget
            .checked_sub(1)
            .ok_or(WalkError::Limit(ResourceLimit::ItemCount))?;

        let declared = r
            .u32_be()
            .ok_or(WalkError::Malformed(MalformedDetail::Truncated))?;
        let kind: BoxType = r
            .take(4)
            .and_then(|b| b.try_into().ok())
            .ok_or(WalkError::Malformed(MalformedDetail::Truncated))?;

        // §4.2: 1 escapes to a 64-bit size, 0 runs to the end of the parent, else total size.
        let (size, header) = match declared {
            1 => {
                let b: [u8; 8] = r
                    .take(8)
                    .and_then(|b| b.try_into().ok())
                    .ok_or(WalkError::Malformed(MalformedDetail::Truncated))?;
                (u64::from_be_bytes(b), LONG_HEADER)
            }
            // §4.2: run to the end of the parent. Legal for the last box only.
            0 => (as_u64(data.len().saturating_sub(start)), SHORT_HEADER),
            n => (u64::from(n), SHORT_HEADER),
        };

        // The non-termination case: a zero or negative advance walks the same offset forever.
        if size < header {
            return Err(WalkError::Malformed(MalformedDetail::LengthOutOfRange));
        }
        let payload_len = usize::try_from(size.saturating_sub(header))
            .map_err(|_| WalkError::Malformed(MalformedDetail::LengthOutOfRange))?;
        let payload = r
            .take(payload_len)
            .ok_or(WalkError::Malformed(MalformedDetail::LengthOutOfRange))?;

        out.push(Box {
            kind,
            payload,
            offset: base.saturating_add(as_u64(start)),
            size,
            header,
        });
    }

    Ok(out)
}

/// Read the top-level boxes, returning trailing bytes separately.
///
/// Fewer than eight bytes left over is appended data, not a malformed tree — a place to hide
/// something, handed back to report and drop as the JPEG handler does after `EOI` (§7.2). An
/// overrunning box is still an error.
///
/// # Errors
///
/// As [`children`].
pub(crate) fn top_level<'a>(
    data: &'a [u8],
    budget: &mut u32,
) -> Result<(Vec<Box<'a>>, &'a [u8]), WalkError> {
    // Walk whole boxes for as long as one fits, then hand back whatever could not be one.
    let mut consumed = 0usize;
    loop {
        let rest = data.get(consumed..).unwrap_or_default();
        if rest.len() < 8 {
            let head = data.get(..consumed).unwrap_or_default();
            let boxes = children(head, 0, budget)?;
            return Ok((boxes, rest));
        }
        let declared = rest
            .get(..4)
            .and_then(|b| <[u8; 4]>::try_from(b).ok())
            .map(u32::from_be_bytes)
            .ok_or(WalkError::Malformed(MalformedDetail::Truncated))?;
        let size = match declared {
            // Left to `children`, which already reads them.
            0 | 1 => data.len(),
            n => consumed.saturating_add(usize::try_from(n).unwrap_or(usize::MAX)),
        };
        if size <= consumed || size > data.len() {
            // The boxes stopped tiling here, so the rest is appended data. Telling that from a
            // *truncated* file is not this function's job and it does not try: the caller resolves
            // every item's extents against the file, so a real truncation is caught there as an
            // offset falling outside it rather than being waved through as trailing junk.
            let head = data.get(..consumed).unwrap_or_default();
            let boxes = children(head, 0, budget)?;
            return Ok((boxes, data.get(consumed..).unwrap_or_default()));
        }
        consumed = size;
        if consumed == data.len() {
            let boxes = children(data, 0, budget)?;
            return Ok((boxes, &[]));
        }
    }
}

/// Read a container box's children, charging the descent against `depth`.
///
/// # Errors
///
/// As [`children`], plus [`ResourceLimit::Depth`].
pub(crate) fn children_at<'a>(
    parent: &Box<'a>,
    payload: &'a [u8],
    depth: u32,
    budget: &mut u32,
) -> Result<Vec<Box<'a>>, WalkError> {
    if depth == 0 {
        return Err(WalkError::Limit(ResourceLimit::Depth));
    }
    let consumed = parent.size.saturating_sub(as_u64(payload.len()));
    children(payload, parent.offset.saturating_add(consumed), budget)
}

/// The box's own bytes, header included, as they appear in `file`.
///
/// Offsets are file-absolute throughout a walk that started at [`top_level`], so this resolves for
/// a nested box as well as a top-level one. [`None`] when they do not — a caller that walked a
/// detached slice gets nothing rather than somebody else's bytes.
pub(crate) fn raw<'a>(file: &'a [u8], b: &Box<'_>) -> Option<&'a [u8]> {
    let start = usize::try_from(b.offset).ok()?;
    let end = start.checked_add(usize::try_from(b.size).ok()?)?;
    file.get(start..end)
}

/// Find the first child of `kind`.
pub(crate) fn find<'a, 'b>(boxes: &'b [Box<'a>], kind: BoxType) -> Option<&'b Box<'a>> {
    boxes.iter().find(|b| b.is(kind))
}

/// Widen a slice length for offset arithmetic.
fn as_u64(value: usize) -> u64 {
    u64::try_from(value).unwrap_or(u64::MAX)
}

/// Write a box, back-filling its size once `body` has produced the payload.
///
/// # Errors
///
/// [`MalformedDetail::LengthOutOfRange`] past what a 32-bit size can express. The 64-bit escape is
/// deliberately never written.
pub(crate) fn write_box<F>(out: &mut Vec<u8>, kind: BoxType, body: F) -> Result<(), MalformedDetail>
where
    F: FnOnce(&mut Vec<u8>) -> Result<(), MalformedDetail>,
{
    let start = out.len();
    out.extend_from_slice(&[0, 0, 0, 0]);
    out.extend_from_slice(&kind);
    body(out)?;
    let size = out
        .len()
        .checked_sub(start)
        .ok_or(MalformedDetail::LengthOutOfRange)?;
    let size = u32::try_from(size).map_err(|_| MalformedDetail::LengthOutOfRange)?;
    let bytes = size.to_be_bytes();
    // One byte at a time: range indexing is denied here (ADR-0006).
    for (i, byte) in bytes.iter().enumerate() {
        let at = start
            .checked_add(i)
            .ok_or(MalformedDetail::LengthOutOfRange)?;
        let slot = out.get_mut(at).ok_or(MalformedDetail::LengthOutOfRange)?;
        *slot = *byte;
    }
    Ok(())
}

/// Write a full box: version, three flag bytes, then `body`.
///
/// # Errors
///
/// As [`write_box`].
pub(crate) fn write_full_box<F>(
    out: &mut Vec<u8>,
    kind: BoxType,
    version: u8,
    flags: u32,
    body: F,
) -> Result<(), MalformedDetail>
where
    F: FnOnce(&mut Vec<u8>) -> Result<(), MalformedDetail>,
{
    write_box(out, kind, |out| {
        out.push(version);
        // Low 24 bits, big-endian.
        let f = flags.to_be_bytes();
        out.extend_from_slice(f.get(1..4).unwrap_or(&[0, 0, 0]));
        body(out)
    })
}

#[cfg(test)]
mod tests {
    // Test code is never reachable from untrusted bytes, which is the boundary the panic-freedom
    // lints police (ADR-0006). A test that cannot index or add says everything twice instead, and
    // the noise hides the assertion that matters.
    #![allow(
        clippy::unwrap_used,
        clippy::indexing_slicing,
        clippy::arithmetic_side_effects
    )]

    use super::*;

    /// Build a box with a 32-bit size.
    fn boxed(kind: [u8; 4], payload: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        let size = u32::try_from(payload.len() + 8).unwrap();
        out.extend_from_slice(&size.to_be_bytes());
        out.extend_from_slice(&kind);
        out.extend_from_slice(payload);
        out
    }

    #[test]
    fn a_flat_sequence_is_read_in_order() {
        let mut data = boxed(*b"ftyp", b"avif");
        data.extend_from_slice(&boxed(*b"mdat", b"picture"));
        let mut budget = 64;
        let boxes = children(&data, 0, &mut budget).unwrap();
        assert_eq!(boxes.len(), 2);
        assert!(boxes.first().unwrap().is(*b"ftyp"));
        assert_eq!(boxes.get(1).unwrap().payload, b"picture");
        assert_eq!(boxes.get(1).unwrap().offset, 12);
    }

    #[test]
    fn a_box_smaller_than_its_own_header_is_refused() {
        // The non-termination case. A declared size of 4 would advance the cursor by less than
        // the header just consumed, and a walker that clamped instead of refusing would read the
        // same offset until the process was killed.
        let data = [0, 0, 0, 4, b'f', b't', b'y', b'p'];
        let mut budget = 64;
        assert_eq!(
            children(&data, 0, &mut budget),
            Err(WalkError::Malformed(MalformedDetail::LengthOutOfRange))
        );
    }

    #[test]
    fn a_size_running_past_the_end_is_refused_not_clamped() {
        let mut data = boxed(*b"mdat", b"short");
        // Claim far more than is present.
        data.splice(0..4, 0xFFFF_u32.to_be_bytes());
        let mut budget = 64;
        assert_eq!(
            children(&data, 0, &mut budget),
            Err(WalkError::Malformed(MalformedDetail::LengthOutOfRange))
        );
    }

    #[test]
    fn trailing_bytes_too_short_for_a_header_are_a_finding_not_a_clean_parse() {
        let mut data = boxed(*b"ftyp", b"avif");
        data.extend_from_slice(&[0, 0, 0]);
        let mut budget = 64;
        assert_eq!(
            children(&data, 0, &mut budget),
            Err(WalkError::Malformed(MalformedDetail::Truncated))
        );
    }

    #[test]
    fn a_size_of_zero_runs_to_the_end_of_the_parent() {
        // §4.2 allows it for the last box only, which is what "to the end" means in practice.
        let mut data = vec![0, 0, 0, 0];
        data.extend_from_slice(b"mdat");
        data.extend_from_slice(b"rest of the file");
        let mut budget = 64;
        let boxes = children(&data, 0, &mut budget).unwrap();
        assert_eq!(boxes.len(), 1);
        assert_eq!(boxes.first().unwrap().payload, b"rest of the file");
    }

    #[test]
    fn the_sixty_four_bit_size_escape_is_read() {
        let mut data = vec![0, 0, 0, 1];
        data.extend_from_slice(b"mdat");
        data.extend_from_slice(&24_u64.to_be_bytes());
        data.extend_from_slice(b"payload!");
        let mut budget = 64;
        let boxes = children(&data, 0, &mut budget).unwrap();
        assert_eq!(boxes.first().unwrap().payload, b"payload!");
    }

    #[test]
    fn the_item_budget_is_shared_across_the_walk() {
        let mut data = Vec::new();
        for _ in 0..5 {
            data.extend_from_slice(&boxed(*b"free", b""));
        }
        let mut budget = 3;
        assert_eq!(
            children(&data, 0, &mut budget),
            Err(WalkError::Limit(ResourceLimit::ItemCount))
        );
    }

    #[test]
    fn descent_is_refused_at_the_depth_ceiling() {
        let data = boxed(*b"meta", b"");
        let mut budget = 64;
        let parent = *children(&data, 0, &mut budget).unwrap().first().unwrap();
        assert_eq!(
            children_at(&parent, parent.payload, 0, &mut budget),
            Err(WalkError::Limit(ResourceLimit::Depth))
        );
    }

    #[test]
    fn a_full_box_splits_its_version_and_flags() {
        let data = boxed(*b"meta", &[1, 0, 0, 7, b'r', b'e', b's', b't']);
        let mut budget = 64;
        let boxes = children(&data, 0, &mut budget).unwrap();
        let (version, flags, rest) = boxes.first().unwrap().full().unwrap();
        assert_eq!(version, 1);
        assert_eq!(flags, 7);
        assert_eq!(rest, b"rest");
    }

    #[test]
    fn a_full_box_too_short_for_its_prefix_yields_none() {
        let data = boxed(*b"meta", &[1, 0]);
        let mut budget = 64;
        let boxes = children(&data, 0, &mut budget).unwrap();
        assert!(boxes.first().unwrap().full().is_none());
    }

    #[test]
    fn appended_bytes_too_short_for_a_box_are_handed_back_rather_than_refused() {
        // At the top level this is somebody appending data to a finished file, which is a place
        // to hide something. The caller reports and drops it; refusing the whole file would tell
        // a user their photograph was corrupt.
        let mut data = boxed(*b"ftyp", b"avif");
        data.extend_from_slice(&boxed(*b"mdat", b"pic"));
        data.extend_from_slice(b"xyz");
        let mut budget = 64;
        let (boxes, trailing) = top_level(&data, &mut budget).unwrap();
        assert_eq!(boxes.len(), 2);
        assert_eq!(trailing, b"xyz");
    }

    #[test]
    fn a_file_that_ends_on_a_box_boundary_has_no_trailing_bytes() {
        let data = boxed(*b"ftyp", b"avif");
        let mut budget = 64;
        let (boxes, trailing) = top_level(&data, &mut budget).unwrap();
        assert_eq!(boxes.len(), 1);
        assert!(trailing.is_empty());
    }

    #[test]
    fn a_top_level_box_that_overruns_ends_the_tiling() {
        // Where the boxes stop tiling, the rest is handed back rather than parsed. This is not
        // leniency about a lying size: the caller resolves every item extent against the file, so
        // a truncated file is refused there. What it avoids is refusing a whole photograph
        // because somebody appended a few bytes to it.
        let mut good = boxed(*b"ftyp", b"avif");
        let mut overrunning = boxed(*b"mdat", b"short");
        overrunning.splice(0..4, 0xFFFF_u32.to_be_bytes());
        good.extend_from_slice(&overrunning);
        let mut budget = 64;
        let (boxes, trailing) = top_level(&good, &mut budget).unwrap();
        assert_eq!(boxes.len(), 1, "only the box that tiled is returned");
        assert_eq!(trailing.len(), overrunning.len());
    }

    #[test]
    fn a_box_hands_back_its_own_bytes_in_the_header_form_it_arrived_in() {
        // What ADR-0042 needs to copy an `mdat` through untouched: a large one carries a 64-bit
        // header, and `write_box` would silently re-emit it as a short one.
        let mut data = vec![0, 0, 0, 1];
        data.extend_from_slice(b"mdat");
        data.extend_from_slice(&24_u64.to_be_bytes());
        data.extend_from_slice(b"payload!");
        let mut budget = 64;
        let boxes = children(&data, 0, &mut budget).unwrap();
        let b = boxes.first().unwrap();
        assert_eq!(b.header, LONG_HEADER);
        assert_eq!(raw(&data, b).unwrap(), &data[..]);
    }

    #[test]
    fn a_nested_box_resolves_against_the_file_it_came_from() {
        let inner = boxed(*b"hdlr", b"vide");
        let outer = boxed(*b"mdia", &inner);
        let mut budget = 64;
        let top = children(&outer, 0, &mut budget).unwrap();
        let parent = *top.first().unwrap();
        let kids = children_at(&parent, parent.payload, 8, &mut budget).unwrap();
        assert_eq!(raw(&outer, kids.first().unwrap()).unwrap(), &inner[..]);
    }

    #[test]
    fn what_this_module_writes_it_can_read_back() {
        // The round trip the ZIP layer's fuzz target asserts, made a unit test here: a writer
        // that emits something its own reader refuses is a defect worth catching cheaply.
        let mut out = Vec::new();
        write_box(&mut out, *b"ftyp", |o| {
            o.extend_from_slice(b"avif");
            Ok(())
        })
        .unwrap();
        write_full_box(&mut out, *b"meta", 0, 0, |o| {
            write_box(o, *b"hdlr", |i| {
                i.extend_from_slice(b"pict");
                Ok(())
            })
        })
        .unwrap();

        let mut budget = 64;
        let boxes = children(&out, 0, &mut budget).unwrap();
        assert_eq!(boxes.len(), 2);
        let meta = find(&boxes, *b"meta").unwrap();
        let (_, _, rest) = meta.full().unwrap();
        let inner = children_at(meta, rest, 8, &mut budget).unwrap();
        assert!(inner.first().unwrap().is(*b"hdlr"));
        assert_eq!(inner.first().unwrap().payload, b"pict");
    }
}
