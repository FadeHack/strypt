//! Ogg pages: the container under Vorbis, Opus and FLAC-in-Ogg, specified by RFC 3533.
//!
//! Generic, like [`super::riff`] and [`super::bmff`]: nothing here knows what a Vorbis comment is
//! or which packet carries one. That lives in [`crate::formats::ogg`] (ADR-0041).
//!
//! Two things shape this module. Each page carries a CRC over itself, so nothing can be edited in
//! place and the reader can check that its walk is where it thinks it is. And a granule position
//! belongs to a *page*, not a packet — it timestamps the last packet finishing on that page — so
//! [`packets`] records which packet closed which page and [`write`] puts it back there.

use crate::bytes::Reader;
use crate::error::{MalformedDetail, ResourceLimit};

/// The capture pattern every page opens with (§6.1).
pub(crate) const MAGIC: &[u8; 4] = b"OggS";

/// The only stream structure version RFC 3533 defines.
const VERSION: u8 = 0;

/// Header type flags (§6.2): a continued packet, the first page, the last page.
pub(crate) const CONTINUED: u8 = 0x01;
pub(crate) const BOS: u8 = 0x02;
pub(crate) const EOS: u8 = 0x04;

/// "No packet finishes on this page", spelled as a −1 granule position (§6.2).
pub(crate) const NO_GRANULE: u64 = u64::MAX;

/// A page header up to and including the segment count.
const HEADER_BYTES: usize = 27;

/// Where the CRC sits within the header, and how wide it is.
const CRC_AT: usize = 22;
const CRC_LEN: usize = 4;

/// Where the header type flags sit.
const FLAGS_AT: usize = 5;

/// A lacing table holds at most 255 values, each at most 255 (§6.2).
const MAX_SEGMENTS: usize = 255;
const MAX_SEGMENT: usize = 255;

/// The generator polynomial (§6.2). Unreflected, zero-initialised, no final xor — which is why no
/// general-purpose CRC-32 is the same function.
const POLY: u32 = 0x04c1_1db7;

/// One page, as it appeared.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Page<'a> {
    pub(crate) flags: u8,
    pub(crate) granule: u64,
    pub(crate) serial: u32,
    /// The lacing table: the segment lengths this page's body is chopped into.
    pub(crate) lacing: &'a [u8],
    pub(crate) body: &'a [u8],
    pub(crate) offset: usize,
}

/// One complete packet, and where it sat in the page structure.
pub(crate) struct Packet<'a> {
    /// The packet's bytes, one entry per page it was spread over.
    pub(crate) fragments: Vec<&'a [u8]>,
    pub(crate) len: usize,
    /// The granule position of the page this packet finished on.
    pub(crate) granule: u64,
    /// True when this was the last packet to finish on its page, which is what makes
    /// [`Self::granule`] its own rather than a later packet's.
    pub(crate) ends_page: bool,
}

impl<'a> Packet<'a> {
    /// The packet as one contiguous slice, copying only when it was spread over pages.
    pub(crate) fn bytes(&self) -> std::borrow::Cow<'a, [u8]> {
        match self.fragments.as_slice() {
            [single] => std::borrow::Cow::Borrowed(single),
            many => std::borrow::Cow::Owned(many.concat()),
        }
    }
}

/// Why a walk stopped early.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum WalkError {
    Malformed {
        detail: MalformedDetail,
        offset: usize,
    },
    Limit(ResourceLimit),
}

impl WalkError {
    const fn at(detail: MalformedDetail, offset: usize) -> Self {
        Self::Malformed { detail, offset }
    }
}

/// The Ogg CRC of `data` (§6.2), with the CRC field taken as already zeroed.
///
/// Bitwise rather than table-driven: a 256-entry table would have to be built by indexing, and
/// eight shifts a byte is not the cost that matters in a metadata tool.
pub(crate) fn crc(data: &[u8]) -> u32 {
    continue_crc(0, data)
}

/// Every page in `input`, which must be pages and nothing else.
///
/// Leading or trailing bytes are refused rather than handed back the way [`super::riff::read`]
/// hands back a trailer: an Ogg file is a sequence of pages by definition, and a run of arbitrary
/// bytes wrapped around one is where something would be hidden from a walk that skipped to the
/// first capture pattern (ADR-0041).
///
/// # Errors
///
/// [`WalkError`] if the file is not pages, if a page's CRC does not match, or if `budget` runs out.
pub(crate) fn pages<'a>(input: &'a [u8], budget: &mut u32) -> Result<Vec<Page<'a>>, WalkError> {
    let mut r = Reader::new(input);
    let mut out: Vec<Page<'a>> = Vec::new();

    while r.remaining() > 0 {
        let at = r.position();
        *budget = budget
            .checked_sub(1)
            .ok_or(WalkError::Limit(ResourceLimit::ItemCount))?;

        let header = r
            .peek(HEADER_BYTES)
            .ok_or(WalkError::at(MalformedDetail::Truncated, at))?;
        if header.get(..MAGIC.len()) != Some(MAGIC.as_slice()) {
            return Err(WalkError::at(MalformedDetail::MissingMarker, at));
        }
        if header.get(4) != Some(&VERSION) {
            return Err(WalkError::at(MalformedDetail::UnexpectedMarker, at));
        }
        r.skip(MAGIC.len().saturating_add(1))
            .ok_or(WalkError::at(MalformedDetail::Truncated, at))?;

        let flags = r
            .u8()
            .ok_or(WalkError::at(MalformedDetail::Truncated, at))?;
        let granule = u64_le(&mut r).ok_or(WalkError::at(MalformedDetail::Truncated, at))?;
        let serial = r
            .u32_le()
            .ok_or(WalkError::at(MalformedDetail::Truncated, at))?;
        // The sequence number is read and discarded: it is renumbered on the way out, so keeping
        // it would only invite a comparison that means nothing (ADR-0041 decision 4).
        let _sequence = r
            .u32_le()
            .ok_or(WalkError::at(MalformedDetail::Truncated, at))?;
        let declared_crc = r
            .u32_le()
            .ok_or(WalkError::at(MalformedDetail::Truncated, at))?;
        let segments = r
            .u8()
            .ok_or(WalkError::at(MalformedDetail::Truncated, at))?;

        let lacing = r
            .take(usize::from(segments))
            .ok_or(WalkError::at(MalformedDetail::Truncated, at))?;
        // At most 255 values of at most 255, so this cannot overflow.
        let body_len = lacing
            .iter()
            .fold(0usize, |sum, n| sum.saturating_add(usize::from(*n)));
        let body = r
            .take(body_len)
            .ok_or(WalkError::at(MalformedDetail::LengthOutOfRange, at))?;

        let raw = input
            .get(at..r.position())
            .ok_or(WalkError::at(MalformedDetail::Truncated, at))?;
        if computed_crc(raw) != declared_crc {
            // The one field in a page that proves the walk landed on a real header rather than on
            // four bytes that happened to spell `OggS` inside a payload.
            return Err(WalkError::at(MalformedDetail::UnexpectedMarker, at));
        }

        out.push(Page {
            flags,
            granule,
            serial,
            lacing,
            body,
            offset: at,
        });
    }

    if out.is_empty() {
        return Err(WalkError::at(MalformedDetail::MissingMarker, 0));
    }
    Ok(out)
}

/// A page's CRC with the field itself taken as zero, without copying the page.
fn computed_crc(raw: &[u8]) -> u32 {
    let head = raw.get(..CRC_AT).unwrap_or_default();
    let tail = raw
        .get(CRC_AT.saturating_add(CRC_LEN)..)
        .unwrap_or_default();
    let mut r = crc(head);
    // Continuing a bitwise CRC across three pieces is just running it over them in order.
    r = continue_crc(r, &[0u8; CRC_LEN]);
    r = continue_crc(r, tail);
    r
}

/// [`crc`], resumed from `state`.
fn continue_crc(state: u32, data: &[u8]) -> u32 {
    let mut r = state;
    for byte in data {
        r ^= u32::from(*byte).wrapping_shl(24);
        for _ in 0..8 {
            r = if r & 0x8000_0000 == 0 {
                r.wrapping_shl(1)
            } else {
                r.wrapping_shl(1) ^ POLY
            };
        }
    }
    r
}

/// Assemble `pages` into complete packets.
///
/// A page whose last segment is 255 continues its packet onto the next page; anything shorter ends
/// one (§6.2). A packet still open at the end of the last page is refused — its remainder is
/// somewhere this file does not contain.
///
/// # Errors
///
/// [`WalkError`] if a page continues a packet nothing started, if a page carrying a real granule
/// finishes no packet, or if the stream ends mid-packet.
pub(crate) fn packets<'a>(pages: &[Page<'a>]) -> Result<Vec<Packet<'a>>, WalkError> {
    let mut out: Vec<Packet<'a>> = Vec::new();
    let mut open: Option<Packet<'a>> = None;

    for page in pages {
        if (page.flags & CONTINUED == 0) != open.is_none() {
            // The flag and the state have to agree: a continuation with nothing open, or an open
            // packet the next page does not claim, means the walk lost the packet boundary.
            return Err(WalkError::at(
                MalformedDetail::UnexpectedMarker,
                page.offset,
            ));
        }

        let mut finished_here = 0usize;
        let mut r = Reader::new(page.body);
        for value in page.lacing {
            let piece = r
                .take(usize::from(*value))
                .ok_or(WalkError::at(MalformedDetail::Truncated, page.offset))?;
            let mut packet = open.take().unwrap_or(Packet {
                fragments: Vec::new(),
                len: 0,
                granule: NO_GRANULE,
                ends_page: false,
            });
            if !piece.is_empty() {
                packet.fragments.push(piece);
            }
            packet.len = packet.len.saturating_add(piece.len());
            if usize::from(*value) == MAX_SEGMENT {
                open = Some(packet);
            } else {
                packet.granule = page.granule;
                out.push(packet);
                finished_here = finished_here.saturating_add(1);
            }
        }

        if finished_here == 0 {
            if page.granule != NO_GRANULE {
                // §6.2 spells "no packet finishes here" as −1. A real granule on such a page is a
                // timestamp for nothing, and dropping the page would silently drop it (ADR-0041).
                return Err(WalkError::at(
                    MalformedDetail::UnexpectedMarker,
                    page.offset,
                ));
            }
        } else if let Some(last) = out.last_mut() {
            last.ends_page = true;
        }
    }

    if open.is_some() {
        return Err(WalkError::at(
            MalformedDetail::Truncated,
            pages.last().map_or(0, |p| p.offset),
        ));
    }
    if out.is_empty() {
        return Err(WalkError::at(MalformedDetail::MissingMarker, 0));
    }
    Ok(out)
}

/// A packet on its way out: its bytes, and the page structure it belongs to.
pub(crate) struct Emit<'a> {
    pub(crate) fragments: Vec<&'a [u8]>,
    pub(crate) len: usize,
    pub(crate) granule: u64,
    pub(crate) ends_page: bool,
}

impl<'a> Emit<'a> {
    /// Carry a packet through unchanged.
    pub(crate) fn copied(packet: &Packet<'a>) -> Self {
        Self {
            fragments: packet.fragments.clone(),
            len: packet.len,
            granule: packet.granule,
            ends_page: packet.ends_page,
        }
    }

    /// Replace a packet's bytes, keeping its place in the page structure.
    pub(crate) fn replacing(packet: &Packet<'a>, bytes: &'a [u8]) -> Self {
        Self {
            fragments: vec![bytes],
            len: bytes.len(),
            granule: packet.granule,
            ends_page: packet.ends_page,
        }
    }
}

/// Write `packets` as a single logical bitstream under `serial`.
///
/// Pages are closed where the input closed them, so every granule position stays attached to the
/// packet it timestamps (ADR-0041 decision 3). A packet too long for one page's lacing table is
/// spread over as many as it needs, and those pages carry −1 as §6.2 requires.
///
/// # Errors
///
/// [`MalformedDetail::LengthOutOfRange`] past what a 32-bit page sequence can count.
pub(crate) fn write(serial: u32, packets: &[Emit<'_>]) -> Result<Vec<u8>, MalformedDetail> {
    let mut w = Writer {
        serial,
        sequence: 0,
        out: Vec::new(),
        lacing: Vec::new(),
        body: Vec::new(),
        continued: false,
        last_page_at: None,
    };
    for packet in packets {
        w.packet(packet)?;
    }
    w.finish()
}

/// The page-building state of one [`write`].
struct Writer {
    serial: u32,
    sequence: u32,
    out: Vec<u8>,
    lacing: Vec<u8>,
    body: Vec<u8>,
    continued: bool,
    last_page_at: Option<usize>,
}

impl Writer {
    /// Lay one packet into the current page, closing pages as the lacing table fills or as the
    /// packet's own page boundary says.
    fn packet(&mut self, packet: &Emit<'_>) -> Result<(), MalformedDetail> {
        let mut cursor = Cursor {
            parts: &packet.fragments,
            part: 0,
            at: 0,
        };
        let mut written = 0usize;
        loop {
            if self.lacing.len() >= MAX_SEGMENTS {
                self.flush(NO_GRANULE)?;
                self.continued = true;
            }
            let take = MAX_SEGMENT.min(packet.len.saturating_sub(written));
            cursor.take(take, &mut self.body);
            self.lacing.push(u8::try_from(take).unwrap_or(0));
            written = written.saturating_add(take);
            if take < MAX_SEGMENT {
                break;
            }
        }
        if packet.ends_page {
            self.flush(packet.granule)?;
        }
        Ok(())
    }

    /// Emit the accumulated segments as one page.
    fn flush(&mut self, granule: u64) -> Result<(), MalformedDetail> {
        let mut flags = 0u8;
        if self.continued {
            flags |= CONTINUED;
        }
        if self.sequence == 0 {
            flags |= BOS;
        }
        let segments = u8::try_from(self.lacing.len()).map_err(|_| {
            // Unreachable by construction — `packet` flushes at 255 — and a refusal rather than a
            // truncating cast, because the cast would write a page whose lacing table lies.
            MalformedDetail::LengthOutOfRange
        })?;

        let at = self.out.len();
        self.out.extend_from_slice(MAGIC);
        self.out.push(VERSION);
        self.out.push(flags);
        self.out.extend_from_slice(&granule.to_le_bytes());
        self.out.extend_from_slice(&self.serial.to_le_bytes());
        self.out.extend_from_slice(&self.sequence.to_le_bytes());
        self.out.extend_from_slice(&[0u8; CRC_LEN]);
        self.out.push(segments);
        self.out.extend_from_slice(&self.lacing);
        self.out.extend_from_slice(&self.body);
        stamp_crc(&mut self.out, at);

        self.sequence = self
            .sequence
            .checked_add(1)
            .ok_or(MalformedDetail::LengthOutOfRange)?;
        self.lacing.clear();
        self.body.clear();
        self.continued = false;
        self.last_page_at = Some(at);
        Ok(())
    }

    /// Close any open page and mark the last one as the end of the stream.
    fn finish(mut self) -> Result<Vec<u8>, MalformedDetail> {
        if !self.lacing.is_empty() {
            self.flush(NO_GRANULE)?;
        }
        let at = self.last_page_at.ok_or(MalformedDetail::Truncated)?;
        if let Some(flags) = self.out.get_mut(at.saturating_add(FLAGS_AT)) {
            *flags |= EOS;
        }
        stamp_crc(&mut self.out, at);
        Ok(self.out)
    }
}

/// Recompute the CRC of the page beginning at `at` and write it into its header.
fn stamp_crc(out: &mut [u8], at: usize) {
    let crc_at = at.saturating_add(CRC_AT);
    if let Some(field) = out.get_mut(crc_at..crc_at.saturating_add(CRC_LEN)) {
        field.fill(0);
    }
    let value = crc(out.get(at..).unwrap_or_default());
    if let Some(field) = out.get_mut(crc_at..crc_at.saturating_add(CRC_LEN)) {
        field.copy_from_slice(&value.to_le_bytes());
    }
}

/// Re-stamp every page [`pages`] could frame from the start, stopping at the first it could not.
#[cfg(feature = "fuzzing")]
pub(crate) fn restamp(data: &mut [u8]) {
    let mut at = 0usize;
    loop {
        let Some(header) = data.get(at..at.saturating_add(HEADER_BYTES)) else {
            return;
        };
        if header.get(..MAGIC.len()) != Some(MAGIC.as_slice()) {
            return;
        }
        let segments = usize::from(header.last().copied().unwrap_or_default());
        let lacing_at = at.saturating_add(HEADER_BYTES);
        let body_at = lacing_at.saturating_add(segments);
        let Some(lacing) = data.get(lacing_at..body_at) else {
            return;
        };
        let end = lacing
            .iter()
            .fold(body_at, |sum, n| sum.saturating_add(usize::from(*n)));
        let Some(page) = data.get_mut(at..end) else {
            return;
        };
        stamp_crc(page, 0);
        at = end;
    }
}

/// A read position across a packet's fragments.
struct Cursor<'a> {
    parts: &'a [&'a [u8]],
    part: usize,
    at: usize,
}

impl Cursor<'_> {
    /// Copy the next `n` bytes into `out`, stopping early if the fragments run out.
    fn take(&mut self, n: usize, out: &mut Vec<u8>) {
        let mut left = n;
        while left > 0 {
            let Some(part) = self.parts.get(self.part) else {
                return;
            };
            let Some(rest) = part.get(self.at..) else {
                return;
            };
            if rest.is_empty() {
                self.part = self.part.saturating_add(1);
                self.at = 0;
                continue;
            }
            let take = left.min(rest.len());
            out.extend_from_slice(rest.get(..take).unwrap_or_default());
            self.at = self.at.saturating_add(take);
            left = left.saturating_sub(take);
        }
    }
}

/// Read a 64-bit little-endian value.
fn u64_le(r: &mut Reader<'_>) -> Option<u64> {
    let bytes: [u8; 8] = r.take(8)?.try_into().ok()?;
    Some(u64::from_le_bytes(bytes))
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

    /// One page, with its CRC filled in.
    fn page(flags: u8, granule: u64, serial: u32, sequence: u32, packets: &[&[u8]]) -> Vec<u8> {
        let mut lacing = Vec::new();
        let mut body = Vec::new();
        for packet in packets {
            let mut written = 0;
            loop {
                let take = 255.min(packet.len() - written);
                lacing.push(u8::try_from(take).unwrap());
                body.extend_from_slice(&packet[written..written + take]);
                written += take;
                if take < 255 {
                    break;
                }
            }
        }
        let mut out = MAGIC.to_vec();
        out.push(0);
        out.push(flags);
        out.extend_from_slice(&granule.to_le_bytes());
        out.extend_from_slice(&serial.to_le_bytes());
        out.extend_from_slice(&sequence.to_le_bytes());
        out.extend_from_slice(&[0u8; 4]);
        out.push(u8::try_from(lacing.len()).unwrap());
        out.extend_from_slice(&lacing);
        out.extend_from_slice(&body);
        stamp_crc(&mut out, 0);
        out
    }

    /// A page carrying a packet fragment that continues onto the next one: every lacing value is
    /// 255, which is how "not finished here" is spelled (§6.2).
    fn page_continuing(flags: u8, serial: u32, sequence: u32, fragment: &[u8]) -> Vec<u8> {
        assert_eq!(
            fragment.len() % 255,
            0,
            "a continuing fragment fills its segments"
        );
        let mut out = MAGIC.to_vec();
        out.push(0);
        out.push(flags);
        out.extend_from_slice(&NO_GRANULE.to_le_bytes());
        out.extend_from_slice(&serial.to_le_bytes());
        out.extend_from_slice(&sequence.to_le_bytes());
        out.extend_from_slice(&[0u8; 4]);
        let segments = fragment.len() / 255;
        out.push(u8::try_from(segments).unwrap());
        out.extend_from_slice(&vec![255u8; segments]);
        out.extend_from_slice(fragment);
        stamp_crc(&mut out, 0);
        out
    }

    fn walk(data: &[u8]) -> Result<Vec<Page<'_>>, WalkError> {
        let mut budget = 4096;
        pages(data, &mut budget)
    }

    #[test]
    fn the_crc_matches_the_value_rfc_3533_defines() {
        // The specification's polynomial with no reflection and no final xor, which is why no
        // general-purpose CRC-32 produces it. Checked against a page ffmpeg wrote.
        assert_eq!(crc(b""), 0);
        assert_eq!(crc(b"OggS"), 0x5FB0_A94F);
    }

    #[test]
    fn a_page_round_trips_through_the_walker() {
        let data = page(BOS | EOS, 42, 7, 0, &[b"HELLO"]);
        let read = walk(&data).unwrap();
        assert_eq!(read.len(), 1);
        assert_eq!(read[0].granule, 42);
        assert_eq!(read[0].serial, 7);
        assert_eq!(read[0].body, b"HELLO");
    }

    #[test]
    fn a_page_whose_crc_does_not_match_is_refused() {
        // The evidence that the walk is on a real header rather than four bytes spelling `OggS`
        // inside a payload.
        let mut data = page(BOS | EOS, 0, 1, 0, &[b"HELLO"]);
        let at = data.len() - 1;
        data[at] ^= 0xFF;
        assert_eq!(
            walk(&data),
            Err(WalkError::at(MalformedDetail::UnexpectedMarker, 0))
        );
    }

    #[cfg(feature = "fuzzing")]
    #[test]
    fn restamp_repairs_every_framed_page_and_stops_at_a_truncated_one() {
        let mut data = page(BOS, 0, 1, 0, &[b"HELLO"]);
        data.extend_from_slice(&page(EOS, 0, 1, 1, &[b"WORLD"]));
        let first = data.len() / 2;
        data[first - 1] ^= 0xFF;
        let last = data.len() - 1;
        data[last] ^= 0xFF;
        assert!(walk(&data).is_err());

        restamp(&mut data);
        assert_eq!(walk(&data).unwrap().len(), 2);

        let mut truncated = data[..data.len() - 1].to_vec();
        truncated[first - 1] ^= 0xFF;
        let tail = truncated[first..].to_vec();
        restamp(&mut truncated);
        assert!(walk(&truncated[..first]).is_ok());
        assert_eq!(
            truncated[first..],
            tail,
            "a page it cannot frame is left alone"
        );
    }

    #[test]
    fn bytes_wrapped_around_the_pages_are_refused_rather_than_handed_back() {
        let mut data = b"PREFIX".to_vec();
        data.extend_from_slice(&page(BOS | EOS, 0, 1, 0, &[b"HELLO"]));
        assert!(matches!(
            walk(&data),
            Err(WalkError::Malformed {
                detail: MalformedDetail::MissingMarker,
                ..
            })
        ));

        let mut trailing = page(BOS | EOS, 0, 1, 0, &[b"HELLO"]);
        trailing.extend_from_slice(b"APPENDED");
        assert!(walk(&trailing).is_err());
    }

    #[test]
    fn a_packet_spread_over_pages_is_reassembled() {
        let long: Vec<u8> = (0..600u32)
            .map(|n| u8::try_from(n % 251).unwrap())
            .collect();
        let mut data = page_continuing(BOS, 1, 0, &long[0..510]);
        data.extend_from_slice(&page(CONTINUED | EOS, 99, 1, 1, &[&long[510..]]));
        let read = walk(&data).unwrap();
        let assembled = packets(&read).unwrap();
        assert_eq!(assembled.len(), 1);
        assert_eq!(assembled[0].bytes().as_ref(), long.as_slice());
        assert_eq!(assembled[0].granule, 99);
        assert!(assembled[0].ends_page);
    }

    #[test]
    fn a_page_that_finishes_nothing_must_say_so_with_a_minus_one_granule() {
        let long: Vec<u8> = vec![0x5A; 600];
        let mut data = page_continuing(BOS, 1, 0, &long[0..510]);
        // Overwrite the −1 with a real granule: a page that finishes nothing has nothing to stamp.
        data[6..14].copy_from_slice(&12_345u64.to_le_bytes());
        stamp_crc(&mut data, 0);
        data.extend_from_slice(&page(CONTINUED | EOS, 99, 1, 1, &[&long[510..]]));
        let read = walk(&data).unwrap();
        assert!(matches!(
            packets(&read),
            Err(WalkError::Malformed {
                detail: MalformedDetail::UnexpectedMarker,
                ..
            })
        ));
    }

    #[test]
    fn a_stream_ending_mid_packet_is_refused() {
        let data = page_continuing(BOS | EOS, 1, 0, &[0x5A; 255]);
        let read = walk(&data).unwrap();
        assert!(matches!(
            packets(&read),
            Err(WalkError::Malformed {
                detail: MalformedDetail::Truncated,
                ..
            })
        ));
    }

    #[test]
    fn what_this_module_writes_it_can_read_back() {
        let long: Vec<u8> = (0..900u32)
            .map(|n| u8::try_from(n % 251).unwrap())
            .collect();
        let mut data = page(BOS, 0, 0xDEAD, 0, &[b"HEAD"]);
        data.extend_from_slice(&page_continuing(0, 0xDEAD, 1, &long[0..765]));
        data.extend_from_slice(&page(CONTINUED | EOS, 4096, 0xDEAD, 2, &[&long[765..]]));

        let read = walk(&data).unwrap();
        let assembled = packets(&read).unwrap();
        let emitted: Vec<Emit<'_>> = assembled.iter().map(Emit::copied).collect();
        let written = write(0, &emitted).unwrap();

        let again = packets(&walk(&written).unwrap()).unwrap();
        assert_eq!(again.len(), assembled.len());
        for (before, after) in assembled.iter().zip(&again) {
            assert_eq!(before.bytes(), after.bytes());
            assert_eq!(before.granule, after.granule);
        }
    }

    #[test]
    fn the_written_stream_is_flagged_and_numbered_from_zero() {
        let data = page(BOS | EOS, 5, 0x1234_5678, 900, &[b"ONE", b"TWO"]);
        let read = walk(&data).unwrap();
        let assembled = packets(&read).unwrap();
        let emitted: Vec<Emit<'_>> = assembled.iter().map(Emit::copied).collect();
        let written = write(0, &emitted).unwrap();

        let out = walk(&written).unwrap();
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].serial, 0, "the serial was not rewritten");
        assert_eq!(out[0].flags, BOS | EOS);
        assert_eq!(written.get(18..22), Some(&0u32.to_le_bytes()[..]));
    }

    #[test]
    fn a_packet_longer_than_one_page_is_spread_and_the_carrier_pages_say_minus_one() {
        let long: Vec<u8> = vec![0x33; 70_000];
        let emitted = vec![Emit {
            fragments: vec![&long],
            len: long.len(),
            granule: 1000,
            ends_page: true,
        }];
        let written = write(0, &emitted).unwrap();
        let read = walk(&written).unwrap();
        assert!(read.len() > 1, "the packet was not spread");
        assert_eq!(read[0].granule, NO_GRANULE);
        assert_eq!(read[read.len() - 1].granule, 1000);
        let assembled = packets(&read).unwrap();
        assert_eq!(assembled[0].bytes().as_ref(), long.as_slice());
    }

    #[test]
    fn a_zero_length_packet_survives_the_round_trip() {
        // Opus writes them for dropped frames, and a lacing value of zero is how they are spelled.
        let data = page(BOS | EOS, 1, 1, 0, &[b"", b"AB"]);
        let assembled = packets(&walk(&data).unwrap()).unwrap();
        assert_eq!(assembled.len(), 2);
        assert_eq!(assembled[0].len, 0);
        let emitted: Vec<Emit<'_>> = assembled.iter().map(Emit::copied).collect();
        let written = write(0, &emitted).unwrap();
        assert_eq!(packets(&walk(&written).unwrap()).unwrap().len(), 2);
    }

    #[test]
    fn a_wrong_stream_structure_version_is_refused() {
        let mut data = page(BOS | EOS, 0, 1, 0, &[b"HELLO"]);
        data[4] = 1;
        assert_eq!(
            walk(&data),
            Err(WalkError::at(MalformedDetail::UnexpectedMarker, 0))
        );
    }

    #[test]
    fn the_page_budget_is_charged() {
        let mut data = Vec::new();
        for n in 0..5u32 {
            data.extend_from_slice(&page(0, u64::from(n), 1, n, &[b"X"]));
        }
        let mut budget = 3;
        assert_eq!(
            pages(&data, &mut budget),
            Err(WalkError::Limit(ResourceLimit::ItemCount))
        );
    }

    #[test]
    fn truncation_at_every_length_is_refused_but_never_panics() {
        let mut data = page(BOS, 0, 1, 0, &[b"HEAD"]);
        data.extend_from_slice(&page(EOS, 10, 1, 1, &[b"AUDIO"]));
        for n in 0..=data.len() {
            let mut budget = 4096;
            if let Ok(read) = pages(&data[0..n], &mut budget) {
                let _ = packets(&read);
            }
        }
    }
}
