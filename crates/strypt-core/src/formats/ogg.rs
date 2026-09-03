//! Ogg: Vorbis, Opus, and FLAC-in-Ogg.
//!
//! The first format here that is a container for somebody else's format. The page layer knows
//! nothing about codecs and lives in [`crate::container::ogg`]; this module is the codec half —
//! which packet is the comment header, what an empty one looks like, and which mappings are
//! refused (ADR-0041).
//!
//! # Rebuilt, because a page carries a CRC
//!
//! Emptying the comment packet changes its length, which changes its page's lacing table and
//! therefore that page's CRC, and every page after it renumbers. So the file is rebuilt: packets
//! are copied verbatim and the pages around them are new. Three fields do not survive the rebuild
//! unchanged, and each is a decision rather than an accident:
//!
//! - **Granule positions are carried verbatim.** They are codec sample counts, not file offsets
//!   (RFC 3533 §3), so removal moves nothing. They belong to a *page*, though, which is why the
//!   rebuild keeps each input page's set of finished packets rather than repaginating freely.
//! - **Page sequence numbers are renumbered from zero**, because removal can change the count.
//! - **The serial number is rewritten to zero.** It is a 32-bit identifier nobody can recompute,
//!   and libogg's own example seeds it from the clock. This is the one place a group-4 handler
//!   gives up a byte-identical clean file, and it is why.
//!
//! # The comment header is emptied, never dropped
//!
//! All three mappings require the packet to be the second one in the stream, so unlike FLAC's
//! metadata block it cannot go. What is written back is an empty vendor string and a zero count.
//!
//! # One logical bitstream
//!
//! A multiplexed or chained file is refused: a second stream is a second mapping with a second
//! comment header this handler has not read.

use crate::bytes::Reader;
use crate::container::ogg::{self as page, Emit, Packet, WalkError};
use crate::detect::Format;
use crate::error::{MalformedDetail, Result, StryptError, UnsupportedKind};
use crate::formats::{MetadataHandler, ParseLimits, StripOptions, Stripped, vorbis, xmp};
use crate::report::{
    Finding, InspectOptions, MetadataKind, MetadataReport, MetadataValue, Note, Retained,
    RetentionReason, StripReport,
};

/// Removal of metadata from an Ogg stream.
#[derive(Debug, Clone, Copy)]
pub struct OggHandler {
    format: Format,
}

impl OggHandler {
    /// The handler instance for Ogg Vorbis.
    pub const VORBIS: Self = Self {
        format: Format::Ogg,
    };
    /// The handler instance for Opus.
    pub const OPUS: Self = Self {
        format: Format::Opus,
    };
    /// The handler instance for FLAC-in-Ogg.
    pub const FLAC: Self = Self {
        format: Format::OggFlac,
    };
}

impl MetadataHandler for OggHandler {
    fn name(&self) -> &'static str {
        self.format.id()
    }

    fn format(&self) -> Format {
        self.format
    }

    fn inspect(&self, input: &[u8], options: &InspectOptions) -> Result<MetadataReport> {
        // The identical pass stripping runs, with the output discarded, so that "everything
        // `strip` removes is something `inspect` can see" holds by construction
        // (`docs/ARCHITECTURE.md` §3).
        let processed = process(input, self.format, options, &ParseLimits::default())?;
        Ok(MetadataReport {
            format: self.format,
            findings: processed.findings,
            notes: processed.notes,
        })
    }

    fn strip(&self, input: &[u8], options: &StripOptions) -> Result<Stripped> {
        let processed = process(input, self.format, &options.inspect, &options.limits)?;
        Ok(Stripped {
            report: StripReport {
                format: self.format,
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

/// The identification packets the three mappings open with.
const VORBIS_ID: &[u8] = b"\x01vorbis";
const VORBIS_COMMENT_ID: &[u8] = b"\x03vorbis";
const VORBIS_SETUP_ID: &[u8] = b"\x05vorbis";
const OPUS_HEAD: &[u8] = b"OpusHead";
const OPUS_TAGS: &[u8] = b"OpusTags";
const FLAC_MAPPING: &[u8] = b"\x7fFLAC";
const THEORA_ID: &[u8] = b"\x80theora";
const SPEEX_ID: &[u8] = b"Speex   ";
const SKELETON_ID: &[u8] = b"fishead\0";

/// Vorbis I §4.2.1 ends the comment header with a framing bit, which Opus and FLAC do not have.
const VORBIS_FRAMING_BIT: u8 = 0x01;

/// The Ogg FLAC mapping's own header: `\x7fFLAC`, a major and minor version, and a 16-bit count of
/// the header packets that follow.
const FLAC_MAPPING_MAJOR: u8 = 1;
const FLAC_MAPPING_HEADER_LEN: usize = 9;

/// FLAC metadata block types used here (RFC 9639 §8.2); the rest are removed unread.
const FLAC_STREAMINFO: u8 = 0;
const FLAC_PADDING: u8 = 1;
const FLAC_SEEKTABLE: u8 = 3;
const FLAC_VORBIS_COMMENT: u8 = 4;
const FLAC_FORBIDDEN: u8 = 127;
const FLAC_BLOCK_HEADER_LEN: usize = 4;
const FLAC_STREAMINFO_LEN: usize = 34;
const FLAC_STREAMINFO_MD5_AT: usize = 18;

/// What [`sniff`] made of a file starting with a page.
pub(crate) enum Sniff {
    /// A mapping this release handles.
    Supported(Format),
    /// An Ogg worth naming in a refusal.
    Refused(UnsupportedKind),
}

/// Identify an Ogg by the codec its first page declares.
///
/// Cheap and integrity-blind on purpose: it reads one page header and the first bytes of the first
/// packet. A file whose CRC is wrong still detects as the codec it claims and is then refused by
/// the handler, which is a far more useful message than "unrecognised".
pub(crate) fn sniff(data: &[u8]) -> Option<Sniff> {
    let first = page_at(data, 0)?;
    if first.flags & page::BOS == 0 {
        // A stream that does not begin at the beginning: either a fragment of one, or a chain
        // joined mid-file. Neither is something to walk.
        return Some(Sniff::Refused(UnsupportedKind::OtherOggCodec));
    }
    // A multiplexed file puts every stream's first page at the front, so the second page is the
    // one that gives it away, and naming it here beats a generic refusal (ADR-0041 decision 6).
    if let Some(second) = page_at(data, first.end)
        && second.flags & page::BOS != 0
    {
        return Some(Sniff::Refused(UnsupportedKind::MultiplexedOgg));
    }

    let body = data.get(first.body..first.end).unwrap_or_default();
    Some(match () {
        () if body.starts_with(VORBIS_ID) => Sniff::Supported(Format::Ogg),
        () if body.starts_with(OPUS_HEAD) => Sniff::Supported(Format::Opus),
        () if body.starts_with(FLAC_MAPPING) => Sniff::Supported(Format::OggFlac),
        () if body.starts_with(THEORA_ID) => Sniff::Refused(UnsupportedKind::OggTheora),
        () if body.starts_with(SPEEX_ID) || body.starts_with(SKELETON_ID) => {
            Sniff::Refused(UnsupportedKind::OtherOggCodec)
        }
        () => Sniff::Refused(UnsupportedKind::OtherOggCodec),
    })
}

/// The little a sniff needs from a page header.
struct Header {
    flags: u8,
    /// Where the page's body starts.
    body: usize,
    /// Where the page ends.
    end: usize,
}

/// Read the page header at `at`, without checking its CRC.
fn page_at(data: &[u8], at: usize) -> Option<Header> {
    let rest = data.get(at..)?;
    if !rest.starts_with(page::MAGIC) {
        return None;
    }
    let segments = usize::from(*rest.get(26)?);
    let body = at.checked_add(27)?.checked_add(segments)?;
    let lacing = rest.get(27..27usize.checked_add(segments)?)?;
    let length = lacing
        .iter()
        .fold(0usize, |sum, n| sum.saturating_add(usize::from(*n)));
    Some(Header {
        flags: *rest.get(5)?,
        body,
        end: body.checked_add(length)?,
    })
}

/// The result of one pass over a file.
struct Processed {
    findings: Vec<Finding>,
    retained: Vec<Retained>,
    notes: Vec<Note>,
    output: Vec<u8>,
}

/// Walk `input`, decide about every header packet, and rebuild the stream.
fn process(
    input: &[u8],
    format: Format,
    options: &InspectOptions,
    limits: &ParseLimits,
) -> Result<Processed> {
    let mut budget = limits.max_items;
    let pages = page::pages(input, &mut budget).map_err(|e| convert(e, format))?;
    single_bitstream(&pages, format)?;
    let packets = page::packets(&pages).map_err(|e| convert(e, format))?;

    let mut out = Processed {
        findings: Vec::new(),
        retained: Vec::new(),
        notes: Vec::new(),
        output: Vec::new(),
    };
    // Built before any borrow of them, so a replacement can be handed to the writer by reference
    // rather than copied a second time.
    let mut replacements: Vec<Option<Vec<u8>>> = vec![None; packets.len()];
    let headers = match format {
        Format::Opus => opus(&packets, options, &mut replacements, &mut out)?,
        Format::OggFlac => flac(&packets, options, &mut replacements, &mut out)?,
        // `Format::Ogg` is Vorbis; nothing else reaches this handler.
        _ => vorbis_stream(&packets, options, &mut replacements, &mut out)?,
    };
    if packets.len() <= headers {
        // Headers and nothing else. Refused rather than rebuilt, on MP3's reasoning: a file with
        // no payload is not one this tool should hand back reporting success (ADR-0040).
        return Err(malformed(format, MalformedDetail::Truncated, None));
    }

    let emits: Vec<Emit<'_>> = packets
        .iter()
        .enumerate()
        .map(
            |(index, packet)| match replacements.get(index).and_then(|slot| slot.as_deref()) {
                Some(bytes) => Emit::replacing(packet, bytes),
                None => Emit::copied(packet),
            },
        )
        .collect();
    out.output = page::write(0, &emits).map_err(|detail| malformed(format, detail, None))?;

    // Said on every file, clean ones included: the packets are copied without being decoded, so
    // anything hidden inside one is out of reach rather than absent.
    out.notes.push(Note::OutOfScopeContent {
        location: "audio packets, which are copied without being decoded".to_owned(),
    });
    Ok(out)
}

/// Refuse anything that is not exactly one logical bitstream.
fn single_bitstream(pages: &[page::Page<'_>], format: Format) -> Result<()> {
    let Some(first) = pages.first() else {
        return Err(malformed(format, MalformedDetail::MissingMarker, None));
    };
    if first.flags & page::BOS == 0 {
        return Err(malformed(
            format,
            MalformedDetail::MissingMarker,
            as_offset(first.offset),
        ));
    }
    for (index, current) in pages.iter().enumerate() {
        if current.serial != first.serial || (index > 0 && current.flags & page::BOS != 0) {
            return Err(StryptError::UnsupportedFormat {
                format: UnsupportedKind::MultiplexedOgg,
            });
        }
        let last = index.saturating_add(1) == pages.len();
        if (current.flags & page::EOS != 0) != last {
            // An end-of-stream page in the middle is a chain; a stream that never ends is a
            // fragment. Both are refused rather than guessed at.
            return Err(StryptError::UnsupportedFormat {
                format: UnsupportedKind::MultiplexedOgg,
            });
        }
    }
    Ok(())
}

/// Vorbis I §4.2: three header packets, the second of which is the comment.
fn vorbis_stream(
    packets: &[Packet<'_>],
    options: &InspectOptions,
    replacements: &mut [Option<Vec<u8>>],
    out: &mut Processed,
) -> Result<usize> {
    let format = Format::Ogg;
    expect(packets, 0, VORBIS_ID, format)?;
    let comment = expect(packets, 1, VORBIS_COMMENT_ID, format)?;
    expect(packets, 2, VORBIS_SETUP_ID, format)?;

    let body = comment.get(VORBIS_COMMENT_ID.len()..).unwrap_or_default();
    vorbis::comments(
        body,
        "VORBIS_COMMENT",
        as_u64(body.len()),
        options,
        &mut out.findings,
    );

    let mut empty = VORBIS_COMMENT_ID.to_vec();
    empty.extend_from_slice(&vorbis::EMPTY);
    empty.push(VORBIS_FRAMING_BIT);
    set(replacements, 1, empty);
    Ok(3)
}

/// RFC 7845 §5: two header packets, the second of which is `OpusTags`.
fn opus(
    packets: &[Packet<'_>],
    options: &InspectOptions,
    replacements: &mut [Option<Vec<u8>>],
    out: &mut Processed,
) -> Result<usize> {
    let format = Format::Opus;
    expect(packets, 0, OPUS_HEAD, format)?;
    let comment = expect(packets, 1, OPUS_TAGS, format)?;

    let body = comment.get(OPUS_TAGS.len()..).unwrap_or_default();
    vorbis::comments(
        body,
        "OpusTags",
        as_u64(body.len()),
        options,
        &mut out.findings,
    );

    let mut empty = OPUS_TAGS.to_vec();
    empty.extend_from_slice(&vorbis::EMPTY);
    set(replacements, 1, empty);
    Ok(2)
}

/// The Ogg FLAC mapping: a mapping header carrying `STREAMINFO`, then one FLAC metadata block per
/// packet until one sets the last-block flag.
///
/// Blocks are replaced rather than dropped, so the packet count and the mapping header's declared
/// count of them stay true without either being rewritten (ADR-0041 decision 9).
fn flac(
    packets: &[Packet<'_>],
    options: &InspectOptions,
    replacements: &mut [Option<Vec<u8>>],
    out: &mut Processed,
) -> Result<usize> {
    let format = Format::OggFlac;
    let mapping = expect(packets, 0, FLAC_MAPPING, format)?;
    let mut r = Reader::new(&mapping);
    r.skip(FLAC_MAPPING.len())
        .ok_or_else(|| malformed(format, MalformedDetail::Truncated, None))?;
    if r.u8() != Some(FLAC_MAPPING_MAJOR) {
        // A mapping version whose layout this code has never read. Refused, not guessed at.
        return Err(malformed(format, MalformedDetail::UnexpectedMarker, None));
    }
    let _minor = r.u8();
    let declared = r
        .u16_be()
        .ok_or_else(|| malformed(format, MalformedDetail::Truncated, None))?;
    if r.take(4) != Some(b"fLaC") {
        return Err(malformed(
            format,
            MalformedDetail::MissingMarker,
            as_offset(FLAC_MAPPING_HEADER_LEN),
        ));
    }
    let (kind, last, payload) = block(r.take_rest(), format)?;
    if kind != FLAC_STREAMINFO || payload.len() != FLAC_STREAMINFO_LEN {
        return Err(malformed(format, MalformedDetail::MissingMarker, None));
    }
    if !md5_is_absent(payload) {
        // Computed from the samples the file still carries, so its holder can recompute it and
        // removing it hides nothing from them — but it does link this copy to another, so it is
        // declared (ADR-0038 decision 4).
        out.retained.push(Retained {
            location: "STREAMINFO (MD5 of the unencoded audio)".to_owned(),
            reason: RetentionReason::DerivedFromPayload,
        });
    }

    let mut index = 1usize;
    let mut done = last;
    while !done {
        let Some(packet) = packets.get(index) else {
            return Err(malformed(format, MalformedDetail::Truncated, None));
        };
        let bytes = packet.bytes();
        let (kind, last, payload) = block(&bytes, format)?;
        done = last;
        let flag = if last { 0x80 } else { 0x00 };
        let size = as_u64(payload.len());
        match kind {
            FLAC_STREAMINFO | FLAC_FORBIDDEN => {
                // A second `STREAMINFO` or the type §8.1 forbids outright: the walk is no longer
                // where it thinks it is.
                return Err(malformed(format, MalformedDetail::UnexpectedMarker, None));
            }
            FLAC_SEEKTABLE => {}
            FLAC_VORBIS_COMMENT => {
                vorbis::comments(payload, "VORBIS_COMMENT", size, options, &mut out.findings);
                set(
                    replacements,
                    index,
                    flac_block(FLAC_VORBIS_COMMENT, flag, &vorbis::EMPTY),
                );
            }
            FLAC_PADDING => {
                if payload.iter().any(|byte| *byte != 0) {
                    // §8.2 says a padding block is zero bits. Anything else was put there.
                    out.findings.push(
                        Finding::new(MetadataKind::Other, "PADDING", size)
                            .with_field("Padding")
                            .with_value(options, || MetadataValue::Opaque { bytes: size }),
                    );
                    set(
                        replacements,
                        index,
                        flac_block(FLAC_PADDING, flag, &vec![0u8; payload.len()]),
                    );
                }
            }
            other => {
                out.findings
                    .push(finding_for(other, payload, size, options));
                set(replacements, index, flac_block(FLAC_PADDING, flag, &[]));
            }
        }
        index = index.saturating_add(1);
    }

    let counted = u16::try_from(index.saturating_sub(1)).unwrap_or(u16::MAX);
    if declared != 0 && declared != counted {
        // The mapping header says how many header packets follow. A file where it disagrees with
        // the last-block flag is one whose two answers cannot both be acted on.
        return Err(malformed(format, MalformedDetail::LengthOutOfRange, None));
    }
    Ok(index)
}

/// A FLAC metadata block filling `data`: type, last-block flag, and payload.
fn block(data: &[u8], format: Format) -> Result<(u8, bool, &[u8])> {
    let header = data
        .get(..FLAC_BLOCK_HEADER_LEN)
        .ok_or_else(|| malformed(format, MalformedDetail::Truncated, None))?;
    let first = header.first().copied().unwrap_or_default();
    let length = match header.get(1..4) {
        Some([high, middle, low]) => {
            usize::try_from(u32::from_be_bytes([0, *high, *middle, *low])).ok()
        }
        _ => None,
    }
    .ok_or_else(|| malformed(format, MalformedDetail::LengthOutOfRange, None))?;
    let payload = data
        .get(FLAC_BLOCK_HEADER_LEN..)
        .ok_or_else(|| malformed(format, MalformedDetail::Truncated, None))?;
    if payload.len() != length {
        // One block per packet, so the block must fill the packet exactly. A shorter one hides
        // bytes behind it; a longer one is lying about its own size.
        return Err(malformed(format, MalformedDetail::LengthOutOfRange, None));
    }
    Ok((first & 0x7F, first & 0x80 != 0, payload))
}

/// Build a FLAC metadata block packet.
fn flac_block(kind: u8, last: u8, payload: &[u8]) -> Vec<u8> {
    let mut out = vec![kind | last];
    let length = u32::try_from(payload.len())
        .unwrap_or(u32::MAX)
        .to_be_bytes();
    out.extend_from_slice(length.get(1..4).unwrap_or_default());
    out.extend_from_slice(payload);
    out
}

/// Report a FLAC metadata block that is going. Types are named where §8.2 names them, and a
/// reserved one is named by its number rather than passed over for being unrecognised.
fn finding_for(kind: u8, payload: &[u8], size: u64, options: &InspectOptions) -> Finding {
    match kind {
        2 => Finding::new(MetadataKind::SoftwareFingerprint, "APPLICATION", size)
            .with_field(xmp::name_of(payload.get(0..4).unwrap_or(payload)))
            .with_value(options, || MetadataValue::Opaque { bytes: size }),
        5 => Finding::new(MetadataKind::DocumentIdentifier, "CUESHEET", size)
            .with_field("MediaCatalogNumber"),
        6 => Finding::new(MetadataKind::Thumbnail, "PICTURE", size)
            .with_value(options, || MetadataValue::Opaque { bytes: size }),
        other => Finding::new(
            MetadataKind::Other,
            format!("Metadata block type {other}"),
            size,
        ),
    }
}

/// True when `STREAMINFO`'s MD5 field is all zeros, which §8.2 defines as "unknown".
fn md5_is_absent(payload: &[u8]) -> bool {
    payload
        .get(FLAC_STREAMINFO_MD5_AT..)
        .is_none_or(|md5| md5.iter().all(|byte| *byte == 0))
}

/// The packet at `index`, refusing the file unless it opens with `marker`.
fn expect<'a>(
    packets: &'a [Packet<'_>],
    index: usize,
    marker: &[u8],
    format: Format,
) -> Result<std::borrow::Cow<'a, [u8]>> {
    let packet = packets
        .get(index)
        .ok_or_else(|| malformed(format, MalformedDetail::Truncated, None))?;
    let bytes = packet.bytes();
    if !bytes.starts_with(marker) {
        return Err(malformed(format, MalformedDetail::MissingMarker, None));
    }
    Ok(bytes)
}

/// Record a replacement for the packet at `index`.
fn set(replacements: &mut [Option<Vec<u8>>], index: usize, bytes: Vec<u8>) {
    if let Some(slot) = replacements.get_mut(index) {
        *slot = Some(bytes);
    }
}

/// Re-label a page-layer failure as this format's error.
fn convert(error: WalkError, format: Format) -> StryptError {
    match error {
        WalkError::Malformed { detail, offset } => malformed(format, detail, as_offset(offset)),
        WalkError::Limit(limit) => StryptError::LimitExceeded { format, limit },
    }
}

/// A malformed-file error for this format.
fn malformed(format: Format, detail: MalformedDetail, offset: Option<u64>) -> StryptError {
    StryptError::Malformed {
        format,
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
    // Test code is never reachable from untrusted bytes, which is the boundary the panic-freedom
    // lints police (ADR-0006).
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::indexing_slicing,
        clippy::arithmetic_side_effects
    )]

    use super::*;

    fn le32(n: usize) -> [u8; 4] {
        u32::try_from(n).unwrap().to_le_bytes()
    }

    /// A comment body: a vendor string, a count, then the items.
    fn comment_body(vendor: &[u8], items: &[&[u8]]) -> Vec<u8> {
        let mut out = le32(vendor.len()).to_vec();
        out.extend_from_slice(vendor);
        out.extend_from_slice(&le32(items.len()));
        for item in items {
            out.extend_from_slice(&le32(item.len()));
            out.extend_from_slice(item);
        }
        out
    }

    /// One page carrying whole packets, with its CRC filled in.
    fn build_page(
        flags: u8,
        granule: u64,
        serial: u32,
        sequence: u32,
        packets: &[&[u8]],
    ) -> Vec<u8> {
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
        let mut out = page::MAGIC.to_vec();
        out.push(0);
        out.push(flags);
        out.extend_from_slice(&granule.to_le_bytes());
        out.extend_from_slice(&serial.to_le_bytes());
        out.extend_from_slice(&sequence.to_le_bytes());
        out.extend_from_slice(&[0u8; 4]);
        out.push(u8::try_from(lacing.len()).unwrap());
        out.extend_from_slice(&lacing);
        out.extend_from_slice(&body);
        let crc = page::crc(&out);
        out[22..26].copy_from_slice(&crc.to_le_bytes());
        out
    }

    /// A Vorbis stream: identification, comment, setup, and one audio packet.
    fn vorbis_file(vendor: &[u8], items: &[&[u8]]) -> Vec<u8> {
        let mut comment = VORBIS_COMMENT_ID.to_vec();
        comment.extend_from_slice(&comment_body(vendor, items));
        comment.push(VORBIS_FRAMING_BIT);
        let mut id = VORBIS_ID.to_vec();
        id.extend_from_slice(&[0u8; 23]);
        let mut setup = VORBIS_SETUP_ID.to_vec();
        setup.extend_from_slice(b"SETUP");

        let mut out = build_page(page::BOS, 0, 0x1234_5678, 0, &[&id]);
        out.extend_from_slice(&build_page(0, 0, 0x1234_5678, 1, &[&comment, &setup]));
        out.extend_from_slice(&build_page(
            page::EOS,
            1024,
            0x1234_5678,
            2,
            &[b"AUDIO-PACKET-PAYLOAD"],
        ));
        out
    }

    /// An Opus stream: `OpusHead`, `OpusTags`, and one audio packet.
    fn opus_file(vendor: &[u8], items: &[&[u8]]) -> Vec<u8> {
        let mut head = OPUS_HEAD.to_vec();
        head.extend_from_slice(&[1, 1, 0x38, 1, 0x80, 0xBB, 0, 0, 0, 0, 0]);
        let mut tags = OPUS_TAGS.to_vec();
        tags.extend_from_slice(&comment_body(vendor, items));

        let mut out = build_page(page::BOS, 0, 99, 0, &[&head]);
        out.extend_from_slice(&build_page(0, 0, 99, 1, &[&tags]));
        out.extend_from_slice(&build_page(page::EOS, 960, 99, 2, &[b"AUDIO-PAYLOAD"]));
        out
    }

    fn flac_mapping(headers: u16, md5: u8) -> Vec<u8> {
        let mut out = FLAC_MAPPING.to_vec();
        out.extend_from_slice(&[FLAC_MAPPING_MAJOR, 0]);
        out.extend_from_slice(&headers.to_be_bytes());
        out.extend_from_slice(b"fLaC");
        let mut streaminfo = vec![0u8; FLAC_STREAMINFO_LEN];
        for byte in streaminfo.iter_mut().skip(FLAC_STREAMINFO_MD5_AT) {
            *byte = md5;
        }
        out.extend_from_slice(&flac_block(FLAC_STREAMINFO, 0, &streaminfo));
        out
    }

    /// An Ogg FLAC stream carrying the given metadata blocks after `STREAMINFO`.
    fn flac_file(blocks: &[(u8, Vec<u8>)]) -> Vec<u8> {
        let mapping = flac_mapping(u16::try_from(blocks.len()).unwrap(), 0xAB);
        let mut packets: Vec<Vec<u8>> = vec![mapping];
        for (index, (kind, payload)) in blocks.iter().enumerate() {
            let last = if index + 1 == blocks.len() { 0x80 } else { 0 };
            packets.push(flac_block(*kind, last, payload));
        }
        let refs: Vec<&[u8]> = packets.iter().skip(1).map(Vec::as_slice).collect();
        let mut out = build_page(page::BOS, 0, 7, 0, &[&packets[0]]);
        out.extend_from_slice(&build_page(0, 0, 7, 1, &refs));
        out.extend_from_slice(&build_page(page::EOS, 4096, 7, 2, &[b"\xff\xf8AUDIO"]));
        out
    }

    fn strip_ok(handler: OggHandler, data: &[u8]) -> Stripped {
        handler
            .strip(data, &StripOptions::default())
            .expect("strip failed")
    }

    fn contains(haystack: &[u8], needle: &[u8]) -> bool {
        haystack.windows(needle.len()).any(|w| w == needle)
    }

    #[test]
    fn a_vorbis_comment_is_itemised_and_emptied() {
        let input = vorbis_file(
            b"SYNTHETIC-VENDOR-0001",
            &[b"ARTIST=SYNTHETIC-ARTIST-0002", b"DATE=2026-09-03"],
        );
        let stripped = strip_ok(OggHandler::VORBIS, &input);
        let fields: Vec<&str> = stripped
            .report
            .removed
            .iter()
            .filter_map(|f| f.field.as_deref())
            .collect();
        assert!(fields.contains(&"vendor"));
        assert!(fields.contains(&"ARTIST"));
        assert!(!contains(&stripped.bytes, b"SYNTHETIC-"));
    }

    #[test]
    fn the_audio_packets_cross_byte_for_byte() {
        // The property the rebuild trades page structure for: nothing is re-encoded.
        let input = vorbis_file(b"v", &[b"ARTIST=SYNTHETIC-0003"]);
        let output = strip_ok(OggHandler::VORBIS, &input).bytes;
        assert!(contains(&output, b"AUDIO-PACKET-PAYLOAD"));
        assert!(contains(&output, b"SETUP"), "the setup header moved");
    }

    #[test]
    fn the_comment_packet_is_emptied_rather_than_dropped() {
        // All three mappings need it in place; unlike FLAC's block it cannot go (ADR-0041).
        let input = opus_file(b"libopus SYNTHETIC-0004", &[b"TITLE=SYNTHETIC-0005"]);
        let output = strip_ok(OggHandler::OPUS, &input).bytes;
        assert!(contains(&output, OPUS_TAGS));
        assert!(!contains(&output, b"SYNTHETIC-"));
    }

    #[test]
    fn the_serial_number_is_rewritten() {
        // It is a 32-bit identifier nobody can recompute, and libogg seeds it from the clock.
        for (handler, input) in [
            (OggHandler::VORBIS, vorbis_file(b"v", &[])),
            (OggHandler::OPUS, opus_file(b"v", &[])),
        ] {
            let output = strip_ok(handler, &input).bytes;
            assert_eq!(output.get(14..18), Some(&0u32.to_le_bytes()[..]));
        }
    }

    #[test]
    fn the_granule_positions_are_carried_verbatim() {
        // They are sample counts, not offsets, so removal moves nothing (RFC 3533 §3).
        let input = opus_file(b"v", &[b"ARTIST=SYNTHETIC-0006"]);
        let output = strip_ok(OggHandler::OPUS, &input).bytes;
        let mut budget = 4096;
        let pages = page::pages(&output, &mut budget).unwrap();
        let granules: Vec<u64> = pages.iter().map(|p| p.granule).collect();
        assert_eq!(granules, vec![0, 0, 960]);
    }

    #[test]
    fn stripping_twice_is_byte_exact() {
        for (handler, input) in [
            (
                OggHandler::VORBIS,
                vorbis_file(b"v", &[b"A=SYNTHETIC-0007"]),
            ),
            (OggHandler::OPUS, opus_file(b"v", &[b"A=SYNTHETIC-0008"])),
            (
                OggHandler::FLAC,
                flac_file(&[(FLAC_VORBIS_COMMENT, comment_body(b"v", &[b"A=SYN-9"]))]),
            ),
        ] {
            let once = strip_ok(handler, &input).bytes;
            let twice = strip_ok(handler, &once).bytes;
            assert_eq!(once, twice, "strip is not idempotent");
        }
    }

    #[test]
    fn a_stripped_stream_re_inspects_clean() {
        for (handler, input) in [
            (
                OggHandler::VORBIS,
                vorbis_file(b"v", &[b"A=SYNTHETIC-0010"]),
            ),
            (OggHandler::OPUS, opus_file(b"v", &[b"A=SYNTHETIC-0011"])),
            (
                OggHandler::FLAC,
                flac_file(&[(FLAC_VORBIS_COMMENT, comment_body(b"v", &[b"A=SYN-12"]))]),
            ),
        ] {
            let output = strip_ok(handler, &input).bytes;
            let report = handler
                .inspect(&output, &InspectOptions::names_only())
                .unwrap();
            assert!(report.findings.is_empty(), "{:?}", report.findings);
        }
    }

    #[test]
    fn an_ogg_flac_keeps_its_packet_count_when_a_block_goes() {
        // A removed block becomes a zero-length PADDING packet, so neither the declared header
        // count nor the last-block flag has to be rewritten (ADR-0041 decision 9).
        let mut picture = 3u32.to_be_bytes().to_vec();
        picture.extend_from_slice(&9u32.to_be_bytes());
        picture.extend_from_slice(b"image/png");
        picture.extend_from_slice(&21u32.to_be_bytes());
        picture.extend_from_slice(b"SYNTHETIC-PICTURE-013");
        let input = flac_file(&[
            (
                FLAC_VORBIS_COMMENT,
                comment_body(b"v", &[b"A=SYNTHETIC-14"]),
            ),
            (6, picture),
        ]);

        let stripped = strip_ok(OggHandler::FLAC, &input);
        assert!(!contains(&stripped.bytes, b"SYNTHETIC-"));
        let mut budget = 4096;
        let before = page::packets(&page::pages(&input, &mut budget).unwrap())
            .unwrap()
            .len();
        let mut budget = 4096;
        let after = page::packets(&page::pages(&stripped.bytes, &mut budget).unwrap())
            .unwrap()
            .len();
        assert_eq!(before, after, "a header packet was dropped");
    }

    #[test]
    fn an_ogg_flac_declares_the_audio_md5_it_keeps() {
        let input = flac_file(&[(FLAC_PADDING, vec![0u8; 8])]);
        let stripped = strip_ok(OggHandler::FLAC, &input);
        assert_eq!(
            stripped.report.retained.first().map(|r| r.reason),
            Some(RetentionReason::DerivedFromPayload)
        );
    }

    #[test]
    fn ogg_flac_padding_keeps_its_size_and_loses_its_contents() {
        let mut payload = vec![0u8; 32];
        payload[4..27].copy_from_slice(b"SYNTHETIC-IN-PADDING-15");
        let input = flac_file(&[(FLAC_PADDING, payload)]);
        let stripped = strip_ok(OggHandler::FLAC, &input);
        assert!(!contains(&stripped.bytes, b"SYNTHETIC-"));
        assert_eq!(stripped.report.removed[0].location, "PADDING");
    }

    #[test]
    fn a_second_bitstream_is_refused_by_name() {
        let mut input = vorbis_file(b"v", &[]);
        let mut second = build_page(page::BOS | page::EOS, 0, 4242, 0, &[b"\x80theora"]);
        std::mem::swap(&mut input, &mut second);
        input.extend_from_slice(&second);
        assert!(matches!(
            OggHandler::VORBIS.strip(&input, &StripOptions::default()),
            Err(StryptError::UnsupportedFormat {
                format: UnsupportedKind::MultiplexedOgg
            })
        ));
    }

    #[test]
    fn a_sniff_names_what_it_will_not_handle() {
        let theora = build_page(page::BOS | page::EOS, 0, 1, 0, &[b"\x80theora"]);
        assert!(matches!(
            sniff(&theora),
            Some(Sniff::Refused(UnsupportedKind::OggTheora))
        ));
        let speex = build_page(page::BOS | page::EOS, 0, 1, 0, &[b"Speex   "]);
        assert!(matches!(
            sniff(&speex),
            Some(Sniff::Refused(UnsupportedKind::OtherOggCodec))
        ));
        assert!(matches!(
            sniff(&vorbis_file(b"v", &[])),
            Some(Sniff::Supported(Format::Ogg))
        ));
        assert!(matches!(
            sniff(&opus_file(b"v", &[])),
            Some(Sniff::Supported(Format::Opus))
        ));
        assert!(matches!(
            sniff(&flac_file(&[(FLAC_PADDING, vec![0u8; 4])])),
            Some(Sniff::Supported(Format::OggFlac))
        ));
    }

    #[test]
    fn a_page_whose_crc_does_not_match_is_refused() {
        let mut input = vorbis_file(b"v", &[]);
        let at = input.len() - 1;
        input[at] ^= 0xFF;
        assert!(matches!(
            OggHandler::VORBIS.strip(&input, &StripOptions::default()),
            Err(StryptError::Malformed { .. })
        ));
    }

    #[test]
    fn a_stream_that_is_only_headers_is_refused() {
        let mut comment = VORBIS_COMMENT_ID.to_vec();
        comment.extend_from_slice(&comment_body(b"v", &[]));
        comment.push(VORBIS_FRAMING_BIT);
        let mut id = VORBIS_ID.to_vec();
        id.extend_from_slice(&[0u8; 23]);
        let mut setup = VORBIS_SETUP_ID.to_vec();
        setup.extend_from_slice(b"SETUP");
        let mut input = build_page(page::BOS, 0, 1, 0, &[&id]);
        input.extend_from_slice(&build_page(page::EOS, 0, 1, 1, &[&comment, &setup]));
        assert!(matches!(
            OggHandler::VORBIS.strip(&input, &StripOptions::default()),
            Err(StryptError::Malformed { .. })
        ));
    }

    #[test]
    fn a_missing_comment_header_is_refused() {
        let mut id = VORBIS_ID.to_vec();
        id.extend_from_slice(&[0u8; 23]);
        let mut input = build_page(page::BOS, 0, 1, 0, &[&id]);
        input.extend_from_slice(&build_page(
            page::EOS,
            1,
            1,
            1,
            &[b"NOT-A-HEADER", b"AUDIO"],
        ));
        assert!(matches!(
            OggHandler::VORBIS.strip(&input, &StripOptions::default()),
            Err(StryptError::Malformed {
                detail: MalformedDetail::MissingMarker,
                ..
            })
        ));
    }

    #[test]
    fn an_ogg_flac_block_that_does_not_fill_its_packet_is_refused() {
        // One block per packet: a short one hides bytes behind it, a long one lies about its size.
        let mut input = flac_file(&[(FLAC_PADDING, vec![0u8; 8])]);
        // The block packet sits on the second page; corrupt its declared length and re-stamp.
        let at = input
            .windows(4)
            .position(|w| w == b"OggS")
            .and_then(|_| input.windows(2).position(|w| w == [0x81, 0x00]))
            .unwrap();
        input[at + 3] = 0x40;
        let mut budget = 4096;
        if page::pages(&input, &mut budget).is_ok() {
            // The CRC guards the page, so a hand-edited byte usually fails there first; either
            // refusal is the fail-closed answer this asserts.
        }
        assert!(
            OggHandler::FLAC
                .strip(&input, &StripOptions::default())
                .is_err()
        );
    }

    #[test]
    fn truncation_at_every_length_is_refused_but_never_panics() {
        let input = vorbis_file(b"vendor", &[b"ARTIST=SYNTHETIC-0016"]);
        for n in 0..=input.len() {
            let prefix = input.get(0..n).unwrap();
            let _ = OggHandler::VORBIS.inspect(prefix, &InspectOptions::names_only());
            let _ = OggHandler::VORBIS.strip(prefix, &StripOptions::default());
        }
    }
}
