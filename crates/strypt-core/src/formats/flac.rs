//! FLAC.
//!
//! The first handler in Phase 2's fourth group (ADR-0037), and the format that makes the group
//! look easier than it is: a four-byte magic, a list of typed metadata blocks, then audio frames
//! to the end of the file. The identifying material is all in the block list — a Vorbis comment
//! naming the artist, the ripping software and the machine that ripped it; cover art that is an
//! ordinary image with its own Exif inside it; a cuesheet carrying the catalogue number of the
//! disc it came from.
//!
//! # Block surgery, never re-encoding
//!
//! Blocks are dropped whole and everything else is copied through as raw bytes, so a clean file
//! comes back byte-identical — the property GIF and JPEG XL have and TIFF and HEIF cannot
//! (ADR-0033, ADR-0034). Nothing here decodes audio. **Removing a block moves no offset**: a seek
//! point's offset is measured "from the first byte of the first frame header" (RFC 9639 §8.5), not
//! from the start of the file, so the seek table stays valid however much metadata goes. That one
//! sentence of the spec is why this tranche is cheap and MP4 is not (ADR-0037).
//!
//! The only field rewritten anywhere is the last-metadata-block flag in a block header, which says
//! whether another block follows (§8.1) and therefore has to move when the block after it goes.
//!
//! # Padding is kept at its length and zeroed, rather than dropped
//!
//! §8.2 says a padding block is *n* zero bits. Real encoders leave several kilobytes of it so a
//! later tagger can write in place, and real taggers leave whatever they were holding in it. So
//! the bytes are replaced with the zeros the spec calls for and the block keeps its size: a
//! compliant file is unchanged, a file hiding data in its padding is scrubbed and told about, and
//! the room a tagger needs is still there.
//!
//! # Tags glued to the ends, which are not FLAC at all
//!
//! Taggers write an ID3v2 tag in front of the stream marker and an ID3v1, APE or Lyrics3 tag past
//! the last frame. Neither is FLAC — §8 has no room for either — and a decoder skips them, so they
//! survive every block this handler cleans. They were refused outright until the MP3 tranche put a
//! reader in the tree; now they are peeled by [`super::tags`] and the FLAC in between is walked
//! (ADR-0040 lifts ADR-0038 decision 7).
//!
//! # What is kept, and the one thing that is kept and declared
//!
//! `STREAMINFO` is mandatory and first (§8.2), and its last sixteen bytes are an MD5 of the
//! *unencoded* audio. That is a fingerprint, and it is left alone: it is computed from the samples
//! the file still carries, so anyone holding the file can recompute it and removing it hides
//! nothing from them. It is declared in the report rather than passed over in silence, because
//! it does link this file to any other copy of the same recording.

use crate::bytes::Reader;
use crate::detect::Format;
use crate::error::{MalformedDetail, ResourceLimit, Result, StryptError};
use crate::formats::tags::{self, TagError};
use crate::formats::{MetadataHandler, ParseLimits, StripOptions, Stripped, xmp};
use crate::report::{
    Finding, InspectOptions, MetadataKind, MetadataReport, MetadataValue, Note, Retained,
    RetentionReason, StripReport,
};

/// Removal of metadata from FLAC audio.
#[derive(Debug, Clone, Copy, Default)]
pub struct FlacHandler;

impl MetadataHandler for FlacHandler {
    fn name(&self) -> &'static str {
        Format::Flac.id()
    }

    fn format(&self) -> Format {
        Format::Flac
    }

    fn inspect(&self, input: &[u8], options: &InspectOptions) -> Result<MetadataReport> {
        // The identical pass stripping runs, with the output discarded, so that "everything
        // `strip` removes is something `inspect` can see" holds by construction rather than by two
        // code paths agreeing to stay in step (`docs/ARCHITECTURE.md` §3).
        let processed = process(input, options, &ParseLimits::default())?;
        Ok(MetadataReport {
            format: Format::Flac,
            findings: processed.findings,
            notes: processed.notes,
        })
    }

    fn strip(&self, input: &[u8], options: &StripOptions) -> Result<Stripped> {
        let processed = process(input, &options.inspect, &options.limits)?;
        Ok(Stripped {
            report: StripReport {
                format: Format::Flac,
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

/// The stream marker (§8).
const MAGIC: &[u8; 4] = b"fLaC";

/// Block types §8.2 defines. Everything from 7 to 126 is reserved and is removed unread.
const STREAMINFO: u8 = 0;
const PADDING: u8 = 1;
const APPLICATION: u8 = 2;
const SEEKTABLE: u8 = 3;
const VORBIS_COMMENT: u8 = 4;
const CUESHEET: u8 = 5;
const PICTURE: u8 = 6;
/// §8.1 forbids this type outright, so that a block header can never be mistaken for a frame sync.
const FORBIDDEN: u8 = 127;

/// `STREAMINFO` is a fixed 34 bytes (§8.2). A file declaring anything else is not one.
const STREAMINFO_LEN: usize = 34;
/// Where the MD5 of the unencoded audio starts within `STREAMINFO`.
const STREAMINFO_MD5_AT: usize = 18;

/// A registered application identifier is four bytes (§8.4).
const APPLICATION_ID_LEN: usize = 4;
/// The media catalogue number that opens a cuesheet (§8.6).
const CUESHEET_CATALOGUE_LEN: usize = 128;

/// How much of a Vorbis comment block is itemised before the rest is reported in one line.
///
/// A block is removed whole whatever this is; the cap bounds only how many findings one file can
/// produce, because a report is itself allocated and rendered.
const MAX_ITEMISED_COMMENTS: u32 = 512;

/// One metadata block, and the payload span it occupied.
struct Block<'a> {
    kind: u8,
    payload: &'a [u8],
}

/// What is written out for a kept block: its original bytes, or a run of zeros standing in for
/// padding whose contents were not zeros.
enum Payload<'a> {
    Raw(&'a [u8]),
    Zeros(usize),
}

impl Payload<'_> {
    const fn len(&self) -> usize {
        match self {
            Self::Raw(bytes) => bytes.len(),
            Self::Zeros(n) => *n,
        }
    }
}

/// The result of one pass over a file.
struct Processed {
    findings: Vec<Finding>,
    retained: Vec<Retained>,
    notes: Vec<Note>,
    output: Vec<u8>,
}

/// Split `input` into its metadata blocks and its audio frames.
///
/// Every length here was chosen by whoever made the file, so every one is read through [`Reader`]
/// and every failure is a typed error. A file that does not parse is refused whole: nothing
/// returns a partial block list for a caller to strip and write out.
fn walk<'a>(input: &'a [u8], limits: &ParseLimits) -> Result<(Vec<Block<'a>>, &'a [u8])> {
    let mut r = Reader::new(input);
    if r.take(MAGIC.len()) != Some(MAGIC.as_slice()) {
        return Err(malformed(MalformedDetail::MissingMarker, Some(0)));
    }

    let mut blocks: Vec<Block<'a>> = Vec::new();
    let mut budget = limits.max_items;
    loop {
        let at = r.position();
        spend(&mut budget)?;
        let header = r
            .take(4)
            .ok_or_else(|| malformed(MalformedDetail::Truncated, as_offset(at)))?;
        let first = header.first().copied().unwrap_or_default();
        let kind = first & 0x7F;
        let last = first & 0x80 != 0;
        let length = block_length(header)
            .ok_or_else(|| malformed(MalformedDetail::Truncated, as_offset(at)))?;

        if kind == FORBIDDEN {
            // §8.1 reserves it precisely so this byte cannot look like a frame sync. A file using
            // it is not a FLAC, and guessing at what it meant is how a walk ends up somewhere else.
            return Err(malformed(MalformedDetail::UnexpectedMarker, as_offset(at)));
        }
        if blocks.is_empty() && kind != STREAMINFO {
            return Err(malformed(MalformedDetail::MissingMarker, as_offset(at)));
        }
        if !blocks.is_empty() && kind == STREAMINFO {
            return Err(malformed(MalformedDetail::UnexpectedMarker, as_offset(at)));
        }

        let payload = r
            .take(length)
            .ok_or_else(|| malformed(MalformedDetail::LengthOutOfRange, as_offset(at)))?;
        if kind == STREAMINFO && payload.len() != STREAMINFO_LEN {
            return Err(malformed(MalformedDetail::LengthOutOfRange, as_offset(at)));
        }
        blocks.push(Block { kind, payload });
        if last {
            break;
        }
    }

    let audio = r.take_rest();
    // A frame opens with the 14-bit sync code 0b11111111111110 (§9.1). Checking it is what turns a
    // block length that lied into a refusal: without it, a length landing mid-audio produces a
    // confident report about bytes that were never a metadata block.
    let sync = matches!((audio.first(), audio.get(1)), (Some(0xFF), Some(second)) if second & 0xFE == 0xF8);
    if !sync {
        return Err(malformed(
            MalformedDetail::MissingMarker,
            as_offset(input.len().saturating_sub(audio.len())),
        ));
    }
    Ok((blocks, audio))
}

/// The 24-bit big-endian length that follows a block header's type byte (§8.1).
fn block_length(header: &[u8]) -> Option<usize> {
    match header.get(1..4)? {
        [high, middle, low] => usize::try_from(u32::from_be_bytes([0, *high, *middle, *low])).ok(),
        _ => None,
    }
}

/// Charge one structural item against the budget.
fn spend(budget: &mut u32) -> Result<()> {
    if *budget == 0 {
        return Err(StryptError::LimitExceeded {
            format: Format::Flac,
            limit: ResourceLimit::ItemCount,
        });
    }
    *budget = budget.saturating_sub(1);
    Ok(())
}

/// Walk `input`, decide about every block, and build the sanitised file.
fn process(input: &[u8], options: &InspectOptions, limits: &ParseLimits) -> Result<Processed> {
    // Peeled before the stream marker is looked for, because a prepended ID3v2 tag is what stands
    // in front of it (ADR-0040).
    let (head_tags, start) = tags::head(input).map_err(convert)?;
    let (tail_tags, end) = tags::tail(input, start).map_err(convert)?;
    let body = input
        .get(start..end)
        .ok_or_else(|| malformed(MalformedDetail::LengthOutOfRange, as_offset(start)))?;

    let (blocks, audio) = walk(body, limits)?;
    let mut out = Processed {
        findings: Vec::new(),
        retained: Vec::new(),
        notes: Vec::new(),
        output: Vec::with_capacity(body.len()),
    };
    for tag in head_tags.iter().chain(tail_tags.iter()) {
        out.findings.extend(tags::findings(tag, options));
    }

    let mut kept: Vec<(u8, Payload<'_>)> = Vec::new();
    for block in &blocks {
        let size = as_u64(block.payload.len());
        match block.kind {
            STREAMINFO => {
                // Mandatory, and the only block a decoder cannot do without.
                if !md5_is_absent(block.payload) {
                    out.retained.push(Retained {
                        location: "STREAMINFO (MD5 of the unencoded audio)".to_owned(),
                        reason: RetentionReason::DerivedFromPayload,
                    });
                }
                kept.push((block.kind, Payload::Raw(block.payload)));
            }
            SEEKTABLE => {
                // Playback structure, and nothing else: sample numbers and offsets measured from
                // the first frame header (§8.5), which no removal here can move.
                kept.push((block.kind, Payload::Raw(block.payload)));
            }
            PADDING => {
                if block.payload.iter().any(|byte| *byte != 0) {
                    // §8.2 says this block is zero bits. Anything else was put there by something,
                    // and a scrubber that leaves it because the block is "only padding" is not
                    // scrubbing.
                    out.findings.push(
                        Finding::new(MetadataKind::Other, "PADDING", size)
                            .with_field("Padding")
                            .with_value(options, || MetadataValue::Opaque { bytes: size }),
                    );
                }
                kept.push((block.kind, Payload::Zeros(block.payload.len())));
            }
            APPLICATION => out.findings.push(application(block.payload, size, options)),
            VORBIS_COMMENT => comments(block.payload, size, options, &mut out.findings),
            CUESHEET => {
                out.findings.push(cuesheet(block.payload, size));
                out.notes.push(Note::CapabilityRemoved {
                    location: "CUESHEET".to_owned(),
                    capability: "be split into the tracks of the disc it was ripped from"
                        .to_owned(),
                });
            }
            PICTURE => out.findings.push(picture(block.payload, size, options)),
            other => out.findings.push(
                // §8.2 defines seven types. A block under a reserved one was written by something
                // whose intentions this code cannot know, and it goes for the same reason an
                // unrecognised GIF extension does.
                Finding::new(
                    MetadataKind::Other,
                    format!("Metadata block type {other}"),
                    size,
                ),
            ),
        }
    }

    out.output.extend_from_slice(MAGIC);
    let last_index = kept.len().saturating_sub(1);
    for (index, (kind, payload)) in kept.iter().enumerate() {
        let last = if index == last_index { 0x80 } else { 0x00 };
        out.output.push(kind | last);
        // The payload length is unchanged by anything above — padding keeps its size — so this
        // reproduces the header the file arrived with whenever nothing was removed.
        let length = u32::try_from(payload.len())
            .unwrap_or(u32::MAX)
            .to_be_bytes();
        out.output
            .extend_from_slice(length.get(1..4).unwrap_or_default());
        match payload {
            Payload::Raw(bytes) => out.output.extend_from_slice(bytes),
            Payload::Zeros(n) => out.output.resize(out.output.len().saturating_add(*n), 0),
        }
    }
    out.output.extend_from_slice(audio);

    // Said on every file, clean ones included. The frames are copied without being decoded, so
    // anything hidden inside one — data in a frame's reserved bits, a payload in the last partial
    // frame — is out of reach rather than absent. What is appended *past* them is now removed.
    out.notes.push(Note::OutOfScopeContent {
        location: "audio frames, which are copied without being decoded".to_owned(),
    });
    Ok(out)
}

/// Re-label a tag failure as this format's error, so a caller sees "a FLAC failed" rather than a
/// module it has no reason to know about.
fn convert(error: TagError) -> StryptError {
    match error {
        TagError::Malformed { detail, offset } => malformed(detail, as_offset(offset)),
        TagError::Limit(limit) => StryptError::LimitExceeded {
            format: Format::Flac,
            limit,
        },
    }
}

/// True when `STREAMINFO`'s MD5 field is all zeros, which §8.2 defines as "unknown".
fn md5_is_absent(payload: &[u8]) -> bool {
    payload
        .get(STREAMINFO_MD5_AT..)
        .is_none_or(|md5| md5.iter().all(|byte| *byte == 0))
}

/// An application block: four bytes of registered identifier, then whatever that application put
/// there (§8.4) — a whole RIFF or AIFF chunk, in the two cases the registry names.
fn application(payload: &[u8], size: u64, options: &InspectOptions) -> Finding {
    let id = payload.get(0..APPLICATION_ID_LEN).unwrap_or(payload);
    Finding::new(MetadataKind::SoftwareFingerprint, "APPLICATION", size)
        .with_field(xmp::name_of(id))
        .with_value(options, || MetadataValue::Opaque { bytes: size })
}

/// A cuesheet (§8.6). It is track geometry, and it is also a 128-byte media catalogue number and
/// an ISRC for every track — identifiers for the exact disc the audio was taken from.
fn cuesheet(payload: &[u8], size: u64) -> Finding {
    let catalogue = payload
        .get(0..CUESHEET_CATALOGUE_LEN)
        .unwrap_or(payload)
        .iter()
        .any(|byte| *byte != 0);
    let finding = Finding::new(MetadataKind::DocumentIdentifier, "CUESHEET", size);
    if catalogue {
        finding.with_field("MediaCatalogNumber")
    } else {
        finding
    }
}

/// A picture block (§8.7): cover art, which is an ordinary image file carrying whatever its own
/// container carries, plus a description field that is free text.
fn picture(payload: &[u8], size: u64, options: &InspectOptions) -> Finding {
    let mut r = Reader::new(payload);
    let kind = r.u32_be().unwrap_or_default();
    let media_type = r
        .u32_be()
        .and_then(|n| usize::try_from(n).ok())
        .and_then(|n| r.take(n))
        .unwrap_or_default();
    let description = r
        .u32_be()
        .and_then(|n| usize::try_from(n).ok())
        .and_then(|n| r.take(n))
        .unwrap_or_default();

    let field = if media_type.is_empty() {
        format!("PictureType {kind}")
    } else {
        format!("PictureType {kind} ({})", xmp::name_of(media_type))
    };
    Finding::new(MetadataKind::Thumbnail, "PICTURE", size)
        .with_field(field)
        .with_value(options, || {
            if description.is_empty() {
                MetadataValue::Opaque { bytes: size }
            } else {
                MetadataValue::Text(xmp::name_of(description))
            }
        })
}

/// Field names worth ranking, matched on the part before the `=` (§8.10 leaves the set open, so
/// this is a ranking table and never a filter — every comment goes whether it is named here or
/// not).
const COMMENT_KINDS: &[(&str, MetadataKind)] = &[
    ("ARTIST", MetadataKind::PersonalIdentity),
    ("ALBUMARTIST", MetadataKind::PersonalIdentity),
    ("PERFORMER", MetadataKind::PersonalIdentity),
    ("COMPOSER", MetadataKind::PersonalIdentity),
    ("CONDUCTOR", MetadataKind::PersonalIdentity),
    ("COPYRIGHT", MetadataKind::PersonalIdentity),
    ("ORGANIZATION", MetadataKind::PersonalIdentity),
    ("ENCODED-BY", MetadataKind::PersonalIdentity),
    ("CONTACT", MetadataKind::PersonalIdentity),
    ("LOCATION", MetadataKind::Location),
    ("GEO", MetadataKind::Location),
    ("GPS", MetadataKind::Location),
    ("DATE", MetadataKind::Timestamp),
    ("YEAR", MetadataKind::Timestamp),
    ("ENCODER", MetadataKind::SoftwareFingerprint),
    ("ENCODING", MetadataKind::SoftwareFingerprint),
    ("SOURCEMEDIA", MetadataKind::SoftwareFingerprint),
    ("MUSICBRAINZ", MetadataKind::DocumentIdentifier),
    ("CDDB", MetadataKind::DocumentIdentifier),
    ("ISRC", MetadataKind::DocumentIdentifier),
    ("REPLAYGAIN", MetadataKind::Other),
    ("COMMENT", MetadataKind::Comment),
    ("DESCRIPTION", MetadataKind::Comment),
    // Cover art, base64-encoded into a comment rather than put in a picture block. Some taggers
    // write it this way, and it is a whole image file however it is spelled.
    ("METADATA_BLOCK_PICTURE", MetadataKind::Thumbnail),
];

/// A Vorbis comment block (§8.10): a vendor string, a count, then that many `NAME=value` items,
/// every length little-endian.
///
/// Itemising is best-effort and removal is not: the block goes whole whatever this finds. A block
/// whose lengths do not add up is reported in one line and deleted, because a block strypt cannot
/// read is still one it can delete, and deleting is the safe direction.
fn comments(payload: &[u8], size: u64, options: &InspectOptions, out: &mut Vec<Finding>) {
    let before = out.len();
    let mut r = Reader::new(payload);

    let vendor = r
        .u32_le()
        .and_then(|n| usize::try_from(n).ok())
        .and_then(|n| r.take(n));
    if let Some(vendor) = vendor
        && !vendor.is_empty()
    {
        // The encoder's own name and version — "reference libFLAC 1.5.0 20250101" and the like.
        out.push(
            Finding::new(
                MetadataKind::SoftwareFingerprint,
                "VORBIS_COMMENT",
                as_u64(vendor.len()),
            )
            .with_field("vendor")
            .with_value(options, || MetadataValue::Text(xmp::name_of(vendor))),
        );
    }

    let count = r.u32_le().unwrap_or_default().min(MAX_ITEMISED_COMMENTS);
    for _ in 0..count {
        let Some(item) = r
            .u32_le()
            .and_then(|n| usize::try_from(n).ok())
            .and_then(|n| r.take(n))
        else {
            break;
        };
        let (name, value) = split_comment(item);
        out.push(
            Finding::new(kind_of(&name), "VORBIS_COMMENT", as_u64(item.len()))
                .with_field(name)
                .with_value(options, || MetadataValue::Text(xmp::name_of(value))),
        );
    }

    if out.len() == before {
        // Nothing was legible. Something is there, it is going, and saying nothing would read as
        // "no metadata here".
        out.push(Finding::new(MetadataKind::Other, "VORBIS_COMMENT", size).with_field("Comments"));
    }
}

/// Split `NAME=value` at the first `=`. A malformed item with no separator is reported whole under
/// its own bytes rather than dropped from the report.
fn split_comment(item: &[u8]) -> (String, &[u8]) {
    match item.iter().position(|byte| *byte == b'=') {
        Some(at) => (
            xmp::name_of(item.get(0..at).unwrap_or_default()),
            item.get(at.saturating_add(1)..).unwrap_or_default(),
        ),
        None => (xmp::name_of(item), &[]),
    }
}

/// Rank a comment by its field name, case-insensitively and by prefix — real files spell
/// `MUSICBRAINZ_TRACKID`, `REPLAYGAIN_TRACK_GAIN`, `DATE_RECORDED`.
fn kind_of(name: &str) -> MetadataKind {
    let upper = name.to_uppercase();
    COMMENT_KINDS
        .iter()
        .find(|(candidate, _)| upper.starts_with(candidate))
        .map_or(MetadataKind::Other, |(_, kind)| *kind)
}

/// A malformed-file error for this format.
fn malformed(detail: MalformedDetail, offset: Option<u64>) -> StryptError {
    StryptError::Malformed {
        format: Format::Flac,
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
    // lints exist to police (ADR-0006).
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::indexing_slicing,
        clippy::arithmetic_side_effects
    )]

    use super::*;

    /// A metadata block: type, length, payload. `last` sets the flag §8.1 defines.
    fn block(kind: u8, payload: &[u8], last: bool) -> Vec<u8> {
        let mut out = vec![kind | if last { 0x80 } else { 0 }];
        let length = u32::try_from(payload.len()).unwrap().to_be_bytes();
        out.extend_from_slice(&length[1..4]);
        out.extend_from_slice(payload);
        out
    }

    /// A 34-byte `STREAMINFO` whose MD5 field is `md5`.
    fn streaminfo(md5: u8) -> Vec<u8> {
        let mut payload = vec![0u8; STREAMINFO_LEN];
        for byte in payload.iter_mut().skip(STREAMINFO_MD5_AT) {
            *byte = md5;
        }
        payload
    }

    /// Two bytes that are a frame sync, standing in for the audio this handler never decodes.
    fn frames() -> Vec<u8> {
        let mut out = vec![0xFF, 0xF8];
        out.extend_from_slice(b"SYNTHETIC-AUDIO-FRAMES");
        out
    }

    /// A file: the marker, `STREAMINFO`, the given blocks, and the frames.
    fn flac(blocks: &[Vec<u8>]) -> Vec<u8> {
        let mut out = MAGIC.to_vec();
        out.extend_from_slice(&block(STREAMINFO, &streaminfo(0xAB), blocks.is_empty()));
        for (index, payload) in blocks.iter().enumerate() {
            let mut copy = payload.clone();
            if index == blocks.len() - 1 {
                copy[0] |= 0x80;
            }
            out.extend_from_slice(&copy);
        }
        out.extend_from_slice(&frames());
        out
    }

    fn le32(n: usize) -> [u8; 4] {
        u32::try_from(n)
            .expect("test lengths are small")
            .to_le_bytes()
    }

    fn comment_block(vendor: &[u8], items: &[&[u8]]) -> Vec<u8> {
        let mut payload = le32(vendor.len()).to_vec();
        payload.extend_from_slice(vendor);
        payload.extend_from_slice(&le32(items.len()));
        for item in items {
            payload.extend_from_slice(&le32(item.len()));
            payload.extend_from_slice(item);
        }
        block(VORBIS_COMMENT, &payload, false)
    }

    fn strip_ok(data: &[u8]) -> Stripped {
        FlacHandler
            .strip(data, &StripOptions::default())
            .expect("strip failed")
    }

    fn findings(data: &[u8]) -> Vec<Finding> {
        FlacHandler
            .inspect(data, &InspectOptions::names_only())
            .expect("inspect failed")
            .findings
    }

    fn contains(haystack: &[u8], needle: &[u8]) -> bool {
        haystack.windows(needle.len()).any(|w| w == needle)
    }

    #[test]
    fn a_clean_file_strips_to_a_byte_identical_copy() {
        // A block-list format edited by deletion can promise this, and so it must. TIFF and HEIF
        // cannot (ADR-0033, ADR-0034).
        let input = flac(&[]);
        let stripped = strip_ok(&input);
        assert!(stripped.report.removed.is_empty());
        assert_eq!(stripped.bytes, input);
    }

    #[test]
    fn the_audio_is_never_touched() {
        let input = flac(&[comment_block(
            b"SYNTHETIC-ENCODER",
            &[b"ARTIST=SYNTHETIC-0001"],
        )]);
        let output = strip_ok(&input).bytes;
        assert!(
            contains(&output, b"SYNTHETIC-AUDIO-FRAMES"),
            "the audio frames did not survive byte for byte"
        );
    }

    #[test]
    fn a_vorbis_comment_is_itemised_by_field_and_removed() {
        let input = flac(&[comment_block(
            b"reference libFLAC SYNTHETIC-VENDOR-0002",
            &[
                b"ARTIST=SYNTHETIC-ARTIST-0003",
                b"DATE=2026-09-01",
                b"MUSICBRAINZ_TRACKID=SYNTHETIC-0004",
            ],
        )]);
        let found = findings(&input);
        let fields: Vec<&str> = found.iter().filter_map(|f| f.field.as_deref()).collect();
        assert!(fields.contains(&"vendor"));
        assert!(fields.contains(&"ARTIST"));
        assert_eq!(
            found
                .iter()
                .find(|f| f.field.as_deref() == Some("ARTIST"))
                .unwrap()
                .kind,
            MetadataKind::PersonalIdentity
        );
        assert_eq!(
            found
                .iter()
                .find(|f| f.field.as_deref() == Some("DATE"))
                .unwrap()
                .kind,
            MetadataKind::Timestamp
        );
        assert_eq!(
            found
                .iter()
                .find(|f| f.field.as_deref() == Some("MUSICBRAINZ_TRACKID"))
                .unwrap()
                .kind,
            MetadataKind::DocumentIdentifier
        );
        assert!(
            found.iter().all(|f| f.value.is_none()),
            "values are withheld by default"
        );
        assert!(!contains(&strip_ok(&input).bytes, b"SYNTHETIC-ARTIST-0003"));
    }

    #[test]
    fn a_comment_value_is_reported_only_when_the_caller_asks() {
        let input = flac(&[comment_block(b"v", &[b"ARTIST=SYNTHETIC-ARTIST-0005"])]);
        let report = FlacHandler
            .inspect(&input, &InspectOptions::with_values())
            .unwrap();
        assert!(
            report
                .findings
                .iter()
                .any(|f| f.value == Some(MetadataValue::Text("SYNTHETIC-ARTIST-0005".to_owned())))
        );
    }

    #[test]
    fn cover_art_is_removed_and_ranked_as_a_picture() {
        // ADR-0037: cover art goes with its block. Deleting the block deletes the image and
        // whatever Exif was inside it, so no descent into it is needed (ADR-0029).
        let mut payload = 3u32.to_be_bytes().to_vec(); // front cover
        payload.extend_from_slice(&(9u32).to_be_bytes());
        payload.extend_from_slice(b"image/png");
        payload.extend_from_slice(&(24u32).to_be_bytes());
        payload.extend_from_slice(b"SYNTHETIC-DESCRIPTION-006");
        let input = flac(&[block(PICTURE, &payload[0..payload.len()], false)]);

        let found = findings(&input);
        assert_eq!(found[0].kind, MetadataKind::Thumbnail);
        assert_eq!(found[0].location, "PICTURE");
        assert!(!contains(&strip_ok(&input).bytes, b"SYNTHETIC-DESCRIPTION"));
    }

    #[test]
    fn a_cuesheet_is_removed_and_the_report_says_what_that_costs() {
        let mut payload = vec![0u8; CUESHEET_CATALOGUE_LEN];
        payload[0..9].copy_from_slice(b"012345678");
        payload.extend_from_slice(&[0u8; 8]);
        let input = flac(&[block(CUESHEET, &payload, false)]);

        let stripped = strip_ok(&input);
        assert_eq!(
            stripped.report.removed[0].kind,
            MetadataKind::DocumentIdentifier
        );
        assert_eq!(
            stripped.report.removed[0].field.as_deref(),
            Some("MediaCatalogNumber")
        );
        assert!(matches!(
            stripped.report.notes.first(),
            Some(Note::CapabilityRemoved { .. })
        ));
        assert!(!contains(&stripped.bytes, b"012345678"));
    }

    #[test]
    fn padding_keeps_its_size_and_loses_its_contents() {
        // §8.2 says a padding block is zero bits, so anything else in there was put there. Keeping
        // the length means a compliant file is unchanged and a tagger still has its room.
        let mut payload = vec![0u8; 64];
        payload[8..31].copy_from_slice(b"SYNTHETIC-IN-PADDING-07");
        let input = flac(&[block(PADDING, &payload, false)]);

        let stripped = strip_ok(&input);
        assert_eq!(stripped.report.removed[0].location, "PADDING");
        assert!(!contains(&stripped.bytes, b"SYNTHETIC-IN-PADDING-07"));
        assert_eq!(
            stripped.bytes.len(),
            input.len(),
            "the padding block changed size"
        );
    }

    #[test]
    fn zero_padding_is_left_exactly_as_it_was() {
        let input = flac(&[block(PADDING, &[0u8; 32], false)]);
        let stripped = strip_ok(&input);
        assert!(stripped.report.removed.is_empty());
        assert_eq!(stripped.bytes, input);
    }

    #[test]
    fn a_seek_table_survives_because_removal_moves_no_offset() {
        // §8.5: a seek point's offset is measured from the first frame header, not from the start
        // of the file, so it stays correct however many blocks in front of it go.
        let seek = vec![0x11u8; 18];
        let input = flac(&[
            comment_block(b"v", &[b"ARTIST=SYNTHETIC-0008"]),
            block(SEEKTABLE, &seek, false),
        ]);
        let output = strip_ok(&input).bytes;
        assert!(contains(&output, &seek));
        assert!(!contains(&output, b"SYNTHETIC-0008"));
    }

    #[test]
    fn an_application_block_is_removed_and_named_by_its_registered_id() {
        let mut payload = b"riff".to_vec();
        payload.extend_from_slice(b"SYNTHETIC-APPLICATION-0009");
        let input = flac(&[block(APPLICATION, &payload, false)]);
        let found = findings(&input);
        assert_eq!(found[0].field.as_deref(), Some("riff"));
        assert!(!contains(
            &strip_ok(&input).bytes,
            b"SYNTHETIC-APPLICATION-0009"
        ));
    }

    #[test]
    fn a_reserved_block_type_does_not_survive_by_being_unknown() {
        let input = flac(&[block(42, b"SYNTHETIC-RESERVED-0010", false)]);
        let found = findings(&input);
        assert_eq!(found[0].location, "Metadata block type 42");
        assert!(!contains(
            &strip_ok(&input).bytes,
            b"SYNTHETIC-RESERVED-0010"
        ));
    }

    #[test]
    fn the_last_block_flag_moves_to_whatever_block_ends_up_last() {
        // Removing the final block leaves the one before it last, and a file whose flag says
        // otherwise sends a decoder into the audio looking for another header.
        let input = flac(&[comment_block(b"v", &[b"ARTIST=SYNTHETIC-0011"])]);
        let output = strip_ok(&input).bytes;
        assert_eq!(
            output[4] & 0x80,
            0x80,
            "STREAMINFO was not marked as the last metadata block"
        );
        assert_eq!(output[4] & 0x7F, STREAMINFO);
    }

    #[test]
    fn the_audio_md5_is_kept_and_declared() {
        // It is computed from the samples the file still carries, so removing it hides nothing
        // from anyone holding the file — but it does link this copy to any other, so it is
        // declared rather than passed over.
        let stripped = strip_ok(&flac(&[]));
        assert_eq!(
            stripped.report.retained[0].reason,
            RetentionReason::DerivedFromPayload
        );
    }

    #[test]
    fn a_file_whose_md5_is_already_absent_declares_nothing() {
        let mut input = MAGIC.to_vec();
        input.extend_from_slice(&block(STREAMINFO, &[0u8; STREAMINFO_LEN], true));
        input.extend_from_slice(&frames());
        assert!(strip_ok(&input).report.retained.is_empty());
    }

    #[test]
    fn every_file_says_the_audio_was_not_examined() {
        let notes = FlacHandler
            .inspect(&flac(&[]), &InspectOptions::names_only())
            .unwrap()
            .notes;
        assert!(matches!(
            notes.last(),
            Some(Note::OutOfScopeContent { location }) if location.starts_with("audio frames")
        ));
    }

    #[test]
    fn stripping_twice_changes_nothing() {
        let input = flac(&[
            comment_block(b"v", &[b"ARTIST=SYNTHETIC-0012"]),
            block(PADDING, &[0x7Fu8; 16], false),
            block(APPLICATION, b"riffSYNTHETIC-0013", false),
        ]);
        let once = strip_ok(&input).bytes;
        let twice = strip_ok(&once).bytes;
        assert_eq!(once, twice, "strip is not idempotent");
    }

    /// An ID3v2.4 tag carrying one text frame.
    fn id3v2(id: &[u8], text: &[u8]) -> Vec<u8> {
        let syncsafe = |n: usize| {
            [
                u8::try_from((n >> 21) & 0x7F).unwrap(),
                u8::try_from((n >> 14) & 0x7F).unwrap(),
                u8::try_from((n >> 7) & 0x7F).unwrap(),
                u8::try_from(n & 0x7F).unwrap(),
            ]
        };
        let mut payload = vec![0x03u8];
        payload.extend_from_slice(text);
        let mut body = id.to_vec();
        body.extend_from_slice(&syncsafe(payload.len()));
        body.extend_from_slice(&[0, 0]);
        body.extend_from_slice(&payload);
        let mut out = b"ID3\x04\x00\x00".to_vec();
        out.extend_from_slice(&syncsafe(body.len()));
        out.extend_from_slice(&body);
        out
    }

    #[test]
    fn a_prepended_id3v2_tag_is_read_and_removed_rather_than_refused() {
        // ADR-0040 lifts ADR-0038 decision 7: the refusal stood only because there was no ID3
        // reader in the tree.
        let clean = flac(&[]);
        let mut input = id3v2(b"TPE1", b"SYNTHETIC-ARTIST-0101");
        input.extend_from_slice(&clean);
        let result = strip_ok(&input);
        assert_eq!(result.bytes, clean, "the FLAC behind the tag moved");
        assert!(!contains(&result.bytes, b"SYNTHETIC-ARTIST-0101"));
        assert!(
            result
                .report
                .removed
                .iter()
                .any(|f| f.location == "ID3v2.4" && f.field.as_deref() == Some("TPE1"))
        );
    }

    #[test]
    fn tags_appended_past_the_last_frame_are_removed_too() {
        let clean = flac(&[]);
        let mut input = clean.clone();
        let mut v1 = vec![0u8; 128];
        v1[0..3].copy_from_slice(b"TAG");
        v1[33..54].copy_from_slice(b"SYNTHETIC-ARTIST-0102");
        input.extend_from_slice(&v1);
        let result = strip_ok(&input);
        assert_eq!(result.bytes, clean);
        assert!(
            result
                .report
                .removed
                .iter()
                .any(|f| f.location == "ID3v1" && f.field.as_deref() == Some("Artist"))
        );
    }

    #[test]
    fn a_tag_at_each_end_leaves_the_stream_between_them_untouched() {
        let clean = flac(&[comment_block(b"SYNTHETIC-VENDOR-0103", &[])]);
        let mut input = id3v2(b"TIT2", b"SYNTHETIC-TITLE-0104");
        input.extend_from_slice(&clean);
        input.extend_from_slice(b"LYRICSBEGINSYNTHETIC-LYRIC-0105");
        input.extend_from_slice(b"LYRICSEND");
        let result = strip_ok(&input);
        assert_eq!(result.bytes, strip_ok(&clean).bytes);
        for secret in [
            &b"SYNTHETIC-TITLE-0104"[..],
            &b"SYNTHETIC-LYRIC-0105"[..],
            &b"SYNTHETIC-VENDOR-0103"[..],
        ] {
            assert!(!contains(&result.bytes, secret));
        }
    }

    #[test]
    fn a_file_that_is_not_flac_is_refused() {
        assert!(matches!(
            FlacHandler.inspect(b"fLaD\x00\x00\x00\x22", &InspectOptions::names_only()),
            Err(StryptError::Malformed {
                detail: MalformedDetail::MissingMarker,
                ..
            })
        ));
    }

    #[test]
    fn a_first_block_that_is_not_streaminfo_is_refused() {
        let mut input = MAGIC.to_vec();
        input.extend_from_slice(&block(PADDING, &[0u8; 4], true));
        input.extend_from_slice(&frames());
        assert!(matches!(
            FlacHandler.inspect(&input, &InspectOptions::names_only()),
            Err(StryptError::Malformed {
                detail: MalformedDetail::MissingMarker,
                ..
            })
        ));
    }

    #[test]
    fn the_forbidden_block_type_is_refused() {
        let mut input = MAGIC.to_vec();
        input.extend_from_slice(&block(STREAMINFO, &streaminfo(1), false));
        input.extend_from_slice(&block(FORBIDDEN, &[0u8; 2], true));
        input.extend_from_slice(&frames());
        assert!(matches!(
            FlacHandler.inspect(&input, &InspectOptions::names_only()),
            Err(StryptError::Malformed {
                detail: MalformedDetail::UnexpectedMarker,
                ..
            })
        ));
    }

    #[test]
    fn a_block_length_running_past_the_end_of_the_file_is_refused() {
        let mut input = flac(&[]);
        input[5] = 0xFF;
        assert!(matches!(
            FlacHandler.inspect(&input, &InspectOptions::names_only()),
            Err(StryptError::Malformed {
                detail: MalformedDetail::LengthOutOfRange,
                ..
            })
        ));
    }

    #[test]
    fn a_file_with_no_frame_sync_after_its_blocks_is_refused() {
        // The check that turns a lying block length into a refusal rather than a confident report
        // about bytes that were never a metadata block.
        let mut input = MAGIC.to_vec();
        input.extend_from_slice(&block(STREAMINFO, &streaminfo(1), true));
        input.extend_from_slice(b"NOT-A-FRAME");
        assert!(matches!(
            FlacHandler.strip(&input, &StripOptions::default()),
            Err(StryptError::Malformed {
                detail: MalformedDetail::MissingMarker,
                ..
            })
        ));
    }

    #[test]
    fn a_second_streaminfo_is_refused() {
        let mut input = MAGIC.to_vec();
        input.extend_from_slice(&block(STREAMINFO, &streaminfo(1), false));
        input.extend_from_slice(&block(STREAMINFO, &streaminfo(2), true));
        input.extend_from_slice(&frames());
        assert!(matches!(
            FlacHandler.inspect(&input, &InspectOptions::names_only()),
            Err(StryptError::Malformed {
                detail: MalformedDetail::UnexpectedMarker,
                ..
            })
        ));
    }

    #[test]
    fn a_streaminfo_of_the_wrong_length_is_refused() {
        let mut input = MAGIC.to_vec();
        input.extend_from_slice(&block(STREAMINFO, &[0u8; 20], true));
        input.extend_from_slice(&frames());
        assert!(matches!(
            FlacHandler.inspect(&input, &InspectOptions::names_only()),
            Err(StryptError::Malformed {
                detail: MalformedDetail::LengthOutOfRange,
                ..
            })
        ));
    }

    #[test]
    fn a_comment_block_whose_lengths_do_not_add_up_is_reported_and_deleted() {
        // A block strypt cannot read is still one it can delete, and deleting is the safe
        // direction (the JXL handler takes the same line on an unreadable Exif block).
        let mut payload = 0xFFFF_FFFFu32.to_le_bytes().to_vec();
        payload.extend_from_slice(b"SYNTHETIC-UNREADABLE-0014");
        let input = flac(&[block(VORBIS_COMMENT, &payload, false)]);

        let stripped = strip_ok(&input);
        assert_eq!(stripped.report.removed[0].location, "VORBIS_COMMENT");
        assert!(!contains(&stripped.bytes, b"SYNTHETIC-UNREADABLE-0014"));
    }

    #[test]
    fn a_block_count_beyond_the_limit_is_refused() {
        let blocks: Vec<Vec<u8>> = (0..64).map(|_| block(PADDING, &[0u8; 1], false)).collect();
        let input = flac(&blocks);
        let options = StripOptions {
            limits: ParseLimits {
                max_items: 8,
                ..ParseLimits::default()
            },
            ..StripOptions::default()
        };
        assert!(matches!(
            FlacHandler.strip(&input, &options),
            Err(StryptError::LimitExceeded { .. })
        ));
    }

    #[test]
    fn truncation_at_every_length_is_refused_or_survived_but_never_panics() {
        let input = flac(&[
            comment_block(b"vendor", &[b"ARTIST=SYNTHETIC-0015"]),
            block(PICTURE, b"\0\0\0\x03\0\0\0\x09image/pngSYNTHETIC", false),
            block(PADDING, &[0u8; 8], false),
        ]);
        for n in 0..=input.len() {
            let prefix = &input[0..n];
            let _ = FlacHandler.inspect(prefix, &InspectOptions::names_only());
            let _ = FlacHandler.strip(prefix, &StripOptions::default());
        }
    }
}
