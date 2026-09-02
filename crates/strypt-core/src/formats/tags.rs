//! The tags glued to the ends of an audio file: ID3v2 at the head, ID3v1, APE and Lyrics3 at the
//! tail.
//!
//! Shared by [`super::mp3`] and [`super::flac`], as [`super::xmp`] is shared by every image
//! handler and for the same reason: the tag is the same wherever it is stuck, and two handlers
//! have no business disagreeing about what is in one (ADR-0040).
//!
//! # This module names byte ranges. It never rewrites one
//!
//! Everything here is removed whole, so nothing in this file decides what goes — it decides where
//! a tag *ends*, and how the report reads. That split is what keeps the fail-closed surface small:
//! a mis-parsed frame costs a line of a report, while a mis-parsed tag length would cost the
//! boundary between metadata and audio, which is the one number that must be right.
//!
//! Itemising is therefore best-effort and removal is not, exactly as
//! [`super::flac`]'s Vorbis comment handling is. A tag whose insides do not add up is reported in
//! one line and deleted.
//!
//! # Where the specifications are
//!
//! ID3v2.2 (informal, 1998), ID3v2.3 (1999) and ID3v2.4 (2000) at `id3.org`; ID3v1 is a
//! convention rather than a specification; APEv2 from the Monkey's Audio project; Lyrics3 v1 and
//! v2 from `id3.org/Lyrics3`. Section numbers below are ID3v2.4's unless another is named.

use crate::bytes::Reader;
use crate::error::{MalformedDetail, ResourceLimit};
use crate::formats::xmp::name_of;
use crate::report::{Finding, InspectOptions, MetadataKind, MetadataValue};

/// How many tags may be peeled from one end of a file.
///
/// Taggers really do stack an ID3v2 on an ID3v2, and a file may carry Lyrics3, APE and ID3v1 at
/// once. Sixteen is past every real arrangement and short of a file that is nothing but headers.
const MAX_TAGS: u32 = 16;

/// How many items inside one tag are itemised before the rest is covered by the whole-tag line.
///
/// The tag goes whole whatever this is; the cap bounds only how many findings one file can
/// produce, because a report is itself allocated and rendered.
const MAX_ITEMS: u32 = 512;

/// An ID3v2 header, and the footer §3.1 permits at the other end of the tag.
const ID3V2_HEADER: usize = 10;
/// An ID3v1 tag is exactly this many bytes, at the very end of the file.
const ID3V1_BYTES: usize = 128;
/// The extended `TAG+` block, which sits immediately in front of an ID3v1 tag.
const ID3V1_EXTENDED_BYTES: usize = 227;
/// An APE header or footer.
const APE_FOOTER_BYTES: usize = 32;
/// `LYRICSBEGIN` plus six size digits plus `LYRICS200`.
const LYRICS3V2_MINIMUM: usize = 26;
/// Lyrics3 v1 has no size field, so its start is searched for. §"Lyrics3 v1.00" caps a tag at 5100
/// bytes, which is what bounds the search.
const LYRICS3V1_LIMIT: usize = 5100;

/// Which tag a span turned out to be.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum TagKind {
    /// An ID3v2 tag at the head of the file. `major` is 2, 3 or 4.
    Id3v2 { major: u8, flags: u8 },
    /// An ID3v1 tag at the very end, with the `TAG+` extension when one precedes it.
    Id3v1 { extended: bool },
    /// An APE tag, v1 or v2.
    Ape { version: u32 },
    /// A Lyrics3 tag, v1 or v2.
    Lyrics3 { version: u8 },
}

impl TagKind {
    /// The format-domain identifier this tag is reported under.
    pub(crate) fn location(self) -> String {
        match self {
            Self::Id3v2 { major, .. } => format!("ID3v2.{major}"),
            Self::Id3v1 { extended: true } => "ID3v1 (with TAG+)".to_owned(),
            Self::Id3v1 { extended: false } => "ID3v1".to_owned(),
            Self::Ape { version } => format!("APE (version {version})"),
            Self::Lyrics3 { version } => format!("Lyrics3 v{version}"),
        }
    }
}

/// One tag, and the exact bytes it occupied.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Tag<'a> {
    pub(crate) kind: TagKind,
    /// The whole tag, header and footer included. This is the span that is deleted.
    pub(crate) raw: &'a [u8],
}

/// Why a scan stopped.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum TagError {
    /// The tag violates its own structure.
    Malformed {
        detail: MalformedDetail,
        offset: usize,
    },
    /// A parser ceiling was hit.
    Limit(ResourceLimit),
}

impl TagError {
    const fn at(detail: MalformedDetail, offset: usize) -> Self {
        Self::Malformed { detail, offset }
    }
}

/// Peel every ID3v2 tag off the front of `input`.
///
/// Returns the tags in file order and the offset where the first byte that is not a tag begins.
///
/// # Errors
///
/// [`TagError`] when a tag's declared size runs past the end of the file, when its size field is
/// not the syncsafe integer §6.2 requires, or when it declares a major version whose header this
/// code cannot read — each refused rather than guessed at, because the number in question is the
/// boundary between metadata and audio.
pub(crate) fn head(input: &[u8]) -> Result<(Vec<Tag<'_>>, usize), TagError> {
    let mut out = Vec::new();
    let mut at = 0usize;
    let mut budget = MAX_TAGS;

    while input.get(at..at.saturating_add(3)) == Some(b"ID3") {
        spend(&mut budget)?;
        let rest = input.get(at..).unwrap_or_default();
        let (kind, len) = id3v2_span(rest, at)?;
        let raw = rest
            .get(..len)
            .ok_or(TagError::at(MalformedDetail::LengthOutOfRange, at))?;
        out.push(Tag { kind, raw });
        // Cannot loop forever: `id3v2_span` never returns a length below the header size.
        at = at.saturating_add(len);
    }
    Ok((out, at))
}

/// Measure one ID3v2 tag starting at the front of `data`, which begins at `offset` in the file.
fn id3v2_span(data: &[u8], offset: usize) -> Result<(TagKind, usize), TagError> {
    let mut r = Reader::new(data);
    r.skip(3)
        .ok_or(TagError::at(MalformedDetail::Truncated, offset))?;
    let major = r
        .u8()
        .ok_or(TagError::at(MalformedDetail::Truncated, offset))?;
    let _revision = r
        .u8()
        .ok_or(TagError::at(MalformedDetail::Truncated, offset))?;
    let flags = r
        .u8()
        .ok_or(TagError::at(MalformedDetail::Truncated, offset))?;
    let size = r
        .take(4)
        .ok_or(TagError::at(MalformedDetail::Truncated, offset))?;

    if !matches!(major, 2..=4) {
        // §3.1 promises that a later major version keeps the header but not the body. A tag whose
        // header this code has never read is one whose *length* it cannot trust, and length is the
        // only field here that must be right.
        return Err(TagError::at(MalformedDetail::UnsupportedFeature, offset));
    }
    let Some(body) = syncsafe(size) else {
        return Err(TagError::at(MalformedDetail::LengthOutOfRange, offset));
    };

    // §3.1: the size counts neither the header it sits in nor the optional footer.
    let footer = if flags & 0x10 != 0 && major == 4 {
        ID3V2_HEADER
    } else {
        0
    };
    let total = ID3V2_HEADER
        .checked_add(body)
        .and_then(|n| n.checked_add(footer))
        .ok_or(TagError::at(MalformedDetail::LengthOutOfRange, offset))?;
    if total > data.len() {
        return Err(TagError::at(MalformedDetail::LengthOutOfRange, offset));
    }
    Ok((TagKind::Id3v2 { major, flags }, total))
}

/// A syncsafe integer: four bytes carrying seven bits each, with every high bit clear (§6.2).
///
/// A high bit that is set means the field is not syncsafe, which in turn means the writer's idea
/// of the tag's length is not the one this code would compute. Refusing is the only safe reading.
fn syncsafe(bytes: &[u8]) -> Option<usize> {
    let mut total: usize = 0;
    for byte in bytes {
        if byte & 0x80 != 0 {
            return None;
        }
        total = total
            .checked_mul(128)?
            .checked_add(usize::from(byte & 0x7F))?;
    }
    Some(total)
}

/// Peel every recognised tag off the end of `input`, stopping at `floor`.
///
/// Returns the tags in file order and the offset at which the payload ends. `floor` is where the
/// caller's payload starts — the byte after the head tags — so that a lying size cannot make a
/// tail tag swallow the audio.
///
/// # Errors
///
/// [`TagError`] when a tag's declared size runs below `floor` or past the end of the file, or when
/// an APE footer claims a header that is not there.
pub(crate) fn tail(input: &[u8], floor: usize) -> Result<(Vec<Tag<'_>>, usize), TagError> {
    let mut out = Vec::new();
    let mut end = input.len().max(floor);
    let mut budget = MAX_TAGS;

    while let Some((kind, start)) = peel(input, floor, end)? {
        spend(&mut budget)?;
        let raw = input
            .get(start..end)
            .ok_or(TagError::at(MalformedDetail::LengthOutOfRange, start))?;
        out.push(Tag { kind, raw });
        // `peel` never returns `start == end`, so this terminates.
        end = start;
    }

    out.reverse();
    Ok((out, end))
}

/// Identify the tag ending at `end`, and say where it starts. [`None`] when there is not one.
fn peel(input: &[u8], floor: usize, end: usize) -> Result<Option<(TagKind, usize)>, TagError> {
    let available = end.saturating_sub(floor);

    // ID3v1 is last in the file by convention, so it is tried first.
    if available >= ID3V1_BYTES {
        let start = end.saturating_sub(ID3V1_BYTES);
        if input.get(start..start.saturating_add(3)) == Some(b"TAG") {
            // The `TAG+` extension sits immediately in front, and is part of the same tag.
            let extended_at = start.saturating_sub(ID3V1_EXTENDED_BYTES);
            let extended = start.saturating_sub(floor) >= ID3V1_EXTENDED_BYTES
                && input.get(extended_at..extended_at.saturating_add(4)) == Some(b"TAG+");
            return Ok(Some((
                TagKind::Id3v1 { extended },
                if extended { extended_at } else { start },
            )));
        }
    }

    if available >= APE_FOOTER_BYTES {
        let at = end.saturating_sub(APE_FOOTER_BYTES);
        if input.get(at..at.saturating_add(8)) == Some(b"APETAGEX") {
            return ape(input, floor, end, at).map(Some);
        }
    }

    if available >= LYRICS3V2_MINIMUM && input.get(end.saturating_sub(9)..end) == Some(b"LYRICS200")
    {
        return lyrics3v2(input, floor, end).map(Some);
    }
    if available > 9 && input.get(end.saturating_sub(9)..end) == Some(b"LYRICSEND") {
        return Ok(
            lyrics3v1(input, floor, end).map(|start| (TagKind::Lyrics3 { version: 1 }, start))
        );
    }

    Ok(None)
}

/// An APE tag, measured from the footer at `at`.
///
/// The footer's size field counts the footer and every item but *not* the optional header, which
/// is what the flag at bit 31 declares.
fn ape(input: &[u8], floor: usize, end: usize, at: usize) -> Result<(TagKind, usize), TagError> {
    let mut r = Reader::new(input.get(at..end).unwrap_or_default());
    r.skip(8)
        .ok_or(TagError::at(MalformedDetail::Truncated, at))?;
    let version = r
        .u32_le()
        .ok_or(TagError::at(MalformedDetail::Truncated, at))?;
    let size = r
        .u32_le()
        .and_then(|n| usize::try_from(n).ok())
        .ok_or(TagError::at(MalformedDetail::LengthOutOfRange, at))?;
    r.skip(4)
        .ok_or(TagError::at(MalformedDetail::Truncated, at))?;
    let flags = r
        .u32_le()
        .ok_or(TagError::at(MalformedDetail::Truncated, at))?;

    if size < APE_FOOTER_BYTES {
        return Err(TagError::at(MalformedDetail::LengthOutOfRange, at));
    }
    let has_header = flags & 0x8000_0000 != 0;
    let total = if has_header {
        size.checked_add(APE_FOOTER_BYTES)
            .ok_or(TagError::at(MalformedDetail::LengthOutOfRange, at))?
    } else {
        size
    };
    if total > end.saturating_sub(floor) {
        return Err(TagError::at(MalformedDetail::LengthOutOfRange, at));
    }
    let start = end.saturating_sub(total);
    if has_header && input.get(start..start.saturating_add(8)) != Some(b"APETAGEX") {
        // The footer says a header is there. A file where it is not has lied about the one field
        // that decides where the audio ends.
        return Err(TagError::at(MalformedDetail::MissingMarker, start));
    }
    Ok((TagKind::Ape { version }, start))
}

/// A Lyrics3 v2 tag: `LYRICSBEGIN`, the lyrics, six ASCII size digits, then `LYRICS200`.
///
/// The size counts `LYRICSBEGIN` and the fields, but neither the six digits nor the closing
/// marker, so the tag is fifteen bytes longer than it says. Checked against `ExifTool`'s
/// `ID3.pm` (`$len = $1 + 15`, 13.55) rather than read off the specification page.
fn lyrics3v2(input: &[u8], floor: usize, end: usize) -> Result<(TagKind, usize), TagError> {
    let digits_at = end.saturating_sub(15);
    let digits = input
        .get(digits_at..digits_at.saturating_add(6))
        .ok_or(TagError::at(MalformedDetail::Truncated, digits_at))?;
    let mut size: usize = 0;
    for digit in digits {
        let value = digit
            .checked_sub(b'0')
            .filter(|v| *v < 10)
            .ok_or(TagError::at(MalformedDetail::LengthOutOfRange, digits_at))?;
        size = size
            .checked_mul(10)
            .and_then(|n| n.checked_add(usize::from(value)))
            .ok_or(TagError::at(MalformedDetail::LengthOutOfRange, digits_at))?;
    }
    let total = size
        .checked_add(15)
        .ok_or(TagError::at(MalformedDetail::LengthOutOfRange, digits_at))?;
    if total > end.saturating_sub(floor) {
        return Err(TagError::at(MalformedDetail::LengthOutOfRange, digits_at));
    }
    let start = end.saturating_sub(total);
    if input.get(start..start.saturating_add(11)) != Some(b"LYRICSBEGIN") {
        return Err(TagError::at(MalformedDetail::MissingMarker, start));
    }
    Ok((TagKind::Lyrics3 { version: 2 }, start))
}

/// A Lyrics3 v1 tag, which carries no size at all: `LYRICSBEGIN`, the lyrics, `LYRICSEND`.
///
/// Found by searching backwards, bounded by the 5100-byte ceiling the specification sets. Returns
/// [`None`] rather than an error when the opener is not there: without a size field there is
/// nothing to have lied, and a `LYRICSEND` that is really audio must not refuse the file.
fn lyrics3v1(input: &[u8], floor: usize, end: usize) -> Option<usize> {
    let window = end.saturating_sub(floor).min(LYRICS3V1_LIMIT);
    let from = end.saturating_sub(window);
    let region = input.get(from..end)?;
    let at = region
        .windows(11)
        .rposition(|candidate| candidate == b"LYRICSBEGIN")?;
    Some(from.saturating_add(at))
}

/// Charge one structural item against a budget.
fn spend(budget: &mut u32) -> Result<(), TagError> {
    *budget = budget
        .checked_sub(1)
        .ok_or(TagError::Limit(ResourceLimit::ItemCount))?;
    Ok(())
}

/// ID3v2 frame identifiers worth ranking, in the four-character spelling of v2.3 and v2.4.
///
/// A ranking table and never a filter: the tag goes whole, so a frame missing from here is
/// reported under [`MetadataKind::Other`] and removed exactly the same.
const FRAME_KINDS: &[(&[u8], MetadataKind)] = &[
    (b"TPE1", MetadataKind::PersonalIdentity),
    (b"TPE2", MetadataKind::PersonalIdentity),
    (b"TPE3", MetadataKind::PersonalIdentity),
    (b"TPE4", MetadataKind::PersonalIdentity),
    (b"TCOM", MetadataKind::PersonalIdentity),
    (b"TEXT", MetadataKind::PersonalIdentity),
    (b"TOPE", MetadataKind::PersonalIdentity),
    (b"TOLY", MetadataKind::PersonalIdentity),
    (b"TPUB", MetadataKind::PersonalIdentity),
    (b"TOWN", MetadataKind::PersonalIdentity),
    (b"TCOP", MetadataKind::PersonalIdentity),
    // The tagger, and often the machine it ran on.
    (b"TENC", MetadataKind::PersonalIdentity),
    (b"TDRC", MetadataKind::Timestamp),
    (b"TDEN", MetadataKind::Timestamp),
    (b"TDOR", MetadataKind::Timestamp),
    (b"TDRL", MetadataKind::Timestamp),
    (b"TDTG", MetadataKind::Timestamp),
    (b"TYER", MetadataKind::Timestamp),
    (b"TDAT", MetadataKind::Timestamp),
    (b"TIME", MetadataKind::Timestamp),
    (b"TRDA", MetadataKind::Timestamp),
    (b"TSSE", MetadataKind::SoftwareFingerprint),
    (b"TMED", MetadataKind::SoftwareFingerprint),
    (b"TFLT", MetadataKind::SoftwareFingerprint),
    // Cover art, which is an ordinary image file with whatever its own container carries.
    (b"APIC", MetadataKind::Thumbnail),
    // Any file at all, base64 or raw, under a name the tagger chose.
    (b"GEOB", MetadataKind::Thumbnail),
    (b"UFID", MetadataKind::DocumentIdentifier),
    (b"MCDI", MetadataKind::DocumentIdentifier),
    (b"TSRC", MetadataKind::DocumentIdentifier),
    (b"PRIV", MetadataKind::DocumentIdentifier),
    (b"COMM", MetadataKind::Comment),
    (b"USLT", MetadataKind::Comment),
    (b"SYLT", MetadataKind::Comment),
    (b"TXXX", MetadataKind::Comment),
    (b"TIT1", MetadataKind::Comment),
    (b"TIT2", MetadataKind::Comment),
    (b"TIT3", MetadataKind::Comment),
    (b"TALB", MetadataKind::Comment),
    // A geotagging convention some taggers use, and the only place ID3 names a place directly.
    (b"TLOC", MetadataKind::Location),
];

/// The v2.2 spelling of the frames above, which is three characters rather than four (§4 of the
/// v2.2 document).
const FRAME_KINDS_V22: &[(&[u8], MetadataKind)] = &[
    (b"TP1", MetadataKind::PersonalIdentity),
    (b"TP2", MetadataKind::PersonalIdentity),
    (b"TP3", MetadataKind::PersonalIdentity),
    (b"TCM", MetadataKind::PersonalIdentity),
    (b"TCR", MetadataKind::PersonalIdentity),
    (b"TEN", MetadataKind::PersonalIdentity),
    (b"TYE", MetadataKind::Timestamp),
    (b"TDA", MetadataKind::Timestamp),
    (b"TIM", MetadataKind::Timestamp),
    (b"TSS", MetadataKind::SoftwareFingerprint),
    (b"PIC", MetadataKind::Thumbnail),
    (b"GEO", MetadataKind::Thumbnail),
    (b"UFI", MetadataKind::DocumentIdentifier),
    (b"MCI", MetadataKind::DocumentIdentifier),
    (b"TRC", MetadataKind::DocumentIdentifier),
    (b"COM", MetadataKind::Comment),
    (b"ULT", MetadataKind::Comment),
    (b"TXX", MetadataKind::Comment),
    (b"TT1", MetadataKind::Comment),
    (b"TT2", MetadataKind::Comment),
    (b"TT3", MetadataKind::Comment),
    (b"TAL", MetadataKind::Comment),
];

/// The ID3v1 fields, by offset and width.
const ID3V1_FIELDS: &[(usize, usize, &str, MetadataKind)] = &[
    (3, 30, "Title", MetadataKind::Comment),
    (33, 30, "Artist", MetadataKind::PersonalIdentity),
    (63, 30, "Album", MetadataKind::Comment),
    (93, 4, "Year", MetadataKind::Timestamp),
    (97, 30, "Comment", MetadataKind::Comment),
];

/// Name what is in `tag`, for the report.
///
/// Best-effort by design, per this module's header: the caller deletes the whole span whatever
/// comes back, and a tag whose insides do not parse yields one line rather than none — silence
/// would read as "there was nothing here".
pub(crate) fn findings(tag: &Tag<'_>, options: &InspectOptions) -> Vec<Finding> {
    let location = tag.kind.location();
    let mut out = Vec::new();
    match tag.kind {
        TagKind::Id3v2 { major, flags } => {
            id3v2_frames(tag.raw, major, flags, &location, options, &mut out);
        }
        TagKind::Id3v1 { .. } => id3v1_fields(tag.raw, &location, options, &mut out),
        TagKind::Ape { .. } => ape_items(tag.raw, &location, options, &mut out),
        TagKind::Lyrics3 { .. } => {}
    }
    if out.is_empty() {
        out.push(
            Finding::new(MetadataKind::Other, location, as_u64(tag.raw.len()))
                .with_field("Tag")
                .with_value(options, || MetadataValue::Opaque {
                    bytes: as_u64(tag.raw.len()),
                }),
        );
    }
    out
}

/// Walk an ID3v2 tag's frames.
fn id3v2_frames(
    raw: &[u8],
    major: u8,
    flags: u8,
    location: &str,
    options: &InspectOptions,
    out: &mut Vec<Finding>,
) {
    // §6.1: with the unsynchronisation flag set, every `FF 00` in the tag stands for a single
    // `FF`, so frame sizes read from the raw bytes would be measured in the wrong units. Undone on
    // a copy, and only for the report — the span that is deleted is the untouched one.
    let undone;
    let body = if flags & 0x80 == 0 {
        raw
    } else {
        undone = desynchronise(raw);
        undone.as_slice()
    };

    let Some(mut at) = frames_start(body, major, flags) else {
        return;
    };
    let (id_len, size_len, flag_len) = if major == 2 { (3, 3, 0) } else { (4, 4, 2) };
    let mut budget = MAX_ITEMS;

    while spend(&mut budget).is_ok() {
        let Some(id) = body.get(at..at.saturating_add(id_len)) else {
            return;
        };
        if id.iter().all(|b| *b == 0) {
            // §3.2's padding: the rest of the tag is zeros, and there are no more frames.
            return;
        }
        if !id.iter().all(u8::is_ascii_alphanumeric) {
            return;
        }
        let header = id_len.saturating_add(size_len).saturating_add(flag_len);
        let Some(size_bytes) =
            body.get(at.saturating_add(id_len)..at.saturating_add(id_len).saturating_add(size_len))
        else {
            return;
        };
        // v2.4 made the frame size syncsafe (§4); v2.2 and v2.3 write a plain integer.
        let Some(size) = (if major == 4 {
            syncsafe(size_bytes).or_else(|| plain(size_bytes))
        } else {
            plain(size_bytes)
        }) else {
            return;
        };
        let Some(payload) = body
            .get(at.saturating_add(header)..)
            .and_then(|rest| rest.get(..size))
        else {
            return;
        };

        let table = if major == 2 {
            FRAME_KINDS_V22
        } else {
            FRAME_KINDS
        };
        let kind = table
            .iter()
            .find(|(candidate, _)| *candidate == id)
            .map_or(MetadataKind::Other, |(_, kind)| *kind);
        out.push(
            Finding::new(kind, location.to_owned(), as_u64(size))
                .with_field(name_of(id))
                .with_value(options, || text_value(payload)),
        );

        let Some(next) = at
            .checked_add(header)
            .and_then(|n| n.checked_add(size))
            .filter(|n| *n > at)
        else {
            return;
        };
        at = next;
    }
}

/// Where an ID3v2 tag's first frame begins: past the header, and past the extended header when
/// §3.2's flag says there is one.
fn frames_start(body: &[u8], major: u8, flags: u8) -> Option<usize> {
    if body.len() < ID3V2_HEADER {
        return None;
    }
    if flags & 0x40 == 0 {
        return Some(ID3V2_HEADER);
    }
    let size_bytes = body.get(ID3V2_HEADER..ID3V2_HEADER.saturating_add(4))?;
    // v2.4's extended header size is syncsafe and counts itself; v2.3's is a plain integer that
    // does not. v2.2 has no extended header at all — the flag means compression there, and a
    // compressed tag is one this best-effort walk simply does not itemise.
    let skip = match major {
        4 => syncsafe(size_bytes)?,
        3 => plain(size_bytes)?.checked_add(4)?,
        _ => return None,
    };
    ID3V2_HEADER.checked_add(skip)
}

/// A plain big-endian integer of up to four bytes.
fn plain(bytes: &[u8]) -> Option<usize> {
    let mut total: usize = 0;
    for byte in bytes {
        total = total.checked_mul(256)?.checked_add(usize::from(*byte))?;
    }
    Some(total)
}

/// Undo §6.1's unsynchronisation: every `FF 00` stands for one `FF`.
fn desynchronise(raw: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(raw.len());
    let mut skip = false;
    for (index, byte) in raw.iter().enumerate() {
        if skip {
            skip = false;
            continue;
        }
        out.push(*byte);
        // The header itself is never unsynchronised, so the rewrite starts after it.
        if index >= ID3V2_HEADER && *byte == 0xFF && raw.get(index.saturating_add(1)) == Some(&0x00)
        {
            skip = true;
        }
    }
    out
}

/// The fields of an ID3v1 tag, which are fixed-width and start at fixed offsets.
fn id3v1_fields(raw: &[u8], location: &str, options: &InspectOptions, out: &mut Vec<Finding>) {
    // A `TAG+` extension shifts the 128-byte tag to the end of the span.
    let tag = raw
        .get(raw.len().saturating_sub(ID3V1_BYTES)..)
        .unwrap_or(raw);
    if raw.len() > ID3V1_BYTES {
        out.push(
            Finding::new(
                MetadataKind::Comment,
                location.to_owned(),
                as_u64(raw.len().saturating_sub(ID3V1_BYTES)),
            )
            .with_field("TAG+"),
        );
    }
    for (at, width, name, kind) in ID3V1_FIELDS {
        let Some(value) = tag.get(*at..at.saturating_add(*width)) else {
            continue;
        };
        if value.iter().all(|b| *b == 0 || *b == b' ') {
            continue;
        }
        out.push(
            Finding::new(*kind, location.to_owned(), as_u64(*width))
                .with_field(*name)
                .with_value(options, || text_value(value)),
        );
    }
}

/// The items of an APE tag: a size, flags, a NUL-terminated key, then the value.
fn ape_items(raw: &[u8], location: &str, options: &InspectOptions, out: &mut Vec<Finding>) {
    // The span may open with a header, which has the same shape as the footer that closes it.
    let start = if raw.get(..8) == Some(b"APETAGEX") {
        APE_FOOTER_BYTES
    } else {
        0
    };
    let Some(items) = raw.get(start..raw.len().saturating_sub(APE_FOOTER_BYTES)) else {
        return;
    };
    let mut r = Reader::new(items);
    let mut budget = MAX_ITEMS;

    while spend(&mut budget).is_ok() {
        let Some(size) = r.u32_le().and_then(|n| usize::try_from(n).ok()) else {
            return;
        };
        if r.skip(4).is_none() {
            return;
        }
        let mut key = Vec::new();
        loop {
            match r.u8() {
                Some(0) => break,
                Some(byte) => key.push(byte),
                None => return,
            }
        }
        let Some(value) = r.take(size) else {
            return;
        };
        let name = name_of(&key);
        out.push(
            Finding::new(ape_kind(&name), location.to_owned(), as_u64(size))
                .with_field(name)
                .with_value(options, || text_value(value)),
        );
    }
}

/// Rank an APE item by its key, which is free text rather than a fixed vocabulary.
fn ape_kind(name: &str) -> MetadataKind {
    let upper = name.to_uppercase();
    for (candidate, kind) in [
        ("ARTIST", MetadataKind::PersonalIdentity),
        ("COMPOSER", MetadataKind::PersonalIdentity),
        ("PERFORMER", MetadataKind::PersonalIdentity),
        ("COPYRIGHT", MetadataKind::PersonalIdentity),
        ("PUBLISHER", MetadataKind::PersonalIdentity),
        ("YEAR", MetadataKind::Timestamp),
        ("RECORD DATE", MetadataKind::Timestamp),
        ("TOOL", MetadataKind::SoftwareFingerprint),
        ("ENCODER", MetadataKind::SoftwareFingerprint),
        ("REPLAYGAIN", MetadataKind::Other),
        ("ISRC", MetadataKind::DocumentIdentifier),
        ("CATALOG", MetadataKind::DocumentIdentifier),
        ("COVER ART", MetadataKind::Thumbnail),
        ("COMMENT", MetadataKind::Comment),
    ] {
        if upper.starts_with(candidate) {
            return kind;
        }
    }
    MetadataKind::Other
}

/// A frame or field payload as a reportable value.
///
/// ID3 text frames open with an encoding byte (§4), and the UTF-16 encodings interleave NUL bytes
/// that [`name_of`] filters out as control characters — so a UTF-16 value of ASCII text still
/// reads correctly without a decoder for it. A payload that is not text is reported by its length.
fn text_value(payload: &[u8]) -> MetadataValue {
    let text = match payload.first() {
        Some(0..=3) => payload.get(1..).unwrap_or_default(),
        _ => payload,
    };
    let rendered = name_of(text);
    if rendered.trim().is_empty() {
        MetadataValue::Opaque {
            bytes: as_u64(payload.len()),
        }
    } else {
        MetadataValue::Text(rendered)
    }
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

    fn byte(n: usize) -> u8 {
        u8::try_from(n & 0x7F).unwrap()
    }

    fn syncsafe_bytes(n: usize) -> [u8; 4] {
        [byte(n >> 21), byte(n >> 14), byte(n >> 7), byte(n)]
    }

    fn le32(n: usize) -> [u8; 4] {
        u32::try_from(n).unwrap().to_le_bytes()
    }

    fn frame(id: &[u8], text: &[u8]) -> Vec<u8> {
        let mut payload = vec![0x03u8];
        payload.extend_from_slice(text);
        let mut out = id.to_vec();
        out.extend_from_slice(&syncsafe_bytes(payload.len()));
        out.extend_from_slice(&[0, 0]);
        out.extend_from_slice(&payload);
        out
    }

    fn id3v2(frames: &[Vec<u8>], flags: u8) -> Vec<u8> {
        let body: Vec<u8> = frames.concat();
        let mut out = b"ID3\x04\x00".to_vec();
        out.push(flags);
        out.extend_from_slice(&syncsafe_bytes(body.len()));
        out.extend_from_slice(&body);
        out
    }

    fn options() -> InspectOptions {
        InspectOptions::with_values()
    }

    #[test]
    fn a_head_tag_is_measured_from_its_syncsafe_size() {
        let tag = id3v2(&[frame(b"TPE1", b"SYNTHETIC-0001")], 0);
        let mut input = tag.clone();
        input.extend_from_slice(b"AUDIO");
        let (tags, at) = head(&input).unwrap();
        assert_eq!(tags.len(), 1);
        assert_eq!(at, tag.len());
        assert_eq!(tags[0].raw, tag.as_slice());
    }

    #[test]
    fn stacked_head_tags_are_all_peeled() {
        // Taggers really do write a second tag in front of the first.
        let mut input = id3v2(&[frame(b"TIT2", b"SYNTHETIC-0002")], 0);
        input.extend_from_slice(&id3v2(&[frame(b"TPE1", b"SYNTHETIC-0003")], 0));
        let audio_at = input.len();
        input.extend_from_slice(b"AUDIO");
        let (tags, at) = head(&input).unwrap();
        assert_eq!(tags.len(), 2);
        assert_eq!(at, audio_at);
    }

    #[test]
    fn a_size_field_that_is_not_syncsafe_is_refused() {
        // A set high bit means the writer's idea of the tag's length is not this code's, and that
        // length is the boundary between metadata and audio.
        let mut input = id3v2(&[frame(b"TIT2", b"x")], 0);
        input[6] = 0x80;
        assert!(matches!(
            head(&input),
            Err(TagError::Malformed {
                detail: MalformedDetail::LengthOutOfRange,
                ..
            })
        ));
    }

    #[test]
    fn a_major_version_this_code_cannot_read_is_refused() {
        let mut input = id3v2(&[frame(b"TIT2", b"x")], 0);
        input[3] = 5;
        assert!(matches!(
            head(&input),
            Err(TagError::Malformed {
                detail: MalformedDetail::UnsupportedFeature,
                ..
            })
        ));
    }

    #[test]
    fn a_tag_longer_than_the_file_is_refused_not_clamped() {
        let mut input = id3v2(&[frame(b"TIT2", b"x")], 0);
        input[6..10].copy_from_slice(&syncsafe_bytes(0x0010_0000));
        assert!(matches!(
            head(&input),
            Err(TagError::Malformed {
                detail: MalformedDetail::LengthOutOfRange,
                ..
            })
        ));
    }

    #[test]
    fn a_footer_adds_its_ten_bytes_to_the_span() {
        let body = frame(b"TIT2", b"SYNTHETIC-0004");
        let mut input = id3v2(std::slice::from_ref(&body), 0x10);
        input.extend_from_slice(b"3DI\x04\x00\x10");
        input.extend_from_slice(&syncsafe_bytes(body.len()));
        let (tags, at) = head(&input).unwrap();
        assert_eq!(at, ID3V2_HEADER + body.len() + ID3V2_HEADER);
        assert_eq!(tags[0].raw.len(), at);
    }

    #[test]
    fn frames_are_itemised_and_ranked() {
        let tag = id3v2(
            &[
                frame(b"TPE1", b"SYNTHETIC-ARTIST-0005"),
                frame(b"TDRC", b"2026-09-02"),
                frame(b"TSSE", b"SYNTHETIC-ENCODER-0006"),
                frame(b"APIC", b"SYNTHETIC-COVER-0007"),
            ],
            0,
        );
        let (tags, _) = head(&tag).unwrap();
        let found = findings(&tags[0], &options());
        let by_field = |name: &str| found.iter().find(|f| f.field.as_deref() == Some(name));
        assert_eq!(
            by_field("TPE1").unwrap().kind,
            MetadataKind::PersonalIdentity
        );
        assert_eq!(by_field("TDRC").unwrap().kind, MetadataKind::Timestamp);
        assert_eq!(
            by_field("TSSE").unwrap().kind,
            MetadataKind::SoftwareFingerprint
        );
        assert_eq!(by_field("APIC").unwrap().kind, MetadataKind::Thumbnail);
        assert_eq!(
            by_field("TPE1").unwrap().value,
            Some(MetadataValue::Text("SYNTHETIC-ARTIST-0005".to_owned()))
        );
    }

    #[test]
    fn an_unknown_frame_is_reported_rather_than_passed_over() {
        // The tag goes whole either way, so the table is a ranking and never a filter.
        let tag = id3v2(&[frame(b"ZZZZ", b"SYNTHETIC-0008")], 0);
        let (tags, _) = head(&tag).unwrap();
        let found = findings(&tags[0], &options());
        assert_eq!(found[0].field.as_deref(), Some("ZZZZ"));
        assert_eq!(found[0].kind, MetadataKind::Other);
    }

    #[test]
    fn an_unsynchronised_tag_is_still_itemised() {
        // §6.1: every FF 00 stands for one FF, so frame sizes read from the raw bytes would be in
        // the wrong units. Undone on a copy, for the report only.
        let mut body = frame(b"TIT2", b"SYNTHETIC\xFF\x00-0009");
        // The frame declares its *desynchronised* length, which is one byte shorter than the raw
        // payload because the `FF 00` escape collapses to a single `FF`.
        let raw_payload = body.len() - 10;
        body[4..8].copy_from_slice(&syncsafe_bytes(raw_payload - 1));
        let tag = id3v2(&[body], 0x80);
        let (tags, _) = head(&tag).unwrap();
        let found = findings(&tags[0], &options());
        assert_eq!(found[0].field.as_deref(), Some("TIT2"));
    }

    #[test]
    fn a_tag_whose_frames_do_not_parse_yields_one_line_rather_than_none() {
        let mut tag = id3v2(&[frame(b"TIT2", b"SYNTHETIC-0010")], 0);
        tag[10] = 0x01;
        let (tags, _) = head(&tag).unwrap();
        let found = findings(&tags[0], &options());
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].field.as_deref(), Some("Tag"));
    }

    #[test]
    fn an_id3v1_tag_is_peeled_off_the_end() {
        let mut input = b"AUDIO".to_vec();
        let mut tag = vec![0u8; ID3V1_BYTES];
        tag[0..3].copy_from_slice(b"TAG");
        tag[33..54].copy_from_slice(b"SYNTHETIC-ARTIST-0011");
        input.extend_from_slice(&tag);
        let (tags, end) = tail(&input, 0).unwrap();
        assert_eq!(end, 5);
        assert_eq!(tags.len(), 1);
        let found = findings(&tags[0], &options());
        assert!(found.iter().any(|f| f.field.as_deref() == Some("Artist")));
    }

    #[test]
    fn the_tag_plus_extension_is_part_of_the_same_span() {
        let mut input = b"AUDIO".to_vec();
        let mut extended = vec![0u8; ID3V1_EXTENDED_BYTES];
        extended[0..4].copy_from_slice(b"TAG+");
        let mut tag = vec![0u8; ID3V1_BYTES];
        tag[0..3].copy_from_slice(b"TAG");
        input.extend_from_slice(&extended);
        input.extend_from_slice(&tag);
        let (tags, end) = tail(&input, 0).unwrap();
        assert_eq!(end, 5);
        assert_eq!(tags[0].kind, TagKind::Id3v1 { extended: true });
        assert_eq!(tags[0].raw.len(), ID3V1_EXTENDED_BYTES + ID3V1_BYTES);
    }

    fn ape_tag(items: &[(&[u8], &[u8])], with_header: bool) -> Vec<u8> {
        let mut body = Vec::new();
        for (key, value) in items {
            body.extend_from_slice(&le32(value.len()));
            body.extend_from_slice(&0u32.to_le_bytes());
            body.extend_from_slice(key);
            body.push(0);
            body.extend_from_slice(value);
        }
        let size = le32(body.len() + APE_FOOTER_BYTES);
        let footer = |flags: u32| {
            let mut out = b"APETAGEX".to_vec();
            out.extend_from_slice(&2000u32.to_le_bytes());
            out.extend_from_slice(&size);
            out.extend_from_slice(&le32(items.len()));
            out.extend_from_slice(&flags.to_le_bytes());
            out.extend_from_slice(&[0u8; 8]);
            out
        };
        let mut out = Vec::new();
        if with_header {
            out.extend_from_slice(&footer(0xA000_0000));
        }
        out.extend_from_slice(&body);
        out.extend_from_slice(&footer(if with_header { 0x8000_0000 } else { 0 }));
        out
    }

    #[test]
    fn an_ape_tag_is_peeled_and_itemised() {
        let mut input = b"AUDIO".to_vec();
        input.extend_from_slice(&ape_tag(
            &[
                (b"Artist", b"SYNTHETIC-ARTIST-0012"),
                (b"Tool Name", b"SYNTHETIC-TOOL-0013"),
            ],
            true,
        ));
        let (tags, end) = tail(&input, 0).unwrap();
        assert_eq!(end, 5);
        let found = findings(&tags[0], &options());
        assert_eq!(
            found
                .iter()
                .find(|f| f.field.as_deref() == Some("Artist"))
                .unwrap()
                .kind,
            MetadataKind::PersonalIdentity
        );
        assert_eq!(
            found
                .iter()
                .find(|f| f.field.as_deref() == Some("Tool Name"))
                .unwrap()
                .kind,
            MetadataKind::SoftwareFingerprint
        );
    }

    #[test]
    fn an_ape_footer_claiming_a_header_that_is_not_there_is_refused() {
        let mut input = b"AUDIO-AUDIO-AUDIO-AUDIO".to_vec();
        let mut tag = ape_tag(&[(b"Artist", b"x")], true);
        // Blank the header the footer's flag promises.
        tag[0..8].copy_from_slice(b"XXXXXXXX");
        input.extend_from_slice(&tag);
        assert!(matches!(
            tail(&input, 0),
            Err(TagError::Malformed {
                detail: MalformedDetail::MissingMarker,
                ..
            })
        ));
    }

    #[test]
    fn several_tail_tags_are_peeled_in_one_pass() {
        // The real arrangement: Lyrics3, then APE, then ID3v1 at the very end.
        let mut input = b"AUDIO".to_vec();
        let lyrics = b"LYRICSBEGININD0000SYNTHETIC-LYRIC-0014".to_vec();
        let size = format!("{:06}", lyrics.len());
        input.extend_from_slice(&lyrics);
        input.extend_from_slice(size.as_bytes());
        input.extend_from_slice(b"LYRICS200");
        input.extend_from_slice(&ape_tag(&[(b"Comment", b"SYNTHETIC-0015")], false));
        let mut v1 = vec![0u8; ID3V1_BYTES];
        v1[0..3].copy_from_slice(b"TAG");
        v1[3..24].copy_from_slice(b"SYNTHETIC-TITLE-00016");
        input.extend_from_slice(&v1);

        let (tags, end) = tail(&input, 0).unwrap();
        assert_eq!(end, 5, "the audio boundary moved");
        assert_eq!(tags.len(), 3);
        assert_eq!(tags[0].kind, TagKind::Lyrics3 { version: 2 });
        assert!(matches!(tags[1].kind, TagKind::Ape { .. }));
        assert_eq!(tags[2].kind, TagKind::Id3v1 { extended: false });
    }

    #[test]
    fn a_tail_tag_may_not_reach_below_the_floor() {
        // The floor is where the caller's payload starts. Without it a lying size would let a tail
        // tag swallow the audio, and the file would strip to nothing while reporting success.
        let mut input = b"AUDIO".to_vec();
        input.extend_from_slice(&ape_tag(&[(b"Artist", b"x")], false));
        let at = input.len() - APE_FOOTER_BYTES;
        input[at + 12..at + 16].copy_from_slice(&0xFFFF_u32.to_le_bytes());
        assert!(matches!(
            tail(&input, 0),
            Err(TagError::Malformed {
                detail: MalformedDetail::LengthOutOfRange,
                ..
            })
        ));
    }

    #[test]
    fn a_lyrics_end_marker_that_is_really_audio_does_not_refuse_the_file() {
        // Lyrics3 v1 carries no size, so there is nothing to have lied about. Returning "no tag"
        // is the only reading that does not refuse a file over a coincidence.
        let mut input = b"AUDIO".to_vec();
        input.extend_from_slice(b"LYRICSEND");
        let (tags, end) = tail(&input, 0).unwrap();
        assert!(tags.is_empty());
        assert_eq!(end, input.len());
    }

    #[test]
    fn nothing_at_either_end_is_not_an_error() {
        let (head_tags, at) = head(b"AUDIO").unwrap();
        assert!(head_tags.is_empty());
        assert_eq!(at, 0);
        let (tail_tags, end) = tail(b"AUDIO", 0).unwrap();
        assert!(tail_tags.is_empty());
        assert_eq!(end, 5);
    }

    #[test]
    fn truncation_at_every_length_is_refused_or_survived_but_never_panics() {
        let mut input = id3v2(
            &[
                frame(b"TPE1", b"SYNTHETIC-0017"),
                frame(b"APIC", b"\x00\x01"),
            ],
            0,
        );
        input.extend_from_slice(b"AUDIO");
        input.extend_from_slice(&ape_tag(&[(b"Artist", b"SYNTHETIC-0018")], true));
        let mut v1 = vec![0u8; ID3V1_BYTES];
        v1[0..3].copy_from_slice(b"TAG");
        input.extend_from_slice(&v1);

        for n in 0..=input.len() {
            let prefix = input.get(0..n).unwrap();
            if let Ok((tags, at)) = head(prefix) {
                for tag in &tags {
                    let _ = findings(tag, &options());
                }
                if let Ok((tags, _)) = tail(prefix, at) {
                    for tag in &tags {
                        let _ = findings(tag, &options());
                    }
                }
            }
        }
    }
}
