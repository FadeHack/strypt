//! Exif, which is a TIFF file living inside another file's metadata slot.
//!
//! Shared rather than owned by one handler: the same TIFF structure appears in a JPEG `APP1`
//! segment, in a PNG `eXIf` chunk, in a WebP `EXIF` chunk, and — in Phase 2 — as a whole TIFF
//! file. One parser for it means one place where the bounds checking is right.
//!
//! # This module only reads
//!
//! Nothing here rewrites anything. The handlers that use it drop the *entire* container the
//! Exif block sits in, which is the only removal that can be reasoned about: a TIFF is a graph
//! of absolute file offsets, so editing tags out of one means rewriting every offset that
//! followed them, and a mistake there produces a file that still parses while pointing at the
//! wrong bytes. Dropping the block whole cannot half-succeed.
//!
//! What this module is for is telling the user *what* was in there — `GPSLatitude`,
//! `BodySerialNumber`, `DateTimeOriginal` — rather than "a 12 KB Exif block". A report that
//! names the tag is what lets someone decide whether a file they already published is a
//! problem.
//!
//! # Hostility
//!
//! Every offset, count, and length below was chosen by whoever made the file. IFDs can point
//! at each other in a cycle, a tag can claim four billion components, and a sub-IFD pointer
//! can point back at its own parent. Each is handled by construction: offsets are followed
//! only through [`Reader`], every IFD start is recorded and never visited twice, and the
//! entry count is drawn from a shared budget so that a wide IFD cannot be traded for a deep
//! one.

use crate::bytes::{Reader, u32_to_usize};
use crate::formats::ParseLimits;
use crate::report::{Finding, InspectOptions, MetadataKind, MetadataValue, Note};

/// Byte order declared by the TIFF header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Endian {
    Little,
    Big,
}

impl Endian {
    pub(crate) fn u16(self, r: &mut Reader<'_>) -> Option<u16> {
        match self {
            Self::Little => r.u16_le(),
            Self::Big => r.u16_be(),
        }
    }

    pub(crate) fn u32(self, r: &mut Reader<'_>) -> Option<u32> {
        match self {
            Self::Little => r.u32_le(),
            Self::Big => r.u32_be(),
        }
    }
}

/// Which image-file directory an entry was found in.
///
/// The same tag number means different things in different IFDs — tag `0x0001` is
/// `InteropIndex` in the interoperability IFD and `GPSLatitudeRef` in the GPS one — so the
/// directory has to travel with the tag.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Ifd {
    /// The main image directory, and sub-directories that use its tag set.
    Primary,
    /// The Exif private directory, reached through tag `0x8769`.
    Exif,
    /// The GPS directory, reached through tag `0x8825`.
    Gps,
    /// The interoperability directory, reached through tag `0xA005`.
    Interop,
    /// The thumbnail directory: a second, smaller copy of the image.
    Thumbnail,
}

impl Ifd {
    /// The label a finding carries, appended to the container's own location.
    const fn label(self) -> &'static str {
        match self {
            Self::Primary => "IFD0",
            Self::Exif => "Exif IFD",
            Self::Gps => "GPS IFD",
            Self::Interop => "Interop IFD",
            Self::Thumbnail => "IFD1 (thumbnail)",
        }
    }
}

/// What a scan found.
pub(crate) struct ExifScan {
    /// One entry per tag, in the order the directories were walked.
    pub(crate) findings: Vec<Finding>,
    /// Caveats — a header that did not parse, or a walk that hit its budget.
    pub(crate) notes: Vec<Note>,
}

/// Walk the TIFF structure at `tiff` and name what is in it.
///
/// `tiff` starts at the byte-order mark, *not* at the `Exif\0\0` introducer: offsets inside a
/// TIFF are relative to that mark, so a caller that passes the introducer as well shifts every
/// offset by six and gets a plausible-looking parse of the wrong bytes.
///
/// Never fails. An Exif block that does not parse is still an Exif block that is about to be
/// removed, and refusing the whole file over it would help nobody; the caller gets a
/// [`Note::UnparsedRegion`] to pass on instead.
pub(crate) fn scan(
    tiff: &[u8],
    location: &str,
    options: &InspectOptions,
    limits: &ParseLimits,
) -> ExifScan {
    let mut out = ExifScan {
        findings: Vec::new(),
        notes: Vec::new(),
    };

    let Some((endian, first_ifd)) = header(tiff) else {
        out.notes.push(Note::UnparsedRegion {
            location: location.to_owned(),
            bytes: as_u64(tiff.len()),
        });
        return out;
    };

    // One budget for the whole walk. Spending it on entries *and* on directories is what
    // stops a file trading a legal number of directories against a legal number of entries in
    // each and multiplying its way to an unbounded scan.
    let mut budget = limits.max_items;
    let mut visited: Vec<usize> = Vec::new();
    let mut walker = Walk {
        tiff,
        endian,
        location,
        options,
        limits,
        budget: &mut budget,
        visited: &mut visited,
        out: &mut out,
    };

    // IFD0 and IFD1 are a chain: each directory ends with the offset of the next. IFD1, when
    // present, is the thumbnail — a complete second image that survives cropping and any
    // redaction painted over the main one (`docs/THREAT_MODEL.md` §3).
    let mut next = first_ifd;
    let mut kind = Ifd::Primary;
    while next != 0 {
        let Some(following) = walker.directory(next, kind, 0) else {
            break;
        };
        next = following;
        kind = Ifd::Thumbnail;
    }
    out
}

/// Read the TIFF header, returning the byte order and the offset of the first directory.
pub(crate) fn header(tiff: &[u8]) -> Option<(Endian, u32)> {
    let mut r = Reader::new(tiff);
    let endian = match r.take(2)? {
        b"II" => Endian::Little,
        b"MM" => Endian::Big,
        _ => return None,
    };
    // TIFF 6.0 §2: the magic number is 42, written in the declared byte order. It is the only
    // thing distinguishing a real header from two bytes that happen to spell "MM".
    if endian.u16(&mut r)? != 42 {
        return None;
    }
    Some((endian, endian.u32(&mut r)?))
}

/// State carried through a walk, so that the budget and the visited set are shared.
struct Walk<'a, 'b> {
    tiff: &'a [u8],
    endian: Endian,
    location: &'a str,
    options: &'a InspectOptions,
    limits: &'a ParseLimits,
    budget: &'b mut u32,
    visited: &'b mut Vec<usize>,
    out: &'b mut ExifScan,
}

impl Walk<'_, '_> {
    /// Walk one directory, returning the offset of the next in its chain.
    fn directory(&mut self, offset: u32, kind: Ifd, depth: u32) -> Option<u32> {
        if depth > self.limits.max_depth {
            return None;
        }
        let start = u32_to_usize(offset)?;
        // A directory that points at itself, directly or through a sub-IFD, is a cycle. It is
        // also perfectly legal-looking, so it has to be refused by memory rather than by
        // pattern: an offset is walked at most once per file.
        if self.visited.contains(&start) {
            return None;
        }
        self.visited.push(start);

        let mut r = Reader::new(self.tiff);
        r.seek(start)?;
        let count = self.endian.u16(&mut r)?;

        for _ in 0..count {
            if *self.budget == 0 {
                self.out.notes.push(Note::UnparsedRegion {
                    location: format!("{} {}", self.location, kind.label()),
                    bytes: as_u64(r.remaining()),
                });
                return None;
            }
            *self.budget = self.budget.saturating_sub(1);
            self.entry(&mut r, kind, depth)?;
        }
        self.endian.u32(&mut r)
    }

    /// Handle one 12-byte directory entry.
    fn entry(&mut self, r: &mut Reader<'_>, kind: Ifd, depth: u32) -> Option<()> {
        let tag = self.endian.u16(r)?;
        let field_type = self.endian.u16(r)?;
        let count = self.endian.u32(r)?;
        let inline = r.take(4)?;

        // TIFF 6.0 §2: a value of four bytes or fewer is stored in the entry itself; anything
        // longer is stored elsewhere and those four bytes are its offset.
        let length = type_size(field_type)
            .and_then(|size| u64::from(count).checked_mul(u64::from(size)))
            .unwrap_or(0);
        let value = if length <= 4 {
            usize::try_from(length).ok().and_then(|n| inline.get(0..n))
        } else {
            at_offset(self.tiff, self.endian, inline, length)
        };

        if let Some(sub) = sub_directory(kind, tag) {
            // A pointer's own four bytes carry nothing identifying; what it points at does.
            if let Some(target) = word(self.endian, value.unwrap_or(inline)) {
                let _ = self.directory(target, sub, depth.saturating_add(1));
            }
            return Some(());
        }

        let (name, metadata_kind) = describe(kind, tag);
        let bytes = if kind == Ifd::Thumbnail && tag == THUMBNAIL_LENGTH_TAG {
            // The thumbnail's own size is a far more useful number to show than the four
            // bytes of the tag that records it.
            value
                .and_then(|v| integer(self.endian, v, field_type))
                .unwrap_or(length)
        } else {
            length
        };

        let location = format!("{} {}", self.location, kind.label());
        self.out.findings.push(
            Finding::new(metadata_kind, location, bytes)
                .with_field(name)
                .with_value(self.options, || render(value, field_type)),
        );
        Some(())
    }
}

/// Resolve an out-of-line value, refusing one that runs past the end of the block.
///
/// A truncated or lying offset yields [`None`] and the entry is still reported: the tag name
/// is what the user needs, and it was read from the directory, not from here.
fn at_offset<'a>(tiff: &'a [u8], endian: Endian, inline: &[u8], length: u64) -> Option<&'a [u8]> {
    let start = u32_to_usize(word(endian, inline)?)?;
    let len = usize::try_from(length).ok()?;
    let mut r = Reader::new(tiff);
    r.seek(start)?;
    r.take(len)
}

/// Read the first four bytes of `value` as a word in the declared byte order.
fn word(endian: Endian, value: &[u8]) -> Option<u32> {
    let mut r = Reader::new(value);
    endian.u32(&mut r)
}

/// Read a short or long value as an integer, for the tags whose value is a size.
fn integer(endian: Endian, value: &[u8], field_type: u16) -> Option<u64> {
    let mut r = Reader::new(value);
    match field_type {
        SHORT => endian.u16(&mut r).map(u64::from),
        LONG => endian.u32(&mut r).map(u64::from),
        _ => None,
    }
}

/// TIFF field type codes used below.
const SHORT: u16 = 3;
const LONG: u16 = 4;
const ASCII: u16 = 2;

/// Bytes per component for a TIFF field type, or [`None`] for a type this build does not know.
///
/// An unknown type is not an error — TIFF has been extended repeatedly — it just means the
/// length cannot be computed, so the entry is reported without a size rather than with a
/// wrong one.
pub(crate) const fn type_size(field_type: u16) -> Option<u16> {
    Some(match field_type {
        1 | 2 | 6 | 7 => 1,   // BYTE, ASCII, SBYTE, UNDEFINED
        3 | 8 => 2,           // SHORT, SSHORT
        4 | 9 | 11 | 13 => 4, // LONG, SLONG, FLOAT, IFD
        // RATIONAL, SRATIONAL, DOUBLE, and the three BigTIFF eight-byte types.
        5 | 10 | 12 | 16..=18 => 8,
        _ => return None,
    })
}

/// The directory a pointer tag leads to, if this tag is one.
pub(crate) const fn sub_directory(kind: Ifd, tag: u16) -> Option<Ifd> {
    match (kind, tag) {
        (Ifd::Primary | Ifd::Thumbnail, 0x8769) => Some(Ifd::Exif),
        (Ifd::Primary | Ifd::Thumbnail, 0x8825) => Some(Ifd::Gps),
        (Ifd::Exif, 0xA005) => Some(Ifd::Interop),
        _ => None,
    }
}

/// `JPEGInterchangeFormatLength`: the size of the embedded thumbnail image.
const THUMBNAIL_LENGTH_TAG: u16 = 0x0202;

/// Tags worth naming, with what each one exposes.
///
/// Deliberately not exhaustive — Exif has hundreds of tags and vendors invent more. Anything
/// absent is still reported, under its hexadecimal tag number and as
/// [`MetadataKind::Other`], because everything in the block is removed whether or not this
/// table has heard of it. The table improves the *report*; it never decides what goes.
const PRIMARY_TAGS: &[(u16, &str, MetadataKind)] = &[
    (
        0x000B,
        "ProcessingSoftware",
        MetadataKind::SoftwareFingerprint,
    ),
    (0x010E, "ImageDescription", MetadataKind::Comment),
    (0x010F, "Make", MetadataKind::DeviceIdentity),
    (0x0110, "Model", MetadataKind::DeviceIdentity),
    (0x0112, "Orientation", MetadataKind::Other),
    (0x0131, "Software", MetadataKind::SoftwareFingerprint),
    (0x0132, "DateTime", MetadataKind::Timestamp),
    (0x013B, "Artist", MetadataKind::PersonalIdentity),
    (0x013C, "HostComputer", MetadataKind::DeviceIdentity),
    (0x02BC, "XMLPacket (XMP)", MetadataKind::Other),
    // IPTC and Photoshop image resources, carried inside TIFF by producers that write both.
    (0x83BB, "IPTC/NAA", MetadataKind::PersonalIdentity),
    (
        0x8649,
        "PhotoshopSettings",
        MetadataKind::SoftwareFingerprint,
    ),
    (0x8773, "InterColorProfile", MetadataKind::ColourProfile),
    (0x8298, "Copyright", MetadataKind::PersonalIdentity),
    // The Windows XP tags, written by Explorer's file-properties dialogue. Users often do not
    // know these exist, because nothing in the camera put them there — a person did.
    (0x9C9B, "XPTitle", MetadataKind::Comment),
    (0x9C9C, "XPComment", MetadataKind::Comment),
    (0x9C9D, "XPAuthor", MetadataKind::PersonalIdentity),
    (0x9C9E, "XPKeywords", MetadataKind::Comment),
    (0x9C9F, "XPSubject", MetadataKind::Comment),
];

/// Tags in the Exif private directory.
const EXIF_TAGS: &[(u16, &str, MetadataKind)] = &[
    (0x9003, "DateTimeOriginal", MetadataKind::Timestamp),
    (0x9004, "DateTimeDigitized", MetadataKind::Timestamp),
    (0x9010, "OffsetTime", MetadataKind::Timestamp),
    (0x9011, "OffsetTimeOriginal", MetadataKind::Timestamp),
    (0x9012, "OffsetTimeDigitized", MetadataKind::Timestamp),
    (0x9286, "UserComment", MetadataKind::Comment),
    // The MakerNote is a vendor-private blob with no public schema. It is routinely the
    // largest thing in the block and has been shown to carry serial numbers, shutter counts,
    // focus points, and in some models a second thumbnail.
    (0x927C, "MakerNote", MetadataKind::DeviceIdentity),
    (0xA420, "ImageUniqueID", MetadataKind::DocumentIdentifier),
    (0xA430, "CameraOwnerName", MetadataKind::PersonalIdentity),
    // A body serial number links every photograph a camera ever took. One missed image is
    // enough to retroactively attribute an entire archive.
    (0xA431, "BodySerialNumber", MetadataKind::DeviceIdentity),
    (0xA433, "LensMake", MetadataKind::DeviceIdentity),
    (0xA434, "LensModel", MetadataKind::DeviceIdentity),
    (0xA435, "LensSerialNumber", MetadataKind::DeviceIdentity),
];

/// Tags in the GPS directory. Every entry there is location data by definition, so the table
/// exists only to give the common ones a readable name.
const GPS_TAGS: &[(u16, &str)] = &[
    (0x0000, "GPSVersionID"),
    (0x0001, "GPSLatitudeRef"),
    (0x0002, "GPSLatitude"),
    (0x0003, "GPSLongitudeRef"),
    (0x0004, "GPSLongitude"),
    (0x0005, "GPSAltitudeRef"),
    (0x0006, "GPSAltitude"),
    (0x0007, "GPSTimeStamp"),
    (0x0010, "GPSImgDirectionRef"),
    (0x0011, "GPSImgDirection"),
    (0x001D, "GPSDateStamp"),
];

/// The name and category to report an entry under.
pub(crate) fn describe(kind: Ifd, tag: u16) -> (String, MetadataKind) {
    match kind {
        Ifd::Gps => {
            let name = GPS_TAGS
                .iter()
                .find(|(number, _)| *number == tag)
                .map_or_else(|| unnamed(tag), |(_, name)| (*name).to_owned());
            (name, MetadataKind::Location)
        }
        Ifd::Thumbnail => {
            // Everything in IFD1 describes the embedded second image, so it is all reported
            // as the thumbnail rather than as a scattering of unrelated tags.
            let name =
                lookup(PRIMARY_TAGS, tag).map_or_else(|| unnamed(tag), |(name, _)| name.to_owned());
            (name, MetadataKind::Thumbnail)
        }
        Ifd::Exif => lookup(EXIF_TAGS, tag)
            .or_else(|| lookup(PRIMARY_TAGS, tag))
            .map_or_else(
                || (unnamed(tag), MetadataKind::Other),
                |(name, kind)| (name.to_owned(), kind),
            ),
        Ifd::Primary | Ifd::Interop => lookup(PRIMARY_TAGS, tag).map_or_else(
            || (unnamed(tag), MetadataKind::Other),
            |(name, kind)| (name.to_owned(), kind),
        ),
    }
}

fn lookup(
    table: &[(u16, &'static str, MetadataKind)],
    tag: u16,
) -> Option<(&'static str, MetadataKind)> {
    table
        .iter()
        .find(|(number, _, _)| *number == tag)
        .map(|(_, name, kind)| (*name, *kind))
}

/// The name for a tag no table knows, which is still a tag the user is entitled to hear about.
fn unnamed(tag: u16) -> String {
    format!("Tag 0x{tag:04X}")
}

/// Render a value for a caller that opted into seeing values.
///
/// Only ASCII fields become text, and control characters are dropped: a value goes to a
/// terminal, and a hostile file can put an escape sequence in a tag it knows will be printed.
pub(crate) fn render(value: Option<&[u8]>, field_type: u16) -> MetadataValue {
    let bytes = value.unwrap_or_default();
    if field_type == ASCII {
        let text: String = String::from_utf8_lossy(bytes)
            .chars()
            .filter(|c| !c.is_control())
            .collect();
        return MetadataValue::Text(text);
    }
    MetadataValue::Opaque {
        bytes: as_u64(bytes.len()),
    }
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
        clippy::indexing_slicing,
        clippy::arithmetic_side_effects
    )]

    use super::*;

    /// Build a little-endian TIFF block with one IFD of `entries`, each `(tag, type, count,
    /// value)` with the value already packed into four bytes.
    fn tiff(entries: &[(u16, u16, u32, [u8; 4])]) -> Vec<u8> {
        let mut out = b"II\x2A\x00\x08\x00\x00\x00".to_vec();
        out.extend_from_slice(&u16::try_from(entries.len()).unwrap().to_le_bytes());
        for (tag, field_type, count, value) in entries {
            out.extend_from_slice(&tag.to_le_bytes());
            out.extend_from_slice(&field_type.to_le_bytes());
            out.extend_from_slice(&count.to_le_bytes());
            out.extend_from_slice(value);
        }
        out.extend_from_slice(&0u32.to_le_bytes());
        out
    }

    fn scan_of(data: &[u8]) -> ExifScan {
        scan(
            data,
            "APP1 (Exif)",
            &InspectOptions::names_only(),
            &ParseLimits::default(),
        )
    }

    #[test]
    fn a_gps_tag_is_reported_as_location() {
        let block = tiff(&[(0x8825, LONG, 1, 26u32.to_le_bytes())]);
        // The GPS directory sits immediately after IFD0's terminator, at offset 26.
        let mut data = block;
        data.extend_from_slice(&1u16.to_le_bytes());
        data.extend_from_slice(&0x0002u16.to_le_bytes());
        data.extend_from_slice(&5u16.to_le_bytes());
        data.extend_from_slice(&3u32.to_le_bytes());
        data.extend_from_slice(&64u32.to_le_bytes());
        data.extend_from_slice(&0u32.to_le_bytes());

        let found = scan_of(&data);
        let gps = found
            .findings
            .iter()
            .find(|f| f.kind == MetadataKind::Location)
            .unwrap();
        assert_eq!(gps.field.as_deref(), Some("GPSLatitude"));
        assert!(gps.location.contains("GPS IFD"));
    }

    #[test]
    fn a_tag_no_table_knows_is_still_reported() {
        // The alternative — silently skipping unknown tags — would make the report a claim
        // about what strypt recognises rather than about what is in the file.
        let found = scan_of(&tiff(&[(0xDEAD, SHORT, 1, [1, 0, 0, 0])]));
        assert_eq!(found.findings.len(), 1);
        assert_eq!(found.findings[0].field.as_deref(), Some("Tag 0xDEAD"));
    }

    #[test]
    fn a_directory_pointing_at_itself_terminates() {
        // Offset 8 is IFD0's own start: a self-referential Exif pointer. Legal-looking, and
        // an infinite loop for a walker that trusts offsets.
        let found = scan_of(&tiff(&[(0x8769, LONG, 1, 8u32.to_le_bytes())]));
        assert!(found.findings.is_empty());
    }

    #[test]
    fn a_lying_offset_still_yields_the_tag_name() {
        // Value four billion bytes into a 30-byte block. The name came from the directory, so
        // the user still learns that an author name was in the file.
        let found = scan_of(&tiff(&[(
            0x013B,
            ASCII,
            4_000_000,
            [0xFF, 0xFF, 0xFF, 0x7F],
        )]));
        assert_eq!(found.findings.len(), 1);
        assert_eq!(found.findings[0].kind, MetadataKind::PersonalIdentity);
    }

    #[test]
    fn a_block_that_is_not_tiff_produces_a_note_not_a_failure() {
        let found = scan_of(b"not a tiff header at all");
        assert!(found.findings.is_empty());
        assert!(matches!(
            found.notes.first(),
            Some(Note::UnparsedRegion { .. })
        ));
    }

    #[test]
    fn truncation_at_every_length_is_survived() {
        let full = tiff(&[
            (0x010F, ASCII, 4, *b"ACME"),
            (0x8769, LONG, 1, 8u32.to_le_bytes()),
        ]);
        for n in 0..=full.len() {
            let _ = scan_of(&full[0..n]);
        }
    }

    #[test]
    fn values_stay_out_of_the_report_unless_asked_for() {
        let data = tiff(&[(0x013B, ASCII, 4, *b"NAME")]);
        let names_only = scan(
            &data,
            "APP1 (Exif)",
            &InspectOptions::names_only(),
            &ParseLimits::default(),
        );
        assert_eq!(names_only.findings[0].value, None);

        let with_values = scan(
            &data,
            "APP1 (Exif)",
            &InspectOptions::with_values(),
            &ParseLimits::default(),
        );
        assert_eq!(
            with_values.findings[0].value,
            Some(MetadataValue::Text("NAME".to_owned()))
        );
    }

    #[test]
    fn a_control_sequence_in_a_value_is_stripped() {
        // A value is printed to a terminal. A file that can put an escape sequence in one can
        // rewrite the report the user is reading.
        let data = tiff(&[(0x013B, ASCII, 4, [0x1B, b'[', b'2', b'J'])]);
        let found = scan(
            &data,
            "APP1 (Exif)",
            &InspectOptions::with_values(),
            &ParseLimits::default(),
        );
        assert_eq!(
            found.findings[0].value,
            Some(MetadataValue::Text("[2J".to_owned()))
        );
    }
}
