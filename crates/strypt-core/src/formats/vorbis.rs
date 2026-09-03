//! The Vorbis comment: a vendor string, a count, then that many `NAME=value` items, every length
//! little-endian.
//!
//! Shared by [`super::flac`] and [`super::ogg`], on ADR-0040 decision 2's reasoning: the structure
//! is the same wherever it is stuck, and two handlers have no business disagreeing about what is in
//! one. It names fields and never rewrites one — the empty body in [`EMPTY`] is the only thing here
//! that produces bytes (ADR-0041 decision 10).

use crate::bytes::Reader;
use crate::formats::xmp;
use crate::report::{Finding, InspectOptions, MetadataKind, MetadataValue};

/// How much of a comment block is itemised before the rest is reported in one line.
///
/// The block goes whole whatever this is; the cap bounds only how many findings one file can
/// produce, because a report is itself allocated and rendered.
const MAX_ITEMISED_COMMENTS: u32 = 512;

/// An empty comment body: no vendor string, no comments. Vorbis I adds a framing bit after it;
/// Opus and FLAC do not.
pub(crate) const EMPTY: [u8; 8] = [0; 8];

/// Field names worth ranking, matched on the part before the `=`. The specification leaves the set
/// open, so this is a ranking table and never a filter — every comment goes whether it is named
/// here or not.
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

/// Itemise a comment body into `out`, reporting it under `location`.
///
/// Itemising is best-effort and removal is not: the caller empties or deletes the block whatever
/// this finds. A body whose lengths do not add up is reported in one line, because a block strypt
/// cannot read is still one it can remove, and removing is the safe direction.
pub(crate) fn comments(
    payload: &[u8],
    location: &str,
    size: u64,
    options: &InspectOptions,
    out: &mut Vec<Finding>,
) {
    if !itemise(payload, location, options, out) {
        // Something is there, it is going, and saying nothing would read as "no metadata here".
        // Reported only when the body did not *parse* — a legibly empty one has nothing to say,
        // and an already-stripped file has to re-inspect clean.
        out.push(Finding::new(MetadataKind::Other, location, size).with_field("Comments"));
    }
}

/// Itemise into `out`, returning false as soon as a length does not add up.
fn itemise(
    payload: &[u8],
    location: &str,
    options: &InspectOptions,
    out: &mut Vec<Finding>,
) -> bool {
    let mut r = Reader::new(payload);

    let Some(vendor) = r
        .u32_le()
        .and_then(|n| usize::try_from(n).ok())
        .and_then(|n| r.take(n))
    else {
        return false;
    };
    if !vendor.is_empty() {
        // The encoder's own name and version — "reference libFLAC 1.5.0 20250101", "libopus 1.5.2".
        out.push(
            Finding::new(
                MetadataKind::SoftwareFingerprint,
                location,
                as_u64(vendor.len()),
            )
            .with_field("vendor")
            .with_value(options, || MetadataValue::Text(xmp::name_of(vendor))),
        );
    }

    let Some(declared) = r.u32_le() else {
        return false;
    };
    // Itemising stops at the cap; the caller still removes the whole body.
    for _ in 0..declared.min(MAX_ITEMISED_COMMENTS) {
        let Some(item) = r
            .u32_le()
            .and_then(|n| usize::try_from(n).ok())
            .and_then(|n| r.take(n))
        else {
            return false;
        };
        let (name, value) = split_comment(item);
        out.push(
            Finding::new(kind_of(&name), location, as_u64(item.len()))
                .with_field(name)
                .with_value(options, || MetadataValue::Text(xmp::name_of(value))),
        );
    }
    true
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

/// Widen a length for reporting. Saturating: a report field is not worth failing a strip over.
fn as_u64(value: usize) -> u64 {
    u64::try_from(value).unwrap_or(u64::MAX)
}

#[cfg(test)]
mod tests {
    // Test code is never reachable from untrusted bytes, which is the boundary the panic-freedom
    // lints police (ADR-0006).
    #![allow(clippy::unwrap_used, clippy::indexing_slicing)]

    use super::*;

    fn body(vendor: &[u8], items: &[&[u8]]) -> Vec<u8> {
        let le32 = |n: usize| u32::try_from(n).unwrap().to_le_bytes();
        let mut out = le32(vendor.len()).to_vec();
        out.extend_from_slice(vendor);
        out.extend_from_slice(&le32(items.len()));
        for item in items {
            out.extend_from_slice(&le32(item.len()));
            out.extend_from_slice(item);
        }
        out
    }

    fn found(payload: &[u8]) -> Vec<Finding> {
        let mut out = Vec::new();
        comments(
            payload,
            "OpusTags",
            u64::try_from(payload.len()).unwrap(),
            &InspectOptions::names_only(),
            &mut out,
        );
        out
    }

    #[test]
    fn the_vendor_string_and_every_item_are_reported_under_the_callers_location() {
        let out = found(&body(
            b"libopus SYNTHETIC-VENDOR",
            &[b"ARTIST=SYNTHETIC", b"LOCATION=51.5,-0.1"],
        ));
        assert!(out.iter().all(|f| f.location == "OpusTags"));
        assert_eq!(out[0].field.as_deref(), Some("vendor"));
        assert_eq!(out[1].kind, MetadataKind::PersonalIdentity);
        assert_eq!(out[2].kind, MetadataKind::Location);
    }

    #[test]
    fn a_body_whose_lengths_do_not_add_up_still_produces_a_finding() {
        let mut payload = 0xFFFF_FFFFu32.to_le_bytes().to_vec();
        payload.extend_from_slice(b"SYNTHETIC-UNREADABLE");
        let out = found(&payload);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].field.as_deref(), Some("Comments"));
    }

    #[test]
    fn the_empty_body_is_a_zero_vendor_and_a_zero_count() {
        // Load-bearing: it is what a stripped file carries, and a stripped file must re-inspect
        // clean.
        assert!(found(&EMPTY).is_empty());
        let mut r = Reader::new(&EMPTY);
        assert_eq!(r.u32_le(), Some(0));
        assert_eq!(r.u32_le(), Some(0));
    }

    #[test]
    fn a_field_name_is_ranked_by_prefix_and_case_insensitively() {
        assert_eq!(
            kind_of("musicbrainz_trackid"),
            MetadataKind::DocumentIdentifier
        );
        assert_eq!(kind_of("SOMETHING_ELSE"), MetadataKind::Other);
    }
}
