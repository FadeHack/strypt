//! MP3.
//!
//! The third tranche of Phase 2's fourth group (ADR-0037), and the one format in this project that
//! is **not a container at all**. There is no header describing the file, no index, no chunk list:
//! an MP3 is a run of self-describing MPEG audio frames, and every piece of metadata it carries was
//! glued to one end or the other by a tagger. An ID3v2 tag at the head; ID3v1, APE, and Lyrics3 at
//! the tail; frames in between (ADR-0040 — required reading before touching this handler).
//!
//! # Edited by deletion at both ends, never re-encoded
//!
//! The tags are dropped whole and the frames are copied verbatim, so a file with no tags comes back
//! **byte-identical** — GIF's, JPEG XL's, FLAC's and WAV's property. Nothing here decodes audio and
//! nothing rewrites a field: unlike every other format strypt handles, an MP3 has no length,
//! offset, or flag anywhere that removal could invalidate, because nothing in it points at anything
//! else.
//!
//! # The output is what is left, not what was kept
//!
//! There is no allow-list here because there is nothing to allow-list: the frames are the payload
//! and everything that is not a frame goes. That makes the *boundary* the whole of the safety
//! argument, which is why [`super::tags`] refuses a tag length rather than clamping it, and why
//! this module demands a real frame header where the tags stop (§2.4.2.3 of ISO/IEC 11172-3). A
//! tag that lied about its length would otherwise take audio with it, or leave metadata behind as
//! "audio".
//!
//! # What stays, and it is measured rather than assumed
//!
//! A VBR header — `Xing`, `Info`, or `VBRI` — is a real MPEG frame that decoders decode as silence,
//! and the LAME extension inside it names the encoder and its settings. It is a software
//! fingerprint, it stays, and the report says so: it is *inside the encoded stream*, which
//! ADR-0037 commits this group to never entering, and removing it would break VBR seeking and
//! gapless playback. mat2 leaves it too (`docs/THREAT_MODEL.md` §7.15).

use crate::detect::Format;
use crate::error::{MalformedDetail, Result, StryptError, UnsupportedKind};
use crate::formats::tags::{self, TagError};
use crate::formats::{MetadataHandler, StripOptions, Stripped};
use crate::report::{
    Finding, InspectOptions, MetadataKind, MetadataReport, Note, Retained, RetentionReason,
    StripReport,
};

/// Removal of metadata from MP3 audio.
#[derive(Debug, Clone, Copy, Default)]
pub struct Mp3Handler;

impl MetadataHandler for Mp3Handler {
    fn name(&self) -> &'static str {
        Format::Mp3.id()
    }

    fn format(&self) -> Format {
        Format::Mp3
    }

    fn inspect(&self, input: &[u8], options: &InspectOptions) -> Result<MetadataReport> {
        // Inspection runs the identical pass that stripping does and throws the output away, so
        // "everything `strip` removes is something `inspect` can see" holds by construction.
        let processed = process(input, options)?;
        Ok(MetadataReport {
            format: Format::Mp3,
            findings: processed.findings,
            notes: processed.notes,
        })
    }

    fn strip(&self, input: &[u8], options: &StripOptions) -> Result<Stripped> {
        let processed = process(input, &options.inspect)?;
        Ok(Stripped {
            report: StripReport {
                format: Format::Mp3,
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

/// How many zero bytes may sit between the head tags and the first frame.
///
/// Some taggers pad past the size their own header declares. The bytes are zeros, so they hide
/// nothing, and they are dropped rather than copied. Anything that is *not* zero there refuses the
/// file: a run of arbitrary bytes in front of the audio is exactly where something would be hidden
/// from a tool that skipped ahead to the first sync.
const MAX_LEADING_PADDING: usize = 4096;

/// The result of one pass over a file.
struct Processed {
    findings: Vec<Finding>,
    retained: Vec<Retained>,
    notes: Vec<Note>,
    output: Vec<u8>,
}

/// One MPEG audio frame header (ISO/IEC 11172-3 §2.4.2.3, ISO/IEC 13818-3 for MPEG-2).
pub(crate) struct FrameHeader {
    /// `3` for MPEG-1, `2` for MPEG-2, `0` for the unofficial MPEG-2.5.
    version: u8,
    /// `1` for Layer III, `2` for Layer II, `3` for Layer I.
    layer: u8,
    /// `3` for single channel; anything else has two.
    channel_mode: u8,
}

impl FrameHeader {
    /// Layer III, which is what "MP3" means. Layers I and II are a different format in the same
    /// frame grammar, and Phase 2's scope is MP3 (ADR-0027).
    const LAYER_III: u8 = 1;

    /// How many bytes of side information follow the header (§2.4.1.7).
    ///
    /// It is the region a `Xing` or `Info` header sits behind, and its length depends on both the
    /// MPEG version and the channel count.
    const fn side_info_bytes(&self) -> usize {
        match (self.version, self.channel_mode) {
            (3, 3) => 17,
            (3, _) => 32,
            (_, 3) => 9,
            (_, _) => 17,
        }
    }
}

/// Read a frame header, or [`None`] when these four bytes are not one.
///
/// Reserved values in the version, layer, bitrate and sampling-frequency fields are all rejected,
/// rather than only the eleven-bit sync being matched. `FF Ex` is a common byte pair in any binary
/// file, so the weaker test would claim files that are not audio at all — and this same function is
/// what [`crate::detect`] routes on, so a false positive there becomes a refusal the user has to
/// read (ADR-0040).
pub(crate) fn frame_header(bytes: &[u8]) -> Option<FrameHeader> {
    let (first, second, third) = (bytes.first()?, bytes.get(1)?, bytes.get(2)?);
    if *first != 0xFF || second & 0xE0 != 0xE0 {
        return None;
    }
    let version = (second >> 3) & 0x03;
    let layer = (second >> 1) & 0x03;
    // `01` is reserved in the version field and `00` in the layer field.
    if version == 1 || layer == 0 {
        return None;
    }
    // `1111` in the bitrate index and `11` in the sampling-frequency index are both forbidden.
    if third >> 4 == 0x0F || (third >> 2) & 0x03 == 0x03 {
        return None;
    }
    Some(FrameHeader {
        version,
        layer,
        channel_mode: bytes.get(3)? >> 6,
    })
}

/// Walk `input`, decide about every tag, and build the sanitised file.
///
/// [`crate::formats::ParseLimits`] is not taken, and that is deliberate rather than an oversight:
/// this format has
/// no nesting, no item list, and nothing that decompresses. The only counts here are how many tags
/// may be stacked at one end and how many items inside one are itemised, and both are structural
/// constants of the tag formats rather than a caller's policy ([`super::tags`]).
fn process(input: &[u8], options: &InspectOptions) -> Result<Processed> {
    let (head, audio_start) = tags::head(input).map_err(convert)?;
    let (tail, audio_end) = tags::tail(input, audio_start).map_err(convert)?;

    let mut findings = Vec::new();
    for tag in head.iter().chain(tail.iter()) {
        findings.extend(tags::findings(tag, options));
    }

    let region = input
        .get(audio_start..audio_end)
        .ok_or_else(|| malformed(MalformedDetail::LengthOutOfRange, as_offset(audio_start)))?;
    let padding = leading_padding(region)?;
    let audio = region.get(padding..).unwrap_or_default();
    if padding > 0 {
        // Zeros, so nothing identifying is in them — but the file changes size, and a report that
        // did not account for that would be a report the output does not match.
        findings.push(Finding::new(
            MetadataKind::Other,
            "zero padding before the first frame",
            as_u64(padding),
        ));
    }

    let Some(header) = frame_header(audio) else {
        // The only structural check this format has. Without it a tag that lied about its length
        // would take audio with it, or leave metadata behind under the name "audio".
        return Err(malformed(
            MalformedDetail::MissingMarker,
            as_offset(audio_start.saturating_add(padding)),
        ));
    };
    if header.layer != FrameHeader::LAYER_III {
        return Err(StryptError::UnsupportedFormat {
            format: UnsupportedKind::MpegAudioNotLayerThree,
        });
    }

    let mut retained = Vec::new();
    if let Some(marker) = vbr_header(audio, &header) {
        // Inside the encoded stream, which this group never enters (ADR-0037). Declared rather
        // than passed over: the LAME extension behind that marker names the encoder and its
        // settings, and a user is entitled to know it is still in the file.
        retained.push(Retained {
            location: format!("{marker} header frame, which names the encoder"),
            reason: RetentionReason::RemovalWouldAlterPayload,
        });
    }

    // Said on every file, clean ones included. The frames are copied without being decoded, so
    // anything in a frame's ancillary data or between frames is out of reach rather than absent.
    let notes = vec![Note::OutOfScopeContent {
        location: "audio frames, which are copied without being decoded".to_owned(),
    }];

    Ok(Processed {
        findings,
        retained,
        notes,
        output: audio.to_vec(),
    })
}

/// How many zero bytes precede the first frame. Refuses anything else in front of the audio.
fn leading_padding(region: &[u8]) -> Result<usize> {
    let run = region
        .iter()
        .take(MAX_LEADING_PADDING)
        .take_while(|byte| **byte == 0)
        .count();
    if run == 0 || region.get(run).is_some_and(|byte| *byte == 0xFF) {
        return Ok(run);
    }
    Err(malformed(MalformedDetail::UnexpectedMarker, as_offset(run)))
}

/// The VBR header a variable-bitrate encoder writes into the first frame, if there is one.
///
/// `Xing` and `Info` sit behind the side information; `VBRI` is Fraunhofer's spelling and sits at a
/// fixed offset of 32 bytes regardless of it.
fn vbr_header(audio: &[u8], header: &FrameHeader) -> Option<&'static str> {
    let at = header.side_info_bytes().saturating_add(4);
    let marker = audio.get(at..at.saturating_add(4));
    if marker == Some(b"Xing") {
        return Some("Xing");
    }
    if marker == Some(b"Info") {
        return Some("Info");
    }
    if audio.get(36..40) == Some(b"VBRI") {
        return Some("VBRI");
    }
    None
}

/// A tag-layer failure as this format's error.
fn convert(error: TagError) -> StryptError {
    match error {
        TagError::Malformed { detail, offset } => malformed(detail, as_offset(offset)),
        TagError::Limit(limit) => StryptError::LimitExceeded {
            format: Format::Mp3,
            limit,
        },
    }
}

/// A malformed-file error for this format.
fn malformed(detail: MalformedDetail, offset: Option<u64>) -> StryptError {
    StryptError::Malformed {
        format: Format::Mp3,
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
        clippy::panic,
        clippy::indexing_slicing,
        clippy::arithmetic_side_effects
    )]

    use super::*;
    use crate::report::MetadataValue;

    /// One MPEG-1 Layer III frame at 128 kbps, 44.1 kHz, mono: 417 bytes of which the first four
    /// are the header and the rest is zeroed, which decodes as silence.
    const FRAME_BYTES: usize = 417;

    fn frame() -> Vec<u8> {
        let mut out = vec![0xFF, 0xFB, 0x90, 0xC0];
        out.resize(FRAME_BYTES, 0);
        out
    }

    fn audio() -> Vec<u8> {
        let mut out = Vec::new();
        for _ in 0..4 {
            out.extend_from_slice(&frame());
        }
        out
    }

    fn byte(n: usize) -> u8 {
        u8::try_from(n & 0x7F).unwrap()
    }

    fn syncsafe(n: usize) -> [u8; 4] {
        [byte(n >> 21), byte(n >> 14), byte(n >> 7), byte(n)]
    }

    fn id3v2(frames: &[(&[u8], &[u8])]) -> Vec<u8> {
        let mut body = Vec::new();
        for (id, text) in frames {
            let mut payload = vec![0x03u8];
            payload.extend_from_slice(text);
            body.extend_from_slice(id);
            body.extend_from_slice(&syncsafe(payload.len()));
            body.extend_from_slice(&[0, 0]);
            body.extend_from_slice(&payload);
        }
        let mut out = b"ID3\x04\x00\x00".to_vec();
        out.extend_from_slice(&syncsafe(body.len()));
        out.extend_from_slice(&body);
        out
    }

    fn id3v1(artist: &[u8]) -> Vec<u8> {
        let mut out = vec![0u8; 128];
        out[0..3].copy_from_slice(b"TAG");
        out[33..33 + artist.len()].copy_from_slice(artist);
        out
    }

    fn strip_ok(data: &[u8]) -> Stripped {
        Mp3Handler
            .strip(data, &StripOptions::default())
            .expect("strip failed")
    }

    fn findings(data: &[u8]) -> Vec<Finding> {
        Mp3Handler
            .inspect(data, &InspectOptions::names_only())
            .expect("inspect failed")
            .findings
    }

    fn contains(haystack: &[u8], needle: &[u8]) -> bool {
        haystack.windows(needle.len()).any(|w| w == needle)
    }

    #[test]
    fn a_file_with_no_tags_strips_to_a_byte_identical_copy() {
        // Deletion at both ends can promise this, and so it must. TIFF and HEIF cannot.
        let input = audio();
        let stripped = strip_ok(&input);
        assert!(stripped.report.removed.is_empty());
        assert_eq!(stripped.bytes, input);
    }

    #[test]
    fn a_head_tag_is_removed_and_itemised() {
        let mut input = id3v2(&[
            (b"TPE1", b"SYNTHETIC-ARTIST-0001"),
            (b"TSSE", b"SYNTHETIC-ENCODER-0002"),
        ]);
        input.extend_from_slice(&audio());

        let found = findings(&input);
        let fields: Vec<&str> = found.iter().filter_map(|f| f.field.as_deref()).collect();
        assert!(fields.contains(&"TPE1"));
        assert!(fields.contains(&"TSSE"));
        let stripped = strip_ok(&input);
        assert!(!contains(&stripped.bytes, b"SYNTHETIC-ARTIST-0001"));
        assert_eq!(stripped.bytes, audio(), "the frames did not cross intact");
    }

    #[test]
    fn a_tail_tag_is_removed_and_itemised() {
        let mut input = audio();
        input.extend_from_slice(&id3v1(b"SYNTHETIC-ARTIST-0003"));
        let stripped = strip_ok(&input);
        assert_eq!(stripped.report.removed[0].field.as_deref(), Some("Artist"));
        assert_eq!(stripped.bytes, audio());
    }

    #[test]
    fn tags_at_both_ends_go_in_one_pass() {
        let mut input = id3v2(&[(b"TIT2", b"SYNTHETIC-TITLE-0004")]);
        input.extend_from_slice(&audio());
        input.extend_from_slice(&id3v1(b"SYNTHETIC-ARTIST-0005"));
        let stripped = strip_ok(&input);
        assert_eq!(stripped.bytes, audio());
        assert!(!contains(&stripped.bytes, b"SYNTHETIC"));
    }

    #[test]
    fn a_value_is_reported_only_when_the_caller_asks() {
        let mut input = id3v2(&[(b"TPE1", b"SYNTHETIC-ARTIST-0006")]);
        input.extend_from_slice(&audio());
        assert!(findings(&input).iter().all(|f| f.value.is_none()));

        let report = Mp3Handler
            .inspect(&input, &InspectOptions::with_values())
            .unwrap();
        assert!(
            report
                .findings
                .iter()
                .any(|f| f.value == Some(MetadataValue::Text("SYNTHETIC-ARTIST-0006".to_owned())))
        );
    }

    #[test]
    fn a_vbr_header_stays_and_is_declared() {
        // It is a real frame inside the encoded stream, which this group never enters (ADR-0037),
        // and the LAME extension behind the marker names the encoder. Kept, and said out loud.
        let mut first = frame();
        first[4 + 17..4 + 17 + 4].copy_from_slice(b"Xing");
        first[4 + 17 + 12..4 + 17 + 21].copy_from_slice(b"LAME3.100");
        let mut input = first;
        input.extend_from_slice(&audio());

        let stripped = strip_ok(&input);
        assert_eq!(
            stripped.report.retained[0].reason,
            RetentionReason::RemovalWouldAlterPayload
        );
        assert!(stripped.report.retained[0].location.starts_with("Xing"));
        assert!(
            contains(&stripped.bytes, b"LAME3.100"),
            "the VBR frame was not copied through"
        );
    }

    #[test]
    fn every_file_says_the_frames_were_not_examined() {
        let notes = Mp3Handler
            .inspect(&audio(), &InspectOptions::names_only())
            .unwrap()
            .notes;
        assert!(matches!(
            notes.first(),
            Some(Note::OutOfScopeContent { location }) if location.starts_with("audio frames")
        ));
    }

    #[test]
    fn zero_padding_before_the_first_frame_is_dropped_and_reported() {
        let mut input = id3v2(&[(b"TIT2", b"SYNTHETIC-0007")]);
        input.extend_from_slice(&[0u8; 64]);
        input.extend_from_slice(&audio());
        let stripped = strip_ok(&input);
        assert!(
            stripped
                .report
                .removed
                .iter()
                .any(|f| f.location.starts_with("zero padding")),
            "the size change went unaccounted for"
        );
        assert_eq!(stripped.bytes, audio());
    }

    #[test]
    fn anything_other_than_zeros_in_front_of_the_audio_is_refused() {
        // A run of arbitrary bytes there is exactly where something would be hidden from a tool
        // that skipped ahead to the first sync.
        let mut input = id3v2(&[(b"TIT2", b"x")]);
        input.extend_from_slice(b"SYNTHETIC-HIDDEN-0008");
        input.extend_from_slice(&audio());
        assert!(matches!(
            Mp3Handler.strip(&input, &StripOptions::default()),
            Err(StryptError::Malformed { .. })
        ));
    }

    #[test]
    fn a_file_that_is_nothing_but_tags_is_refused() {
        // It would otherwise strip to an empty file and be reported as a success, which is the
        // fail-closed rule's worst case.
        let mut input = id3v2(&[(b"TPE1", b"SYNTHETIC-0009")]);
        input.extend_from_slice(&id3v1(b"SYNTHETIC-0010"));
        assert!(matches!(
            Mp3Handler.strip(&input, &StripOptions::default()),
            Err(StryptError::Malformed {
                detail: MalformedDetail::MissingMarker,
                ..
            })
        ));
    }

    #[test]
    fn a_reserved_field_in_the_first_frame_header_is_refused() {
        // Stricter than detection on purpose: this header decides where the audio begins.
        for (at, value) in [(1u8, 0xEBu8), (1, 0xF9), (2, 0xF0), (2, 0x9C)] {
            let mut input = audio();
            input[usize::from(at)] = value;
            assert!(
                Mp3Handler.strip(&input, &StripOptions::default()).is_err(),
                "byte {at} = {value:#04x} was accepted"
            );
        }
    }

    #[test]
    fn layer_one_and_layer_two_are_refused_by_name() {
        // The same frame grammar, a different format, and Phase 2's scope is MP3 (ADR-0027).
        // MPEG-1 Layer II and Layer I, which differ from `0xFB` only in the two layer bits.
        for second in [0xFDu8, 0xFF] {
            let mut input = audio();
            input[1] = second;
            match Mp3Handler.strip(&input, &StripOptions::default()) {
                Err(StryptError::UnsupportedFormat { format }) => {
                    assert_eq!(format, UnsupportedKind::MpegAudioNotLayerThree);
                }
                other => panic!("byte 1 = {second:#04x} gave {other:?}"),
            }
        }
    }

    #[test]
    fn stripping_twice_changes_nothing() {
        let mut input = id3v2(&[(b"TPE1", b"SYNTHETIC-0011"), (b"APIC", b"SYNTHETIC-0012")]);
        input.extend_from_slice(&audio());
        input.extend_from_slice(&id3v1(b"SYNTHETIC-0013"));
        let once = strip_ok(&input).bytes;
        let twice = strip_ok(&once).bytes;
        assert_eq!(once, twice, "strip is not idempotent");
    }

    #[test]
    fn truncation_at_every_length_is_refused_or_survived_but_never_panics() {
        let mut input = id3v2(&[(b"TPE1", b"SYNTHETIC-0014")]);
        input.extend_from_slice(&audio());
        input.extend_from_slice(&id3v1(b"SYNTHETIC-0015"));
        for n in 0..=input.len() {
            let prefix = &input[0..n];
            let _ = Mp3Handler.inspect(prefix, &InspectOptions::names_only());
            let _ = Mp3Handler.strip(prefix, &StripOptions::default());
        }
    }
}
