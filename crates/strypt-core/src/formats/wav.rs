//! WAV.
//!
//! A RIFF file of form type `WAVE`, so the chunk walk is the shared one in
//! [`crate::container::riff`] and this module is only the part that is WAVE rather than RIFF
//! (ADR-0039). Specified by "Multimedia Programming Interface and Data Specifications 1.0"
//! (IBM/Microsoft, 1991); the metadata chunks come from later specifications named at each one.
//!
//! # Chunk surgery, never re-encoding
//!
//! Kept chunks are copied through **as raw bytes** — code, length, payload, and pad byte
//! verbatim — and the only field recomputed anywhere is the RIFF size. The samples are never
//! decoded, so a WAV comes out of strypt as the same recording it went in as, bit for bit, and a
//! file with nothing to remove strips to a byte-identical copy of itself.
//!
//! mat2's `WAVParser` rebuilds the file through ffmpeg instead. That looked like it would reach
//! data hidden in the samples where this cannot; measured 2026-09-01, it does not — the re-encode
//! reproduces 16-bit PCM exactly. See `docs/THREAT_MODEL.md` §7.14.
//!
//! # Nothing here moves an offset
//!
//! Group 4's hazard is a format whose index is a table of absolute file offsets, so that removing
//! a chunk silently invalidates it. WAV does not have one. `cue `'s `dwChunkStart` and
//! `dwBlockStart` are byte offsets **into the data section of a `wavl` list**, not into the file,
//! so chunk removal moves nothing (verified 2026-09-01). The one shape where that reasoning would
//! not hold — a `LIST` of form `wavl` — is refused by name rather than edited.
//!
//! # Output is an allow-list
//!
//! Only `fmt `, `data`, `fact`, and `cue ` reach the output; `JUNK` and `PAD ` are kept at their
//! length with every byte zeroed (ADR-0038 decision 3, carried across). Everything else goes,
//! including every chunk this handler has no name for — a producer's private chunk is where the
//! thing they did not want looked at is kept.

use crate::container::riff::{self, Chunk, FourCc, WalkError, name_of};
use crate::detect::Format;
use crate::error::{MalformedDetail, Result, StryptError, UnsupportedKind};
use crate::formats::{MetadataHandler, ParseLimits, StripOptions, Stripped, xmp};
use crate::report::{
    Finding, InspectOptions, MetadataKind, MetadataReport, MetadataValue, Note, Retained,
    RetentionReason, StripReport,
};

/// Removal of metadata from WAV audio.
#[derive(Debug, Clone, Copy, Default)]
pub struct WavHandler;

impl MetadataHandler for WavHandler {
    fn name(&self) -> &'static str {
        Format::Wav.id()
    }

    fn format(&self) -> Format {
        Format::Wav
    }

    fn inspect(&self, input: &[u8], options: &InspectOptions) -> Result<MetadataReport> {
        // Inspection runs the identical pass that stripping does and throws the output away, so
        // "everything `strip` removes is something `inspect` can see" holds by construction.
        let processed = process(input, options, &ParseLimits::default())?;
        Ok(MetadataReport {
            format: Format::Wav,
            findings: processed.findings,
            notes: processed.notes,
        })
    }

    fn strip(&self, input: &[u8], options: &StripOptions) -> Result<Stripped> {
        let processed = process(input, &options.inspect, &options.limits)?;
        Ok(Stripped {
            report: StripReport {
                format: Format::Wav,
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

/// The form type that makes a RIFF file a WAV file.
const WAVE: FourCc = *b"WAVE";

/// The shortest `fmt ` any WAV has: the PCM form, before the extension size field.
const FMT_MINIMUM: usize = 16;

/// Chunks copied through byte for byte.
///
/// `fmt ` says what the audio is, `data` is the audio, `fact` is the decoded sample count that
/// every non-PCM encoding requires, and `cue ` is playback structure whose offsets removal cannot
/// move. None of the four has a field that names anybody.
const KEPT: [&FourCc; 4] = [b"fmt ", b"data", b"fact", b"cue "];

/// Chunks kept at their length with every byte zeroed.
///
/// `FLLR` is Pro Tools' spelling of the same idea. Real writers leave kilobytes of this for
/// sector alignment or to reserve room for a `bext` that may be written later, and a producer
/// that reserved room by writing out an old buffer left whatever was in it (ADR-0038 decision 3).
const ZEROED: [&FourCc; 3] = [b"JUNK", b"PAD ", b"FLLR"];

/// `LIST` form types this handler knows. Any other is removed whole.
const LIST_INFO: FourCc = *b"INFO";
const LIST_ADTL: FourCc = *b"adtl";
/// A wave list: `data` and `slnt` chunks interleaved, and the thing `cue ` offsets index into.
const LIST_WAVL: FourCc = *b"wavl";

/// `LIST`/`INFO` tags worth naming individually in a report (RIFFMCI, "Information chunks").
const INFO_TAGS: &[(&[u8; 4], &str, MetadataKind)] = &[
    (b"IART", "Artist", MetadataKind::PersonalIdentity),
    (b"IENG", "Engineer", MetadataKind::PersonalIdentity),
    (b"ITCH", "Technician", MetadataKind::PersonalIdentity),
    (b"ICMS", "Commissioned", MetadataKind::PersonalIdentity),
    (b"ICOP", "Copyright", MetadataKind::PersonalIdentity),
    (b"IARL", "ArchivalLocation", MetadataKind::Location),
    (b"ICRD", "CreationDate", MetadataKind::Timestamp),
    (b"IDIT", "DigitisationTime", MetadataKind::Timestamp),
    (b"ISFT", "Software", MetadataKind::SoftwareFingerprint),
    (b"ITOC", "TableOfContents", MetadataKind::DocumentIdentifier),
    (b"ISRC", "Source", MetadataKind::DocumentIdentifier),
    (b"ICMT", "Comment", MetadataKind::Comment),
    (b"INAM", "Title", MetadataKind::Comment),
    (b"ISBJ", "Subject", MetadataKind::Comment),
    (b"IKEY", "Keywords", MetadataKind::Comment),
    (b"IPRD", "Product", MetadataKind::Comment),
    (b"IGNR", "Genre", MetadataKind::Comment),
    (b"IMED", "Medium", MetadataKind::Comment),
];

/// `bext`'s fixed-width text fields, by offset (EBU Tech 3285, the Broadcast Wave extension).
///
/// The chunk goes whole either way; this table only decides how the report reads. `TimeReference`
/// and the loudness fields are numeric and are covered by the whole-chunk finding.
const BEXT_FIELDS: &[(usize, usize, &str, MetadataKind)] = &[
    (0, 256, "Description", MetadataKind::Comment),
    (256, 32, "Originator", MetadataKind::PersonalIdentity),
    (288, 32, "OriginatorReference", MetadataKind::DeviceIdentity),
    (320, 10, "OriginationDate", MetadataKind::Timestamp),
    (330, 8, "OriginationTime", MetadataKind::Timestamp),
    // A UMID embeds the recorder's own number, which links every take it ever made.
    (348, 64, "UMID", MetadataKind::DocumentIdentifier),
    // Unbounded, and a log of every process the audio has been through.
    (
        602,
        usize::MAX,
        "CodingHistory",
        MetadataKind::EditingHistory,
    ),
];

/// `cart`'s fixed-width text fields, by offset (AES46-2002, the radio traffic chunk).
const CART_FIELDS: &[(usize, usize, &str, MetadataKind)] = &[
    (4, 64, "Title", MetadataKind::Comment),
    (68, 64, "Artist", MetadataKind::PersonalIdentity),
    (132, 64, "CutID", MetadataKind::DocumentIdentifier),
    (196, 64, "ClientID", MetadataKind::PersonalIdentity),
    (388, 10, "StartDate", MetadataKind::Timestamp),
    (420, 64, "ProducerAppID", MetadataKind::SoftwareFingerprint),
    (
        484,
        64,
        "ProducerAppVersion",
        MetadataKind::SoftwareFingerprint,
    ),
    (1024, 1024, "URL", MetadataKind::Location),
];

/// The result of one pass over a file: what was found, and what the sanitised file looks like.
struct Processed {
    findings: Vec<Finding>,
    retained: Vec<Retained>,
    notes: Vec<Note>,
    output: Vec<u8>,
}

/// What to do with one chunk.
enum Outcome {
    /// Copy it through unchanged.
    Keep,
    /// Copy it through with the given bytes in its place.
    Replace(Vec<u8>),
    /// Remove it entirely.
    Drop,
}

/// A decision about one chunk, with what to tell the user about it.
struct Decision {
    outcome: Outcome,
    findings: Vec<Finding>,
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
    let mut budget = limits.max_items;
    let (chunks, trailing) = riff::read(input, WAVE, &mut budget).map_err(convert)?;
    validate_shape(&chunks)?;

    let mut findings = Vec::new();
    let mut retained = Vec::new();
    let mut notes = Vec::new();

    let mut body: Vec<u8> = Vec::with_capacity(input.len());
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
        // can be there.
        findings.push(Finding::new(
            MetadataKind::Other,
            "trailing data after the RIFF chunk",
            as_u64(trailing.len()),
        ));
    }

    // Said once per file, because the whole design rests on it: the samples are copied without
    // being looked at, so anything hidden *in the audio* is still there.
    notes.push(Note::OutOfScopeContent {
        location: "audio samples, which are copied without being decoded".to_owned(),
    });

    // Unreachable in practice: the output body is never larger than the input's declared RIFF
    // size, which was itself read as a `u32`.
    let output = riff::write(WAVE, &body).map_err(|d| malformed(d, None))?;

    Ok(Processed {
        findings,
        retained,
        notes,
        output,
    })
}

/// A container-layer walk failure as this format's error.
fn convert(error: WalkError) -> StryptError {
    match error {
        WalkError::Malformed { detail, offset } => malformed(detail, as_offset(offset)),
        WalkError::Limit(limit) => StryptError::LimitExceeded {
            format: Format::Wav,
            limit,
        },
    }
}

/// Refuse a chunk list that is not a shape this handler has understood.
///
/// The first two checks stop the handler emitting something that passes for a WAV and is not
/// one: a file consisting of a `bext` and nothing else would otherwise strip to an empty
/// container and be reported as a success, which is the fail-closed rule's worst case.
fn validate_shape(chunks: &[Chunk<'_>]) -> Result<()> {
    for chunk in chunks {
        if &chunk.kind == b"LIST" && matches!(riff::list_form(chunk.data), Some((LIST_WAVL, _))) {
            return Err(StryptError::UnsupportedFormat {
                format: UnsupportedKind::WaveList,
            });
        }
        // A `fmt ` shorter than the PCM form is not a `fmt `, and every field after it in the
        // file is being read relative to something this handler cannot check.
        if &chunk.kind == b"fmt " && chunk.data.len() < FMT_MINIMUM {
            return Err(malformed(
                MalformedDetail::LengthOutOfRange,
                as_offset(chunk.offset),
            ));
        }
    }

    for required in [b"fmt ", b"data"] {
        if !chunks.iter().any(|c| &c.kind == required) {
            return Err(malformed(
                MalformedDetail::MissingMarker,
                as_offset(riff::HEADER_BYTES),
            ));
        }
    }
    Ok(())
}

/// Decide about one chunk.
fn decide(chunk: &Chunk<'_>, options: &InspectOptions, limits: &ParseLimits) -> Decision {
    let size = as_u64(chunk.data.len());
    let kind = &chunk.kind;

    if KEPT.contains(&kind) {
        return Decision::keep();
    }
    if ZEROED.contains(&kind) {
        return zeroed(chunk);
    }

    match kind {
        b"LIST" => list(chunk, options, limits),
        // EBU Tech 3285. The chunk this tranche exists for: an originator, a globally unique
        // material identifier, and an unbounded log of every process the audio has been through.
        b"bext" => Decision::drop_with(fields(
            chunk.data,
            BEXT_FIELDS,
            "bext",
            size,
            MetadataKind::Other,
            options,
        )),
        // AES46-2002: the broadcast traffic chunk, which names a client and a producing station.
        b"cart" => Decision::drop_with(fields(
            chunk.data,
            CART_FIELDS,
            "cart",
            size,
            MetadataKind::Other,
            options,
        )),
        // XMP in RIFF, as Adobe's applications write it.
        b"_PMX" => {
            let found = xmp::scan(chunk.data, "_PMX", options);
            if found.is_empty() {
                Decision::drop_one(MetadataKind::Other, "_PMX", size)
            } else {
                Decision::drop_with(found)
            }
        }
        // Field-recorder XML: project, scene, take, note, and the recorder's serial number.
        b"iXML" => Decision::drop_one(MetadataKind::DeviceIdentity, "iXML", size),
        // Dropped whole rather than parsed. An ID3 reader belongs to the MP3 tranche, and this
        // handler does not need one to remove the tag (ADR-0037).
        b"id3 " | b"ID3 " => Decision::drop_one(MetadataKind::Other, "id3", size),
        // A clipboard rendering of the file — often its title, sometimes a bitmap.
        b"DISP" => Decision::drop_one(MetadataKind::Comment, "DISP", size),
        // The code page the text chunks were written in, which narrows down where they came from.
        b"CSET" => Decision::drop_one(MetadataKind::Other, "CSET", size),
        // Sampler metadata: MIDI manufacturer and product numbers, and an SMPTE offset. Removing
        // it costs the file its loop points, which is worth saying out loud.
        b"smpl" => Decision {
            outcome: Outcome::Drop,
            findings: vec![Finding::new(MetadataKind::DeviceIdentity, "smpl", size)],
            retained: Vec::new(),
            notes: vec![Note::CapabilityRemoved {
                location: "smpl".to_owned(),
                capability: "be looped by a sampler at the points it recorded".to_owned(),
            }],
        },
        b"inst" => Decision::drop_one(MetadataKind::Other, "inst", size),
        b"plst" => Decision::drop_one(MetadataKind::Other, "plst", size),
        // Everything else, `aXML` — EBU Tech 3285's arbitrary XML document — included. An unknown
        // chunk is precisely where a producer puts something they do not want a metadata tool to
        // look at, and RIFF readers are required to skip what they do not know, so dropping one
        // cannot break a player.
        _ => Decision::drop_one(MetadataKind::Other, name_of(kind), size),
    }
}

/// `JUNK`, `PAD `, `FLLR`: kept at their length, every byte zeroed.
///
/// Dropping them instead would be simpler and would lose the alignment the file was written with.
/// Zeroing scrubs whatever was in the buffer without costing the user the room it exists for.
fn zeroed(chunk: &Chunk<'_>) -> Decision {
    if chunk.data.iter().all(|b| *b == 0) {
        // Already clean, so it is copied rather than rebuilt — which keeps a padded file
        // byte-identical through a strip.
        return Decision::keep();
    }
    let mut out = Vec::with_capacity(chunk.raw.len());
    if riff::write_chunk(&mut out, chunk.kind, &vec![0u8; chunk.data.len()]).is_err() {
        // Unreachable: the length came from a chunk that was already read.
        return Decision::keep();
    }
    Decision {
        outcome: Outcome::Replace(out),
        findings: vec![Finding::new(
            MetadataKind::Other,
            name_of(&chunk.kind),
            as_u64(chunk.data.len()),
        )],
        retained: vec![Retained {
            location: name_of(&chunk.kind),
            reason: RetentionReason::StructurallyRequired,
        }],
        notes: Vec::new(),
    }
}

/// `LIST`: a form type and a nested chunk sequence.
fn list(chunk: &Chunk<'_>, options: &InspectOptions, limits: &ParseLimits) -> Decision {
    let size = as_u64(chunk.data.len());
    let Some((form, rest)) = riff::list_form(chunk.data) else {
        return Decision::drop_one(MetadataKind::Other, "LIST", size);
    };
    // `wavl` never reaches here: `validate_shape` refuses the file.
    if form != LIST_INFO && form != LIST_ADTL {
        return Decision::drop_one(
            MetadataKind::Other,
            format!("LIST {}", name_of(&form)),
            size,
        );
    }

    let mut budget = limits.max_items;
    let Ok(items) = riff::chunks(rest, 0, &mut budget) else {
        // The list does not parse, so it is removed whole and reported as one item rather than
        // half-read. Nothing is kept, so there is nothing to be wrong about.
        return Decision::drop_one(
            MetadataKind::Other,
            format!("LIST {}", name_of(&form)),
            size,
        );
    };

    let mut findings = Vec::new();
    for item in &items {
        let bytes = as_u64(item.data.len());
        let (field, kind) = if form == LIST_INFO {
            INFO_TAGS
                .iter()
                .find(|(tag, _, _)| *tag == &item.kind)
                .map_or_else(
                    || (name_of(&item.kind), MetadataKind::Other),
                    |(_, name, kind)| ((*name).to_owned(), *kind),
                )
        } else {
            // `adtl`: `labl` and `note` are free text attached to a cue point, `ltxt` is a
            // labelled text region.
            (name_of(&item.kind), MetadataKind::Comment)
        };
        findings.push(
            Finding::new(kind, format!("LIST {}", name_of(&form)), bytes)
                .with_field(field)
                .with_value(options, || MetadataValue::Text(text_of(item.data))),
        );
    }
    if findings.is_empty() {
        findings.push(Finding::new(
            MetadataKind::Other,
            format!("LIST {}", name_of(&form)),
            size,
        ));
    }
    Decision::drop_with(findings)
}

/// Report the non-empty fixed-width text fields of a chunk that is going whole.
///
/// A chunk too short for the table still yields one finding under `fallback`: something is there,
/// it is going, and silence would read as "no metadata here".
fn fields(
    data: &[u8],
    table: &[(usize, usize, &str, MetadataKind)],
    location: &str,
    size: u64,
    fallback: MetadataKind,
    options: &InspectOptions,
) -> Vec<Finding> {
    let mut out = Vec::new();
    for (at, len, name, kind) in table {
        let Some(tail) = data.get(*at..) else {
            continue;
        };
        let raw = tail.get(..*len).unwrap_or(tail);
        let value = text_of(raw);
        if value.is_empty() {
            continue;
        }
        out.push(
            Finding::new(*kind, location.to_owned(), as_u64(raw.len()))
                .with_field((*name).to_owned())
                .with_value(options, || MetadataValue::Text(value.clone())),
        );
    }
    if out.is_empty() {
        out.push(Finding::new(fallback, location.to_owned(), size));
    }
    out
}

/// A fixed-width or NUL-terminated RIFF string as reportable text.
///
/// Padding here is written as NULs by some producers and as spaces by others, so both are
/// trimmed. Control characters are dropped rather than rendered, which is also what keeps a
/// hostile field from writing escape sequences into a terminal.
fn text_of(raw: &[u8]) -> String {
    let end = raw.iter().position(|b| *b == 0).unwrap_or(raw.len());
    let head = raw.get(..end).unwrap_or_default();
    xmp::name_of(head).trim().to_owned()
}

/// A malformed-file error for this format.
fn malformed(detail: MalformedDetail, offset: Option<u64>) -> StryptError {
    StryptError::Malformed {
        format: Format::Wav,
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

    fn chunk(kind: FourCc, payload: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        riff::write_chunk(&mut out, kind, payload).unwrap();
        out
    }

    /// A 16-bit mono PCM format chunk at 8 kHz.
    fn fmt() -> Vec<u8> {
        let mut p = Vec::new();
        p.extend_from_slice(&1u16.to_le_bytes()); // PCM
        p.extend_from_slice(&1u16.to_le_bytes()); // channels
        p.extend_from_slice(&8000u32.to_le_bytes());
        p.extend_from_slice(&16000u32.to_le_bytes());
        p.extend_from_slice(&2u16.to_le_bytes());
        p.extend_from_slice(&16u16.to_le_bytes());
        chunk(*b"fmt ", &p)
    }

    fn data() -> Vec<u8> {
        chunk(*b"data", b"SYNTHETIC-SAMPLES-0001\0\0")
    }

    fn wav(parts: &[Vec<u8>]) -> Vec<u8> {
        riff::write(WAVE, &parts.concat()).unwrap()
    }

    fn strip_ok(input: &[u8]) -> Stripped {
        WavHandler
            .strip(input, &StripOptions::default())
            .expect("strip failed")
    }

    fn findings(input: &[u8]) -> Vec<Finding> {
        WavHandler
            .inspect(input, &InspectOptions::names_only())
            .expect("inspect failed")
            .findings
    }

    fn contains(haystack: &[u8], needle: &[u8]) -> bool {
        haystack.windows(needle.len()).any(|w| w == needle)
    }

    /// A `LIST`/`INFO` carrying the given tags.
    fn info(tags: &[(FourCc, &[u8])]) -> Vec<u8> {
        let mut body = LIST_INFO.to_vec();
        for (tag, value) in tags {
            let mut v = value.to_vec();
            v.push(0);
            body.extend_from_slice(&chunk(*tag, &v));
        }
        chunk(*b"LIST", &body)
    }

    #[test]
    fn a_clean_file_comes_back_byte_identical() {
        let input = wav(&[fmt(), data()]);
        let stripped = strip_ok(&input);
        assert!(stripped.report.removed.is_empty());
        assert_eq!(stripped.bytes, input, "a clean WAV was rewritten");
    }

    #[test]
    fn the_audio_crosses_byte_for_byte() {
        let input = wav(&[fmt(), info(&[(*b"IART", b"SYNTHETIC-ARTIST-0002")]), data()]);
        let output = strip_ok(&input).bytes;
        assert!(contains(&output, b"SYNTHETIC-SAMPLES-0001"));
        assert!(!contains(&output, b"SYNTHETIC-ARTIST-0002"));
    }

    #[test]
    fn an_info_list_is_itemised_by_tag() {
        let input = wav(&[
            fmt(),
            info(&[
                (*b"IART", b"SYNTHETIC-ARTIST-0002"),
                (*b"ISFT", b"SYNTHETIC-RECORDER-0003"),
                (*b"ICRD", b"2026-09-01"),
            ]),
            data(),
        ]);
        let found = findings(&input);
        let fields: Vec<&str> = found.iter().filter_map(|f| f.field.as_deref()).collect();
        assert!(fields.contains(&"Artist"), "{fields:?}");
        assert!(fields.contains(&"Software"), "{fields:?}");
        assert!(fields.contains(&"CreationDate"), "{fields:?}");
        let kinds: Vec<MetadataKind> = found.iter().map(|f| f.kind).collect();
        assert!(kinds.contains(&MetadataKind::PersonalIdentity));
        assert!(kinds.contains(&MetadataKind::SoftwareFingerprint));
        assert!(kinds.contains(&MetadataKind::Timestamp));
    }

    #[test]
    fn an_unrecognised_info_tag_is_still_removed_and_reported() {
        let input = wav(&[
            fmt(),
            info(&[(*b"IZZZ", b"SYNTHETIC-PRIVATE-0004")]),
            data(),
        ]);
        let stripped = strip_ok(&input);
        assert!(!contains(&stripped.bytes, b"SYNTHETIC-PRIVATE-0004"));
        assert_eq!(stripped.report.removed[0].field.as_deref(), Some("IZZZ"));
    }

    #[test]
    fn a_broadcast_extension_is_itemised_down_to_its_coding_history() {
        let mut p = vec![0u8; 602];
        p[0..9].copy_from_slice(b"SYNTHETIC");
        p[256..265].copy_from_slice(b"ORIG-0005");
        p[288..297].copy_from_slice(b"REF--0006");
        p[320..330].copy_from_slice(b"2026-09-01");
        p[348..357].copy_from_slice(b"UMID-0007");
        p.extend_from_slice(b"A=PCM,F=8000,W=16,M=mono,T=SYNTHETIC-DECK-0008");
        let input = wav(&[fmt(), chunk(*b"bext", &p), data()]);

        let found = findings(&input);
        let fields: Vec<&str> = found.iter().filter_map(|f| f.field.as_deref()).collect();
        for want in [
            "Description",
            "Originator",
            "OriginatorReference",
            "OriginationDate",
            "UMID",
            "CodingHistory",
        ] {
            assert!(fields.contains(&want), "{want} missing from {fields:?}");
        }

        let stripped = strip_ok(&input);
        assert!(!contains(&stripped.bytes, b"SYNTHETIC-DECK-0008"));
        assert!(!contains(&stripped.bytes, b"UMID-0007"));
    }

    #[test]
    fn an_empty_broadcast_extension_still_yields_one_finding() {
        // Silence would read as "no metadata here".
        let input = wav(&[fmt(), chunk(*b"bext", &[0u8; 602]), data()]);
        let found = findings(&input);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].location, "bext");
    }

    #[test]
    fn an_id3_tag_is_dropped_whole_without_being_parsed() {
        let mut tag = b"ID3\x04\x00\x00\x00\x00\x00\x20".to_vec();
        tag.extend_from_slice(b"TPE1SYNTHETIC-ID3-ARTIST-0009");
        let input = wav(&[fmt(), data(), chunk(*b"id3 ", &tag)]);
        let stripped = strip_ok(&input);
        assert!(!contains(&stripped.bytes, b"SYNTHETIC-ID3-ARTIST-0009"));
        assert_eq!(stripped.report.removed[0].location, "id3");
    }

    #[test]
    fn an_xmp_packet_is_itemised_by_property() {
        let input = wav(&[
            fmt(),
            data(),
            chunk(
                *b"_PMX",
                br#"<x:xmpmeta xmpMM:DocumentID="uuid:1" xmp:CreatorTool="SYNTHETIC"/>"#,
            ),
        ]);
        let fields: Vec<String> = findings(&input)
            .iter()
            .filter_map(|f| f.field.clone())
            .collect();
        assert!(fields.iter().any(|f| f == "xmpMM:DocumentID"), "{fields:?}");
    }

    #[test]
    fn a_sampler_chunk_says_what_the_file_can_no_longer_do() {
        let input = wav(&[fmt(), data(), chunk(*b"smpl", &[0u8; 36])]);
        let stripped = strip_ok(&input);
        assert!(matches!(
            stripped.report.notes.first(),
            Some(Note::CapabilityRemoved { location, .. }) if location == "smpl"
        ));
    }

    #[test]
    fn padding_is_zeroed_at_its_length_rather_than_dropped() {
        let input = wav(&[fmt(), chunk(*b"JUNK", b"SYNTHETIC-LEFTOVER-0010!"), data()]);
        let stripped = strip_ok(&input);
        assert!(!contains(&stripped.bytes, b"SYNTHETIC-LEFTOVER-0010"));
        assert_eq!(
            stripped.bytes.len(),
            input.len(),
            "zeroing changed the file's length"
        );
        assert_eq!(
            stripped.report.retained[0].reason,
            RetentionReason::StructurallyRequired
        );
    }

    #[test]
    fn padding_that_is_already_zero_is_copied_rather_than_rebuilt() {
        let input = wav(&[fmt(), chunk(*b"JUNK", &[0u8; 32]), data()]);
        let stripped = strip_ok(&input);
        assert!(stripped.report.removed.is_empty());
        assert_eq!(stripped.bytes, input);
    }

    #[test]
    fn a_cue_chunk_survives_because_removing_metadata_cannot_move_its_offsets() {
        let mut cue = 1u32.to_le_bytes().to_vec();
        cue.extend_from_slice(&[0u8; 24]);
        let input = wav(&[fmt(), data(), chunk(*b"cue ", &cue)]);
        assert_eq!(strip_ok(&input).bytes, input);
    }

    #[test]
    fn an_unknown_chunk_is_removed_rather_than_preserved() {
        let input = wav(&[fmt(), data(), chunk(*b"PrVw", b"SYNTHETIC-PRIVATE-0011")]);
        let stripped = strip_ok(&input);
        assert!(!contains(&stripped.bytes, b"SYNTHETIC-PRIVATE-0011"));
        assert_eq!(stripped.report.removed[0].location, "PrVw");
    }

    #[test]
    fn data_after_the_riff_chunk_is_removed() {
        let mut input = wav(&[fmt(), data()]);
        input.extend_from_slice(b"SYNTHETIC-APPENDED-0012");
        let stripped = strip_ok(&input);
        assert!(!contains(&stripped.bytes, b"SYNTHETIC-APPENDED-0012"));
        assert_eq!(
            stripped.report.removed[0].location,
            "trailing data after the RIFF chunk"
        );
    }

    #[test]
    fn a_file_with_no_format_or_no_audio_is_refused_rather_than_emptied() {
        // Otherwise this strips to a valid-looking container with no audio in it, and the user is
        // told it succeeded.
        for parts in [
            vec![fmt()],
            vec![data()],
            vec![chunk(*b"bext", &[0u8; 602])],
        ] {
            assert!(
                matches!(
                    WavHandler.strip(&wav(&parts), &StripOptions::default()),
                    Err(StryptError::Malformed {
                        detail: MalformedDetail::MissingMarker,
                        ..
                    })
                ),
                "a WAV missing fmt or data was accepted"
            );
        }
    }

    #[test]
    fn a_wave_list_is_refused_by_name_rather_than_edited() {
        // The one shape where a cue offset indexes into something removal could move.
        let mut body = LIST_WAVL.to_vec();
        body.extend_from_slice(&chunk(*b"data", b"AB"));
        let input = wav(&[fmt(), chunk(*b"LIST", &body), data()]);
        assert!(matches!(
            WavHandler.inspect(&input, &InspectOptions::names_only()),
            Err(StryptError::UnsupportedFormat {
                format: UnsupportedKind::WaveList,
            })
        ));
    }

    #[test]
    fn a_format_chunk_shorter_than_the_pcm_form_is_refused() {
        let input = wav(&[chunk(*b"fmt ", &[0u8; 8]), data()]);
        assert!(matches!(
            WavHandler.inspect(&input, &InspectOptions::names_only()),
            Err(StryptError::Malformed {
                detail: MalformedDetail::LengthOutOfRange,
                ..
            })
        ));
    }

    #[test]
    fn a_riff_size_beyond_the_end_of_the_file_is_refused_rather_than_clamped() {
        let mut input = wav(&[fmt(), data()]);
        input[4..8].copy_from_slice(&0x00FF_FFFFu32.to_le_bytes());
        assert!(matches!(
            WavHandler.inspect(&input, &InspectOptions::names_only()),
            Err(StryptError::Malformed {
                detail: MalformedDetail::LengthOutOfRange,
                ..
            })
        ));
    }

    #[test]
    fn a_chunk_count_beyond_the_limit_is_refused() {
        let mut parts = vec![fmt(), data()];
        parts.extend((0..64).map(|_| chunk(*b"PrVw", b"xx")));
        let options = StripOptions {
            limits: ParseLimits {
                max_items: 8,
                ..ParseLimits::default()
            },
            ..StripOptions::default()
        };
        assert!(matches!(
            WavHandler.strip(&wav(&parts), &options),
            Err(StryptError::LimitExceeded { .. })
        ));
    }

    #[test]
    fn values_are_withheld_from_a_default_inspection() {
        let input = wav(&[fmt(), info(&[(*b"IART", b"SYNTHETIC-ARTIST-0002")]), data()]);
        assert_eq!(findings(&input)[0].value, None);
        let with_values = WavHandler
            .inspect(&input, &InspectOptions::with_values())
            .unwrap();
        assert_eq!(
            with_values.findings[0].value,
            Some(MetadataValue::Text("SYNTHETIC-ARTIST-0002".to_owned()))
        );
    }

    #[test]
    fn the_uninspected_audio_is_declared_on_every_file() {
        let stripped = strip_ok(&wav(&[fmt(), data()]));
        assert!(
            stripped
                .report
                .notes
                .iter()
                .any(|n| matches!(n, Note::OutOfScopeContent { location } if location.starts_with("audio samples")))
        );
    }

    #[test]
    fn stripping_twice_changes_nothing() {
        let input = wav(&[
            fmt(),
            info(&[(*b"IART", b"SYNTHETIC-ARTIST-0002")]),
            chunk(*b"JUNK", b"SYNTHETIC-LEFTOVER-0010!"),
            data(),
            chunk(*b"bext", &[0u8; 602]),
        ]);
        let once = strip_ok(&input).bytes;
        let twice = strip_ok(&once).bytes;
        assert_eq!(once, twice, "strip is not idempotent");
        assert!(findings(&once).is_empty(), "a strip left something behind");
    }

    #[test]
    fn an_odd_length_chunk_keeps_its_padding_byte() {
        let input = wav(&[fmt(), chunk(*b"data", b"ODD")]);
        let stripped = strip_ok(&input);
        assert_eq!(stripped.bytes, input);
        assert_eq!(stripped.bytes.len() % 2, 0);
    }

    #[test]
    fn truncation_at_every_length_is_refused_or_survived_but_never_panics() {
        let input = wav(&[
            fmt(),
            info(&[(*b"IART", b"SYNTHETIC-ARTIST-0002")]),
            chunk(*b"bext", &[7u8; 700]),
            chunk(*b"JUNK", b"x"),
            data(),
            chunk(*b"smpl", &[0u8; 36]),
        ]);
        for n in 0..=input.len() {
            let prefix = &input[0..n];
            let _ = WavHandler.inspect(prefix, &InspectOptions::names_only());
            let _ = WavHandler.strip(prefix, &StripOptions::default());
        }
    }
}
