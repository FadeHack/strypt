//! MP4 and M4A: the ISO base media file format carrying tracks rather than a picture.
//!
//! # Why this is edited by deletion where HEIF is rebuilt
//!
//! `stco` holds absolute file offsets into `mdat` (§8.7.5), so removing a box in front of the media
//! moves every chunk. ADR-0034 met that sentence in HEIF and rebuilt the file; here it reverses.
//! HEIF's metadata is *inside* `mdat`, interleaved with the picture, so removals leave a hole and
//! nothing translates uniformly. MP4's metadata is entirely outside `mdat` — `udta`, `meta`, a
//! top-level `uuid` — so each `mdat` moves as one rigid block and the media never changes.
//!
//! The tree is therefore filtered and re-emitted: `ftyp` and every `mdat` cross verbatim, header
//! form included, and only `moov` is written fresh. Every chunk offset is then remapped through a
//! table of `mdat` extents, and **an offset that resolves inside none of them refuses the file**
//! rather than being nudged by a delta nobody verified (ADR-0042).
//!
//! Fragmented files and encrypted files are refused by name: the first keeps sample offsets in
//! structures this handler does not rewrite, the second is ciphertext no rule here matches.

use crate::bytes::Reader;
use crate::container::bmff::{self, Box as Bmff, BoxType, WalkError};
use crate::detect::Format;
use crate::error::{MalformedDetail, Result, StryptError, UnsupportedKind};
use crate::formats::{MetadataHandler, ParseLimits, StripOptions, Stripped, xmp};
use crate::report::{
    Finding, InspectOptions, MetadataKind, MetadataReport, MetadataValue, Note, Retained,
    RetentionReason, StripReport,
};

pub(crate) mod boxes;

/// The MP4 and M4A handler. One type, one instance per format, as [`super::heif`] does.
#[derive(Debug, Clone, Copy)]
#[non_exhaustive]
pub struct Mp4Handler {
    format: Format,
}

impl Mp4Handler {
    /// The handler instance for MP4 — `.mp4`, `.m4v`.
    pub const MP4: Self = Self {
        format: Format::Mp4,
    };
    /// The handler instance for M4A — `.m4a`, `.m4b`.
    pub const M4A: Self = Self {
        format: Format::M4a,
    };
}

impl MetadataHandler for Mp4Handler {
    fn name(&self) -> &'static str {
        self.format.id()
    }

    fn format(&self) -> Format {
        self.format
    }

    fn inspect(&self, input: &[u8], options: &InspectOptions) -> Result<MetadataReport> {
        // The same pass strip runs, output discarded, so the two cannot drift (ARCHITECTURE §3).
        let processed = process(self.format, input, options, &ParseLimits::default())?;
        Ok(MetadataReport {
            format: self.format,
            findings: processed.findings,
            notes: processed.notes,
        })
    }

    fn strip(&self, input: &[u8], options: &StripOptions) -> Result<Stripped> {
        let processed = process(self.format, input, &options.inspect, &options.limits)?;
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

/// One run of the shared inspect/strip pass.
struct Processed {
    output: Vec<u8>,
    findings: Vec<Finding>,
    retained: Vec<Retained>,
    notes: Vec<Note>,
}

/// One `mdat`'s payload, where it was and where it lands.
#[derive(Debug, Clone, Copy)]
struct Extent {
    old_start: u64,
    old_end: u64,
    new_start: u64,
}

/// Resolve a chunk offset against the input's `mdat` extents.
///
/// [`None`] when it falls in none of them — into a box that was dropped, into `moov`, or past the
/// end of the file. The caller turns that into a refusal (ADR-0042 decision 2).
fn relocate(extents: &[Extent], offset: u64) -> Option<u64> {
    extents
        .iter()
        .find(|e| offset >= e.old_start && offset < e.old_end)
        .and_then(|e| offset.checked_sub(e.old_start)?.checked_add(e.new_start))
}

/// A box as it will be written.
enum Node<'a> {
    /// Copied byte for byte, header form included.
    Copy(&'a [u8]),
    /// A container whose children were filtered.
    Container {
        kind: BoxType,
        children: Vec<Node<'a>>,
    },
    /// A full box whose fields were edited in place. `body` includes the version and flags.
    Patched { kind: BoxType, body: Vec<u8> },
    /// A chunk offset table, written once with placeholders to measure and once for real.
    Offsets {
        kind: BoxType,
        head: [u8; 4],
        values: Vec<u64>,
    },
}

/// A top-level emission, in input order.
enum Top<'a> {
    Copy(&'a [u8]),
    Mdat {
        raw: &'a [u8],
        header: u64,
        old_start: u64,
        len: u64,
    },
    Moov,
}

/// Read `input`, name what is being dropped, and write the edited file.
fn process(
    format: Format,
    input: &[u8],
    options: &InspectOptions,
    limits: &ParseLimits,
) -> Result<Processed> {
    let mut budget = limits.max_items;
    let (top, trailing) = bmff::top_level(input, &mut budget).map_err(|e| from_walk(format, e))?;

    // Before anything else, so a refusal names what the file is rather than what it lacks.
    for b in &top {
        refuse_structural(b.kind)?;
    }
    let ftyp = bmff::find(&top, *b"ftyp")
        .ok_or_else(|| malformed(format, MalformedDetail::MissingMarker))?;
    refuse_brands(ftyp.payload)?;

    // Exactly one movie box. None is a file with no index; more than one is a file whose index is
    // ambiguous, and guessing which one a player picks is not a decision to make on a user's behalf.
    match top.iter().filter(|b| b.is(*b"moov")).count() {
        1 => {}
        0 => return Err(malformed(format, MalformedDetail::MissingMarker)),
        _ => return Err(malformed(format, MalformedDetail::UnexpectedMarker)),
    }

    let mut findings = Vec::new();
    let mut tops = Vec::with_capacity(top.len());
    let mut moov_node = None;

    for b in &top {
        let raw = bmff::raw(input, b)
            .ok_or_else(|| malformed(format, MalformedDetail::LengthOutOfRange))?;
        if b.is(*b"moov") {
            moov_node = Some(container_node(
                format,
                input,
                b,
                b.payload,
                limits.max_depth,
                &mut budget,
                &mut findings,
                options,
                None,
            )?);
            tops.push(Top::Moov);
        } else if b.is(*b"mdat") {
            let old_start = b.offset.saturating_add(b.header);
            tops.push(Top::Mdat {
                raw,
                header: b.header,
                old_start,
                len: b.size.saturating_sub(b.header),
            });
        } else if boxes::TOP_LEVEL_COPIED.contains(&b.kind) {
            tops.push(Top::Copy(raw));
        } else {
            findings.extend(report_dropped(
                b,
                "",
                limits.max_depth,
                &mut budget,
                options,
            ));
        }
    }

    if !trailing.is_empty() {
        // Appended past the last box, where nothing reads them — as JPEG after `EOI` (§7.2).
        findings.push(Finding::new(
            MetadataKind::Other,
            "trailing data",
            as_u64(trailing.len()),
        ));
    }

    let moov = moov_node.ok_or_else(|| malformed(format, MalformedDetail::MissingMarker))?;
    require_playable(format, &moov)?;

    // Pass one measures `moov`; pass two writes it for real. The widths never change, so the two
    // must agree — and if they do not, the layout the offsets were computed against is wrong and
    // nothing is written (ADR-0042 decision 3).
    let probe = write_moov(format, &moov, None)?;
    let extents = layout(&tops, as_u64(probe.len()));
    let written = write_moov(format, &moov, Some(&extents))?;
    if written.len() != probe.len() {
        return Err(malformed(format, MalformedDetail::NotRoundTrippable));
    }

    let mut output = Vec::with_capacity(input.len());
    for t in &tops {
        match t {
            Top::Copy(raw) | Top::Mdat { raw, .. } => output.extend_from_slice(raw),
            Top::Moov => output.extend_from_slice(&written),
        }
    }

    Ok(Processed {
        output,
        findings,
        retained: vec![Retained {
            location: "moov/trak/mdia/minf/stbl/stsd (codec configuration)".to_owned(),
            // Parameter sets and codec setup. Removing them leaves samples nothing can decode.
            reason: RetentionReason::StructurallyRequired,
        }],
        notes: vec![Note::OutOfScopeContent {
            location: "coded samples (SEI user data and in-band codec headers are not decoded)"
                .to_owned(),
        }],
    })
}

/// Where each `mdat`'s payload lands once `moov` is `moov_len` bytes long.
fn layout(tops: &[Top<'_>], moov_len: u64) -> Vec<Extent> {
    let mut at = 0u64;
    let mut extents = Vec::new();
    for t in tops {
        match t {
            Top::Copy(raw) => at = at.saturating_add(as_u64(raw.len())),
            Top::Mdat {
                raw,
                header,
                old_start,
                len,
            } => {
                let new_start = at.saturating_add(*header);
                extents.push(Extent {
                    old_start: *old_start,
                    old_end: old_start.saturating_add(*len),
                    new_start,
                });
                at = at.saturating_add(as_u64(raw.len()));
            }
            Top::Moov => at = at.saturating_add(moov_len),
        }
    }
    extents
}

/// Refuse the two shapes this handler will not edit, wherever their marker boxes appear.
fn refuse_structural(kind: BoxType) -> Result<()> {
    if boxes::FRAGMENT_BOXES.contains(&kind) {
        return Err(StryptError::UnsupportedFormat {
            format: UnsupportedKind::FragmentedMp4,
        });
    }
    if boxes::PROTECTION_BOXES.contains(&kind) {
        return Err(StryptError::UnsupportedFormat {
            format: UnsupportedKind::ProtectedMedia,
        });
    }
    Ok(())
}

/// Refuse on what the file declares itself to be.
///
/// Re-checked here rather than trusted from detection: a caller may reach a handler directly, and
/// fail-closed means the refusal does not depend on who dispatched (§5.4).
fn refuse_brands(ftyp: &[u8]) -> Result<()> {
    for brand in ftyp.chunks_exact(4) {
        let Ok(b) = <[u8; 4]>::try_from(brand) else {
            continue;
        };
        // The minor version sits between the major brand and the compatible list and is a number,
        // not a brand. Matching it against these lists is harmless: none of them is a plausible
        // version, and the check that matters is done on the same window detection uses.
        if boxes::FRAGMENT_BRANDS.contains(&b) {
            return Err(StryptError::UnsupportedFormat {
                format: UnsupportedKind::FragmentedMp4,
            });
        }
        if b == boxes::PROTECTED_BRAND {
            return Err(StryptError::UnsupportedFormat {
                format: UnsupportedKind::ProtectedMedia,
            });
        }
        if b == boxes::QUICKTIME_BRAND {
            return Err(StryptError::UnsupportedFormat {
                format: UnsupportedKind::QuickTimeMovie,
            });
        }
        if b.get(..3) == Some(b"3gp") || b.get(..3) == Some(b"3g2") {
            return Err(StryptError::UnsupportedFormat {
                format: UnsupportedKind::ThirdGenerationPartnership,
            });
        }
    }
    Ok(())
}

/// A `moov` with no `mvhd`, or with no surviving track, is not a file anybody can play.
///
/// Refused rather than written: output that opens as an empty container while the report says the
/// strip succeeded is the failure in `docs/THREAT_MODEL.md` §5.4.
fn require_playable(format: Format, moov: &Node<'_>) -> Result<()> {
    let Node::Container { children, .. } = moov else {
        return Err(malformed(format, MalformedDetail::MissingMarker));
    };
    let has = |kind: BoxType| {
        children.iter().any(|c| match c {
            Node::Container { kind: k, .. }
            | Node::Patched { kind: k, .. }
            | Node::Offsets { kind: k, .. } => *k == kind,
            Node::Copy(_) => false,
        })
    };
    if has(*b"mvhd") && has(*b"trak") {
        Ok(())
    } else {
        Err(malformed(format, MalformedDetail::MissingMarker))
    }
}

// ---------------------------------------------------------------------------------------------
// Building the tree
// ---------------------------------------------------------------------------------------------

/// Filter one container's children against the allow-list for its type.
#[allow(clippy::too_many_arguments)]
fn container_node<'a>(
    format: Format,
    input: &'a [u8],
    parent: &Bmff<'a>,
    payload: &'a [u8],
    depth: u32,
    budget: &mut u32,
    findings: &mut Vec<Finding>,
    options: &InspectOptions,
    handler: Option<BoxType>,
) -> Result<Node<'a>> {
    let kids =
        bmff::children_at(parent, payload, depth, budget).map_err(|e| from_walk(format, e))?;
    let mut children = Vec::with_capacity(kids.len());

    // §8.5.1: which sample entry a `stsd` holds is decided by the track's handler type, so it is
    // read at `mdia` and carried down to the `stbl` that needs it.
    let handler = if parent.is(*b"mdia") {
        bmff::find(&kids, *b"hdlr")
            .and_then(Bmff::full)
            .and_then(|(_, _, rest)| rest.get(4..8).and_then(|s| BoxType::try_from(s).ok()))
    } else {
        handler
    };

    for kid in &kids {
        refuse_structural(kid.kind)?;
        if !boxes::kept_in(parent.kind, kid.kind) {
            findings.extend(report_dropped(
                kid,
                location_of(parent.kind),
                depth,
                budget,
                options,
            ));
            continue;
        }
        let raw = bmff::raw(input, kid)
            .ok_or_else(|| malformed(format, MalformedDetail::LengthOutOfRange))?;

        if boxes::is_container(kid.kind) {
            children.push(container_node(
                format,
                input,
                kid,
                kid.payload,
                depth.saturating_sub(1),
                budget,
                findings,
                options,
                handler,
            )?);
            continue;
        }

        if kid.kind == boxes::STCO || kid.kind == boxes::CO64 {
            children.push(offsets_node(format, kid)?);
            continue;
        }
        match &kid.kind {
            b"mvhd" | b"tkhd" | b"mdhd" => {
                children.push(header_node(format, kid, raw, findings, options)?);
            }
            b"hdlr" => children.push(handler_node(kid, raw, findings, options)),
            b"stsd" => {
                children.push(sample_description_node(
                    format,
                    kid,
                    raw,
                    handler,
                    depth.saturating_sub(1),
                    budget,
                    findings,
                    options,
                )?);
            }
            b"dinf" => {
                check_data_reference(format, kid, depth.saturating_sub(1), budget)?;
                children.push(Node::Copy(raw));
            }
            _ => children.push(Node::Copy(raw)),
        }
    }

    Ok(Node::Container {
        kind: parent.kind,
        children,
    })
}

/// The reporting path for a box dropped from inside `parent`.
fn location_of(parent: BoxType) -> &'static str {
    match &parent {
        b"moov" => "moov",
        b"trak" => "moov/trak",
        b"mdia" => "moov/trak/mdia",
        b"minf" => "moov/trak/mdia/minf",
        b"stbl" => "moov/trak/mdia/minf/stbl",
        _ => "",
    }
}

/// Where one of the three patched header boxes sits in the tree, for reporting.
fn path_of(kind: BoxType) -> &'static str {
    match &kind {
        b"mvhd" => "moov/mvhd",
        b"tkhd" => "moov/trak/tkhd",
        _ => "moov/trak/mdia/mdhd",
    }
}

/// `und`, packed as three five-bit letters (§8.4.2). What a track declares when it is not in any
/// particular language.
const LANGUAGE_UNDETERMINED: [u8; 2] = [0x55, 0xC4];

/// Zero the timestamps in `mvhd`, `tkhd` or `mdhd`, and the two fields that ride along with them.
fn header_node<'a>(
    format: Format,
    b: &Bmff<'a>,
    raw: &'a [u8],
    findings: &mut Vec<Finding>,
    options: &InspectOptions,
) -> Result<Node<'a>> {
    let (version, flags, rest) = b
        .full()
        .ok_or_else(|| malformed(format, MalformedDetail::Truncated))?;
    let wide = version == 1;
    let times = if wide { 16usize } else { 8 };
    let Some(head) = rest.get(..times) else {
        // Too short to hold the fields it declares. Copied rather than half-edited; the walker
        // already proved the box tiles, so this is a producer quirk, not an attack surface.
        return Ok(Node::Copy(raw));
    };

    let mut body = Vec::with_capacity(rest.len().saturating_add(4));
    if head.iter().any(|byte| *byte != 0) {
        findings.push(
            Finding::new(MetadataKind::Timestamp, path_of(b.kind), as_u64(times))
                .with_field("creation_time, modification_time"),
        );
    }
    body.push(version);
    let f = flags.to_be_bytes();
    body.extend_from_slice(f.get(1..4).unwrap_or(&[0, 0, 0]));
    body.resize(body.len().saturating_add(times), 0);
    body.extend_from_slice(rest.get(times..).unwrap_or_default());

    // `body` is version+flags followed by `rest`, so a field at `n` within `rest` is at `n + 4`.
    if b.is(*b"mdhd") {
        let at: usize = if wide { 32 } else { 20 };
        if rest.get(at.saturating_sub(4)..at.saturating_sub(2)) != Some(&LANGUAGE_UNDETERMINED)
            && set_bytes(&mut body, at, &LANGUAGE_UNDETERMINED)
        {
            findings.push(
                Finding::new(MetadataKind::Other, "moov/trak/mdia/mdhd", 2).with_field("language"),
            );
        }
    }
    if b.is(*b"mvhd") {
        // §8.2.2 says these 24 bytes are pre-defined and should already be zero. QuickTime writes
        // poster time, preview and selection windows there, and ExifTool reports every one.
        let at: usize = if wide { 84 } else { 72 };
        let already_zero = body
            .get(at..at.saturating_add(24))
            .is_none_or(|s| s.iter().all(|byte| *byte == 0));
        if !already_zero && set_bytes(&mut body, at, &[0u8; 24]) {
            findings.push(
                Finding::new(MetadataKind::Other, "moov/mvhd", 24)
                    .with_field("pre_defined")
                    .with_value(options, || {
                        MetadataValue::Text("poster, preview and selection times".to_owned())
                    }),
            );
        }
    }

    Ok(Node::Patched { kind: b.kind, body })
}

/// Overwrite `len` bytes of `body` at `at`. False when the range does not fit.
fn set_bytes(body: &mut [u8], at: usize, value: &[u8]) -> bool {
    let Some(end) = at.checked_add(value.len()) else {
        return false;
    };
    match body.get_mut(at..end) {
        Some(slot) => {
            slot.copy_from_slice(value);
            true
        }
        None => false,
    }
}

/// How far into a `hdlr` box's payload the free-text name starts (§8.4.3).
const HDLR_NAME_OFFSET: usize = 20;

/// Empty `hdlr`'s trailing name, which is where encoders write their own product name.
fn handler_node<'a>(
    b: &Bmff<'a>,
    raw: &'a [u8],
    findings: &mut Vec<Finding>,
    options: &InspectOptions,
) -> Node<'a> {
    let Some((version, flags, rest)) = b.full() else {
        return Node::Copy(raw);
    };
    let Some(name) = rest.get(HDLR_NAME_OFFSET..) else {
        return Node::Copy(raw);
    };
    // Already empty — an absent name or a bare terminator. Copied so that a clean file comes back
    // byte-identical rather than gaining a byte (ADR-0042).
    if name.is_empty() || name == b"\0" {
        return Node::Copy(raw);
    }

    findings.push(
        Finding::new(
            MetadataKind::SoftwareFingerprint,
            "moov/trak/mdia/hdlr",
            as_u64(name.len()),
        )
        .with_field("name")
        .with_value(options, || MetadataValue::Text(xmp::name_of(name))),
    );

    let mut body = Vec::with_capacity(HDLR_NAME_OFFSET.saturating_add(5));
    body.push(version);
    let f = flags.to_be_bytes();
    body.extend_from_slice(f.get(1..4).unwrap_or(&[0, 0, 0]));
    body.extend_from_slice(rest.get(..HDLR_NAME_OFFSET).unwrap_or_default());
    body.push(0);
    Node::Patched { kind: b.kind, body }
}

/// Read a `stco` or `co64` table. The entries are remapped when the tree is written.
fn offsets_node<'a>(format: Format, b: &Bmff<'_>) -> Result<Node<'a>> {
    let (version, flags, rest) = b
        .full()
        .ok_or_else(|| malformed(format, MalformedDetail::Truncated))?;
    let wide = b.is(boxes::CO64);
    let width = if wide { 8usize } else { 4 };

    let mut r = Reader::new(rest);
    let count = r
        .u32_be()
        .ok_or_else(|| malformed(format, MalformedDetail::Truncated))?;
    let count =
        usize::try_from(count).map_err(|_| malformed(format, MalformedDetail::BrokenIndex))?;
    let declared = count
        .checked_mul(width)
        .ok_or_else(|| malformed(format, MalformedDetail::BrokenIndex))?;
    // Exactly, not at least: a table shorter than it claims would be written back padded, and one
    // longer hides bytes nothing accounted for.
    if r.remaining() != declared {
        return Err(malformed(format, MalformedDetail::BrokenIndex));
    }

    let mut values = Vec::with_capacity(count);
    for _ in 0..count {
        let value = if wide {
            let hi = r
                .u32_be()
                .ok_or_else(|| malformed(format, MalformedDetail::Truncated))?;
            let lo = r
                .u32_be()
                .ok_or_else(|| malformed(format, MalformedDetail::Truncated))?;
            (u64::from(hi) << 32) | u64::from(lo)
        } else {
            u64::from(
                r.u32_be()
                    .ok_or_else(|| malformed(format, MalformedDetail::Truncated))?,
            )
        };
        values.push(value);
    }

    let f = flags.to_be_bytes();
    let head = [
        version,
        f.get(1).copied().unwrap_or(0),
        f.get(2).copied().unwrap_or(0),
        f.get(3).copied().unwrap_or(0),
    ];
    Ok(Node::Offsets {
        kind: b.kind,
        head,
        values,
    })
}

/// Read the sample descriptions: refuse encrypted samples, and clear the encoder name.
///
/// The entry *type* is the encryption signal (§8.5.2 with ISO/IEC 23001-7). strypt does not descend
/// into an entry to look for a `sinf`, because the fixed fields in front of an entry's child boxes
/// differ per media type and it does not parse them — recorded in `docs/THREAT_MODEL.md` §7.17.
///
/// `compressorname` is the one exception, and only for a video track: §12.1.3 puts it at a fixed
/// offset in `VisualSampleEntry`, it is a producer's own string (`Lavc libx264`, a camera's
/// firmware), and nothing decodes it. It is zeroed in place, so the entry keeps its length and
/// every offset behind it.
#[allow(clippy::too_many_arguments)]
fn sample_description_node<'a>(
    format: Format,
    b: &Bmff<'_>,
    raw: &'a [u8],
    handler: Option<BoxType>,
    depth: u32,
    budget: &mut u32,
    findings: &mut Vec<Finding>,
    options: &InspectOptions,
) -> Result<Node<'a>> {
    let (version, flags, rest) = b
        .full()
        .ok_or_else(|| malformed(format, MalformedDetail::Truncated))?;
    let entries = rest.get(4..).unwrap_or_default();
    // A sample description that does not tile is refused rather than skipped: an entry nobody read
    // is an entry nobody ruled encryption out of.
    let kids = bmff::children_at(b, entries, depth, budget).map_err(|e| from_walk(format, e))?;
    for kid in &kids {
        if boxes::PROTECTED_SAMPLE_ENTRIES.contains(&kid.kind) {
            return Err(StryptError::UnsupportedFormat {
                format: UnsupportedKind::ProtectedMedia,
            });
        }
    }

    if handler != Some(*b"vide") {
        return Ok(Node::Copy(raw));
    }

    // Offsets are into `body`, which is version+flags then `rest`, matching how the box is written.
    let mut body = Vec::with_capacity(rest.len().saturating_add(4));
    body.push(version);
    let f = flags.to_be_bytes();
    body.extend_from_slice(f.get(1..4).unwrap_or(&[0, 0, 0]));
    body.extend_from_slice(rest);

    let mut touched = false;
    for kid in &kids {
        // The entry's payload starts `header` bytes into the box; `compressorname` is 32 bytes at
        // offset 42 of the payload, itself a length-prefixed string.
        let Some(at) = kid
            .offset
            .checked_add(kid.header)
            .and_then(|start| start.checked_sub(b.offset.checked_add(b.header)?))
            .and_then(|within| usize::try_from(within).ok())
            .and_then(|within| within.checked_add(COMPRESSOR_NAME_OFFSET))
        else {
            continue;
        };
        let Some(end) = at.checked_add(COMPRESSOR_NAME_LEN) else {
            continue;
        };
        let Some(field) = body.get(at..end) else {
            continue;
        };
        if field.iter().all(|byte| *byte == 0) {
            continue;
        }
        findings.push(
            Finding::new(
                MetadataKind::SoftwareFingerprint,
                "moov/trak/mdia/minf/stbl/stsd",
                as_u64(COMPRESSOR_NAME_LEN),
            )
            .with_field("compressorname")
            .with_value(options, || {
                MetadataValue::Text(compressor_name(field).unwrap_or_default())
            }),
        );
        set_bytes(&mut body, at, &[0u8; COMPRESSOR_NAME_LEN]);
        touched = true;
    }

    if touched {
        Ok(Node::Patched { kind: b.kind, body })
    } else {
        Ok(Node::Copy(raw))
    }
}

/// §12.1.3's `compressorname`: 32 bytes at this offset into a `VisualSampleEntry`'s payload.
const COMPRESSOR_NAME_OFFSET: usize = 42;
const COMPRESSOR_NAME_LEN: usize = 32;

/// The encoder string, read as the length-prefixed name §12.1.3 specifies.
fn compressor_name(field: &[u8]) -> Option<String> {
    let len = usize::from(*field.first()?).min(COMPRESSOR_NAME_LEN.saturating_sub(1));
    Some(xmp::name_of(field.get(1..1usize.checked_add(len)?)?))
}

/// Refuse a track whose media lives in another file.
///
/// §8.7.2: a `dref` entry with the self-contained flag clear names an external URL, so the `mdat`
/// this handler relocates offsets into is not where the samples are.
fn check_data_reference(
    format: Format,
    dinf: &Bmff<'_>,
    depth: u32,
    budget: &mut u32,
) -> Result<()> {
    let kids =
        bmff::children_at(dinf, dinf.payload, depth, budget).map_err(|e| from_walk(format, e))?;
    let Some(dref) = bmff::find(&kids, *b"dref") else {
        return Ok(());
    };
    let Some((_, _, rest)) = dref.full() else {
        return Err(malformed(format, MalformedDetail::Truncated));
    };
    let entries = rest.get(4..).unwrap_or_default();
    let refs = bmff::children_at(dref, entries, depth.saturating_sub(1), budget)
        .map_err(|e| from_walk(format, e))?;
    for entry in &refs {
        let self_contained = entry.full().is_some_and(|(_, flags, _)| flags & 1 != 0);
        if !self_contained {
            return Err(malformed(format, MalformedDetail::UnsupportedFeature));
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------------------------
// Writing
// ---------------------------------------------------------------------------------------------

/// Serialise the `moov` subtree. `extents` absent writes placeholder offsets, to measure only.
fn write_moov(format: Format, moov: &Node<'_>, extents: Option<&[Extent]>) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    write_node(&mut out, moov, extents).map_err(|detail| malformed(format, detail))?;
    Ok(out)
}

fn write_node(
    out: &mut Vec<u8>,
    node: &Node<'_>,
    extents: Option<&[Extent]>,
) -> std::result::Result<(), MalformedDetail> {
    match node {
        Node::Copy(raw) => {
            out.extend_from_slice(raw);
            Ok(())
        }
        Node::Container { kind, children } => bmff::write_box(out, *kind, |o| {
            for child in children {
                write_node(o, child, extents)?;
            }
            Ok(())
        }),
        Node::Patched { kind, body } => bmff::write_box(out, *kind, |o| {
            o.extend_from_slice(body);
            Ok(())
        }),
        Node::Offsets { kind, head, values } => bmff::write_box(out, *kind, |o| {
            o.extend_from_slice(head);
            let count =
                u32::try_from(values.len()).map_err(|_| MalformedDetail::LengthOutOfRange)?;
            o.extend_from_slice(&count.to_be_bytes());
            let wide = kind == &boxes::CO64;
            for value in values {
                let mapped = match extents {
                    // The measuring pass. Widths are fixed, so the placeholder is the same size
                    // as whatever the second pass writes here.
                    None => 0,
                    Some(extents) => {
                        relocate(extents, *value).ok_or(MalformedDetail::BrokenIndex)?
                    }
                };
                if wide {
                    o.extend_from_slice(&mapped.to_be_bytes());
                } else {
                    let narrow =
                        u32::try_from(mapped).map_err(|_| MalformedDetail::LengthOutOfRange)?;
                    o.extend_from_slice(&narrow.to_be_bytes());
                }
            }
            Ok(())
        }),
    }
}

// ---------------------------------------------------------------------------------------------
// Reporting
// ---------------------------------------------------------------------------------------------

/// How many levels of a dropped box are walked to name what was in it.
const REPORT_DESCENT: u32 = 3;

/// Name what one dropped box held.
fn report_dropped(
    b: &Bmff<'_>,
    parent: &str,
    depth: u32,
    budget: &mut u32,
    options: &InspectOptions,
) -> Vec<Finding> {
    let at = if parent.is_empty() {
        xmp::name_of(&b.kind)
    } else {
        format!("{parent}/{}", xmp::name_of(&b.kind))
    };

    if b.is(*b"uuid") {
        if b.payload.get(..16) == Some(&boxes::XMP_UUID)
            && let Some(packet) = b.payload.get(16..)
        {
            let scanned = xmp::scan(packet, &format!("{at} (XMP)"), options);
            if !scanned.is_empty() {
                return scanned;
            }
        }
        return vec![Finding::new(MetadataKind::Other, at, b.size)];
    }
    if matches!(&b.kind, b"free" | b"skip" | b"wide") {
        return vec![Finding::new(MetadataKind::Other, "free space", b.size).with_field(at)];
    }

    // `udta` and `meta` are where the tags live, so they are walked rather than named whole: a
    // report that said "1.2 kB of udta" would not tell a user their video carries their address.
    if matches!(&b.kind, b"udta" | b"meta" | b"ilst" | b"keys") {
        let body = if b.is(*b"meta") {
            b.full().map_or(b.payload, |(_, _, rest)| rest)
        } else {
            b.payload
        };
        if depth > 0
            && let Ok(kids) = bmff::children_at(b, body, REPORT_DESCENT.min(depth), budget)
            && !kids.is_empty()
        {
            let mut out = Vec::new();
            for kid in &kids {
                out.extend(report_dropped(
                    kid,
                    &at,
                    depth.saturating_sub(1),
                    budget,
                    options,
                ));
            }
            return out;
        }
    }

    let kind = tag_kind(b.kind);
    let mut finding = Finding::new(kind, at, b.size).with_field(xmp::name_of(&b.kind));
    if let Some(text) = tag_text(b.payload) {
        finding = finding.with_value(options, || MetadataValue::Text(text));
    }
    vec![finding]
}

/// What one metadata atom is, by its four-character name.
///
/// The names are Apple's `udta` vocabulary and the iTunes `ilst` keys built on it. `©xyz` is the
/// one that matters most: it is an ISO-6709 coordinate, and every iPhone and most Android phones
/// write it into every video they record.
fn tag_kind(name: BoxType) -> MetadataKind {
    match &name {
        b"\xA9xyz" | b"loci" | b"gps " | b"\xA9gps" => MetadataKind::Location,
        b"\xA9day" | b"date" | b"\xA9dtm" => MetadataKind::Timestamp,
        b"\xA9too" | b"\xA9swr" | b"\xA9enc" | b"\xA9req" => MetadataKind::SoftwareFingerprint,
        b"\xA9mak" | b"\xA9mod" | b"mak " | b"mod " | b"\xA9xmk" | b"\xA9xmd" => {
            MetadataKind::DeviceIdentity
        }
        b"\xA9ART" | b"aART" | b"\xA9wrt" | b"\xA9alb" | b"\xA9cpy" | b"cprt" | b"auth"
        | b"perf" | b"\xA9prf" | b"\xA9ope" => MetadataKind::PersonalIdentity,
        b"covr" | b"\xA9art" => MetadataKind::Thumbnail,
        b"\xA9cmt" | b"desc" | b"ldes" | b"\xA9des" | b"\xA9lyr" => MetadataKind::Comment,
        _ => MetadataKind::Other,
    }
}

/// A tag's text, where the payload is one of the two shapes these atoms use.
///
/// `udta` atoms carry a two-byte length and a two-byte language before the text; an `ilst` value
/// sits in a `data` box behind four bytes of type and four of locale. Anything else returns
/// [`None`] rather than being guessed at — a report field is not worth a wrong answer.
fn tag_text(payload: &[u8]) -> Option<String> {
    let text = payload.get(8..).filter(|_| payload.len() > 8)?;
    let printable = text.iter().all(|b| *b >= 0x20 || *b == b'\n');
    if printable && std::str::from_utf8(text).is_ok() {
        return Some(xmp::name_of(text));
    }
    let short = payload.get(4..)?;
    if short.iter().all(|b| *b >= 0x20) && std::str::from_utf8(short).is_ok() {
        return Some(xmp::name_of(short));
    }
    None
}

// ---------------------------------------------------------------------------------------------

fn from_walk(format: Format, e: WalkError) -> StryptError {
    match e {
        WalkError::Malformed(detail) => malformed(format, detail),
        WalkError::Limit(limit) => StryptError::LimitExceeded { format, limit },
    }
}

fn malformed(format: Format, detail: MalformedDetail) -> StryptError {
    StryptError::Malformed {
        format,
        offset: None,
        detail,
    }
}

fn as_u64(value: usize) -> u64 {
    u64::try_from(value).unwrap_or(u64::MAX)
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

    #[test]
    fn an_offset_outside_every_mdat_does_not_resolve() {
        // The whole safety argument (ADR-0042 decision 2): an offset into a box that was dropped
        // must refuse the file rather than be nudged by a delta nobody verified.
        let extents = [Extent {
            old_start: 100,
            old_end: 200,
            new_start: 40,
        }];
        assert_eq!(relocate(&extents, 100), Some(40));
        assert_eq!(relocate(&extents, 199), Some(139));
        assert_eq!(relocate(&extents, 200), None);
        assert_eq!(relocate(&extents, 99), None);
    }

    #[test]
    fn several_mdats_each_translate_by_their_own_delta() {
        let extents = [
            Extent {
                old_start: 100,
                old_end: 200,
                new_start: 90,
            },
            Extent {
                old_start: 300,
                old_end: 400,
                new_start: 250,
            },
        ];
        assert_eq!(relocate(&extents, 150), Some(140));
        assert_eq!(relocate(&extents, 350), Some(300));
        assert_eq!(relocate(&extents, 250), None);
    }

    #[test]
    fn the_gps_atom_is_named_as_a_location() {
        assert_eq!(tag_kind(*b"\xA9xyz"), MetadataKind::Location);
        assert_eq!(tag_kind(*b"\xA9too"), MetadataKind::SoftwareFingerprint);
        assert_eq!(tag_kind(*b"XPRV"), MetadataKind::Other);
    }
}
