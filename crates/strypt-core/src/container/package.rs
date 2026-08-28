//! What Office Open XML and `OpenDocument` do the same way.
//!
//! Both are ZIP archives of parts, both carry photographs the author pasted in, both record a
//! modification time per entry, and both can contain something strypt must refuse to descend
//! into. Those four things are here rather than in either handler, for one reason above the
//! others: **the one-level, images-only descent of ADR-0029 must exist exactly once.** A second
//! copy of it in the `OpenDocument` handler would be a second place for the depth to grow, and the
//! ADR fixes the depth in the type system precisely so that it cannot.
//!
//! What is *not* here is anything about where a format keeps its metadata. `docProps/core.xml`
//! and `meta.xml` are not two spellings of one idea — see ADR-0031 — and pretending otherwise
//! in a shared layer would push both handlers toward whichever format was implemented first.

use crate::detect::Format;
use crate::error::{Result, StryptError};
use crate::formats::{ParseLimits, StripOptions};
use crate::report::{Finding, InspectOptions, MetadataKind, Note};

use super::zip::{self, Entry};

/// The magic number of an OLE2 compound file (`vbaProject.bin`, `oleObject1.bin`, and the
/// `Object N` of an OLE object embedded in an `OpenDocument` package).
///
/// Its own container format, with its own directory and its own metadata streams. strypt cannot
/// read it, so a document containing one is refused rather than reported clean (ADR-0029).
const OLE_MAGIC: [u8; 8] = [0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1];

/// One archive entry, decompressed once and kept for the passes that follow.
pub(crate) struct Part<'a> {
    pub(crate) entry: Entry<'a>,
    /// The decompressed contents. Absent for directory markers, which have none.
    pub(crate) data: Option<Vec<u8>>,
}

impl Part<'_> {
    /// The part's path within the package, when it is valid UTF-8.
    pub(crate) fn name(&self) -> Option<&str> {
        self.entry.name_str()
    }

    /// The contents as text, when they are valid UTF-8.
    ///
    /// A part that is not UTF-8 is not XML a handler will edit. It is copied through, and the
    /// [`Note::UnparsedRegion`] that goes with it says so — silently passing bytes nobody looked
    /// at is the thing to avoid, not the passing itself.
    pub(crate) fn text(&self) -> Option<&str> {
        std::str::from_utf8(self.data.as_deref()?).ok()
    }
}

/// Read every entry of the package, decompressing each against a budget shared across the whole
/// archive.
///
/// Shared rather than per-entry, so that a hundred entries each individually within the ceiling
/// cannot collectively exceed it — which is the shape of every archive bomb that gets past a
/// naive limit.
pub(crate) fn read_parts<'a>(
    input: &'a [u8],
    format: Format,
    limits: &ParseLimits,
) -> Result<Vec<Part<'a>>> {
    let entries = zip::read(input, limits).map_err(|e| e.into_strypt(format))?;
    let mut budget = limits.max_expanded_bytes;
    let mut parts = Vec::with_capacity(entries.len());
    for entry in entries {
        let data = if entry.is_directory() {
            None
        } else {
            let contents = entry.contents(budget).map_err(|e| e.into_strypt(format))?;
            let owned = contents.into_owned();
            zip::spend(&mut budget, as_u64(owned.len())).map_err(|e| e.into_strypt(format))?;
            Some(owned)
        };
        parts.push(Part { entry, data });
    }
    Ok(parts)
}

/// Refuse a package containing something strypt would have to descend into a second time.
///
/// ADR-0029 fixes the descent at one level and at images only. A nested archive, an embedded
/// PDF, and an OLE compound file each carry their own metadata that a single pass cannot reach,
/// so the document is refused rather than reported clean — the user learns the file is there
/// instead of publishing over it.
pub(crate) fn refuse_nested_containers(
    parts: &[Part<'_>],
    format: Format,
    notes: &mut Vec<Note>,
) -> Result<()> {
    for part in parts {
        let Some(data) = part.data.as_deref() else {
            continue;
        };
        let name = part.name().unwrap_or("<non-utf8 entry name>");
        let nested = if data.starts_with(&OLE_MAGIC) {
            Some("an OLE compound file")
        } else if data.starts_with(b"PK\x03\x04") {
            Some("a nested archive")
        } else if matches!(crate::detect::detect(data), Ok(Format::Pdf)) {
            // Reaching `lopdf` through a decompressed, attacker-chosen archive entry composes
            // this project's weakest parser with its newest one. Not in this phase (ADR-0029).
            Some("an embedded PDF")
        } else {
            None
        };
        if let Some(what) = nested {
            notes.push(Note::OutOfScopeContent {
                location: format!("{name} ({what})"),
            });
            return Err(StryptError::Malformed {
                format,
                offset: None,
                detail: crate::error::MalformedDetail::UnsupportedFeature,
            });
        }
    }
    Ok(())
}

/// What to do with one part.
pub(crate) enum Action {
    /// Copy it through with its compressed bytes untouched.
    Copy,
    /// Remove it from the package entirely.
    Drop,
    /// Replace its contents, which the writer will store uncompressed (ADR-0028).
    Rewrite(Vec<u8>),
}

/// A decision about one part, with what to tell the user about it.
pub(crate) struct Decision {
    pub(crate) action: Action,
    pub(crate) findings: Vec<Finding>,
    pub(crate) notes: Vec<Note>,
}

impl Decision {
    /// Copy the part through, with nothing to report.
    pub(crate) const fn copy() -> Self {
        Self {
            action: Action::Copy,
            findings: Vec::new(),
            notes: Vec::new(),
        }
    }

    /// Copy the part through, saying plainly that nobody looked inside it.
    ///
    /// A font, an audio clip, a binary blob: not text, and not an image strypt handles. Copying
    /// it is the right call — an unrecognised part may be load-bearing, and dropping it would
    /// break the document — but a user deciding whether to publish should know what strypt did
    /// not examine.
    pub(crate) fn unexamined(location: impl Into<String>, bytes: usize) -> Self {
        Self {
            action: Action::Copy,
            findings: Vec::new(),
            notes: vec![Note::UnparsedRegion {
                location: location.into(),
                bytes: as_u64(bytes),
            }],
        }
    }
}

/// What came of handing an embedded picture to its own format handler.
pub(crate) enum Embedded {
    /// The picture had nothing in it. Copying rather than rewriting keeps an already-clean
    /// document's entries byte-identical to their originals.
    Unchanged,
    /// The picture was stripped, and these are its bytes and its report.
    Stripped {
        bytes: Vec<u8>,
        findings: Vec<Finding>,
        notes: Vec<Note>,
    },
}

/// Strip an embedded image through its own format handler.
///
/// The picture goes through the *same* handler the CLI uses on a loose file, so it inherits
/// Phase 1's verification pass, its byte-identical idempotence, and its recorded limitations.
/// A second, weaker implementation of JPEG stripping for the embedded case is exactly the
/// divergence ADR-0003 exists to prevent.
///
/// The image handlers do not open containers, and this function does not call itself, so a
/// second level of descent is unreachable by construction rather than by a counter somebody
/// could raise later.
pub(crate) fn strip_embedded_image(
    format: Format,
    data: &[u8],
    name: &str,
    options: &InspectOptions,
    limits: &ParseLimits,
) -> Result<Embedded> {
    let Some(handler) = crate::registry::handler_for(format) else {
        return Err(StryptError::UnsupportedFormat {
            format: crate::error::UnsupportedKind::NotYetImplemented(format),
        });
    };
    let stripped = handler.strip(
        data,
        &StripOptions {
            inspect: options.clone(),
            limits: *limits,
        },
    )?;

    if stripped.report.removed.is_empty() {
        return Ok(Embedded::Unchanged);
    }
    let findings = stripped
        .report
        .removed
        .into_iter()
        .map(|mut finding| {
            // Attribute the leak to the picture rather than to the document as a whole, so a
            // report reads `word/media/image2.jpeg → APP1 (Exif)`.
            finding.location = format!("{name} → {}", finding.location);
            finding
        })
        .collect();
    Ok(Embedded::Stripped {
        bytes: stripped.bytes,
        findings,
        notes: stripped.report.notes,
    })
}

/// The image formats an embedded picture may be descended into (ADR-0029).
///
/// **Every raster image format the registry has a handler for**, which as of ADR-0035 is more than
/// the three that happened to exist when this was written: ADR-0029's rule was always "one level,
/// images only" and never "one level, three formats", so a TIFF or a HEIC pasted into a document
/// now has its own metadata removed instead of being copied through unexamined.
///
/// **SVG is deliberately absent**, and its absence is what keeps the descent one level deep by
/// construction rather than by a counter. An SVG may itself carry a `data:` URI, so descending
/// into one would be a recursion with no fixed bottom; a caller that finds one treats it as a
/// nested container and refuses, which is this module's existing answer to that shape.
pub(crate) fn embedded_image_format(data: &[u8]) -> Option<Format> {
    match crate::detect::detect(data) {
        Ok(
            format @ (Format::Jpeg
            | Format::Png
            | Format::Webp
            | Format::Gif
            | Format::Tiff
            | Format::Heif
            | Format::Avif),
        ) => Some(format),
        _ => None,
    }
}

/// Findings that belong to the archive itself rather than to any one part.
pub(crate) fn container_findings(parts: &[Part<'_>]) -> Vec<Finding> {
    let mut findings = Vec::new();

    let timestamped = parts
        .iter()
        .filter(|p| p.entry.modified != zip::NORMALISED_DOS_DATETIME)
        .count();
    if timestamped > 0 {
        // Every entry header records when that part was last written. Across a document's parts
        // that is a record of an editing session's clock times, which is not visible in any
        // application.
        findings.push(Finding::new(
            MetadataKind::Timestamp,
            "ZIP entry headers",
            as_u64(timestamped),
        ));
    }

    let host_fields = parts
        .iter()
        .filter(|p| zip::extra_names_the_host(p.entry.extra))
        .count();
    if host_fields > 0 {
        findings.push(Finding::new(
            MetadataKind::DeviceIdentity,
            "ZIP entry extra fields",
            as_u64(host_fields),
        ));
    }

    findings
}

/// Widen a length for a report field.
///
/// Saturating rather than fallible: this is only ever a count in a report, and no length that
/// fits in memory comes close to `u64::MAX`.
pub(crate) fn as_u64(n: usize) -> u64 {
    u64::try_from(n).unwrap_or(u64::MAX)
}
