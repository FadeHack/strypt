//! Office Open XML — `.docx`, `.xlsx`, `.pptx`.
//!
//! Structurally unlike anything in Phase 1. A JPEG or a PNG is one file with metadata segments
//! in it; an OOXML document is a ZIP archive of XML parts, described by `[Content_Types].xml`
//! and wired together by relationship parts under `_rels/`. Its metadata is spread across at
//! least five places, and one of them — the pictures the author pasted in — is a set of
//! complete image files carrying whatever their cameras wrote.
//!
//! The ZIP layer lives in [`crate::container::zip`] and is written rather than imported
//! (ADR-0028). The descent into embedded images is bounded at exactly one level and to images
//! only (ADR-0029). What this handler removes, keeps, and merely reports is ADR-0030.
//!
//! # Where the metadata is
//!
//! - `docProps/core.xml` — Dublin Core: `dc:creator`, `cp:lastModifiedBy`, `dcterms:created`,
//!   `dcterms:modified`, `cp:revision`.
//! - `docProps/app.xml` — the producing application and version, `Company`, `Manager`, and
//!   `TotalTime`, which is cumulative editing minutes and therefore a record of how long
//!   somebody worked on a document and, across saves, when.
//! - `docProps/custom.xml` — arbitrary named properties. Document management systems write
//!   internal matter numbers and usernames here.
//! - `docProps/thumbnail.*` — a rendered preview of the first page. It survives every kind of
//!   redaction applied to the text, in the same way an Exif thumbnail survives cropping.
//! - Revision-save identifiers, spread through the document body: `w:rsid*` attributes and the
//!   `w:rsids` table in `settings.xml`. Each one marks an editing session, and two documents
//!   sharing an rsid were edited in the same session on the same machine.
//! - `w14:paraId` and `w14:textId`, which are per-paragraph identifiers stable across saves and
//!   across copies of a document.
//! - Author names and timestamps on tracked changes and comments, sitting inline in the body.
//!
//! # Removing a part is not enough
//!
//! `[Content_Types].xml` still declares a removed part's type and `_rels/.rels` still points at
//! it, and a document referencing parts that are not there is invalid. Word offers to repair
//! it, which for a user trying not to draw attention to a document is a worse outcome than a
//! slightly larger file. So both are rewritten, by deleting the byte ranges of the entries that
//! referred to what went — never by re-serialising, which would change bytes that had no reason
//! to change.
//!
//! # What is reported rather than removed
//!
//! The *content* of comments and tracked changes stays. Removing a tracked insertion means
//! deciding whether the document accepts or rejects it, and that changes the document's words —
//! `docs/PRD.md` §8.1 says the payload wins, and a document's visible text is its payload in
//! the most direct sense there is. A tool that silently accepted every pending revision would
//! hand a journalist a document that says something different from the one they reviewed.
//!
//! Their **author names, initials, and timestamps** are a different matter: those are metadata
//! sitting on content, and removing them changes no words at all. They go.
//!
//! This is a recorded limitation, and for a document whose comments themselves must not be
//! published, mat2 is the better recommendation — ADR-0012 requires saying so where it is true.

use std::collections::{BTreeMap, BTreeSet};

use crate::container::zip::{self, Entry, Method, Output};
use crate::detect::Format;
use crate::error::{MalformedDetail, Result, StryptError};
use crate::formats::{MetadataHandler, ParseLimits, StripOptions, Stripped};
use crate::report::{
    Finding, InspectOptions, MetadataKind, MetadataReport, MetadataValue, Note, StripReport,
};

mod xml;

/// The part that describes every other part's type. Required in every OOXML package.
const CONTENT_TYPES: &str = "[Content_Types].xml";
/// The package-level relationship part, which is where the properties parts are referenced from.
const ROOT_RELS: &str = "_rels/.rels";

/// Content types whose parts are metadata in their entirety and are removed whole.
///
/// Matched on the **content type, not the path**: the `docProps/` convention is what producers
/// happen to do, and the content type is what the format actually guarantees. A producer that
/// puts its core properties at `custom/props.xml` is unusual, not exempt.
const PROPERTY_CONTENT_TYPES: [(&str, MetadataKind); 3] = [
    (
        "application/vnd.openxmlformats-package.core-properties+xml",
        MetadataKind::PersonalIdentity,
    ),
    (
        "application/vnd.openxmlformats-officedocument.extended-properties+xml",
        MetadataKind::SoftwareFingerprint,
    ),
    (
        "application/vnd.openxmlformats-officedocument.custom-properties+xml",
        MetadataKind::PersonalIdentity,
    ),
];

/// The relationship type of the package thumbnail (ECMA-376 Part 2, §10.1.4).
///
/// The thumbnail has no content-type override of its own — it is covered by the `Default` for
/// its extension — so it is found through the relationship instead.
const THUMBNAIL_RELATIONSHIP: &str =
    "http://schemas.openxmlformats.org/package/2006/relationships/metadata/thumbnail";

/// The main-document content type for each format this handler serves.
///
/// The macro-enabled variants are deliberately absent: they are refused at detection, because a
/// `vbaProject.bin` is an OLE compound file that strypt cannot read, and reporting a document
/// clean while a container inside it went unexamined is the failure this project exists to
/// avoid.
const MAIN_PART_TYPES: [(&str, Format); 3] = [
    (
        "application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml",
        Format::Docx,
    ),
    (
        "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml",
        Format::Xlsx,
    ),
    (
        "application/vnd.openxmlformats-officedocument.presentationml.presentation.main+xml",
        Format::Pptx,
    ),
];

/// The magic number of an OLE2 compound file (`vbaProject.bin`, `oleObject1.bin`).
///
/// Its own container format, with its own directory and its own metadata streams. strypt cannot
/// read it, so a document containing one is refused rather than reported clean (ADR-0029).
const OLE_MAGIC: [u8; 8] = [0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1];

/// Removal of metadata from Office Open XML documents.
///
/// One handler type serving three formats, instantiated once per format rather than branching
/// internally, so that [`MetadataHandler::format`] keeps returning the format the registry
/// dispatched on.
#[derive(Debug, Clone, Copy)]
pub struct OoxmlHandler {
    format: Format,
}

impl OoxmlHandler {
    /// The handler for `WordprocessingML` documents.
    pub const DOCX: Self = Self {
        format: Format::Docx,
    };
    /// The handler for `SpreadsheetML` workbooks.
    pub const XLSX: Self = Self {
        format: Format::Xlsx,
    };
    /// The handler for `PresentationML` presentations.
    pub const PPTX: Self = Self {
        format: Format::Pptx,
    };
}

impl MetadataHandler for OoxmlHandler {
    fn name(&self) -> &'static str {
        self.format.id()
    }

    fn format(&self) -> Format {
        self.format
    }

    fn inspect(&self, input: &[u8], options: &InspectOptions) -> Result<MetadataReport> {
        // The same pass stripping uses, with the output discarded — so "everything `strip`
        // removes is something `inspect` can see" holds by construction rather than by two code
        // paths agreeing to stay in step. The pipeline's verification pass depends on it, and
        // for this format it depends on it twice over: a document with a photograph in it would
        // fail verification if the descent happened only on the strip side (ADR-0029).
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
                retained: Vec::new(),
                notes: processed.notes,
                input_bytes: as_u64(input.len()),
                output_bytes: as_u64(processed.output.len()),
            },
            bytes: processed.output,
        })
    }
}

/// The result of one pass over a document.
struct Processed {
    findings: Vec<Finding>,
    notes: Vec<Note>,
    output: Vec<u8>,
}

/// An entry, decompressed once and kept for the passes that follow.
struct Part<'a> {
    entry: Entry<'a>,
    /// The decompressed contents. Absent for directory markers, which have none.
    data: Option<Vec<u8>>,
}

impl Part<'_> {
    /// The part's path within the package, when it is valid UTF-8.
    fn name(&self) -> Option<&str> {
        self.entry.name_str()
    }

    /// The contents as text, when they are valid UTF-8.
    ///
    /// A part that is not UTF-8 is not XML this handler will edit. It is copied through, and
    /// the [`Note::UnparsedRegion`] that goes with it says so — silently passing bytes nobody
    /// looked at is the thing to avoid, not the passing itself.
    fn text(&self) -> Option<&str> {
        std::str::from_utf8(self.data.as_deref()?).ok()
    }
}

/// Walk the package once and produce both the report and the sanitised archive.
fn process(
    input: &[u8],
    format: Format,
    options: &InspectOptions,
    limits: &ParseLimits,
) -> Result<Processed> {
    let entries = zip::read(input, limits).map_err(|e| e.into_strypt(format))?;
    let parts = decompress_all(entries, format, limits)?;

    let types = ContentTypes::parse(&parts, format)?;
    types.confirm_format(format)?;

    let mut findings = Vec::new();
    let mut notes = Vec::new();

    let rels = Relationships::parse(&parts);
    let dropped = parts_to_drop(&parts, &types, &rels);
    let dead_rels = dead_relationships(&parts);

    refuse_nested_containers(&parts, format, &mut notes)?;

    let mut outputs: Vec<Output<'_>> = Vec::with_capacity(parts.len());
    for part in &parts {
        let decision = decide(part, &types, &dropped, &dead_rels, options, limits)?;
        findings.extend(decision.findings);
        notes.extend(decision.notes);
        match decision.action {
            Action::Copy => outputs.push(Output::Copied(part.entry.clone())),
            Action::Drop => {}
            Action::Rewrite(data) => outputs.push(Output::Rewritten {
                name: part.entry.name.to_vec(),
                data,
                flags: part.entry.flags,
            }),
        }
    }

    findings.extend(container_findings(&parts));

    let output = zip::write(&outputs).map_err(|e| e.into_strypt(format))?;
    Ok(Processed {
        findings,
        notes,
        output,
    })
}

/// Decompress every entry once, against a budget shared across the whole archive.
///
/// Shared rather than per-entry, so that a hundred entries each individually within the ceiling
/// cannot collectively exceed it — which is the shape of every archive bomb that gets past a
/// naive limit.
fn decompress_all<'a>(
    entries: Vec<Entry<'a>>,
    format: Format,
    limits: &ParseLimits,
) -> Result<Vec<Part<'a>>> {
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

/// `[Content_Types].xml`, parsed into the two lookups the rest of this module needs.
struct ContentTypes {
    /// Part path (without its leading slash) to content type, from `Override` elements.
    overrides: Vec<(String, String)>,
    /// Lowercase extension to content type, from `Default` elements.
    defaults: Vec<(String, String)>,
}

impl ContentTypes {
    fn parse(parts: &[Part<'_>], format: Format) -> Result<Self> {
        let part = parts
            .iter()
            .find(|p| p.name() == Some(CONTENT_TYPES))
            .ok_or_else(|| malformed(format, MalformedDetail::MissingMarker))?;
        let text = part
            .text()
            .ok_or_else(|| malformed(format, MalformedDetail::BrokenIndex))?;

        let mut overrides = Vec::new();
        let mut defaults = Vec::new();
        for tag in xml::tags(text) {
            match tag.name {
                "Override" => {
                    if let (Some(name), Some(kind)) =
                        (tag.attribute("PartName"), tag.attribute("ContentType"))
                    {
                        overrides.push((normalise_part_name(name), kind.to_owned()));
                    }
                }
                "Default" => {
                    if let (Some(ext), Some(kind)) =
                        (tag.attribute("Extension"), tag.attribute("ContentType"))
                    {
                        defaults.push((ext.to_ascii_lowercase(), kind.to_owned()));
                    }
                }
                _ => {}
            }
        }
        Ok(Self {
            overrides,
            defaults,
        })
    }

    /// The content type declared for `part`, by override first and by extension second.
    fn type_of(&self, part: &str) -> Option<&str> {
        if let Some((_, kind)) = self.overrides.iter().find(|(name, _)| name == part) {
            return Some(kind);
        }
        let ext = part.rsplit_once('.')?.1.to_ascii_lowercase();
        self.defaults
            .iter()
            .find(|(candidate, _)| *candidate == ext)
            .map(|(_, kind)| kind.as_str())
    }

    /// Refuse a package whose main part is not the one this handler was dispatched for.
    ///
    /// Detection decides the format by reading this same declaration, so a mismatch here means
    /// the package changed underneath us or the two disagree — either way, guessing is how a
    /// handler ends up confidently reporting on a file it does not understand.
    fn confirm_format(&self, format: Format) -> Result<()> {
        let declared = self.overrides.iter().find_map(|(_, kind)| {
            MAIN_PART_TYPES
                .iter()
                .find(|(candidate, _)| candidate == kind)
                .map(|(_, f)| *f)
        });
        if declared == Some(format) {
            Ok(())
        } else {
            Err(malformed(format, MalformedDetail::MissingMarker))
        }
    }
}

/// The package-level relationships, which is where the thumbnail is named.
#[derive(Default)]
struct Relationships {
    /// Targets of relationships whose type marks them as metadata rather than content.
    metadata_targets: Vec<String>,
    /// Relationships pointing outside the package, which frequently carry a local filesystem
    /// path — an attached template on a user's desktop names that user.
    external_targets: Vec<String>,
}

impl Relationships {
    fn parse(parts: &[Part<'_>]) -> Self {
        let Some(text) = parts
            .iter()
            .find(|p| p.name() == Some(ROOT_RELS))
            .and_then(Part::text)
        else {
            return Self::default();
        };
        let mut rels = Self::default();
        for tag in xml::tags(text) {
            if tag.name != "Relationship" {
                continue;
            }
            let Some(target) = tag.attribute("Target") else {
                continue;
            };
            if tag.attribute("Type") == Some(THUMBNAIL_RELATIONSHIP) {
                rels.metadata_targets.push(normalise_part_name(target));
            }
            if tag.attribute("TargetMode") == Some("External") {
                rels.external_targets.push(target.to_owned());
            }
        }
        rels
    }
}

/// Every part path this pass will remove.
fn parts_to_drop(
    parts: &[Part<'_>],
    types: &ContentTypes,
    rels: &Relationships,
) -> BTreeSet<String> {
    let mut dropped: BTreeSet<String> = rels.metadata_targets.iter().cloned().collect();
    for part in parts {
        let Some(name) = part.name() else { continue };
        let Some(kind) = types.type_of(name) else {
            continue;
        };
        if PROPERTY_CONTENT_TYPES
            .iter()
            .any(|(candidate, _)| *candidate == kind)
        {
            dropped.insert(name.to_owned());
        }
    }
    dropped
}

/// Refuse a package containing something strypt would have to descend into a second time.
///
/// ADR-0029 fixes the descent at one level and at images only. A nested archive, an embedded
/// PDF, and an OLE compound file each carry their own metadata that this pass cannot reach, so
/// the document is refused rather than reported clean — the user learns the file is there
/// instead of publishing over it.
fn refuse_nested_containers(
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
            // this project's weakest parser with its newest one. Not in the change that
            // introduces the ZIP layer (ADR-0029).
            Some("an embedded PDF")
        } else {
            None
        };
        if let Some(what) = nested {
            notes.push(Note::OutOfScopeContent {
                location: format!("{name} ({what})"),
            });
            return Err(malformed(format, MalformedDetail::UnsupportedFeature));
        }
    }
    Ok(())
}

/// What to do with one part.
enum Action {
    /// Copy it through with its compressed bytes untouched.
    Copy,
    /// Remove it from the package entirely.
    Drop,
    /// Replace its contents, which the writer will store uncompressed (ADR-0028).
    Rewrite(Vec<u8>),
}

/// A decision about one part, with what to tell the user about it.
struct Decision {
    action: Action,
    findings: Vec<Finding>,
    notes: Vec<Note>,
}

impl Decision {
    const fn copy() -> Self {
        Self {
            action: Action::Copy,
            findings: Vec::new(),
            notes: Vec::new(),
        }
    }
}

/// Decide about one part.
fn decide(
    part: &Part<'_>,
    types: &ContentTypes,
    dropped: &BTreeSet<String>,
    dead_rels: &DeadRelationships,
    options: &InspectOptions,
    limits: &ParseLimits,
) -> Result<Decision> {
    let Some(name) = part.name() else {
        // A part whose name is not UTF-8 cannot be one this handler knows, and cannot be
        // referenced by any relationship, whose targets are text. Copied, and declared.
        return Ok(Decision {
            action: Action::Copy,
            findings: Vec::new(),
            notes: vec![Note::UnparsedRegion {
                location: "an entry whose name is not valid UTF-8".to_owned(),
                bytes: as_u64(part.entry.compressed.len()),
            }],
        });
    };
    if part.entry.is_directory() {
        return Ok(Decision::copy());
    }
    // The two index parts, which have to stop referring to whatever went. They are handled
    // here rather than in a pass of their own so that they keep their position in the archive —
    // and, more to the point, so that they are written exactly once. Writing them in a second
    // pass produced a package containing two `[Content_Types].xml` entries, which readers
    // tolerate and which quietly broke byte-identical idempotence.
    if name == CONTENT_TYPES || name == ROOT_RELS {
        let Some(text) = part.text() else {
            return Ok(Decision::copy());
        };
        let dereferenced = xml::drop_references(text, dropped);
        let base = dereferenced.as_deref().unwrap_or(text);
        let scrubbed = xml::scrub(base, name, dead_rels.for_part(name), options);
        let action = match scrubbed.output.or(dereferenced) {
            Some(rewritten) => Action::Rewrite(rewritten.into_bytes()),
            None => Action::Copy,
        };
        return Ok(Decision {
            action,
            findings: scrubbed.findings,
            notes: scrubbed.notes,
        });
    }

    if dropped.contains(name) {
        return Ok(Decision {
            action: Action::Drop,
            findings: property_findings(part, name, types, options),
            notes: Vec::new(),
        });
    }

    let Some(data) = part.data.as_deref() else {
        return Ok(Decision::copy());
    };

    // An embedded image goes through the *same* handler the CLI uses on a loose file, so it
    // inherits Phase 1's verification, idempotence, and recorded limitations. A second, weaker
    // implementation of JPEG stripping for the embedded case is exactly the divergence ADR-0003
    // exists to prevent.
    if let Ok(embedded) = crate::detect::detect(data)
        && matches!(embedded, Format::Jpeg | Format::Png | Format::Webp)
    {
        return strip_embedded_image(embedded, data, name, options, limits);
    }

    match part.text() {
        Some(text) => Ok(scrub_part(text, name, dead_rels.for_part(name), options)),
        // Not text, not an image strypt handles: a font, an audio clip, a binary blob. Copied
        // through, and the note says which one, because a user deciding whether to publish
        // should know what strypt did not look inside.
        None => Ok(Decision {
            action: Action::Copy,
            findings: Vec::new(),
            notes: vec![Note::UnparsedRegion {
                location: name.to_owned(),
                bytes: as_u64(data.len()),
            }],
        }),
    }
}

/// Strip an embedded image through its own format handler.
fn strip_embedded_image(
    format: Format,
    data: &[u8],
    name: &str,
    options: &InspectOptions,
    limits: &ParseLimits,
) -> Result<Decision> {
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

    // A picture that had nothing in it is copied rather than rewritten, which keeps an
    // already-clean document's entries byte-identical to their originals.
    if stripped.report.removed.is_empty() {
        return Ok(Decision::copy());
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
    Ok(Decision {
        action: Action::Rewrite(stripped.bytes),
        findings,
        notes: stripped.report.notes,
    })
}

/// Report what a properties part held, before it is dropped.
///
/// The part goes whole either way. Naming its fields is what makes `strypt show` useful — "this
/// document names an author and records 340 minutes of editing" is actionable, where "a
/// properties part was removed" is not.
fn property_findings(
    part: &Part<'_>,
    name: &str,
    types: &ContentTypes,
    options: &InspectOptions,
) -> Vec<Finding> {
    let kind = types
        .type_of(name)
        .and_then(|declared| {
            PROPERTY_CONTENT_TYPES
                .iter()
                .find(|(candidate, _)| *candidate == declared)
                .map(|(_, kind)| *kind)
        })
        .unwrap_or(MetadataKind::Other);

    let Some(text) = part.text() else {
        // The thumbnail, which is an image rather than XML, and anything else non-textual.
        return vec![Finding::new(
            MetadataKind::Thumbnail,
            name.to_owned(),
            as_u64(part.data.as_ref().map_or(0, Vec::len)),
        )];
    };

    let mut findings = Vec::new();
    for element in xml::elements_with_text(text) {
        if element.text.trim().is_empty() {
            continue;
        }
        findings.push(
            Finding::new(
                kind_of_property(element.name, kind),
                name.to_owned(),
                as_u64(element.text.len()),
            )
            .with_field(element.name.to_owned())
            .with_value(options, || MetadataValue::Text(element.text.to_owned())),
        );
    }
    if findings.is_empty() {
        // An empty properties part is still a part that should not be published, and a report
        // that said nothing about it would be a report claiming there was nothing there.
        findings.push(Finding::new(kind, name.to_owned(), as_u64(text.len())));
    }
    findings
}

/// Classify a property element more precisely than its part's default.
fn kind_of_property(element: &str, fallback: MetadataKind) -> MetadataKind {
    match element {
        "dc:creator" | "cp:lastModifiedBy" | "Manager" | "Company" => {
            MetadataKind::PersonalIdentity
        }
        "dcterms:created" | "dcterms:modified" | "cp:lastPrinted" => MetadataKind::Timestamp,
        "Application" | "AppVersion" | "Template" => MetadataKind::SoftwareFingerprint,
        // Cumulative editing minutes, and the revision counter beside it. Neither names anyone
        // and both narrow the field considerably — `docs/THREAT_MODEL.md` §4.7 on correlation.
        "TotalTime" | "cp:revision" => MetadataKind::EditingHistory,
        "cp:contentStatus" | "dc:description" | "cp:keywords" | "dc:subject" => {
            MetadataKind::Comment
        }
        _ => fallback,
    }
}

/// Scrub identifying attributes out of one XML part.
fn scrub_part(
    text: &str,
    name: &str,
    dead_rel_ids: &BTreeSet<String>,
    options: &InspectOptions,
) -> Decision {
    let scrubbed = xml::scrub(text, name, dead_rel_ids, options);
    let action = match scrubbed.output {
        // Unchanged parts keep their original compressed bytes, so a document with nothing to
        // remove differs from its input only in its entry headers.
        None => Action::Copy,
        Some(text) => Action::Rewrite(text.into_bytes()),
    };
    Decision {
        action,
        findings: scrubbed.findings,
        notes: scrubbed.notes,
    }
}

/// The relationships this package will remove, indexed by the part that has to change.
///
/// A relationship removal has two ends: the `Relationship` element in the `.rels` part, and
/// whatever carried the `r:id` in the part that `.rels` belongs to. Both are collected here,
/// before any part is rewritten, because a part cannot see the other end from inside its own
/// scrub pass — and removing one end without the other leaves a reference pointing at nothing,
/// which is the repair prompt this handler exists to avoid.
#[derive(Default)]
struct DeadRelationships {
    by_part: BTreeMap<String, BTreeSet<String>>,
}

impl DeadRelationships {
    /// The ids this part must stop referring to. Empty for a part with nothing to change.
    fn for_part(&self, name: &str) -> &BTreeSet<String> {
        static NONE: BTreeSet<String> = BTreeSet::new();
        self.by_part.get(name).unwrap_or(&NONE)
    }
}

/// Find every external relationship whose target is a local or network path.
fn dead_relationships(parts: &[Part<'_>]) -> DeadRelationships {
    let mut dead = DeadRelationships::default();
    for part in parts {
        let (Some(name), Some(text)) = (part.name(), part.text()) else {
            continue;
        };
        if !name.to_ascii_lowercase().ends_with(".rels") {
            continue;
        }
        let ids = xml::external_local_relationships(text);
        if ids.is_empty() {
            continue;
        }
        // The part a `.rels` belongs to: `word/_rels/settings.xml.rels` describes
        // `word/settings.xml` (ECMA-376 Part 2, §9.3.2). The package-level `_rels/.rels` has no
        // owning part, and `owner_part` returns `None` for it.
        if let Some(owner) = owner_part(name) {
            dead.by_part.entry(owner).or_default().extend(ids.clone());
        }
        dead.by_part.entry(name.to_owned()).or_default().extend(ids);
    }
    dead
}

/// The part a relationship part describes, or [`None`] for the package-level one.
fn owner_part(rels_name: &str) -> Option<String> {
    let stem = rels_name.strip_suffix(".rels")?;
    let (directory, file) = match stem.rsplit_once('/') {
        Some((directory, file)) => (directory, file),
        None => ("", stem),
    };
    let base = directory.strip_suffix("_rels")?;
    if file.is_empty() {
        // `_rels/.rels`, which describes the package rather than a part.
        return None;
    }
    Some(format!("{base}{file}"))
}

/// Findings that belong to the archive itself rather than to any one part.
fn container_findings(parts: &[Part<'_>]) -> Vec<Finding> {
    let mut findings = Vec::new();

    let timestamped = parts
        .iter()
        .filter(|p| p.entry.modified != zip::NORMALISED_DOS_DATETIME)
        .count();
    if timestamped > 0 {
        // Every entry header records when that part was last written. Across a document's parts
        // that is a record of an editing session's clock times, which is the same class of
        // information as `TotalTime` and is not visible in any application.
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

/// Strip a leading slash from a part path so that the content-types, relationship, and entry
/// spellings of the same part compare equal.
fn normalise_part_name(name: &str) -> String {
    name.strip_prefix('/').unwrap_or(name).to_owned()
}

/// A malformed-structure error for this format.
const fn malformed(format: Format, detail: MalformedDetail) -> StryptError {
    StryptError::Malformed {
        format,
        offset: None,
        detail,
    }
}

/// Widen a length for a report field.
///
/// Saturating rather than fallible: this is only ever a count in a report, and no length that
/// fits in memory comes close to `u64::MAX`.
fn as_u64(n: usize) -> u64 {
    u64::try_from(n).unwrap_or(u64::MAX)
}

/// Silence the unused-import warning for a type the module uses only through `zip::`.
const _: Option<Method> = None;
