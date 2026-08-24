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

use crate::container::package::{self, Action, Decision, Embedded, Part, as_u64};
use crate::container::zip::{self, Output};
use crate::detect::Format;
use crate::error::{MalformedDetail, Result, StryptError};
use crate::formats::xml;
use crate::formats::{MetadataHandler, ParseLimits, StripOptions, Stripped};
use crate::report::{
    Finding, InspectOptions, MetadataKind, MetadataReport, MetadataValue, Note, StripReport,
};

mod rules;

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

/// Walk the package once and produce both the report and the sanitised archive.
fn process(
    input: &[u8],
    format: Format,
    options: &InspectOptions,
    limits: &ParseLimits,
) -> Result<Processed> {
    let parts = package::read_parts(input, format, limits)?;

    let types = ContentTypes::parse(&parts, format)?;
    types.confirm_format(format)?;

    let mut findings = Vec::new();
    let mut notes = Vec::new();

    let rels = Relationships::parse(&parts);
    let dropped = parts_to_drop(&parts, &types, &rels);
    let dead_rels = dead_relationships(&parts);

    package::refuse_nested_containers(&parts, format, &mut notes)?;

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

    findings.extend(package::container_findings(&parts));

    let output = zip::write(&outputs).map_err(|e| e.into_strypt(format))?;
    Ok(Processed {
        findings,
        notes,
        output,
    })
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
        return Ok(Decision::unexamined(
            "an entry whose name is not valid UTF-8",
            part.entry.compressed.len(),
        ));
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
        let dereferenced = rules::drop_references(text, dropped);
        let base = dereferenced.as_deref().unwrap_or(text);
        let scrubbed = rules::scrub(base, name, dead_rels.for_part(name), options);
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

    // An embedded image goes through the *same* handler the CLI uses on a loose file, one level
    // deep and images only (ADR-0029). The descent itself lives in `container::package` so that
    // there is exactly one of it.
    if let Some(embedded) = package::embedded_image_format(data) {
        return match package::strip_embedded_image(embedded, data, name, options, limits)? {
            package::Embedded::Unchanged => Ok(Decision::copy()),
            Embedded::Stripped {
                bytes,
                findings,
                notes,
            } => Ok(Decision {
                action: Action::Rewrite(bytes),
                findings,
                notes,
            }),
        };
    }

    match part.text() {
        Some(text) => Ok(scrub_part(text, name, dead_rels.for_part(name), options)),
        // Not text, not an image strypt handles: a font, an audio clip, a binary blob.
        None => Ok(Decision::unexamined(name, data.len())),
    }
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
    let scrubbed = rules::scrub(text, name, dead_rel_ids, options);
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
        let ids = rules::external_local_relationships(text);
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
