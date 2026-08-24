//! `OpenDocument` — `.odt`, `.ods`, `.odp`.
//!
//! A ZIP package like Office Open XML, and the ZIP layer ([`crate::container::zip`], ADR-0028)
//! and the one-level descent into embedded images ([`crate::container::package`], ADR-0029) are
//! shared with it unchanged. **What is inside the package is not shared, and the differences are
//! not cosmetic** — ADR-0031 records them. The four that shape this module:
//!
//! 1. **Parts are found by name, not by declared type.** ADR-0030 matches Office property parts
//!    on their content type, because `docProps/` is a convention and the content type is the
//!    contract. ODF is the other way round: `meta.xml`, `settings.xml`, and
//!    `META-INF/manifest.xml` are *named* by ODF 1.3 Part 2 §3.1, while the manifest gives
//!    `meta.xml` the media type `text/xml` — the same as every other XML part in the package.
//!    There is no type to match on, so the rule that is right for one format is unusable in the
//!    other.
//! 2. **Authorship is element text, not an attribute.** See [`rules`].
//! 3. **An encrypted package does not look encrypted to ZIP.** ODF encrypts entry data itself
//!    and records it in the manifest (Part 2 §3.4), so the general-purpose-bit refusal that
//!    catches an encrypted Office document passes an encrypted `OpenDocument` through. Refusing it
//!    is this handler's job, and it is the most dangerous thing in this module.
//! 4. **An embedded chart is not a nested container.** `LibreOffice` stores one as ordinary
//!    entries in the same archive — `Object 1/content.xml`, `Object 1/meta.xml` — so its author
//!    metadata is reachable in the same pass, with no recursion at all. The equivalent Office
//!    document holds a whole `.xlsx` inside itself and is refused (§7.6). Same feature, opposite
//!    outcome, because of how the two formats store it.
//!
//! # Where the metadata is
//!
//! - `meta.xml` — the document's own metadata: `meta:initial-creator` and `dc:creator` (which in
//!   ODF is the *last* person to save it), `meta:creation-date` and `dc:date`, `meta:printed-by`
//!   and `meta:print-date`, `meta:generator` (which names the operating system as well as the
//!   application), `meta:user-defined` properties, `meta:template` pointing at a file on the
//!   author's machine, and the pair with no Office counterpart worth calling equivalent:
//!   `meta:editing-cycles` and `meta:editing-duration`.
//! - `settings.xml` — window geometry, the last cursor position, and — the reason it is removed
//!   rather than scrubbed — the printer's name and its base64 setup blob, plus a per-release set
//!   of configuration keys that fingerprints the producing build.
//! - `Thumbnails/thumbnail.png` — a rendered preview of the first page (Part 2 §3.8). It
//!   survives every redaction applied to the text, exactly as an Exif thumbnail survives
//!   cropping.
//! - `Configurations2/` — the producer's saved user-interface configuration.
//! - `Pictures/` — whole JPEG, PNG, and WebP files with whatever their cameras wrote.
//! - `content.xml` and `styles.xml` — comment and revision authorship, and fields holding a
//!   cached copy of the author's name.
//! - The ZIP entry headers themselves, as for every package format.

use std::collections::BTreeSet;

use crate::container::package::{self, Action, Decision, Embedded, Part, as_u64};
use crate::container::zip::{self, Method, Output};
use crate::detect::Format;
use crate::error::{MalformedDetail, Result, StryptError};
use crate::formats::{MetadataHandler, ParseLimits, StripOptions, Stripped};
use crate::report::{
    Finding, InspectOptions, MetadataKind, MetadataReport, MetadataValue, Note, StripReport,
};

mod rules;

/// The package's own one-line statement of what it is. ODF 1.3 Part 2 §3.3.
const MIMETYPE: &str = "mimetype";
/// The part that lists every other part. Required in every `OpenDocument` package (Part 2 §2.2.1).
const MANIFEST: &str = "META-INF/manifest.xml";

/// The three media types this release handles.
pub(crate) const MEDIA_TYPES: [(&str, Format); 3] = [
    ("application/vnd.oasis.opendocument.text", Format::Odt),
    (
        "application/vnd.oasis.opendocument.spreadsheet",
        Format::Ods,
    ),
    (
        "application/vnd.oasis.opendocument.presentation",
        Format::Odp,
    ),
];

/// The `OpenDocument` media-type prefix, used to *name* the ones this release does not handle.
///
/// Drawings, formulas, charts, databases, and every `-template` variant share this prefix. They
/// are refused, and saying "an `OpenDocument` type strypt does not handle yet" is more use to
/// someone than "a ZIP container": the first tells them the file was understood and declined,
/// the second sounds like the file was not recognised at all.
pub(crate) const MEDIA_TYPE_PREFIX: &str = "application/vnd.oasis.opendocument.";

/// The media type a package's manifest declares for the package as a whole.
///
/// Exposed for detection, which has to identify the package before any handler is chosen, and
/// must not have a second, more permissive idea of what an `OpenDocument` package looks like than
/// the handler it routes to.
pub(crate) fn root_media_type_of(manifest: &str) -> Option<String> {
    rules::root_media_type(manifest)
}

/// The format a package's declared media type corresponds to, if this release handles it.
pub(crate) fn format_for_media_type(media_type: &str) -> Option<Format> {
    MEDIA_TYPES
        .iter()
        .find(|(candidate, _)| *candidate == media_type.trim())
        .map(|(_, format)| *format)
}

/// Removal of metadata from `OpenDocument` documents.
///
/// One handler type serving three formats, instantiated once per format rather than branching
/// internally, so that [`MetadataHandler::format`] keeps returning the format the registry
/// dispatched on.
#[derive(Debug, Clone, Copy)]
pub struct OdfHandler {
    format: Format,
}

impl OdfHandler {
    /// The handler for text documents.
    pub const ODT: Self = Self {
        format: Format::Odt,
    };
    /// The handler for spreadsheets.
    pub const ODS: Self = Self {
        format: Format::Ods,
    };
    /// The handler for presentations.
    pub const ODP: Self = Self {
        format: Format::Odp,
    };
}

impl MetadataHandler for OdfHandler {
    fn name(&self) -> &'static str {
        self.format.id()
    }

    fn format(&self) -> Format {
        self.format
    }

    fn inspect(&self, input: &[u8], options: &InspectOptions) -> Result<MetadataReport> {
        // The same pass stripping uses, with the output discarded — so "everything `strip`
        // removes is something `inspect` can see" holds by construction rather than by two code
        // paths agreeing to stay in step (ADR-0029).
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
    confirm_package(&parts, format)?;

    let mut findings = Vec::new();
    let mut notes = Vec::new();

    package::refuse_nested_containers(&parts, format, &mut notes)?;

    let dropped: BTreeSet<String> = parts
        .iter()
        .filter_map(|part| {
            let name = part.name()?;
            removed_whole(name).map(|_| name.to_owned())
        })
        .collect();

    let mut outputs: Vec<Output<'_>> = Vec::with_capacity(parts.len());

    // The `mimetype` entry shall be the first file in the package and shall not be compressed
    // (Part 2 §3.3). Emitting it first is the only place this handler reorders anything, and it
    // is what keeps output a conforming package when the input was written by a producer that
    // did not put it there — a reader that checks the first entry to identify the file would
    // otherwise be handed something it does not recognise as OpenDocument at all.
    if let Some(part) = parts.iter().find(|p| p.name() == Some(MIMETYPE)) {
        outputs.push(mimetype_output(part));
    }

    for part in &parts {
        if part.name() == Some(MIMETYPE) {
            continue;
        }
        let decision = decide(part, &dropped, options, limits)?;
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

/// The `mimetype` entry as it will be written: first, and stored.
///
/// A conforming package already stores it, in which case its bytes are copied through untouched.
/// One that deflated it is re-emitted stored, which is a change to the input — recorded here
/// rather than glossed, and the narrowest one available: the alternative is emitting a package
/// that violates the clause every ODF reader uses to identify the format.
fn mimetype_output<'a>(part: &Part<'a>) -> Output<'a> {
    if part.entry.method == Method::Stored {
        return Output::Copied(part.entry.clone());
    }
    Output::Rewritten {
        name: part.entry.name.to_vec(),
        data: part.data.clone().unwrap_or_default(),
        flags: part.entry.flags,
    }
}

/// Refuse anything that is not the `OpenDocument` package this handler was dispatched for.
///
/// Three separate refusals, none of them optional:
///
/// - **No manifest.** Part 2 §2.2.1 requires `META-INF/manifest.xml`. Without it there is no
///   package, only a ZIP of loose XML, and treating it as a document would mean guessing.
/// - **An encrypted package.** See [`rules::declares_encryption`] — ZIP cannot see this, and a
///   package whose parts are ciphertext would otherwise be reported clean having been examined
///   by nobody.
/// - **A package that says it is something else.** Detection routes on the same declaration, so
///   a mismatch means the two disagree, and guessing is how a handler ends up confidently
///   reporting on a file it does not understand.
fn confirm_package(parts: &[Part<'_>], format: Format) -> Result<()> {
    let manifest = parts
        .iter()
        .find(|p| p.name() == Some(MANIFEST))
        .ok_or_else(|| malformed(format, MalformedDetail::MissingMarker))?;
    let manifest_text = manifest
        .text()
        .ok_or_else(|| malformed(format, MalformedDetail::BrokenIndex))?;

    if rules::declares_encryption(manifest_text) {
        return Err(malformed(format, MalformedDetail::UnsupportedFeature));
    }

    let declared = declared_format(parts, manifest_text)?;
    if declared == Some(format) {
        Ok(())
    } else {
        Err(malformed(format, MalformedDetail::MissingMarker))
    }
}

/// What the package says it is, from its `mimetype` entry and its manifest.
///
/// Part 2 §3.3 requires the two to agree where both are present. Where they do not, the package
/// is refused rather than resolved in either direction: a file with two different answers to
/// "what am I" is one where different readers will disagree about what they are opening, and
/// picking a winner would mean strypt deciding which of two documents the user has.
fn declared_format(parts: &[Part<'_>], manifest_text: &str) -> Result<Option<Format>> {
    let from_mimetype = parts
        .iter()
        .find(|p| p.name() == Some(MIMETYPE))
        .and_then(Part::text)
        .map(str::trim)
        .map(str::to_owned);
    let from_manifest = rules::root_media_type(manifest_text);

    if let (Some(mime), Some(root)) = (&from_mimetype, &from_manifest)
        && mime != root
    {
        return Err(StryptError::Malformed {
            format: from_mimetype
                .as_deref()
                .and_then(format_for_media_type)
                .unwrap_or(Format::Odt),
            offset: None,
            detail: MalformedDetail::BrokenIndex,
        });
    }
    Ok(from_mimetype
        .or(from_manifest)
        .as_deref()
        .and_then(format_for_media_type))
}

/// Whether a part is metadata in its entirety, and what it exposes.
///
/// **Matched on the name**, which is the inversion of ADR-0030 explained in the module header:
/// ODF fixes these names in Part 2 §3.1, and gives them no media type that distinguishes them
/// from any other XML in the package.
///
/// The leaf name rather than the whole path, so that an embedded object's own metadata — the
/// `Object 1/meta.xml` of a chart, which carries the name of whoever made the chart — is removed
/// by the same rule as the document's.
fn removed_whole(name: &str) -> Option<MetadataKind> {
    // A subtree, directory marker included: `Thumbnails/` and `Configurations2/` are removed
    // whole, so an entry anywhere beneath them goes with them.
    if name.starts_with("Thumbnails/") {
        return Some(MetadataKind::Thumbnail);
    }
    if name.starts_with("Configurations2/") {
        return Some(MetadataKind::SoftwareFingerprint);
    }
    let leaf = name.rsplit_once('/').map_or(name, |(_, leaf)| leaf);
    match leaf {
        "meta.xml" => Some(MetadataKind::PersonalIdentity),
        "settings.xml" => Some(MetadataKind::SoftwareFingerprint),
        // A binary cache of where the producer laid the text out, written by LibreOffice to make
        // reopening faster. Its format is undocumented, it holds no payload, and nothing refers
        // to it — so unlike an unrecognised part (which may be load-bearing and is copied with a
        // note, §7.6) there is nothing to weigh against removing it.
        "layout-cache" => Some(MetadataKind::Other),
        _ => None,
    }
}

/// Decide about one part.
fn decide(
    part: &Part<'_>,
    dropped: &BTreeSet<String>,
    options: &InspectOptions,
    limits: &ParseLimits,
) -> Result<Decision> {
    let Some(name) = part.name() else {
        // A part whose name is not UTF-8 cannot be one this handler knows, and cannot be named
        // by the manifest, whose paths are text. Copied, and declared.
        return Ok(Decision::unexamined(
            "an entry whose name is not valid UTF-8",
            part.entry.compressed.len(),
        ));
    };

    if part.entry.is_directory() {
        return Ok(if dropped.contains(name) {
            Decision {
                action: Action::Drop,
                findings: Vec::new(),
                notes: Vec::new(),
            }
        } else {
            Decision::copy()
        });
    }

    // The manifest, which has to stop listing whatever went. Handled here rather than in a pass
    // of its own so that it keeps its position in the archive and is written exactly once —
    // writing an index part in a second pass is the bug §7.6 records, where every reader
    // tolerated the duplicate and only byte-identical idempotence noticed.
    if name == MANIFEST {
        let Some(text) = part.text() else {
            return Ok(Decision::copy());
        };
        return Ok(Decision {
            action: match rules::drop_manifest_entries(text, dropped) {
                Some(rewritten) => Action::Rewrite(rewritten.into_bytes()),
                None => Action::Copy,
            },
            findings: Vec::new(),
            notes: Vec::new(),
        });
    }

    if let Some(kind) = removed_whole(name) {
        return Ok(Decision {
            action: Action::Drop,
            findings: metadata_part_findings(part, name, kind, options),
            notes: Vec::new(),
        });
    }

    let Some(data) = part.data.as_deref() else {
        return Ok(Decision::copy());
    };

    // A photograph in `Pictures/` goes through the *same* handler the CLI uses on a loose file,
    // one level deep and images only (ADR-0029).
    if let Some(embedded) = package::embedded_image_format(data) {
        return match package::strip_embedded_image(embedded, data, name, options, limits)? {
            Embedded::Unchanged => Ok(Decision::copy()),
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
        Some(text) => {
            let scrubbed = rules::scrub(text, name, options);
            Ok(Decision {
                action: match scrubbed.output {
                    // An unchanged part keeps its original compressed bytes, so a document with
                    // nothing to remove differs from its input only in its entry headers.
                    None => Action::Copy,
                    Some(rewritten) => Action::Rewrite(rewritten.into_bytes()),
                },
                findings: scrubbed.findings,
                notes: scrubbed.notes,
            })
        }
        // Not text, not an image strypt handles: a font, an embedded object's replacement
        // rendering, a binary blob.
        None => Ok(Decision::unexamined(name, data.len())),
    }
}

/// Report what a metadata part held, before it is dropped.
///
/// The part goes whole either way, and naming its fields is what makes `strypt show` worth
/// running before deciding to publish.
fn metadata_part_findings(
    part: &Part<'_>,
    name: &str,
    kind: MetadataKind,
    options: &InspectOptions,
) -> Vec<Finding> {
    let leaf = name.rsplit_once('/').map_or(name, |(_, leaf)| leaf);
    if let Some(text) = part.text() {
        let findings = match leaf {
            "meta.xml" => rules::meta_findings(text, name, options),
            "settings.xml" => rules::settings_findings(text, name, options),
            _ => Vec::new(),
        };
        if !findings.is_empty() {
            return findings;
        }
    }

    // The thumbnail, which is an image rather than XML, and anything else this pass does not
    // itemise. An empty metadata part is still a part that should not be published, and a report
    // that said nothing about it would be a report claiming there was nothing there.
    vec![
        Finding::new(
            kind,
            name.to_owned(),
            as_u64(part.data.as_ref().map_or(0, Vec::len)),
        )
        .with_value(options, || MetadataValue::Opaque {
            bytes: as_u64(part.data.as_ref().map_or(0, Vec::len)),
        }),
    ]
}

/// A malformed-structure error for this format.
const fn malformed(format: Format, detail: MalformedDetail) -> StryptError {
    StryptError::Malformed {
        format,
        offset: None,
        detail,
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    #[test]
    fn the_parts_removed_whole_are_the_ones_odf_names() {
        for (name, expected) in [
            ("meta.xml", Some(MetadataKind::PersonalIdentity)),
            ("settings.xml", Some(MetadataKind::SoftwareFingerprint)),
            ("Thumbnails/thumbnail.png", Some(MetadataKind::Thumbnail)),
            ("Thumbnails/", Some(MetadataKind::Thumbnail)),
            (
                "Configurations2/accelerator/current.xml",
                Some(MetadataKind::SoftwareFingerprint),
            ),
            ("layout-cache", Some(MetadataKind::Other)),
            // An embedded chart's own metadata, reachable in the same pass because ODF stores an
            // embedded object as ordinary entries rather than as a nested archive.
            ("Object 1/meta.xml", Some(MetadataKind::PersonalIdentity)),
            ("content.xml", None),
            ("styles.xml", None),
            ("Pictures/image1.jpg", None),
            ("META-INF/manifest.xml", None),
        ] {
            assert_eq!(removed_whole(name), expected, "{name}");
        }
    }

    #[test]
    fn a_media_type_this_release_does_not_handle_is_not_claimed() {
        assert_eq!(
            format_for_media_type("application/vnd.oasis.opendocument.text"),
            Some(Format::Odt)
        );
        assert_eq!(
            format_for_media_type("application/vnd.oasis.opendocument.spreadsheet"),
            Some(Format::Ods)
        );
        // A drawing and a template are OpenDocument and are not in this format group.
        assert_eq!(
            format_for_media_type("application/vnd.oasis.opendocument.graphics"),
            None
        );
        assert_eq!(
            format_for_media_type("application/vnd.oasis.opendocument.text-template"),
            None
        );
    }
}
