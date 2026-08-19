//! Turning `strypt-core`'s structured results into something to read.
//!
//! All presentation lives here. `strypt-core` returns data and never a formatted sentence
//! (ADR-0003), so this is the only place where wording is chosen — which also makes it the
//! only place where the language rules can be broken. Two of them are binding:
//!
//! - **"Complete", "guaranteed", and "100%" are banned.** No tool can guarantee total
//!   metadata removal, and a user who believes otherwise takes risks they would not otherwise
//!   take (`docs/THREAT_MODEL.md` §5.6).
//! - **Values are not printed unless the user asked.** `--show-values` exists for that; the
//!   default reports field names and counts.

use std::fmt::Write as _;

use strypt_core::report::{
    Finding, MetadataKind, MetadataReport, MetadataValue, Note, Sensitivity, StripReport,
};

/// Render a `show` result for one file.
pub fn show_text(path: &std::path::Path, report: &MetadataReport) -> String {
    let mut out = String::new();
    let _ = writeln!(out, "{}  [{}]", path.display(), report.format);
    if report.findings.is_empty() {
        out.push_str("  no removable metadata found\n");
    } else {
        for finding in &report.findings {
            let _ = writeln!(out, "  {}", finding_line(finding));
        }
    }
    for note in &report.notes {
        let _ = writeln!(out, "  note: {}", note_line(note));
    }
    out
}

/// Render a `strip` result for one file.
pub fn strip_text(
    input: &std::path::Path,
    output: &std::path::Path,
    report: &StripReport,
) -> String {
    let mut out = String::new();
    let _ = writeln!(
        out,
        "{} -> {}  [{}]",
        input.display(),
        output.display(),
        report.format
    );
    if report.removed.is_empty() {
        out.push_str("  nothing to remove; wrote a clean copy\n");
    } else {
        // Say what came out, not merely that something did (PRD §8.2).
        for finding in &report.removed {
            let _ = writeln!(out, "  removed {}", finding_line(finding));
        }
    }
    for retained in &report.retained {
        let _ = writeln!(
            out,
            "  kept {} ({})",
            retained.location,
            match retained.reason {
                strypt_core::report::RetentionReason::RemovalWouldAlterPayload =>
                    "removing it would have altered the file's contents",
                strypt_core::report::RetentionReason::StructurallyRequired =>
                    "the format requires it",
                // strypt-core's enums are non-exhaustive so that new cases are additive. A
                // front-end that has not been taught the new case must still say something
                // truthful rather than fail to build or, worse, stay silent about it.
                _ => "reason not recognised by this version of the CLI",
            }
        );
    }
    for note in &report.notes {
        let _ = writeln!(out, "  note: {}", note_line(note));
    }
    out
}

fn finding_line(finding: &Finding) -> String {
    let mut line = String::new();
    line.push_str(match finding.sensitivity() {
        Sensitivity::Direct => "!! ",
        Sensitivity::Correlating => " ! ",
        Sensitivity::Incidental => "   ",
        _ => " ? ",
    });
    line.push_str(kind_label(finding.kind));
    line.push_str(" — ");
    line.push_str(&finding.location);
    if let Some(field) = &finding.field {
        let _ = write!(line, " /{field}");
    }
    if let Some(value) = &finding.value {
        match value {
            MetadataValue::Text(text) => {
                let _ = write!(line, " = {text}");
            }
            MetadataValue::Opaque { bytes } => {
                let _ = write!(line, " = <{bytes} bytes>");
            }
            _ => line.push_str(" = <value of an unrecognised kind>"),
        }
    }
    line
}

fn kind_label(kind: MetadataKind) -> &'static str {
    match kind {
        MetadataKind::Location => "location",
        MetadataKind::DeviceIdentity => "device identity",
        MetadataKind::PersonalIdentity => "personal identity",
        MetadataKind::SoftwareFingerprint => "software fingerprint",
        MetadataKind::Timestamp => "timestamp",
        MetadataKind::Thumbnail => "embedded thumbnail",
        MetadataKind::EditingHistory => "editing history",
        MetadataKind::DocumentIdentifier => "document identifier",
        MetadataKind::ColourProfile => "colour profile",
        MetadataKind::Comment => "comment",
        MetadataKind::Other => "other metadata",
        _ => "metadata of a kind this version of the CLI does not recognise",
    }
}

fn note_line(note: &Note) -> String {
    match note {
        Note::UnparsedRegion { location, bytes } => format!(
            "{location} could not be parsed ({bytes} bytes left untouched) — \
             any metadata inside it was not removed"
        ),
        Note::IncrementalHistory { revisions } => format!(
            "this file had been saved {revisions} time(s) before; earlier revisions were \
             inside it"
        ),
        Note::OrphanedObjectsRemoved { objects } => {
            format!("{objects} object(s) nothing referred to any more were dropped")
        }
        Note::OutOfScopeContent { location } => {
            format!("contains {location}, which strypt does not open — check it separately")
        }
        Note::FilenameMayIdentify => {
            "the filename itself may identify its subject; strypt does not change filenames"
                .to_string()
        }
        _ => "this version of the CLI does not recognise a note strypt-core produced".to_string(),
    }
}

/// A `show` result as JSON.
///
/// The schema is part of the CLI's contract and is stable across releases: scripts key on it.
pub fn show_json(path: &std::path::Path, report: &MetadataReport) -> serde_json::Value {
    serde_json::json!({
        "path": path.to_string_lossy(),
        "format": report.format.id(),
        "status": "inspected",
        "findings": report.findings.iter().map(finding_json).collect::<Vec<_>>(),
        "notes": report.notes.iter().map(note_json).collect::<Vec<_>>(),
    })
}

/// A `strip` result as JSON.
pub fn strip_json(
    input: &std::path::Path,
    output: &std::path::Path,
    report: &StripReport,
) -> serde_json::Value {
    serde_json::json!({
        "path": input.to_string_lossy(),
        "output": output.to_string_lossy(),
        "format": report.format.id(),
        "status": "stripped",
        "removed": report.removed.iter().map(finding_json).collect::<Vec<_>>(),
        "notes": report.notes.iter().map(note_json).collect::<Vec<_>>(),
        "input_bytes": report.input_bytes,
        "output_bytes": report.output_bytes,
    })
}

/// A failure as JSON, so that a batch run's machine-readable output accounts for every file.
///
/// A file that failed must appear in the output. Omitting it would let a script iterate the
/// results and conclude every file it sees was handled — which is the silent-failure shape
/// this project treats as a security bug (`docs/THREAT_MODEL.md` §5.4).
pub fn error_json(path: &std::path::Path, error: &strypt_core::StryptError) -> serde_json::Value {
    serde_json::json!({
        "path": path.to_string_lossy(),
        "status": "failed",
        "error": error.to_string(),
    })
}

fn finding_json(finding: &Finding) -> serde_json::Value {
    serde_json::json!({
        "kind": finding.kind.id(),
        "sensitivity": match finding.sensitivity() {
            Sensitivity::Direct => "direct",
            Sensitivity::Correlating => "correlating",
            Sensitivity::Incidental => "incidental",
            _ => "unknown",
        },
        "location": finding.location,
        "field": finding.field,
        "bytes": finding.bytes,
        "value": finding.value.as_ref().map(|v| match v {
            MetadataValue::Text(text) => serde_json::Value::String(text.clone()),
            MetadataValue::Opaque { bytes } => serde_json::json!({ "opaque_bytes": bytes }),
            _ => serde_json::Value::Null,
        }),
    })
}

fn note_json(note: &Note) -> serde_json::Value {
    match note {
        Note::UnparsedRegion { location, bytes } => serde_json::json!({
            "note": "unparsed-region", "location": location, "bytes": bytes }),
        Note::IncrementalHistory { revisions } => serde_json::json!({
            "note": "incremental-history", "revisions": revisions }),
        Note::OrphanedObjectsRemoved { objects } => serde_json::json!({
            "note": "orphaned-objects-removed", "objects": objects }),
        Note::OutOfScopeContent { location } => serde_json::json!({
            "note": "out-of-scope-content", "location": location }),
        Note::FilenameMayIdentify => serde_json::json!({ "note": "filename-may-identify" }),
        _ => serde_json::json!({ "note": "unrecognised" }),
    }
}
