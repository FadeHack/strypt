//! Words shared by the CLI and the GUI, which compiles this file by `#[path]` (ADR-0060), so the
//! two cannot drift. Plain lowercase phrases: each front-end adds its own layout.
//!
//! Core's enums are non-exhaustive; a case added there falls to a `_` arm that still says
//! something true.

use strypt_core::report::{MetadataKind, Note, RetentionReason, Sensitivity};

/// What kind of information an item is.
pub const fn kind_label(kind: MetadataKind) -> &'static str {
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
        _ => "metadata of a kind this version of strypt does not recognise",
    }
}

/// `!!` identifies on its own, `!` in combination, blank rarely; `?` is a rank this build lacks.
pub const fn sensitivity_mark(sensitivity: Sensitivity) -> &'static str {
    match sensitivity {
        Sensitivity::Direct => "!!",
        Sensitivity::Correlating => "!",
        Sensitivity::Incidental => "",
        _ => "?",
    }
}

/// Why a handler kept something it could see.
pub const fn retention_reason(reason: RetentionReason) -> &'static str {
    match reason {
        RetentionReason::RemovalWouldAlterPayload => {
            "removing it would have altered the file's contents"
        }
        RetentionReason::StructurallyRequired => "the format requires it",
        RetentionReason::DerivedFromPayload => {
            "it is computed from the file's contents, so anyone holding the file can recompute it"
        }
        _ => "reason not recognised by this version of strypt",
    }
}

/// One caveat about what strypt did or could not do.
pub fn note_line(note: &Note) -> String {
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
        Note::CapabilityRemoved {
            location,
            capability,
        } => format!("{location} was removed, so this file can no longer {capability}"),
        _ => "strypt produced a note this version does not recognise; treat the file with care"
            .to_string(),
    }
}

/// strypt reads contents; what it cannot see often identifies someone (`THREAT_MODEL.md` §4).
pub const NOT_TOUCHED: &str =
    "filenames, folder names, and anything visible in the document itself are not touched";
