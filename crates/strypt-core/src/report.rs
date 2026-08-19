//! Structured results.
//!
//! `strypt-core` returns data; front-ends render it (ADR-0003). Nothing in this module is a
//! sentence meant for a human — the strings that do appear are *format-domain identifiers*
//! such as `APP1 (Exif)` or `/Info /Author`, which are stable, machine-usable, and identical
//! in the CLI's text output, its JSON output, and the Phase 5 GUI. If a type here ever grows
//! a field holding a translated or prose string, that is the boundary being violated.
//!
//! # Values are opt-in, and off by default
//!
//! A report names the metadata it found. It carries the *value* only when the caller sets
//! [`InspectOptions::include_values`]. The default is off because a report is easy to
//! redirect into a file, paste into an issue, or scroll back to — each of which recreates the
//! secret the user just asked to have destroyed (`docs/THREAT_MODEL.md` §5.5). Front-ends
//! that show values, such as the Phase 5 before/after diff, opt in deliberately.

use crate::detect::Format;

/// What kind of identifying information an item represents.
///
/// These categories mirror `docs/THREAT_MODEL.md` §3 so that a user can connect what strypt
/// reports to what the threat model claims it protects against.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[non_exhaustive]
pub enum MetadataKind {
    /// GPS coordinates, altitude, bearing — anything that places the file.
    Location,
    /// Camera make, model, lens, and body serial numbers. Serial numbers link every file a
    /// device ever produced, so one missed image can retroactively deanonymise an archive.
    DeviceIdentity,
    /// Author, creator, last-modified-by, organisation, registered owner.
    PersonalIdentity,
    /// Producing application and version.
    SoftwareFingerprint,
    /// Creation and modification times.
    Timestamp,
    /// Embedded thumbnails and previews, which survive cropping and visual redaction of the
    /// main image — a "redacted" photograph can carry an unredacted copy of itself.
    Thumbnail,
    /// Revision identifiers, editing-cycle counts, total editing time, tracked changes.
    EditingHistory,
    /// An identifier that stays stable across saves and copies of one document — a PDF file
    /// identifier, an XMP `DocumentID`. It names nobody, and it links every copy and every
    /// revision of the document to each other, which for a leaked draft is the whole question.
    DocumentIdentifier,
    /// Embedded ICC colour profiles, which frequently carry a device or vendor name.
    ColourProfile,
    /// Free-text comments.
    Comment,
    /// Recognised as metadata, but not in any category above.
    Other,
}

impl MetadataKind {
    /// The stable lowercase identifier used in JSON output.
    #[must_use]
    pub const fn id(self) -> &'static str {
        match self {
            Self::Location => "location",
            Self::DeviceIdentity => "device-identity",
            Self::PersonalIdentity => "personal-identity",
            Self::SoftwareFingerprint => "software-fingerprint",
            Self::Timestamp => "timestamp",
            Self::Thumbnail => "thumbnail",
            Self::EditingHistory => "editing-history",
            Self::DocumentIdentifier => "document-identifier",
            Self::ColourProfile => "colour-profile",
            Self::Comment => "comment",
            Self::Other => "other",
        }
    }

    /// How much this kind of item typically matters, used by front-ends for ordering and
    /// emphasis.
    #[must_use]
    pub const fn sensitivity(self) -> Sensitivity {
        match self {
            // Each of these can identify a person or a place on its own, with no correlation
            // and no further work by the adversary.
            Self::Location | Self::DeviceIdentity | Self::PersonalIdentity | Self::Thumbnail => {
                Sensitivity::Direct
            }
            // Rarely identifying alone; frequently identifying in combination
            // (docs/THREAT_MODEL.md §4.7).
            Self::Timestamp
            | Self::EditingHistory
            | Self::DocumentIdentifier
            | Self::ColourProfile
            | Self::Comment => Sensitivity::Correlating,
            Self::SoftwareFingerprint | Self::Other => Sensitivity::Incidental,
        }
    }
}

/// How directly an item exposes its subject.
///
/// A hint for presentation only. It must never gate whether something is removed: strypt
/// removes what it removes regardless of how it is ranked here.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[non_exhaustive]
pub enum Sensitivity {
    /// Identifies a person, device, or place on its own.
    Direct,
    /// Narrows the field, and identifies when combined with other traits.
    Correlating,
    /// Unlikely to identify anyone by itself.
    Incidental,
}

/// A metadata value, when the caller asked for values.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum MetadataValue {
    /// A decoded textual value.
    Text(String),
    /// A value that is not text, or not valid text. Only its length is carried: rendering an
    /// arbitrary binary blob into a report has no benefit to the user and every opportunity
    /// to leak.
    Opaque {
        /// Length of the value in bytes.
        bytes: u64,
    },
}

/// One piece of metadata found in a file.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Finding {
    /// What kind of identifying information this is.
    pub kind: MetadataKind,
    /// Where it lives in the file's structure, as a format-domain identifier — `APP1 (Exif)`,
    /// `tEXt`, `/Info /Author`. Stable across releases; front-ends may show it verbatim.
    pub location: String,
    /// The field's name within that structure, where the format names its fields.
    pub field: Option<String>,
    /// Size of the item in bytes.
    pub bytes: u64,
    /// The value — present only when [`InspectOptions::include_values`] was set.
    pub value: Option<MetadataValue>,
}

impl Finding {
    /// A finding with no field name and no value.
    #[must_use]
    pub fn new(kind: MetadataKind, location: impl Into<String>, bytes: u64) -> Self {
        Self {
            kind,
            location: location.into(),
            field: None,
            bytes,
            value: None,
        }
    }

    /// Attach the field name this item was stored under.
    #[must_use]
    pub fn with_field(mut self, field: impl Into<String>) -> Self {
        self.field = Some(field.into());
        self
    }

    /// Attach the value, but only if `options` asked for it.
    ///
    /// Taking the options here rather than at the call site means a handler cannot leak a
    /// value by forgetting to check — the check lives in one place and every handler goes
    /// through it.
    #[must_use]
    pub fn with_value(
        mut self,
        options: &InspectOptions,
        value: impl FnOnce() -> MetadataValue,
    ) -> Self {
        if options.include_values {
            self.value = Some(value());
        }
        self
    }

    /// How directly this finding exposes its subject.
    #[must_use]
    pub const fn sensitivity(&self) -> Sensitivity {
        self.kind.sensitivity()
    }
}

/// A caveat about what strypt did or could not do.
///
/// Modelled as an enum rather than free text so that front-ends can present notes
/// consistently, and so that a limitation cannot be introduced by a handler quietly writing a
/// new sentence. Notes are how the tool stays honest about partial knowledge without either
/// hiding a limitation or failing outright.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Note {
    /// The file contained a region the handler could not parse. Its bytes were preserved
    /// as-is, so metadata inside it — if any — was not removed.
    UnparsedRegion {
        /// The region's format-domain identifier.
        location: String,
        /// How many bytes were left untouched.
        bytes: u64,
    },
    /// The file had been saved incrementally, so earlier revisions were present in it.
    IncrementalHistory {
        /// How many prior revisions were found.
        revisions: usize,
    },
    /// Objects that nothing in the finished document referred to any more were dropped.
    ///
    /// Usually the remains of superseded revisions. They are worth reporting because their
    /// presence tells the user something true about the file they were about to publish:
    /// earlier drafts of it were physically inside it.
    OrphanedObjectsRemoved {
        /// How many unreachable objects were dropped.
        objects: usize,
    },
    /// Content was found that strypt deliberately does not touch, such as text drawn under a
    /// redaction rectangle (`docs/THREAT_MODEL.md` §4.3).
    OutOfScopeContent {
        /// What was seen.
        location: String,
    },
    /// The filename itself may identify its subject. A scrubbed file called
    /// `IMG_survivor_address.jpg` is not scrubbed in any meaningful sense
    /// (`docs/ARCHITECTURE.md` §8).
    FilenameMayIdentify,
}

/// The result of inspecting a file. Produced without modifying anything.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct MetadataReport {
    /// The format the content was detected as.
    pub format: Format,
    /// Everything found, in the order the handler encountered it in the file.
    pub findings: Vec<Finding>,
    /// Caveats about the inspection.
    pub notes: Vec<Note>,
}

impl MetadataReport {
    /// An empty report for `format`.
    #[must_use]
    pub const fn empty(format: Format) -> Self {
        Self {
            format,
            findings: Vec::new(),
            notes: Vec::new(),
        }
    }

    /// Whether anything removable was found.
    ///
    /// Drives the documented non-zero exit of `strypt show`, so it must mean exactly "there
    /// is something here to remove" — never "something might be here".
    #[must_use]
    pub fn has_findings(&self) -> bool {
        !self.findings.is_empty()
    }
}

/// The result of stripping a file.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct StripReport {
    /// The format that was processed.
    pub format: Format,
    /// What was removed. Says what came out, not merely that something did (PRD §8.2).
    pub removed: Vec<Finding>,
    /// What was deliberately kept, and why. An empty list here is a claim, so a handler that
    /// knowingly leaves something behind must say so rather than staying silent.
    pub retained: Vec<Retained>,
    /// Caveats about the operation.
    pub notes: Vec<Note>,
    /// Input size in bytes.
    pub input_bytes: u64,
    /// Output size in bytes.
    pub output_bytes: u64,
}

/// Something the handler found and chose not to remove.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Retained {
    /// Where it lives, as a format-domain identifier.
    pub location: String,
    /// Why it was kept.
    pub reason: RetentionReason,
}

/// Why a handler kept something it could see.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum RetentionReason {
    /// Removing it would have altered the payload — re-encoding pixels, for instance — which
    /// PRD §8.1 forbids. Preserving the payload wins, and the limitation gets documented.
    RemovalWouldAlterPayload,
    /// The format requires it to be present for the file to remain valid.
    StructurallyRequired,
}

/// What a caller wants from an inspection.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct InspectOptions {
    /// Include metadata values in findings.
    ///
    /// Off by default. See this module's note on why the default is the safe one.
    pub include_values: bool,
}

impl InspectOptions {
    /// Options that report field names and counts but never values. The default.
    #[must_use]
    pub const fn names_only() -> Self {
        Self {
            include_values: false,
        }
    }

    /// Options that include values, for a caller that has decided it needs them.
    #[must_use]
    pub const fn with_values() -> Self {
        Self {
            include_values: true,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn values_are_absent_unless_the_caller_asks() {
        let options = InspectOptions::names_only();
        let f = Finding::new(MetadataKind::Location, "APP1 (Exif)", 42)
            .with_field("GPSLatitude")
            .with_value(&options, || MetadataValue::Text("51.5074".into()));

        assert_eq!(f.field.as_deref(), Some("GPSLatitude"));
        assert_eq!(
            f.value, None,
            "a default inspection must name the field and withhold the coordinate"
        );
    }

    #[test]
    fn values_are_present_when_the_caller_opts_in() {
        let options = InspectOptions::with_values();
        let f = Finding::new(MetadataKind::PersonalIdentity, "/Info", 12)
            .with_value(&options, || MetadataValue::Text("A. Name".into()));
        assert_eq!(f.value, Some(MetadataValue::Text("A. Name".into())));
    }

    #[test]
    fn directly_identifying_kinds_outrank_incidental_ones() {
        // Front-ends sort by this, so the ordering is part of the contract.
        assert!(Sensitivity::Direct < Sensitivity::Correlating);
        assert!(Sensitivity::Correlating < Sensitivity::Incidental);
        assert_eq!(MetadataKind::Location.sensitivity(), Sensitivity::Direct);
        assert_eq!(
            MetadataKind::SoftwareFingerprint.sensitivity(),
            Sensitivity::Incidental
        );
    }

    #[test]
    fn an_embedded_thumbnail_ranks_as_directly_identifying() {
        // It can survive cropping and visual redaction, so it is not a lesser finding than
        // the GPS tag next to it (docs/THREAT_MODEL.md §3).
        assert_eq!(MetadataKind::Thumbnail.sensitivity(), Sensitivity::Direct);
    }
}
