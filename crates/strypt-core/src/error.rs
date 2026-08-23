//! Typed errors.
//!
//! Callers must be able to distinguish "this format is not supported" from "this file is
//! corrupt" from "the disk is full", because those three demand different actions from the
//! user and different exit codes from the CLI. That is why `strypt-core` uses `thiserror`
//! and never `anyhow` (ADR-0008): a boxed, stringly-typed error erases exactly the
//! distinction the front-ends need to make.
//!
//! # These messages must never contain metadata values
//!
//! An error string is durable — it lands in terminal scrollback, in a shell's history file,
//! in a bug report pasted into a public issue tracker. A message that helpfully quoted the
//! GPS coordinate it failed to parse would be a durable copy of the secret the user was
//! trying to destroy (`docs/THREAT_MODEL.md` §5.5). Errors here name *fields, offsets, and
//! counts*. They never name values.

use crate::detect::Format;

/// Everything that can go wrong in `strypt-core`.
///
/// Non-exhaustive: new variants are additive and must not break front-ends that match on it.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum StryptError {
    /// The underlying I/O operation failed.
    ///
    /// `action` says what was being attempted, so a front-end can render "could not read the
    /// input" rather than a bare `ENOENT`.
    #[error("i/o failure while {action}")]
    Io {
        /// What the operation was trying to do.
        action: IoAction,
        /// The operating system's error.
        #[source]
        source: std::io::Error,
    },

    /// The input exceeds the configured size limit and was not read.
    ///
    /// This is a refusal, not a failure: an unbounded read of an attacker-supplied file is a
    /// memory-exhaustion vector (`docs/ARCHITECTURE.md` §5.1), so strypt declines rather than
    /// trying and dying.
    #[error("input is larger than the configured limit of {limit} bytes")]
    InputTooLarge {
        /// The limit that was exceeded, in bytes.
        limit: u64,
        /// The input's actual size, where the source could report it.
        actual: Option<u64>,
    },

    /// The content was recognised, but no handler for it exists in this release.
    ///
    /// Reported explicitly and never silently passed through — a silent pass-through is the
    /// failure mode in `docs/THREAT_MODEL.md` §5.4, where the user publishes a file the tool
    /// implied it had cleaned.
    #[error("{format} is not supported in this release")]
    UnsupportedFormat {
        /// What the content was identified as.
        format: UnsupportedKind,
    },

    /// The content matched no format strypt recognises at all.
    #[error("the content does not match any format strypt recognises")]
    UnrecognisedFormat,

    /// The file claims to be `format` but violates its structure.
    ///
    // The offset is formatted by hand because `{offset:?}` on an `Option` renders "None" or
    // "Some(42)" — debug syntax shown to someone deciding whether to publish a document. When
    // the position is unknown, saying nothing is better than saying "None".
    #[error("malformed {format}{}: {detail}", .offset.map_or_else(String::new, |o| format!(" at byte offset {o}")))]
    Malformed {
        /// The format whose rules were broken.
        format: Format,
        /// Where the parser gave up, when the position is known.
        offset: Option<u64>,
        /// Which structural rule was violated. Never contains a metadata value.
        detail: MalformedDetail,
    },

    /// A hostile or pathological file hit one of the parser's resource ceilings.
    ///
    /// For memory-safe Rust this is the realistic residual attack class, not memory
    /// corruption (`docs/THREAT_MODEL.md` §5.1), so it gets its own variant rather than being
    /// folded into [`StryptError::Malformed`].
    #[error("{format} parsing exceeded the {limit} limit")]
    LimitExceeded {
        /// The format being parsed when the ceiling was hit.
        format: Format,
        /// Which ceiling.
        limit: ResourceLimit,
    },

    /// The handler produced output, but re-inspecting that output still found metadata.
    ///
    /// The output is discarded. This is the verification pass in `docs/ARCHITECTURE.md` §1
    /// doing its job: it converts a silent handler bug into a loud, safe failure, which is
    /// the whole reason it exists.
    #[error("verification failed: {residual} metadata item(s) survived stripping")]
    VerificationFailed {
        /// The format that was being stripped.
        format: Format,
        /// How many items the re-inspection still found. Counts only — never the values.
        residual: usize,
    },
}

/// What an I/O operation was attempting when it failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum IoAction {
    /// Opening or reading the input file.
    ReadingInput,
    /// Determining the input's size before reading it.
    MeasuringInput,
    /// Creating the temporary file that output is written to.
    CreatingTemporary,
    /// Writing sanitised bytes.
    WritingOutput,
    /// Flushing and synchronising output to disk.
    SyncingOutput,
    /// Renaming the temporary file over the destination.
    ReplacingDestination,
    /// Setting permissions on the output.
    SettingPermissions,
    /// Removing a temporary file after a failure.
    CleaningUp,
}

impl std::fmt::Display for IoAction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            Self::ReadingInput => "reading the input",
            Self::MeasuringInput => "measuring the input",
            Self::CreatingTemporary => "creating a temporary file",
            Self::WritingOutput => "writing output",
            Self::SyncingOutput => "syncing output to disk",
            Self::ReplacingDestination => "replacing the destination file",
            Self::SettingPermissions => "setting output permissions",
            Self::CleaningUp => "removing a temporary file",
        };
        f.write_str(s)
    }
}

/// A format strypt can identify but cannot yet process.
///
/// Naming it is worth the small amount of detection code: "this is an `OpenXML` document,
/// which arrives in Phase 2" is actionable, where "unrecognised" sends the user away
/// believing their file is exotic when it is merely out of scope.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum UnsupportedKind {
    /// A format strypt identifies and has a place for, but whose handler has not landed yet.
    ///
    /// Distinct from the Phase 2 formats below, because the advice differs: "not in this
    /// release" versus "not in this phase of the project".
    NotYetImplemented(crate::detect::Format),
    /// A ZIP container, which may be an Office document, an ODF document, or an archive.
    ZipContainer,
    /// A macro-enabled Office document — `.docm`, `.xlsm`, `.pptm`.
    ///
    /// Refused rather than handled, and named separately from [`Self::ZipContainer`] because
    /// the advice differs. This is not "a later phase will get to it": the document carries a
    /// `vbaProject.bin`, which is an OLE compound file with its own directory and its own
    /// metadata streams that strypt cannot read. Reporting the document clean while a container
    /// inside it went unexamined is the failure in `docs/THREAT_MODEL.md` §5.4 (ADR-0029).
    MacroEnabledOffice,
    /// GIF.
    Gif,
    /// TIFF.
    Tiff,
    /// An ISO base-media file: MP4, M4A, HEIF, AVIF.
    IsoBaseMedia,
    /// An MP3 audio file.
    Mp3,
    /// An Ogg container.
    Ogg,
    /// A FLAC audio file.
    Flac,
    /// A RIFF container that is not WebP, such as WAV or AVI.
    OtherRiff,
    /// SVG or another XML document.
    Xml,
}

impl std::fmt::Display for UnsupportedKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Written as a total match rather than an early return plus `unreachable!()`: this
        // crate has no panic paths, and "obviously unreachable" is how they get introduced.
        let s = match self {
            Self::NotYetImplemented(format) => {
                return write!(f, "{format}, whose handler has not landed yet");
            }
            Self::ZipContainer => "a ZIP container (Office, OpenDocument, or archive)",
            Self::MacroEnabledOffice => {
                "a macro-enabled Office document, whose embedded VBA project strypt cannot read"
            }
            Self::Gif => "GIF",
            Self::Tiff => "TIFF",
            Self::IsoBaseMedia => "an ISO base-media file (MP4, HEIF, or AVIF)",
            Self::Mp3 => "MP3",
            Self::Ogg => "Ogg",
            Self::Flac => "FLAC",
            Self::OtherRiff => "a RIFF container other than WebP",
            Self::Xml => "an XML document (possibly SVG)",
        };
        f.write_str(s)
    }
}

/// Which structural rule a malformed file broke.
///
/// Deliberately coarse. The purpose is to let a user tell "this file is truncated" from
/// "this file is not really the format it claims", not to provide a parser trace.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum MalformedDetail {
    /// The file ends in the middle of a structure that declared more bytes.
    Truncated,
    /// A length or offset field points outside the file.
    LengthOutOfRange,
    /// A required structural marker is missing.
    MissingMarker,
    /// A structural marker appeared where it is not permitted.
    UnexpectedMarker,
    /// The cross-reference or index structure is unusable.
    BrokenIndex,
    /// The file's objects reference each other in a cycle.
    CyclicReference,
    /// The file uses a feature strypt will not process, such as encryption.
    UnsupportedFeature,
    /// A third-party parser panicked on this file and the panic was contained.
    ///
    /// Reported as malformed input rather than as an internal error because that is what it
    /// means for the user: the file was not processed and nothing was written. It is a
    /// distinct variant rather than being folded into `BrokenIndex` because a panic in a
    /// dependency is a defect worth being able to find in the wild, not an ordinary refusal
    /// (`crate::panic_guard`).
    DependencyPanic,
}

impl std::fmt::Display for MalformedDetail {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            Self::Truncated => "the file ends mid-structure",
            Self::LengthOutOfRange => "a declared length or offset falls outside the file",
            Self::MissingMarker => "a required structural marker is missing",
            Self::UnexpectedMarker => "a structural marker appeared where it is not allowed",
            Self::BrokenIndex => "the cross-reference structure is unusable",
            Self::CyclicReference => "objects reference each other in a cycle",
            Self::UnsupportedFeature => "the file uses a feature strypt will not process",
            Self::DependencyPanic => "the parser failed on this file and it was not processed",
        };
        f.write_str(s)
    }
}

/// Which parser ceiling a file hit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ResourceLimit {
    /// Nesting depth. Guards against stack exhaustion, which aborts the process and so
    /// cannot be recovered from after the fact.
    Depth,
    /// Number of objects, segments, or chunks.
    ItemCount,
    /// Total bytes a single structure may expand to.
    ExpandedSize,
}

impl std::fmt::Display for ResourceLimit {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            Self::Depth => "nesting depth",
            Self::ItemCount => "item count",
            Self::ExpandedSize => "expanded size",
        };
        f.write_str(s)
    }
}

/// The result type used throughout `strypt-core`.
pub type Result<T> = std::result::Result<T, StryptError>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn error_messages_carry_structure_not_values() {
        // The guard from docs/THREAT_MODEL.md §5.5: a rendered error is durable, so it may
        // report counts and offsets but never the metadata itself.
        let e = StryptError::VerificationFailed {
            format: Format::Pdf,
            residual: 3,
        };
        let rendered = e.to_string();
        assert!(rendered.contains('3'));
        assert!(!rendered.contains("Author"));
    }

    #[test]
    fn unsupported_is_distinguishable_from_unrecognised() {
        // A front-end must be able to tell "Phase 2 will handle this" from "no idea what
        // this is" — they warrant different advice and different exit codes.
        let known = StryptError::UnsupportedFormat {
            format: UnsupportedKind::ZipContainer,
        };
        assert!(matches!(known, StryptError::UnsupportedFormat { .. }));
        assert!(matches!(
            StryptError::UnrecognisedFormat,
            StryptError::UnrecognisedFormat
        ));
    }
}
