//! Detection and removal of hidden identifying metadata from files.
//!
//! # Status
//!
//! **Phase 1 complete (2026-08-22); Phase 2 in progress.** JPEG, PNG, WebP, PDF, TIFF, GIF, HEIF,
//! AVIF, SVG, JPEG XL, FLAC, WAV, MP3, Ogg, Office Open XML, and `OpenDocument` are handled, each
//! with its own fuzz target and seed corpus. Phase 2 opened on 2026-08-23 (ADR-0027). Ogg is the
//! most recent to land, on 2026-09-04, and as of that date every shipped handler has had a clean
//! sustained fuzz run. A format with no handler is reported as unsupported and is never passed
//! through untouched.
//!
//! What is *not* claimed: no tool guarantees total metadata removal, and the recorded
//! per-format limitations in `docs/THREAT_MODEL.md` are real. Read them before relying on this.
//!
//! # Invariants
//!
//! These are project invariants, not style preferences. Each has an ADR in
//! `docs/DECISIONS.md`, and code violating them should not be merged:
//!
//! - **No network access, ever, in any code path.** No dependency that opens a socket may
//!   appear in this crate's tree, including transitively. (ADR-0004)
//! - **No `unsafe`.** Enforced by `unsafe_code = "forbid"` at the workspace level. (ADR-0007)
//! - **No panics on untrusted input.** Every failure is a typed `Result`. Malformed input is
//!   *expected* input, not an exceptional condition. (ADR-0006)
//! - **No CLI concerns.** This crate returns structured data; it never formats output for
//!   humans, reads argv, prints, or exits. Front-ends render. (ADR-0003)
//! - **Fail closed.** Never emit partially-sanitised output, and never report success for a
//!   file that was not actually processed.

mod bytes;
mod container;
pub mod detect;
pub mod error;
pub mod formats;
// Behind a non-default feature, and not part of the public API: it exists so the ZIP container
// layer can be fuzzed directly, which ADR-0028 requires and which reaching it only through the
// OOXML handler would not achieve.
#[cfg(feature = "fuzzing")]
#[doc(hidden)]
pub mod fuzzing;
pub mod io;
pub mod panic_guard;
pub mod pipeline;
pub mod registry;
pub mod report;

pub use detect::{Format, detect};
pub use error::{IoAction, MalformedDetail, ResourceLimit, Result, StryptError, UnsupportedKind};
pub use formats::{MetadataHandler, ParseLimits, StripOptions, Stripped};
pub use io::{AtomicWrite, Limits, Overwrite, Permissions};
pub use pipeline::{inspect_bytes, inspect_file, strip_bytes, strip_file};
pub use report::{
    Finding, InspectOptions, MetadataKind, MetadataReport, MetadataValue, Note, Retained,
    RetentionReason, Sensitivity, StripReport,
};

/// The crate version, for front-ends to report.
#[must_use]
pub const fn version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_is_reported() {
        assert!(!version().is_empty());
    }
}
