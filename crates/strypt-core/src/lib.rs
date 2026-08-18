//! Detection and removal of hidden identifying metadata from files.
//!
//! # Status
//!
//! **Phase 0 — scaffolding only.** This crate contains no logic yet. The intended design is
//! specified in `docs/ARCHITECTURE.md`; implementation begins in Phase 1 with the JPEG, PNG,
//! WebP, and PDF handlers (scope locked by ADR-0005).
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
