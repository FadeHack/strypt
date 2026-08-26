//! Format handlers.
//!
//! Organised by **file format, not by dependency**: someone looking for how WebP is handled
//! opens `webp.rs`. If the crate underneath a handler is ever swapped, the change stops at
//! that module boundary and nothing else in the tree moves. A module must never be named
//! after the crate it wraps.
//!
//! # Why handlers take a slice and return a buffer
//!
//! `docs/ARCHITECTURE.md` §3 sketched this trait over a `ReadSeek`. Phase 1 refines it to
//! `&[u8]` in and `Vec<u8>` out, recorded as ADR-0017. Two reasons:
//!
//! - **Output must be verified before it can reach the disk.** The verification pass
//!   (`docs/ARCHITECTURE.md` §1) re-inspects what the handler produced and fails if metadata
//!   survived. Streaming straight to the destination would mean unverified — possibly
//!   partially-sanitised — bytes had already been written by the time the check ran, which is
//!   exactly the outcome the fail-closed rule exists to prevent.
//! - **A slice makes the panic-freedom lints enforceable.** Seek-driven parsing spreads
//!   bounds checking across every read; a slice concentrates it in
//!   [`crate::bytes::Reader`], where `indexing_slicing` and `arithmetic_side_effects` can be
//!   denied and actually mean something (ADR-0006).
//!
//! The cost is that a file is held in memory, which is why ingest is bounded before a handler
//! ever sees it ([`crate::io::Limits`]).

use crate::detect::Format;
use crate::error::Result;
use crate::report::{InspectOptions, MetadataReport, StripReport};

mod exif;
pub mod gif;
pub mod jpeg;
pub mod odf;
pub mod ooxml;
pub mod pdf;
pub mod png;
pub mod tiff;
pub mod webp;
mod xml;
mod xmp;

/// Sanitised bytes and an account of what was done to produce them.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct Stripped {
    /// The sanitised file. Not yet written anywhere: the pipeline verifies it first.
    pub bytes: Vec<u8>,
    /// What was removed, what was kept, and any caveats.
    pub report: StripReport,
}

/// Ceilings a handler applies while parsing.
///
/// Separate from [`crate::io::Limits`], which bounds how much is *read*. These bound what a
/// parser will do with what it read — the difference between refusing a 4 GB file and
/// refusing a 4 KB file that describes four billion objects.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct ParseLimits {
    /// Maximum nesting depth.
    ///
    /// Stack overflow aborts the process; it is not a catchable panic, so it cannot be
    /// handled after the fact and must be prevented by construction
    /// (`docs/ARCHITECTURE.md` §5.1).
    pub max_depth: u32,
    /// Maximum number of structural items — objects, segments, chunks — in one file.
    pub max_items: u32,
    /// Maximum bytes a single compressed structure may expand to.
    ///
    /// **Load-bearing as of the OOXML handler.** It was reserved through Phase 1, because no
    /// handler decompressed anything: PNG's compressed text chunks are removed without being
    /// inflated (ADR-0022), and the PDF handler declines to inflate a filtered metadata stream
    /// for the same reason. The ZIP container layer is the first code here to inflate, and it
    /// spends this ceiling as an allowance shared across a whole archive — so that a hundred
    /// entries each individually within it cannot collectively exceed it, which is the shape of
    /// every archive bomb that gets past a naive limit (ADR-0028, ADR-0029).
    ///
    /// The ceiling is enforced *as output is produced*, never checked afterwards. A limit
    /// tested after decompressing is not a limit — the memory is already committed by the time
    /// it fails.
    pub max_expanded_bytes: u64,
}

impl Default for ParseLimits {
    fn default() -> Self {
        Self {
            // Comfortably past what real documents nest to, far short of what blows a stack.
            max_depth: 64,
            // A large real PDF runs to tens of thousands of objects; a million is a refusal.
            max_items: 1_000_000,
            max_expanded_bytes: 256 * 1024 * 1024,
        }
    }
}

/// What a caller wants from a strip.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct StripOptions {
    /// Whether the returned report names the values that were removed.
    ///
    /// Off by default, for the reason in [`crate::report`]: a report is easy to redirect into
    /// a file, and a file naming everything just removed is a durable copy of the secret.
    pub inspect: InspectOptions,
    /// Parser ceilings.
    pub limits: ParseLimits,
}

/// Detection, reporting, and removal for one file format.
///
/// Implementations sit directly on attacker-controlled bytes and must uphold the invariants
/// in `docs/ARCHITECTURE.md` §3: `inspect` never mutates, nothing panics, failure is total
/// rather than partial, resources are bounded, the payload is preserved, and anything `strip`
/// claims to remove is something `inspect` can detect — without which the verification pass
/// would be checking nothing.
pub trait MetadataHandler: Send + Sync {
    /// Stable identifier, matching [`Format::id`].
    fn name(&self) -> &'static str;

    /// The format this handler is responsible for.
    fn format(&self) -> Format;

    /// Report what metadata the file contains, without modifying anything.
    ///
    /// An unparseable region is a [`crate::report::Note`], not necessarily an error: a file
    /// strypt only partly understands is still worth telling the user about, provided the
    /// report says plainly which part was not understood.
    ///
    /// # Errors
    ///
    /// Returns an error when the file's structure is unusable, or when a parse ceiling is hit.
    fn inspect(&self, input: &[u8], options: &InspectOptions) -> Result<MetadataReport>;

    /// Produce a sanitised copy.
    ///
    /// # Errors
    ///
    /// Returns an error rather than partially-sanitised bytes. There is no half-success.
    fn strip(&self, input: &[u8], options: &StripOptions) -> Result<Stripped>;
}
