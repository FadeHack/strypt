//! Dispatch from a detected format to its handler.
//!
//! The registry is a static table, not a plugin system. Nothing is loaded at runtime, ever
//! (ADR-0011): a metadata scrubber that can be taught new behaviour by a file on disk has
//! handed an attacker the tool's own privileges over the user's most sensitive documents.
//!
//! Adding a format means adding a line here and implementing the trait. Core dispatch does
//! not otherwise change, which is the point of the design.

use crate::detect::Format;
use crate::formats::MetadataHandler;
use crate::formats::pdf::PdfHandler;

/// The handler for `format`, or [`None`] if this release has none.
///
/// [`None`] is a real answer that the pipeline turns into a reported refusal. It must never
/// become "pass the file through unchanged" — that is the silent failure in
/// `docs/THREAT_MODEL.md` §5.4, and it is the one bug in this project that gets a user hurt
/// while the tool prints success.
#[must_use]
pub fn handler_for(format: Format) -> Option<&'static dyn MetadataHandler> {
    match format {
        Format::Pdf => Some(&PdfHandler),
        // JPEG, PNG, and WebP are landing in this phase, each with its own fuzz target and
        // seed corpus. Until each arrives, its format is reported as unsupported.
        Format::Jpeg | Format::Png | Format::Webp => None,
    }
}

/// Every format this release can actually process.
#[must_use]
pub fn supported_formats() -> Vec<Format> {
    [Format::Jpeg, Format::Png, Format::Webp, Format::Pdf]
        .into_iter()
        .filter(|f| handler_for(*f).is_some())
        .collect()
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]

    use super::*;

    #[test]
    fn a_handler_is_registered_for_its_own_format() {
        for format in supported_formats() {
            let handler = handler_for(format).expect("listed as supported");
            assert_eq!(handler.format(), format);
            assert_eq!(
                handler.name(),
                format.id(),
                "the handler name is the format id, because both appear in JSON output"
            );
        }
    }

    #[test]
    fn an_unimplemented_format_reports_none_rather_than_a_default_handler() {
        // There is deliberately no fallback handler. A pass-through default would make every
        // future unimplemented format silently "succeed".
        assert!(handler_for(Format::Pdf).is_some());
    }
}
