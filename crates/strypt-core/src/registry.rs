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
use crate::formats::gif::GifHandler;
use crate::formats::heif::HeifHandler;
use crate::formats::jpeg::JpegHandler;
use crate::formats::jxl::JxlHandler;
use crate::formats::odf::OdfHandler;
use crate::formats::ooxml::OoxmlHandler;
use crate::formats::pdf::PdfHandler;
use crate::formats::png::PngHandler;
use crate::formats::svg::SvgHandler;
use crate::formats::tiff::TiffHandler;
use crate::formats::webp::WebpHandler;

/// The handler for `format`, or [`None`] if this release has none.
///
/// [`None`] is a real answer that the pipeline turns into a reported refusal. It must never
/// become "pass the file through unchanged" — that is the silent failure in
/// `docs/THREAT_MODEL.md` §5.4, and it is the one bug in this project that gets a user hurt
/// while the tool prints success.
#[must_use]
pub fn handler_for(format: Format) -> Option<&'static dyn MetadataHandler> {
    match format {
        Format::Jpeg => Some(&JpegHandler),
        Format::Pdf => Some(&PdfHandler),
        Format::Png => Some(&PngHandler),
        Format::Tiff => Some(&TiffHandler),
        Format::Gif => Some(&GifHandler),
        Format::Svg => Some(&SvgHandler),
        Format::Jxl => Some(&JxlHandler),
        // As the Office and OpenDocument handlers below: one type, one instance per format, so
        // that `handler.format()` answers with what dispatch chose.
        Format::Heif => Some(&HEIF),
        Format::Avif => Some(&AVIF),
        Format::Webp => Some(&WebpHandler),
        // One handler type serving three formats, instantiated once per format rather than
        // branching inside itself, so `handler.format()` still answers with the format the
        // registry dispatched on.
        Format::Docx => Some(&DOCX),
        Format::Xlsx => Some(&XLSX),
        Format::Pptx => Some(&PPTX),
        Format::Odt => Some(&ODT),
        Format::Ods => Some(&ODS),
        Format::Odp => Some(&ODP),
    }
}

static HEIF: HeifHandler = HeifHandler::HEIF;
static AVIF: HeifHandler = HeifHandler::AVIF;
static DOCX: OoxmlHandler = OoxmlHandler::DOCX;
static XLSX: OoxmlHandler = OoxmlHandler::XLSX;
static PPTX: OoxmlHandler = OoxmlHandler::PPTX;
static ODT: OdfHandler = OdfHandler::ODT;
static ODS: OdfHandler = OdfHandler::ODS;
static ODP: OdfHandler = OdfHandler::ODP;

/// Every format this release can actually process.
#[must_use]
pub fn supported_formats() -> Vec<Format> {
    [
        Format::Jpeg,
        Format::Png,
        Format::Webp,
        Format::Pdf,
        Format::Tiff,
        Format::Gif,
        Format::Svg,
        Format::Jxl,
        Format::Heif,
        Format::Avif,
        Format::Docx,
        Format::Xlsx,
        Format::Pptx,
        Format::Odt,
        Format::Ods,
        Format::Odp,
    ]
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
    fn every_shipped_format_has_a_handler() {
        // The assertion that matters is not this one but its absent counterpart: there is
        // deliberately no fallback handler, so a format added to `Format` without a line in
        // `handler_for` fails to compile rather than silently "succeeding" by being passed
        // through (`docs/THREAT_MODEL.md` §5.4).
        for format in [
            Format::Jpeg,
            Format::Png,
            Format::Webp,
            Format::Pdf,
            Format::Tiff,
            Format::Gif,
            Format::Svg,
            Format::Jxl,
            Format::Docx,
            Format::Xlsx,
            Format::Pptx,
            Format::Odt,
            Format::Ods,
            Format::Odp,
        ] {
            assert!(handler_for(format).is_some(), "{format} has no handler");
        }
    }
}
