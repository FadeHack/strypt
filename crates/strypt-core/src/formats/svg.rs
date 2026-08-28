//! SVG — the one format in this project where strypt removes *less* than mat2 and says so.
//!
//! The fourth tranche of Phase 2's third group (ADR-0032), and the only member of it that is not
//! a container of encoded pixels. **ADR-0035 is required reading before touching this handler.**
//!
//! # Editing is deletion, so a clean drawing comes back byte-identical
//!
//! Output is the input's bytes with some ranges cut out — the property GIF has (`THREAT_MODEL`
//! §7.9) and that TIFF and HEIF cannot promise at all, because those two are rebuilt. Namespace
//! declarations keep their order, attribute quoting keeps its style, whitespace keeps its shape,
//! and a diff of input against output shows exactly what strypt did and nothing else. The one
//! exception is an embedded image that was itself stripped, whose `data:` URI is re-encoded
//! canonically in place.
//!
//! # mat2 is the opposite tool here
//!
//! For every raster format in this tree, mat2 re-renders the pixels and strypt does not, so mat2
//! reaches metadata hidden inside the compressed image data and strypt records that as a
//! limitation. SVG inverts it: mat2 loads the document through Rsvg and re-renders it onto a
//! blank Cairo surface (verified against its `libmat2/images.py`, 2026-08-28), which removes
//! everything — including the accessibility text and the script this handler will not touch — and
//! also rewrites the whole document, so identifiers, grouping, animation, interactivity, and the
//! author's editable structure do not survive.
//!
//! **Neither behaviour is a defect**, and `docs/THREAT_MODEL.md` §7.11 says which tool is the
//! better recommendation for which user rather than implying strypt wins (ADR-0012).
//!
//! # Where the metadata is
//!
//! - `<metadata>` — RDF, Dublin Core, Creative Commons licensing, XMP. SVG 1.1 §5.10 states its
//!   contents are not rendered, so it is the one element in the format that is metadata by
//!   definition.
//! - **Editor namespaces** — `<sodipodi:namedview>` records the author's window geometry, zoom,
//!   and current layer; `sodipodi:docname` is the file's name on the author's disk;
//!   `inkscape:export-filename` is an absolute path; Illustrator's `<i:pgf>` is a compressed copy
//!   of the original AI document hidden inside the exported SVG.
//! - **Comments** — `<!-- Generator: Adobe Illustrator 25.0 -->`, and whatever a hand-editing
//!   author left behind.
//! - **Processing instructions** — an XMP packet's `<?xpacket?>` wrapper.
//! - **`data:` URIs** — a pasted photograph, complete with its GPS coordinates, its body serial
//!   number, and its own thumbnail, base64-encoded into an attribute of a file the user thinks of
//!   as a drawing.
//! - **Stylesheet comments**, which fingerprint the producing tool as an XML comment does.

use crate::detect::Format;
use crate::error::{MalformedDetail, Result, StryptError};
use crate::formats::{MetadataHandler, ParseLimits, StripOptions, Stripped};
use crate::report::{InspectOptions, MetadataReport, StripReport};

mod data_uri;
mod rules;

/// Removal of metadata from SVG documents.
#[derive(Debug, Clone, Copy)]
pub struct SvgHandler;

impl MetadataHandler for SvgHandler {
    fn name(&self) -> &'static str {
        Format::Svg.id()
    }

    fn format(&self) -> Format {
        Format::Svg
    }

    fn inspect(&self, input: &[u8], options: &InspectOptions) -> Result<MetadataReport> {
        // The same pass stripping uses, with the bytes discarded — so "everything `strip` removes
        // is something `inspect` can see" holds by construction rather than by two code paths
        // agreeing to stay in step, which is the ODF handler's arrangement and for the same
        // reason: the verification pass is only worth anything if the two cannot diverge.
        let outcome = rules::process(text(input)?, options, &ParseLimits::default())?;
        Ok(MetadataReport {
            format: Format::Svg,
            findings: outcome.findings,
            notes: outcome.notes,
        })
    }

    fn strip(&self, input: &[u8], options: &StripOptions) -> Result<Stripped> {
        let source = text(input)?;
        let outcome = rules::process(source, &options.inspect, &options.limits)?;
        // A document with nothing to remove is not rewritten at all, which is what makes the
        // byte-identical guarantee above hold rather than merely usually hold.
        let bytes = outcome.output.unwrap_or_else(|| source.as_bytes().to_vec());
        Ok(Stripped {
            report: StripReport {
                format: Format::Svg,
                removed: outcome.findings,
                retained: outcome.retained,
                notes: outcome.notes,
                input_bytes: crate::container::package::as_u64(input.len()),
                output_bytes: crate::container::package::as_u64(bytes.len()),
            },
            bytes,
        })
    }
}

/// The document as text, or a refusal.
///
/// **Non-UTF-8 input is refused rather than scanned as bytes on a guess about its encoding.** XML
/// permits UTF-16, and a scanner that read one as UTF-8 would find no tags at all and report a
/// clean file — which is the silent pass-through of `docs/THREAT_MODEL.md` §5.4 wearing a
/// success message (ADR-0035 §9).
fn text(input: &[u8]) -> Result<&str> {
    std::str::from_utf8(input).map_err(|e| StryptError::Malformed {
        format: Format::Svg,
        offset: Some(crate::container::package::as_u64(e.valid_up_to())),
        detail: MalformedDetail::UnsupportedFeature,
    })
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;
    use crate::error::UnsupportedKind;

    const CLEAN: &str = "<svg xmlns=\"http://www.w3.org/2000/svg\" viewBox=\"0 0 8 8\">\
                         <rect width=\"8\" height=\"8\" fill=\"#abcdef\"/></svg>";

    fn strip(src: &str) -> Stripped {
        SvgHandler
            .strip(src.as_bytes(), &StripOptions::default())
            .expect("stripping a well-formed drawing")
    }

    #[test]
    fn a_clean_drawing_comes_back_byte_identical() {
        // No other format in this tree can promise this of a whole file except GIF, and both can
        // only promise it because they are edited by deletion rather than rebuilt.
        let stripped = strip(CLEAN);
        assert_eq!(stripped.bytes, CLEAN.as_bytes());
        assert!(stripped.report.removed.is_empty());
    }

    #[test]
    fn stripping_is_idempotent_byte_for_byte() {
        let dirty = "<?xml version=\"1.0\"?><!-- Generator: A Tool -->\
                     <svg xmlns=\"http://www.w3.org/2000/svg\" xmlns:i=\"http://ns.adobe.com/\" \
                     i:extraneous=\"self\"><metadata><dc:creator>A Name</dc:creator></metadata>\
                     <rect/></svg>";
        let once = strip(dirty);
        let twice = SvgHandler
            .strip(&once.bytes, &StripOptions::default())
            .unwrap();
        assert_eq!(once.bytes, twice.bytes);
        assert!(twice.report.removed.is_empty());
    }

    #[test]
    fn what_strip_removes_inspect_can_see() {
        // The invariant the verification pass depends on. If inspect could not see it, the pass
        // would be checking nothing.
        let dirty = "<svg xmlns=\"http://www.w3.org/2000/svg\"><!-- gen -->\
                     <metadata><dc:creator>A Name</dc:creator></metadata><rect/></svg>";
        let before = SvgHandler
            .inspect(dirty.as_bytes(), &InspectOptions::names_only())
            .unwrap();
        assert!(before.has_findings());
        let after = SvgHandler
            .inspect(&strip(dirty).bytes, &InspectOptions::names_only())
            .unwrap();
        assert!(!after.has_findings(), "{:?}", after.findings);
    }

    #[test]
    fn a_utf16_document_is_refused_rather_than_read_as_bytes() {
        // A scanner reading UTF-16 as UTF-8 finds no tags at all and reports a clean file.
        let mut utf16 = vec![0xFF, 0xFE];
        for unit in "<svg/>".encode_utf16() {
            utf16.extend_from_slice(&unit.to_le_bytes());
        }
        assert!(matches!(
            SvgHandler.strip(&utf16, &StripOptions::default()),
            Err(StryptError::Malformed { .. })
        ));
    }

    #[test]
    fn a_scripted_document_is_refused_by_name() {
        let src = "<svg xmlns=\"http://www.w3.org/2000/svg\"><script>fetch('x')</script></svg>";
        let e = SvgHandler
            .strip(src.as_bytes(), &StripOptions::default())
            .expect_err("a document that can execute code must be refused");
        assert!(
            matches!(
                e,
                StryptError::UnsupportedFormat {
                    format: UnsupportedKind::ScriptedSvg
                }
            ),
            "{e:?}"
        );
        // The message has to name what happened: "malformed SVG" would send the user looking for
        // a corrupt file they do not have.
        assert!(e.to_string().contains("script"), "{e}");
    }

    #[test]
    fn an_embedded_photograph_is_stripped_through_its_own_handler() {
        // ADR-0029's descent, applied to a data: URI. The picture stays and its metadata goes.
        let png = png_with_a_text_chunk();
        let encoded = data_uri::encode("image/png", &png);
        let src =
            format!("<svg xmlns=\"http://www.w3.org/2000/svg\"><image href=\"{encoded}\"/></svg>");
        let stripped = strip(&src);
        let out = String::from_utf8(stripped.bytes).unwrap();
        assert!(!out.contains(&encoded), "the URI must have been rewritten");
        assert!(out.starts_with("<svg"), "the drawing itself is untouched");
        assert!(
            !stripped.report.removed.is_empty(),
            "the embedded picture's metadata has to be reported"
        );
    }

    /// A minimal PNG carrying one `tEXt` chunk, built by hand so the test needs no fixture file.
    fn png_with_a_text_chunk() -> Vec<u8> {
        fn chunk(kind: [u8; 4], data: &[u8]) -> Vec<u8> {
            let mut out = u32::try_from(data.len()).unwrap().to_be_bytes().to_vec();
            out.extend_from_slice(&kind);
            out.extend_from_slice(data);
            let mut crc = 0xFFFF_FFFFu32;
            for byte in kind.iter().chain(data) {
                crc ^= u32::from(*byte);
                for _ in 0..8 {
                    crc = if crc & 1 == 1 {
                        (crc >> 1) ^ 0xEDB8_8320
                    } else {
                        crc >> 1
                    };
                }
            }
            out.extend_from_slice(&(!crc).to_be_bytes());
            out
        }

        let mut png = vec![0x89, b'P', b'N', b'G', 0x0D, 0x0A, 0x1A, 0x0A];
        let mut ihdr = 1u32.to_be_bytes().to_vec();
        ihdr.extend_from_slice(&1u32.to_be_bytes());
        ihdr.extend_from_slice(&[8, 0, 0, 0, 0]);
        png.extend(chunk(*b"IHDR", &ihdr));
        png.extend(chunk(*b"tEXt", b"Author\0A Name"));
        // One zlib-stored deflate block holding a single filtered scanline.
        png.extend(chunk(
            *b"IDAT",
            &[
                0x78, 0x01, 0x01, 0x02, 0x00, 0xFD, 0xFF, 0x00, 0x00, 0x00, 0x01, 0x00, 0x01,
            ],
        ));
        png.extend(chunk(*b"IEND", b""));
        png
    }
}
