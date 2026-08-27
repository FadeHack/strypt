//! Format detection by content sniffing.
//!
//! **The file extension is a hint and is never consulted here.** A `.jpg` that is really a
//! PDF must be handled as a PDF or refused outright; handing it to the JPEG handler would
//! produce a confident success message about a file that was never touched
//! (`docs/ARCHITECTURE.md` §1, `docs/THREAT_MODEL.md` §5.4). Detection therefore takes bytes
//! and nothing else — there is deliberately no way to pass it a path.
//!
//! Detection is itself a hostile-input parser: it is the one piece of code that sees every
//! byte of every file the user feeds in, including files no handler will ever accept. It
//! reads through [`crate::bytes::Reader`] for the same reason the handlers do.
//!
//! # Why this is hand-written rather than a dependency
//!
//! `file-format` and `infer` were both evaluated (`docs/ARCHITECTURE.md` §4). Phase 1 needed
//! to discriminate exactly four supported formats plus a short list of formats worth *naming*
//! in a refusal, which is under a hundred lines of magic-number matching. Taking a crate with
//! broad magic tables for that would add supply-chain surface (ADR-0008) to save very little.
//!
//! Phase 2 brought the ambiguity that comment anticipated, and it turned out not to be the kind
//! a magic table solves. `.docx`, `.xlsx`, `.pptx`, and every `OpenDocument` file share one magic
//! number, because they are all ZIP archives. Telling them apart means opening the container and
//! reading the content type the package declares for its own main part — which no magic-number
//! crate does either, and which the ZIP layer this crate already owns does directly
//! (ADR-0027, ADR-0028).
//!
//! # Why detection opens the container
//!
//! It would be cheaper to search the raw bytes for `word/document.xml` and be done. That is
//! also how a file gets routed to the wrong handler: the string appears verbatim in any archive
//! that merely *contains* a Word document, and an attacker can put it in a comment. Reading the
//! declared content type is the format's own answer to "what is this", and it costs one central
//! directory walk and one small inflate.

use crate::bytes::Reader;
use crate::error::{Result, StryptError, UnsupportedKind};

/// A format strypt has a handler for.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[non_exhaustive]
pub enum Format {
    /// JPEG, in a JFIF or EXIF container.
    Jpeg,
    /// PNG.
    Png,
    /// WebP, which is a RIFF container.
    Webp,
    /// PDF.
    Pdf,
    /// TIFF, including the multi-page files scanners produce.
    Tiff,
    /// GIF, in either the 87a or the 89a spelling.
    Gif,
    /// HEIF — `.heic` and `.heif`, the format an iPhone photograph arrives in.
    Heif,
    /// AVIF: the same container as HEIF, carrying AV1 rather than HEVC.
    Avif,
    /// A `WordprocessingML` document — `.docx`.
    Docx,
    /// A `SpreadsheetML` workbook — `.xlsx`.
    Xlsx,
    /// A `PresentationML` presentation — `.pptx`.
    Pptx,
    /// An `OpenDocument` text document — `.odt`.
    Odt,
    /// An `OpenDocument` spreadsheet — `.ods`.
    Ods,
    /// An `OpenDocument` presentation — `.odp`.
    Odp,
}

impl Format {
    /// The stable lowercase identifier used in reports and JSON output.
    ///
    /// Stable across releases: front-ends and downstream scripts key on it.
    #[must_use]
    pub const fn id(self) -> &'static str {
        match self {
            Self::Jpeg => "jpeg",
            Self::Png => "png",
            Self::Webp => "webp",
            Self::Pdf => "pdf",
            Self::Tiff => "tiff",
            Self::Gif => "gif",
            Self::Heif => "heif",
            Self::Avif => "avif",
            Self::Docx => "docx",
            Self::Xlsx => "xlsx",
            Self::Pptx => "pptx",
            Self::Odt => "odt",
            Self::Ods => "ods",
            Self::Odp => "odp",
        }
    }

    /// The conventional extension for this format, without a leading dot.
    ///
    /// Used when deriving a default output filename. Never used to *detect* anything.
    #[must_use]
    pub const fn conventional_extension(self) -> &'static str {
        match self {
            Self::Jpeg => "jpg",
            Self::Png => "png",
            Self::Webp => "webp",
            Self::Pdf => "pdf",
            Self::Tiff => "tiff",
            Self::Gif => "gif",
            // `.heic` rather than `.heif`: it is what cameras write and what users see.
            Self::Heif => "heic",
            Self::Avif => "avif",
            Self::Docx => "docx",
            Self::Xlsx => "xlsx",
            Self::Pptx => "pptx",
            Self::Odt => "odt",
            Self::Ods => "ods",
            Self::Odp => "odp",
        }
    }
}

impl std::fmt::Display for Format {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Jpeg => "JPEG",
            Self::Png => "PNG",
            Self::Webp => "WebP",
            Self::Pdf => "PDF",
            Self::Tiff => "TIFF",
            Self::Gif => "GIF",
            Self::Heif => "HEIF",
            Self::Avif => "AVIF",
            Self::Docx => "DOCX",
            Self::Xlsx => "XLSX",
            Self::Pptx => "PPTX",
            Self::Odt => "ODT",
            Self::Ods => "ODS",
            Self::Odp => "ODP",
        })
    }
}

/// How far into a file the PDF header is allowed to appear.
///
/// ISO 32000-1 requires `%PDF-` at the start, but Adobe's own implementation notes have long
/// tolerated leading bytes, and real-world files — particularly ones that have been through
/// an email gateway or a broken CGI script — routinely carry a preamble. Readers accept it,
/// so a file with a preamble *is* a PDF in every way that matters to the user, and refusing
/// to recognise it would leave that user believing they had an exotic file rather than a
/// slightly damaged ordinary one. The window is bounded because scanning an arbitrary
/// distance into an arbitrary file is how a detector becomes a denial-of-service target.
const PDF_HEADER_SEARCH_WINDOW: usize = 1024;

/// Identify `data` by content.
///
/// # Errors
///
/// Returns [`StryptError::UnsupportedFormat`] when the content is recognised but has no
/// handler in this release, and [`StryptError::UnrecognisedFormat`] when it matches nothing.
/// Both are reported to the user; neither is ever treated as "pass the file through
/// unchanged", which is the failure this whole module exists to prevent.
pub fn detect(data: &[u8]) -> Result<Format> {
    if let Some(format) = detect_supported(data) {
        return Ok(format);
    }
    if let Some(kind) = detect_unsupported(data) {
        return Err(StryptError::UnsupportedFormat { format: kind });
    }
    Err(StryptError::UnrecognisedFormat)
}

/// Match the formats this release handles. Exact magic numbers are checked before the PDF
/// header scan, so that a `%PDF-` string sitting inside a JPEG's EXIF block cannot cause a
/// mis-dispatch.
fn detect_supported(data: &[u8]) -> Option<Format> {
    // JPEG: SOI (FFD8) immediately followed by the first marker's FF prefix. Checking the
    // third byte rejects a bare FFD8 that starts some other file by coincidence.
    if starts_with(data, &[0xFF, 0xD8, 0xFF]) {
        return Some(Format::Jpeg);
    }
    // PNG signature, ISO/IEC 15948 §5.2. The CR-LF-EOF-LF tail exists to detect exactly the
    // kind of transfer corruption that would otherwise silently truncate a file.
    if starts_with(data, &[0x89, b'P', b'N', b'G', 0x0D, 0x0A, 0x1A, 0x0A]) {
        return Some(Format::Png);
    }
    if is_riff_with_form(data, *b"WEBP") {
        return Some(Format::Webp);
    }
    // TIFF byte-order mark followed by the magic number 42, in that byte order. BigTIFF
    // spells 43 here and is refused by the handler by name rather than matched as TIFF.
    if starts_with(data, &[b'I', b'I', 0x2A, 0x00]) || starts_with(data, &[b'M', b'M', 0x00, 0x2A])
    {
        return Some(Format::Tiff);
    }
    // GIF89a and its predecessor. §17 fixes the signature and the version as six bytes together,
    // and the handler treats both spellings alike — an `87a` file carrying extensions is common,
    // and no decoder enforces the version string either.
    if starts_with(data, b"GIF87a") || starts_with(data, b"GIF89a") {
        return Some(Format::Gif);
    }
    if let Some(format) = iso_base_media_still(data) {
        return Some(format);
    }
    if find_pdf_header(data).is_some() {
        return Some(Format::Pdf);
    }
    if let Some(Package::Ooxml(format) | Package::OpenDocument(format)) = zip_package(data) {
        return Some(format);
    }
    None
}

/// Name formats we can identify but do not yet handle, so a refusal can say something useful.
fn detect_unsupported(data: &[u8]) -> Option<UnsupportedKind> {
    // ZIP local-file, end-of-central-directory, and spanned-archive signatures. All three
    // reach the same place for us: OOXML, ODF, and plain archives are Phase 2.
    if starts_with(data, b"PK\x03\x04")
        || starts_with(data, b"PK\x05\x06")
        || starts_with(data, b"PK\x07\x08")
    {
        // A macro-enabled document is named specifically, because the advice differs. It is not
        // "Phase 2 will get to this": its `vbaProject.bin` is an OLE compound file strypt cannot
        // read, and a document reported clean while a container inside it went unexamined is the
        // failure in `docs/THREAT_MODEL.md` §5.4 (ADR-0029).
        return Some(match zip_package(data) {
            Some(Package::MacroEnabled) => UnsupportedKind::MacroEnabledOffice,
            // A drawing, a formula, a chart, or any `-template` variant: understood, named, and
            // declined. `docs/ROADMAP.md` Phase 2 group 2 is the three document types, and
            // widening it is a superseding ADR rather than a judgement call (ADR-0027).
            Some(Package::OtherOpenDocument) => UnsupportedKind::OtherOpenDocument,
            _ => UnsupportedKind::ZipContainer,
        });
    }
    // BigTIFF: the same byte-order marks, but spelling 43. Named separately from the TIFF the
    // handler accepts, because its eight-byte offsets are a different layout (ADR-0033).
    if starts_with(data, &[b'I', b'I', 0x2B, 0x00]) || starts_with(data, &[b'M', b'M', 0x00, 0x2B])
    {
        return Some(UnsupportedKind::BigTiff);
    }
    // Any remaining ISO base-media file: MP4, M4A, and the motion HEIF spellings. The still-image
    // brands were matched as supported formats above, so what reaches here is genuinely a
    // container this release does not handle.
    if data.get(4..8) == Some(b"ftyp") {
        return Some(UnsupportedKind::IsoBaseMedia);
    }
    if starts_with(data, b"OggS") {
        return Some(UnsupportedKind::Ogg);
    }
    if starts_with(data, b"fLaC") {
        return Some(UnsupportedKind::Flac);
    }
    // ID3v2-tagged MP3, or a bare MPEG audio frame sync (11 set bits).
    if starts_with(data, b"ID3") {
        return Some(UnsupportedKind::Mp3);
    }
    if let (Some(&0xFF), Some(&second)) = (data.first(), data.get(1))
        && (second & 0xE0) == 0xE0
    {
        return Some(UnsupportedKind::Mp3);
    }
    // Any other RIFF payload: WAV, AVI, and friends.
    if starts_with(data, b"RIFF") {
        return Some(UnsupportedKind::OtherRiff);
    }
    if looks_like_xml(data) {
        return Some(UnsupportedKind::Xml);
    }
    None
}

/// What a ZIP package turned out to be.
enum Package {
    /// An Office Open XML package this release handles.
    Ooxml(Format),
    /// A macro-enabled Office document, refused rather than handled.
    MacroEnabled,
    /// An `OpenDocument` package this release handles.
    OpenDocument(Format),
    /// An `OpenDocument` package of a type this release does not handle — a drawing, a formula,
    /// a chart, a database, or any of the `-template` variants.
    OtherOpenDocument,
}

/// The main-part content type each supported format declares for itself.
///
/// ECMA-376 Part 2: `[Content_Types].xml` is the package's own statement of what it holds, and
/// it is the only place in the file that answers the question authoritatively.
const OOXML_MAIN_TYPES: [(&str, Format); 3] = [
    ("wordprocessingml.document.main+xml", Format::Docx),
    ("spreadsheetml.sheet.main+xml", Format::Xlsx),
    ("presentationml.presentation.main+xml", Format::Pptx),
];

/// The macro-enabled counterparts, matched only so the refusal can name them.
const OOXML_MACRO_TYPES: [&str; 3] = [
    "wordprocessingml.document.macroEnabled.main+xml",
    "spreadsheetml.sheet.macroEnabled.main+xml",
    "presentationml.presentation.macroEnabled.main+xml",
];

/// How much of an index part is inflated to answer the question.
///
/// `[Content_Types].xml` and `META-INF/manifest.xml` are each a few kilobytes in any real
/// document, and `mimetype` is one line. Bounding the inflate keeps detection — which sees every
/// byte of every file the user offers, including files no handler will accept — from becoming
/// somewhere an attacker can make strypt do work.
const INDEX_PART_BUDGET: u64 = 4 * 1024 * 1024;

/// Identify a ZIP package by what it declares about itself.
///
/// Every failure returns [`None`], which routes the file to the generic ZIP refusal. Detection
/// is not the place to explain why an archive is malformed; the handler that gets a real
/// package is.
fn zip_package(data: &[u8]) -> Option<Package> {
    let entries =
        crate::container::zip::read(data, &crate::formats::ParseLimits::default()).ok()?;
    // OpenDocument is checked first because its answer is cheaper and unambiguous: a one-line
    // `mimetype` entry, which no OOXML package has.
    opendocument_package(&entries).or_else(|| ooxml_package(&entries))
}

/// The contents of `name`, when the package has such an entry and it is text.
fn index_part(entries: &[crate::container::zip::Entry<'_>], name: &str) -> Option<String> {
    let entry = entries
        .iter()
        .find(|entry| entry.name_str() == Some(name))?;
    let bytes = entry.contents(INDEX_PART_BUDGET).ok()?;
    std::str::from_utf8(bytes.as_ref()).ok().map(str::to_owned)
}

/// Identify an `OpenDocument` package by the media type it declares for itself.
///
/// ODF 1.3 Part 2 §3.3 puts that media type in a `mimetype` entry, and §4.3 puts it again on the
/// manifest's root file-entry. Both are read, because the first is optional in older packages
/// and the second is what remains when a producer omitted it.
fn opendocument_package(entries: &[crate::container::zip::Entry<'_>]) -> Option<Package> {
    let declared = index_part(entries, "mimetype")
        .map(|text| text.trim().to_owned())
        .filter(|text| text.starts_with(crate::formats::odf::MEDIA_TYPE_PREFIX))
        .or_else(|| {
            let manifest = index_part(entries, "META-INF/manifest.xml")?;
            crate::formats::odf::root_media_type_of(&manifest)
        })?;

    if !declared.starts_with(crate::formats::odf::MEDIA_TYPE_PREFIX) {
        return None;
    }
    Some(
        crate::formats::odf::format_for_media_type(&declared)
            .map_or(Package::OtherOpenDocument, Package::OpenDocument),
    )
}

/// Identify an Office Open XML package by the content type it declares for its main part.
///
/// ECMA-376 Part 2: `[Content_Types].xml` is the package's own statement of what it holds, and
/// it is the only place in the file that answers the question authoritatively.
fn ooxml_package(entries: &[crate::container::zip::Entry<'_>]) -> Option<Package> {
    let text = index_part(entries, "[Content_Types].xml")?;

    // Macro-enabled is checked first: its content type contains the plain one's spelling as a
    // substring in some producers' output, so matching the other way round would silently accept
    // a document whose VBA project nobody looked at.
    if OOXML_MACRO_TYPES
        .iter()
        .any(|candidate| text.contains(candidate))
    {
        return Some(Package::MacroEnabled);
    }
    OOXML_MAIN_TYPES
        .iter()
        .find(|(candidate, _)| text.contains(candidate))
        .map(|(_, format)| Package::Ooxml(*format))
}

/// Brands that make an ISO base-media file a still HEIF, and the format each routes to.
///
/// ISO/IEC 23008-12 §10.2 and the AVIF specification §4 both work this way: the container is the
/// same one MP4 uses, and the `ftyp` brands are what say which of them a file is. Matching on
/// `ftyp` alone — which is all this module did before the handler landed — cannot tell a
/// photograph from a video.
const STILL_BRANDS: [(&[u8; 4], Format); 7] = [
    (b"avif", Format::Avif),
    (b"avio", Format::Avif),
    (b"heic", Format::Heif),
    (b"heix", Format::Heif),
    (b"heim", Format::Heif),
    (b"heis", Format::Heif),
    // The generic HEIF image brand. Listed last so that a file declaring both `mif1` and a
    // specific brand is named by the specific one.
    (b"mif1", Format::Heif),
];

/// Brands that declare an image *sequence* rather than a still.
///
/// Matched so that such a file is **not** claimed by the still handler. It falls through to the
/// generic ISO base-media refusal, and the handler refuses the same shape again from the inside
/// when a `moov` box is present (ADR-0034). Two checks rather than one because a file may carry a
/// sequence brand without a `moov`, or a `moov` without the brand.
const SEQUENCE_BRANDS: [&[u8; 4]; 3] = [b"msf1", b"avis", b"hevc"];

/// How many bytes of `ftyp` are scanned for brands.
const BRAND_WINDOW: usize = 256;

/// Identify a still HEIF or AVIF by the brands its `ftyp` declares.
///
/// Returns [`None`] for every other ISO base-media file, including video, which then reaches
/// [`detect_unsupported`] and is refused by name. Routing an MP4 to the HEIF handler would be a
/// mis-dispatch of exactly the kind this module exists to prevent.
fn iso_base_media_still(data: &[u8]) -> Option<Format> {
    if data.get(4..8) != Some(b"ftyp") {
        return None;
    }
    // The declared box size is deliberately not trusted: a truncated or lying size is common, and
    // detection's job is to route the file to a handler that polices its own structure. The brand
    // list is read from what is actually present, bounded by a window rather than by the field.
    let window = data.get(..BRAND_WINDOW).unwrap_or(data);
    // Major brand at offset 8, minor version at 12, then compatible brands to the end.
    let major = window.get(8..12);
    let compatible = window.get(16..).unwrap_or_default();

    let brands = major
        .into_iter()
        .chain(compatible.chunks_exact(4))
        .collect::<Vec<_>>();

    // A sequence brand anywhere disqualifies the file, even alongside a still brand: an Apple Live
    // Photo declares `heic` and carries a video track, and claiming it here would mean the handler
    // had to refuse a file detection had already called a photograph.
    if brands
        .iter()
        .any(|b| SEQUENCE_BRANDS.iter().any(|s| b == &&s[..]))
    {
        return None;
    }
    for (brand, format) in STILL_BRANDS {
        if brands.iter().any(|b| b == &&brand[..]) {
            return Some(format);
        }
    }
    None
}

/// True when `data` begins with `prefix`.
fn starts_with(data: &[u8], prefix: &[u8]) -> bool {
    data.get(0..prefix.len()) == Some(prefix)
}

/// True when `data` is a RIFF container whose form type matches `form`.
///
/// The declared RIFF size is deliberately *not* trusted here — a lying size field is common
/// in truncated files, and detection's job is to route the file to a handler that will police
/// its own structure, not to validate it.
fn is_riff_with_form(data: &[u8], form: [u8; 4]) -> bool {
    let mut r = Reader::new(data);
    if r.peek(4) != Some(b"RIFF") {
        return false;
    }
    // Skip "RIFF" and the 32-bit little-endian size that follows it.
    if r.skip(8).is_none() {
        return false;
    }
    r.peek(4) == Some(form.as_slice())
}

/// Find the `%PDF-` header within the bounded search window, returning its offset.
fn find_pdf_header(data: &[u8]) -> Option<usize> {
    const HEADER: &[u8] = b"%PDF-";
    let window = data.get(0..PDF_HEADER_SEARCH_WINDOW).unwrap_or(data);
    window
        .windows(HEADER.len())
        .position(|candidate| candidate == HEADER)
}

/// Crude XML sniff: skip a UTF-8 BOM and leading whitespace, then look for a tag opener.
///
/// Only used to *name* an unsupported format, so a false positive costs the user a slightly
/// wrong noun in a refusal message, never a mis-dispatch to a handler.
fn looks_like_xml(data: &[u8]) -> bool {
    let mut r = Reader::new(data);
    if r.peek(3) == Some(&[0xEF, 0xBB, 0xBF]) && r.skip(3).is_none() {
        return false;
    }
    // Bounded: a file of nothing but whitespace must not spin.
    for _ in 0..64 {
        match r.peek(1) {
            Some([b' ' | b'\t' | b'\r' | b'\n']) => {
                if r.skip(1).is_none() {
                    return false;
                }
            }
            _ => break,
        }
    }
    r.peek(5) == Some(b"<?xml") || r.peek(4) == Some(b"<svg") || r.peek(9) == Some(b"<!DOCTYPE")
}

#[cfg(test)]
mod tests {
    // Test code is never reachable from untrusted bytes, which is the boundary the
    // panic-freedom lints exist to police (ADR-0006). A test that cannot say `.unwrap()` says
    // everything twice instead, and the noise hides the assertion that matters.
    #![allow(clippy::unwrap_used)]

    use super::*;

    #[test]
    fn the_four_supported_formats_are_recognised() {
        assert_eq!(detect(&[0xFF, 0xD8, 0xFF, 0xE0]).unwrap(), Format::Jpeg);
        assert_eq!(
            detect(&[0x89, b'P', b'N', b'G', 0x0D, 0x0A, 0x1A, 0x0A]).unwrap(),
            Format::Png
        );
        assert_eq!(
            detect(b"RIFF\x00\x00\x00\x00WEBPVP8 ").unwrap(),
            Format::Webp
        );
        assert_eq!(detect(b"%PDF-1.7\n").unwrap(), Format::Pdf);
    }

    #[test]
    fn both_gif_spellings_route_to_the_handler() {
        // `87a` predates extension blocks, but files spelling it while carrying them are common
        // and no decoder enforces the version string. Both reach the same handler.
        assert_eq!(
            detect(b"GIF87a\x01\x00\x01\x00\x00\x00\x00").unwrap(),
            Format::Gif
        );
        assert_eq!(
            detect(b"GIF89a\x01\x00\x01\x00\x00\x00\x00").unwrap(),
            Format::Gif
        );
    }

    #[test]
    fn a_pdf_named_jpg_is_still_a_pdf() {
        // The mis-dispatch guard from docs/ARCHITECTURE.md §1. Detection never sees the name,
        // which is precisely why this cannot go wrong.
        assert_eq!(
            detect(b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n").unwrap(),
            Format::Pdf
        );
    }

    #[test]
    fn a_pdf_header_inside_a_jpeg_does_not_win() {
        // A hostile file could embed "%PDF-" in an EXIF comment to try to steer dispatch.
        // Exact magic numbers are matched first, so the JPEG handler keeps the file.
        let mut data = vec![0xFF, 0xD8, 0xFF, 0xE1];
        data.extend_from_slice(b"junk %PDF-1.7 junk");
        assert_eq!(detect(&data).unwrap(), Format::Jpeg);
    }

    #[test]
    fn a_pdf_with_a_leading_preamble_is_recognised() {
        // Real-world files mangled by gateways carry junk before the header, and readers
        // accept them — so a user with one has an ordinary PDF, not an exotic file.
        let mut data = b"\r\n<!-- inserted by a broken proxy -->\r\n".to_vec();
        data.extend_from_slice(b"%PDF-1.5\n");
        assert_eq!(detect(&data).unwrap(), Format::Pdf);
    }

    #[test]
    fn a_pdf_header_beyond_the_search_window_is_not_scanned_for() {
        // Bounding the scan is what stops detection becoming a denial-of-service target on
        // large files that mention "%PDF-" somewhere in the middle.
        let mut data = vec![b'x'; PDF_HEADER_SEARCH_WINDOW];
        data.extend_from_slice(b"%PDF-1.7\n");
        assert!(matches!(
            detect(&data),
            Err(StryptError::UnrecognisedFormat)
        ));
    }

    #[test]
    fn a_non_webp_riff_is_named_rather_than_mishandled() {
        // WAV shares WebP's container. Routing it to the WebP handler would be a
        // mis-dispatch; calling it "unrecognised" would be unhelpful. Name it.
        let e = detect(b"RIFF\x00\x00\x00\x00WAVEfmt ").unwrap_err();
        assert!(matches!(
            e,
            StryptError::UnsupportedFormat {
                format: UnsupportedKind::OtherRiff
            }
        ));
    }

    #[test]
    fn phase_two_formats_are_named_in_the_refusal() {
        for (bytes, expected) in [
            (&b"PK\x03\x04"[..], UnsupportedKind::ZipContainer),
            (&b"II\x2B\x00"[..], UnsupportedKind::BigTiff),
            (&b"OggS"[..], UnsupportedKind::Ogg),
            (&b"fLaC"[..], UnsupportedKind::Flac),
            (&b"ID3\x04"[..], UnsupportedKind::Mp3),
            // MP4 shares HEIF's container, so what makes it unsupported is the brand, not `ftyp`.
            (
                &b"\x00\x00\x00\x18ftypisom\x00\x00\x02\x00isomiso2"[..],
                UnsupportedKind::IsoBaseMedia,
            ),
            (&b"<?xml version=\"1.0\"?><svg/>"[..], UnsupportedKind::Xml),
        ] {
            let got = detect(bytes).unwrap_err();
            assert!(
                matches!(got, StryptError::UnsupportedFormat { format } if format == expected),
                "detecting {expected:?} gave {got:?}"
            );
        }
    }

    #[test]
    fn still_image_brands_route_to_the_handler_and_video_does_not() {
        // The whole of this format's detection is the brand list: `ftyp` alone cannot tell a
        // photograph from a film, and routing a video to the still handler would mean reporting
        // a stripped photograph for a file that is neither.
        for (brand, expected) in [
            (&b"avif"[..], Format::Avif),
            (&b"heic"[..], Format::Heif),
            (&b"mif1"[..], Format::Heif),
        ] {
            let mut data = vec![0, 0, 0, 0x14];
            data.extend_from_slice(b"ftyp");
            data.extend_from_slice(brand);
            data.extend_from_slice(&[0, 0, 0, 0]);
            data.extend_from_slice(brand);
            assert_eq!(detect(&data).unwrap(), expected, "brand {brand:?}");
        }
    }

    #[test]
    fn a_sequence_brand_is_not_claimed_as_a_still_image() {
        // An Apple Live Photo declares a still brand *and* a sequence one. Claiming it here would
        // mean detection calling it a photograph and the handler then having to refuse it.
        let mut data = vec![0, 0, 0, 0x18];
        data.extend_from_slice(b"ftypheic\x00\x00\x00\x00heicmsf1");
        assert!(matches!(
            detect(&data),
            Err(StryptError::UnsupportedFormat {
                format: UnsupportedKind::IsoBaseMedia
            })
        ));
    }

    #[test]
    fn nothing_recognisable_is_an_error_never_a_silent_pass() {
        // The single most dangerous outcome this tool can produce is "success" on a file it
        // did not process (docs/THREAT_MODEL.md §5.4). There is no Ok path here.
        assert!(matches!(detect(b""), Err(StryptError::UnrecognisedFormat)));
        assert!(matches!(
            detect(b"hello world"),
            Err(StryptError::UnrecognisedFormat)
        ));
    }

    #[test]
    fn truncated_magic_numbers_do_not_panic() {
        // Every prefix of every signature, including the empty one.
        let signatures: [&[u8]; 4] = [
            &[0xFF, 0xD8, 0xFF],
            &[0x89, b'P', b'N', b'G', 0x0D, 0x0A, 0x1A, 0x0A],
            b"RIFF\x00\x00\x00\x00WEBP",
            b"%PDF-1.7",
        ];
        for sig in signatures {
            for n in 0..=sig.len() {
                let prefix = sig.get(0..n).unwrap_or_default();
                let _ = detect(prefix);
            }
        }
    }
}
