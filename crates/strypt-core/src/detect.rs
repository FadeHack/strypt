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
use crate::formats::{jxl, ogg};

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
    /// SVG, which is XML text rather than a container of encoded pixels.
    Svg,
    /// JPEG XL, in either of its two spellings: a bare codestream or a BMFF container.
    Jxl,
    /// FLAC, in its native spelling — a `fLaC` marker and a list of metadata blocks.
    Flac,
    /// WAV: a RIFF container of form type `WAVE`. RF64 and BW64 are a different container and
    /// are named separately in `detect_unsupported`.
    Wav,
    /// MP3: MPEG-1 Audio Layer III frames, with or without the tags glued to either end of them.
    Mp3,
    /// Ogg Vorbis. One handler serves all three Ogg spellings; they are separate formats here
    /// because they are separate mappings with separate header packets (ADR-0041).
    Ogg,
    /// Opus, in its Ogg encapsulation (RFC 7845). The only encapsulation strypt handles.
    Opus,
    /// FLAC carried in Ogg pages rather than in its native container.
    OggFlac,
    /// MP4: the ISO base media file format carrying tracks. `.mp4` and `.m4v`.
    Mp4,
    /// M4A: the same container carrying audio only. `.m4a` and `.m4b`.
    M4a,
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
            Self::Svg => "svg",
            Self::Jxl => "jxl",
            Self::Flac => "flac",
            Self::Wav => "wav",
            Self::Mp3 => "mp3",
            Self::Ogg => "ogg",
            Self::Opus => "opus",
            Self::OggFlac => "ogg-flac",
            Self::Mp4 => "mp4",
            Self::M4a => "m4a",
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
            Self::Svg => "svg",
            Self::Jxl => "jxl",
            Self::Flac => "flac",
            Self::Wav => "wav",
            Self::Mp3 => "mp3",
            Self::Ogg => "ogg",
            Self::Opus => "opus",
            // `.oga` rather than `.ogg`: the Xiph naming note reserves `.ogg` for Vorbis.
            Self::OggFlac => "oga",
            Self::Mp4 => "mp4",
            Self::M4a => "m4a",
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
            Self::Svg => "SVG",
            Self::Jxl => "JPEG XL",
            Self::Flac => "FLAC",
            Self::Wav => "WAV",
            Self::Mp3 => "MP3",
            Self::Ogg => "Ogg Vorbis",
            Self::Opus => "Opus",
            Self::OggFlac => "Ogg FLAC",
            Self::Mp4 => "MP4",
            Self::M4a => "M4A",
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
    if is_riff_with_form(data, *b"WAVE") {
        return Some(Format::Wav);
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
    // JPEG XL, both spellings (ISO/IEC 18181-2 §5.2, ISO/IEC 18181-1 §9.1). The container's
    // signature box is checked before the `ftyp` sniffs below, and the bare codestream's `FF 0A`
    // is checked before the MPEG audio frame sync in `detect_unsupported`, which matches `FF`
    // followed by three set bits and would otherwise call a `.jxl` an MP3.
    if starts_with(data, &jxl::SIGNATURE_BOX) || starts_with(data, &jxl::CODESTREAM_MAGIC) {
        return Some(Format::Jxl);
    }
    // The stream marker (RFC 9639 §8). A FLAC carrying a prepended ID3v2 tag does not start with
    // it, and used to be refused by name here. It is routed to the handler now: the MP3 tranche
    // put an ID3 reader in the tree, so the tag is read and removed rather than left in front of
    // blocks strypt had cleaned (ADR-0040 lifts ADR-0038 decision 7).
    if starts_with(data, b"fLaC") || id3_precedes(data, b"fLaC") {
        return Some(Format::Flac);
    }
    // MPEG audio: an ID3v2 tag with frames behind it, or the frames on their own. It has to come
    // after JPEG XL's bare `FF 0A` codestream, which a frame sync matches, and after the FLAC
    // check above, which claims the other thing an ID3v2 tag gets stuck in front of.
    if starts_with(data, b"ID3") || crate::formats::mp3::frame_header(data).is_some() {
        return Some(Format::Mp3);
    }
    // Ogg carries somebody else's codec, so the container's magic is not the answer: the first
    // page's packet is. A mapping with no handler is named in `detect_unsupported` (ADR-0041).
    if let Some(ogg::Sniff::Supported(format)) = ogg::sniff(data) {
        return Some(format);
    }
    if let Some(format) = iso_base_media_still(data) {
        return Some(format);
    }
    // Tracks rather than a picture, and the brand list is again the whole of the answer: the same
    // `ftyp` introduces a photograph, a film, a fragmented stream and an encrypted one (ADR-0042).
    if let Some(IsoClass::Movie(format)) = iso_base_media_movie(data) {
        return Some(format);
    }
    if find_pdf_header(data).is_some() {
        return Some(Format::Pdf);
    }
    if let Some(Package::Ooxml(format) | Package::OpenDocument(format)) = zip_package(data) {
        return Some(format);
    }
    // Last, because it is the only sniff here that reads text rather than a magic number. SVG
    // has no signature at all: the format's own answer to "what is this" is its root element,
    // and finding it means stepping over an XML declaration, comments, and a doctype first.
    if is_svg(data) {
        return Some(Format::Svg);
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
    // Any remaining ISO base-media file. Still images, progressive MP4 and M4A were matched above,
    // so what is left is a shape strypt refuses by name — fragmented, encrypted, QuickTime, 3GPP —
    // or a motion HEIF, which reaches the generic refusal.
    if data.get(4..8) == Some(b"ftyp") {
        return Some(match iso_base_media_movie(data) {
            Some(IsoClass::Refused(kind)) => kind,
            _ => UnsupportedKind::IsoBaseMedia,
        });
    }
    // Theora, Speex, Skeleton, anything unrecognised, and any file carrying more than one logical
    // bitstream. Named rather than left unrecognised, for a file every player calls an Ogg.
    if let Some(ogg::Sniff::Refused(kind)) = ogg::sniff(data) {
        return Some(kind);
    }
    if starts_with(data, b"OggS") {
        return Some(UnsupportedKind::OtherOggCodec);
    }
    // RF64 (EBU Tech 3306) and BW64 (ITU-R BS.2088) spell the >4 GB case with their own magic and
    // a `ds64` chunk holding the real sizes, so a WAV handler would walk the wrong extent. Named
    // rather than left unrecognised, because "unrecognised" is untrue for a file most users would
    // call a WAV (ADR-0039).
    if starts_with(data, b"RF64") || starts_with(data, b"BW64") {
        return Some(UnsupportedKind::Rf64);
    }
    // Any other RIFF payload: AVI, and friends.
    if starts_with(data, b"RIFF") {
        return Some(UnsupportedKind::OtherRiff);
    }
    // A gzip stream, which for this project means `.svgz` far more often than anything else.
    // Named rather than left unrecognised so the message can say "decompress it first", because
    // "the content does not match any format strypt recognises" is untrue and unhelpful for a
    // common spelling of a format that *is* handled (ADR-0035).
    if starts_with(data, &[0x1F, 0x8B]) {
        return Some(UnsupportedKind::Gzip);
    }
    if looks_like_xml(data) {
        return Some(UnsupportedKind::Xml);
    }
    None
}

/// How far into a file the SVG root element is allowed to appear.
///
/// An XML declaration, a generator comment, and the SVG 1.1 doctype together run to a few
/// hundred bytes in real files, and Adobe's export writes all three. The window is generous
/// enough for them and bounded for the reason [`PDF_HEADER_SEARCH_WINDOW`] is: detection sees
/// every byte of every file offered to it, including ones no handler will accept.
const SVG_ROOT_SEARCH_WINDOW: usize = 8192;

/// True when the first element of `data` is `<svg`.
///
/// **The root element, not the presence of the string.** `<svg` appears inside any HTML page that
/// embeds a drawing, and inside an XML document that merely describes one; routing either to this
/// handler would be the mis-dispatch this module exists to prevent. The scan therefore steps over
/// exactly what may legally precede a root element — an XML declaration, comments, processing
/// instructions, and a doctype — and then requires what follows to be the element itself.
fn is_svg(data: &[u8]) -> bool {
    let window = data.get(..SVG_ROOT_SEARCH_WINDOW).unwrap_or(data);
    let Ok(text) = std::str::from_utf8(window) else {
        // Not UTF-8 within the window. A UTF-16 SVG is legal XML and is refused by the handler
        // rather than misread here (ADR-0035), and a truncated multi-byte character at the window
        // edge is not worth a second decode attempt for a sniff.
        return false;
    };
    let mut rest = text.trim_start_matches('\u{feff}').trim_start();

    // Bounded: a file of nothing but comments must not spin.
    for _ in 0..64 {
        let terminator = if rest.starts_with("<!--") {
            "-->"
        } else if rest.starts_with("<?") {
            "?>"
        } else if rest.starts_with("<!") {
            // A doctype, whose internal subset may itself contain `>`. Stopping at the first one
            // is good enough for a sniff: the handler refuses an internal subset outright.
            ">"
        } else {
            // A prefixed root — `<svg:svg>`, which very old Inkscape releases wrote — is
            // deliberately *not* claimed. The handler removes prefixed elements on an
            // allow-list (ADR-0035), so claiming it would mean removing the document. It
            // falls through to the generic XML refusal instead, which is fail-closed.
            return rest.starts_with("<svg")
                && rest
                    .get(4..5)
                    .is_none_or(|c| c.starts_with([' ', '\t', '\r', '\n', '>', '/']));
        };
        let Some(end) = rest.find(terminator) else {
            return false;
        };
        rest = rest
            .get(end.saturating_add(terminator.len())..)
            .unwrap_or_default()
            .trim_start();
    }
    false
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

/// What an ISO base-media file's brands turned out to declare.
enum IsoClass {
    /// A container of tracks this release handles.
    Movie(Format),
    /// A shape refused by name.
    Refused(UnsupportedKind),
}

/// Classify an ISO base-media file by the brands its `ftyp` declares.
///
/// Refusals are matched before acceptances, because a protected or fragmented file declares the
/// ordinary brands as well: an encrypted `.m4p` carries `M4A ` and `mp42` beside `M4P `, and
/// claiming it on the first match would route it to a handler that must then refuse it anyway.
fn iso_base_media_movie(data: &[u8]) -> Option<IsoClass> {
    use crate::formats::mp4::boxes as mp4;

    if data.get(4..8) != Some(b"ftyp") {
        return None;
    }
    // As `iso_base_media_still`: the declared box size is not trusted, and the brand list is read
    // from a bounded window of what is actually present.
    let window = data.get(..BRAND_WINDOW).unwrap_or(data);
    let brands: Vec<&[u8]> = window
        .get(8..12)
        .into_iter()
        .chain(window.get(16..).unwrap_or_default().chunks_exact(4))
        .collect();
    let has = |list: &[[u8; 4]]| {
        brands
            .iter()
            .any(|b| list.iter().any(|candidate| *b == &candidate[..]))
    };

    if has(&mp4::FRAGMENT_BRANDS) {
        return Some(IsoClass::Refused(UnsupportedKind::FragmentedMp4));
    }
    if has(&[mp4::PROTECTED_BRAND]) {
        return Some(IsoClass::Refused(UnsupportedKind::ProtectedMedia));
    }
    if has(&[mp4::QUICKTIME_BRAND]) {
        return Some(IsoClass::Refused(UnsupportedKind::QuickTimeMovie));
    }
    if brands
        .iter()
        .any(|b| b.get(..3) == Some(b"3gp") || b.get(..3) == Some(b"3g2"))
    {
        return Some(IsoClass::Refused(
            UnsupportedKind::ThirdGenerationPartnership,
        ));
    }
    // Audio first: an `.m4a` declares `mp42` and `isom` alongside `M4A `, so the more specific
    // brand has to win or every M4A would be reported as an MP4.
    if has(&mp4::M4A_BRANDS) {
        return Some(IsoClass::Movie(Format::M4a));
    }
    if has(&mp4::MP4_BRANDS) || has(&mp4::MP4_BRANDS_VIDEO) {
        return Some(IsoClass::Movie(Format::Mp4));
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

/// True when `data` opens with an `ID3v2` tag that is followed immediately by `marker`.
///
/// The tag's own header is all this reads: three bytes of identifier, a version, a flags byte, and
/// a four-byte size whose bytes carry seven bits each (ID3v2.4 §3.1). No frame is parsed — the
/// question is only what kind of file the tag was stuck on the front of.
fn id3_precedes(data: &[u8], marker: &[u8]) -> bool {
    let mut r = Reader::new(data);
    if r.skip(5).is_none() {
        return false;
    }
    let Some(flags) = r.u8() else {
        return false;
    };
    let Some(size) = r.take(4) else {
        return false;
    };
    let mut total: usize = 0;
    for byte in size {
        total = total
            .saturating_mul(128)
            .saturating_add(usize::from(byte & 0x7F));
    }
    // The size counts neither the ten-byte header it sits in nor the optional footer.
    let mut at = total.saturating_add(10);
    if flags & 0x10 != 0 {
        at = at.saturating_add(10);
    }
    data.get(at..at.saturating_add(marker.len())) == Some(marker)
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
    fn a_riff_is_routed_by_its_form_type_rather_than_by_its_magic() {
        // WAV and WebP share a container, so the form type is what tells them apart. Anything
        // else RIFF is named rather than called "unrecognised", which would be unhelpful.
        assert_eq!(
            detect(b"RIFF\x00\x00\x00\x00WAVEfmt ").unwrap(),
            Format::Wav
        );
        assert!(matches!(
            detect(b"RIFF\x00\x00\x00\x00AVI LIST").unwrap_err(),
            StryptError::UnsupportedFormat {
                format: UnsupportedKind::OtherRiff
            }
        ));
        // RF64 and BW64 are a different container, not a large WAV.
        for magic in [
            &b"RF64\x00\x00\x00\x00WAVEds64"[..],
            &b"BW64\x00\x00\x00\x00WAVEds64"[..],
        ] {
            assert!(matches!(
                detect(magic).unwrap_err(),
                StryptError::UnsupportedFormat {
                    format: UnsupportedKind::Rf64
                }
            ));
        }
    }

    #[test]
    fn mpeg_audio_is_claimed_by_its_tag_or_by_a_frame_header() {
        // A bare frame sync is only four bytes, so the reserved values in the version, layer,
        // bitrate and sampling-frequency fields are what keep `FF Ex` in an unrelated binary from
        // being read as audio (ADR-0040).
        for bytes in [
            &b"ID3\x04\x00\x00\x00\x00\x00\x00"[..],
            &b"ID3\x03\x00\x00\x00\x00\x00\x00"[..],
            // MPEG-1 Layer III, 128 kbps, 44.1 kHz.
            &b"\xFF\xFB\x90\xC0"[..],
        ] {
            assert_eq!(detect(bytes).unwrap(), Format::Mp3, "{bytes:?}");
        }
        for bytes in [
            // Reserved version, reserved layer, forbidden bitrate, forbidden sample rate.
            &b"\xFF\xEB\x90\xC0"[..],
            &b"\xFF\xF9\x90\xC0"[..],
            &b"\xFF\xFB\xF0\xC0"[..],
            &b"\xFF\xFB\x9C\xC0"[..],
        ] {
            assert!(detect(bytes).is_err(), "{bytes:?}");
        }
    }

    #[test]
    fn an_id3_prefixed_flac_is_routed_to_the_flac_handler_not_to_mp3() {
        // Both formats get an ID3v2 tag stuck in front of them, so the order of the two sniffs is
        // what tells them apart (ADR-0040).
        let mut input = b"ID3\x04\x00\x00".to_vec();
        input.extend_from_slice(&[0, 0, 0, 4]);
        input.extend_from_slice(&[0u8; 4]);
        input.extend_from_slice(b"fLaC");
        assert_eq!(detect(&input).unwrap(), Format::Flac);
    }

    #[test]
    fn phase_two_formats_are_named_in_the_refusal() {
        for (bytes, expected) in [
            (&b"PK\x03\x04"[..], UnsupportedKind::ZipContainer),
            (&b"II\x2B\x00"[..], UnsupportedKind::BigTiff),
            (&b"OggS"[..], UnsupportedKind::OtherOggCodec),
            // MP4 shares HEIF's container, so the brand is what routes it — and what refuses it.
            (
                &b"\x00\x00\x00\x18ftypdash\x00\x00\x02\x00iso6dash"[..],
                UnsupportedKind::FragmentedMp4,
            ),
            (
                &b"\x00\x00\x00\x18ftypM4P \x00\x00\x02\x00M4A mp42"[..],
                UnsupportedKind::ProtectedMedia,
            ),
            (
                &b"\x00\x00\x00\x18ftypqt  \x00\x00\x02\x00qt  qt  "[..],
                UnsupportedKind::QuickTimeMovie,
            ),
            (
                &b"\x00\x00\x00\x18ftyp3gp4\x00\x00\x02\x003gp4isom"[..],
                UnsupportedKind::ThirdGenerationPartnership,
            ),
            // An ISO base-media file whose brands name nothing at all.
            (
                &b"\x00\x00\x00\x18ftypzzzz\x00\x00\x02\x00zzzzyyyy"[..],
                UnsupportedKind::IsoBaseMedia,
            ),
            // XML that is not SVG. The SVG spelling of this is now *supported*, so what is left
            // here is a document strypt identifies as markup and declines.
            (&b"<?xml version=\"1.0\"?><rss/>"[..], UnsupportedKind::Xml),
            // A gzip stream, which for this project means `.svgz` far more often than not.
            (&b"\x1f\x8b\x08\x00"[..], UnsupportedKind::Gzip),
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
    fn movie_brands_route_to_the_mp4_handler_and_audio_wins_over_the_generic_one() {
        // An `.m4a` declares `M4A `, `mp42` and `isom` together, so the order of the two lists is
        // what keeps it from being reported as a video (ADR-0042).
        for (major, compatible, expected) in [
            (&b"isom"[..], &b"isomiso2mp41"[..], Format::Mp4),
            (&b"mp42"[..], &b"mp42isom"[..], Format::Mp4),
            (&b"M4V "[..], &b"M4V mp42"[..], Format::Mp4),
            (&b"M4A "[..], &b"M4A mp42isom"[..], Format::M4a),
            (&b"M4B "[..], &b"M4B mp42"[..], Format::M4a),
        ] {
            let mut data = vec![0, 0, 0, 0x18];
            data.extend_from_slice(b"ftyp");
            data.extend_from_slice(major);
            data.extend_from_slice(&[0, 0, 2, 0]);
            data.extend_from_slice(compatible);
            assert_eq!(detect(&data).unwrap(), expected, "brand {major:?}");
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
    fn an_svg_is_recognised_by_its_root_element_and_nothing_else() {
        // SVG has no magic number at all: the format's own answer to "what is this" is its root
        // element, reached past an XML declaration, comments, and a doctype.
        for bytes in [
            &b"<svg xmlns=\"http://www.w3.org/2000/svg\"/>"[..],
            b"\xef\xbb\xbf<svg/>",
            b"<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<svg width=\"1\"/>",
            b"<!-- Generator: Adobe Illustrator --><svg>x</svg>",
            b"<!DOCTYPE svg PUBLIC \"-//W3C//DTD SVG 1.1//EN\" \"svg11.dtd\">\n<svg/>",
        ] {
            assert_eq!(detect(bytes).unwrap(), Format::Svg, "{bytes:?}");
        }
    }

    #[test]
    fn markup_that_merely_mentions_svg_is_not_claimed_as_one() {
        // The mis-dispatch guard for a format sniffed from text rather than from a signature.
        // `<svg` appears inside any HTML page that embeds a drawing, and routing one here would
        // mean the handler editing a document it has no rules for.
        for bytes in [
            &b"<html><body><svg><rect/></svg></body></html>"[..],
            b"<?xml version=\"1.0\"?><gallery><svg/></gallery>",
            b"<svgeny/>",
            // A prefixed root, which very old Inkscape releases wrote. Not claimed, because the
            // handler removes prefixed elements on an allow-list and would remove the document.
            b"<svg:svg xmlns:svg=\"http://www.w3.org/2000/svg\"/>",
        ] {
            assert!(
                !matches!(detect(bytes), Ok(Format::Svg)),
                "wrongly claimed {bytes:?}"
            );
        }
    }

    #[test]
    fn a_root_element_beyond_the_search_window_is_not_scanned_for() {
        let mut data = b"<!--".to_vec();
        data.resize(SVG_ROOT_SEARCH_WINDOW, b'x');
        data.extend_from_slice(b"--><svg/>");
        assert!(!matches!(detect(&data), Ok(Format::Svg)));
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
