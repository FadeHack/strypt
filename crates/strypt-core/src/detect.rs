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
//! `file-format` and `infer` were both evaluated (`docs/ARCHITECTURE.md` §4). Phase 1 needs
//! to discriminate exactly four supported formats plus a short list of formats worth *naming*
//! in a refusal, which is under a hundred lines of magic-number matching. Taking a crate with
//! broad magic tables for that would add supply-chain surface (ADR-0008) to save very little.
//! Revisit in Phase 2, when the supported-format count grows and the container types get
//! genuinely ambiguous.

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

/// Match the four formats Phase 1 handles. Exact magic numbers are checked before the PDF
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
    if find_pdf_header(data).is_some() {
        return Some(Format::Pdf);
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
        return Some(UnsupportedKind::ZipContainer);
    }
    if starts_with(data, b"GIF87a") || starts_with(data, b"GIF89a") {
        return Some(UnsupportedKind::Gif);
    }
    // TIFF byte-order marks: "II" little-endian, "MM" big-endian, each followed by 42.
    if starts_with(data, &[b'I', b'I', 0x2A, 0x00]) || starts_with(data, &[b'M', b'M', 0x00, 0x2A])
    {
        return Some(UnsupportedKind::Tiff);
    }
    // ISO base media (MP4/M4A/HEIF/AVIF): a box whose type at offset 4 is "ftyp".
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
            (&b"GIF89a"[..], UnsupportedKind::Gif),
            (&b"II\x2A\x00"[..], UnsupportedKind::Tiff),
            (&b"OggS"[..], UnsupportedKind::Ogg),
            (&b"fLaC"[..], UnsupportedKind::Flac),
            (&b"ID3\x04"[..], UnsupportedKind::Mp3),
            (
                &b"\x00\x00\x00\x18ftypavif"[..],
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
