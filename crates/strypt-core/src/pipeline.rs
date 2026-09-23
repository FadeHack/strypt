//! The end-to-end operations front-ends call.
//!
//! Detection, dispatch, the handler, and — the part that is easy to leave out and expensive
//! to add later — the verification pass. Front-ends should call these rather than reaching
//! for a handler directly, because the checks that make a result trustworthy live here.

use std::path::Path;

use crate::detect::{Format, detect};
use crate::error::{Result, StryptError};
use crate::formats::{StripOptions, Stripped};
use crate::io::{AtomicWrite, Limits, Overwrite, Permissions, read_bounded};
use crate::registry::handler_for;
use crate::report::{InspectOptions, MetadataReport, StripReport};

/// Report what metadata `data` contains, without modifying anything.
///
/// # Errors
///
/// Returns [`StryptError::UnsupportedFormat`] or [`StryptError::UnrecognisedFormat`] when
/// there is no handler, and the handler's own errors otherwise. There is no variant of this
/// function that quietly returns an empty report for a file it did not understand.
pub fn inspect_bytes(data: &[u8], options: &InspectOptions) -> Result<MetadataReport> {
    let format = detect(data)?;
    handler(format)?.inspect(data, options)
}

/// Produce a sanitised copy of `data` in memory, verified before it is returned.
///
/// The output is re-inspected here, and metadata that survived the strip fails the whole
/// operation. That check is the reason this function exists rather than callers using a
/// handler directly: it converts an entire class of handler bug — one that removes less than
/// it reports — from a silent leak into a loud refusal (`docs/ARCHITECTURE.md` §1 stage 5).
///
/// What it cannot do is find metadata the inspector does not know to look for. It makes the
/// tool internally consistent, not omniscient, and `docs/THREAT_MODEL.md` §4.8 says so to
/// users in those words.
///
/// # Errors
///
/// [`StryptError::VerificationFailed`] if anything survived; otherwise the handler's errors.
pub fn strip_bytes(data: &[u8], options: &StripOptions) -> Result<Stripped> {
    let format = detect(data)?;
    let handler = handler(format)?;
    let stripped = handler.strip(data, options)?;

    // Verify through the same top-level path a user would: detect the output afresh rather
    // than assuming it is still the format we started with. A handler that emitted something
    // unparseable should fail here, not at the point where the user opens the file.
    let verified_format = detect(&stripped.bytes)?;
    if verified_format != format {
        return Err(StryptError::VerificationFailed {
            format,
            residual: 0,
        });
    }
    let residual = handler
        .inspect(&stripped.bytes, &InspectOptions::names_only())?
        .findings
        .len();
    if residual > 0 {
        return Err(StryptError::VerificationFailed { format, residual });
    }
    Ok(stripped)
}

/// Report what metadata the file at `path` contains.
///
/// # Errors
///
/// As [`inspect_bytes`], plus [`StryptError::Io`] and [`StryptError::InputTooLarge`].
pub fn inspect_file(
    path: &Path,
    limits: Limits,
    options: &InspectOptions,
) -> Result<MetadataReport> {
    let data = read_bounded(path, limits)?;
    inspect_bytes(&data, options)
}

/// Strip `input` and write the result to `output`.
///
/// Nothing is written unless the whole operation succeeds and the output passes verification:
/// on any failure the destination is left exactly as it was, and no partial file is left
/// anywhere for a user to mistake for a clean copy.
///
/// # Errors
///
/// As [`strip_bytes`], plus [`StryptError::Io`] if the output cannot be written.
pub fn strip_file(
    input: &Path,
    output: &Path,
    limits: Limits,
    overwrite: Overwrite,
    options: &StripOptions,
) -> Result<StripReport> {
    let data = read_bounded(input, limits)?;
    strip_bytes_to_file(&data, output, overwrite, options)
}

/// [`strip_file`] for bytes already read, so a front-end that inspects first reads the file once.
///
/// # Errors
///
/// As [`strip_bytes`], plus [`StryptError::Io`] if the output cannot be written.
pub fn strip_bytes_to_file(
    data: &[u8],
    output: &Path,
    overwrite: Overwrite,
    options: &StripOptions,
) -> Result<StripReport> {
    let stripped = strip_bytes(data, options)?;

    let mut writer = AtomicWrite::begin(output, overwrite, Permissions::OwnerOnly)?;
    writer.write_all(&stripped.bytes)?;
    writer.commit()?;
    Ok(stripped.report)
}

/// The handler for `format`, or a reported refusal.
fn handler(format: Format) -> Result<&'static dyn crate::formats::MetadataHandler> {
    handler_for(format).ok_or(StryptError::UnsupportedFormat {
        format: match format {
            // A format strypt recognises but has not implemented yet is still a refusal. The
            // one outcome that must never exist is a success message about a file that was
            // copied through untouched (`docs/THREAT_MODEL.md` §5.4).
            Format::Jpeg
            | Format::Png
            | Format::Webp
            | Format::Pdf
            | Format::Tiff
            | Format::Gif
            | Format::Heif
            | Format::Avif
            | Format::Docx
            | Format::Xlsx
            | Format::Pptx
            | Format::Odt
            | Format::Ods
            | Format::Odp
            | Format::Svg
            | Format::Jxl
            | Format::Flac
            | Format::Wav
            | Format::Mp3
            | Format::Ogg
            | Format::Opus
            | Format::OggFlac
            | Format::Mp4
            | Format::M4a => crate::error::UnsupportedKind::NotYetImplemented(format),
        },
    })
}
