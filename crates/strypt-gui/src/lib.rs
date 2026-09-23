//! The GUI's only path into `strypt-core`, kept apart from the UI so the byte-identity test
//! (ROADMAP Phase 5, exit criterion 1) exercises exactly what the window calls.

#![forbid(unsafe_code)]

use std::path::{Path, PathBuf};

use strypt_core::report::StripReport;
use strypt_core::{Limits, Overwrite, Result, StripOptions, strip_file, stripped_path};

/// Strip `input` into core's `*.stripped.*` copy, beside it or in `output_dir`, under the CLI's
/// defaults: its size limit, refusing to overwrite, owner-only permissions. Returns where the copy
/// went.
///
/// Reads through `strypt-core`, never egui's `DroppedFile::bytes`, which has no size bound.
///
/// # Errors
///
/// Whatever [`strip_file`] returns; nothing is written on error.
pub fn clean(input: &Path, output_dir: Option<&Path>) -> Result<(PathBuf, StripReport)> {
    let output = stripped_path(input, output_dir);
    let report = strip_file(
        input,
        &output,
        Limits::default(),
        Overwrite::Refuse,
        &StripOptions::default(),
    )?;
    Ok((output, report))
}
