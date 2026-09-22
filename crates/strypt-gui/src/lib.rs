//! The GUI's only path into `strypt-core`, kept apart from the UI so the byte-identity test
//! (ROADMAP Phase 5, exit criterion 1) exercises exactly what the window calls.

#![forbid(unsafe_code)]

use std::path::Path;

use strypt_core::io::{Limits, read_bounded};
use strypt_core::{Result, StripOptions, Stripped, strip_bytes};

/// Read `path` under the CLI's default limits and strip it in memory.
///
/// Reads through `strypt-core`, never egui's `DroppedFile::bytes`, which has no size bound.
///
/// # Errors
///
/// Whatever [`read_bounded`] or [`strip_bytes`] returns.
pub fn clean(path: &Path) -> Result<Stripped> {
    let data = read_bounded(path, Limits::default())?;
    strip_bytes(&data, &StripOptions::default())
}
