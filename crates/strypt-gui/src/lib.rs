//! The GUI's only path into `strypt-core`, kept apart from the UI so the byte-identity test
//! (ROADMAP Phase 5, exit criterion 1) exercises exactly what the window calls.

#![forbid(unsafe_code)]

use std::path::{Path, PathBuf};

use strypt_core::report::StripReport;
use strypt_core::{
    Limits, Overwrite, Result, StripOptions, StryptError, strip_file, stripped_path,
};

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

/// One dropped file's state. Only [`Status::Cleaned`] means a file was written (hard constraint 6).
#[derive(Debug)]
pub enum Status {
    /// Queued or being stripped.
    Working,
    /// A verified copy was written.
    Cleaned {
        /// Where the copy went.
        output: PathBuf,
        /// What came out and what was kept.
        report: StripReport,
    },
    /// Nothing was written; the reason is the CLI's.
    Refused(String),
    /// No handler for this format; nothing was written.
    Unsupported(String),
}

/// How a row is drawn. Only a cleaned file gets [`Tone::Success`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tone {
    /// Cleaned.
    Success,
    /// Refused or unsupported.
    Failure,
    /// Still working.
    Pending,
}

impl Status {
    /// The row's first word or two.
    #[must_use]
    pub const fn headline(&self) -> &'static str {
        match self {
            Self::Working => "Working…",
            Self::Cleaned { .. } => "Cleaned",
            Self::Refused(_) => "Not cleaned",
            Self::Unsupported(_) => "Not cleaned: unsupported",
        }
    }

    /// How the row is coloured.
    #[must_use]
    pub const fn tone(&self) -> Tone {
        match self {
            Self::Working => Tone::Pending,
            Self::Cleaned { .. } => Tone::Success,
            Self::Refused(_) | Self::Unsupported(_) => Tone::Failure,
        }
    }

    /// The line under the headline: where the copy went, or why there is none.
    #[must_use]
    pub fn detail(&self) -> String {
        match self {
            Self::Working => String::new(),
            Self::Cleaned { output, report } => {
                let name = output.file_name().unwrap_or_default().to_string_lossy();
                if report.removed.is_empty() {
                    format!("Nothing to remove; wrote a clean copy to {name}")
                } else {
                    format!("Wrote {name}")
                }
            }
            Self::Refused(reason) | Self::Unsupported(reason) => {
                format!("{reason}. No file was written.")
            }
        }
    }
}

/// Clean one dropped path into a [`Status`], with the reason the CLI would print on failure.
#[must_use]
pub fn process(input: &Path, output_dir: Option<&Path>) -> Status {
    // The CLI refuses a directory without --recursive; the GUI has no such switch.
    if input.is_dir() {
        return Status::Refused("This is a folder; drop the files inside it instead".into());
    }
    match clean(input, output_dir) {
        Ok((output, report)) => Status::Cleaned { output, report },
        Err(StryptError::OutputExists) => Status::Refused(format!(
            "{} already exists, and strypt will not overwrite it",
            stripped_path(input, output_dir)
                .file_name()
                .unwrap_or_default()
                .to_string_lossy()
        )),
        Err(e @ (StryptError::UnsupportedFormat { .. } | StryptError::UnrecognisedFormat)) => {
            Status::Unsupported(capitalise(&e.to_string()))
        }
        Err(e) => Status::Refused(capitalise(&e.to_string())),
    }
}

fn capitalise(s: &str) -> String {
    let mut chars = s.chars();
    chars
        .next()
        .map_or_else(String::new, |c| c.to_uppercase().chain(chars).collect())
}
