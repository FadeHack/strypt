//! The GUI's only path into `strypt-core`, kept apart from the UI so the byte-identity test
//! (ROADMAP Phase 5, exit criterion 1) exercises exactly what the window calls.

#![forbid(unsafe_code)]

use std::path::{Path, PathBuf};

use strypt_core::io::read_bounded;
use strypt_core::report::{
    Finding, InspectOptions, MetadataReport, Note, Retained, Sensitivity, StripReport,
};
use strypt_core::{
    Limits, Overwrite, Result, StripOptions, StryptError, inspect_bytes, strip_bytes_to_file,
    stripped_path,
};

// The CLI's words, compiled here too so the two front-ends cannot drift (ADR-0060).
#[path = "../../strypt/src/wording.rs"]
mod wording;

/// Strip `input` into core's `*.stripped.*` copy, beside it or in `output_dir`, under the CLI's
/// defaults: its size limit, refusing to overwrite, owner-only permissions. Returns where the copy
/// went and what was found beforehand.
///
/// Reads through `strypt-core`, never egui's `DroppedFile::bytes`, which has no size bound.
///
/// # Errors
///
/// Whatever [`strypt_core::strip_file`] returns; nothing is written on error.
pub fn clean(input: &Path, output_dir: Option<&Path>) -> Result<(PathBuf, Diff)> {
    let output = stripped_path(input, output_dir);
    let data = read_bounded(input, Limits::default())?;
    let found = inspect_bytes(&data, &InspectOptions::names_only())?;
    let stripped =
        strip_bytes_to_file(&data, &output, Overwrite::Refuse, &StripOptions::default())?;
    Ok((output, Diff { found, stripped }))
}

/// What one file held before stripping, and what stripping removed and kept. Names only: the
/// inspection never asks for values.
#[derive(Debug)]
pub struct Diff {
    /// The original, inspected before stripping.
    pub found: MetadataReport,
    /// What the strip removed, kept and noted.
    pub stripped: StripReport,
}

/// One item in a [`Section`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Line {
    /// The CLI's `!!`/`!`/`?` mark; empty for the least sensitive, and for kept items and notes.
    pub mark: &'static str,
    /// The mark in words, for a tooltip.
    pub sensitivity: Option<&'static str>,
    /// The item, by name.
    pub text: String,
}

/// One heading of the diff. An empty section still says so.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Section {
    /// The heading.
    pub title: &'static str,
    /// Its items.
    pub lines: Vec<Line>,
    /// What to show when there are none.
    pub empty: &'static str,
}

/// What the `!!` and `!` marks mean.
pub const SENSITIVITY_KEY: &str = "!! can identify someone or somewhere on its own. ! can identify when combined with other details.";

/// The opening caveat of `KNOWN_LIMITATIONS.md`.
pub const NOTHING_FOUND: &str = "Finding nothing does not mean a file is clean. \
                                 It means strypt found nothing it knows to look for.";

impl Diff {
    /// Found, removed, kept and notes, in that order.
    #[must_use]
    pub fn sections(&self) -> [Section; 4] {
        let mut notes = self.found.notes.clone();
        for note in &self.stripped.notes {
            if !notes.contains(note) {
                notes.push(note.clone());
            }
        }
        [
            Section {
                title: "Found in the original",
                lines: self.found.findings.iter().map(finding_line).collect(),
                empty: "Nothing strypt knows to look for.",
            },
            Section {
                title: "Removed",
                lines: self.stripped.removed.iter().map(finding_line).collect(),
                empty: "Nothing.",
            },
            Section {
                title: "Kept, and why",
                lines: self.stripped.retained.iter().map(kept_line).collect(),
                empty: "Nothing that strypt could see.",
            },
            Section {
                title: "Notes",
                lines: notes.iter().map(note_line).collect(),
                empty: "None.",
            },
        ]
    }

    /// One line for a collapsed diff.
    #[must_use]
    pub fn summary(&self) -> String {
        let count = |n: usize| {
            if n == 1 {
                "1 item".to_string()
            } else {
                format!("{n} items")
            }
        };
        let (found, removed, kept) = (
            self.found.findings.len(),
            self.stripped.removed.len(),
            self.stripped.retained.len(),
        );
        if found + removed + kept == 0 {
            return "Found nothing to remove".to_string();
        }
        format!(
            "Found {}, removed {}, kept {}",
            count(found),
            count(removed),
            count(kept)
        )
    }

    /// Shown under every diff, whatever it holds.
    #[must_use]
    pub fn caveats() -> [String; 2] {
        [
            format!("{}.", capitalise(wording::NOT_TOUCHED)),
            NOTHING_FOUND.to_string(),
        ]
    }
}

fn finding_line(finding: &Finding) -> Line {
    let mut text = format!(
        "{}, in {}",
        capitalise(wording::kind_label(finding.kind)),
        finding.location
    );
    if let Some(field) = &finding.field {
        text.push_str(", field ");
        text.push_str(field);
    }
    Line {
        mark: wording::sensitivity_mark(finding.sensitivity()),
        sensitivity: Some(sensitivity_words(finding.sensitivity())),
        text,
    }
}

const fn sensitivity_words(sensitivity: Sensitivity) -> &'static str {
    match sensitivity {
        Sensitivity::Direct => "Can identify someone or somewhere on its own",
        Sensitivity::Correlating => "Can identify when combined with other details",
        Sensitivity::Incidental => "Unlikely to identify anyone by itself",
        _ => "This version of strypt does not recognise how sensitive this is",
    }
}

fn kept_line(retained: &Retained) -> Line {
    Line {
        mark: "",
        sensitivity: None,
        text: format!(
            "{}: kept because {}",
            retained.location,
            wording::retention_reason(retained.reason)
        ),
    }
}

fn note_line(note: &Note) -> Line {
    Line {
        mark: "",
        sensitivity: None,
        text: format!("{}.", capitalise(&wording::note_line(note))),
    }
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
        /// What was found, removed and kept.
        diff: Diff,
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
            // The folder too: a copy lands beside its original, wherever that is.
            Self::Cleaned { output, diff } => {
                let name = output.file_name().unwrap_or_default().to_string_lossy();
                let folder = output.parent().unwrap_or(Path::new("")).display();
                if diff.stripped.removed.is_empty() {
                    format!("Nothing to remove; saved a copy as {name} in {folder}")
                } else {
                    format!("Saved as {name} in {folder}")
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
        Ok((output, diff)) => Status::Cleaned { output, diff },
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

/// Which windowing backend to start on Linux. winit 0.30 delivers no file drops under Wayland
/// (ADR-0059).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Backend {
    /// Not a Wayland session: winit's own choice already has drops.
    Default,
    /// Wayland with an X server beside it: start on X11 so drops work.
    X11,
    /// Wayland alone: start there, and say that dragging will not work.
    WaylandWithoutDrops,
}

impl Backend {
    /// Choose from whether `DISPLAY` and `WAYLAND_DISPLAY` (or `WAYLAND_SOCKET`) are set.
    #[must_use]
    pub const fn choose(x11: bool, wayland: bool) -> Self {
        match (wayland, x11) {
            (true, true) => Self::X11,
            (true, false) => Self::WaylandWithoutDrops,
            (false, _) => Self::Default,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn x11_is_chosen_only_under_wayland_with_xwayland() {
        assert_eq!(Backend::choose(true, true), Backend::X11);
        assert_eq!(Backend::choose(false, true), Backend::WaylandWithoutDrops);
        assert_eq!(Backend::choose(true, false), Backend::Default);
        assert_eq!(Backend::choose(false, false), Backend::Default);
    }

    use strypt_core::report::{MetadataKind, RetentionReason};

    const KINDS: [MetadataKind; 11] = [
        MetadataKind::Location,
        MetadataKind::DeviceIdentity,
        MetadataKind::PersonalIdentity,
        MetadataKind::SoftwareFingerprint,
        MetadataKind::Timestamp,
        MetadataKind::Thumbnail,
        MetadataKind::EditingHistory,
        MetadataKind::DocumentIdentifier,
        MetadataKind::ColourProfile,
        MetadataKind::Comment,
        MetadataKind::Other,
    ];

    /// A label a person can read: not a fallback, not a Rust name, no banned word.
    fn assert_human(text: &str, debug: &str) {
        let lower = text.to_lowercase();
        assert!(!lower.contains("recognise"), "fallback wording: {text}");
        // `Location` is also English; `DeviceIdentity` is only Rust.
        if debug.chars().skip(1).any(char::is_uppercase) {
            assert!(!text.contains(debug), "Debug name {debug} in: {text}");
        }
        for banned in ["complete", "guarantee", "100%"] {
            assert!(!lower.contains(banned), "{banned} in: {text}");
        }
    }

    #[test]
    fn every_kind_and_rank_has_a_human_label() {
        for kind in KINDS {
            let line = finding_line(&Finding::new(kind, "loc", 1));
            assert_human(&line.text, &format!("{kind:?}"));
            assert_human(
                line.sensitivity.unwrap(),
                &format!("{:?}", kind.sensitivity()),
            );
        }
        let marks: Vec<_> = [
            Sensitivity::Direct,
            Sensitivity::Correlating,
            Sensitivity::Incidental,
        ]
        .map(wording::sensitivity_mark)
        .into();
        assert_eq!(marks, ["!!", "!", ""], "the CLI's marks");
    }

    #[test]
    fn every_kept_reason_has_a_human_label() {
        for reason in [
            RetentionReason::RemovalWouldAlterPayload,
            RetentionReason::StructurallyRequired,
            RetentionReason::DerivedFromPayload,
        ] {
            assert_human(wording::retention_reason(reason), &format!("{reason:?}"));
        }
    }

    #[test]
    fn every_note_has_a_human_label() {
        let notes = [
            Note::UnparsedRegion {
                location: "loc".into(),
                bytes: 1,
            },
            Note::IncrementalHistory { revisions: 2 },
            Note::OrphanedObjectsRemoved { objects: 3 },
            Note::OutOfScopeContent {
                location: "loc".into(),
            },
            Note::FilenameMayIdentify,
            Note::CapabilityRemoved {
                location: "loc".into(),
                capability: "do something".into(),
            },
        ];
        for note in &notes {
            let debug = format!("{note:?}");
            let name = debug.split([' ', '{']).next().unwrap_or_default();
            assert_human(&note_line(note).text, name);
        }
    }
}
