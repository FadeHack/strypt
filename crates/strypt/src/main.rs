//! `strypt` — remove hidden identifying metadata from files.
//!
//! This crate stays thin on purpose (ADR-0003): argument parsing, walking paths, choosing
//! output names, presentation, and exit codes. Every decision about what metadata *is* and
//! what to do with it lives in `strypt-core`, so that the Phase 5 GUI and this CLI cannot
//! drift into behaving differently — and in a security tool, "subtly different" means one of
//! them is quietly less safe.

mod render;

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use clap::{Args, Parser, Subcommand};
use strypt_core::formats::StripOptions;
use strypt_core::io::{Limits, Overwrite};
use strypt_core::report::InspectOptions;
use strypt_core::{StryptError, inspect_file, strip_file};

/// Exit codes. Documented in `INSTRUCTIONS.md` and **stable across releases** — scripts and
/// pre-commit hooks depend on them, so changing one is a breaking change.
mod exit {
    /// Everything succeeded and nothing removable was found.
    pub const CLEAN: u8 = 0;
    /// `show` found metadata, or `strip` had at least one file fail.
    pub const FOUND_OR_FAILED: u8 = 1;
    /// The command line was wrong.
    ///
    /// clap exits with this itself before any of our code runs, so nothing here reads the
    /// constant. It is declared anyway because this list is the documented contract, and a
    /// contract with a hole in it invites someone to reuse 2 for something else.
    #[allow(dead_code)]
    pub const USAGE: u8 = 2;
    /// A file could not be read or written.
    pub const IO: u8 = 3;
    /// A file's format has no handler in this release.
    pub const UNSUPPORTED: u8 = 4;
    /// Output failed its post-strip verification and was discarded. This means strypt does
    /// not trust its own result — treat it as a bug report, not as a bad file.
    pub const VERIFICATION: u8 = 5;
}

#[derive(Debug, Parser)]
#[command(
    name = "strypt",
    version,
    about = "Remove hidden identifying metadata from files",
    long_about = "Detects and removes metadata — GPS coordinates, device serial numbers, \
                  author names, timestamps, editing history — from files so they are safer \
                  to publish.\n\n\
                  strypt works on file contents. It does not change filenames, does not \
                  redact anything visible in the document, and cannot remove metadata it \
                  does not know about. No tool can promise a file carries nothing \
                  identifying; see the threat model before relying on this one for anything \
                  that matters."
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Report the metadata in files without modifying anything.
    ///
    /// Exits 1 when metadata is found, so it composes in scripts and pre-commit checks.
    Show {
        #[command(flatten)]
        input: InputArgs,
        /// Print the metadata values themselves, not only the field names.
        ///
        /// Off by default: this output is easy to redirect into a file or paste into a bug
        /// report, and either turns it into a durable copy of what you are trying to remove.
        #[arg(long)]
        show_values: bool,
    },
    /// Write sanitised copies of files.
    Strip {
        #[command(flatten)]
        input: InputArgs,
        /// Overwrite the original instead of writing a copy.
        ///
        /// Never the default. The original is your only copy of the unstripped file.
        #[arg(long)]
        in_place: bool,
        /// Write outputs into this directory instead of beside their inputs.
        #[arg(long, value_name = "DIR")]
        output_dir: Option<PathBuf>,
        /// Overwrite an existing output file.
        #[arg(long)]
        force: bool,
    },
}

#[derive(Debug, Args)]
struct InputArgs {
    /// Files, or directories to process.
    #[arg(required = true, value_name = "PATH")]
    paths: Vec<PathBuf>,
    /// Descend into directories.
    #[arg(short, long)]
    recursive: bool,
    /// Emit JSON on stdout; diagnostics still go to stderr.
    #[arg(long)]
    json: bool,
    /// Refuse inputs larger than this many bytes.
    #[arg(long, value_name = "BYTES", default_value_t = Limits::DEFAULT_MAX_INPUT_BYTES)]
    max_bytes: u64,
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let code = match &cli.command {
        Command::Show { input, show_values } => run_show(input, *show_values),
        Command::Strip {
            input,
            in_place,
            output_dir,
            force,
        } => run_strip(input, *in_place, output_dir.as_deref(), *force),
    };
    ExitCode::from(code)
}

/// Accumulates the worst outcome seen across a batch.
///
/// A batch run continues past a failure and reports it, rather than stopping at the first
/// problem — but the exit code must still reflect that something went wrong, or a script
/// wrapping this will conclude every file was handled.
#[derive(Default)]
struct Outcome {
    /// Whether `show` found anything removable.
    found: bool,
    /// Whether any file was reported on, rather than failing.
    reported: bool,
    /// The most serious failure seen so far.
    worst: Failure,
}

/// Failure severities, ordered least to most alarming.
///
/// The ordering is the point: a batch that hits both an unreadable file and a verification
/// failure must exit on the verification failure, because that is the one saying strypt does
/// not trust its own output.
#[derive(Default, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Failure {
    #[default]
    None,
    Other,
    Io,
    Unsupported,
    Verification,
}

impl Outcome {
    fn record(&mut self, error: &StryptError) {
        let severity = match error {
            StryptError::Io { .. }
            | StryptError::InputTooLarge { .. }
            | StryptError::OutputExists => Failure::Io,
            StryptError::UnsupportedFormat { .. } | StryptError::UnrecognisedFormat => {
                Failure::Unsupported
            }
            StryptError::VerificationFailed { .. } => Failure::Verification,
            _ => Failure::Other,
        };
        self.worst = self.worst.max(severity);
    }

    /// Record a failure that did not come from `strypt-core` — an unreadable directory, say.
    fn record_local(&mut self, severity: Failure) {
        self.worst = self.worst.max(severity);
    }

    fn code(&self) -> u8 {
        match self.worst {
            Failure::Verification => exit::VERIFICATION,
            Failure::Unsupported => exit::UNSUPPORTED,
            Failure::Io => exit::IO,
            Failure::Other => exit::FOUND_OR_FAILED,
            Failure::None if self.found => exit::FOUND_OR_FAILED,
            Failure::None => exit::CLEAN,
        }
    }
}

fn run_show(input: &InputArgs, show_values: bool) -> u8 {
    let options = if show_values {
        InspectOptions::with_values()
    } else {
        InspectOptions::names_only()
    };
    let limits = Limits::with_max_input_bytes(input.max_bytes);
    let mut outcome = Outcome::default();
    let mut json = Vec::new();

    for path in collect(input, &mut outcome) {
        match inspect_file(&path, limits, &options) {
            Ok(report) => {
                outcome.reported = true;
                if report.has_findings() {
                    outcome.found = true;
                }
                if input.json {
                    json.push(render::show_json(&path, &report));
                } else {
                    print!("{}", render::show_text(&path, &report));
                }
            }
            Err(error) => {
                outcome.record(&error);
                report_failure(&path, &error, input.json, &mut json);
            }
        }
    }

    finish(input.json, &json, &outcome);
    outcome.code()
}

fn run_strip(input: &InputArgs, in_place: bool, output_dir: Option<&Path>, force: bool) -> u8 {
    let limits = Limits::with_max_input_bytes(input.max_bytes);
    let options = StripOptions::default();
    let mut outcome = Outcome::default();
    let mut json = Vec::new();

    for path in collect(input, &mut outcome) {
        let destination = if in_place {
            path.clone()
        } else {
            output_path(&path, output_dir)
        };
        // In-place means replacing the file that is already there, so it implies the
        // overwrite that `--force` otherwise gates. Asking for both would be noise.
        let overwrite = if force || in_place {
            Overwrite::Replace
        } else {
            Overwrite::Refuse
        };

        match strip_file(&path, &destination, limits, overwrite, &options) {
            Ok(report) => {
                outcome.reported = true;
                if input.json {
                    json.push(render::strip_json(&path, &destination, &report));
                } else {
                    print!("{}", render::strip_text(&path, &destination, &report));
                }
            }
            Err(StryptError::OutputExists) => {
                outcome.record(&StryptError::OutputExists);
                eprintln!(
                    "strypt: {} already exists; pass --force to overwrite it",
                    destination.display()
                );
                if input.json {
                    json.push(render::error_json(&path, &StryptError::OutputExists));
                }
            }
            Err(error) => {
                outcome.record(&error);
                report_failure(&path, &error, input.json, &mut json);
            }
        }
    }

    finish(input.json, &json, &outcome);
    outcome.code()
}

/// Expand the requested paths into files to process.
fn collect(input: &InputArgs, outcome: &mut Outcome) -> Vec<PathBuf> {
    let mut files = Vec::new();
    for path in &input.paths {
        if path.is_dir() {
            if input.recursive {
                walk(path, &mut files, outcome);
            } else {
                eprintln!(
                    "strypt: {} is a directory; pass --recursive to descend into it",
                    path.display()
                );
                outcome.record_local(Failure::Other);
            }
        } else {
            files.push(path.clone());
        }
    }
    // Sorted so that a batch run's output and exit behaviour do not depend on the order the
    // filesystem happened to return entries in.
    files.sort();
    files
}

fn walk(dir: &Path, files: &mut Vec<PathBuf>, outcome: &mut Outcome) {
    let entries = match std::fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(e) => {
            eprintln!("strypt: cannot read {}: {e}", dir.display());
            outcome.record_local(Failure::Io);
            return;
        }
    };
    for entry in entries.flatten() {
        let path = entry.path();
        // Symbolic links are not followed. Following them would let a directory tree redirect
        // a batch run outside the directory the user pointed at — and in `--in-place` mode
        // that means writing to a file they never named.
        if entry.file_type().is_ok_and(|t| t.is_symlink()) {
            continue;
        }
        if path.is_dir() {
            walk(&path, files, outcome);
        } else {
            files.push(path);
        }
    }
}

/// Where a stripped copy goes: `photo.jpg` becomes `photo.stripped.jpg`.
///
/// The suffix goes before the extension so the file still opens in the right application, and
/// the name is deliberately not a temporary-looking one — this is the file the user will
/// publish.
fn output_path(input: &Path, output_dir: Option<&Path>) -> PathBuf {
    let stem = input.file_stem().unwrap_or_default();
    let mut name = stem.to_os_string();
    name.push(".stripped");
    if let Some(extension) = input.extension() {
        name.push(".");
        name.push(extension);
    }
    match output_dir {
        Some(dir) => dir.join(name),
        None => input.with_file_name(name),
    }
}

fn report_failure(path: &Path, error: &StryptError, json: bool, sink: &mut Vec<serde_json::Value>) {
    // Failures go to stderr even in JSON mode, so a human watching a batch run sees them
    // without reading the JSON, and to the JSON array as well, so a script sees them too.
    eprintln!("strypt: {}: {error}", path.display());
    if json {
        sink.push(render::error_json(path, error));
    }
}

fn finish(json: bool, values: &[serde_json::Value], outcome: &Outcome) {
    if json {
        println!(
            "{}",
            serde_json::json!({
                "strypt": strypt_core::version(),
                "files": values,
            })
        );
    } else if outcome.reported {
        // A standing reminder rather than a per-file line. strypt reads file contents; the
        // things it cannot see are frequently the ones that identify someone
        // (docs/THREAT_MODEL.md §4). Most needed after a clean result, when a user publishes.
        eprintln!(
            "strypt: filenames, folder names, and anything visible in the document itself \
             are not touched."
        );
    }
}
