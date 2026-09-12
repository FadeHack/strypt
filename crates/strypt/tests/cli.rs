//! CLI contract tests, run against the built binary (`TESTING_STRATEGY.md` §2.2).

use std::ffi::OsStr;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

const CAVEAT: &str = "are not touched";
// Synthetic values in `corpus/jpeg/exif-gps.jpg` (corpus/MANIFEST.md).
const ARTIST: &str = "SYNTHETIC-ARTIST-0004";

fn fixture(rel: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../corpus")
        .join(rel)
}

fn scratch(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("strypt-cli-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// Copy the fixture `rel` into `dir` as `name`.
fn copy_in(dir: &Path, rel: &str, name: &str) -> PathBuf {
    let path = dir.join(name);
    std::fs::copy(fixture(rel), &path).unwrap();
    path
}

fn run<I: IntoIterator<Item = S>, S: AsRef<OsStr>>(args: I) -> Output {
    Command::new(env!("CARGO_BIN_EXE_strypt"))
        .args(args)
        .output()
        .unwrap()
}

fn strypt(args: &[&str], path: &Path) -> Output {
    run(args
        .iter()
        .map(OsStr::new)
        .chain(std::iter::once(path.as_os_str())))
}

fn stdout(out: &Output) -> String {
    String::from_utf8_lossy(&out.stdout).into_owned()
}

fn stderr(out: &Output) -> String {
    String::from_utf8_lossy(&out.stderr).into_owned()
}

fn json(out: &Output) -> serde_json::Value {
    serde_json::from_slice(&out.stdout).expect("stdout must be exactly one JSON document")
}

fn keys(value: &serde_json::Value) -> Vec<&str> {
    let mut keys: Vec<&str> = value
        .as_object()
        .unwrap()
        .keys()
        .map(String::as_str)
        .collect();
    keys.sort_unstable();
    keys
}

// --- Exit codes (INSTRUCTIONS.md) -------------------------------------------------------

#[test]
fn a_missing_path_argument_is_a_usage_error() {
    assert_eq!(run(["show"]).status.code(), Some(2));
}

#[test]
fn an_unreadable_file_exits_3() {
    let dir = scratch("missing");
    let out = strypt(&["show"], &dir.join("absent.jpg"));
    assert_eq!(out.status.code(), Some(3));
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn an_input_over_max_bytes_exits_3() {
    let out = strypt(&["show", "--max-bytes", "10"], &fixture("jpeg/clean.jpg"));
    assert_eq!(out.status.code(), Some(3));
}

#[test]
fn the_most_serious_failure_in_a_batch_wins() {
    let dir = scratch("batch");
    let text = dir.join("notes.txt");
    std::fs::write(&text, "plain text").unwrap();
    let out = run([
        OsStr::new("show"),
        dir.join("absent.jpg").as_os_str(),
        text.as_os_str(),
    ]);
    assert_eq!(
        out.status.code(),
        Some(4),
        "unsupported outranks unreadable"
    );
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn a_directory_needs_recursive() {
    let dir = scratch("dir");
    copy_in(&dir, "jpeg/clean.jpg", "photo.jpg");
    let out = strypt(&["show"], &dir);
    assert_eq!(out.status.code(), Some(1));
    assert!(stderr(&out).contains("--recursive"));
    assert_eq!(
        strypt(&["show", "--recursive"], &dir).status.code(),
        Some(0)
    );
    std::fs::remove_dir_all(&dir).unwrap();
}

// --- Safety behaviours --------------------------------------------------------------------

// THREAT_MODEL §5.4: the failure a refactor is most likely to reintroduce.
#[test]
fn an_unsupported_file_is_never_copied_or_reported_as_success() {
    let dir = scratch("unsupported");
    let input = dir.join("notes.txt");
    std::fs::write(&input, "plain text").unwrap();
    let out = strypt(&["strip"], &input);
    assert_eq!(out.status.code(), Some(4));
    assert!(!dir.join("notes.stripped.txt").exists());
    assert!(!stderr(&out).contains(CAVEAT), "nothing was reported on");
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn a_corrupt_file_produces_no_output() {
    let dir = scratch("corrupt");
    let input = copy_in(&dir, "jpeg/malformed/length-past-end.jpg", "photo.jpg");
    let out = strypt(&["strip"], &input);
    assert_eq!(out.status.code(), Some(1));
    assert!(!dir.join("photo.stripped.jpg").exists());
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn strip_leaves_its_input_untouched() {
    let dir = scratch("untouched");
    let input = copy_in(&dir, "jpeg/exif-gps.jpg", "photo.jpg");
    let before = std::fs::read(&input).unwrap();
    assert_eq!(strypt(&["strip"], &input).status.code(), Some(0));
    assert_eq!(std::fs::read(&input).unwrap(), before);
    assert_eq!(
        strypt(&["show"], &dir.join("photo.stripped.jpg"))
            .status
            .code(),
        Some(0)
    );
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn an_existing_output_is_kept_without_force() {
    let dir = scratch("force");
    let input = copy_in(&dir, "jpeg/exif-gps.jpg", "photo.jpg");
    let existing = dir.join("photo.stripped.jpg");
    std::fs::write(&existing, "the user's file").unwrap();

    assert_eq!(strypt(&["strip"], &input).status.code(), Some(3));
    assert_eq!(std::fs::read(&existing).unwrap(), b"the user's file");

    assert_eq!(strypt(&["strip", "--force"], &input).status.code(), Some(0));
    assert_ne!(std::fs::read(&existing).unwrap(), b"the user's file");
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn in_place_replaces_the_original_and_writes_no_copy() {
    let dir = scratch("in-place");
    let input = copy_in(&dir, "jpeg/exif-gps.jpg", "photo.jpg");
    assert_eq!(
        strypt(&["strip", "--in-place"], &input).status.code(),
        Some(0)
    );
    assert!(!dir.join("photo.stripped.jpg").exists());
    assert_eq!(strypt(&["show"], &input).status.code(), Some(0));
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn output_dir_writes_there_and_not_beside_the_input() {
    let dir = scratch("output-dir");
    let input = copy_in(&dir, "jpeg/exif-gps.jpg", "photo.jpg");
    let out_dir = dir.join("out");
    std::fs::create_dir(&out_dir).unwrap();
    let out = run([
        OsStr::new("strip"),
        OsStr::new("--output-dir"),
        out_dir.as_os_str(),
        input.as_os_str(),
    ]);
    assert_eq!(out.status.code(), Some(0));
    assert!(out_dir.join("photo.stripped.jpg").exists());
    assert!(!dir.join("photo.stripped.jpg").exists());
    std::fs::remove_dir_all(&dir).unwrap();
}

// A link would let a tree redirect a batch, and --in-place, outside what the user named.
#[cfg(unix)]
#[test]
fn recursive_does_not_follow_symlinks() {
    let dir = scratch("symlink");
    let outside = scratch("symlink-target");
    copy_in(&outside, "jpeg/exif-gps.jpg", "photo.jpg");
    std::os::unix::fs::symlink(&outside, dir.join("link")).unwrap();
    let out = strypt(&["strip", "--recursive", "--in-place"], &dir);
    assert_eq!(out.status.code(), Some(0));
    assert_eq!(
        std::fs::read(outside.join("photo.jpg")).unwrap(),
        std::fs::read(fixture("jpeg/exif-gps.jpg")).unwrap()
    );
    std::fs::remove_dir_all(&dir).unwrap();
    std::fs::remove_dir_all(&outside).unwrap();
}

// Constraint 8: a report is easy to paste somewhere durable.
#[test]
fn values_are_printed_only_on_request() {
    let photo = fixture("jpeg/exif-gps.jpg");
    assert!(!stdout(&strypt(&["show"], &photo)).contains(ARTIST));
    assert!(!stdout(&strypt(&["show", "--json"], &photo)).contains(ARTIST));
    assert!(stdout(&strypt(&["show", "--show-values"], &photo)).contains(ARTIST));
}

// --- Output streams and JSON schema -----------------------------------------------------

#[test]
fn text_reports_go_to_stdout_and_the_caveat_to_stderr() {
    let out = strypt(&["show"], &fixture("jpeg/exif-gps.jpg"));
    assert!(stdout(&out).contains("personal identity"));
    assert!(!stdout(&out).contains(CAVEAT));
    assert!(stderr(&out).contains(CAVEAT));
}

#[test]
fn show_json_schema_is_stable() {
    let out = strypt(&["show", "--json"], &fixture("jpeg/exif-gps.jpg"));
    assert_eq!(out.status.code(), Some(1));
    let doc = json(&out);
    assert_eq!(keys(&doc), ["files", "strypt"]);
    let file = &doc["files"][0];
    assert_eq!(
        keys(file),
        ["findings", "format", "notes", "path", "status"]
    );
    assert_eq!(file["status"], "inspected");
    assert_eq!(
        keys(&file["findings"][0]),
        ["bytes", "field", "kind", "location", "sensitivity", "value"]
    );
}

#[test]
fn strip_json_schema_is_stable() {
    let dir = scratch("strip-json");
    let input = copy_in(&dir, "jpeg/exif-gps.jpg", "photo.jpg");
    let doc = json(&strypt(&["strip", "--json"], &input));
    let file = &doc["files"][0];
    assert_eq!(
        keys(file),
        [
            "format",
            "input_bytes",
            "notes",
            "output",
            "output_bytes",
            "path",
            "removed",
            "status"
        ]
    );
    assert_eq!(file["status"], "stripped");
    std::fs::remove_dir_all(&dir).unwrap();
}

// A failure must appear in the JSON as well as on stderr, or a script counts it as handled.
#[test]
fn a_failure_is_in_the_json_and_on_stderr() {
    let dir = scratch("json-failure");
    let out = strypt(&["show", "--json"], &dir.join("absent.jpg"));
    assert_eq!(out.status.code(), Some(3));
    let file = &json(&out)["files"][0];
    assert_eq!(keys(file), ["error", "path", "status"]);
    assert_eq!(file["status"], "failed");
    assert!(stderr(&out).contains("absent.jpg"));
    std::fs::remove_dir_all(&dir).unwrap();
}

// --- The not-touched caveat -------------------------------------------------------------

// A clean result is when a user publishes, so it is where the caveat matters most.
#[test]
fn show_on_a_clean_file_still_prints_the_caveat() {
    let out = strypt(&["show"], &fixture("jpeg/clean.jpg"));
    assert_eq!(out.status.code(), Some(0));
    assert!(stderr(&out).contains(CAVEAT));
}

#[test]
fn show_with_findings_prints_the_caveat() {
    let out = strypt(&["show"], &fixture("jpeg/exif-gps.jpg"));
    assert_eq!(out.status.code(), Some(1));
    assert!(stderr(&out).contains(CAVEAT));
}

#[test]
fn strip_prints_the_caveat() {
    let dir = scratch("strip");
    let input = copy_in(&dir, "jpeg/exif-gps.jpg", "photo.jpg");
    let out = strypt(&["strip"], &input);
    assert_eq!(out.status.code(), Some(0));
    assert!(stderr(&out).contains(CAVEAT));
    std::fs::remove_dir_all(&dir).unwrap();
}

// JSON consumers are scripts; the caveat is for a person reading a terminal.
#[test]
fn json_output_gets_no_caveat() {
    let out = strypt(&["show", "--json"], &fixture("jpeg/clean.jpg"));
    assert!(!stderr(&out).contains(CAVEAT));
}
