//! CLI contract tests, run against the built binary.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

const CAVEAT: &str = "are not touched";

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

fn strypt(args: &[&str], path: &Path) -> Output {
    Command::new(env!("CARGO_BIN_EXE_strypt"))
        .args(args)
        .arg(path)
        .output()
        .unwrap()
}

fn stderr(out: &Output) -> String {
    String::from_utf8_lossy(&out.stderr).into_owned()
}

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
    let input = dir.join("photo.jpg");
    std::fs::copy(fixture("jpeg/exif-gps.jpg"), &input).unwrap();
    let out = strypt(&["strip"], &input);
    assert_eq!(out.status.code(), Some(0));
    assert!(stderr(&out).contains(CAVEAT));
    std::fs::remove_dir_all(&dir).unwrap();
}

// Nothing was reported on, so there is nothing for the caveat to qualify.
#[test]
fn an_unsupported_file_gets_no_caveat() {
    let dir = scratch("unsupported");
    let input = dir.join("notes.txt");
    std::fs::write(&input, "plain text").unwrap();
    let out = strypt(&["show"], &input);
    assert_ne!(out.status.code(), Some(0));
    assert!(!stderr(&out).contains(CAVEAT));
    std::fs::remove_dir_all(&dir).unwrap();
}

// JSON consumers are scripts; the caveat is for a person reading a terminal.
#[test]
fn json_output_gets_no_caveat() {
    let out = strypt(&["show", "--json"], &fixture("jpeg/clean.jpg"));
    assert!(!stderr(&out).contains(CAVEAT));
}
