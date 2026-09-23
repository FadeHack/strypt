//! Hard constraint 6 in the GUI: a row says "Cleaned", in the success colour, exactly when a
//! stripped copy was written, and every other row says no file was written.

use std::path::{Path, PathBuf};

use strypt_gui::{Status, Tone, process};

fn corpus() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../corpus")
}

fn files(dir: &Path, out: &mut Vec<PathBuf>) {
    for entry in std::fs::read_dir(dir).unwrap() {
        let path = entry.unwrap().path();
        if path.is_dir() {
            files(&path, out);
        } else {
            out.push(path);
        }
    }
}

fn scratch(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("strypt-gui-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn written(dir: &Path) -> usize {
    std::fs::read_dir(dir).unwrap().count()
}

/// Checks one row against what actually landed on disk.
fn assert_honest(input: &Path, status: &Status, before: usize, after: usize) {
    let cleaned = matches!(status, Status::Cleaned { .. });
    assert_eq!(
        cleaned,
        after == before + 1,
        "{}: row says {:?} but {} file(s) were written",
        input.display(),
        status.headline(),
        after - before
    );
    assert_eq!(
        cleaned,
        status.tone() == Tone::Success,
        "{}",
        input.display()
    );
    assert_eq!(
        cleaned,
        status.headline() == "Cleaned",
        "{}",
        input.display()
    );
    if let Status::Cleaned { output, .. } = status {
        assert!(output.is_file(), "{}", input.display());
    } else {
        assert!(!status.headline().starts_with("Cleaned"));
        assert!(status.detail().ends_with("No file was written."));
    }
}

#[test]
fn a_row_says_cleaned_exactly_when_a_file_was_written() {
    let out = scratch("batch-corpus");
    let mut inputs = Vec::new();
    files(&corpus(), &mut inputs);
    inputs.sort();
    let (mut cleaned, mut not) = (0, 0);
    for input in &inputs {
        let before = written(&out);
        let status = process(input, Some(&out));
        assert_honest(input, &status, before, written(&out));
        if status.tone() == Tone::Success {
            cleaned += 1;
        } else {
            not += 1;
        }
    }
    let _ = std::fs::remove_dir_all(&out);
    assert!(cleaned > 0 && not > 0, "{cleaned} cleaned, {not} not");
}

#[test]
fn every_kind_of_failure_is_shown_as_one() {
    let work = scratch("batch-planted");
    let out = work.join("out");
    std::fs::create_dir(&out).unwrap();
    let text = work.join("notes.txt");
    std::fs::write(&text, "plain text, which strypt has no handler for").unwrap();
    let jpeg = std::fs::read(corpus().join("jpeg/exif-gps.jpg")).unwrap();
    let truncated = work.join("truncated.jpg");
    std::fs::write(&truncated, &jpeg[..jpeg.len() / 3]).unwrap();
    let good = work.join("photo.jpg");
    std::fs::write(&good, &jpeg).unwrap();

    let first = process(&good, Some(&out));
    assert!(matches!(first, Status::Cleaned { .. }));
    let cases: [(&str, &Path); 5] = [
        ("unsupported", &text),
        ("truncated", &truncated),
        ("folder", &work),
        ("missing", &work.join("gone.jpg")),
        ("output exists", &good),
    ];
    for (name, input) in cases {
        let before = written(&out);
        let status = process(input, Some(&out));
        assert!(status.tone() == Tone::Failure, "{name}: {status:?}");
        assert_honest(input, &status, before, written(&out));
    }
    assert!(matches!(process(&text, Some(&out)), Status::Unsupported(_)));
    let _ = std::fs::remove_dir_all(&work);
}

#[test]
fn a_file_still_working_does_not_look_cleaned() {
    assert_eq!(Status::Working.tone(), Tone::Pending);
    assert_ne!(Status::Working.headline(), "Cleaned");
}
