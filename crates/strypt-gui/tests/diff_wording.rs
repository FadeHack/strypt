//! The before/after diff over the whole corpus: names only, a human label for everything, the
//! caveats on every file, and none of hard constraint 7's words.

use std::path::{Path, PathBuf};

use strypt_core::report::{InspectOptions, MetadataValue};
use strypt_gui::{Diff, Section, Status, process};

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

/// Every string the window draws for one cleaned file.
fn drawn(diff: &Diff) -> Vec<String> {
    let mut out = vec![diff.summary()];
    for Section {
        title,
        lines,
        empty,
    } in diff.sections()
    {
        out.push(title.to_string());
        if lines.is_empty() {
            out.push(empty.to_string());
        }
        for line in lines {
            out.push(format!("{} {}", line.mark, line.text));
            out.extend(line.sensitivity.map(str::to_string));
        }
    }
    out.push(strypt_gui::SENSITIVITY_KEY.to_string());
    out.extend(Diff::caveats());
    out
}

/// Tests run in parallel, so each gets its own folder.
fn scratch(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("strypt-gui-diff-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// The corpus, cleaned into a scratch folder: (input, diff) for every file strypt handles.
fn cleaned(tag: &str) -> Vec<(PathBuf, Diff)> {
    let out = scratch(tag);
    let mut inputs = Vec::new();
    files(&corpus(), &mut inputs);
    inputs.sort();
    let diffs: Vec<_> = inputs
        .into_iter()
        .filter_map(|input| match process(&input, Some(&out)) {
            Status::Cleaned { diff, .. } => Some((input, diff)),
            _ => None,
        })
        .collect();
    let _ = std::fs::remove_dir_all(&out);
    assert!(
        diffs.len() > 50,
        "only {} corpus files cleaned",
        diffs.len()
    );
    diffs
}

#[test]
fn the_diff_names_fields_and_never_shows_a_value() {
    let mut checked = 0;
    for (input, diff) in cleaned("values") {
        let text = drawn(&diff).join("\n");
        let data = std::fs::read(&input).unwrap();
        let with_values =
            strypt_core::inspect_bytes(&data, &InspectOptions::with_values()).unwrap();
        for finding in &with_values.findings {
            let Some(MetadataValue::Text(value)) = &finding.value else {
                continue;
            };
            let value = value.trim();
            // Short values collide with labels and counts by chance.
            if value.len() < 6 {
                continue;
            }
            assert!(
                !text.contains(value),
                "{}: the value of {} {:?} is on screen",
                input.display(),
                finding.location,
                finding.field
            );
            checked += 1;
        }
    }
    assert!(checked > 20, "only {checked} values checked");
}

#[test]
fn everything_in_the_corpus_has_a_human_label_and_no_banned_word() {
    for (input, diff) in cleaned("labels") {
        for line in drawn(&diff) {
            let lower = line.to_lowercase();
            assert!(
                !lower.contains("recognise"),
                "{}: fallback wording: {line}",
                input.display()
            );
            for banned in ["complete", "guarantee", "100%"] {
                assert!(!lower.contains(banned), "{}: {line}", input.display());
            }
        }
    }
}

#[test]
fn every_diff_carries_both_caveats() {
    for (input, diff) in cleaned("caveats") {
        let text = drawn(&diff).join("\n");
        assert!(
            text.contains("Filenames, folder names, and anything visible in the document itself are not touched."),
            "{}",
            input.display()
        );
        assert!(
            text.contains("Finding nothing does not mean a file is clean."),
            "{}",
            input.display()
        );
    }
}

#[test]
fn an_empty_result_is_said_not_left_blank() {
    let empty: Vec<_> = cleaned("empty")
        .into_iter()
        .filter(|(_, d)| d.found.findings.is_empty() && d.stripped.removed.is_empty())
        .collect();
    assert!(!empty.is_empty(), "the corpus has clean files");
    for (input, diff) in empty {
        let [found, removed, ..] = diff.sections();
        assert!(found.lines.is_empty() && !found.empty.is_empty());
        assert!(removed.lines.is_empty() && !removed.empty.is_empty());
        assert!(
            drawn(&diff).contains(&found.empty.to_string()),
            "{}",
            input.display()
        );
    }
}

#[test]
fn a_dirty_file_lists_what_came_out_with_the_clis_marks() {
    let out = scratch("marks");
    let (_, diff) = strypt_gui::clean(&corpus().join("jpeg/exif-gps.jpg"), Some(&out)).unwrap();
    let [found, removed, ..] = diff.sections();
    assert!(!removed.lines.is_empty());
    assert!(
        found
            .lines
            .iter()
            .any(|l| l.mark == "!!" && l.text.starts_with("Location, in "))
    );
    let _ = std::fs::remove_dir_all(&out);
}
