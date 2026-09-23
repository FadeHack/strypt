//! ROADMAP Phase 5 exit criterion 1: the GUI writes byte-identical files to the CLI's for every
//! corpus file, under the same names and permissions, and refuses exactly what the CLI refuses.

use std::path::{Path, PathBuf};
use std::process::Command;

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

/// `CARGO_BIN_EXE_*` exists only for the binary's own package, so build it beside this test.
fn cli() -> PathBuf {
    let profile_dir = std::env::current_exe()
        .unwrap()
        .parent()
        .and_then(Path::parent)
        .unwrap()
        .to_path_buf();
    let mut build = Command::new(env!("CARGO"));
    build.args(["build", "-p", "strypt", "--bin", "strypt"]);
    if profile_dir.ends_with("release") {
        build.arg("--release");
    }
    assert!(build.status().unwrap().success(), "building the CLI failed");
    profile_dir.join(format!("strypt{}", std::env::consts::EXE_SUFFIX))
}

fn scratch(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("strypt-gui-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn cli_strip(cli: &Path, input: &Path, out: &Path) -> bool {
    Command::new(cli)
        .arg("strip")
        .arg("--output-dir")
        .arg(out)
        .arg(input)
        .output()
        .unwrap()
        .status
        .success()
}

#[cfg(unix)]
fn mode(path: &Path) -> u32 {
    use std::os::unix::fs::PermissionsExt as _;
    std::fs::metadata(path).unwrap().permissions().mode() & 0o777
}

#[cfg(not(unix))]
fn mode(_: &Path) -> u32 {
    0
}

/// Every difference between what the two front-ends left in their output directories.
fn differences(cli: &Path, gui: &Path) -> Vec<String> {
    let listing = |dir: &Path| {
        let mut names: Vec<_> = std::fs::read_dir(dir)
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .collect();
        names.sort();
        names
    };
    let (cli_names, gui_names) = (listing(cli), listing(gui));
    if cli_names != gui_names {
        return vec![format!("names: CLI {cli_names:?}, GUI {gui_names:?}")];
    }
    let mut found = Vec::new();
    for name in &cli_names {
        let (c, g) = (cli.join(name), gui.join(name));
        if std::fs::read(&c).unwrap() != std::fs::read(&g).unwrap() {
            found.push(format!("bytes of {}", name.to_string_lossy()));
        }
        if mode(&c) != mode(&g) {
            found.push(format!("mode of {}", name.to_string_lossy()));
        }
    }
    found
}

#[test]
fn gui_matches_cli_across_the_corpus() {
    let cli = cli();
    let (cli_out, gui_out) = (scratch("identity-cli"), scratch("identity-gui"));
    let mut inputs = Vec::new();
    files(&corpus(), &mut inputs);
    inputs.sort();
    let (mut same, mut refused) = (0, 0);

    for input in &inputs {
        for dir in [&cli_out, &gui_out] {
            std::fs::remove_dir_all(dir).unwrap();
            std::fs::create_dir(dir).unwrap();
        }
        let cli_ok = cli_strip(&cli, input, &cli_out);
        let gui_ok = strypt_gui::clean(input, Some(&gui_out)).is_ok();
        assert_eq!(cli_ok, gui_ok, "front-ends disagree on {}", input.display());
        let diff = differences(&cli_out, &gui_out);
        assert!(diff.is_empty(), "{}: {diff:?}", input.display());
        if cli_ok {
            same += 1;
        } else {
            assert!(
                std::fs::read_dir(&cli_out).unwrap().next().is_none(),
                "both refused but wrote: {}",
                input.display()
            );
            refused += 1;
        }
    }
    let _ = std::fs::remove_dir_all(&cli_out);
    let _ = std::fs::remove_dir_all(&gui_out);
    eprintln!(
        "{same} identical, {refused} refused by both, of {}",
        inputs.len()
    );
    assert!(same > 0);
}

/// A dropped folder against `strip --recursive`: the same walk, the same order, so the same
/// files written and the same name clashes refused in the one output folder.
#[test]
fn a_folder_drop_matches_cli_recursive() {
    let cli = cli();
    let (cli_out, gui_out) = (scratch("folder-cli"), scratch("folder-gui"));
    let status = Command::new(&cli)
        .args(["strip", "--recursive", "--output-dir"])
        .arg(&cli_out)
        .arg(corpus())
        .output()
        .unwrap()
        .status;
    assert!(status.code().is_some(), "the CLI was killed");

    let walk = strypt_core::walk(&corpus());
    assert!(walk.skipped.is_empty(), "{:?}", walk.skipped);
    let cleaned = walk
        .files
        .iter()
        .filter(|file| strypt_gui::clean(file, Some(&gui_out)).is_ok())
        .count();
    let diff = differences(&cli_out, &gui_out);
    assert!(diff.is_empty(), "{diff:?}");
    assert!(cleaned > 0);
    let _ = std::fs::remove_dir_all(&cli_out);
    let _ = std::fs::remove_dir_all(&gui_out);
}

/// A comparison that cannot fail proves nothing, so plant each kind of difference.
#[test]
fn a_planted_difference_fails_the_comparison() {
    let cli = cli();
    let input = corpus().join("jpeg/exif-gps.jpg");
    let (cli_out, gui_out) = (scratch("plant-cli"), scratch("plant-gui"));
    assert!(cli_strip(&cli, &input, &cli_out));
    let (written, _) = strypt_gui::clean(&input, Some(&gui_out)).unwrap();
    assert!(differences(&cli_out, &gui_out).is_empty());

    let original = std::fs::read(&written).unwrap();
    let mut planted = original.clone();
    let last = planted.len() - 1;
    planted[last] ^= 1;
    std::fs::write(&written, &planted).unwrap();
    assert!(
        !differences(&cli_out, &gui_out).is_empty(),
        "a flipped byte"
    );
    std::fs::write(&written, &original).unwrap();

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&written, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(!differences(&cli_out, &gui_out).is_empty(), "a wider mode");
        std::fs::set_permissions(&written, std::fs::Permissions::from_mode(0o600)).unwrap();
    }

    let renamed = gui_out.join("exif-gps.clean.jpg");
    std::fs::rename(&written, &renamed).unwrap();
    assert!(!differences(&cli_out, &gui_out).is_empty(), "another name");

    let _ = std::fs::remove_dir_all(&cli_out);
    let _ = std::fs::remove_dir_all(&gui_out);
}

#[test]
fn the_gui_refuses_to_overwrite_as_the_cli_does() {
    let input = corpus().join("jpeg/exif-gps.jpg");
    let out = scratch("overwrite");
    let (written, _) = strypt_gui::clean(&input, Some(&out)).unwrap();
    std::fs::write(&written, b"the user's own file").unwrap();
    assert!(matches!(
        strypt_gui::clean(&input, Some(&out)),
        Err(strypt_core::StryptError::OutputExists)
    ));
    assert_eq!(std::fs::read(&written).unwrap(), b"the user's own file");
    let _ = std::fs::remove_dir_all(&out);
}
