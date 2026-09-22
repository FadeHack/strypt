//! ROADMAP Phase 5 exit criterion 1: the GUI's output is byte-identical to the CLI's for every
//! corpus file, and it refuses exactly what the CLI refuses.

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

#[test]
fn gui_matches_cli_across_the_corpus() {
    let cli = cli();
    let out = std::env::temp_dir().join(format!("strypt-gui-identity-{}", std::process::id()));
    let mut inputs = Vec::new();
    files(&corpus(), &mut inputs);
    inputs.sort();
    let (mut same, mut refused) = (0, 0);

    for input in &inputs {
        let _ = std::fs::remove_dir_all(&out);
        std::fs::create_dir_all(&out).unwrap();
        let status = Command::new(&cli)
            .arg("strip")
            .arg("--output-dir")
            .arg(&out)
            .arg(input)
            .output()
            .unwrap()
            .status;
        let written: Vec<_> = std::fs::read_dir(&out).unwrap().collect();
        let gui = strypt_gui::clean(input);

        match (status.success(), gui) {
            (true, Ok(stripped)) => {
                assert_eq!(written.len(), 1, "{}", input.display());
                let cli_bytes = std::fs::read(written[0].as_ref().unwrap().path()).unwrap();
                assert!(
                    cli_bytes == stripped.bytes,
                    "output differs: {}",
                    input.display()
                );
                same += 1;
            }
            (false, Err(_)) => {
                assert!(
                    written.is_empty(),
                    "CLI failed but wrote: {}",
                    input.display()
                );
                refused += 1;
            }
            (cli_ok, gui) => panic!(
                "front-ends disagree on {}: CLI success={cli_ok}, GUI success={}",
                input.display(),
                gui.is_ok()
            ),
        }
    }
    let _ = std::fs::remove_dir_all(&out);
    eprintln!(
        "{same} identical, {refused} refused by both, of {}",
        inputs.len()
    );
    assert!(same > 0);
}
