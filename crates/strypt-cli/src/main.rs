//! `strypt` — strip hidden identifying metadata from files.
//!
//! **Phase 0 — scaffolding only.** No functionality yet. The CLI contract (`show` / `strip`,
//! batch handling, `--json`, exit codes) is specified in `docs/PRD.md` §8.2 and lands in
//! Phase 1.
//!
//! This crate stays thin by design: argument parsing, I/O orchestration, and presentation
//! only. All detection and stripping logic lives in `strypt-core` (ADR-0003).

fn main() {
    eprintln!(
        "strypt {} — not implemented yet (Phase 0: foundation).\n\
         This repository currently contains design documents only; there is nothing to run.\n\
         See docs/ROADMAP.md for what Phase 1 will deliver.\n\
         \n\
         To strip metadata today, use mat2 (https://github.com/jvoisin/mat2) or ExifTool.",
        strypt_core::version()
    );
    std::process::exit(2);
}
