//! Fuzz target for the JPEG handler.
//!
//! Like the PDF target, this does more than ask "did it survive?" — the fuzzer has already
//! done the hard work of reaching a strange code path, so it is also asked whether the
//! *answer* was right (`docs/TESTING_STRATEGY.md` §2.4). Every input that strips successfully
//! is held to the invariants that matter: the output re-inspects clean and stripping it again
//! changes nothing.
//!
//! # Why "the picture is unchanged" is not asserted here
//!
//! It is the invariant this handler exists to protect, and it is checked — over the corpus, in
//! `tests/jpeg.rs`, where every fixture is the same known image. It cannot be checked here,
//! because finding the picture in an arbitrary byte string means parsing the file, and a fuzz
//! target that re-implements the parser under test is asserting that two copies of the same
//! logic agree. Three attempts at a cheap approximation each produced false positives on
//! inputs the handler had got right: a start-of-scan marker inside an Exif thumbnail, a second
//! image spliced in mid-scan, a comparison that straddled a removed segment. Each of those is
//! a legal file, so each failure was the target being wrong, not the handler.
//!
//! A panic is a finding; so is a hang, so is unbounded allocation. For safe Rust those are the
//! realistic residual risks (`docs/THREAT_MODEL.md` §5.1), and a policy that counts only
//! crashes measures the wrong thing.

#![no_main]

use libfuzzer_sys::fuzz_target;
use strypt_core::formats::StripOptions;
use strypt_core::report::InspectOptions;
use strypt_core::{inspect_bytes, strip_bytes};

fuzz_target!(|data: &[u8]| {
    // Inspection must never modify anything and must never panic, whatever it is handed.
    let _ = inspect_bytes(data, &InspectOptions::names_only());

    let Ok(first) = strip_bytes(data, &StripOptions::default()) else {
        // A refusal is a correct outcome for a hostile file. Failing closed is the design.
        return;
    };

    // Whatever strip claims to have removed, inspect must be unable to find.
    match inspect_bytes(&first.bytes, &InspectOptions::names_only()) {
        Ok(report) => assert!(
            report.findings.is_empty(),
            "metadata survived a successful strip: {:?}",
            report.findings
        ),
        Err(e) => panic!("stripped output no longer inspects: {e}"),
    }

    // Idempotence, byte for byte (docs/TESTING_STRATEGY.md §1, invariant 3).
    let second = strip_bytes(&first.bytes, &StripOptions::default())
        .expect("stripping already-stripped output failed");
    assert!(
        first.bytes == second.bytes,
        "strip is not idempotent for this input"
    );
});
