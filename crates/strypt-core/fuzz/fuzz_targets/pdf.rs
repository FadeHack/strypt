//! Fuzz target for the PDF handler.
//!
//! This target does more than check for crashes. A target that only asks "did it survive?"
//! leaves most of its value unclaimed (`docs/TESTING_STRATEGY.md` §2.4): the fuzzer has
//! already done the hard work of reaching a strange code path, so it should also be asked
//! whether the *answer* was right. So every input that strips successfully is then held to
//! the invariants that matter — the output re-inspects clean, and stripping it again changes
//! nothing.
//!
//! Failures are equally interesting in both directions. A panic is a finding; so is a hang,
//! so is unbounded allocation. For safe Rust those are the realistic residual risks
//! (`docs/THREAT_MODEL.md` §5.1), and a policy that counts only crashes measures the wrong
//! thing.

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

    // Whatever strip claims to have removed, inspect must be unable to find. If this ever
    // fires, the pipeline's verification pass and this assertion disagree, which means one of
    // them is wrong — and the one users rely on is the pass.
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
