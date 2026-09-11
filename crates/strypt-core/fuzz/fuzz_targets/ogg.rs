//! Fuzz target for the Ogg handler — Vorbis, Opus and FLAC-in-Ogg.
//!
//! Like the other handler targets, this asks whether the *answer* was right rather than only
//! whether the code survived (`docs/TESTING_STRATEGY.md` §2.4): every input that strips
//! successfully must re-inspect clean and must strip again to the same bytes.
//!
//! # Why the size invariant is not asserted here
//!
//! Every other group-4 target asserts that stripping never grows a file. An Ogg is rebuilt rather
//! than edited (ADR-0041), and a rebuild can legitimately grow one: an input paginated with more
//! pages than the rebuild needs loses page headers, but one whose packets were laid out more
//! tightly than the rebuild lays them out gains a few. Asserting it anyway would be asserting
//! something untrue, which is worse than asserting nothing.
//!
//! Had it been assertable, it would still have needed a `detect` guard: these targets drive the
//! whole pipeline, so a mutation can land on another format's magic and be dispatched to that
//! format's handler. An unguarded version of exactly that assertion killed a twelve-hour GIF run
//! at 144.5M inputs on 2026-08-26.
//!
//! A panic is a finding; so is a hang, so is unbounded allocation (`docs/THREAT_MODEL.md` §5.1).
//!
//! The custom mutator re-stamps page CRCs after libFuzzer's own mutation; without it the fuzzer
//! spent most of 84 CPU-hours failing the checksum (ADR-0044 decision 5).

#![no_main]

use libfuzzer_sys::{fuzz_mutator, fuzz_target};
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

    // Idempotence, byte for byte (`docs/TESTING_STRATEGY.md` §1, invariant 3).
    let second = strip_bytes(&first.bytes, &StripOptions::default())
        .expect("stripping already-stripped output failed");
    assert!(
        first.bytes == second.bytes,
        "strip is not idempotent for this input"
    );
});

fuzz_mutator!(|data: &mut [u8], size: usize, max_size: usize, seed: u32| {
    let size = libfuzzer_sys::fuzzer_mutate(data, size, max_size);
    // One in eight keeps its broken CRC, so the refusal path stays under the fuzzer.
    if seed % 8 != 0 {
        strypt_core::fuzzing::ogg_restamp(data.get_mut(..size).unwrap_or_default());
    }
    size
});
