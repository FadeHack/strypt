//! Fuzz target for the GIF handler.
//!
//! Like the other handler targets, this asks more than "did it survive?" — the fuzzer has
//! already done the hard work of reaching a strange code path, so it is also asked whether the
//! *answer* was right (`docs/TESTING_STRATEGY.md` §2.4). Every input that strips successfully
//! must re-inspect clean, must strip again to the same bytes, and must never have grown.
//!
//! # The size invariant is asserted here, and for TIFF it could not be
//!
//! GIF stripping only ever removes whole blocks and copies the rest through byte for byte, so
//! output larger than input means bytes were synthesised — the same invariant the PNG target
//! holds, and for the same structural reason. The TIFF target has to do without it because that
//! handler rebuilds the file and a legal TIFF can legitimately grow when strips overlap
//! (ADR-0033). Where the property is available it is worth asserting: nothing here should ever
//! be putting bytes into a user's file.
//!
//! # Why "the picture is unchanged" is not asserted here
//!
//! Finding the image data in an arbitrary byte string means parsing the file, and a fuzz target
//! that re-implements the parser under test is asserting that two copies of the same logic
//! agree. It is checked instead over the corpus, in `tests/gif.rs`, where an independent walker
//! compares every image block before and after.
//!
//! A panic is a finding; so is a hang, so is unbounded allocation. For safe Rust those are the
//! realistic residual risks (`docs/THREAT_MODEL.md` §5.1), and a policy that counts only crashes
//! measures the wrong thing.

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

    assert!(
        first.bytes.len() <= data.len(),
        "stripping a GIF produced more bytes than it was given"
    );

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
