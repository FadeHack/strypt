//! Fuzz target for the TIFF handler.
//!
//! Like the PDF, JPEG, PNG, and WebP targets, this asks more than "did it survive?" — the
//! fuzzer has already done the hard work of reaching a strange code path, so it is also asked
//! whether the *answer* was right (`docs/TESTING_STRATEGY.md` §2.4). Every input that strips
//! successfully must re-inspect clean and must strip again to the same bytes.
//!
//! # Why the size invariant the PNG target asserts is absent here
//!
//! PNG stripping only ever removes chunks and copies the rest through, so output larger than
//! input means bytes were synthesised. **TIFF cannot make that promise, and the reason is
//! structural rather than a defect** (ADR-0033): the handler rebuilds the file, and a legal
//! TIFF may point several strips at the *same* bytes. Those strips are separate strips in the
//! output, so a file whose geometry overlaps heavily can legitimately grow. Asserting the PNG
//! invariant here would report a correct rebuild as a crash.
//!
//! What is asserted instead is idempotence, which is the stronger property for a rewriting
//! handler: it says the writer's output is a fixed point of its own reader, so the second pass
//! finds nothing left to move.
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

    // Idempotence, byte for byte (`docs/TESTING_STRATEGY.md` §1, invariant 3). For a handler
    // that rebuilds rather than edits, this is also the proof that the rebuild settles.
    let second = strip_bytes(&first.bytes, &StripOptions::default())
        .expect("stripping already-stripped output failed");
    assert!(
        first.bytes == second.bytes,
        "strip is not idempotent for this input"
    );
});
