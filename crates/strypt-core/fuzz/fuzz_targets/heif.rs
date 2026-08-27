//! Fuzz target for the HEIF and AVIF handler.
//!
//! As the other handler targets, this asks whether the *answer* was right rather than only
//! whether the code survived (`docs/TESTING_STRATEGY.md` §2.4): a successful strip must
//! re-inspect clean and must strip again to the same bytes.
//!
//! # There is no size invariant here, deliberately
//!
//! The GIF, PNG and WebP targets assert that stripping never grows a file. This handler rebuilds
//! the container (ADR-0034), so like TIFF it may legitimately produce more bytes than it was
//! given — a file whose `iloc` used narrow offsets can come back with wider ones. Asserting the
//! invariant anyway is what cost the GIF run of 2026-08-26 seven hours, so it is left out rather
//! than guarded.
//!
//! # Why "the picture is unchanged" is not asserted here
//!
//! Finding the coded image in an arbitrary byte string means parsing the file, and a target that
//! re-implements the parser under test asserts only that two copies of the same logic agree. It
//! is checked over the corpus instead, in `tests/heif.rs`, by an independent box walker.
//!
//! A panic is a finding; so is a hang, so is unbounded allocation (`docs/THREAT_MODEL.md` §5.1).

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

    // Idempotence, byte for byte (`docs/TESTING_STRATEGY.md` §1, invariant 3).
    let second = strip_bytes(&first.bytes, &StripOptions::default())
        .expect("stripping already-stripped output failed");
    assert!(
        first.bytes == second.bytes,
        "strip is not idempotent for this input"
    );
});
