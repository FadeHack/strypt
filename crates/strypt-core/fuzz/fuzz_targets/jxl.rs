//! Fuzz target for the JPEG XL handler.
//!
//! Like the other handler targets, this asks whether the *answer* was right rather than only
//! whether the code survived (`docs/TESTING_STRATEGY.md` §2.4): every input that strips
//! successfully must re-inspect clean, must strip again to the same bytes, and must never have
//! grown.
//!
//! # The size invariant is asserted, and it is guarded
//!
//! A JPEG XL is edited by deletion (ADR-0036), so output larger than input means bytes were
//! synthesised — the property GIF, PNG and SVG have, and that TIFF and HEIF cannot claim because
//! they are rebuilt.
//!
//! The guard is not optional. These targets drive the whole pipeline, so a mutation is free to
//! land on another format's magic and be dispatched to that format's handler, where a JPEG
//! XL-shaped invariant says nothing at all. An unguarded version of exactly this assertion killed
//! a twelve-hour GIF run at 144.5M inputs on 2026-08-26.
//!
//! # Why "the picture is unchanged" is not asserted here
//!
//! Finding the codestream in an arbitrary byte string means parsing the file, and a target that
//! re-implements the parser under test asserts only that two copies of the same logic agree. It
//! is checked over the corpus instead, in `tests/jxl.rs`, by an independent box walker.
//!
//! A panic is a finding; so is a hang, so is unbounded allocation (`docs/THREAT_MODEL.md` §5.1).

#![no_main]

use libfuzzer_sys::fuzz_target;
use strypt_core::formats::StripOptions;
use strypt_core::report::InspectOptions;
use strypt_core::{Format, detect, inspect_bytes, strip_bytes};

fuzz_target!(|data: &[u8]| {
    // Inspection must never modify anything and must never panic, whatever it is handed.
    let _ = inspect_bytes(data, &InspectOptions::names_only());

    let Ok(first) = strip_bytes(data, &StripOptions::default()) else {
        // A refusal is a correct outcome for a hostile file. Failing closed is the design.
        return;
    };

    if matches!(detect(data), Ok(Format::Jxl)) {
        assert!(
            first.bytes.len() <= data.len(),
            "stripping a JPEG XL produced more bytes than it was given"
        );
    }

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
