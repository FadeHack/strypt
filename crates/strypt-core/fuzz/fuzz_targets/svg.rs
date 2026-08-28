//! Fuzz target for the SVG handler.
//!
//! Like the other handler targets, this asks more than "did it survive?" — the fuzzer has already
//! done the hard work of reaching a strange code path, so it is also asked whether the *answer*
//! was right (`docs/TESTING_STRATEGY.md` §2.4).
//!
//! # There is no size invariant here, and that is deliberate
//!
//! The GIF and PNG targets assert that stripping never grows a file. SVG cannot: a `data:` URI is
//! decoded, handed to the embedded image's own handler, and re-encoded (ADR-0035 §4), and that
//! handler may be TIFF's or HEIF's, both of which rebuild rather than edit and may legitimately
//! return more bytes than they were given (ADR-0033, ADR-0034).
//!
//! What replaces it is stronger and is the promise ADR-0035 §1 actually makes: **a document with
//! nothing to remove comes back byte-identical**. That catches a handler rewriting bytes it had no
//! reason to touch, which a size bound would not.
//!
//! It is asserted only when `detect` really chose SVG. These targets drive the whole pipeline, so
//! a mutation is free to wander onto another format's magic and be dispatched elsewhere — the
//! mistake that killed a twelve-hour GIF run at 144.5M inputs on 2026-08-26.
//!
//! A panic is a finding; so is a hang, so is unbounded allocation. For safe Rust those are the
//! realistic residual risks (`docs/THREAT_MODEL.md` §5.1), and a policy that counts only crashes
//! measures the wrong thing.

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

    if matches!(detect(data), Ok(Format::Svg)) && first.report.removed.is_empty() {
        assert!(
            first.bytes == data,
            "an SVG with nothing to remove was rewritten anyway"
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
