//! Fuzz target for the Office Open XML handler.
//!
//! Like the Phase 1 targets, this asks more than "did it survive?" — the fuzzer has already done
//! the hard work of reaching a strange code path, so it is also asked whether the *answer* was
//! right (`docs/TESTING_STRATEGY.md` §2.4). Every input that strips successfully is held to the
//! invariants that matter: the output re-inspects clean, and stripping it again changes nothing.
//!
//! # Why the size invariant from the image targets is absent here
//!
//! The WebP, PNG, and JPEG targets assert that output is never larger than input, because those
//! handlers only ever drop bytes. This one legitimately grows a file: a part strypt rewrites is
//! re-emitted **stored** where it arrived deflated, which is ADR-0028's deliberate trade —
//! deflate output is implementation-defined, and compressing on output would make byte-identical
//! idempotence depend on a compressor's internal choices staying stable across versions.
//!
//! Asserting a size bound anyway would mean asserting something about the compression ratio of
//! attacker-chosen XML, which is not a property this handler has. Idempotence is the invariant
//! that actually catches the bug the size check was standing in for, and it is checked below.
//!
//! # What this target reaches that the `zip` target does not
//!
//! The ZIP layer has its own target, deliberately, because it is a hostile parser in its own
//! right (ADR-0028). This one goes further up: the content-types and relationship parsing, the
//! XML scanner, the part-classification rules, and — the piece with the most surface — the
//! one-level descent into embedded images, where an arbitrary decompressed archive entry is
//! handed to the JPEG, PNG, or WebP handler (ADR-0029). That composition is not reachable from
//! any Phase 1 target.
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
        // A refusal is a correct outcome for a hostile file. Failing closed is the design, and
        // for this format there are more ways to earn a refusal than for any Phase 1 one:
        // encryption, an unsupported compression method, a nested container, a package whose
        // declared main part does not match what the handler was dispatched for.
        return;
    };

    // Whatever strip claims to have removed, inspect must be unable to find. For this format
    // that covers the embedded pictures too, since both sides run the same pass.
    match inspect_bytes(&first.bytes, &InspectOptions::names_only()) {
        Ok(report) => assert!(
            report.findings.is_empty(),
            "metadata survived a successful strip: {:?}",
            report.findings
        ),
        Err(e) => panic!("stripped output no longer inspects: {e}"),
    }

    // Idempotence, byte for byte (docs/TESTING_STRATEGY.md §1, invariant 3). This is the load-
    // bearing assertion here: it is what caught the handler writing `[Content_Types].xml` twice
    // into the same package, which every reader tolerated and no other check noticed.
    let second = strip_bytes(&first.bytes, &StripOptions::default())
        .expect("stripping already-stripped output failed");
    assert!(
        first.bytes == second.bytes,
        "strip is not idempotent for this input"
    );
});
