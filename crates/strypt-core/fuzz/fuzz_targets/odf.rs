//! Fuzz target for the OpenDocument handler.
//!
//! Like every target here, this asks more than "did it survive?" — the fuzzer has already done
//! the hard work of reaching a strange code path, so it is also asked whether the *answer* was
//! right (`docs/TESTING_STRATEGY.md` §2.4). Every input that strips successfully is held to the
//! invariants that matter: the output re-inspects clean, and stripping it again changes nothing.
//!
//! # What this reaches that the `ooxml` and `zip` targets do not
//!
//! The ZIP layer below it is shared and has its own target (ADR-0028), and the one-level descent
//! into embedded images is shared too (ADR-0029). What is new here is everything above them, and
//! it is not a variation on the Office rules:
//!
//! - **The manifest is the only index**, and it is where an ODF-encrypted package declares
//!   itself — the refusal that ZIP's own encryption bit cannot see. A fuzzer that turns a
//!   manifest into something the scanner reads differently is exactly the input that would get
//!   a package of ciphertext reported clean, so it matters that it is reachable from here.
//! - **The scanner tracks context**, because ODF puts authorship in element text rather than in
//!   an attribute and the same element name means different things in different places. The
//!   depth bound, the mismatched-tag bail-out, and the fall back to removing a whole element
//!   when its value cannot be isolated are all only reachable through this target.
//! - **`mimetype` is reordered and re-stored on output**, which is the one place a handler in
//!   this project moves an entry. Idempotence is what proves it settles.
//!
//! # Why the size invariant from the image targets is absent here
//!
//! The WebP, PNG, and JPEG targets assert that output is never larger than input, because those
//! handlers only ever drop bytes. This one legitimately grows a file: a part strypt rewrites is
//! re-emitted **stored** where it arrived deflated, which is ADR-0028's deliberate trade.
//! Asserting a size bound anyway would mean asserting something about the compression ratio of
//! attacker-chosen XML, which is not a property this handler has.
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
        // for this format there are more ways to earn one than for any Phase 1 format: a missing
        // manifest, an ODF-encrypted entry, a package whose `mimetype` and manifest disagree
        // about what it is, a nested container, an unsupported compression method.
        return;
    };

    // Whatever strip claims to have removed, inspect must be unable to find. For this format
    // that covers the embedded pictures and an embedded object's own metadata too, since both
    // sides run the same pass.
    match inspect_bytes(&first.bytes, &InspectOptions::names_only()) {
        Ok(report) => assert!(
            report.findings.is_empty(),
            "metadata survived a successful strip: {:?}",
            report.findings
        ),
        Err(e) => panic!("stripped output no longer inspects: {e}"),
    }

    // Idempotence, byte for byte (docs/TESTING_STRATEGY.md §1, invariant 3). This is the load-
    // bearing assertion in every container target: it is what caught the OOXML handler writing
    // `[Content_Types].xml` twice into one package, which every reader tolerated and no other
    // check noticed.
    let second = strip_bytes(&first.bytes, &StripOptions::default())
        .expect("stripping already-stripped output failed");
    assert!(
        first.bytes == second.bytes,
        "strip is not idempotent for this input"
    );
});
