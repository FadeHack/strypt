//! Fuzz target for format detection.
//!
//! Detection gets its own target because it is the one parser that sees every byte of every
//! file the user offers, including files no handler will ever accept. A shared parser reached
//! by every path is a shared risk (`docs/TESTING_STRATEGY.md` §2.4).
//!
//! The assertion is that detection is a *pure function of the bytes*. If the same input ever
//! detected two different ways, dispatch would be non-deterministic — and the failure mode
//! that lands on a user is a file routed to the wrong handler, which then reports success
//! having stripped nothing (`docs/THREAT_MODEL.md` §5.4).

#![no_main]

use libfuzzer_sys::fuzz_target;
use strypt_core::detect;

fuzz_target!(|data: &[u8]| {
    let first = detect(data).ok();
    let second = detect(data).ok();
    assert!(first == second, "detection is not deterministic for this input");
});
