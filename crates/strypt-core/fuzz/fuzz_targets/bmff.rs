//! Fuzz target for the ISO-BMFF box walker.
//!
//! Separate from the `heif` target for the reason ADR-0028 gives for separating `zip` from
//! `ooxml`: the container is a hostile parser in its own right, and reaching it only through a
//! handler means every input has to look like a plausible HEIF before the walker sees it — the
//! shape of corpus that leaves a container parser untested. This one hands it arbitrary bytes.
//!
//! What it exercises that the handler target does not: the 64-bit size escape, the run-to-the-end
//! size, the boundary between a trailing fragment and a box, nesting against the depth ceiling,
//! and the writer — including that a tree this code writes is one it can read back.
//!
//! A panic is a finding; so is a hang, so is unbounded allocation (`docs/THREAT_MODEL.md` §5.1).

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    strypt_core::fuzzing::bmff_round_trip(data);
});
