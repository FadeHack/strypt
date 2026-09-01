//! Fuzz target for the RIFF chunk walker.
//!
//! Separate from the `webp` and `wav` targets for the reason ADR-0028 gives for separating `zip`
//! from `ooxml`: the container is a hostile parser in its own right, and reaching it only through
//! a handler means every input has to look like a plausible WebP or WAV before the walker sees it
//! — the shape of corpus that leaves a container parser untested. This one hands it arbitrary
//! bytes, under both form types the crate ships.
//!
//! What it exercises that the handler targets do not: the odd-length pad byte at the very end of
//! an extent, a `LIST` body walked as a nested sequence, the item budget shared across both
//! levels, and the writer — including that a file this code writes is one it can read back.
//!
//! A panic is a finding; so is a hang, so is unbounded allocation (`docs/THREAT_MODEL.md` §5.1).

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    strypt_core::fuzzing::riff_round_trip(data);
});
