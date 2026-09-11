//! Fuzz target for the Ogg page layer.
//!
//! Separate from the `ogg` handler target for the reason ADR-0028 gives for separating `zip` from
//! `ooxml`: the container is a hostile parser in its own right, and reaching it only through a
//! handler means every input has to look like a plausible Vorbis, Opus or FLAC stream before the
//! page walk sees it. This one hands it arbitrary bytes.
//!
//! What it exercises that the handler target does not: packet assembly across page boundaries, the
//! CRC check, the lacing arithmetic, and the writer — including that a stream this code writes is
//! one it can read back with the same packets and the same granule positions.
//!
//! A panic is a finding; so is a hang, so is unbounded allocation (`docs/THREAT_MODEL.md` §5.1).
//!
//! The mutator re-stamps page CRCs, as in the `ogg` target.

#![no_main]

use libfuzzer_sys::{fuzz_mutator, fuzz_target};

fuzz_target!(|data: &[u8]| {
    strypt_core::fuzzing::ogg_round_trip(data);
});

fuzz_mutator!(|data: &mut [u8], size: usize, max_size: usize, seed: u32| {
    let size = libfuzzer_sys::fuzzer_mutate(data, size, max_size);
    // One in eight keeps its broken CRC, so the refusal path stays under the fuzzer.
    if seed % 8 != 0 {
        strypt_core::fuzzing::ogg_restamp(data.get_mut(..size).unwrap_or_default());
    }
    size
});
