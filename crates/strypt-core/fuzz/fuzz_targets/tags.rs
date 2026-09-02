//! Fuzz target for the ID3v2 / ID3v1 / APE / Lyrics3 tag reader.
//!
//! Separate from the `mp3` and `flac` targets for the reason ADR-0028 gives for separating `zip`
//! from `ooxml`: the tag layer is a hostile parser in its own right, and reaching it only through a
//! handler means every input has to look like plausible audio before the reader sees it — the
//! shape of corpus that leaves a shared layer untested.
//!
//! What it exercises that the handler targets do not: the backwards `tail` scan on arbitrary
//! bytes, tags of one kind stacked on another at both ends, the syncsafe and extended-header
//! arithmetic, and the floor that keeps a lying tail-tag size from reaching below the payload.
//!
//! A panic is a finding; so is a hang, so is unbounded allocation (`docs/THREAT_MODEL.md` §5.1).

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    strypt_core::fuzzing::tags_scan(data);
});
