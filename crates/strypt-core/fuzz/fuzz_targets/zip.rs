//! Fuzz target for the ZIP container layer.
//!
//! Separate from the OOXML target on purpose. ADR-0028 records the ZIP layer as a hostile parser
//! in its own right, and reaching it only through a format handler would mean every input had to
//! look like a plausible Office package before the container code saw it — which is precisely
//! the shape of corpus that leaves a container parser untested. This one hands it arbitrary
//! bytes.
//!
//! What it exercises that no handler target does: the backward end-of-central-directory scan,
//! ZIP64 resolution, the disagreement between local headers and the central directory, the
//! expansion-ratio bound, CRC verification, and the writer — including the assertion that an
//! archive this code writes is one it can read back.
//!
//! A panic is a finding; so is a hang, so is unbounded allocation (`docs/THREAT_MODEL.md` §5.1).

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    strypt_core::fuzzing::zip_round_trip(data);
});
