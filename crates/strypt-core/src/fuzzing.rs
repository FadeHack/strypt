//! Entry points that exist only so fuzz targets can reach internal parsers directly.
//!
//! **Behind the non-default `fuzzing` feature, and not part of the public API.** Nothing here is
//! covered by any stability promise, and no front-end may call it.
//!
//! # Why this module exists at all
//!
//! ADR-0028 commits the ZIP container layer to having a fuzz target *independent of any format
//! handler that sits on top of it*. That commitment is the whole reason the layer was written
//! rather than imported: it is a hostile parser in its own right, and reaching it only through
//! the OOXML handler would mean every input had to be a plausible Office package before the ZIP
//! code saw it — which is exactly the shape of corpus that leaves a container parser untested.
//!
//! The alternative was to make [`crate::container`] public. That would have put a ZIP reader in
//! strypt's API surface, where someone would eventually use it, and it is emphatically not a
//! general-purpose implementation (see that module's header). A hidden feature-gated door is the
//! smaller cost.

use crate::container::zip;
use crate::formats::ParseLimits;

/// Read an archive and write it back out, exercising both directions of the ZIP layer.
///
/// Every entry's contents are decompressed against a bounded budget, which is what puts the
/// inflate path, the expansion-ratio check, and the CRC verification under the fuzzer.
///
/// # Panics
///
/// Never, by design — that is the property being fuzzed. A panic escaping this function is a
/// finding (ADR-0006).
pub fn zip_round_trip(data: &[u8]) {
    let limits = ParseLimits::default();
    let Ok(entries) = zip::read(data, &limits) else {
        return;
    };

    let mut budget = limits.max_expanded_bytes;
    let mut outputs = Vec::with_capacity(entries.len());
    for entry in entries {
        if let Ok(contents) = entry.contents(budget) {
            let len = u64::try_from(contents.len()).unwrap_or(u64::MAX);
            if zip::spend(&mut budget, len).is_err() {
                return;
            }
        }
        outputs.push(zip::Output::Copied(entry));
    }

    let Ok(written) = zip::write(&outputs) else {
        return;
    };
    // An archive this module just wrote must be one it can read back. A writer that emits
    // something its own reader refuses is a defect the round trip is here to surface.
    assert!(
        zip::read(&written, &limits).is_ok(),
        "the ZIP writer produced an archive the ZIP reader refuses"
    );
}
