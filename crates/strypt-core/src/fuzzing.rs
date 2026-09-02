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

use crate::container::bmff;
use crate::container::riff;
use crate::container::zip;
use crate::formats::ParseLimits;
use crate::formats::tags;
use crate::report::InspectOptions;

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

/// Walk a box tree and write it back out, exercising both directions of the BMFF layer.
///
/// The walk is recursive into every container box the tree declares, so the depth ceiling and the
/// shared item budget are both under the fuzzer rather than only the top level.
///
/// # Panics
///
/// Never, by design — that is the property being fuzzed. A panic escaping this is a finding.
pub fn bmff_round_trip(data: &[u8]) {
    let limits = ParseLimits::default();
    let mut budget = limits.max_items;
    let Ok((top, _trailing)) = bmff::top_level(data, &mut budget) else {
        return;
    };

    let mut out = Vec::new();
    for b in &top {
        descend(b, limits.max_depth, &mut budget);
        if bmff::write_box(&mut out, b.kind, |o| {
            o.extend_from_slice(b.payload);
            Ok(())
        })
        .is_err()
        {
            return;
        }
    }

    // A tree this module just wrote must be one it can read back. A writer emitting something its
    // own reader refuses is the defect the round trip exists to surface.
    let mut read_budget = limits.max_items;
    assert!(
        bmff::children(&out, 0, &mut read_budget).is_ok(),
        "the BMFF writer produced a tree the walker refuses"
    );
}

/// Walk a RIFF file and write it back out, exercising both directions of the RIFF layer.
///
/// Both form types the crate ships are tried, and every `LIST` body is walked as a nested chunk
/// sequence, so the pad-byte arithmetic runs at two levels rather than only the top (ADR-0039).
///
/// # Panics
///
/// Never, by design — that is the property being fuzzed. A panic escaping this is a finding.
pub fn riff_round_trip(data: &[u8]) {
    let limits = ParseLimits::default();
    for form in [*b"WEBP", *b"WAVE"] {
        let mut budget = limits.max_items;
        let Ok((chunks, _trailing)) = riff::read(data, form, &mut budget) else {
            continue;
        };

        let mut body = Vec::new();
        for chunk in &chunks {
            if let Some((_, rest)) = riff::list_form(chunk.data) {
                let _ = riff::chunks(rest, chunk.offset, &mut budget);
            }
            if riff::write_chunk(&mut body, chunk.kind, chunk.data).is_err() {
                return;
            }
        }

        let Ok(written) = riff::write(form, &body) else {
            return;
        };
        // A file this module just wrote must be one it can read back. A writer emitting something
        // its own reader refuses is the defect the round trip exists to surface.
        let mut read_budget = limits.max_items;
        assert!(
            riff::read(&written, form, &mut read_budget).is_ok(),
            "the RIFF writer produced a file the RIFF walker refuses"
        );
    }
}

/// Walk into `parent`, charging the descent against the depth and item ceilings.
///
/// Exactly **one** interpretation of the payload is followed per box: the plain one, falling back
/// to the full-box one only when that fails. Trying both at every level is 2^depth work, which
/// took the target from 22,000 executions a second to 113 — a harness that spends a sustained run
/// on itself finds nothing.
fn descend(parent: &bmff::Box<'_>, depth: u32, budget: &mut u32) {
    let children = bmff::children_at(parent, parent.payload, depth, budget).or_else(|_| {
        let rest = parent.full().map(|(_, _, rest)| rest).unwrap_or_default();
        bmff::children_at(parent, rest, depth, budget)
    });
    let Ok(children) = children else {
        return;
    };
    for child in &children {
        descend(child, depth.saturating_sub(1), budget);
    }
}

/// Peel the tags off both ends of `data` and itemise every one.
///
/// Separate from the `mp3` and `flac` targets for the reason ADR-0028 gives for separating `zip`
/// from `ooxml`: reaching the tag reader only through a handler means every input has to look like
/// plausible audio before the reader sees it. The `tail` scan in particular is the part no handler
/// target reaches with arbitrary bytes — it searches backwards, and its floor is the one number
/// standing between a lying tag size and the payload (ADR-0040).
///
/// # Panics
///
/// Never, by design — that is the property being fuzzed. A panic escaping this is a finding.
pub fn tags_scan(data: &[u8]) {
    let options = InspectOptions::with_values();
    let Ok((head, start)) = tags::head(data) else {
        return;
    };
    for tag in &head {
        let _ = tags::findings(tag, &options);
    }
    let Ok((tail, end)) = tags::tail(data, start) else {
        return;
    };
    for tag in &tail {
        let _ = tags::findings(tag, &options);
    }
    // The payload boundary is what the whole module exists to compute. A tail tag reaching below
    // the head tags would let a strip delete audio and report success (`docs/THREAT_MODEL.md` §4).
    assert!(end >= start, "a tail tag reached below the head tags");
    assert!(end <= data.len(), "a tag span ran past the end of the file");
}
