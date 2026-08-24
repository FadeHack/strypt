//! A ZIP reader for the package-format tests, written **here rather than borrowed from
//! [`strypt_core`]**.
//!
//! That is the whole point of it. A test that parsed strypt's output with the code under test
//! would be asserting that the parser agrees with itself, and would pass just as happily on an
//! archive no other tool can open. This one walks the central directory independently, inflates
//! with `flate2` directly, and computes its own CRC-32, so a wrong checksum in strypt's output
//! cannot be validated by the code that produced it.
//!
//! Shared by the Office Open XML and `OpenDocument` suites. Both need the same independence, and
//! two copies of it would drift.

// Each suite uses a subset of these helpers, and a helper that is unused by one of them is not
// dead code — it is used by the other. This module is compiled into both test binaries
// separately, so the compiler cannot see that.
#![allow(dead_code)]
// Test code is not reachable from untrusted bytes, which is the boundary the panic-freedom
// lints police (ADR-0006).
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

use std::collections::BTreeMap;

/// One entry of an archive, as an independent reader sees it.
pub struct Entry {
    pub contents: Vec<u8>,
    /// The compression method from the central directory: 0 stored, 8 deflate.
    pub method: u16,
    /// Position in the central directory, so a test can assert that an entry comes first.
    pub index: usize,
    /// Length of the entry's local-header extra field.
    pub local_extra_len: usize,
}

/// Read an archive into an ordered map of entry name to entry.
///
/// Asserts on the way through that no entry name appears twice — the check that caught the OOXML
/// handler writing `[Content_Types].xml` into the package a second time, which every real reader
/// tolerates by silently preferring one of the two copies.
pub fn read_archive(data: &[u8]) -> BTreeMap<String, Entry> {
    let eocd = rfind(data, b"PK\x05\x06").expect("no end-of-central-directory record");
    let count = u16::from_le_bytes(data[eocd + 10..eocd + 12].try_into().unwrap()) as usize;
    let mut at = u32::from_le_bytes(data[eocd + 16..eocd + 20].try_into().unwrap()) as usize;

    let mut out = BTreeMap::new();
    for index in 0..count {
        assert_eq!(
            &data[at..at + 4],
            b"PK\x01\x02",
            "central directory ended early"
        );
        let method = u16::from_le_bytes(data[at + 10..at + 12].try_into().unwrap());
        let crc = u32::from_le_bytes(data[at + 16..at + 20].try_into().unwrap());
        let compressed = u32::from_le_bytes(data[at + 20..at + 24].try_into().unwrap()) as usize;
        let uncompressed = u32::from_le_bytes(data[at + 24..at + 28].try_into().unwrap()) as usize;
        let name_len = u16::from_le_bytes(data[at + 28..at + 30].try_into().unwrap()) as usize;
        let extra_len = u16::from_le_bytes(data[at + 30..at + 32].try_into().unwrap()) as usize;
        let comment_len = u16::from_le_bytes(data[at + 32..at + 34].try_into().unwrap()) as usize;
        let local = u32::from_le_bytes(data[at + 42..at + 46].try_into().unwrap()) as usize;
        let name = String::from_utf8_lossy(&data[at + 46..at + 46 + name_len]).into_owned();
        at += 46 + name_len + extra_len + comment_len;

        assert_eq!(
            &data[local..local + 4],
            b"PK\x03\x04",
            "{name}: bad local header"
        );
        let local_name =
            u16::from_le_bytes(data[local + 26..local + 28].try_into().unwrap()) as usize;
        let local_extra =
            u16::from_le_bytes(data[local + 28..local + 30].try_into().unwrap()) as usize;
        let start = local + 30 + local_name + local_extra;
        let payload = &data[start..start + compressed];

        let contents = match method {
            0 => payload.to_vec(),
            8 => {
                use std::io::Read as _;
                let mut decoded = Vec::new();
                flate2::read::DeflateDecoder::new(payload)
                    .read_to_end(&mut decoded)
                    .unwrap_or_else(|e| panic!("{name}: inflate failed: {e}"));
                decoded
            }
            other => panic!("{name}: unexpected compression method {other}"),
        };
        assert_eq!(
            contents.len(),
            uncompressed,
            "{name}: declared size is wrong"
        );
        assert_eq!(crc32(&contents), crc, "{name}: CRC does not match the data");

        assert!(
            out.insert(
                name.clone(),
                Entry {
                    contents,
                    method,
                    index,
                    local_extra_len: local_extra,
                },
            )
            .is_none(),
            "the archive contains {name} twice"
        );
    }
    out
}

/// Read an archive into an ordered map of entry name to uncompressed contents.
pub fn unzip(data: &[u8]) -> BTreeMap<String, Vec<u8>> {
    read_archive(data)
        .into_iter()
        .map(|(name, entry)| (name, entry.contents))
        .collect()
}

/// The offset of the last occurrence of `needle`.
pub fn rfind(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .rposition(|window| window == needle)
}

/// CRC-32, computed here rather than borrowed from the crate strypt uses.
pub fn crc32(data: &[u8]) -> u32 {
    let mut crc = 0xFFFF_FFFFu32;
    for byte in data {
        crc ^= u32::from(*byte);
        for _ in 0..8 {
            crc = if crc & 1 == 1 {
                (crc >> 1) ^ 0xEDB8_8320
            } else {
                crc >> 1
            };
        }
    }
    !crc
}

/// Whether `haystack` contains `needle` as a byte sequence.
pub fn contains(haystack: &[u8], needle: &str) -> bool {
    haystack
        .windows(needle.len())
        .any(|w| w == needle.as_bytes())
}

/// Every substring of `text` between `open` and the next `close`.
pub fn between_all(text: &str, open: &str, close: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut rest = text;
    while let Some(start) = rest.find(open) {
        rest = &rest[start + open.len()..];
        let Some(end) = rest.find(close) else { break };
        out.push(rest[..end].to_owned());
        rest = &rest[end..];
    }
    out
}
