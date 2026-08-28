//! `data:` URIs, and the base64 codec they need.
//!
//! An SVG carries a pasted photograph as `<image href="data:image/jpeg;base64,...">`, which is a
//! whole JPEG — its GPS coordinates, its body serial number, its own thumbnail — encoded into an
//! attribute of a file the user thinks of as a drawing. ADR-0035 §4 descends into it exactly once
//! and only when it is an image, which is ADR-0029's rule unchanged; this module is the part that
//! gets the bytes out and back in.
//!
//! # Why the codec is written here
//!
//! Forty lines of table lookup, for one call site. ADR-0008 asks a dependency to earn its place
//! and this one cannot: `base64` is a fine crate and admitting it would buy nothing a small,
//! bounded, fully-tested function does not already provide.
//!
//! **Decoding is charged against a budget before the memory is committed**, never checked
//! afterwards, for the reason [`crate::formats::ParseLimits::max_expanded_bytes`] gives: a limit
//! tested after decoding is not a limit. The output length is known from the input length before
//! a byte is allocated, which makes that easy here in a way it is not for a stream compressor.

/// The standard base64 alphabet, RFC 4648 §4.
const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/// One parsed `data:` URI.
pub(super) struct DataUri<'a> {
    /// The declared media type, lowercased and without parameters — `image/jpeg`.
    ///
    /// **Advisory only.** What the payload actually is comes from [`crate::detect`], as it does
    /// for a file on disk: a `data:` URI's media type is written by whoever wrote the document,
    /// so trusting it to choose a handler would be trusting an attacker's label
    /// (`docs/ARCHITECTURE.md` §1).
    pub(super) media_type: String,
    /// Everything between the comma and the end.
    pub(super) payload: &'a str,
    /// Whether the payload is base64 rather than percent-encoded.
    pub(super) base64: bool,
}

/// Parse an attribute value as a `data:` URI, or [`None`] if it is not one.
pub(super) fn parse(value: &str) -> Option<DataUri<'_>> {
    let rest = strip_prefix_ignoring_case(value.trim_start(), "data:")?;
    let (meta, payload) = rest.split_once(',')?;
    // RFC 2397: the media type is followed by zero or more `;parameter=value`, and `;base64` is
    // spelled as a bare parameter in that same list rather than at a fixed position.
    let mut parameters = meta.split(';');
    let media_type = parameters.next().unwrap_or_default().trim().to_lowercase();
    let base64 = parameters.any(|p| p.trim().eq_ignore_ascii_case("base64"));
    Some(DataUri {
        media_type,
        payload,
        base64,
    })
}

/// Case-insensitive [`str::strip_prefix`], because a URI scheme is case-insensitive and real
/// documents contain `DATA:`.
fn strip_prefix_ignoring_case<'a>(value: &'a str, prefix: &str) -> Option<&'a str> {
    let head = value.get(..prefix.len())?;
    head.eq_ignore_ascii_case(prefix)
        .then(|| value.get(prefix.len()..))
        .flatten()
}

/// Decode a base64 payload, spending `budget` before the memory is allocated.
///
/// Whitespace is skipped: an attribute value may be wrapped across lines, and every real
/// Inkscape document with an embedded photograph in it is. Any other character outside the
/// alphabet ends the decode with [`None`] rather than being ignored, because a decoder that
/// silently drops what it does not understand produces bytes that are not what the document
/// said, and strypt would then write them back into the user's file.
pub(super) fn decode(payload: &str, budget: &mut u64) -> Option<Vec<u8>> {
    // Counted first and decoded second, so the output length is known — and charged — before a
    // byte is allocated. One pass with a growing buffer would commit the memory and then ask.
    let mut count = 0usize;
    for byte in significant(payload) {
        symbol(byte)?;
        count = count.checked_add(1)?;
    }

    // Four symbols make three bytes, and a trailing group of one symbol encodes nothing.
    let remainder = count.checked_rem(4)?;
    if remainder == 1 {
        return None;
    }
    let len = count
        .checked_div(4)?
        .checked_mul(3)?
        .checked_add(remainder.saturating_sub(1))?;

    *budget = budget.checked_sub(u64::try_from(len).ok()?)?;

    let mut out = Vec::with_capacity(len);
    let mut accumulator = 0u32;
    let mut bits = 0u32;
    for byte in significant(payload) {
        accumulator = (accumulator << 6) | u32::from(symbol(byte)?);
        bits = bits.saturating_add(6);
        if bits >= 8 {
            bits = bits.saturating_sub(8);
            out.push(u8::try_from((accumulator >> bits) & 0xFF).ok()?);
        }
    }
    Some(out)
}

/// The payload's bytes with whitespace dropped and everything from the first `=` onwards cut off.
fn significant(payload: &str) -> impl Iterator<Item = u8> + '_ {
    payload
        .bytes()
        .take_while(|byte| *byte != b'=')
        .filter(|byte| !byte.is_ascii_whitespace())
}

/// The value of one base64 symbol, or [`None`] when the byte is not one.
///
/// A table lookup rather than a search of [`ALPHABET`]: a megabyte of embedded photograph is a
/// megabyte of symbols, and a linear scan per byte is how a decoder becomes a hang the fuzzer
/// finds. The subtractions cannot underflow inside their own match arms.
fn symbol(byte: u8) -> Option<u8> {
    match byte {
        b'A'..=b'Z' => Some(byte.saturating_sub(b'A')),
        b'a'..=b'z' => Some(byte.saturating_sub(b'a').saturating_add(26)),
        b'0'..=b'9' => Some(byte.saturating_sub(b'0').saturating_add(52)),
        b'+' => Some(62),
        b'/' => Some(63),
        _ => None,
    }
}

/// Re-encode `bytes` as a complete `data:` URI.
///
/// Canonical: standard alphabet, padded, no line breaks. A document whose embedded image changed
/// therefore does not come back byte-identical in that attribute even where the original
/// encoding was merely unusual — recorded in ADR-0035 rather than glossed. A document with
/// nothing to remove is never re-encoded at all.
pub(super) fn encode(media_type: &str, bytes: &[u8]) -> String {
    let mut out = String::with_capacity(
        bytes
            .len()
            .saturating_div(3)
            .saturating_mul(4)
            .saturating_add(media_type.len())
            .saturating_add(16),
    );
    out.push_str("data:");
    out.push_str(media_type);
    out.push_str(";base64,");

    for chunk in bytes.chunks(3) {
        let (a, b, c) = (
            u32::from(*chunk.first().unwrap_or(&0)),
            u32::from(*chunk.get(1).unwrap_or(&0)),
            u32::from(*chunk.get(2).unwrap_or(&0)),
        );
        let triple = (a << 16) | (b << 8) | c;
        for shift in [18u32, 12, 6, 0] {
            let index = usize::try_from((triple >> shift) & 0x3F).unwrap_or(0);
            out.push(char::from(*ALPHABET.get(index).unwrap_or(&b'A')));
        }
        // One input byte encodes to two symbols, two encode to three; the rest is padding.
        let pad = 3usize.saturating_sub(chunk.len());
        out.truncate(out.len().saturating_sub(pad));
        for _ in 0..pad {
            out.push('=');
        }
    }
    out
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::indexing_slicing)]

    use super::*;

    fn round_trip(bytes: &[u8]) {
        let uri = encode("image/png", bytes);
        let parsed = parse(&uri).unwrap();
        assert_eq!(parsed.media_type, "image/png");
        assert!(parsed.base64);
        let mut budget = u64::MAX;
        assert_eq!(decode(parsed.payload, &mut budget).unwrap(), bytes);
    }

    #[test]
    fn every_length_up_to_a_few_blocks_round_trips() {
        // The padding arithmetic is where a hand-written codec goes wrong, and it goes wrong
        // only at lengths that are not multiples of three.
        for len in 0..64usize {
            let bytes: Vec<u8> = (0..len)
                .map(|i| u8::try_from(i % 251).unwrap_or(0))
                .collect();
            round_trip(&bytes);
        }
        round_trip(&[0x89, b'P', b'N', b'G', 0x0D, 0x0A, 0x1A, 0x0A]);
    }

    #[test]
    fn the_encoding_matches_the_reference_vectors() {
        // RFC 4648 §10, so that "it round-trips" is not the only evidence the alphabet is right.
        for (input, expected) in [
            (&b""[..], ""),
            (b"f", "Zg=="),
            (b"fo", "Zm8="),
            (b"foo", "Zm9v"),
            (b"foob", "Zm9vYg=="),
            (b"fooba", "Zm9vYmE="),
            (b"foobar", "Zm9vYmFy"),
        ] {
            let uri = encode("text/plain", input);
            assert_eq!(
                uri,
                format!("data:text/plain;base64,{expected}"),
                "{input:?}"
            );
        }
    }

    #[test]
    fn a_wrapped_payload_decodes_and_a_corrupt_one_does_not() {
        // Inkscape wraps a long attribute across lines, so skipping whitespace is not optional.
        let mut budget = u64::MAX;
        assert_eq!(decode("Zm9v\n  YmFy", &mut budget).unwrap(), b"foobar");
        // A character outside the alphabet ends the decode rather than being dropped: bytes that
        // are not what the document said would be written back into the user's file.
        let mut budget = u64::MAX;
        assert!(decode("Zm9v*YmFy", &mut budget).is_none());
        // A trailing group of one symbol encodes nothing and is not a truncation we may guess at.
        let mut budget = u64::MAX;
        assert!(decode("Zm9vY", &mut budget).is_none());
    }

    #[test]
    fn decoding_is_charged_before_the_memory_is_committed() {
        // The ceiling exists so that base64 in an attribute cannot be an expansion vector. A
        // check made after decoding would already have committed the allocation.
        let payload = encode("image/png", &vec![0u8; 4096]);
        let payload = payload.split_once(',').unwrap().1;
        let mut plenty = u64::MAX;
        assert!(decode(payload, &mut plenty).is_some());
        let mut stingy = 100u64;
        assert!(decode(payload, &mut stingy).is_none());
        assert_eq!(stingy, 100, "a refused decode must not spend the budget");
    }

    #[test]
    fn the_media_type_is_parsed_but_never_trusted_to_choose_a_handler() {
        let uri = parse("data:image/jpeg;charset=utf-8;base64,Zm9v").unwrap();
        assert_eq!(uri.media_type, "image/jpeg");
        assert!(uri.base64, "`;base64` is a parameter, not a fixed position");

        // A percent-encoded payload is a legal data: URI and is not descended into.
        let plain = parse("data:image/png,%89PNG").unwrap();
        assert!(!plain.base64);

        // Scheme case is not significant, and real documents contain `DATA:`.
        assert!(parse("DATA:image/png;base64,Zg==").is_some());
        assert!(parse("https://example.invalid/x.png").is_none());
        assert!(parse("data:no-comma").is_none());
    }

    #[test]
    fn arbitrary_text_does_not_panic_the_codec() {
        for case in [
            "",
            "data:",
            "data:,",
            "data:;base64,",
            ",",
            "data:a/b;base64",
            "=",
            "====",
            "data:image/png;base64,=A",
            "\u{feff}data:x,y",
        ] {
            let _ = parse(case);
            let _ = decode(case, &mut 1024);
        }
    }
}
