//! Checked sequential reading over an in-memory byte slice.
//!
//! Every format handler walks attacker-controlled bytes, and every length, offset, and count
//! it reads is attacker-controlled too (`docs/ARCHITECTURE.md` §5.1). This module is the
//! single place where that walking happens, so that bounds and overflow checks exist once
//! and correctly rather than being re-derived in four handlers.
//!
//! The whole surface returns [`Option`]: running off the end of a truncated file is expected
//! input, not an error condition worth a distinct type at this layer. Handlers convert a
//! [`None`] into the specific typed error that describes what they were looking for.
//!
//! Note what is deliberately absent: indexing, slicing with ranges, and unchecked
//! arithmetic. `strypt-core` denies all three (ADR-0006), and this module is written so that
//! handlers never need them.
//!
//! Some of the accessors below are not yet called: the JPEG, PNG, and WebP handlers landing
//! later in this phase are what read little-endian lengths and single bytes. The allowance is
//! scoped to this module and comes off as those handlers arrive — the alternative, trimming
//! the primitive to exactly today's callers and regrowing it three times, would churn the one
//! file where a mistake is most expensive.
#![allow(dead_code)]

/// A cursor over a byte slice that cannot read out of bounds and cannot overflow.
///
/// Invariant, upheld by every method: `self.pos <= self.data.len()`.
pub(crate) struct Reader<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    /// Start reading `data` from offset zero.
    pub(crate) const fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }

    /// Current offset from the start of the slice.
    pub(crate) const fn position(&self) -> usize {
        self.pos
    }

    /// Bytes left to read.
    pub(crate) const fn remaining(&self) -> usize {
        // Cannot underflow: `pos <= data.len()` is this type's invariant.
        self.data.len().saturating_sub(self.pos)
    }

    /// True when the cursor has consumed the whole slice.
    pub(crate) const fn is_empty(&self) -> bool {
        self.remaining() == 0
    }

    /// Move the cursor to an absolute offset, refusing to seek past the end.
    ///
    /// Refusing rather than clamping is deliberate: a clamped seek turns a lying offset in a
    /// hostile file into a silent read of the wrong bytes, which is exactly the class of bug
    /// that produces a confident report about a file that was never really parsed.
    pub(crate) fn seek(&mut self, offset: usize) -> Option<()> {
        if offset > self.data.len() {
            return None;
        }
        self.pos = offset;
        Some(())
    }

    /// Advance by `n` bytes, or return [`None`] if fewer than `n` remain.
    pub(crate) fn skip(&mut self, n: usize) -> Option<()> {
        self.take(n).map(|_| ())
    }

    /// Consume and return the next `n` bytes, or [`None`] if fewer than `n` remain.
    pub(crate) fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        let end = self.pos.checked_add(n)?;
        let out = self.data.get(self.pos..end)?;
        self.pos = end;
        Some(out)
    }

    /// Return the next `n` bytes without consuming them.
    pub(crate) fn peek(&self, n: usize) -> Option<&'a [u8]> {
        let end = self.pos.checked_add(n)?;
        self.data.get(self.pos..end)
    }

    /// Consume everything from the cursor to the end of the slice.
    pub(crate) fn take_rest(&mut self) -> &'a [u8] {
        let out = self.data.get(self.pos..).unwrap_or_default();
        self.pos = self.data.len();
        out
    }

    /// Consume one byte.
    pub(crate) fn u8(&mut self) -> Option<u8> {
        self.take(1)?.first().copied()
    }

    /// Consume a big-endian `u16`.
    pub(crate) fn u16_be(&mut self) -> Option<u16> {
        let b: [u8; 2] = self.take(2)?.try_into().ok()?;
        Some(u16::from_be_bytes(b))
    }

    /// Consume a big-endian `u32`.
    pub(crate) fn u32_be(&mut self) -> Option<u32> {
        let b: [u8; 4] = self.take(4)?.try_into().ok()?;
        Some(u32::from_be_bytes(b))
    }

    /// Consume a little-endian `u32`.
    pub(crate) fn u32_le(&mut self) -> Option<u32> {
        let b: [u8; 4] = self.take(4)?.try_into().ok()?;
        Some(u32::from_le_bytes(b))
    }
}

/// Widen a `u32` read from a file to a `usize` for use as a length or offset.
///
/// On a 16-bit target this can genuinely fail, so it is fallible rather than a cast. A cast
/// would be a silent truncation driven by a value the attacker chose.
pub(crate) fn u32_to_usize(value: u32) -> Option<usize> {
    usize::try_from(value).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn take_stops_at_the_end_instead_of_panicking() {
        let mut r = Reader::new(&[1, 2, 3]);
        assert_eq!(r.take(2), Some(&[1u8, 2][..]));
        assert_eq!(r.take(2), None, "a truncated read yields None, not a panic");
        assert_eq!(r.remaining(), 1, "a failed take must not consume anything");
    }

    #[test]
    fn a_length_field_near_usize_max_cannot_overflow_the_cursor() {
        // Models a hostile file whose declared segment length is absurd: the addition
        // `pos + n` would wrap on a release build without overflow checks.
        let mut r = Reader::new(&[0xFF; 8]);
        assert_eq!(r.skip(4), Some(()));
        assert_eq!(r.take(usize::MAX), None);
        assert_eq!(r.position(), 4, "the cursor is unmoved by a failed read");
    }

    #[test]
    fn seek_past_the_end_is_refused_not_clamped() {
        let mut r = Reader::new(&[1, 2, 3]);
        assert_eq!(r.seek(4), None);
        assert_eq!(r.position(), 0);
        assert_eq!(r.seek(3), Some(()), "seeking exactly to the end is valid");
        assert!(r.is_empty());
    }

    #[test]
    fn integers_are_read_with_the_declared_endianness() {
        let mut r = Reader::new(&[0x00, 0x01, 0x00, 0x00, 0x00, 0x02]);
        assert_eq!(r.u16_be(), Some(1));
        assert_eq!(r.u32_be(), Some(2));
        assert_eq!(r.u8(), None);
    }

    #[test]
    fn take_rest_is_total() {
        let mut r = Reader::new(&[1, 2, 3]);
        assert_eq!(r.skip(1), Some(()));
        assert_eq!(r.take_rest(), &[2, 3][..]);
        assert_eq!(r.take_rest(), &[][..], "calling it again is harmless");
    }
}
