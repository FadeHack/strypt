//! The ZIP container, read and written by hand.
//!
//! OOXML and ``OpenDocument`` are both ZIP archives with an agreed layout inside them, so reaching
//! their metadata means parsing ZIP first. `docs/ROADMAP.md` Phase 2 names this layer as a
//! hostile parser in its own right, and ADR-0028 records why it is written here rather than
//! taken as a dependency: the no-panic rule in ADR-0006 is this project's real safety property
//! and it stops at the crate boundary. Every fuzz defect Phase 1 found was in the one parsing
//! path that sits outside that rule.
//!
//! Everything below follows PKWARE's APPNOTE.TXT 6.3.10; section numbers refer to it.
//!
//! # This is not a general-purpose ZIP implementation
//!
//! It reads the subset that OOXML and ODF actually use and **refuses the rest**, because for
//! this tool a refusal is a correct answer and a partial parse is not. Refused outright:
//!
//! - **Encrypted entries** (§4.4.4, general-purpose bit 0), AES extensions included. strypt
//!   cannot inspect what it cannot read, and reporting success on a document whose parts were
//!   never examined is the failure in `docs/THREAT_MODEL.md` §5.4.
//! - **Every compression method except stored (0) and deflate (8)** (§4.4.5). These are the
//!   two the target formats use. Refusing the others keeps bzip2, LZMA, zstd, XZ, and `PPMd` out
//!   of the dependency tree entirely, which was half the argument in ADR-0028.
//! - **Multi-disk and spanned archives** (§4.4.19–§4.4.21).
//! - **Entry names that are absolute, contain a `..` component, or contain a backslash.**
//!   Nothing here ever writes an entry to the filesystem by name, so traversal is not directly
//!   exploitable today. They are refused anyway: a document containing one is not a document,
//!   and treating it as ordinary is how "we never write these out" quietly stops being true
//!   three phases later.
//!
//! # Nothing is compressed on the way out
//!
//! An entry strypt does not modify is copied through with its original compressed bytes, local
//! header fields, and CRC verbatim. An entry strypt rewrites is re-emitted **stored**. Deflate
//! output is implementation-defined, so compressing on output would make byte-identical
//! idempotence depend on a compressor's internal choices staying stable across versions, which
//! no compressor promises. The cost is a slightly larger output for rewritten parts. The
//! benefit is that this module needs a deflate *decoder* and no encoder at all.

use std::borrow::Cow;

use crate::bytes::Reader;
use crate::error::{MalformedDetail, ResourceLimit};
use crate::formats::ParseLimits;

/// Central directory file header (§4.3.12).
const CENTRAL_HEADER_SIGNATURE: [u8; 4] = [b'P', b'K', 0x01, 0x02];
/// Local file header (§4.3.7).
const LOCAL_HEADER_SIGNATURE: [u8; 4] = [b'P', b'K', 0x03, 0x04];
/// End of central directory record (§4.3.16).
const EOCD_SIGNATURE: [u8; 4] = [b'P', b'K', 0x05, 0x06];
/// ZIP64 end of central directory record (§4.3.14).
const ZIP64_EOCD_SIGNATURE: [u8; 4] = [b'P', b'K', 0x06, 0x06];
/// ZIP64 end of central directory locator (§4.3.15).
const ZIP64_LOCATOR_SIGNATURE: [u8; 4] = [b'P', b'K', 0x06, 0x07];

/// Fixed portion of the end-of-central-directory record, signature included (§4.3.16).
const EOCD_FIXED_BYTES: usize = 22;
/// Fixed portion of the ZIP64 end-of-central-directory locator (§4.3.15).
const ZIP64_LOCATOR_BYTES: usize = 20;

/// The archive comment's length field is 16 bits, so the record can start no further back than
/// this from the end of the file (§4.3.16). Bounding the backward scan is what stops a large
/// file that happens to contain the signature becoming a denial-of-service target.
const MAX_EOCD_SEARCH: usize = EOCD_FIXED_BYTES.saturating_add(u16::MAX as usize);

/// General-purpose bit 0: the entry is encrypted (§4.4.4).
const FLAG_ENCRYPTED: u16 = 1 << 0;
/// General-purpose bit 3: sizes and CRC follow the data in a descriptor rather than appearing
/// in the local header (§4.4.4). The central directory always carries the real values, so this
/// is read but never trusted for sizes — and it is cleared on output, where sizes are known.
const FLAG_DATA_DESCRIPTOR: u16 = 1 << 3;

/// The ZIP64 extended information extra field (§4.5.3).
const ZIP64_EXTRA_ID: u16 = 0x0001;
/// The sentinel a 32-bit field carries when its real value lives in the ZIP64 extra field.
const ZIP64_SENTINEL_32: u32 = 0xFFFF_FFFF;
/// The same sentinel for the 16-bit entry-count fields.
const ZIP64_SENTINEL_16: u16 = 0xFFFF;

/// MS-DOS date for 1980-01-01, the earliest the format can express (§4.4.6).
///
/// Written into every output entry in place of the input's timestamps. Each entry header
/// records when that part was last written, which is a metadata field like any other — see
/// ADR-0030 — and this is the same normalisation ADR-0019 applies to output files.
const DOS_EPOCH_DATE: u16 = 0x0021;
/// MS-DOS time for midnight.
const DOS_EPOCH_TIME: u16 = 0x0000;

/// Version needed to extract, as written on output: 2.0, meaning deflate may be present
/// (§4.4.3.2). Stored entries would permit 1.0, but a single value keeps output uniform.
const VERSION_NEEDED: u16 = 20;

/// The largest ratio between an entry's decompressed and compressed size that this module will
/// produce before refusing.
///
/// An absolute ceiling alone is not enough: `ParseLimits::max_expanded_bytes` defaults to
/// 256 MiB, and without a ratio check a 300-byte archive is entitled to demand all of it. The
/// classic 42.zip layer inflates by roughly 1000:1, and deflate's theoretical maximum is about
/// 1032:1, so this bound sits below what a bomb needs and above what a document reaches —
/// XML compresses well, but not by two orders of magnitude.
const MAX_EXPANSION_RATIO: u64 = 200;

/// A compression method this module will process.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Method {
    /// Method 0: the entry is not compressed.
    Stored,
    /// Method 8: raw deflate.
    Deflate,
}

impl Method {
    /// The method's on-disk code (§4.4.5).
    const fn code(self) -> u16 {
        match self {
            Self::Stored => 0,
            Self::Deflate => 8,
        }
    }
}

/// What went wrong while reading an archive.
///
/// The ZIP layer has no [`crate::detect::Format`] of its own — nobody hands strypt a bare
/// archive — so it reports structurally and the format handler above it attaches its own
/// format when converting to a [`crate::error::StryptError`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ZipError {
    /// The archive violates the format's structure.
    Malformed {
        /// Which rule was broken.
        detail: MalformedDetail,
        /// Where the parser gave up, when the position is known.
        offset: Option<u64>,
    },
    /// A resource ceiling was hit. A refusal, not a failure.
    Limit(ResourceLimit),
}

impl ZipError {
    /// A malformed-structure error at a known offset.
    fn at(detail: MalformedDetail, offset: usize) -> Self {
        Self::Malformed {
            detail,
            offset: u64::try_from(offset).ok(),
        }
    }

    /// A malformed-structure error whose position is not meaningful.
    const fn anywhere(detail: MalformedDetail) -> Self {
        Self::Malformed {
            detail,
            offset: None,
        }
    }

    /// Render as a [`crate::error::StryptError`] for `format`.
    pub(crate) fn into_strypt(self, format: crate::detect::Format) -> crate::error::StryptError {
        match self {
            Self::Malformed { detail, offset } => crate::error::StryptError::Malformed {
                format,
                offset,
                detail,
            },
            Self::Limit(limit) => crate::error::StryptError::LimitExceeded { format, limit },
        }
    }
}

type ZipResult<T> = std::result::Result<T, ZipError>;

/// One entry, as the central directory describes it and as its bytes actually sit in the file.
#[derive(Debug, Clone)]
pub(crate) struct Entry<'a> {
    /// The entry's path within the archive, exactly as stored.
    ///
    /// Kept as bytes rather than a `String` because the format does not require UTF-8 (§4.4.17
    /// makes it conditional on general-purpose bit 11), and a lossy conversion here would let
    /// two distinct entries collide into one name.
    pub(crate) name: &'a [u8],
    /// How the data is compressed.
    pub(crate) method: Method,
    /// CRC-32 of the *uncompressed* data (§4.4.7).
    pub(crate) crc32: u32,
    /// The entry's data exactly as stored, compressed if it is compressed.
    pub(crate) compressed: &'a [u8],
    /// Decompressed length, from the central directory.
    pub(crate) uncompressed_size: u64,
    /// General-purpose flags, carried through so that the UTF-8 name bit (11) survives a
    /// rewrite. Bits this module refuses or invalidates are masked before output.
    pub(crate) flags: u16,
    /// The MS-DOS modification date and time as one packed value, date in the high half
    /// (§4.4.6).
    ///
    /// Read but never used structurally. It exists so the handler above can *report* it: every
    /// entry header records when that part was last written, and a document's part timestamps
    /// describe the author's working hours. Output normalises them (ADR-0030), and a caller
    /// that removes something has to be able to say it did.
    pub(crate) modified: u32,
    /// The central directory's extra field, unparsed beyond ZIP64.
    ///
    /// Also present for reporting rather than for use. The tags worth naming are the extended
    /// timestamp (0x5455), the Unix UID/GID field (0x7875), and NTFS high-precision times
    /// (0x000A) — all of which describe the machine the document was made on, and none of
    /// which survives into output.
    pub(crate) extra: &'a [u8],
}

impl<'a> Entry<'a> {
    /// The entry's name as text, when it is valid UTF-8.
    ///
    /// Only ever used to *match* against the fixed part names OOXML defines, all of which are
    /// ASCII. An entry whose name is not UTF-8 therefore cannot be one of them, and returning
    /// [`None`] routes it to the same place any other unrecognised part goes.
    pub(crate) fn name_str(&self) -> Option<&'a str> {
        std::str::from_utf8(self.name).ok()
    }

    /// True when the entry is a directory marker rather than a file.
    ///
    /// §4.4.17.1: a name ending in `/` denotes a directory, whose data is empty.
    pub(crate) fn is_directory(&self) -> bool {
        self.name.last() == Some(&b'/')
    }

    /// The entry's decompressed contents, bounded as they are produced.
    ///
    /// A stored entry is borrowed rather than copied. A deflated one is inflated against
    /// `budget`, which is the archive-wide remaining allowance — decremented by the caller, so
    /// that a hundred entries each individually within the ceiling cannot collectively exceed
    /// it.
    ///
    /// The CRC-32 is verified against the header. A mismatch is treated as malformed rather
    /// than ignored: if the checksum disagrees, this module is not reading what it thinks it is
    /// reading, and every finding derived from those bytes would be a confident report about
    /// the wrong data.
    pub(crate) fn contents(&self, budget: u64) -> ZipResult<Cow<'a, [u8]>> {
        if self.uncompressed_size > budget {
            return Err(ZipError::Limit(ResourceLimit::ExpandedSize));
        }
        let data: Cow<'a, [u8]> = match self.method {
            Method::Stored => {
                if u64::try_from(self.compressed.len()) != Ok(self.uncompressed_size) {
                    // A stored entry whose two sizes disagree is not merely odd: which of them
                    // a reader believes decides where the data ends.
                    return Err(ZipError::anywhere(MalformedDetail::LengthOutOfRange));
                }
                Cow::Borrowed(self.compressed)
            }
            Method::Deflate => Cow::Owned(inflate_bounded(
                self.compressed,
                self.uncompressed_size,
                budget,
            )?),
        };
        if crc32fast::hash(data.as_ref()) != self.crc32 {
            return Err(ZipError::anywhere(MalformedDetail::BrokenIndex));
        }
        Ok(data)
    }
}

/// Inflate `input` to exactly `expected` bytes, refusing to produce more than `budget`.
///
/// The output buffer is capped before decompression starts rather than checked afterwards. A
/// limit tested after inflating is not a limit — the memory has already been committed by the
/// time it fails.
fn inflate_bounded(input: &[u8], expected: u64, budget: u64) -> ZipResult<Vec<u8>> {
    let ratio_ceiling = u64::try_from(input.len())
        .ok()
        .and_then(|n| n.checked_mul(MAX_EXPANSION_RATIO))
        // An empty compressed payload can still legitimately carry deflate's ~2-byte empty
        // stream, so the floor keeps a zero-length input from having a zero-byte allowance.
        .map_or(u64::MAX, |n| n.max(1024));
    if expected > ratio_ceiling || expected > budget {
        return Err(ZipError::Limit(ResourceLimit::ExpandedSize));
    }
    let capacity =
        usize::try_from(expected).map_err(|_| ZipError::Limit(ResourceLimit::ExpandedSize))?;

    let mut out: Vec<u8> = Vec::with_capacity(capacity);
    let mut decompress = flate2::Decompress::new(false);
    let status = decompress
        .decompress_vec(input, &mut out, flate2::FlushDecompress::Finish)
        .map_err(|_| ZipError::anywhere(MalformedDetail::Truncated))?;

    // `decompress_vec` writes no further than the buffer's capacity, so a stream that wanted
    // more than `expected` bytes stops here with `Ok` rather than `StreamEnd`. That is the
    // bound doing its job, not an ordinary parse failure.
    if status != flate2::Status::StreamEnd {
        return Err(ZipError::Limit(ResourceLimit::ExpandedSize));
    }
    if u64::try_from(out.len()) != Ok(expected) {
        return Err(ZipError::anywhere(MalformedDetail::LengthOutOfRange));
    }
    Ok(out)
}

/// Read every entry of the archive in `data`, in central directory order.
///
/// The central directory is the authority, not the local headers: §4.3.12 makes it the index a
/// reader is meant to use, and a hostile archive can put entirely different values in the two
/// places. Local headers are consulted only to find where each entry's data begins, because
/// their name and extra-field lengths may legitimately differ from the central copy's.
pub(crate) fn read<'a>(data: &'a [u8], limits: &ParseLimits) -> ZipResult<Vec<Entry<'a>>> {
    let eocd = find_eocd(data)?;
    let directory = locate_directory(data, &eocd)?;

    if directory.entries > u64::from(limits.max_items) {
        return Err(ZipError::Limit(ResourceLimit::ItemCount));
    }
    let count = usize::try_from(directory.entries)
        .map_err(|_| ZipError::Limit(ResourceLimit::ItemCount))?;
    let start = usize::try_from(directory.offset)
        .map_err(|_| ZipError::at(MalformedDetail::LengthOutOfRange, 0))?;

    let mut r = Reader::new(data);
    r.seek(start)
        .ok_or_else(|| ZipError::at(MalformedDetail::LengthOutOfRange, start))?;

    let mut entries = Vec::new();
    for _ in 0..count {
        entries.push(read_central_header(data, &mut r)?);
    }
    Ok(entries)
}

/// The end-of-central-directory record's fields, after ZIP64 has been resolved.
struct Eocd {
    /// Offset of the record itself, used to bound the ZIP64 locator search.
    offset: usize,
    entries: u64,
    directory_offset: u64,
}

/// Where the central directory starts and how many records it holds.
struct Directory {
    entries: u64,
    offset: u64,
}

/// Find the end-of-central-directory record by scanning backwards from the end of the file.
///
/// Scanning backwards means the *last* valid record wins, which is what mainstream readers do
/// and therefore what a user's other tools will agree with. Every candidate is validated
/// against its own comment length before it is accepted, so a file that merely contains the
/// four signature bytes somewhere does not derail the parse.
fn find_eocd(data: &[u8]) -> ZipResult<Eocd> {
    let window_start = data.len().saturating_sub(MAX_EOCD_SEARCH);
    let mut candidate = data.len().saturating_sub(EOCD_FIXED_BYTES);

    loop {
        if data.get(candidate..candidate.saturating_add(EOCD_SIGNATURE.len()))
            == Some(EOCD_SIGNATURE.as_slice())
            && let Some(eocd) = parse_eocd(data, candidate)
        {
            return Ok(eocd);
        }
        if candidate <= window_start {
            // Not a ZIP archive at all, or one whose directory has been destroyed. Either way
            // there is nothing to parse, and guessing would mean inventing an entry list.
            return Err(ZipError::anywhere(MalformedDetail::MissingMarker));
        }
        candidate = candidate.saturating_sub(1);
    }
}

/// Parse a candidate end-of-central-directory record, returning [`None`] if it is not one.
fn parse_eocd(data: &[u8], offset: usize) -> Option<Eocd> {
    let mut r = Reader::new(data);
    r.seek(offset)?;
    r.skip(EOCD_SIGNATURE.len())?;

    let this_disk = r.u16_le()?;
    let directory_disk = r.u16_le()?;
    let entries_here = r.u16_le()?;
    let entries_total = r.u16_le()?;
    let _directory_size = r.u32_le()?;
    let directory_offset = r.u32_le()?;
    let comment_len = r.u16_le()?;

    // §4.4.19–§4.4.21. A spanned archive is refused rather than parsed as if it were whole:
    // the parts strypt cannot see might be the ones holding the metadata.
    if this_disk != 0 || directory_disk != 0 || entries_here != entries_total {
        return None;
    }
    // The comment must account for exactly the rest of the file. This is what makes a stray
    // signature inside some other structure fail to validate.
    if usize::from(comment_len) != r.remaining() {
        return None;
    }

    Some(Eocd {
        offset,
        entries: u64::from(entries_total),
        directory_offset: u64::from(directory_offset),
    })
}

/// Resolve the directory's position and size, consulting the ZIP64 records when the 32-bit
/// fields carry their sentinel (§4.3.14, §4.3.15).
///
/// ZIP64 is supported rather than refused because some writers emit it unconditionally, and
/// refusing an ordinary document because of how its producer was configured would be a refusal
/// the user cannot act on.
fn locate_directory(data: &[u8], eocd: &Eocd) -> ZipResult<Directory> {
    let needs_zip64 = eocd.entries == u64::from(ZIP64_SENTINEL_16)
        || eocd.directory_offset == u64::from(ZIP64_SENTINEL_32);
    if !needs_zip64 {
        return Ok(Directory {
            entries: eocd.entries,
            offset: eocd.directory_offset,
        });
    }

    let locator_at = eocd
        .offset
        .checked_sub(ZIP64_LOCATOR_BYTES)
        .ok_or_else(|| ZipError::at(MalformedDetail::MissingMarker, eocd.offset))?;
    let mut r = Reader::new(data);
    r.seek(locator_at)
        .ok_or_else(|| ZipError::at(MalformedDetail::MissingMarker, locator_at))?;
    if r.take(ZIP64_LOCATOR_SIGNATURE.len()) != Some(ZIP64_LOCATOR_SIGNATURE.as_slice()) {
        return Err(ZipError::at(MalformedDetail::MissingMarker, locator_at));
    }
    r.skip(4)
        .ok_or_else(|| ZipError::at(MalformedDetail::Truncated, locator_at))?;
    let record_at =
        read_u64_le(&mut r).ok_or_else(|| ZipError::at(MalformedDetail::Truncated, locator_at))?;
    let record_at = usize::try_from(record_at)
        .map_err(|_| ZipError::at(MalformedDetail::LengthOutOfRange, locator_at))?;

    r.seek(record_at)
        .ok_or_else(|| ZipError::at(MalformedDetail::LengthOutOfRange, locator_at))?;
    if r.take(ZIP64_EOCD_SIGNATURE.len()) != Some(ZIP64_EOCD_SIGNATURE.as_slice()) {
        return Err(ZipError::at(MalformedDetail::MissingMarker, record_at));
    }
    // Record size, version made by, version needed, this disk, directory disk.
    r.skip(8)
        .and_then(|()| r.skip(4))
        .and_then(|()| r.skip(8))
        .ok_or_else(|| ZipError::at(MalformedDetail::Truncated, record_at))?;
    let entries_here =
        read_u64_le(&mut r).ok_or_else(|| ZipError::at(MalformedDetail::Truncated, record_at))?;
    let entries_total =
        read_u64_le(&mut r).ok_or_else(|| ZipError::at(MalformedDetail::Truncated, record_at))?;
    let _directory_size =
        read_u64_le(&mut r).ok_or_else(|| ZipError::at(MalformedDetail::Truncated, record_at))?;
    let directory_offset =
        read_u64_le(&mut r).ok_or_else(|| ZipError::at(MalformedDetail::Truncated, record_at))?;

    if entries_here != entries_total {
        return Err(ZipError::at(MalformedDetail::UnsupportedFeature, record_at));
    }
    Ok(Directory {
        entries: entries_total,
        offset: directory_offset,
    })
}

/// Read one central directory file header and resolve the entry's data.
fn read_central_header<'a>(data: &'a [u8], r: &mut Reader<'a>) -> ZipResult<Entry<'a>> {
    let start = r.position();
    if r.take(CENTRAL_HEADER_SIGNATURE.len()) != Some(CENTRAL_HEADER_SIGNATURE.as_slice()) {
        // The record count and the records disagree. Continuing would mean reading whatever
        // happens to sit here as if it were a header.
        return Err(ZipError::at(MalformedDetail::MissingMarker, start));
    }
    // Version made by, version needed to extract.
    r.skip(4)
        .ok_or_else(|| ZipError::at(MalformedDetail::Truncated, start))?;

    let flags = r
        .u16_le()
        .ok_or_else(|| ZipError::at(MalformedDetail::Truncated, start))?;
    if flags & FLAG_ENCRYPTED != 0 {
        // §4.4.4 bit 0. strypt cannot examine an encrypted part, and a document reported clean
        // on the strength of parts nobody read is the one outcome this project must not
        // produce (`docs/THREAT_MODEL.md` §5.4).
        return Err(ZipError::at(MalformedDetail::UnsupportedFeature, start));
    }

    let method_code = r
        .u16_le()
        .ok_or_else(|| ZipError::at(MalformedDetail::Truncated, start))?;
    let method = match method_code {
        0 => Method::Stored,
        8 => Method::Deflate,
        // Every other method is refused, which is what keeps the C decompressors out of the
        // tree (ADR-0028).
        _ => return Err(ZipError::at(MalformedDetail::UnsupportedFeature, start)),
    };

    // Modification time and date. Kept for reporting only: they are metadata, and output
    // writes a fixed value in their place (ADR-0030).
    let modified = r
        .u32_le()
        .ok_or_else(|| ZipError::at(MalformedDetail::Truncated, start))?;

    let crc32 = r
        .u32_le()
        .ok_or_else(|| ZipError::at(MalformedDetail::Truncated, start))?;
    let compressed_size = r
        .u32_le()
        .ok_or_else(|| ZipError::at(MalformedDetail::Truncated, start))?;
    let uncompressed_size = r
        .u32_le()
        .ok_or_else(|| ZipError::at(MalformedDetail::Truncated, start))?;
    let name_len = r
        .u16_le()
        .ok_or_else(|| ZipError::at(MalformedDetail::Truncated, start))?;
    let extra_len = r
        .u16_le()
        .ok_or_else(|| ZipError::at(MalformedDetail::Truncated, start))?;
    let comment_len = r
        .u16_le()
        .ok_or_else(|| ZipError::at(MalformedDetail::Truncated, start))?;
    let disk = r
        .u16_le()
        .ok_or_else(|| ZipError::at(MalformedDetail::Truncated, start))?;
    // Internal and external file attributes.
    r.skip(6)
        .ok_or_else(|| ZipError::at(MalformedDetail::Truncated, start))?;
    let local_offset = r
        .u32_le()
        .ok_or_else(|| ZipError::at(MalformedDetail::Truncated, start))?;

    let name = r
        .take(usize::from(name_len))
        .ok_or_else(|| ZipError::at(MalformedDetail::Truncated, start))?;
    let extra = r
        .take(usize::from(extra_len))
        .ok_or_else(|| ZipError::at(MalformedDetail::Truncated, start))?;
    r.skip(usize::from(comment_len))
        .ok_or_else(|| ZipError::at(MalformedDetail::Truncated, start))?;

    if disk != 0 && disk != ZIP64_SENTINEL_16 {
        return Err(ZipError::at(MalformedDetail::UnsupportedFeature, start));
    }
    if !name_is_safe(name) {
        return Err(ZipError::at(MalformedDetail::UnexpectedMarker, start));
    }

    let sizes = resolve_zip64_sizes(
        extra,
        compressed_size,
        uncompressed_size,
        local_offset,
        start,
    )?;

    let compressed = slice_entry_data(data, &sizes, start)?;
    Ok(Entry {
        name,
        method,
        crc32,
        compressed,
        uncompressed_size: sizes.uncompressed,
        flags,
        modified,
        extra,
    })
}

/// The packed MS-DOS date and time this module writes on output.
///
/// Exposed so the handler can tell an entry that already carries the normalised value from one
/// that carries a real modification time, without duplicating the constants.
pub(crate) const NORMALISED_DOS_DATETIME: u32 =
    ((DOS_EPOCH_DATE as u32) << 16) | (DOS_EPOCH_TIME as u32);

/// Extra-field tags that carry information about the machine a part was written on.
///
/// Every extra field is dropped on output regardless; this list is what lets the handler
/// distinguish "there was host metadata here and it is gone" from "there was alignment padding
/// here", so that a report says something true rather than something alarming (§4.5).
const HOST_METADATA_EXTRA_TAGS: [u16; 4] = [
    // Extended timestamp: access, modification, and creation times to one-second resolution.
    0x5455, // NTFS: the same three times to 100-nanosecond resolution.
    0x000A, // Unix UID and GID of the file's owner.
    0x7875, // Info-ZIP Unix, an older form of the same.
    0x5855,
];

/// Whether `extra` contains any field that describes the host rather than the archive.
pub(crate) fn extra_names_the_host(extra: &[u8]) -> bool {
    let mut r = Reader::new(extra);
    while r.remaining() >= 4 {
        let Some(id) = r.u16_le() else { return false };
        let Some(len) = r.u16_le() else { return false };
        if r.skip(usize::from(len)).is_none() {
            return false;
        }
        if HOST_METADATA_EXTRA_TAGS.contains(&id) {
            return true;
        }
    }
    false
}

/// An entry's sizes and position, after the ZIP64 extra field has been applied.
struct Sizes {
    compressed: u64,
    uncompressed: u64,
    local_offset: u64,
}

/// Replace any 32-bit field carrying the ZIP64 sentinel with its 64-bit value (§4.5.3).
///
/// The extra field is a sequence of tagged blocks, and the ZIP64 block lists only the values
/// that actually overflowed, in a fixed order. Reading a value that was not written is the
/// classic way to misparse this field, so each is taken only when its 32-bit counterpart says
/// it should be there.
fn resolve_zip64_sizes(
    extra: &[u8],
    compressed: u32,
    uncompressed: u32,
    local_offset: u32,
    start: usize,
) -> ZipResult<Sizes> {
    let mut sizes = Sizes {
        compressed: u64::from(compressed),
        uncompressed: u64::from(uncompressed),
        local_offset: u64::from(local_offset),
    };
    let needs = compressed == ZIP64_SENTINEL_32
        || uncompressed == ZIP64_SENTINEL_32
        || local_offset == ZIP64_SENTINEL_32;
    if !needs {
        return Ok(sizes);
    }

    let mut r = Reader::new(extra);
    while r.remaining() >= 4 {
        let id = r
            .u16_le()
            .ok_or_else(|| ZipError::at(MalformedDetail::Truncated, start))?;
        let len = r
            .u16_le()
            .ok_or_else(|| ZipError::at(MalformedDetail::Truncated, start))?;
        let block = r
            .take(usize::from(len))
            .ok_or_else(|| ZipError::at(MalformedDetail::LengthOutOfRange, start))?;
        if id != ZIP64_EXTRA_ID {
            continue;
        }
        let mut b = Reader::new(block);
        if uncompressed == ZIP64_SENTINEL_32 {
            sizes.uncompressed = read_u64_le(&mut b)
                .ok_or_else(|| ZipError::at(MalformedDetail::Truncated, start))?;
        }
        if compressed == ZIP64_SENTINEL_32 {
            sizes.compressed = read_u64_le(&mut b)
                .ok_or_else(|| ZipError::at(MalformedDetail::Truncated, start))?;
        }
        if local_offset == ZIP64_SENTINEL_32 {
            sizes.local_offset = read_u64_le(&mut b)
                .ok_or_else(|| ZipError::at(MalformedDetail::Truncated, start))?;
        }
        return Ok(sizes);
    }
    // A field declared its value lives in ZIP64 and the block is not there. Refused rather than
    // falling back to the sentinel, which would be read as a four-gigabyte length.
    Err(ZipError::at(MalformedDetail::BrokenIndex, start))
}

/// Find an entry's compressed data by reading its local header for the true data offset.
///
/// The local header's name and extra-field lengths may differ from the central directory's —
/// legitimately, since writers pad the local extra field for alignment — so the data offset
/// cannot be computed from the central copy and has to be read here.
fn slice_entry_data<'a>(data: &'a [u8], sizes: &Sizes, start: usize) -> ZipResult<&'a [u8]> {
    let local_at = usize::try_from(sizes.local_offset)
        .map_err(|_| ZipError::at(MalformedDetail::LengthOutOfRange, start))?;
    let mut r = Reader::new(data);
    r.seek(local_at)
        .ok_or_else(|| ZipError::at(MalformedDetail::LengthOutOfRange, start))?;
    if r.take(LOCAL_HEADER_SIGNATURE.len()) != Some(LOCAL_HEADER_SIGNATURE.as_slice()) {
        // The central directory points somewhere that is not a local header. The two indexes
        // disagree, and a reader that trusts either one in isolation reads different bytes than
        // another reader would.
        return Err(ZipError::at(MalformedDetail::BrokenIndex, local_at));
    }
    // Version needed, flags, method, time, date, CRC, and both sizes: all present in the local
    // header too, and all deliberately ignored. The central directory is the authority
    // (§4.3.12), and where the two disagree the local copy is the one an attacker controls
    // independently of what a directory-reading tool will report.
    r.skip(22)
        .ok_or_else(|| ZipError::at(MalformedDetail::Truncated, local_at))?;
    let name_len = r
        .u16_le()
        .ok_or_else(|| ZipError::at(MalformedDetail::Truncated, local_at))?;
    let extra_len = r
        .u16_le()
        .ok_or_else(|| ZipError::at(MalformedDetail::Truncated, local_at))?;
    r.skip(usize::from(name_len))
        .and_then(|()| r.skip(usize::from(extra_len)))
        .ok_or_else(|| ZipError::at(MalformedDetail::Truncated, local_at))?;

    let data_at = r.position();
    let length = usize::try_from(sizes.compressed)
        .map_err(|_| ZipError::at(MalformedDetail::LengthOutOfRange, start))?;
    let end = data_at
        .checked_add(length)
        .ok_or_else(|| ZipError::at(MalformedDetail::LengthOutOfRange, data_at))?;
    data.get(data_at..end)
        .ok_or_else(|| ZipError::at(MalformedDetail::LengthOutOfRange, data_at))
}

/// Reject an entry name that would escape the archive if it were ever written out.
///
/// Nothing here writes entries to disk, so this is defence for a property that is currently
/// true by construction rather than by check. It is enforced anyway because "we never write
/// these out" is exactly the kind of assumption that stops holding without anyone noticing —
/// and because a document containing such a name is not a document.
fn name_is_safe(name: &[u8]) -> bool {
    if name.is_empty() || name.len() > u16::MAX as usize {
        return false;
    }
    if name.first() == Some(&b'/') {
        return false;
    }
    // A backslash is a separator on Windows and an ordinary character in the format, which is
    // precisely the disagreement traversal payloads are built on.
    if name.contains(&b'\\') {
        return false;
    }
    // A Windows drive letter, which is absolute on one platform and relative on another.
    if matches!(name.get(1), Some(&b':')) {
        return false;
    }
    !name.split(|b| *b == b'/').any(|part| part == b"..")
}

/// Read a little-endian `u64` through the checked reader.
///
/// [`Reader`] stops at 32 bits because no Phase 1 format needed more; ZIP64 does, and building
/// it from two halves here keeps the widening in one place rather than adding a method used by
/// one caller.
fn read_u64_le(r: &mut Reader<'_>) -> Option<u64> {
    let low = u64::from(r.u32_le()?);
    let high = u64::from(r.u32_le()?);
    high.checked_shl(32)?.checked_add(low)
}

/// What the central directory has to say about one written entry.
///
/// A named record rather than a tuple: seven positional fields of which four are integers is a
/// shape where transposing two of them compiles cleanly and produces an archive whose sizes
/// belong to the wrong entry.
struct CentralRecord<'a> {
    offset: u32,
    name: &'a [u8],
    method: Method,
    crc: u32,
    compressed_len: u32,
    uncompressed_len: u32,
    flags: u16,
}

/// An entry as it will be written.
pub(crate) enum Output<'a> {
    /// Copy the entry through with its stored bytes, header fields, and CRC untouched. An
    /// archive whose entries are all copied differs from its input only in entry timestamps
    /// and the offsets in its directory.
    Copied(Entry<'a>),
    /// Write these bytes under this name, stored rather than compressed (ADR-0028).
    Rewritten {
        /// The entry's path within the archive.
        name: Vec<u8>,
        /// The uncompressed contents.
        data: Vec<u8>,
        /// The general-purpose flags to carry over, so a UTF-8 name stays declared as one.
        flags: u16,
    },
}

/// Assemble an archive from a list of entries.
///
/// Every offset and length is computed here rather than copied, so an output archive is
/// internally consistent even when its input was not — which matters, because an input whose
/// local headers and central directory disagreed is exactly the input most likely to reach
/// this function.
///
/// # Errors
///
/// Refuses an archive that would need ZIP64 on output. Ingest is bounded well below four
/// gigabytes (`crate::io::Limits`), so this is unreachable for any file strypt will accept, and
/// it is a refusal rather than a silent truncation of the offset fields.
#[expect(
    clippy::too_many_lines,
    reason = "the local headers, the central directory, and the end record are three views of \
              one set of fields written in the order the specification lays them out; splitting \
              them apart would put the three out of step, and an archive whose three copies of \
              a length disagree is exactly what this module refuses on the way in"
)]
pub(crate) fn write(entries: &[Output<'_>]) -> ZipResult<Vec<u8>> {
    let mut out: Vec<u8> = Vec::new();
    let mut directory: Vec<CentralRecord<'_>> = Vec::with_capacity(entries.len());

    for entry in entries {
        let offset = u32::try_from(out.len())
            .map_err(|_| ZipError::anywhere(MalformedDetail::LengthOutOfRange))?;
        let (name, method, crc, payload, uncompressed, flags): (&[u8], _, _, &[u8], usize, u16) =
            match entry {
                Output::Copied(e) => {
                    let uncompressed = usize::try_from(e.uncompressed_size)
                        .map_err(|_| ZipError::anywhere(MalformedDetail::LengthOutOfRange))?;
                    (
                        e.name,
                        e.method,
                        e.crc32,
                        e.compressed,
                        uncompressed,
                        // The data descriptor bit is cleared because output always writes the
                        // real sizes into the local header. Leaving it set would tell a reader
                        // to look for a descriptor that is not there.
                        e.flags & !FLAG_DATA_DESCRIPTOR,
                    )
                }
                Output::Rewritten { name, data, flags } => (
                    name.as_slice(),
                    Method::Stored,
                    crc32fast::hash(data),
                    data.as_slice(),
                    data.len(),
                    *flags & !FLAG_DATA_DESCRIPTOR,
                ),
            };

        let name_len = u16::try_from(name.len())
            .map_err(|_| ZipError::anywhere(MalformedDetail::LengthOutOfRange))?;
        let compressed_len = u32::try_from(payload.len())
            .map_err(|_| ZipError::anywhere(MalformedDetail::LengthOutOfRange))?;
        let uncompressed_len = u32::try_from(uncompressed)
            .map_err(|_| ZipError::anywhere(MalformedDetail::LengthOutOfRange))?;

        out.extend_from_slice(&LOCAL_HEADER_SIGNATURE);
        out.extend_from_slice(&VERSION_NEEDED.to_le_bytes());
        out.extend_from_slice(&flags.to_le_bytes());
        out.extend_from_slice(&method.code().to_le_bytes());
        out.extend_from_slice(&DOS_EPOCH_TIME.to_le_bytes());
        out.extend_from_slice(&DOS_EPOCH_DATE.to_le_bytes());
        out.extend_from_slice(&crc.to_le_bytes());
        out.extend_from_slice(&compressed_len.to_le_bytes());
        out.extend_from_slice(&uncompressed_len.to_le_bytes());
        out.extend_from_slice(&name_len.to_le_bytes());
        // No extra field on output. The input's extra fields hold alignment padding, ZIP64
        // values this writer does not need, and — in the fields worth naming — Unix UIDs and
        // high-precision modification times (§4.5.5, §4.5.7). Those are metadata, and dropping
        // them is the point of the exercise.
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(name);
        out.extend_from_slice(payload);

        directory.push(CentralRecord {
            offset,
            name,
            method,
            crc,
            compressed_len,
            uncompressed_len,
            flags,
        });
    }

    let directory_offset = u32::try_from(out.len())
        .map_err(|_| ZipError::anywhere(MalformedDetail::LengthOutOfRange))?;
    for record in &directory {
        let CentralRecord {
            offset,
            name,
            method,
            crc,
            compressed_len,
            uncompressed_len,
            flags,
        } = record;
        let name_len = u16::try_from(name.len())
            .map_err(|_| ZipError::anywhere(MalformedDetail::LengthOutOfRange))?;
        out.extend_from_slice(&CENTRAL_HEADER_SIGNATURE);
        // Version made by: 2.0, with 0 in the high byte for the "MS-DOS and FAT" host system
        // (§4.4.2). A fixed value rather than the input's, because the producing platform is
        // itself a fingerprint — an archive stamped "Unix" narrows its author's machine before
        // anyone opens it.
        //
        // Zero specifically, because it is what Word writes. mat2 normalises the same field to
        // 3, which says "made on Linux", and then reports any other value — including this one
        // — as "Weird", since it recognises only 2 and 3. Neither tool leaks the real host; the
        // difference is which constant blends in, and for a document that is supposed to look
        // like an ordinary Office file, Word's own value is the quieter choice.
        out.extend_from_slice(&VERSION_NEEDED.to_le_bytes());
        out.extend_from_slice(&VERSION_NEEDED.to_le_bytes());
        out.extend_from_slice(&flags.to_le_bytes());
        out.extend_from_slice(&method.code().to_le_bytes());
        out.extend_from_slice(&DOS_EPOCH_TIME.to_le_bytes());
        out.extend_from_slice(&DOS_EPOCH_DATE.to_le_bytes());
        out.extend_from_slice(&crc.to_le_bytes());
        out.extend_from_slice(&compressed_len.to_le_bytes());
        out.extend_from_slice(&uncompressed_len.to_le_bytes());
        out.extend_from_slice(&name_len.to_le_bytes());
        // Extra length, comment length, disk number, internal attributes.
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        // External attributes: zeroed. They carry Unix permission bits, which describe the
        // machine the document was made on.
        out.extend_from_slice(&0u32.to_le_bytes());
        out.extend_from_slice(&offset.to_le_bytes());
        out.extend_from_slice(name);
    }

    let directory_size = u32::try_from(out.len().saturating_sub(directory_offset as usize))
        .map_err(|_| ZipError::anywhere(MalformedDetail::LengthOutOfRange))?;
    let count = u16::try_from(directory.len())
        .map_err(|_| ZipError::anywhere(MalformedDetail::LengthOutOfRange))?;

    out.extend_from_slice(&EOCD_SIGNATURE);
    out.extend_from_slice(&0u16.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    out.extend_from_slice(&count.to_le_bytes());
    out.extend_from_slice(&count.to_le_bytes());
    out.extend_from_slice(&directory_size.to_le_bytes());
    out.extend_from_slice(&directory_offset.to_le_bytes());
    // No archive comment. The input's is dropped rather than copied: it is free-form text at
    // the end of the file that no application shows, which makes it a good hiding place and a
    // poor thing to preserve.
    out.extend_from_slice(&0u16.to_le_bytes());

    Ok(out)
}

/// Whether the archive-wide decompression budget has room for `entry`.
///
/// Kept next to the reader rather than in the handler so that the archive-wide accounting and
/// the per-entry ceiling cannot drift apart.
pub(crate) fn spend(budget: &mut u64, spent: u64) -> ZipResult<()> {
    *budget = budget
        .checked_sub(spent)
        .ok_or(ZipError::Limit(ResourceLimit::ExpandedSize))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    // Test code is never reachable from untrusted bytes, which is the boundary the
    // panic-freedom lints police (ADR-0006).
    #![allow(clippy::unwrap_used, clippy::indexing_slicing)]

    use super::*;

    /// Build a minimal archive from name/contents pairs, all stored.
    fn archive(parts: &[(&str, &[u8])]) -> Vec<u8> {
        let outputs: Vec<Output<'_>> = parts
            .iter()
            .map(|(name, data)| Output::Rewritten {
                name: name.as_bytes().to_vec(),
                data: (*data).to_vec(),
                flags: 0,
            })
            .collect();
        write(&outputs).unwrap()
    }

    #[test]
    fn a_written_archive_reads_back_with_the_same_entries() {
        let bytes = archive(&[("a.xml", b"<a/>"), ("dir/b.bin", &[0u8; 32])]);
        let entries = read(&bytes, &ParseLimits::default()).unwrap();

        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].name_str(), Some("a.xml"));
        assert_eq!(
            entries[0].contents(u64::MAX).unwrap().as_ref(),
            b"<a/>".as_slice()
        );
        assert_eq!(entries[1].name_str(), Some("dir/b.bin"));
        assert_eq!(entries[1].contents(u64::MAX).unwrap().len(), 32);
    }

    #[test]
    fn writing_is_deterministic() {
        // Invariant 4 in docs/TESTING_STRATEGY.md §1: the same input must produce the same
        // bytes every time, which is what makes byte-identical idempotence testable at all.
        let a = archive(&[("x", b"1"), ("y", b"2")]);
        let b = archive(&[("x", b"1"), ("y", b"2")]);
        assert_eq!(a, b);
    }

    #[test]
    fn an_entry_timestamp_is_normalised_rather_than_preserved() {
        // Each entry header records when that part was last written, which is a metadata field
        // of its own (ADR-0030).
        let bytes = archive(&[("a", b"x")]);
        // Local header: signature(4) version(2) flags(2) method(2) time(2) date(2).
        assert_eq!(&bytes[10..12], DOS_EPOCH_TIME.to_le_bytes());
        assert_eq!(&bytes[12..14], DOS_EPOCH_DATE.to_le_bytes());
    }

    #[test]
    fn an_encrypted_entry_is_refused_not_skipped() {
        // Skipping it would mean reporting a document clean on the strength of parts nobody
        // read (docs/THREAT_MODEL.md §5.4).
        let mut bytes = archive(&[("secret.xml", b"<a/>")]);
        // Set general-purpose bit 0 in the central directory header, which is the copy `read`
        // trusts. The directory starts right after the single local entry.
        let dir = bytes
            .windows(4)
            .position(|w| w == CENTRAL_HEADER_SIGNATURE)
            .unwrap();
        bytes[dir + 8] |= 1;
        assert!(matches!(
            read(&bytes, &ParseLimits::default()),
            Err(ZipError::Malformed {
                detail: MalformedDetail::UnsupportedFeature,
                ..
            })
        ));
    }

    #[test]
    fn an_unsupported_compression_method_is_refused() {
        let mut bytes = archive(&[("a.xml", b"<a/>")]);
        let dir = bytes
            .windows(4)
            .position(|w| w == CENTRAL_HEADER_SIGNATURE)
            .unwrap();
        // Method field sits ten bytes into the central header. 93 is zstd — one of the methods
        // whose decoder ADR-0028 deliberately keeps out of the tree.
        bytes[dir + 10..dir + 12].copy_from_slice(&93u16.to_le_bytes());
        assert!(matches!(
            read(&bytes, &ParseLimits::default()),
            Err(ZipError::Malformed {
                detail: MalformedDetail::UnsupportedFeature,
                ..
            })
        ));
    }

    #[test]
    fn traversal_and_absolute_names_are_refused() {
        for name in ["../escape.xml", "/etc/passwd", "a\\b.xml", "C:/x.xml"] {
            assert!(
                !name_is_safe(name.as_bytes()),
                "{name} should have been refused"
            );
        }
        for name in ["word/media/image1.png", "[Content_Types].xml", "a..b/c"] {
            assert!(name_is_safe(name.as_bytes()), "{name} is an ordinary name");
        }
    }

    #[test]
    fn a_file_with_no_end_record_is_refused() {
        assert!(matches!(
            read(b"PK\x03\x04 not really an archive", &ParseLimits::default()),
            Err(ZipError::Malformed {
                detail: MalformedDetail::MissingMarker,
                ..
            })
        ));
    }

    #[test]
    fn an_entry_count_beyond_the_ceiling_is_refused_before_allocating() {
        // The count is read from the file, so it is attacker-chosen. Refusing on the declared
        // value rather than on what is actually present is what stops a 22-byte file asking for
        // 65535 allocations.
        let mut bytes = archive(&[("a", b"x")]);
        let eocd = bytes.windows(4).rposition(|w| w == EOCD_SIGNATURE).unwrap();
        bytes[eocd + 8..eocd + 10].copy_from_slice(&500u16.to_le_bytes());
        bytes[eocd + 10..eocd + 12].copy_from_slice(&500u16.to_le_bytes());
        let limits = ParseLimits {
            max_items: 10,
            ..ParseLimits::default()
        };
        assert!(matches!(
            read(&bytes, &limits),
            Err(ZipError::Limit(ResourceLimit::ItemCount))
        ));
    }

    #[test]
    fn a_crc_that_does_not_match_the_data_is_refused() {
        // A checksum disagreement means this module is not reading what it thinks it is, and
        // every finding derived from those bytes would describe the wrong data.
        let mut bytes = archive(&[("a.xml", b"<a/>")]);
        let dir = bytes
            .windows(4)
            .position(|w| w == CENTRAL_HEADER_SIGNATURE)
            .unwrap();
        bytes[dir + 16..dir + 20].copy_from_slice(&0xDEAD_BEEFu32.to_le_bytes());
        let entries = read(&bytes, &ParseLimits::default()).unwrap();
        assert!(entries[0].contents(u64::MAX).is_err());
    }

    #[test]
    fn a_stored_entry_whose_sizes_disagree_is_refused() {
        let mut bytes = archive(&[("a.xml", b"<a/>")]);
        let dir = bytes
            .windows(4)
            .position(|w| w == CENTRAL_HEADER_SIGNATURE)
            .unwrap();
        // Uncompressed size, four bytes after the compressed size.
        bytes[dir + 24..dir + 28].copy_from_slice(&99u32.to_le_bytes());
        let entries = read(&bytes, &ParseLimits::default()).unwrap();
        assert!(entries[0].contents(u64::MAX).is_err());
    }

    #[test]
    fn a_declared_expansion_beyond_the_budget_is_refused_before_inflating() {
        // The bound has to bite before the memory is committed: a limit checked after
        // decompressing is not a limit.
        let entry = Entry {
            name: b"bomb.xml",
            method: Method::Deflate,
            crc32: 0,
            compressed: &[0x00; 64],
            uncompressed_size: 1_000_000_000,
            flags: 0,
            modified: NORMALISED_DOS_DATETIME,
            extra: &[],
        };
        assert!(matches!(
            entry.contents(4096),
            Err(ZipError::Limit(ResourceLimit::ExpandedSize))
        ));
    }

    #[test]
    fn the_expansion_ratio_bounds_a_small_archive_with_a_large_budget() {
        // The archive-wide byte ceiling alone would let 64 compressed bytes demand the whole
        // allowance, which is the shape of every zip bomb.
        let entry = Entry {
            name: b"bomb.xml",
            method: Method::Deflate,
            crc32: 0,
            compressed: &[0x00; 64],
            uncompressed_size: 64 * MAX_EXPANSION_RATIO + 1,
            flags: 0,
            modified: NORMALISED_DOS_DATETIME,
            extra: &[],
        };
        assert!(matches!(
            entry.contents(u64::MAX),
            Err(ZipError::Limit(ResourceLimit::ExpandedSize))
        ));
    }

    #[test]
    fn the_budget_refuses_rather_than_wrapping() {
        let mut budget = 10u64;
        assert!(spend(&mut budget, 4).is_ok());
        assert_eq!(budget, 6);
        assert!(matches!(
            spend(&mut budget, 7),
            Err(ZipError::Limit(ResourceLimit::ExpandedSize))
        ));
    }

    #[test]
    fn truncating_a_valid_archive_anywhere_does_not_panic() {
        let bytes = archive(&[("a.xml", b"<a/>"), ("b/c.bin", &[7u8; 100])]);
        for n in 0..bytes.len() {
            let prefix = bytes.get(0..n).unwrap_or_default();
            if let Ok(entries) = read(prefix, &ParseLimits::default()) {
                for entry in &entries {
                    let _ = entry.contents(1 << 20);
                }
            }
        }
    }

    #[test]
    fn a_directory_offset_pointing_outside_the_file_is_refused() {
        let mut bytes = archive(&[("a", b"x")]);
        let eocd = bytes.windows(4).rposition(|w| w == EOCD_SIGNATURE).unwrap();
        bytes[eocd + 16..eocd + 20].copy_from_slice(&0x7FFF_0000u32.to_le_bytes());
        assert!(read(&bytes, &ParseLimits::default()).is_err());
    }

    #[test]
    fn a_stray_end_record_signature_in_the_data_does_not_derail_the_parse() {
        // Every candidate is validated against its own comment length, so a payload that
        // happens to contain the four signature bytes is not mistaken for the real record.
        let mut payload = EOCD_SIGNATURE.to_vec();
        payload.extend_from_slice(&[0u8; 40]);
        let bytes = archive(&[("a.bin", &payload)]);
        let entries = read(&bytes, &ParseLimits::default()).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].name_str(), Some("a.bin"));
    }
}
