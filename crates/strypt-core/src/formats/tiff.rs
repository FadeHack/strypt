//! TIFF, the format whose metadata *is* its file structure.
//!
//! Every other image handler in this crate removes metadata by dropping the container it sits
//! in: a JPEG `APP1` segment, a PNG `eXIf` chunk, a WebP `EXIF` chunk. Each is a delimited
//! region that can be excised whole, which is why [`super::exif`] only ever reads — as its
//! header says, a TIFF is a graph of absolute file offsets and editing tags out of one means
//! rewriting every offset that followed.
//!
//! A standalone TIFF has no block to drop. So this handler does not edit one. It **writes a new
//! one** (ADR-0033):
//!
//! - **Every offset in the output is computed while writing it**, against the buffer being
//!   built. No offset from the input is ever carried across, so the failure `exif.rs` warns
//!   about — a file that still parses while pointing at the wrong bytes — has nothing to arise
//!   from.
//! - **Tags are written from an allow-list** of what is needed to decode the image, and
//!   nothing else exists in the output because nothing else was ever written. The direction
//!   matters: a deny-list carries an unknown tag through, and the tags that leak hardest here
//!   are the ones no tag table has heard of — a vendor maker note, a scanner's private field
//!   holding a serial number.
//! - **The image data is copied byte for byte.** Strips and tiles are moved, never decoded and
//!   never recompressed, so the output's pixels are bit-identical to the input's. mat2's
//!   default TIFF path re-renders the image through `GdkPixbuf` instead, which reaches metadata
//!   hidden inside the compressed data that a container rebuild cannot; where that is the
//!   user's concern, mat2 is the better recommendation (`docs/THREAT_MODEL.md` §7.8).
//!
//! # What this means for the output
//!
//! **A stripped TIFF is never byte-identical to its input, even when the input carried no
//! metadata at all** — a rebuild reorders the file by construction. Stripping an *already
//! stripped* file is byte-identical, and that idempotence is what proves the writer's output is
//! a fixed point of its own reader.
//!
//! # Hostility
//!
//! Everything read below — every offset, count, and length — was chosen by whoever made the
//! file. Directory offsets are walked at most once each so a cycle terminates, entry counts are
//! drawn from a shared budget so a wide directory cannot be traded for a deep one, and every
//! strip is bounds-checked against the input before a byte of it is copied.

use crate::bytes::{Reader, u32_to_usize};
use crate::detect::Format;
use crate::error::{MalformedDetail, ResourceLimit, Result, StryptError};
use crate::formats::exif::{Endian, Ifd};
use crate::formats::{MetadataHandler, ParseLimits, StripOptions, Stripped, exif};

pub(crate) mod tags;
use crate::report::{Finding, InspectOptions, MetadataKind, MetadataReport, Note, StripReport};

/// The TIFF handler.
#[derive(Debug, Clone, Copy, Default)]
#[non_exhaustive]
pub struct TiffHandler;

impl MetadataHandler for TiffHandler {
    fn name(&self) -> &'static str {
        Format::Tiff.id()
    }

    fn format(&self) -> Format {
        Format::Tiff
    }

    fn inspect(&self, input: &[u8], options: &InspectOptions) -> Result<MetadataReport> {
        // The identical pass that stripping runs, with the output discarded — so "everything
        // `strip` removes is something `inspect` can see" holds by construction rather than by
        // two code paths agreeing to stay in step, which is what makes the pipeline's
        // verification pass mean anything (`docs/ARCHITECTURE.md` §3).
        let processed = process(input, options, &ParseLimits::default())?;
        Ok(MetadataReport {
            format: Format::Tiff,
            findings: processed.findings,
            notes: processed.notes,
        })
    }

    fn strip(&self, input: &[u8], options: &StripOptions) -> Result<Stripped> {
        let processed = process(input, &options.inspect, &options.limits)?;
        Ok(Stripped {
            report: StripReport {
                format: Format::Tiff,
                removed: processed.findings,
                retained: Vec::new(),
                notes: processed.notes,
                input_bytes: as_u64(input.len()),
                output_bytes: as_u64(processed.output.len()),
            },
            bytes: processed.output,
        })
    }
}

/// One run of the shared inspect/strip pass.
struct Processed {
    output: Vec<u8>,
    findings: Vec<Finding>,
    notes: Vec<Note>,
}

/// Read `input`, name what is being dropped, and write the rebuilt file.
fn process(input: &[u8], options: &InspectOptions, limits: &ParseLimits) -> Result<Processed> {
    let (endian, first) = header(input)?;

    let mut walk = Walk {
        input,
        endian,
        options,
        budget: limits.max_items,
        visited: Vec::new(),
        findings: Vec::new(),
        notes: Vec::new(),
    };

    // The IFDs form a chain: each directory ends with the offset of the next. In a standalone
    // TIFF a chained directory is another *page* — a scanned dossier is the case that matters
    // here — unless it flags itself as a reduced-resolution copy, which is the thumbnail case
    // and is dropped (`docs/THREAT_MODEL.md` §3).
    let mut pages: Vec<Page<'_>> = Vec::new();
    let mut next = first;
    while next != 0 {
        let start =
            u32_to_usize(next).ok_or_else(|| malformed(MalformedDetail::LengthOutOfRange))?;
        if walk.visited.contains(&start) {
            return Err(malformed(MalformedDetail::CyclicReference));
        }
        walk.visited.push(start);
        let (page, following) = walk.directory(start)?;
        if let Some(page) = page {
            pages.push(page);
        }
        next = following;
    }

    if pages.is_empty() {
        // Either the file had no directories at all, or every one of them was a
        // reduced-resolution copy. Writing an image-less TIFF would be handing back something
        // that is not the file the user gave us, presented as a clean version of it.
        return Err(malformed(MalformedDetail::MissingMarker));
    }

    let output = write(endian, &pages)?;
    Ok(Processed {
        output,
        findings: walk.findings,
        notes: walk.notes,
    })
}

/// Read the header, returning the byte order and the offset of the first directory.
///
/// `BigTIFF` — magic 43, with eight-byte offsets throughout — is refused by name rather than
/// parsed badly. Its directory layout is not the one below, and a parser that reads it as
/// though it were would produce confident nonsense (ADR-0033).
fn header(input: &[u8]) -> Result<(Endian, u32)> {
    let mut r = Reader::new(input);
    let endian = match r.take(2) {
        Some(b"II") => Endian::Little,
        Some(b"MM") => Endian::Big,
        _ => return Err(malformed(MalformedDetail::MissingMarker)),
    };
    // TIFF 6.0 §2: the magic number is 42 in the declared byte order, and it is the only thing
    // distinguishing a real header from two bytes that happen to spell "MM".
    match endian.u16(&mut r) {
        Some(42) => {}
        Some(43) => return Err(malformed(MalformedDetail::UnsupportedFeature)),
        _ => return Err(malformed(MalformedDetail::MissingMarker)),
    }
    let first = endian
        .u32(&mut r)
        .ok_or_else(|| malformed(MalformedDetail::Truncated))?;
    Ok((endian, first))
}

/// A directory that will be written to the output.
struct Page<'a> {
    /// Allow-listed tags, copied across with their values unchanged.
    verbatim: Vec<Verbatim<'a>>,
    /// The strips or tiles, in order, exactly as they appeared in the input.
    data: Vec<&'a [u8]>,
    /// Whether the image is tiled, which decides the pair of tags the geometry is written under.
    tiled: bool,
}

/// One allow-listed tag and the value bytes it will be written with.
struct Verbatim<'a> {
    tag: u16,
    field_type: u16,
    count: u32,
    value: &'a [u8],
}

/// State carried through the walk, so the budget and the visited set are shared across
/// directories rather than reset per directory — which is what stops a file trading a legal
/// number of directories against a legal number of entries in each.
struct Walk<'a, 'o> {
    input: &'a [u8],
    endian: Endian,
    options: &'o InspectOptions,
    budget: u32,
    visited: Vec<usize>,
    findings: Vec<Finding>,
    notes: Vec<Note>,
}

/// A directory entry as it appears on disk, before its value is resolved.
struct RawEntry<'a> {
    tag: u16,
    field_type: u16,
    count: u32,
    /// The entry's own four value bytes: the value itself when it fits, otherwise its offset.
    inline: &'a [u8],
}

impl<'a> Walk<'a, '_> {
    /// Walk one directory, returning the page to write (if it is one) and the next offset.
    fn directory(&mut self, start: usize) -> Result<(Option<Page<'a>>, u32)> {
        let mut r = Reader::new(self.input);
        r.seek(start)
            .ok_or_else(|| malformed(MalformedDetail::LengthOutOfRange))?;
        let count = self
            .endian
            .u16(&mut r)
            .ok_or_else(|| malformed(MalformedDetail::Truncated))?;

        let mut raw: Vec<RawEntry<'a>> = Vec::new();
        for _ in 0..count {
            if self.budget == 0 {
                return Err(StryptError::LimitExceeded {
                    format: Format::Tiff,
                    limit: ResourceLimit::ItemCount,
                });
            }
            self.budget = self.budget.saturating_sub(1);
            raw.push(self.raw_entry(&mut r)?);
        }
        let following = self
            .endian
            .u32(&mut r)
            .ok_or_else(|| malformed(MalformedDetail::Truncated))?;

        // TIFF 6.0 §8, tag 0x00FE: bit 0 of NewSubfileType marks a reduced-resolution copy of
        // another image in the same file. That is a thumbnail, and a thumbnail survives every
        // crop and every redaction painted over the picture it was made from.
        if self.is_reduced_resolution(&raw) {
            self.findings.push(
                Finding::new(MetadataKind::Thumbnail, "TIFF reduced-resolution IFD", 0)
                    .with_field("reduced-resolution image"),
            );
            return Ok((None, following));
        }

        let page = self.page(&raw)?;
        Ok((Some(page), following))
    }

    /// Read one 12-byte directory entry.
    fn raw_entry(&mut self, r: &mut Reader<'a>) -> Result<RawEntry<'a>> {
        let truncated = || malformed(MalformedDetail::Truncated);
        let tag = self.endian.u16(r).ok_or_else(truncated)?;
        let field_type = self.endian.u16(r).ok_or_else(truncated)?;
        let count = self.endian.u32(r).ok_or_else(truncated)?;
        let inline = r.take(4).ok_or_else(truncated)?;
        Ok(RawEntry {
            tag,
            field_type,
            count,
            inline,
        })
    }

    /// Whether this directory declares itself a reduced-resolution copy.
    fn is_reduced_resolution(&self, raw: &[RawEntry<'a>]) -> bool {
        raw.iter()
            .find(|e| e.tag == tags::NEW_SUBFILE_TYPE)
            .and_then(|e| self.value_of(e))
            .and_then(|v| integer(self.endian, v, tags::LONG))
            .is_some_and(|v| v & 1 == 1)
    }

    /// Resolve an entry's value, refusing one that runs past the end of the file.
    ///
    /// TIFF 6.0 §2: a value of four bytes or fewer is stored in the entry itself; anything
    /// longer is stored elsewhere and those four bytes are its offset.
    fn value_of(&self, entry: &RawEntry<'a>) -> Option<&'a [u8]> {
        let size = exif::type_size(entry.field_type)?;
        let length = u64::from(entry.count).checked_mul(u64::from(size))?;
        let length = usize::try_from(length).ok()?;
        if length <= 4 {
            return entry.inline.get(0..length);
        }
        let mut w = Reader::new(entry.inline);
        let at = u32_to_usize(self.endian.u32(&mut w)?)?;
        let mut r = Reader::new(self.input);
        r.seek(at)?;
        r.take(length)
    }

    /// Split one directory into what is kept and what is reported as removed.
    fn page(&mut self, raw: &[RawEntry<'a>]) -> Result<Page<'a>> {
        let tiled = raw.iter().any(|e| e.tag == tags::TILE_OFFSETS);

        let mut verbatim: Vec<Verbatim<'a>> = Vec::new();
        let mut offsets: Option<Vec<u64>> = None;
        let mut counts: Option<Vec<u64>> = None;

        for entry in raw {
            let value = self.value_of(entry);

            // The four tags that carry the image data's position and size are not copied:
            // they are regenerated from where the data lands in the output.
            let (offsets_tag, counts_tag) = geometry_tags(tiled);
            if entry.tag == offsets_tag {
                offsets = Some(self.integers(entry, value)?);
                continue;
            }
            if entry.tag == counts_tag {
                counts = Some(self.integers(entry, value)?);
                continue;
            }
            // The unused half of the strip/tile pair describes a geometry this image does not
            // use. It is structural rather than identifying, and copying it across would
            // contradict the geometry that is actually written.
            if matches!(
                entry.tag,
                tags::STRIP_OFFSETS
                    | tags::STRIP_BYTE_COUNTS
                    | tags::TILE_OFFSETS
                    | tags::TILE_BYTE_COUNTS
            ) {
                continue;
            }

            if tags::is_structural(entry.tag) {
                // Duplicated tags are not an error in the wild; the first wins, and the second
                // is dropped rather than written twice into a directory that must be sorted.
                if verbatim.iter().any(|v| v.tag == entry.tag) {
                    continue;
                }
                let value = value.ok_or_else(|| malformed(MalformedDetail::LengthOutOfRange))?;
                verbatim.push(Verbatim {
                    tag: entry.tag,
                    field_type: entry.field_type,
                    count: entry.count,
                    value,
                });
                continue;
            }

            // Everything else is removed by never being written. A pointer tag is reported by
            // its contents rather than by itself: the four bytes of the pointer identify
            // nobody, and what they lead to identifies everybody.
            if let Some(sub) = exif::sub_directory(Ifd::Primary, entry.tag) {
                self.report_sub_directory(entry, value, sub);
                continue;
            }
            self.report_removed(Ifd::Primary, entry, value);
        }

        let offsets = offsets.ok_or_else(|| malformed(MalformedDetail::MissingMarker))?;
        let counts = counts.ok_or_else(|| malformed(MalformedDetail::MissingMarker))?;
        let data = self.slice_data(&offsets, &counts)?;

        // Without dimensions there is nothing to write a header about, and a reader given a
        // directory missing them cannot decode what follows.
        for required in [tags::IMAGE_WIDTH, tags::IMAGE_LENGTH] {
            if !verbatim.iter().any(|v| v.tag == required) {
                return Err(malformed(MalformedDetail::MissingMarker));
            }
        }

        Ok(Page {
            verbatim,
            data,
            tiled,
        })
    }

    /// Read a SHORT or LONG array, which is what the strip and tile geometry is written as.
    fn integers(&self, entry: &RawEntry<'a>, value: Option<&'a [u8]>) -> Result<Vec<u64>> {
        let value = value.ok_or_else(|| malformed(MalformedDetail::LengthOutOfRange))?;
        let width = match entry.field_type {
            tags::SHORT => 2usize,
            tags::LONG => 4usize,
            // TIFF 6.0 permits only SHORT or LONG here. Anything else is a file strypt does not
            // understand well enough to rebuild, and guessing is how a strip offset ends up
            // pointing at the wrong bytes.
            _ => return Err(malformed(MalformedDetail::UnsupportedFeature)),
        };
        let mut out = Vec::new();
        let mut r = Reader::new(value);
        while r.remaining() >= width {
            let item = if width == 2 {
                self.endian.u16(&mut r).map(u64::from)
            } else {
                self.endian.u32(&mut r).map(u64::from)
            };
            out.push(item.ok_or_else(|| malformed(MalformedDetail::Truncated))?);
        }
        Ok(out)
    }

    /// Bounds-check the strip or tile geometry and take the data.
    fn slice_data(&self, offsets: &[u64], counts: &[u64]) -> Result<Vec<&'a [u8]>> {
        if offsets.is_empty() || offsets.len() != counts.len() {
            return Err(malformed(MalformedDetail::BrokenIndex));
        }
        let mut data = Vec::new();
        for (offset, count) in offsets.iter().zip(counts.iter()) {
            let start = usize::try_from(*offset)
                .map_err(|_| malformed(MalformedDetail::LengthOutOfRange))?;
            let len = usize::try_from(*count)
                .map_err(|_| malformed(MalformedDetail::LengthOutOfRange))?;
            let mut r = Reader::new(self.input);
            r.seek(start)
                .ok_or_else(|| malformed(MalformedDetail::LengthOutOfRange))?;
            let slice = r
                .take(len)
                .ok_or_else(|| malformed(MalformedDetail::LengthOutOfRange))?;
            data.push(slice);
        }
        Ok(data)
    }

    /// Report every tag inside a sub-directory that is about to vanish with it.
    fn report_sub_directory(&mut self, entry: &RawEntry<'a>, value: Option<&'a [u8]>, sub: Ifd) {
        let Some(target) = value
            .or(Some(entry.inline))
            .and_then(|v| {
                let mut r = Reader::new(v);
                self.endian.u32(&mut r)
            })
            .and_then(u32_to_usize)
        else {
            return;
        };
        if self.visited.contains(&target) {
            return;
        }
        self.visited.push(target);

        let mut r = Reader::new(self.input);
        if r.seek(target).is_none() {
            return;
        }
        let Some(count) = self.endian.u16(&mut r) else {
            return;
        };
        for _ in 0..count {
            if self.budget == 0 {
                self.notes.push(Note::UnparsedRegion {
                    location: format!("TIFF {}", label(sub)),
                    bytes: as_u64(r.remaining()),
                });
                return;
            }
            self.budget = self.budget.saturating_sub(1);
            let Ok(sub_entry) = self.raw_entry(&mut r) else {
                return;
            };
            let sub_value = self.value_of(&sub_entry);
            if let Some(deeper) = exif::sub_directory(sub, sub_entry.tag) {
                self.report_sub_directory(&sub_entry, sub_value, deeper);
                continue;
            }
            self.report_removed(sub, &sub_entry, sub_value);
        }
    }

    /// Record one tag as removed, named from the shared Exif tag table.
    fn report_removed(&mut self, ifd: Ifd, entry: &RawEntry<'a>, value: Option<&'a [u8]>) {
        let (name, kind) = exif::describe(ifd, entry.tag);
        let bytes = value.map_or(0, |v| as_u64(v.len()));
        let field_type = entry.field_type;
        self.findings.push(
            Finding::new(kind, format!("TIFF {}", label(ifd)), bytes)
                .with_field(name)
                .with_value(self.options, || exif::render(value, field_type)),
        );
    }
}

/// The location label a finding carries.
const fn label(ifd: Ifd) -> &'static str {
    match ifd {
        Ifd::Primary => "IFD0",
        Ifd::Exif => "Exif IFD",
        Ifd::Gps => "GPS IFD",
        Ifd::Interop => "Interop IFD",
        Ifd::Thumbnail => "IFD1 (thumbnail)",
    }
}

/// The offsets/byte-counts tag pair an image's geometry is written under.
const fn geometry_tags(tiled: bool) -> (u16, u16) {
    if tiled {
        (tags::TILE_OFFSETS, tags::TILE_BYTE_COUNTS)
    } else {
        (tags::STRIP_OFFSETS, tags::STRIP_BYTE_COUNTS)
    }
}

/// Read a SHORT or LONG scalar.
fn integer(endian: Endian, value: &[u8], field_type: u16) -> Option<u64> {
    let mut r = Reader::new(value);
    match field_type {
        tags::SHORT => endian.u16(&mut r).map(u64::from),
        _ => endian.u32(&mut r).map(u64::from),
    }
}

// ---------------------------------------------------------------------------------------
// Writing
// ---------------------------------------------------------------------------------------

/// An entry as it will be written, before its value bytes exist.
struct OutEntry {
    tag: u16,
    field_type: u16,
    count: u32,
    /// How many bytes the value occupies. Known from the count and the type alone, which is
    /// what lets the whole layout be computed before any value is produced — and therefore
    /// what lets every offset be written once, correctly, rather than patched afterwards.
    len: usize,
    source: Source,
}

/// Where an entry's value bytes come from.
enum Source {
    /// Copied from the input unchanged.
    Verbatim(usize),
    /// The offsets the image data landed at in the output.
    DataOffsets,
    /// The lengths of that data.
    DataCounts,
}

/// Where one page's pieces were placed in the output.
struct Placed {
    entries: Vec<OutEntry>,
    ifd_at: u32,
    /// Offset of each entry's out-of-line value, parallel to `entries`. Zero for inline values.
    value_at: Vec<u32>,
    data_at: Vec<u32>,
}

/// Build the output file.
///
/// Layout is computed in full before a byte is written: header, then for each page its
/// directory, then that page's out-of-line values, then its image data. Every offset therefore
/// has a known value at the moment it is written, and nothing is revisited.
fn write(endian: Endian, pages: &[Page<'_>]) -> Result<Vec<u8>> {
    let mut cursor: u64 = 8;
    let mut placed: Vec<Placed> = Vec::new();

    for page in pages {
        let entries = out_entries(page);
        let ifd_at = to_u32(cursor)?;
        // TIFF 6.0 §2: a directory is a two-byte count, twelve bytes per entry, and a four-byte
        // offset to the next.
        let ifd_size = u64::try_from(entries.len())
            .ok()
            .and_then(|n| n.checked_mul(12))
            .and_then(|n| n.checked_add(6))
            .ok_or_else(|| malformed(MalformedDetail::LengthOutOfRange))?;
        cursor = advance(cursor, ifd_size)?;

        let mut value_at = Vec::with_capacity(entries.len());
        for entry in &entries {
            if entry.len <= 4 {
                value_at.push(0);
                continue;
            }
            value_at.push(to_u32(cursor)?);
            cursor = advance(cursor, pad_even(width_of(entry.len)?))?;
        }

        let mut data_at = Vec::with_capacity(page.data.len());
        for blob in &page.data {
            data_at.push(to_u32(cursor)?);
            cursor = advance(cursor, pad_even(width_of(blob.len())?))?;
        }

        placed.push(Placed {
            entries,
            ifd_at,
            value_at,
            data_at,
        });
    }

    let mut out: Vec<u8> = Vec::new();
    out.extend_from_slice(match endian {
        Endian::Little => b"II",
        Endian::Big => b"MM",
    });
    put_u16(&mut out, endian, 42);
    put_u32(
        &mut out,
        endian,
        placed.first().map_or(0, |first| first.ifd_at),
    );

    for (index, page) in pages.iter().enumerate() {
        let Some(spot) = placed.get(index) else {
            return Err(malformed(MalformedDetail::NotRoundTrippable));
        };
        // The chain ends at zero; every other directory points at the one after it.
        let next = placed.get(index.saturating_add(1)).map_or(0, |p| p.ifd_at);
        write_page(&mut out, endian, page, spot, next)?;
    }
    Ok(out)
}

/// Decide the entries one page will be written with, in the ascending tag order TIFF requires.
fn out_entries(page: &Page<'_>) -> Vec<OutEntry> {
    let mut entries: Vec<OutEntry> = page
        .verbatim
        .iter()
        .enumerate()
        .map(|(index, v)| OutEntry {
            tag: v.tag,
            field_type: v.field_type,
            count: v.count,
            len: v.value.len(),
            source: Source::Verbatim(index),
        })
        .collect();

    let (offsets_tag, counts_tag) = geometry_tags(page.tiled);
    let n = page.data.len();
    // A page cannot have more strips than the entry count ceiling already allowed through, so
    // this saturation is unreachable; it is written rather than asserted because an assertion
    // in the parsing path is a panic (ADR-0006).
    let n32 = u32::try_from(n).unwrap_or(u32::MAX);
    // Written as LONG whatever the input used. A rebuilt file's offsets are not the input's,
    // and a SHORT that fitted before need not fit now; promoting once here is simpler to reason
    // about than a width that depends on where the data happened to land.
    entries.push(OutEntry {
        tag: offsets_tag,
        field_type: tags::LONG,
        count: n32,
        len: n.saturating_mul(4),
        source: Source::DataOffsets,
    });
    entries.push(OutEntry {
        tag: counts_tag,
        field_type: tags::LONG,
        count: n32,
        len: n.saturating_mul(4),
        source: Source::DataCounts,
    });

    // TIFF 6.0 §2 requires directory entries in ascending tag order.
    entries.sort_by_key(|e| e.tag);
    entries
}

/// Write one directory, its out-of-line values, and its image data.
fn write_page(
    out: &mut Vec<u8>,
    endian: Endian,
    page: &Page<'_>,
    spot: &Placed,
    next: u32,
) -> Result<()> {
    let entry_count =
        u16::try_from(spot.entries.len()).map_err(|_| malformed(MalformedDetail::BrokenIndex))?;
    put_u16(out, endian, entry_count);
    for (index, entry) in spot.entries.iter().enumerate() {
        put_u16(out, endian, entry.tag);
        put_u16(out, endian, entry.field_type);
        put_u32(out, endian, entry.count);
        if entry.len <= 4 {
            let mut inline = value_bytes(endian, page, spot, entry)?;
            inline.resize(4, 0);
            out.extend_from_slice(&inline);
        } else {
            let at = spot
                .value_at
                .get(index)
                .copied()
                .ok_or_else(|| malformed(MalformedDetail::NotRoundTrippable))?;
            put_u32(out, endian, at);
        }
    }
    put_u32(out, endian, next);

    for entry in &spot.entries {
        if entry.len <= 4 {
            continue;
        }
        let bytes = value_bytes(endian, page, spot, entry)?;
        out.extend_from_slice(&bytes);
        if !bytes.len().is_multiple_of(2) {
            out.push(0);
        }
    }

    for blob in &page.data {
        out.extend_from_slice(blob);
        if !blob.len().is_multiple_of(2) {
            out.push(0);
        }
    }
    Ok(())
}

/// Produce one entry's value bytes.
fn value_bytes(
    endian: Endian,
    page: &Page<'_>,
    spot: &Placed,
    entry: &OutEntry,
) -> Result<Vec<u8>> {
    match entry.source {
        Source::Verbatim(index) => page
            .verbatim
            .get(index)
            .map(|v| v.value.to_vec())
            .ok_or_else(|| malformed(MalformedDetail::NotRoundTrippable)),
        Source::DataOffsets => {
            let mut bytes = Vec::new();
            for at in &spot.data_at {
                put_u32(&mut bytes, endian, *at);
            }
            Ok(bytes)
        }
        Source::DataCounts => {
            let mut bytes = Vec::new();
            for blob in &page.data {
                put_u32(&mut bytes, endian, to_u32(width_of(blob.len())?)?);
            }
            Ok(bytes)
        }
    }
}

/// Round a length up to a two-byte boundary, which is where TIFF values must start.
const fn pad_even(len: u64) -> u64 {
    if len.is_multiple_of(2) {
        len
    } else {
        len.saturating_add(1)
    }
}

/// Move the write cursor, refusing an output that would not be addressable.
fn advance(cursor: u64, by: u64) -> Result<u64> {
    cursor
        .checked_add(by)
        .filter(|next| u32::try_from(*next).is_ok())
        .ok_or_else(|| malformed(MalformedDetail::LengthOutOfRange))
}

/// Widen a length for offset arithmetic, refusing one this platform cannot represent.
fn width_of(len: usize) -> Result<u64> {
    u64::try_from(len).map_err(|_| malformed(MalformedDetail::LengthOutOfRange))
}

/// Narrow an offset to the four bytes a TIFF offset is written in.
fn to_u32(value: u64) -> Result<u32> {
    u32::try_from(value).map_err(|_| malformed(MalformedDetail::LengthOutOfRange))
}

fn put_u16(out: &mut Vec<u8>, endian: Endian, value: u16) {
    match endian {
        Endian::Little => out.extend_from_slice(&value.to_le_bytes()),
        Endian::Big => out.extend_from_slice(&value.to_be_bytes()),
    }
}

fn put_u32(out: &mut Vec<u8>, endian: Endian, value: u32) {
    match endian {
        Endian::Little => out.extend_from_slice(&value.to_le_bytes()),
        Endian::Big => out.extend_from_slice(&value.to_be_bytes()),
    }
}

fn malformed(detail: MalformedDetail) -> StryptError {
    StryptError::Malformed {
        format: Format::Tiff,
        offset: None,
        detail,
    }
}

fn as_u64(value: usize) -> u64 {
    u64::try_from(value).unwrap_or(u64::MAX)
}

#[cfg(test)]
mod tests {
    // Test code is never reachable from untrusted bytes, which is the boundary the
    // panic-freedom lints exist to police (ADR-0006).
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::indexing_slicing,
        clippy::arithmetic_side_effects,
        clippy::struct_field_names,
        clippy::too_many_lines
    )]

    use super::*;
    use crate::formats::StripOptions;

    /// A tag as the builder below writes it: the value bytes in full, inline or not.
    struct Tag {
        tag: u16,
        field_type: u16,
        count: u32,
        value: Vec<u8>,
    }

    fn short(tag: u16, value: u16) -> Tag {
        Tag {
            tag,
            field_type: tags::SHORT,
            count: 1,
            value: value.to_le_bytes().to_vec(),
        }
    }

    fn ascii(tag: u16, text: &str) -> Tag {
        let mut value = text.as_bytes().to_vec();
        value.push(0);
        Tag {
            tag,
            field_type: 2,
            count: u32::try_from(value.len()).expect("short string"),
            value,
        }
    }

    fn long(tag: u16, value: u32) -> Tag {
        Tag {
            tag,
            field_type: tags::LONG,
            count: 1,
            value: value.to_le_bytes().to_vec(),
        }
    }

    /// The tags every page below needs to be a decodable image.
    fn structural() -> Vec<Tag> {
        vec![
            short(tags::IMAGE_WIDTH, 4),
            short(tags::IMAGE_LENGTH, 1),
            short(0x0102, 8), // BitsPerSample
            short(0x0103, 1), // Compression: none
            short(0x0106, 1), // PhotometricInterpretation: black is zero
            short(0x0115, 1), // SamplesPerPixel
            short(0x0116, 1), // RowsPerStrip
            short(0x011C, 1), // PlanarConfiguration
        ]
    }

    /// One directory to be written by [`build`].
    struct Dir {
        tags: Vec<Tag>,
        strips: Vec<Vec<u8>>,
    }

    fn page(tags: Vec<Tag>, strip: &[u8]) -> Dir {
        Dir {
            tags,
            strips: vec![strip.to_vec()],
        }
    }

    /// One entry as the builder places it.
    struct Slot {
        tag: u16,
        field_type: u16,
        count: u32,
        value: Vec<u8>,
        /// `Some(true)` for the strip offsets, `Some(false)` for the byte counts: both are
        /// filled in once the layout is known.
        geometry: Option<bool>,
    }

    /// Write a little-endian TIFF: header, then each directory followed by its values and its
    /// strips. Deliberately arranged differently from the handler's own writer, so a passing
    /// test cannot be an artefact of the writer reading back its own layout.
    fn build(dirs: &[Dir]) -> Vec<u8> {
        let mut per_dir: Vec<Vec<Slot>> = Vec::new();
        for dir in dirs {
            let n = u32::try_from(dir.strips.len()).unwrap();
            let mut entries: Vec<Slot> = dir
                .tags
                .iter()
                .map(|t| Slot {
                    tag: t.tag,
                    field_type: t.field_type,
                    count: t.count,
                    value: t.value.clone(),
                    geometry: None,
                })
                .collect();
            entries.push(Slot {
                tag: tags::STRIP_OFFSETS,
                field_type: tags::LONG,
                count: n,
                value: vec![0; 4 * dir.strips.len()],
                geometry: Some(true),
            });
            entries.push(Slot {
                tag: tags::STRIP_BYTE_COUNTS,
                field_type: tags::LONG,
                count: n,
                value: vec![0; 4 * dir.strips.len()],
                geometry: Some(false),
            });
            entries.sort_by_key(|e| e.tag);
            per_dir.push(entries);
        }

        let mut cursor = 8usize;
        let mut starts: Vec<usize> = Vec::new();
        let mut value_offs: Vec<Vec<usize>> = Vec::new();
        let mut data_offs: Vec<Vec<usize>> = Vec::new();
        for (index, entries) in per_dir.iter().enumerate() {
            starts.push(cursor);
            cursor += 2 + 12 * entries.len() + 4;
            let mut offs = Vec::new();
            for entry in entries {
                if entry.value.len() > 4 {
                    offs.push(cursor);
                    cursor += entry.value.len() + entry.value.len() % 2;
                } else {
                    offs.push(0);
                }
            }
            value_offs.push(offs);
            let mut data = Vec::new();
            for strip in &dirs[index].strips {
                data.push(cursor);
                cursor += strip.len() + strip.len() % 2;
            }
            data_offs.push(data);
        }

        for (index, entries) in per_dir.iter_mut().enumerate() {
            for entry in entries.iter_mut() {
                match entry.geometry {
                    Some(true) => {
                        entry.value = data_offs[index]
                            .iter()
                            .flat_map(|at| u32::try_from(*at).unwrap().to_le_bytes())
                            .collect();
                    }
                    Some(false) => {
                        entry.value = dirs[index]
                            .strips
                            .iter()
                            .flat_map(|s| u32::try_from(s.len()).unwrap().to_le_bytes())
                            .collect();
                    }
                    None => {}
                }
            }
        }

        let mut out: Vec<u8> = vec![b'I', b'I', 0x2A, 0x00];
        out.extend_from_slice(&u32::try_from(starts[0]).unwrap().to_le_bytes());
        for (index, entries) in per_dir.iter().enumerate() {
            out.extend_from_slice(&u16::try_from(entries.len()).unwrap().to_le_bytes());
            for (slot, entry) in entries.iter().enumerate() {
                out.extend_from_slice(&entry.tag.to_le_bytes());
                out.extend_from_slice(&entry.field_type.to_le_bytes());
                out.extend_from_slice(&entry.count.to_le_bytes());
                if entry.value.len() <= 4 {
                    let mut inline = entry.value.clone();
                    inline.resize(4, 0);
                    out.extend_from_slice(&inline);
                } else {
                    out.extend_from_slice(
                        &u32::try_from(value_offs[index][slot])
                            .unwrap()
                            .to_le_bytes(),
                    );
                }
            }
            let next = starts
                .get(index + 1)
                .map_or(0u32, |s| u32::try_from(*s).unwrap());
            out.extend_from_slice(&next.to_le_bytes());
            for entry in entries {
                if entry.value.len() > 4 {
                    out.extend_from_slice(&entry.value);
                    if entry.value.len() % 2 == 1 {
                        out.push(0);
                    }
                }
            }
            for strip in &dirs[index].strips {
                out.extend_from_slice(strip);
                if strip.len() % 2 == 1 {
                    out.push(0);
                }
            }
        }
        out
    }

    fn strip_ok(data: &[u8]) -> Stripped {
        TiffHandler
            .strip(data, &StripOptions::default())
            .expect("strip failed")
    }

    fn fields(data: &[u8]) -> Vec<String> {
        TiffHandler
            .inspect(data, &InspectOptions::names_only())
            .expect("inspect failed")
            .findings
            .into_iter()
            .filter_map(|f| f.field)
            .collect()
    }

    fn contains(haystack: &[u8], needle: &[u8]) -> bool {
        haystack.windows(needle.len()).any(|w| w == needle)
    }

    #[test]
    fn the_picture_is_copied_byte_for_byte() {
        let mut t = structural();
        t.push(ascii(0x013B, "SYNTHETIC-ARTIST"));
        let input = build(&[page(t, b"SYNTHETIC-PIXELS")]);
        let output = strip_ok(&input).bytes;
        assert!(
            contains(&output, b"SYNTHETIC-PIXELS"),
            "the image data did not survive byte for byte"
        );
    }

    #[test]
    fn identifying_tags_are_reported_and_gone_from_the_output() {
        let mut t = structural();
        t.push(ascii(0x010F, "SYNTHETIC-MAKE"));
        t.push(ascii(0x0110, "SYNTHETIC-MODEL"));
        t.push(ascii(0x0131, "SYNTHETIC-SOFTWARE"));
        t.push(ascii(0x013B, "SYNTHETIC-ARTIST"));
        t.push(ascii(0x0132, "2026:08:25 11:00:00"));
        let input = build(&[page(t, b"SYNTHETIC-PIXELS")]);

        let named = fields(&input);
        for expected in ["Make", "Model", "Software", "Artist", "DateTime"] {
            assert!(
                named.iter().any(|f| f == expected),
                "{expected} not reported"
            );
        }

        let output = strip_ok(&input).bytes;
        for secret in [
            &b"SYNTHETIC-MAKE"[..],
            b"SYNTHETIC-MODEL",
            b"SYNTHETIC-SOFTWARE",
            b"SYNTHETIC-ARTIST",
            b"2026:08:25",
        ] {
            assert!(
                !contains(&output, secret),
                "a removed value survived into the output"
            );
        }
    }

    #[test]
    fn an_unknown_vendor_tag_does_not_survive_by_being_unknown() {
        // The allow-list's whole reason for running in this direction (ADR-0033).
        let mut t = structural();
        t.push(ascii(0xC5D9, "SYNTHETIC-SERIAL-0001"));
        let input = build(&[page(t, b"SYNTHETIC-PIXELS")]);
        let output = strip_ok(&input).bytes;
        assert!(!contains(&output, b"SYNTHETIC-SERIAL-0001"));
        assert!(!fields(&input).is_empty(), "the tag was not reported");
    }

    #[test]
    fn the_output_reads_back_clean() {
        let mut t = structural();
        t.push(ascii(0x013B, "SYNTHETIC-ARTIST"));
        let input = build(&[page(t, b"SYNTHETIC-PIXELS")]);
        let output = strip_ok(&input).bytes;
        // Re-inspecting the output is what the pipeline's verification pass does; nothing may
        // remain for it to find.
        assert!(fields(&output).is_empty(), "metadata survived the rebuild");
    }

    #[test]
    fn stripping_twice_changes_nothing() {
        let mut t = structural();
        t.push(ascii(0x013B, "SYNTHETIC-ARTIST"));
        let input = build(&[page(t, b"SYNTHETIC-PIXELS")]);
        let once = strip_ok(&input).bytes;
        let twice = strip_ok(&once).bytes;
        assert_eq!(once, twice, "strip is not idempotent");
    }

    #[test]
    fn a_reduced_resolution_directory_is_dropped() {
        // A thumbnail is a complete second image that survives any crop or redaction applied
        // to the first (`docs/THREAT_MODEL.md` §3).
        let main = structural();
        let mut thumb = structural();
        thumb.push(long(tags::NEW_SUBFILE_TYPE, 1));
        let input = build(&[
            page(main, b"SYNTHETIC-PIXELS"),
            page(thumb, b"SYNTHETIC-THUMBNAIL"),
        ]);
        let output = strip_ok(&input).bytes;
        assert!(contains(&output, b"SYNTHETIC-PIXELS"));
        assert!(
            !contains(&output, b"SYNTHETIC-THUMBNAIL"),
            "the reduced-resolution copy survived"
        );
    }

    #[test]
    fn the_pages_of_a_multi_page_scan_are_all_kept() {
        // The case that matters for this project's users: a scanned dossier is one TIFF with a
        // directory per page, and dropping pages would be losing the document.
        let input = build(&[
            page(structural(), b"SYNTHETIC-PAGE-ONE"),
            page(structural(), b"SYNTHETIC-PAGE-TWO"),
            page(structural(), b"SYNTHETIC-PAGE-THREE"),
        ]);
        let output = strip_ok(&input).bytes;
        for pixels in [
            &b"SYNTHETIC-PAGE-ONE"[..],
            b"SYNTHETIC-PAGE-TWO",
            b"SYNTHETIC-PAGE-THREE",
        ] {
            assert!(contains(&output, pixels), "a page was lost");
        }
    }

    #[test]
    fn bigtiff_is_refused_rather_than_parsed_as_tiff() {
        let mut input = build(&[page(structural(), b"SYNTHETIC-PIXELS")]);
        input[2] = 0x2B;
        assert!(matches!(
            TiffHandler.strip(&input, &StripOptions::default()),
            Err(StryptError::Malformed {
                detail: MalformedDetail::UnsupportedFeature,
                ..
            })
        ));
    }

    #[test]
    fn a_directory_chain_that_loops_is_refused() {
        let mut input = build(&[page(structural(), b"SYNTHETIC-PIXELS")]);
        // Point the first directory's "next" field back at itself.
        let first = u32::from_le_bytes([input[4], input[5], input[6], input[7]]) as usize;
        let count = u16::from_le_bytes([input[first], input[first + 1]]) as usize;
        let next_at = first + 2 + 12 * count;
        let self_ref = u32::try_from(first).unwrap().to_le_bytes();
        input[next_at..next_at + 4].copy_from_slice(&self_ref);
        assert!(matches!(
            TiffHandler.strip(&input, &StripOptions::default()),
            Err(StryptError::Malformed {
                detail: MalformedDetail::CyclicReference,
                ..
            })
        ));
    }

    #[test]
    fn a_strip_pointing_outside_the_file_is_refused() {
        // Fail closed: an out-of-range strip means the image data cannot be copied, and
        // emitting a TIFF without it would be handing back something that is not the file.
        let mut input = build(&[page(structural(), b"SYNTHETIC-PIXELS")]);
        let pixels_at = input
            .windows(16)
            .position(|w| w == b"SYNTHETIC-PIXELS")
            .expect("pixels not found");
        let needle = u32::try_from(pixels_at).unwrap().to_le_bytes();
        let at = input
            .windows(4)
            .position(|w| w == needle)
            .expect("strip offset not found");
        input[at..at + 4].copy_from_slice(&0xFFFF_0000u32.to_le_bytes());
        assert!(TiffHandler.strip(&input, &StripOptions::default()).is_err());
    }

    #[test]
    fn a_truncated_file_is_refused_rather_than_completed() {
        let input = build(&[page(structural(), b"SYNTHETIC-PIXELS")]);
        for cut in [4, 8, 12, 30, input.len() / 2] {
            let _ = TiffHandler.strip(&input[..cut], &StripOptions::default());
        }
    }
}
