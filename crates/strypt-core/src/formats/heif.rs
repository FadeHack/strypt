//! HEIF and AVIF: one ISO-BMFF container, two codecs (HEVC and AV1). One handler for both, which
//! is why ADR-0032 makes them one tranche.
//!
//! # Why the file is rebuilt rather than edited
//!
//! Exif and XMP are *items* here — declared in `iinf`, located by `iloc` as absolute file offsets
//! into `mdat`, beside the coded picture. There is no delimited region to excise, and dropping an
//! item's bytes moves every surviving one. So the file is written fresh from allow-lists in
//! [`boxes`], with every offset computed against the buffer being built and the coded picture
//! copied byte for byte (ADR-0034; ADR-0033 for the same reasoning applied to TIFF).
//!
//! Two free-text fields leak without being metadata boxes: `hdlr`'s name (libheif writes its own
//! there) and `infe`'s item name. Both are written empty and reported.
//!
//! A `moov` box or a sequence brand means a motion file — an Apple Live Photo — which is refused
//! by name rather than half-cleaned.

use crate::bytes::Reader;
use crate::container::bmff::{self, Box as Bmff, BoxType, WalkError};
use crate::detect::Format;
use crate::error::{MalformedDetail, Result, StryptError};
use crate::formats::{MetadataHandler, ParseLimits, StripOptions, Stripped, exif, xmp};
use crate::report::{
    Finding, InspectOptions, MetadataKind, MetadataReport, MetadataValue, Note, Retained,
    RetentionReason, StripReport,
};

pub(crate) mod boxes;

/// The HEIF and AVIF handler. One type, one instance per format, as [`super::ooxml`] does.
#[derive(Debug, Clone, Copy)]
#[non_exhaustive]
pub struct HeifHandler {
    format: Format,
}

impl HeifHandler {
    /// The handler instance for HEIF — `.heic` and `.heif`.
    pub const HEIF: Self = Self {
        format: Format::Heif,
    };
    /// The handler instance for AVIF.
    pub const AVIF: Self = Self {
        format: Format::Avif,
    };
}

impl MetadataHandler for HeifHandler {
    fn name(&self) -> &'static str {
        self.format.id()
    }

    fn format(&self) -> Format {
        self.format
    }

    fn inspect(&self, input: &[u8], options: &InspectOptions) -> Result<MetadataReport> {
        // The same pass strip runs, output discarded, so the two cannot drift (ARCHITECTURE §3).
        let processed = process(self.format, input, options, &ParseLimits::default())?;
        Ok(MetadataReport {
            format: self.format,
            findings: processed.findings,
            notes: processed.notes,
        })
    }

    fn strip(&self, input: &[u8], options: &StripOptions) -> Result<Stripped> {
        let processed = process(self.format, input, &options.inspect, &options.limits)?;
        Ok(Stripped {
            report: StripReport {
                format: self.format,
                removed: processed.findings,
                retained: processed.retained,
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
    retained: Vec<Retained>,
    notes: Vec<Note>,
}

/// An item as the input declared it.
struct Item<'a> {
    /// The input's identifier. Never written out: items are renumbered from 1.
    id: u32,
    kind: BoxType,
    /// `infe`'s free-text name. Written empty.
    name: &'a [u8],
    /// A `mime` item's declared content type, used to tell XMP from anything else.
    content_type: &'a [u8],
    /// The payload, resolved from its extents and bounds-checked.
    data: Vec<&'a [u8]>,
    bytes: u64,
}

/// One entry of `iref`.
struct Reference {
    kind: BoxType,
    from: u32,
    to: Vec<u32>,
}

/// A property, as it will be written.
struct Property<'a> {
    kind: BoxType,
    payload: &'a [u8],
}

/// One item's association with a property, preserving the essential bit.
#[derive(Clone, Copy)]
struct Association {
    /// One-based index into `ipco`.
    index: u16,
    /// Whether a reader that cannot understand the property must refuse the image.
    essential: bool,
}

/// Everything read out of `meta`, before anything is decided.
struct Parsed<'a> {
    ftyp: &'a [u8],
    primary: u32,
    items: Vec<Item<'a>>,
    references: Vec<Reference>,
    properties: Vec<Property<'a>>,
    associations: Vec<(u32, Vec<Association>)>,
    /// `hdlr`'s free-text name, reported when non-empty.
    handler_name: &'a [u8],
    /// Boxes inside `meta` the allow-list does not keep. §8.11.2 puts `xml ` and `bxml` here, and
    /// a top-level-only rule would drop them silently.
    stray_meta: Vec<(BoxType, u64)>,
}

/// Read `input`, name what is being dropped, and write the rebuilt file.
fn process(
    format: Format,
    input: &[u8],
    options: &InspectOptions,
    limits: &ParseLimits,
) -> Result<Processed> {
    let mut budget = limits.max_items;
    let (top, trailing) = bmff::top_level(input, &mut budget).map_err(|e| from_walk(format, e))?;

    let mut findings = Vec::new();
    let mut notes = Vec::new();

    // Before anything else, so the refusal names what the file is.
    for b in &top {
        if boxes::MOTION_BOXES.contains(&b.kind) {
            return Err(StryptError::UnsupportedFormat {
                format: crate::error::UnsupportedKind::MotionHeif,
            });
        }
    }

    let parsed = parse(format, input, &top, &mut budget, limits)?;

    for b in &top {
        if boxes::top_level_kept(b.kind) {
            continue;
        }
        // Not kept, but not a finding either: its bytes are accounted for by the items pointing
        // into it, and reporting it would make `show` announce a finding on a clean file.
        if b.is(*b"mdat") {
            continue;
        }
        findings.extend(report_stray_box(b, options));
    }

    for (kind, size) in &parsed.stray_meta {
        let location = match kind {
            b"xml " | b"bxml" => "meta/xml",
            b"uuid" => "meta/uuid",
            _ => "meta",
        };
        findings.push(
            Finding::new(MetadataKind::Other, location, *size).with_field(xmp::name_of(kind)),
        );
    }

    if !trailing.is_empty() {
        // Appended past the last box, where nothing reads them — as JPEG after `EOI` (§7.2).
        findings.push(Finding::new(
            MetadataKind::Other,
            "trailing data",
            as_u64(trailing.len()),
        ));
    }

    // A property that is not kept is removed, so it is reported. `colr` carrying an ICC profile
    // is the one that names a device; `udes` is free text describing the image.
    for property in &parsed.properties {
        if boxes::property_kept(property.kind, property.payload) {
            continue;
        }
        let kind = if property.kind == *b"colr" {
            MetadataKind::ColourProfile
        } else {
            MetadataKind::Other
        };
        findings.push(
            Finding::new(kind, "iprp/ipco", as_u64(property.payload.len()))
                .with_field(xmp::name_of(&property.kind)),
        );
    }

    let removed_ids = decide(&parsed, &mut findings, options);

    // Without it the output would be a valid container with no picture, reported as success —
    // §5.4, and the refusal WebP makes for a file with no bitstream (§7.4).
    let primary_kept = parsed
        .items
        .iter()
        .any(|i| i.id == parsed.primary && !removed_ids.contains(&i.id));
    if !primary_kept {
        return Err(malformed(format, MalformedDetail::MissingMarker));
    }

    if !parsed.handler_name.is_empty() {
        findings.push(
            Finding::new(
                MetadataKind::SoftwareFingerprint,
                "meta/hdlr",
                as_u64(parsed.handler_name.len()),
            )
            .with_field("name")
            .with_value(options, || {
                MetadataValue::Text(xmp::name_of(parsed.handler_name))
            }),
        );
    }

    let output = write(&parsed, &removed_ids, format)?;

    let retained = if parsed
        .properties
        .iter()
        .any(|p| p.kind == *b"colr" && boxes::property_kept(p.kind, p.payload))
    {
        vec![Retained {
            location: "iprp/ipco (colr nclx)".to_owned(),
            // Numeric colour signalling: dropping it would change how the decoder interprets the
            // pixels, which is a visible change to the picture rather than a metadata removal.
            reason: RetentionReason::RemovalWouldAlterPayload,
        }]
    } else {
        Vec::new()
    };

    notes.extend(parsed_notes(&parsed));
    Ok(Processed {
        output,
        findings,
        retained,
        notes,
    })
}

/// Notes describing what the structure leaves out of reach.
fn parsed_notes(parsed: &Parsed<'_>) -> Vec<Note> {
    let mut notes = Vec::new();
    if parsed.items.iter().any(|i| i.kind == *b"grid") {
        notes.push(Note::OutOfScopeContent {
            location: "grid (tiled image; tiles are moved, never decoded)".to_owned(),
        });
    }
    notes
}

/// The 16-byte extended type the XMP specification fixes for a `uuid` box (§4.2).
const XMP_UUID: [u8; 16] = [
    0xBE, 0x7A, 0xCF, 0xCB, 0x97, 0xA9, 0x42, 0xE8, 0x9C, 0x71, 0x99, 0x94, 0x91, 0xE3, 0xAF, 0xAC,
];

/// Report a top-level box that is not on the allow-list.
fn report_stray_box(b: &Bmff<'_>, options: &InspectOptions) -> Vec<Finding> {
    let size = b.size;
    if b.is(*b"uuid")
        && b.payload.get(..16) == Some(&XMP_UUID)
        && let Some(packet) = b.payload.get(16..)
    {
        return xmp::scan(packet, "uuid (XMP)", options);
    }
    let location = match &b.kind {
        b"free" | b"skip" => "free space",
        b"uuid" => "uuid",
        _ => "box",
    };
    vec![Finding::new(MetadataKind::Other, location, size).with_field(xmp::name_of(&b.kind))]
}

/// Decide which items go, reporting each. Returns the removed items' input identifiers.
fn decide(parsed: &Parsed<'_>, findings: &mut Vec<Finding>, options: &InspectOptions) -> Vec<u32> {
    // What makes an item a thumbnail is the reference, not its codec (§3). A `thmb` runs *from*
    // the thumbnail *to* the master image, so it is the source that goes — reading it the other
    // way round deletes the picture and keeps the thumbnail.
    let thumbnails: Vec<u32> = parsed
        .references
        .iter()
        .filter(|r| r.kind == boxes::REFERENCE_THUMBNAIL)
        .map(|r| r.from)
        .collect();

    let mut removed = Vec::new();
    for item in &parsed.items {
        let is_thumbnail = thumbnails.contains(&item.id);
        if boxes::is_image_item(item.kind) && !is_thumbnail {
            if !item.name.is_empty() {
                findings.push(
                    Finding::new(MetadataKind::Other, "iinf/infe", as_u64(item.name.len()))
                        .with_field("item_name")
                        .with_value(options, || MetadataValue::Text(xmp::name_of(item.name))),
                );
            }
            continue;
        }
        removed.push(item.id);
        findings.extend(report_item(item, is_thumbnail, options));
    }
    removed
}

/// Name what one removed item held.
fn report_item(item: &Item<'_>, is_thumbnail: bool, options: &InspectOptions) -> Vec<Finding> {
    let joined: Vec<u8> = item.data.iter().flat_map(|s| s.iter().copied()).collect();

    if is_thumbnail {
        return vec![
            Finding::new(MetadataKind::Thumbnail, "item (thmb)", item.bytes)
                .with_field(xmp::name_of(&item.kind)),
        ];
    }

    if item.kind == *b"Exif" {
        // §A.2.1: a four-byte offset to the TIFF header, then the block. Passing the whole payload
        // would shift every offset inside it — the mistake `exif::scan`'s header warns about.
        let start = u32::from_be_bytes([
            joined.first().copied().unwrap_or(0),
            joined.get(1).copied().unwrap_or(0),
            joined.get(2).copied().unwrap_or(0),
            joined.get(3).copied().unwrap_or(0),
        ]);
        let at = usize::try_from(start)
            .unwrap_or(usize::MAX)
            .saturating_add(4);
        if let Some(tiff) = joined.get(at..) {
            let scanned = exif::scan(tiff, "item (Exif)", options, &ParseLimits::default());
            if !scanned.findings.is_empty() {
                return scanned.findings;
            }
        }
        return vec![Finding::new(MetadataKind::Other, "item (Exif)", item.bytes)];
    }

    if item.kind == *b"mime" {
        // XMP declares `application/rdf+xml`. Others go too; the type only names the finding.
        if xmp::contains(item.content_type, b"rdf+xml") || xmp::contains(&joined, b"<x:xmpmeta") {
            let scanned = xmp::scan(&joined, "item (XMP)", options);
            if !scanned.is_empty() {
                return scanned;
            }
        }
        return vec![
            Finding::new(MetadataKind::Other, "item (mime)", item.bytes)
                .with_field(xmp::name_of(item.content_type)),
        ];
    }

    vec![
        Finding::new(
            MetadataKind::Other,
            format!("item ({})", xmp::name_of(&item.kind)),
            item.bytes,
        )
        .with_field(xmp::name_of(&item.kind)),
    ]
}

// ---------------------------------------------------------------------------------------------
// Reading
// ---------------------------------------------------------------------------------------------

/// Read what the rebuild needs out of the box tree.
fn parse<'a>(
    format: Format,
    input: &'a [u8],
    top: &[Bmff<'a>],
    budget: &mut u32,
    limits: &ParseLimits,
) -> Result<Parsed<'a>> {
    let ftyp = bmff::find(top, *b"ftyp")
        .ok_or_else(|| malformed(format, MalformedDetail::MissingMarker))?;

    // §6.4. Checked before the tree is read, so the refusal names the file's own declaration.
    for brand in ftyp.payload.chunks_exact(4).skip(2) {
        if let Ok(b) = <[u8; 4]>::try_from(brand)
            && boxes::SEQUENCE_BRANDS.contains(&b)
        {
            return Err(StryptError::UnsupportedFormat {
                format: crate::error::UnsupportedKind::MotionHeif,
            });
        }
    }

    let meta = bmff::find(top, *b"meta")
        .ok_or_else(|| malformed(format, MalformedDetail::MissingMarker))?;
    let (_, _, meta_body) = meta
        .full()
        .ok_or_else(|| malformed(format, MalformedDetail::Truncated))?;
    let children = bmff::children_at(meta, meta_body, limits.max_depth, budget)
        .map_err(|e| from_walk(format, e))?;

    // Item protection — encryption. Refused as ODF encryption is (§7.7): ciphertext that no rule
    // matches would be reported clean having been examined by nobody.
    if bmff::find(&children, *b"ipro").is_some() {
        return Err(malformed(format, MalformedDetail::UnsupportedFeature));
    }

    // Read from but never written, so absent from the keep list — which governs what is *written*.
    let stray_meta: Vec<(BoxType, u64)> = children
        .iter()
        .filter(|c| !boxes::meta_kept(c.kind) && !c.is(*b"idat") && !c.is(*b"ipro"))
        .map(|c| (c.kind, c.size))
        .collect();

    let handler_name = bmff::find(&children, *b"hdlr")
        .and_then(|b| handler_name(b))
        .unwrap_or_default();

    let primary = bmff::find(&children, *b"pitm")
        .and_then(|b| primary_item(b))
        .ok_or_else(|| malformed(format, MalformedDetail::MissingMarker))?;

    let infos = bmff::find(&children, *b"iinf")
        .ok_or_else(|| malformed(format, MalformedDetail::MissingMarker))
        .and_then(|b| item_infos(format, b, limits.max_depth, budget))?;

    let idat = bmff::find(&children, *b"idat").map(|b| b.payload);
    let locations = bmff::find(&children, *b"iloc")
        .ok_or_else(|| malformed(format, MalformedDetail::MissingMarker))
        .and_then(|b| item_locations(format, b))?;

    let references = bmff::find(&children, *b"iref")
        .map(|b| item_references(format, b, limits.max_depth, budget))
        .transpose()?
        .unwrap_or_default();

    let (properties, associations) = bmff::find(&children, *b"iprp")
        .map(|b| item_properties(format, b, limits.max_depth, budget))
        .transpose()?
        .unwrap_or_default();

    // Resolved now, so a lying extent is refused before anything is decided about what to keep.
    let mut items = Vec::with_capacity(infos.len());
    for info in infos {
        let (kind, name, content_type, protection, id) = info;
        if protection != 0 {
            return Err(malformed(format, MalformedDetail::UnsupportedFeature));
        }
        let extents = locations
            .iter()
            .find(|(item_id, _)| *item_id == id)
            .map(|(_, e)| e.clone())
            .unwrap_or_default();
        let data = resolve(format, input, idat, &extents)?;
        let bytes = data.iter().map(|s| as_u64(s.len())).sum();
        items.push(Item {
            id,
            kind,
            name,
            content_type,
            data,
            bytes,
        });
    }

    Ok(Parsed {
        ftyp: ftyp.payload,
        primary,
        items,
        references,
        properties,
        associations,
        handler_name,
        stray_meta,
    })
}

/// An extent, once its construction method and base offset have been applied.
#[derive(Clone, Copy)]
struct Extent {
    /// 0: an offset into the file. 1: into `idat`. 2 is refused.
    construction: u8,
    offset: u64,
    length: u64,
}

/// Turn extents into the byte ranges they name, refusing any that leaves the file.
fn resolve<'a>(
    format: Format,
    input: &'a [u8],
    idat: Option<&'a [u8]>,
    extents: &[Extent],
) -> Result<Vec<&'a [u8]>> {
    let mut out = Vec::with_capacity(extents.len());
    for extent in extents {
        let source: &[u8] = match extent.construction {
            0 => input,
            1 => idat.ok_or_else(|| malformed(format, MalformedDetail::MissingMarker))?,
            // Method 2 is an offset into another item, which cannot be relocated without resolving
            // an item graph that may be cyclic.
            _ => return Err(malformed(format, MalformedDetail::UnsupportedFeature)),
        };
        let start = usize::try_from(extent.offset)
            .map_err(|_| malformed(format, MalformedDetail::LengthOutOfRange))?;
        let len = usize::try_from(extent.length)
            .map_err(|_| malformed(format, MalformedDetail::LengthOutOfRange))?;
        let end = start
            .checked_add(len)
            .ok_or_else(|| malformed(format, MalformedDetail::LengthOutOfRange))?;
        let slice = source
            .get(start..end)
            .ok_or_else(|| malformed(format, MalformedDetail::LengthOutOfRange))?;
        out.push(slice);
    }
    Ok(out)
}

/// Read `hdlr`'s trailing name field.
fn handler_name<'a>(b: &Bmff<'a>) -> Option<&'a [u8]> {
    let (_, _, body) = b.full()?;
    // pre_defined(4) + handler_type(4) + reserved(12), then the name.
    let rest = body.get(20..)?;
    let end = rest.iter().position(|&c| c == 0).unwrap_or(rest.len());
    rest.get(..end)
}

/// Read `pitm`'s item identifier.
fn primary_item(b: &Bmff<'_>) -> Option<u32> {
    let (version, _, body) = b.full()?;
    let mut r = Reader::new(body);
    if version == 0 {
        r.u16_be().map(u32::from)
    } else {
        r.u32_be()
    }
}

/// Type, name, content type, protection index and identifier, per item.
type ItemInfo<'a> = (BoxType, &'a [u8], &'a [u8], u16, u32);

fn item_infos<'a>(
    format: Format,
    b: &Bmff<'a>,
    depth: u32,
    budget: &mut u32,
) -> Result<Vec<ItemInfo<'a>>> {
    let (version, _, body) = b
        .full()
        .ok_or_else(|| malformed(format, MalformedDetail::Truncated))?;
    let mut r = Reader::new(body);
    let _count = if version == 0 {
        u32::from(
            r.u16_be()
                .ok_or_else(|| malformed(format, MalformedDetail::Truncated))?,
        )
    } else {
        r.u32_be()
            .ok_or_else(|| malformed(format, MalformedDetail::Truncated))?
    };
    // Not trusted as a loop bound: the boxes are self-delimiting, so a lying count changes nothing.
    let rest = r.take_rest();
    let entries = bmff::children_at(b, rest, depth, budget).map_err(|e| from_walk(format, e))?;

    let mut out = Vec::with_capacity(entries.len());
    for entry in &entries {
        if !entry.is(*b"infe") {
            continue;
        }
        out.push(item_info(format, entry)?);
    }
    Ok(out)
}

/// Read one `infe`.
fn item_info<'a>(format: Format, b: &Bmff<'a>) -> Result<ItemInfo<'a>> {
    let (version, _, body) = b
        .full()
        .ok_or_else(|| malformed(format, MalformedDetail::Truncated))?;
    // Versions 0 and 1 predate `item_type`, so a coded image cannot be told from a metadata blob.
    if version < 2 {
        return Err(malformed(format, MalformedDetail::UnsupportedFeature));
    }
    let mut r = Reader::new(body);
    let id = if version == 2 {
        u32::from(
            r.u16_be()
                .ok_or_else(|| malformed(format, MalformedDetail::Truncated))?,
        )
    } else {
        r.u32_be()
            .ok_or_else(|| malformed(format, MalformedDetail::Truncated))?
    };
    let protection = r
        .u16_be()
        .ok_or_else(|| malformed(format, MalformedDetail::Truncated))?;
    let kind: BoxType = r
        .take(4)
        .and_then(|b| b.try_into().ok())
        .ok_or_else(|| malformed(format, MalformedDetail::Truncated))?;
    let rest = r.take_rest();
    let (name, after) = c_string(rest);
    let content_type = if kind == *b"mime" {
        c_string(after).0
    } else {
        &[][..]
    };
    Ok((kind, name, content_type, protection, id))
}

/// Split a null-terminated string off `data`, returning it and the remainder.
fn c_string(data: &[u8]) -> (&[u8], &[u8]) {
    let end = data.iter().position(|&c| c == 0).unwrap_or(data.len());
    let text = data.get(..end).unwrap_or_default();
    let rest = data.get(end.saturating_add(1)..).unwrap_or_default();
    (text, rest)
}

/// Read `iloc`.
fn item_locations(format: Format, b: &Bmff<'_>) -> Result<Vec<(u32, Vec<Extent>)>> {
    let (version, _, body) = b
        .full()
        .ok_or_else(|| malformed(format, MalformedDetail::Truncated))?;
    let mut r = Reader::new(body);
    let sizes = r
        .u16_be()
        .ok_or_else(|| malformed(format, MalformedDetail::Truncated))?;
    let offset_size = ((sizes >> 12) & 0xF) as u8;
    let length_size = ((sizes >> 8) & 0xF) as u8;
    let base_offset_size = ((sizes >> 4) & 0xF) as u8;
    let index_size = (sizes & 0xF) as u8;

    let count = if version < 2 {
        u32::from(
            r.u16_be()
                .ok_or_else(|| malformed(format, MalformedDetail::Truncated))?,
        )
    } else {
        r.u32_be()
            .ok_or_else(|| malformed(format, MalformedDetail::Truncated))?
    };

    let mut out = Vec::new();
    for _ in 0..count {
        let id = if version < 2 {
            u32::from(
                r.u16_be()
                    .ok_or_else(|| malformed(format, MalformedDetail::Truncated))?,
            )
        } else {
            r.u32_be()
                .ok_or_else(|| malformed(format, MalformedDetail::Truncated))?
        };
        let construction = if version == 0 {
            0
        } else {
            let word = r
                .u16_be()
                .ok_or_else(|| malformed(format, MalformedDetail::Truncated))?;
            (word & 0xF) as u8
        };
        // Non-zero means the payload is in another file, which cannot be cleaned here.
        let data_reference = r
            .u16_be()
            .ok_or_else(|| malformed(format, MalformedDetail::Truncated))?;
        if data_reference != 0 {
            return Err(malformed(format, MalformedDetail::UnsupportedFeature));
        }
        let base = read_uint(&mut r, base_offset_size)
            .ok_or_else(|| malformed(format, MalformedDetail::Truncated))?;
        let extent_count = r
            .u16_be()
            .ok_or_else(|| malformed(format, MalformedDetail::Truncated))?;

        let mut extents = Vec::new();
        for _ in 0..extent_count {
            if version > 0 && index_size > 0 {
                read_uint(&mut r, index_size)
                    .ok_or_else(|| malformed(format, MalformedDetail::Truncated))?;
            }
            let offset = read_uint(&mut r, offset_size)
                .ok_or_else(|| malformed(format, MalformedDetail::Truncated))?;
            let length = read_uint(&mut r, length_size)
                .ok_or_else(|| malformed(format, MalformedDetail::Truncated))?;
            extents.push(Extent {
                construction,
                offset: base.saturating_add(offset),
                length,
            });
        }
        out.push((id, extents));
    }
    Ok(out)
}

/// Read a big-endian unsigned integer of `size` bytes; zero reads nothing.
fn read_uint(r: &mut Reader<'_>, size: u8) -> Option<u64> {
    match size {
        0 => Some(0),
        4 => r.u32_be().map(u64::from),
        8 => {
            let b: [u8; 8] = r.take(8)?.try_into().ok()?;
            Some(u64::from_be_bytes(b))
        }
        // §8.11.3 permits only 0, 4 and 8; anything else means the walk is lost.
        _ => None,
    }
}

/// Read `iref` and its per-type child boxes.
fn item_references(
    format: Format,
    b: &Bmff<'_>,
    depth: u32,
    budget: &mut u32,
) -> Result<Vec<Reference>> {
    let (version, _, body) = b
        .full()
        .ok_or_else(|| malformed(format, MalformedDetail::Truncated))?;
    let entries = bmff::children_at(b, body, depth, budget).map_err(|e| from_walk(format, e))?;

    let mut out = Vec::with_capacity(entries.len());
    for entry in &entries {
        let mut r = Reader::new(entry.payload);
        let wide = version != 0;
        let from = if wide {
            r.u32_be()
        } else {
            r.u16_be().map(u32::from)
        }
        .ok_or_else(|| malformed(format, MalformedDetail::Truncated))?;
        let count = r
            .u16_be()
            .ok_or_else(|| malformed(format, MalformedDetail::Truncated))?;
        let mut to = Vec::with_capacity(usize::from(count));
        for _ in 0..count {
            let id = if wide {
                r.u32_be()
            } else {
                r.u16_be().map(u32::from)
            }
            .ok_or_else(|| malformed(format, MalformedDetail::Truncated))?;
            to.push(id);
        }
        out.push(Reference {
            kind: entry.kind,
            from,
            to,
        });
    }
    Ok(out)
}

/// Read `iprp` — its `ipco` property list and the `ipma` associations into it.
type Properties<'a> = (Vec<Property<'a>>, Vec<(u32, Vec<Association>)>);

fn item_properties<'a>(
    format: Format,
    b: &Bmff<'a>,
    depth: u32,
    budget: &mut u32,
) -> Result<Properties<'a>> {
    let children =
        bmff::children_at(b, b.payload, depth, budget).map_err(|e| from_walk(format, e))?;

    let properties = match bmff::find(&children, *b"ipco") {
        Some(ipco) => bmff::children_at(ipco, ipco.payload, depth, budget)
            .map_err(|e| from_walk(format, e))?
            .iter()
            .map(|p| Property {
                kind: p.kind,
                payload: p.payload,
            })
            .collect(),
        None => Vec::new(),
    };

    let mut associations = Vec::new();
    for ipma in children.iter().filter(|c| c.is(*b"ipma")) {
        let (version, flags, body) = ipma
            .full()
            .ok_or_else(|| malformed(format, MalformedDetail::Truncated))?;
        let mut r = Reader::new(body);
        let count = r
            .u32_be()
            .ok_or_else(|| malformed(format, MalformedDetail::Truncated))?;
        for _ in 0..count {
            let id = if version == 0 {
                r.u16_be().map(u32::from)
            } else {
                r.u32_be()
            }
            .ok_or_else(|| malformed(format, MalformedDetail::Truncated))?;
            let n = r
                .u8()
                .ok_or_else(|| malformed(format, MalformedDetail::Truncated))?;
            let mut list = Vec::with_capacity(usize::from(n));
            for _ in 0..n {
                // §8.11.14: flag bit 0 widens the index to 15 bits; the top bit marks essential.
                let (essential, index) = if flags & 1 == 1 {
                    let word = r
                        .u16_be()
                        .ok_or_else(|| malformed(format, MalformedDetail::Truncated))?;
                    ((word & 0x8000) != 0, word & 0x7FFF)
                } else {
                    let byte = r
                        .u8()
                        .ok_or_else(|| malformed(format, MalformedDetail::Truncated))?;
                    ((byte & 0x80) != 0, u16::from(byte & 0x7F))
                };
                list.push(Association { index, essential });
            }
            associations.push((id, list));
        }
    }

    Ok((properties, associations))
}

// ---------------------------------------------------------------------------------------------
// Writing
// ---------------------------------------------------------------------------------------------

/// Fixed widths for the `iloc` written here, so its encoded size does not depend on the offset
/// *values* — which is what makes the two-pass layout below exact.
const ILOC_OFFSET_SIZE: u8 = 4;
const ILOC_LENGTH_SIZE: u8 = 4;

/// Build the output: `ftyp`, `meta`, then one `mdat` of the retained payloads.
///
/// `iloc` sits inside `meta` and names absolute offsets, so `meta` is written twice — once to
/// learn its length, once with the offsets that length implies.
fn write(parsed: &Parsed<'_>, removed: &[u32], format: Format) -> Result<Vec<u8>> {
    let kept: Vec<&Item<'_>> = parsed
        .items
        .iter()
        .filter(|i| !removed.contains(&i.id))
        .collect();

    let mut ftyp = Vec::new();
    bmff::write_box(&mut ftyp, *b"ftyp", |out| {
        // Copied: they declare what a reader needs, and a file not claiming them stops opening.
        // A producer fingerprint in the sense of §4.7, which this tool addresses for no format.
        out.extend_from_slice(parsed.ftyp);
        Ok(())
    })
    .map_err(|d| malformed(format, d))?;

    // First pass: offsets written as zero, purely to measure.
    let probe = write_meta(parsed, &kept, 0, format)?;
    let mdat_base = as_u64(ftyp.len())
        .checked_add(as_u64(probe.len()))
        .and_then(|n| n.checked_add(8))
        .ok_or_else(|| malformed(format, MalformedDetail::LengthOutOfRange))?;
    let meta = write_meta(parsed, &kept, mdat_base, format)?;

    // The invariant the fixed widths guarantee. If it fails, every offset is wrong by the
    // difference, so refuse rather than write a file that parses while pointing at the wrong bytes.
    if meta.len() != probe.len() {
        return Err(malformed(format, MalformedDetail::NotRoundTrippable));
    }

    let mut out = Vec::new();
    out.extend_from_slice(&ftyp);
    out.extend_from_slice(&meta);
    bmff::write_box(&mut out, *b"mdat", |out| {
        for item in &kept {
            for chunk in &item.data {
                out.extend_from_slice(chunk);
            }
        }
        Ok(())
    })
    .map_err(|d| malformed(format, d))?;

    Ok(out)
}

/// Write the `meta` box, with item payloads placed from `mdat_base` onwards.
fn write_meta(
    parsed: &Parsed<'_>,
    kept: &[&Item<'_>],
    mdat_base: u64,
    format: Format,
) -> Result<Vec<u8>> {
    // Renumbered from 1 in write order, so nothing in the output depends on the input's numbering
    // — the reason the PDF handler renumbers objects (ADR-0020).
    let renumber = |old: u32| -> Option<u16> {
        kept.iter()
            .position(|i| i.id == old)
            .and_then(|p| u16::try_from(p.saturating_add(1)).ok())
    };

    // `ipco` is rebuilt, so its indices change. Maps input index to output, dropping associations
    // whose property is gone.
    let mut kept_properties: Vec<usize> = Vec::new();
    for (i, property) in parsed.properties.iter().enumerate() {
        if boxes::property_kept(property.kind, property.payload) {
            kept_properties.push(i);
        }
    }
    let reindex = |old: u16| -> Option<u16> {
        let zero_based = usize::from(old).checked_sub(1)?;
        kept_properties
            .iter()
            .position(|&i| i == zero_based)
            .and_then(|p| u16::try_from(p.saturating_add(1)).ok())
    };

    let mut out = Vec::new();
    bmff::write_full_box(&mut out, *b"meta", 0, 0, |out| {
        // Name written empty: the input's names the producing library.
        bmff::write_full_box(out, *b"hdlr", 0, 0, |out| {
            out.extend_from_slice(&[0; 4]);
            out.extend_from_slice(b"pict");
            out.extend_from_slice(&[0; 12]);
            out.push(0);
            Ok(())
        })?;

        let primary = renumber(parsed.primary).unwrap_or(1);
        bmff::write_full_box(out, *b"pitm", 0, 0, |out| {
            out.extend_from_slice(&primary.to_be_bytes());
            Ok(())
        })?;

        // Fresh and self-contained: the input's could name an external file.
        bmff::write_box(out, *b"dinf", |out| {
            bmff::write_full_box(out, *b"dref", 0, 0, |out| {
                out.extend_from_slice(&1_u32.to_be_bytes());
                // Flag bit 0: the data is in this file, no URL follows.
                bmff::write_full_box(out, *b"url ", 0, 1, |_| Ok(()))
            })
        })?;

        write_iinf(out, kept)?;
        write_iloc(out, kept, mdat_base)?;
        write_iref(out, parsed, &renumber)?;
        write_iprp(out, parsed, kept, &kept_properties, &reindex)
    })
    .map_err(|d| malformed(format, d))?;
    Ok(out)
}

/// Write `iinf`, one `infe` per retained item.
fn write_iinf(out: &mut Vec<u8>, kept: &[&Item<'_>]) -> std::result::Result<(), MalformedDetail> {
    bmff::write_full_box(out, *b"iinf", 0, 0, |out| {
        let count = u16::try_from(kept.len()).map_err(|_| MalformedDetail::LengthOutOfRange)?;
        out.extend_from_slice(&count.to_be_bytes());
        for (i, item) in kept.iter().enumerate() {
            let id = u16::try_from(i.saturating_add(1))
                .map_err(|_| MalformedDetail::LengthOutOfRange)?;
            bmff::write_full_box(out, *b"infe", 2, 0, |out| {
                out.extend_from_slice(&id.to_be_bytes());
                out.extend_from_slice(&0_u16.to_be_bytes());
                out.extend_from_slice(&item.kind);
                // Name empty: the input's is free text a producer may put anything in.
                out.push(0);
                Ok(())
            })?;
        }
        Ok(())
    })
}

/// Write `iloc`: one extent per item, fixed widths, absolute offsets.
fn write_iloc(
    out: &mut Vec<u8>,
    kept: &[&Item<'_>],
    mdat_base: u64,
) -> std::result::Result<(), MalformedDetail> {
    // Version 1 carries the construction method, always written 0. An input using `idat` therefore
    // has none in its output: its items moved into `mdat` like everything else.
    bmff::write_full_box(out, *b"iloc", 1, 0, |out| {
        let widths = (u16::from(ILOC_OFFSET_SIZE) << 12) | (u16::from(ILOC_LENGTH_SIZE) << 8);
        out.extend_from_slice(&widths.to_be_bytes());
        let count = u16::try_from(kept.len()).map_err(|_| MalformedDetail::LengthOutOfRange)?;
        out.extend_from_slice(&count.to_be_bytes());

        let mut cursor = mdat_base;
        for (i, item) in kept.iter().enumerate() {
            let id = u16::try_from(i.saturating_add(1))
                .map_err(|_| MalformedDetail::LengthOutOfRange)?;
            out.extend_from_slice(&id.to_be_bytes());
            out.extend_from_slice(&0_u16.to_be_bytes());
            out.extend_from_slice(&0_u16.to_be_bytes());
            // One extent per item: several inputs are written back to back, so one range covers it.
            out.extend_from_slice(&1_u16.to_be_bytes());
            let offset = u32::try_from(cursor).map_err(|_| MalformedDetail::LengthOutOfRange)?;
            let length =
                u32::try_from(item.bytes).map_err(|_| MalformedDetail::LengthOutOfRange)?;
            out.extend_from_slice(&offset.to_be_bytes());
            out.extend_from_slice(&length.to_be_bytes());
            cursor = cursor
                .checked_add(item.bytes)
                .ok_or(MalformedDetail::LengthOutOfRange)?;
        }
        Ok(())
    })
}

/// Write `iref`, keeping only the types that assemble the picture.
fn write_iref<F>(
    out: &mut Vec<u8>,
    parsed: &Parsed<'_>,
    renumber: &F,
) -> std::result::Result<(), MalformedDetail>
where
    F: Fn(u32) -> Option<u16>,
{
    let usable: Vec<&Reference> = parsed
        .references
        .iter()
        .filter(|r| boxes::REFERENCE_TYPES_KEPT.contains(&r.kind))
        .filter(|r| renumber(r.from).is_some())
        .collect();
    if usable.is_empty() {
        return Ok(());
    }
    bmff::write_full_box(out, *b"iref", 0, 0, |out| {
        for reference in usable {
            // Targets that went are dropped, survivors kept in order — which `grid` depends on.
            let targets: Vec<u16> = reference.to.iter().filter_map(|t| renumber(*t)).collect();
            if targets.is_empty() {
                continue;
            }
            let from = renumber(reference.from).ok_or(MalformedDetail::BrokenIndex)?;
            bmff::write_box(out, reference.kind, |out| {
                out.extend_from_slice(&from.to_be_bytes());
                let count =
                    u16::try_from(targets.len()).map_err(|_| MalformedDetail::LengthOutOfRange)?;
                out.extend_from_slice(&count.to_be_bytes());
                for target in &targets {
                    out.extend_from_slice(&target.to_be_bytes());
                }
                Ok(())
            })?;
        }
        Ok(())
    })
}

/// Write `iprp`: retained properties and the associations into them.
fn write_iprp<F>(
    out: &mut Vec<u8>,
    parsed: &Parsed<'_>,
    kept: &[&Item<'_>],
    kept_properties: &[usize],
    reindex: &F,
) -> std::result::Result<(), MalformedDetail>
where
    F: Fn(u16) -> Option<u16>,
{
    if kept_properties.is_empty() {
        return Ok(());
    }
    bmff::write_box(out, *b"iprp", |out| {
        bmff::write_box(out, *b"ipco", |out| {
            for &i in kept_properties {
                let property = parsed
                    .properties
                    .get(i)
                    .ok_or(MalformedDetail::BrokenIndex)?;
                bmff::write_box(out, property.kind, |out| {
                    out.extend_from_slice(property.payload);
                    Ok(())
                })?;
            }
            Ok(())
        })?;

        // Decided from the retained count before either layout pass, so both passes agree.
        let wide = kept_properties.len() > 0x7F;
        let flags = u32::from(wide);
        bmff::write_full_box(out, *b"ipma", 0, flags, |out| {
            let mut entries: Vec<(u16, Vec<Association>)> = Vec::new();
            for (i, item) in kept.iter().enumerate() {
                let id = u16::try_from(i.saturating_add(1))
                    .map_err(|_| MalformedDetail::LengthOutOfRange)?;
                let mut list = Vec::new();
                for (owner, associations) in &parsed.associations {
                    if *owner != item.id {
                        continue;
                    }
                    for association in associations {
                        if let Some(index) = reindex(association.index) {
                            list.push(Association {
                                index,
                                essential: association.essential,
                            });
                        }
                    }
                }
                if !list.is_empty() {
                    entries.push((id, list));
                }
            }

            let count =
                u32::try_from(entries.len()).map_err(|_| MalformedDetail::LengthOutOfRange)?;
            out.extend_from_slice(&count.to_be_bytes());
            for (id, list) in entries {
                out.extend_from_slice(&id.to_be_bytes());
                let n = u8::try_from(list.len()).map_err(|_| MalformedDetail::LengthOutOfRange)?;
                out.push(n);
                for association in list {
                    if wide {
                        let mut word = association.index & 0x7FFF;
                        if association.essential {
                            word |= 0x8000;
                        }
                        out.extend_from_slice(&word.to_be_bytes());
                    } else {
                        let mut byte = u8::try_from(association.index & 0x7F).unwrap_or_default();
                        if association.essential {
                            byte |= 0x80;
                        }
                        out.push(byte);
                    }
                }
            }
            Ok(())
        })
    })
}

// ---------------------------------------------------------------------------------------------

/// Turn a walk failure into this format's typed error.
fn from_walk(format: Format, e: WalkError) -> StryptError {
    match e {
        WalkError::Malformed(detail) => malformed(format, detail),
        WalkError::Limit(limit) => StryptError::LimitExceeded { format, limit },
    }
}

/// A malformed-file error for this format.
fn malformed(format: Format, detail: MalformedDetail) -> StryptError {
    StryptError::Malformed {
        format,
        offset: None,
        detail,
    }
}

/// Widen a length for reporting.
fn as_u64(value: usize) -> u64 {
    u64::try_from(value).unwrap_or(u64::MAX)
}

#[cfg(test)]
mod tests {
    // Test code is not reachable from untrusted bytes (ADR-0006).
    #![allow(
        clippy::unwrap_used,
        clippy::indexing_slicing,
        clippy::arithmetic_side_effects
    )]

    use super::*;

    fn boxed(kind: [u8; 4], payload: &[u8]) -> Vec<u8> {
        let mut out = u32::try_from(payload.len() + 8)
            .unwrap()
            .to_be_bytes()
            .to_vec();
        out.extend_from_slice(&kind);
        out.extend_from_slice(payload);
        out
    }

    fn full_boxed(kind: [u8; 4], version: u8, flags: u32, payload: &[u8]) -> Vec<u8> {
        let mut body = vec![version];
        body.extend_from_slice(&flags.to_be_bytes()[1..4]);
        body.extend_from_slice(payload);
        boxed(kind, &body)
    }

    /// A minimal file: one `av01` item whose payload is `codestream`.
    fn minimal(codestream: &[u8]) -> Vec<u8> {
        let mut meta = Vec::new();
        meta.extend_from_slice(&full_boxed(
            *b"hdlr",
            0,
            0,
            &[&[0u8; 4][..], b"pict", &[0u8; 13]].concat(),
        ));
        meta.extend_from_slice(&full_boxed(*b"pitm", 0, 0, &1_u16.to_be_bytes()));
        let infe = full_boxed(
            *b"infe",
            2,
            0,
            &[
                &1_u16.to_be_bytes()[..],
                &0_u16.to_be_bytes(),
                b"av01",
                &[0],
            ]
            .concat(),
        );
        meta.extend_from_slice(&full_boxed(
            *b"iinf",
            0,
            0,
            &[&1_u16.to_be_bytes()[..], &infe].concat(),
        ));

        let ftyp = boxed(*b"ftyp", b"avif\x00\x00\x00\x00mif1avif");
        // Placeholder iloc to learn the layout, then the real one.
        let with = |offset: u32| {
            let mut body = (((4_u16) << 12) | ((4_u16) << 8)).to_be_bytes().to_vec();
            body.extend_from_slice(&1_u16.to_be_bytes());
            body.extend_from_slice(&1_u16.to_be_bytes());
            body.extend_from_slice(&0_u16.to_be_bytes());
            body.extend_from_slice(&0_u16.to_be_bytes());
            body.extend_from_slice(&1_u16.to_be_bytes());
            body.extend_from_slice(&offset.to_be_bytes());
            body.extend_from_slice(&u32::try_from(codestream.len()).unwrap().to_be_bytes());
            let mut m = meta.clone();
            m.extend_from_slice(&full_boxed(*b"iloc", 1, 0, &body));
            full_boxed(*b"meta", 0, 0, &m)
        };
        let probe = with(0);
        let base = u32::try_from(ftyp.len() + probe.len() + 8).unwrap();
        let mut out = ftyp.clone();
        out.extend_from_slice(&with(base));
        out.extend_from_slice(&boxed(*b"mdat", codestream));
        out
    }

    fn strip_ok(data: &[u8]) -> Stripped {
        HeifHandler::AVIF
            .strip(data, &StripOptions::default())
            .unwrap()
    }

    #[test]
    fn a_minimal_file_round_trips_and_keeps_its_picture() {
        let out = strip_ok(&minimal(b"PICTURE-BYTES")).bytes;
        assert!(out.windows(13).any(|w| w == b"PICTURE-BYTES"));
    }

    #[test]
    fn the_output_reads_back_clean() {
        let out = strip_ok(&minimal(b"PICTURE-BYTES")).bytes;
        let report = HeifHandler::AVIF
            .inspect(&out, &InspectOptions::names_only())
            .unwrap();
        assert!(report.findings.is_empty(), "{:?}", report.findings);
    }

    #[test]
    fn stripping_twice_is_byte_identical() {
        let once = strip_ok(&minimal(b"PICTURE-BYTES")).bytes;
        let twice = strip_ok(&once).bytes;
        assert_eq!(once, twice);
    }

    #[test]
    fn a_file_with_no_meta_is_refused() {
        let mut data = boxed(*b"ftyp", b"avif\x00\x00\x00\x00mif1avif");
        data.extend_from_slice(&boxed(*b"mdat", b"picture"));
        assert!(
            HeifHandler::AVIF
                .strip(&data, &StripOptions::default())
                .is_err()
        );
    }

    #[test]
    fn a_moov_box_is_refused_as_a_motion_file() {
        let mut data = minimal(b"PICTURE");
        data.extend_from_slice(&boxed(*b"moov", b""));
        assert!(matches!(
            HeifHandler::HEIF.strip(&data, &StripOptions::default()),
            Err(StryptError::UnsupportedFormat {
                format: crate::error::UnsupportedKind::MotionHeif
            })
        ));
    }

    #[test]
    fn an_iloc_width_the_format_does_not_permit_is_refused() {
        // §8.11.3 allows only 0, 4 and 8. A width of 2 means the walk is lost, and continuing
        // would read the wrong bytes with confidence.
        let mut data = minimal(b"PICTURE");
        let at = data.windows(4).position(|w| w == b"iloc").unwrap();
        data[at + 8] = 0x20;
        assert!(
            HeifHandler::AVIF
                .strip(&data, &StripOptions::default())
                .is_err()
        );
    }

    #[test]
    fn read_uint_rejects_widths_outside_the_specification() {
        let mut r = Reader::new(&[0xFF; 16]);
        assert_eq!(read_uint(&mut r, 0), Some(0));
        assert!(read_uint(&mut r, 4).is_some());
        assert!(read_uint(&mut r, 8).is_some());
        assert!(read_uint(&mut r, 2).is_none());
        assert!(read_uint(&mut r, 3).is_none());
    }

    #[test]
    fn a_c_string_stops_at_its_terminator() {
        assert_eq!(c_string(b"name\x00rest"), (&b"name"[..], &b"rest"[..]));
        // Unterminated: the whole slice is the string and nothing follows.
        assert_eq!(c_string(b"name"), (&b"name"[..], &b""[..]));
        assert_eq!(c_string(b""), (&b""[..], &b""[..]));
    }

    #[test]
    fn the_report_counts_bytes_without_naming_values_by_default() {
        // docs/THREAT_MODEL.md §5.5: a report is durable, so values are opt-in.
        let mut data = minimal(b"PICTURE");
        data.extend_from_slice(&boxed(*b"free", b"SECRET"));
        let report = strip_ok(&data).report;
        assert!(report.removed.iter().all(|f| f.value.is_none()));
        assert!(report.removed.iter().any(|f| f.bytes > 0));
    }
}
