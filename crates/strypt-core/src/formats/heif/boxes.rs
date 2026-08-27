//! What a stripped HEIF is allowed to contain: allow-lists of boxes, item types and properties.
//!
//! Allow-lists rather than deny-lists, for ADR-0033's reason applied to a new unit — and more
//! sharply here, since §4.2 makes `uuid` a box type anyone may invent (ADR-0034).

use crate::container::bmff::BoxType;

/// Boxes permitted at the top level. `mdat` is absent because the output's is written fresh.
pub(crate) const TOP_LEVEL_KEPT: [BoxType; 2] = [*b"ftyp", *b"meta"];

/// Boxes permitted inside `meta`, every one of which is rebuilt rather than copied.
pub(crate) const META_KEPT: [BoxType; 7] = [
    *b"hdlr", *b"pitm", *b"iloc", *b"iinf", *b"iref", *b"iprp", *b"dinf",
];

/// Boxes whose presence makes the file a motion sequence — an Apple Live Photo, typically.
///
/// Refused by name: video containers are Phase 2 group 4 (ADR-0034).
pub(crate) const MOTION_BOXES: [BoxType; 4] = [*b"moov", *b"moof", *b"mfra", *b"mvex"];

/// Sequence brands (ISO/IEC 23008-12 §6.4), refused as [`MOTION_BOXES`] are. Checked separately
/// because a file may carry one without a `moov`, or a `moov` without one.
pub(crate) const SEQUENCE_BRANDS: [BoxType; 2] = [*b"msf1", *b"hevc"];

/// Item types carrying the picture, or the structure that assembles it. Anything else is dropped;
/// a *primary* item not on this list means the file is refused (§5.4).
pub(crate) const IMAGE_ITEM_TYPES: [BoxType; 8] = [
    // Coded images.
    *b"av01", // AV1, which is what makes a file an AVIF
    *b"hvc1", // HEVC, the ordinary HEIC spelling
    *b"hev1", // HEVC with parameter sets in the stream
    *b"vvc1", // VVC, ISO/IEC 23008-12:2022
    *b"unci", // uncompressed, ISO/IEC 23001-17
    *b"jpeg", // a JPEG codestream carried as a HEIF item
    // Derived images: these hold no pixels themselves, they say how to assemble the ones that do.
    *b"grid", // a tiled image, which is how large HEICs are stored
    *b"iovl", // an overlay
];

/// Properties permitted in the rebuilt `ipco`: each changes how the picture decodes or renders,
/// and none names a person, device, place, or time.
pub(crate) const PROPERTIES_KEPT: [BoxType; 15] = [
    *b"ispe", // image spatial extents — the dimensions
    *b"pixi", // bits per channel
    *b"av1C", // AV1 decoder configuration
    *b"hvcC", // HEVC decoder configuration
    *b"vvcC", // VVC decoder configuration
    *b"pasp", // pixel aspect ratio
    *b"clap", // clean aperture — a crop the decoder applies
    *b"irot", // rotation
    *b"imir", // mirroring
    *b"auxC", // auxiliary type: what an alpha or depth item *is*
    *b"a1op", // AV1 operating point
    *b"a1lx", // AV1 layered extents
    *b"lsel", // layer selection
    *b"clli", // content light level — HDR rendering
    *b"mdcv", // mastering display colour volume — HDR rendering
];

/// `colr`'s numeric spelling (§12.1.5), kept where `prof`/`rICC` ICC profiles are removed —
/// the same trade as every other handler (§7.2, §7.4, §7.8).
pub(crate) const COLOUR_TYPE_NCLX: [u8; 4] = *b"nclx";

/// Reference types kept: `dimg` binds a grid to its tiles, `auxl` an alpha item to its image.
/// Without either the picture does not assemble.
pub(crate) const REFERENCE_TYPES_KEPT: [BoxType; 2] = [*b"dimg", *b"auxl"];

/// Binds a thumbnail to what it depicts. Its target is removed: a thumbnail survives cropping and
/// visual redaction (§3).
pub(crate) const REFERENCE_THUMBNAIL: BoxType = *b"thmb";

/// Whether a box may appear at the top level of a stripped file.
pub(crate) fn top_level_kept(kind: BoxType) -> bool {
    TOP_LEVEL_KEPT.contains(&kind)
}

/// Whether a box may appear inside a stripped file's `meta`.
pub(crate) fn meta_kept(kind: BoxType) -> bool {
    META_KEPT.contains(&kind)
}

/// Whether an item of this type carries picture data or the structure that assembles it.
pub(crate) fn is_image_item(kind: BoxType) -> bool {
    IMAGE_ITEM_TYPES.contains(&kind)
}

/// Whether a property may be written. `colr` is answered here rather than in the table because
/// the decision needs its payload.
pub(crate) fn property_kept(kind: BoxType, payload: &[u8]) -> bool {
    if &kind == b"colr" {
        return payload.get(..4) == Some(&COLOUR_TYPE_NCLX);
    }
    PROPERTIES_KEPT.contains(&kind)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_unknown_item_type_is_not_an_image_item() {
        // The property the whole allow-list exists for: a vendor item type nobody has heard of
        // must not reach the output by going unrecognised.
        assert!(!is_image_item(*b"XPRV"));
        assert!(!is_image_item(*b"Exif"));
        assert!(is_image_item(*b"av01"));
    }

    #[test]
    fn an_unknown_property_is_not_kept() {
        assert!(!property_kept(*b"udes", b""));
        assert!(!property_kept(*b"XPRV", b"anything"));
        assert!(property_kept(*b"ispe", b""));
    }

    #[test]
    fn an_icc_profile_is_removed_and_numeric_colour_signalling_is_kept() {
        assert!(property_kept(*b"colr", b"nclx\x00\x01\x00\x0d\x00\x01\x80"));
        assert!(!property_kept(*b"colr", b"prof\x00\x00\x02\x0c"));
        assert!(!property_kept(*b"colr", b"rICC\x00\x00\x02\x0c"));
        // A truncated colour type is not nclx, so it is removed rather than guessed at.
        assert!(!property_kept(*b"colr", b"ncl"));
        assert!(!property_kept(*b"colr", b""));
    }

    #[test]
    fn a_uuid_box_is_not_kept_at_any_level() {
        // The blessed extension point, and the reason this list runs as an allow-list.
        assert!(!top_level_kept(*b"uuid"));
        assert!(!meta_kept(*b"uuid"));
        assert!(!top_level_kept(*b"free"));
        assert!(!top_level_kept(*b"skip"));
    }
}
