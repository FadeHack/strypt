//! What a stripped MP4 is allowed to contain: one allow-list per level of the `moov` tree, plus
//! the box and brand names that refuse a file outright.
//!
//! Allow-lists, as in [`crate::formats::heif::boxes`] — but the safety here does not rest on them.
//! Media is only reachable through a chunk offset, and every chunk offset must resolve inside an
//! `mdat` that was kept, so a dropped box something pointed into refuses the file at the offset
//! check rather than by being named here (ADR-0042 decision 10).

use crate::container::bmff::BoxType;

/// Boxes that cross into the output at the top level. `moov` is rebuilt rather than copied and is
/// handled separately; everything else here is copied byte for byte, header form included.
pub(crate) const TOP_LEVEL_COPIED: [BoxType; 2] = [*b"ftyp", *b"mdat"];

/// Boxes whose presence makes the file fragmented. Refused by name: their sample offsets live in
/// structures this handler does not rewrite (ADR-0042 decision 6).
pub(crate) const FRAGMENT_BOXES: [BoxType; 6] =
    [*b"moof", *b"mfra", *b"mvex", *b"styp", *b"sidx", *b"ssix"];

/// Brands that declare a fragmented delivery format.
pub(crate) const FRAGMENT_BRANDS: [BoxType; 5] = [*b"dash", *b"msdh", *b"msix", *b"cmfc", *b"cmfl"];

/// Boxes that mean the samples are encrypted, wherever they appear (ADR-0042 decision 7).
pub(crate) const PROTECTION_BOXES: [BoxType; 4] = [*b"pssh", *b"senc", *b"sinf", *b"schm"];

/// Sample entry types that mean the samples are encrypted. `encv`..`enct` are Common Encryption's
/// four media classes; `drms` and `drmi` are `FairPlay`.
pub(crate) const PROTECTED_SAMPLE_ENTRIES: [BoxType; 6] =
    [*b"encv", *b"enca", *b"encs", *b"enct", *b"drms", *b"drmi"];

/// Brands routing to [`crate::detect::Format::Mp4`].
pub(crate) const MP4_BRANDS: [BoxType; 9] = [
    *b"isom", *b"iso2", *b"iso4", *b"iso5", *b"iso6", *b"mp41", *b"mp42", *b"mmp4", *b"avc1",
];

/// Brands routing to [`crate::detect::Format::M4a`]. `M4V ` is video in the same family and is in
/// [`MP4_BRANDS_VIDEO`]; `M4P ` is `FairPlay` and is refused.
pub(crate) const M4A_BRANDS: [BoxType; 2] = [*b"M4A ", *b"M4B "];

/// Apple's video brand, which is an MP4 by any other name.
pub(crate) const MP4_BRANDS_VIDEO: [BoxType; 1] = [*b"M4V "];

/// `FairPlay`-protected audio.
pub(crate) const PROTECTED_BRAND: BoxType = *b"M4P ";

/// `QuickTime`.
pub(crate) const QUICKTIME_BRAND: BoxType = *b"qt  ";

/// Children of `moov` that reach the output. Everything else — `udta`, `meta`, `uuid`, `iods`,
/// `ctab`, `free` — is dropped and reported.
pub(crate) const MOOV_KEPT: [BoxType; 2] = [*b"mvhd", *b"trak"];

/// Children of `trak` that reach the output. `edts` carries the edit list, whose offsets are media
/// times rather than file offsets; `tref` binds tracks to each other by track ID.
pub(crate) const TRAK_KEPT: [BoxType; 4] = [*b"tkhd", *b"edts", *b"tref", *b"mdia"];

/// Children of `mdia` that reach the output.
pub(crate) const MDIA_KEPT: [BoxType; 3] = [*b"mdhd", *b"hdlr", *b"minf"];

/// Children of `minf` that reach the output: the four media headers, the data reference, and the
/// sample table.
pub(crate) const MINF_KEPT: [BoxType; 6] =
    [*b"vmhd", *b"smhd", *b"hmhd", *b"sthd", *b"nmhd", *b"stbl"];

/// `dinf` is kept separately from [`MINF_KEPT`] because its `dref` is inspected rather than copied
/// blindly: a track whose media lives in another file is refused.
pub(crate) const MINF_DINF: BoxType = *b"dinf";

/// Children of `stbl` that reach the output. Every one of them describes how the samples in `mdat`
/// are laid out or decoded; none names a person, a device, a place, or a time.
pub(crate) const STBL_KEPT: [BoxType; 15] = [
    *b"stsd", // sample descriptions — the codec configuration
    *b"stts", // time-to-sample
    *b"ctts", // composition offsets
    *b"cslg", // composition-to-decode timing
    *b"stss", // sync samples
    *b"stsh", // shadow sync samples
    *b"sdtp", // sample dependency flags
    *b"stsc", // sample-to-chunk
    *b"stsz", // sample sizes
    *b"stz2", // compact sample sizes
    *b"stco", // 32-bit chunk offsets — remapped, not copied
    *b"co64", // 64-bit chunk offsets — remapped, not copied
    *b"sbgp", // sample-to-group
    *b"sgpd", // sample group descriptions
    *b"stps", // partial sync samples
];

/// The 32-bit chunk offset table (§8.7.5).
pub(crate) const STCO: BoxType = *b"stco";
/// The same table with 64-bit entries.
pub(crate) const CO64: BoxType = *b"co64";

/// The 16-byte extended type the XMP specification fixes for a `uuid` box.
pub(crate) const XMP_UUID: [u8; 16] = [
    0xBE, 0x7A, 0xCF, 0xCB, 0x97, 0xA9, 0x42, 0xE8, 0x9C, 0x71, 0x99, 0x94, 0x91, 0xE3, 0xAF, 0xAC,
];

/// Whether `kind` may appear as a child of a box of type `parent` in a stripped file.
pub(crate) fn kept_in(parent: BoxType, kind: BoxType) -> bool {
    match &parent {
        b"moov" => MOOV_KEPT.contains(&kind),
        b"trak" => TRAK_KEPT.contains(&kind),
        b"mdia" => MDIA_KEPT.contains(&kind),
        b"minf" => MINF_KEPT.contains(&kind) || kind == MINF_DINF,
        b"stbl" => STBL_KEPT.contains(&kind),
        _ => false,
    }
}

/// Whether a box of this type has its children filtered rather than being copied whole.
pub(crate) fn is_container(kind: BoxType) -> bool {
    matches!(&kind, b"moov" | b"trak" | b"mdia" | b"minf" | b"stbl")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_unknown_box_is_kept_at_no_level() {
        // The property the allow-lists exist for: a vendor box nobody has heard of must not reach
        // the output by going unrecognised.
        for parent in [*b"moov", *b"trak", *b"mdia", *b"minf", *b"stbl"] {
            assert!(!kept_in(parent, *b"XPRV"));
            assert!(!kept_in(parent, *b"uuid"));
            assert!(!kept_in(parent, *b"udta"));
            assert!(!kept_in(parent, *b"meta"));
            assert!(!kept_in(parent, *b"free"));
        }
    }

    #[test]
    fn the_boxes_a_playable_file_needs_are_kept() {
        assert!(kept_in(*b"moov", *b"trak"));
        assert!(kept_in(*b"trak", *b"mdia"));
        assert!(kept_in(*b"mdia", *b"minf"));
        assert!(kept_in(*b"minf", *b"stbl"));
        assert!(kept_in(*b"minf", *b"dinf"));
        assert!(kept_in(*b"stbl", STCO));
        assert!(kept_in(*b"stbl", CO64));
    }

    #[test]
    fn the_protection_signals_do_not_overlap_the_keep_lists() {
        // A `sinf` reaching the output through a keep list would mean a protected file being
        // reported clean, which is what decision 7 refuses.
        for kind in PROTECTION_BOXES {
            for parent in [*b"moov", *b"trak", *b"mdia", *b"minf", *b"stbl"] {
                assert!(!kept_in(parent, kind), "{kind:?} under {parent:?}");
            }
        }
    }

    #[test]
    fn a_container_is_filtered_and_a_leaf_is_not() {
        assert!(is_container(*b"stbl"));
        assert!(!is_container(*b"stsd"));
        assert!(!is_container(*b"mdat"));
    }
}
