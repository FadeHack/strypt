//! Which TIFF tags survive a rebuild, and why each one has to.
//!
//! **This list is an allow-list and the direction is the point** (ADR-0033). A tag reaches the
//! output only by appearing here; everything else is absent because it was never written. A
//! deny-list would carry an unknown tag through, and the tags that leak hardest in this format
//! are precisely the ones no table has heard of — a vendor maker note, a scanner's private
//! field, a proprietary tag holding a device serial number.
//!
//! The two directions of error are not symmetrical, and the asymmetry is why every entry below
//! carries a reason:
//!
//! - **A tag wrongly omitted breaks the image.** Loud, found by the decode check every fixture
//!   goes through and by the differential against `ExifTool`.
//! - **A tag wrongly included leaks.** Silent, and the user finds out after publishing.
//!
//! So the bar for adding an entry is that the image *cannot be decoded without it* — not that it
//! looks harmless. Tags that merely describe the image without being needed to render it are
//! deliberately absent.

/// TIFF field type codes this module names.
pub(crate) const SHORT: u16 = 3;
pub(crate) const LONG: u16 = 4;

/// `NewSubfileType`. Bit 0 marks a reduced-resolution copy of another image in the file, which
/// is how a thumbnail is flagged (TIFF 6.0 §8).
pub(crate) const NEW_SUBFILE_TYPE: u16 = 0x00FE;

/// `ImageWidth` and `ImageLength`: without these there is no image.
pub(crate) const IMAGE_WIDTH: u16 = 0x0100;
pub(crate) const IMAGE_LENGTH: u16 = 0x0101;

/// Where the image data lives and how much of it there is. Regenerated rather than copied —
/// the data moves, so the input's values describe the input's layout and nothing else.
pub(crate) const STRIP_OFFSETS: u16 = 0x0111;
pub(crate) const STRIP_BYTE_COUNTS: u16 = 0x0117;
pub(crate) const TILE_OFFSETS: u16 = 0x0144;
pub(crate) const TILE_BYTE_COUNTS: u16 = 0x0145;

/// Whether `tag` is structural — needed to decode the image, and therefore written to the
/// output with its value copied across unchanged.
///
/// Each arm states what breaks without it. A tag whose absence merely changes how the image is
/// *described* is not structural and does not belong here.
pub(crate) const fn is_structural(tag: u16) -> bool {
    matches!(
        tag,
        // Which kind of image this directory holds. Carried so a multi-page file keeps saying
        // what its pages are; the reduced-resolution bit is handled before this point, because
        // such a directory is dropped rather than written.
        NEW_SUBFILE_TYPE | 0x00FF
        // Dimensions.
        | IMAGE_WIDTH | IMAGE_LENGTH
        // Bits per sample and how many samples each pixel has: the shape of a pixel.
        | 0x0102 | 0x0115
        // Compression. Without it a reader cannot know how to expand the strips.
        | 0x0103
        // PhotometricInterpretation: whether 0 means black or white, or the data is palette
        // or YCbCr. Wrong or absent, the image renders inverted or as noise.
        | 0x0106
        // FillOrder: the bit order within a byte, which CCITT-compressed scans rely on.
        | 0x010A
        // Orientation. Not required to decode, but a scanned page displayed upside down is a
        // damaged document to the person reading it, and the tag names no one.
        | 0x0112
        // RowsPerStrip: how the strips divide the image. Meaningless to drop.
        | 0x0116
        // The sample value range, which some readers use to scale non-8-bit data.
        | 0x0118 | 0x0119
        // Resolution and its unit. A scanned page at the wrong DPI prints at the wrong size.
        | 0x011A | 0x011B | 0x0128
        // PlanarConfiguration: whether samples are interleaved or in separate planes. Getting
        // this wrong turns a photograph into three grey ghosts.
        | 0x011C
        // PageNumber: which page of how many. Structural for the multi-page scans this format
        // is used for, and it identifies nobody.
        | 0x0129
        // Predictor: the horizontal differencing applied before LZW or Deflate. Dropping it
        // decodes the strips into gradient mush.
        | 0x013D
        // ColorMap: the palette. A palette image without it is unreadable.
        | 0x0140
        // Tile geometry, for tiled images.
        | 0x0142 | 0x0143
        // ExtraSamples: whether the extra channel is alpha, and whether it is premultiplied.
        | 0x0152
        // SampleFormat and its associated minimum/maximum: whether samples are unsigned,
        // signed, or floating point.
        | 0x0153 | 0x0154 | 0x0155
        // JPEGTables: the shared quantisation and Huffman tables for Compression 7. The strips
        // are undecodable without them.
        | 0x015B
        // YCbCr coefficients, subsampling, positioning, and the black/white reference. Needed
        // to convert a YCbCr image back to colour correctly.
        | 0x0211 | 0x0212 | 0x0213 | 0x0214
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_identifying_tags_are_not_structural() {
        // Each of these is a tag a real camera, scanner, or editor writes, and each is the
        // reason this handler exists. If one ever starts reporting as structural, it would be
        // copied into the output silently — so this test names them rather than trusting the
        // match arms above to stay correct under editing.
        for (tag, what) in [
            (0x010D, "DocumentName"),
            (0x010E, "ImageDescription"),
            (0x010F, "Make"),
            (0x0110, "Model"),
            (0x0131, "Software"),
            (0x0132, "DateTime"),
            (0x013B, "Artist"),
            (0x013C, "HostComputer"),
            (0x8298, "Copyright"),
            (0x8769, "ExifIFD"),
            (0x8825, "GPSIFD"),
            (0x02BC, "XMP"),
            (0x83BB, "IPTC"),
            (0x8773, "ICC profile"),
            (0x014A, "SubIFDs"),
            (0x0201, "JPEGInterchangeFormat (thumbnail)"),
            (0x0202, "JPEGInterchangeFormatLength"),
            (0x9286, "UserComment"),
        ] {
            assert!(
                !is_structural(tag),
                "{what} (0x{tag:04X}) would be copied into stripped output"
            );
        }
    }

    #[test]
    fn an_unknown_vendor_tag_is_not_structural() {
        // The whole reason the list runs this direction: a private tag strypt has never seen
        // must not survive by going unrecognised.
        for tag in [0xC62F_u16, 0xFDE8, 0x9C9B, 0xEA1C] {
            assert!(!is_structural(tag));
        }
    }

    #[test]
    fn the_tags_an_image_cannot_decode_without_are_structural() {
        for tag in [
            IMAGE_WIDTH,
            IMAGE_LENGTH,
            0x0102, // BitsPerSample
            0x0103, // Compression
            0x0106, // PhotometricInterpretation
            0x0115, // SamplesPerPixel
            0x0116, // RowsPerStrip
            0x011C, // PlanarConfiguration
            0x0140, // ColorMap
            0x015B, // JPEGTables
        ] {
            assert!(is_structural(tag), "0x{tag:04X} must survive a rebuild");
        }
    }
}
