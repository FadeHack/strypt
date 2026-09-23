//! Icon files, written by hand: ICO for Windows, ICNS for macOS, PNG for Linux and inside ICNS.
//! PNG data is stored, not compressed, so no deflate crate is needed; the `.dmg` compresses it.

use std::num::TryFromIntError;

use crate::pixels;

/// Explorer picks the nearest size, so the small ones are drawn, not scaled down.
const ICO_SIZES: [u16; 6] = [16, 24, 32, 48, 64, 256];

/// ICNS PNG types and their pixel sizes. `ic11`–`ic14` are Retina doubles of 16, 32, 128 and 256
/// points; `ic10`, 512@2x, is left out, as a 1024-pixel stored PNG is 4 MB.
const ICNS_TYPES: [(&[u8; 4], u16); 9] = [
    (b"icp4", 16),
    (b"ic11", 16 * 2),
    (b"icp5", 32),
    (b"ic12", 32 * 2),
    (b"ic07", 128),
    (b"ic13", 128 * 2),
    (b"ic08", 256),
    (b"ic14", 256 * 2),
    (b"ic09", 512),
];

/// An ICO of 32-bit DIBs: a header, one directory entry per size, then each image.
///
/// # Errors
/// Only if an image outgrew a 32-bit length, which the fixed sizes rule out.
pub fn ico() -> Result<Vec<u8>, TryFromIntError> {
    let images = ICO_SIZES.map(dib);
    let count = u16::try_from(ICO_SIZES.len())?;
    let mut offset = u32::from(6 + 16 * count);
    let mut ico = Vec::new();
    for field in [0, 1, count] {
        ico.extend(field.to_le_bytes());
    }
    for (size, image) in ICO_SIZES.iter().zip(&images) {
        let len = u32::try_from(image.len())?;
        // A width or height of 256 is written as 0.
        let edge = u8::try_from(*size).unwrap_or(0);
        ico.extend([edge, edge, 0, 0]);
        ico.extend(1u16.to_le_bytes());
        ico.extend(32u16.to_le_bytes());
        ico.extend(len.to_le_bytes());
        ico.extend(offset.to_le_bytes());
        offset += len;
    }
    for image in &images {
        ico.extend(image);
    }
    Ok(ico)
}

/// A BITMAPINFOHEADER, BGRA rows from the bottom, and an all-zero AND mask, since alpha
/// already says what is transparent.
fn dib(size: u16) -> Vec<u8> {
    let edge = usize::from(size);
    let mask_row = edge.div_ceil(32) * 4;
    let rgba = pixels(size);
    let mut dib = Vec::with_capacity(40 + edge * edge * 4 + edge * mask_row);
    let (width, height) = (i32::from(size), 2 * i32::from(size));
    dib.extend(40u32.to_le_bytes());
    dib.extend(width.to_le_bytes());
    dib.extend(height.to_le_bytes());
    dib.extend(1u16.to_le_bytes());
    dib.extend(32u16.to_le_bytes());
    dib.extend([0; 24]);
    for row in rgba.chunks_exact(edge * 4).rev() {
        for px in row.chunks_exact(4) {
            dib.extend([px[2], px[1], px[0], px[3]]);
        }
    }
    dib.resize(dib.len() + edge * mask_row, 0);
    dib
}

/// An ICNS of PNGs: a header, then one typed, length-prefixed element per size.
///
/// # Errors
/// Only if an element outgrew a 32-bit length, which the fixed sizes rule out.
pub fn icns() -> Result<Vec<u8>, TryFromIntError> {
    let mut body = Vec::new();
    for (kind, size) in ICNS_TYPES {
        let image = png(size)?;
        body.extend(kind);
        body.extend(u32::try_from(8 + image.len())?.to_be_bytes());
        body.extend(image);
    }
    let mut icns = b"icns".to_vec();
    icns.extend(u32::try_from(8 + body.len())?.to_be_bytes());
    icns.extend(body);
    Ok(icns)
}

/// An 8-bit RGBA PNG of the mark at `size`, its image data in stored deflate blocks.
///
/// # Errors
/// Only if the image outgrew a 32-bit length.
pub fn png(size: u16) -> Result<Vec<u8>, TryFromIntError> {
    let edge = usize::from(size);
    // Each row starts with filter type 0, none.
    let mut raw = Vec::with_capacity(edge * (edge * 4 + 1));
    for row in pixels(size).chunks_exact(edge * 4) {
        raw.push(0);
        raw.extend(row);
    }
    let mut zlib = vec![0x78, 0x01];
    let blocks = raw.chunks(usize::from(u16::MAX));
    let last = blocks.len().saturating_sub(1);
    for (i, block) in blocks.enumerate() {
        let len = u16::try_from(block.len())?;
        zlib.push(u8::from(i == last));
        zlib.extend(len.to_le_bytes());
        zlib.extend((!len).to_le_bytes());
        zlib.extend(block);
    }
    zlib.extend(adler32(&raw).to_be_bytes());

    let mut ihdr = Vec::with_capacity(13);
    ihdr.extend(u32::from(size).to_be_bytes());
    ihdr.extend(u32::from(size).to_be_bytes());
    ihdr.extend([8, 6, 0, 0, 0]);
    let mut png = b"\x89PNG\r\n\x1a\n".to_vec();
    chunk(&mut png, *b"IHDR", &ihdr)?;
    chunk(&mut png, *b"IDAT", &zlib)?;
    chunk(&mut png, *b"IEND", &[])?;
    Ok(png)
}

fn chunk(png: &mut Vec<u8>, kind: [u8; 4], data: &[u8]) -> Result<(), TryFromIntError> {
    png.extend(u32::try_from(data.len())?.to_be_bytes());
    let start = png.len();
    png.extend(kind);
    png.extend(data);
    let crc = crc32(png.get(start..).unwrap_or_default());
    png.extend(crc.to_be_bytes());
    Ok(())
}

/// ISO 3309 CRC-32, as PNG uses it, bit by bit: icon files are small.
fn crc32(bytes: &[u8]) -> u32 {
    let mut crc = u32::MAX;
    for &b in bytes {
        crc ^= u32::from(b);
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

/// RFC 1950's Adler-32.
fn adler32(bytes: &[u8]) -> u32 {
    let (mut a, mut b) = (1u32, 0u32);
    for &byte in bytes {
        a = (a + u32::from(byte)) % 65521;
        b = (b + a) % 65521;
    }
    (b << 16) | a
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn checksums_match_their_reference_values() {
        assert_eq!(crc32(b"123456789"), 0xCBF4_3926);
        assert_eq!(adler32(b"Wikipedia"), 0x11E6_0398);
    }

    #[test]
    fn each_file_starts_with_its_signature_and_says_its_own_length() {
        let ico = ico().unwrap();
        assert_eq!(ico.get(..6), Some(&[0, 0, 1, 0, 6, 0][..]));
        let icns = icns().unwrap();
        assert_eq!(icns.get(..4), Some(&b"icns"[..]));
        assert_eq!(
            icns.get(4..8),
            Some(&u32::try_from(icns.len()).unwrap().to_be_bytes()[..])
        );
        let png = png(16).unwrap();
        assert_eq!(png.get(..8), Some(&b"\x89PNG\r\n\x1a\n"[..]));
        assert_eq!(png.get(png.len() - 8..png.len() - 4), Some(&b"IEND"[..]));
    }
}
