//! Gives the Windows `.exe` the mark as its Explorer icon (ADR-0062). The resource compiler is
//! `rc.exe`, so this runs on a Windows host only; a cross-lint from macOS or Linux gets no icon.

#[cfg_attr(not(windows), allow(clippy::unnecessary_wraps))] // fallible on Windows; one signature
fn main() -> std::io::Result<()> {
    println!("cargo::rerun-if-changed=build.rs");
    println!("cargo::rerun-if-changed=src/mark.rs");
    #[cfg(windows)]
    if std::env::var("CARGO_CFG_TARGET_OS").is_ok_and(|os| os == "windows") {
        windows::embed()?;
    }
    Ok(())
}

#[cfg(windows)]
#[path = "src/mark.rs"]
mod mark;

#[cfg(windows)]
mod windows {
    use std::io::{Error, Result};
    use std::path::PathBuf;

    use super::mark;

    /// Explorer picks the nearest size, so the small ones are drawn, not scaled down.
    const SIZES: [u16; 6] = [16, 24, 32, 48, 64, 256];

    pub fn embed() -> Result<()> {
        let out =
            PathBuf::from(std::env::var_os("OUT_DIR").ok_or_else(|| Error::other("OUT_DIR"))?);
        let ico = out.join("strypt.ico");
        std::fs::write(&ico, ico_bytes()?)?;
        winresource::WindowsResource::new()
            .set_icon(
                ico.to_str()
                    .ok_or_else(|| Error::other("OUT_DIR is not UTF-8"))?,
            )
            .set("ProductName", "strypt")
            .set("FileDescription", "strypt")
            .compile()
    }

    /// An ICO of 32-bit DIBs: a header, one directory entry per size, then each image.
    fn ico_bytes() -> Result<Vec<u8>> {
        let images = SIZES.map(dib);
        let count = u16::try_from(SIZES.len()).map_err(Error::other)?;
        let mut offset = u32::from(6 + 16 * count);
        let mut ico = Vec::new();
        for field in [0, 1, count] {
            ico.extend(field.to_le_bytes());
        }
        for (size, image) in SIZES.iter().zip(&images) {
            let len = u32::try_from(image.len()).map_err(Error::other)?;
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
        let rgba = mark::pixels(size);
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
}
