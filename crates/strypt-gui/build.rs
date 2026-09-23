//! Gives the Windows `.exe` the mark as its Explorer icon (ADR-0062). The resource compiler is
//! `rc.exe`, so this runs on a Windows host only; a cross-lint from macOS or Linux gets no icon.

#[cfg_attr(not(windows), allow(clippy::unnecessary_wraps))] // fallible on Windows; one signature
fn main() -> std::io::Result<()> {
    println!("cargo::rerun-if-changed=build.rs");
    #[cfg(windows)]
    if std::env::var("CARGO_CFG_TARGET_OS").is_ok_and(|os| os == "windows") {
        use std::io::Error;
        let out = std::env::var_os("OUT_DIR").ok_or_else(|| Error::other("OUT_DIR"))?;
        let ico = std::path::Path::new(&out).join("strypt.ico");
        std::fs::write(&ico, strypt_mark::ico().map_err(Error::other)?)?;
        let path = ico
            .to_str()
            .ok_or_else(|| Error::other("OUT_DIR is not UTF-8"))?;
        winresource::WindowsResource::new()
            .set_icon(path)
            .set("ProductName", "strypt")
            .set("FileDescription", "strypt")
            .compile()?;
    }
    Ok(())
}
