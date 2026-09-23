//! Writes one of the mark's icon files, for the packaging scripts (ADR-0062).
//!
//! Usage: strypt-mark ico|icns|png OUT [SIZE]    (SIZE is for png; default 256)

#![forbid(unsafe_code)]

use std::process::ExitCode;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let bytes = match (args.first().map(String::as_str), args.get(2)) {
        (Some("ico"), None) => strypt_mark::ico(),
        (Some("icns"), None) => strypt_mark::icns(),
        (Some("png"), size) => match size.map_or(Ok(strypt_mark::SIZE), |s| s.parse()) {
            Ok(size) if size > 0 => strypt_mark::png(size),
            _ => return usage(),
        },
        _ => return usage(),
    };
    let (Ok(bytes), Some(out)) = (bytes, args.get(1)) else {
        return usage();
    };
    match std::fs::write(out, bytes) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("strypt-mark: {out}: {e}");
            ExitCode::FAILURE
        }
    }
}

fn usage() -> ExitCode {
    eprintln!("usage: strypt-mark ico|icns|png OUT [SIZE]");
    ExitCode::from(2)
}
