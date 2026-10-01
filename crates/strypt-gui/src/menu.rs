//! File-manager menu entries (ADR-0064): files that open the app with the selection, written and
//! removed by the app in the user's own directories. Nothing here loads into a file manager.

use std::io;
use std::path::{Path, PathBuf};

use strypt_core::Format;

/// Every format, for the entries' MIME lists. A test checks the corpus against it.
const FORMATS: [Format; 24] = [
    Format::Jpeg,
    Format::Png,
    Format::Webp,
    Format::Pdf,
    Format::Tiff,
    Format::Gif,
    Format::Heif,
    Format::Avif,
    Format::Docx,
    Format::Xlsx,
    Format::Pptx,
    Format::Odt,
    Format::Ods,
    Format::Odp,
    Format::Svg,
    Format::Jxl,
    Format::Flac,
    Format::Wav,
    Format::Mp3,
    Format::Ogg,
    Format::Opus,
    Format::OggFlac,
    Format::Mp4,
    Format::M4a,
];

/// shared-mime-info's names, aliases included: a file manager matches on the name it detects.
const fn mime_types(format: Format) -> &'static [&'static str] {
    match format {
        Format::Jpeg => &["image/jpeg"],
        Format::Png => &["image/png"],
        Format::Webp => &["image/webp"],
        Format::Pdf => &["application/pdf"],
        Format::Tiff => &["image/tiff"],
        Format::Gif => &["image/gif"],
        Format::Heif => &["image/heif", "image/heic"],
        Format::Avif => &["image/avif"],
        Format::Docx => {
            &["application/vnd.openxmlformats-officedocument.wordprocessingml.document"]
        }
        Format::Xlsx => &["application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"],
        Format::Pptx => {
            &["application/vnd.openxmlformats-officedocument.presentationml.presentation"]
        }
        Format::Odt => &["application/vnd.oasis.opendocument.text"],
        Format::Ods => &["application/vnd.oasis.opendocument.spreadsheet"],
        Format::Odp => &["application/vnd.oasis.opendocument.presentation"],
        Format::Svg => &["image/svg+xml"],
        Format::Jxl => &["image/jxl"],
        Format::Flac => &["audio/flac", "audio/x-flac"],
        Format::Wav => &["audio/x-wav", "audio/wav", "audio/vnd.wave"],
        Format::Mp3 => &["audio/mpeg"],
        Format::Ogg => &["audio/x-vorbis+ogg", "audio/ogg"],
        Format::Opus => &["audio/x-opus+ogg", "audio/ogg"],
        Format::OggFlac => &["audio/x-flac+ogg", "audio/ogg"],
        Format::Mp4 => &["video/mp4"],
        Format::M4a => &["audio/mp4", "audio/x-m4b"],
        // `Format` is non-exhaustive; the corpus test catches a format left here.
        _ => &[],
    }
}

fn mime_list(folders: bool) -> String {
    let mut all: Vec<&str> = Vec::new();
    for mime in FORMATS.iter().flat_map(|f| mime_types(*f)) {
        if !all.contains(mime) {
            all.push(mime);
        }
    }
    if folders {
        all.push("inode/directory");
    }
    all.iter().flat_map(|m| [*m, ";"]).collect()
}

/// One file to write, relative to the directory the platform keeps entries in.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    /// Relative to that directory.
    pub path: &'static str,
    /// The file's bytes.
    pub contents: Vec<u8>,
    /// Dolphin ignores a service menu that is not executable.
    pub executable: bool,
}

/// Why no entries can be written. The text is the GUI's.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Refusal(pub String);

/// Every path either platform writes, so Remove also finds an entry for a file manager since
/// uninstalled.
pub const LINUX_PATHS: [&str; 4] = [
    "applications/strypt.desktop",
    "icons/hicolor/256x256/apps/strypt.png",
    "nemo/actions/strypt.nemo_action",
    "kio/servicemenus/strypt.desktop",
];
/// The Send To shortcut, relative to the Send To folder.
pub const WINDOWS_PATHS: [&str; 1] = ["strypt.lnk"];

const LABEL: &str = "Remove metadata with strypt";

/// The app's path as an entry can carry it: absolute, and free of every character that a desktop
/// entry's `Exec` quoting, a Nemo list or a field code would reinterpret.
///
/// # Errors
///
/// A relative path, or one holding such a character.
pub fn plain(app: &Path) -> Result<&str, Refusal> {
    let text = app
        .to_str()
        .filter(|_| app.is_absolute())
        .ok_or_else(|| Refusal("strypt could not find its own location.".into()))?;
    if let Some(c) = text
        .chars()
        .find(|c| c.is_control() || "\"`$\\%;".contains(*c))
    {
        return Err(Refusal(format!(
            "strypt's location contains {c:?}, which a menu entry cannot carry. Move strypt to a \
             folder whose path has none of \" ` $ \\ % ;"
        )));
    }
    Ok(text)
}

/// The Linux entries under `$XDG_DATA_HOME`: Open With for every file manager, and a Nemo action
/// and Dolphin service menu for those found (ADR-0064 decision 5).
///
/// # Errors
///
/// Whatever [`plain`] refuses.
pub fn linux(app: &Path, nemo: bool, dolphin: bool) -> Result<Vec<Entry>, Refusal> {
    let app = plain(app)?;
    let files = mime_list(false);
    let with_folders = mime_list(true);
    let text = |path, contents: String, executable| Entry {
        path,
        contents: contents.into_bytes(),
        executable,
    };
    // TryExec drops the entry from Open With once the app is gone.
    let mut entries = vec![text(
        LINUX_PATHS[0],
        format!(
            "[Desktop Entry]\nType=Application\nName=strypt\nGenericName=Metadata remover\n\
             Comment=Save copies of files without their hidden metadata\nExec=\"{app}\" %F\n\
             TryExec={app}\nIcon=strypt\nTerminal=false\nCategories=Utility;\nMimeType={files}\n"
        ),
        false,
    )];
    if let Ok(png) = strypt_mark::png(256) {
        entries.push(Entry {
            path: LINUX_PATHS[1],
            contents: png,
            executable: false,
        });
    }
    if nemo {
        entries.push(text(
            LINUX_PATHS[2],
            format!(
                "[Nemo Action]\nName={LABEL}\nComment=Open the selection in strypt\n\
                 Exec=\"{app}\" %F\nIcon-Name=strypt\nSelection=notnone\n\
                 Mimetypes={with_folders}\nDependencies={app};\n"
            ),
            false,
        ));
    }
    if dolphin {
        entries.push(text(
            LINUX_PATHS[3],
            format!(
                "[Desktop Entry]\nType=Service\nMimeType={with_folders}\nActions=strypt;\n\
                 TryExec={app}\nX-KDE-Priority=TopLevel\n\n[Desktop Action strypt]\n\
                 Name={LABEL}\nIcon=strypt\nExec=\"{app}\" %F\n"
            ),
            true,
        ));
    }
    Ok(entries)
}

/// The Send To shortcut, one process for any number of files (ADR-0064's Windows spike).
///
/// # Errors
///
/// A path not on a lettered drive, or one outside ASCII, which the shortcut's item ID list
/// carries in the system code page.
pub fn windows(app: &Path) -> Result<Vec<Entry>, Refusal> {
    let text = app
        .to_str()
        .ok_or_else(|| Refusal("strypt could not find its own location.".into()))?;
    let text = text.strip_prefix(r"\\?\").unwrap_or(text);
    let lettered = matches!(text.as_bytes(), [d, b':', b'\\', ..] if d.is_ascii_alphabetic());
    if !lettered {
        return Err(Refusal(
            "strypt must be on a lettered drive, such as C:\\, to add a Send To entry.".into(),
        ));
    }
    if !text.is_ascii() {
        return Err(Refusal(
            "strypt's location has a letter outside plain English, which its Send To entry \
             cannot carry yet. Move strypt to a folder such as C:\\strypt."
                .into(),
        ));
    }
    let contents =
        shortcut(text).ok_or_else(|| Refusal("strypt's location is too long.".into()))?;
    Ok(vec![Entry {
        path: WINDOWS_PATHS[0],
        contents,
        executable: false,
    }])
}

fn utf16z(s: &str) -> Vec<u8> {
    s.encode_utf16()
        .chain([0])
        .flat_map(u16::to_le_bytes)
        .collect()
}

fn push_item(list: &mut Vec<u8>, data: &[u8]) -> Option<()> {
    list.extend(u16::try_from(data.len() + 2).ok()?.to_le_bytes());
    list.extend(data);
    Some(())
}

/// A shell link to `target`, an ASCII path on a lettered drive, with its icon (MS-SHLLINK).
/// Explorer leaves a link out of Send To unless its item ID list resolves, so the list is
/// Computer, the drive, then the rest of the path as one file item, as `mslink` writes it.
/// `LinkInfo` carries the path too. `None` if a length overflows its field.
fn shortcut(target: &str) -> Option<Vec<u8>> {
    const HAS_ID_LIST: u32 = 0x01;
    const HAS_LINK_INFO: u32 = 0x02;
    const HAS_ICON_LOCATION: u32 = 0x40;
    const IS_UNICODE: u32 = 0x80;
    const SW_SHOWNORMAL: u32 = 1;
    const DRIVE_FIXED: u32 = 3;
    let u32_of = |n: usize| u32::try_from(n).ok();
    let (drive, rest) = target.split_at_checked(3)?;

    let mut link = Vec::new();
    link.extend(0x4C_u32.to_le_bytes());
    // CLSID 00021401-0000-0000-C000-000000000046
    link.extend([1, 0x14, 2, 0, 0, 0, 0, 0, 0xC0, 0, 0, 0, 0, 0, 0, 0x46]);
    link.extend((HAS_ID_LIST | HAS_LINK_INFO | HAS_ICON_LOCATION | IS_UNICODE).to_le_bytes());
    link.extend([0; 4 + 24 + 4 + 4]); // attributes, three times, size, icon index
    link.extend(SW_SHOWNORMAL.to_le_bytes());
    link.extend([0; 2 + 2 + 4 + 4]); // hot key, reserved

    let mut ids = Vec::new();
    // Computer, {20D04FE0-3AEA-1069-A2D8-08002B30309D}
    push_item(
        &mut ids,
        &[
            0x1F, 0x50, 0xE0, 0x4F, 0xD0, 0x20, 0xEA, 0x3A, 0x69, 0x10, 0xA2, 0xD8, 0x08, 0x00,
            0x2B, 0x30, 0x30, 0x9D,
        ],
    )?;
    let mut root = vec![0x2F];
    root.extend(drive.as_bytes());
    root.resize(23, 0);
    push_item(&mut ids, &root)?;
    // Type, a pad byte, then size, date and attributes left zero.
    let mut file = vec![0x32; 1];
    file.extend([0; 11]);
    file.extend(rest.as_bytes());
    file.push(0);
    push_item(&mut ids, &file)?;
    link.extend(u16::try_from(ids.len() + 2).ok()?.to_le_bytes());
    link.extend(ids);
    link.extend([0, 0]);

    // LinkInfo with a 0x24-byte header, so the Unicode path offsets are present.
    let ansi: Vec<u8> = target.bytes().chain([0]).collect();
    let volume: Vec<u8> = [17_u32, DRIVE_FIXED, 0, 0x10]
        .iter()
        .flat_map(|n| n.to_le_bytes())
        .chain([0])
        .collect();
    let wide = utf16z(target);
    let volume_at = 0x24;
    let ansi_at = volume_at + volume.len();
    let suffix_at = ansi_at + ansi.len();
    let wide_at = suffix_at + 1;
    let wide_suffix_at = wide_at + wide.len();
    let size = wide_suffix_at + 2;
    for field in [
        size,
        0x24,
        1,
        volume_at,
        ansi_at,
        0,
        suffix_at,
        wide_at,
        wide_suffix_at,
    ] {
        link.extend(u32_of(field)?.to_le_bytes());
    }
    link.extend(volume);
    link.extend(ansi);
    link.push(0);
    link.extend(wide);
    link.extend([0, 0]);

    let units: Vec<u16> = target.encode_utf16().collect();
    link.extend(u16::try_from(units.len()).ok()?.to_le_bytes());
    link.extend(units.iter().flat_map(|u| u.to_le_bytes()));
    link.extend([0; 4]); // terminal extra-data block
    Some(link)
}

/// Whether the entries in `dir` are absent, the ones `entries` would write, or another copy's.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum State {
    /// No entry is present.
    Absent,
    /// The entries open this copy of the app.
    Current,
    /// Some entry is missing or opens another copy, one since moved or replaced.
    Stale,
}

/// Compares the files in `dir` against `entries`; any of `all` present counts as installed.
#[must_use]
pub fn state(dir: &Path, all: &[&str], entries: &[Entry]) -> State {
    if !all.iter().any(|p| dir.join(p).exists()) {
        return State::Absent;
    }
    let current = entries
        .iter()
        .all(|e| std::fs::read(dir.join(e.path)).is_ok_and(|c| c == e.contents));
    let cached = !entries.iter().any(|e| e.path == LINUX_PATHS[0])
        || std::fs::read_to_string(dir.join(MIME_CACHE)).is_ok_and(|cache| {
            cache
                .lines()
                .any(|l| l.starts_with("image/jpeg=") && l.contains("strypt.desktop"))
        });
    if current && cached {
        State::Current
    } else {
        State::Stale
    }
}

/// Writes `entries` under `dir`, first removing every path in `all`. On failure nothing is left.
///
/// # Errors
///
/// The first write that failed.
pub fn install(dir: &Path, all: &[&str], entries: &[Entry]) -> io::Result<()> {
    remove(dir, all)?;
    let written = entries
        .iter()
        .try_for_each(|e| write(&dir.join(e.path), e))
        .and_then(|()| refresh_mime_cache(dir, all));
    if written.is_err() {
        let _ = remove(dir, all);
    }
    written
}

const MIME_CACHE: &str = "applications/mimeinfo.cache";

/// `GLib` takes Open With from this cache, not from the entries (seen on Ubuntu, ADR-0064), so it
/// is rebuilt from every entry in the folder, as `update-desktop-database` builds it.
fn refresh_mime_cache(dir: &Path, all: &[&str]) -> io::Result<()> {
    use std::fmt::Write as _;
    if !all.contains(&LINUX_PATHS[0]) {
        return Ok(());
    }
    let apps = dir.join("applications");
    let mut by_type = std::collections::BTreeMap::<String, Vec<String>>::new();
    collect_mime_types(&apps, "", &mut by_type)?;
    let mut cache = String::from("[MIME Cache]\n");
    for (mime, ids) in by_type {
        let _ = writeln!(cache, "{mime}={};", ids.join(";"));
    }
    std::fs::create_dir_all(&apps)?;
    std::fs::write(apps.join("mimeinfo.cache"), cache)
}

/// A subfolder's entries take its name as a prefix: `kde/a.desktop` is `kde-a.desktop`.
fn collect_mime_types(
    dir: &Path,
    prefix: &str,
    by_type: &mut std::collections::BTreeMap<String, Vec<String>>,
) -> io::Result<()> {
    let mut names: Vec<_> = match std::fs::read_dir(dir) {
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(()),
        listing => listing?.filter_map(Result::ok).map(|e| e.path()).collect(),
    };
    names.sort();
    for path in names {
        let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
            continue;
        };
        if path.is_dir() {
            collect_mime_types(&path, &format!("{prefix}{name}-"), by_type)?;
        } else if name.ends_with(".desktop")
            && let Ok(text) = std::fs::read_to_string(&path)
        {
            for mime in desktop_mime_types(&text) {
                by_type
                    .entry(mime.to_owned())
                    .or_default()
                    .push(format!("{prefix}{name}"));
            }
        }
    }
    Ok(())
}

/// The `MimeType` list of a desktop entry's main group, or none if the entry is hidden.
fn desktop_mime_types(text: &str) -> Vec<&str> {
    let (mut main, mut hidden, mut types) = (false, false, Vec::new());
    for line in text.lines().map(str::trim) {
        if line.starts_with('[') {
            main = line == "[Desktop Entry]";
        } else if main && let Some((key, value)) = line.split_once('=') {
            match key.trim() {
                "MimeType" => {
                    types = value
                        .split(';')
                        .map(str::trim)
                        .filter(|m| !m.is_empty())
                        .collect();
                }
                "Hidden" => hidden = value.trim() == "true",
                _ => {}
            }
        }
    }
    if hidden { Vec::new() } else { types }
}

fn write(path: &Path, entry: &Entry) -> io::Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(path, &entry.contents)?;
    #[cfg(unix)]
    if entry.executable {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755))?;
    }
    Ok(())
}

/// Removes every path in `all` under `dir`; one already gone is not an error.
///
/// # Errors
///
/// The first removal that failed for another reason.
pub fn remove(dir: &Path, all: &[&str]) -> io::Result<()> {
    for path in all {
        match std::fs::remove_file(dir.join(path)) {
            Err(e) if e.kind() != io::ErrorKind::NotFound => return Err(e),
            _ => {}
        }
    }
    refresh_mime_cache(dir, all)
}

/// Whether `name` is an executable on `PATH`.
#[must_use]
pub fn on_path(name: &str) -> bool {
    std::env::var_os("PATH")
        .is_some_and(|paths| std::env::split_paths(&paths).any(|dir| dir.join(name).is_file()))
}

/// Where this platform keeps entries, and what to write there for this copy of the app.
///
/// # Errors
///
/// No home directory, an unusable app path, or a platform without an entry.
pub fn here() -> Result<(PathBuf, &'static [&'static str], Vec<Entry>), Refusal> {
    let lost = || Refusal("strypt could not find its own location.".into());
    let var = |name| {
        std::env::var_os(name)
            .filter(|v| !v.is_empty())
            .map(PathBuf::from)
    };
    if cfg!(target_os = "linux") {
        // An AppImage runs from a temporary mount; `$APPIMAGE` is the file the user keeps.
        let app = match var("APPIMAGE") {
            Some(image) => image,
            None if var("APPDIR").is_some() => return Err(lost()),
            None => std::env::current_exe().map_err(|_| lost())?,
        };
        let data = var("XDG_DATA_HOME")
            .filter(|d| d.is_absolute())
            .or_else(|| var("HOME").map(|h| h.join(".local/share")))
            .ok_or_else(|| Refusal("strypt could not find your home folder.".into()))?;
        let entries = linux(&app, on_path("nemo"), on_path("dolphin"))?;
        Ok((data, &LINUX_PATHS, entries))
    } else if cfg!(windows) {
        let send_to = var("APPDATA")
            .map(|d| d.join(r"Microsoft\Windows\SendTo"))
            .ok_or_else(|| Refusal("strypt could not find your Send To folder.".into()))?;
        let app = std::env::current_exe().map_err(|_| lost())?;
        Ok((send_to, &WINDOWS_PATHS, windows(&app)?))
    } else {
        Err(Refusal("This system has no menu entry yet.".into()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scratch(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("strypt-menu-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        dir
    }

    /// Absolute on the host: Windows needs a drive for `is_absolute`.
    fn abs(path: &str) -> PathBuf {
        PathBuf::from(if cfg!(windows) {
            format!("C:{path}")
        } else {
            path.into()
        })
    }

    #[test]
    fn an_entry_refuses_a_path_its_quoting_would_change() {
        assert!(plain(&abs("/home/u/My Apps/strypt.AppImage")).is_ok());
        for bad in ["/a\"b", "/a`b", "/a$b", "/a\\b", "/a%b", "/a;b", "/a\nb"] {
            assert!(plain(&abs(bad)).is_err(), "{bad:?}");
        }
        assert!(plain(Path::new("rel/strypt")).is_err());
    }

    #[test]
    fn linux_entries_name_the_app_and_only_the_found_file_managers() {
        let app = abs("/home/u/Apps/strypt 0.2.AppImage");
        let text = app.to_str().unwrap();
        let only = linux(&app, false, false).unwrap();
        assert_eq!(only.len(), 2);
        let desktop = String::from_utf8(only[0].contents.clone()).unwrap();
        assert!(desktop.contains(&format!("Exec=\"{text}\" %F\n")));
        assert!(desktop.contains(&format!("TryExec={text}\n")));
        assert!(
            !desktop.contains("inode/directory"),
            "never a folder's default"
        );

        let all = linux(&app, true, true).unwrap();
        let nemo = String::from_utf8(all[2].contents.clone()).unwrap();
        assert!(nemo.contains(&format!("Dependencies={text};\n")));
        assert!(nemo.contains("inode/directory;"));
        assert!(all[3].executable && all[3].path == LINUX_PATHS[3]);
    }

    #[test]
    fn every_corpus_format_has_a_mime_type() {
        let corpus = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../corpus");
        let walk = strypt_core::walk(&corpus);
        let mut seen = 0;
        for file in &walk.files {
            let Ok(data) = std::fs::read(file) else {
                continue;
            };
            let Ok(format) = strypt_core::detect(&data) else {
                continue;
            };
            assert!(
                FORMATS.contains(&format) && !mime_types(format).is_empty(),
                "{format:?}"
            );
            seen += 1;
        }
        assert!(seen > 0);
        assert_eq!(mime_list(false).matches(';').count(), 30);
    }

    #[test]
    fn a_shortcut_carries_the_path_in_its_id_list_link_info_and_icon() {
        let target = r"C:\Users\zoe\Downloads\strypt-gui.exe";
        let lnk = shortcut(target).unwrap();
        assert_eq!(lnk[..4], [0x4C, 0, 0, 0]);
        let header_flags = u32::from_le_bytes(lnk[20..24].try_into().unwrap());
        assert_eq!(header_flags, 0xC3);

        let ids_size = usize::from(u16::from_le_bytes([lnk[76], lnk[77]]));
        let ids = &lnk[78..78 + ids_size];
        let mut items = Vec::new();
        let mut rest = ids;
        while let [lo, hi, ..] = rest {
            let len = usize::from(u16::from_le_bytes([*lo, *hi]));
            if len == 0 {
                break;
            }
            items.push(&rest[2..len]);
            rest = &rest[len..];
        }
        assert_eq!(rest, [0, 0], "terminated");
        assert_eq!(items.len(), 3);
        assert_eq!(items[0][..2], [0x1F, 0x50]);
        assert!(items[1].starts_with(b"/C:\\\0"));
        assert_eq!(items[2][0], 0x32);
        assert_eq!(items[2][12..], *b"Users\\zoe\\Downloads\\strypt-gui.exe\0");

        let info = &lnk[78 + ids_size..];
        let info_size = u32::from_le_bytes(info[..4].try_into().unwrap()) as usize;
        let at = |i: usize| u32::from_le_bytes(info[i..i + 4].try_into().unwrap()) as usize;
        assert!(info[at(16)..].starts_with(target.as_bytes()));
        assert!(info[at(28)..].starts_with(&utf16z(target)));
        assert_eq!(at(32) + 2, info_size);
        let strings = &info[info_size..];
        let chars = usize::from(u16::from_le_bytes([strings[0], strings[1]]));
        assert_eq!(chars, target.encode_utf16().count());
        assert_eq!(strings[2..2 + chars * 2], utf16z(target)[..chars * 2]);
        assert_eq!(strings[2 + chars * 2..], [0; 4]);
    }

    #[test]
    fn send_to_refuses_what_its_id_list_cannot_carry() {
        assert!(windows(Path::new(r"C:\Apps\strypt-gui.exe")).is_ok());
        assert!(windows(Path::new(r"\\?\D:\strypt-gui.exe")).is_ok());
        for bad in [
            r"\\server\share\strypt-gui.exe",
            r"C:\Users\Zoë\strypt-gui.exe",
            "rel",
        ] {
            assert!(windows(Path::new(bad)).is_err(), "{bad}");
        }
    }

    #[test]
    fn the_mime_cache_lists_every_entry_and_drops_ours_on_remove() {
        let dir = scratch("cache");
        let apps = dir.join("applications");
        std::fs::create_dir_all(apps.join("kde")).unwrap();
        let other = "[Desktop Entry]\nName=Viewer\nMimeType=image/jpeg;image/x-raw;\n";
        std::fs::write(apps.join("viewer.desktop"), other).unwrap();
        std::fs::write(apps.join("kde/k.desktop"), other).unwrap();
        let gone = "[Desktop Entry]\nHidden=true\nMimeType=image/jpeg;\n";
        std::fs::write(apps.join("gone.desktop"), gone).unwrap();

        let here = linux(&abs("/opt/strypt"), false, false).unwrap();
        install(&dir, &LINUX_PATHS, &here).unwrap();
        let cache = std::fs::read_to_string(dir.join(MIME_CACHE)).unwrap();
        assert!(cache.starts_with("[MIME Cache]\n"));
        assert!(cache.contains("\nimage/jpeg=kde-k.desktop;strypt.desktop;viewer.desktop;\n"));
        assert!(cache.contains("\nimage/x-raw=kde-k.desktop;viewer.desktop;\n"));
        assert_eq!(state(&dir, &LINUX_PATHS, &here), State::Current);

        // Another tool rebuilt the cache without us: the entries no longer show.
        std::fs::write(dir.join(MIME_CACHE), "[MIME Cache]\n").unwrap();
        assert_eq!(state(&dir, &LINUX_PATHS, &here), State::Stale);

        remove(&dir, &LINUX_PATHS).unwrap();
        let cache = std::fs::read_to_string(dir.join(MIME_CACHE)).unwrap();
        assert!(!cache.contains("strypt"));
        assert!(cache.contains("\nimage/jpeg=kde-k.desktop;viewer.desktop;\n"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn install_writes_state_tells_and_remove_clears() {
        let dir = scratch("install");
        let here = linux(&abs("/opt/strypt"), true, true).unwrap();
        let moved = linux(&abs("/opt/moved/strypt"), true, true).unwrap();
        assert_eq!(state(&dir, &LINUX_PATHS, &here), State::Absent);
        install(&dir, &LINUX_PATHS, &here).unwrap();
        assert_eq!(state(&dir, &LINUX_PATHS, &here), State::Current);
        assert_eq!(state(&dir, &LINUX_PATHS, &moved), State::Stale);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            let mode = |p| std::fs::metadata(dir.join(p)).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode(LINUX_PATHS[3]), 0o755);
        }
        // A reinstall without Nemo drops its action rather than leaving the old one.
        install(&dir, &LINUX_PATHS, &moved[..2]).unwrap();
        assert!(!dir.join(LINUX_PATHS[2]).exists());
        remove(&dir, &LINUX_PATHS).unwrap();
        assert_eq!(state(&dir, &LINUX_PATHS, &here), State::Absent);
        remove(&dir, &LINUX_PATHS).unwrap();
        let _ = std::fs::remove_dir_all(&dir);
    }
}
