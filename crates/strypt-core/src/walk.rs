//! Expanding a folder into the files a batch processes, shared so every front-end descends alike.
//!
//! Nothing is passed over silently: each entry is a file to process or a [`Skipped`] with its
//! reason, because a batch that quietly omits a file lets the user believe it was cleaned.

use std::path::{Path, PathBuf};

/// Why [`walk`] passed over an entry.
#[derive(Debug)]
#[non_exhaustive]
pub enum Skip {
    /// Not followed: a link could redirect a batch, and an in-place strip, outside the folder
    /// the user named.
    SymbolicLink,
    /// A pipe, socket or device. Reading a pipe waits for a writer that may never come.
    NotAFile,
    /// The folder or entry could not be read.
    Unreadable(std::io::Error),
}

/// One entry [`walk`] did not return as a file.
#[derive(Debug)]
pub struct Skipped {
    /// The entry, or the folder whose listing failed.
    pub path: PathBuf,
    /// Why.
    pub reason: Skip,
}

/// What a folder holds.
#[derive(Debug, Default)]
pub struct Walk {
    /// Regular files, sorted, so a batch's order and outcome do not depend on the filesystem's.
    pub files: Vec<PathBuf>,
    /// Everything else, sorted by path.
    pub skipped: Vec<Skipped>,
    /// Folders listed, the root included.
    pub folders: usize,
}

/// Every regular file under `root`, at any depth, never following a symbolic link.
///
/// Iterative, so a deep tree cannot exhaust the stack.
#[must_use]
pub fn walk(root: &Path) -> Walk {
    let mut walk = Walk::default();
    let mut pending = vec![root.to_path_buf()];
    while let Some(dir) = pending.pop() {
        let entries = match std::fs::read_dir(&dir) {
            Ok(entries) => entries,
            Err(error) => {
                walk.skip(dir, Skip::Unreadable(error));
                continue;
            }
        };
        walk.folders = walk.folders.saturating_add(1);
        for entry in entries {
            let entry = match entry {
                Ok(entry) => entry,
                Err(error) => {
                    walk.skip(dir.clone(), Skip::Unreadable(error));
                    continue;
                }
            };
            let path = entry.path();
            // `DirEntry::file_type` does not follow links, so a link is seen as one.
            match entry.file_type() {
                Ok(kind) if kind.is_symlink() => walk.skip(path, Skip::SymbolicLink),
                Ok(kind) if kind.is_dir() => pending.push(path),
                Ok(kind) if kind.is_file() => walk.files.push(path),
                Ok(_) => walk.skip(path, Skip::NotAFile),
                Err(error) => walk.skip(path, Skip::Unreadable(error)),
            }
        }
    }
    walk.files.sort();
    walk.skipped.sort_by(|a, b| a.path.cmp(&b.path));
    walk
}

impl Walk {
    fn skip(&mut self, path: PathBuf, reason: Skip) {
        self.skipped.push(Skipped { path, reason });
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    struct Scratch(PathBuf);

    impl Scratch {
        fn new(tag: &str) -> Self {
            let path = std::env::temp_dir().join(format!(
                "strypt-walk-{tag}-{}-{:?}",
                std::process::id(),
                std::thread::current().id()
            ));
            let _ = std::fs::remove_dir_all(&path);
            std::fs::create_dir_all(&path).unwrap();
            Self(path)
        }
        fn file(&self, rel: &str) -> PathBuf {
            let path = self.0.join(rel);
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(&path, b"x").unwrap();
            path
        }
    }

    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn nested_files_are_found_sorted_and_folders_counted() {
        let dir = Scratch::new("nested");
        let deep = dir.file("b/c/d.jpg");
        let top = dir.file("a.jpg");
        let mid = dir.file("b/e.png");
        std::fs::create_dir(dir.0.join("empty")).unwrap();
        let got = walk(&dir.0);
        assert_eq!(got.files, [top, deep, mid]);
        assert_eq!(got.folders, 4);
        assert!(got.skipped.is_empty());
    }

    #[test]
    fn a_missing_root_is_reported_not_ignored() {
        let got = walk(Path::new("/nonexistent/strypt/walk"));
        assert!(got.files.is_empty());
        assert!(matches!(
            got.skipped.as_slice(),
            [Skipped {
                reason: Skip::Unreadable(_),
                ..
            }]
        ));
        assert_eq!(got.folders, 0);
    }

    #[cfg(unix)]
    #[test]
    fn a_link_is_reported_and_not_followed() {
        let dir = Scratch::new("link");
        let outside = Scratch::new("link-target");
        outside.file("secret.jpg");
        let link = dir.0.join("link");
        std::os::unix::fs::symlink(&outside.0, &link).unwrap();
        let got = walk(&dir.0);
        assert!(got.files.is_empty());
        assert!(matches!(
            got.skipped.as_slice(),
            [Skipped { path, reason: Skip::SymbolicLink }] if *path == link
        ));
    }

    #[cfg(unix)]
    #[test]
    fn a_pipe_is_skipped_rather_than_read() {
        let dir = Scratch::new("fifo");
        let fifo = dir.0.join("pipe");
        let made = std::process::Command::new("mkfifo")
            .arg(&fifo)
            .status()
            .unwrap();
        assert!(made.success());
        let got = walk(&dir.0);
        assert!(got.files.is_empty());
        assert!(matches!(
            got.skipped.as_slice(),
            [Skipped { path, reason: Skip::NotAFile }] if *path == fifo
        ));
    }

    #[cfg(unix)]
    #[test]
    fn an_unreadable_folder_is_reported_and_its_siblings_still_found() {
        use std::os::unix::fs::PermissionsExt as _;
        let dir = Scratch::new("locked");
        let kept = dir.file("open/a.jpg");
        dir.file("locked/b.jpg");
        let locked = dir.0.join("locked");
        std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o000)).unwrap();
        // Root reads a folder whatever its mode, so there is nothing to observe.
        if std::fs::read_dir(&locked).is_ok() {
            std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o700)).unwrap();
            return;
        }
        let got = walk(&dir.0);
        std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o700)).unwrap();
        assert_eq!(got.files, [kept]);
        assert!(matches!(
            got.skipped.as_slice(),
            [Skipped { path, reason: Skip::Unreadable(_) }] if *path == locked
        ));
    }
}
