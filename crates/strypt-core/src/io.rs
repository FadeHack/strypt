//! Bounded reading and atomic writing.
//!
//! This module holds the two file operations that can hurt a user independently of any
//! parser bug: reading an input large enough to exhaust memory, and writing an output in a
//! way that can leave a half-sanitised file where the original was.
//!
//! # Where temporary files go, and why it matters
//!
//! The temporary file is created **in the destination's own directory**, never in `TMPDIR`.
//! Two reasons, and the second is the important one:
//!
//! 1. `rename` is only atomic within a filesystem. A temp file on a different mount turns the
//!    final step into a copy, which is precisely the non-atomic behaviour being avoided.
//! 2. `TMPDIR` is somewhere else on the disk. Writing a copy of a sensitive document to
//!    somewhere the user did not choose — and did not know to clean up — is a leak in its own
//!    right, and on an amnesic system such as Tails it may be the one location that is not
//!    what the user assumed it was (`docs/ARCHITECTURE.md` §8).
//!
//! The temporary file is removed on every failure path.

use std::fs::File;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use crate::error::{IoAction, Result, StryptError};

/// Resource ceilings applied before and during parsing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct Limits {
    /// Largest input strypt will read, in bytes.
    pub max_input_bytes: u64,
}

impl Limits {
    /// The default input ceiling: 512 MiB.
    ///
    /// Chosen to clear the largest files the Phase 1 formats plausibly produce — a
    /// high-resolution scanned PDF runs to a few hundred megabytes — while still refusing a
    /// file whose only purpose is to exhaust memory. It is a ceiling on the *input*; a PDF
    /// rewrite holds the parsed document as well, so peak usage is a multiple of this. That
    /// matters on the constrained, RAM-only systems this tool is aimed at, which is why the
    /// number is deliberately not "as much as will fit".
    ///
    /// Provisional: revisit with measured figures once the handlers exist (`docs/PRD.md` §9
    /// still carries estimates rather than measurements).
    pub const DEFAULT_MAX_INPUT_BYTES: u64 = 512 * 1024 * 1024;
}

impl Limits {
    /// Limits with a caller-chosen input ceiling.
    ///
    /// A constructor rather than a struct literal because this type is `#[non_exhaustive]`:
    /// new ceilings will be added, and a front-end built against an older version must keep
    /// compiling rather than silently missing one.
    #[must_use]
    pub const fn with_max_input_bytes(max_input_bytes: u64) -> Self {
        Self { max_input_bytes }
    }
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_input_bytes: Self::DEFAULT_MAX_INPUT_BYTES,
        }
    }
}

/// Read `path` into memory, refusing anything above `limits.max_input_bytes`.
///
/// The size is checked twice: once against the directory entry, so an oversized file is
/// refused without reading a byte of it, and again while reading, because the first answer
/// came from metadata that a hostile or merely unusual source can misreport — a growing file,
/// a named pipe, a synthetic filesystem. Trusting the first check alone would make the limit
/// advisory.
///
/// # Errors
///
/// [`StryptError::InputTooLarge`] if the file exceeds the limit; [`StryptError::Io`] if it
/// cannot be measured or read.
pub fn read_bounded(path: &Path, limits: Limits) -> Result<Vec<u8>> {
    let file = File::open(path).map_err(|source| StryptError::Io {
        action: IoAction::ReadingInput,
        source,
    })?;
    let declared = file
        .metadata()
        .map_err(|source| StryptError::Io {
            action: IoAction::MeasuringInput,
            source,
        })?
        .len();
    if declared > limits.max_input_bytes {
        return Err(StryptError::InputTooLarge {
            limit: limits.max_input_bytes,
            actual: Some(declared),
        });
    }
    read_bounded_from(file, limits, Some(declared))
}

/// Read a stream into memory under the same ceiling as [`read_bounded`].
///
/// `hint` pre-allocates when a trustworthy size is known. It is only ever a hint: the read
/// itself is what enforces the limit.
fn read_bounded_from<R: Read>(source: R, limits: Limits, hint: Option<u64>) -> Result<Vec<u8>> {
    // Read one byte past the ceiling. If that byte arrives, the source lied about its size
    // and the input is over the limit — a `take(limit)` alone would silently truncate, which
    // would hand a partial file to a handler and produce a report about content that was
    // never there.
    let probe = limits.max_input_bytes.saturating_add(1);
    let mut buffer = Vec::new();
    if let Some(hint) = hint {
        // Reserve only what the ceiling permits: `Vec::with_capacity(n_from_file)` driven by
        // an attacker-controlled number is itself the memory-exhaustion bug.
        let reserve = hint.min(limits.max_input_bytes);
        if let Ok(reserve) = usize::try_from(reserve) {
            buffer
                .try_reserve_exact(reserve)
                .map_err(|_| StryptError::InputTooLarge {
                    limit: limits.max_input_bytes,
                    actual: Some(hint),
                })?;
        }
    }
    let read = source
        .take(probe)
        .read_to_end(&mut buffer)
        .map_err(|source| StryptError::Io {
            action: IoAction::ReadingInput,
            source,
        })?;
    if u64::try_from(read).unwrap_or(u64::MAX) > limits.max_input_bytes {
        return Err(StryptError::InputTooLarge {
            limit: limits.max_input_bytes,
            actual: None,
        });
    }
    Ok(buffer)
}

/// What to do when the destination already exists.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Overwrite {
    /// Refuse. The default everywhere: overwriting the user's file is a decision only the
    /// user gets to make.
    Refuse,
    /// Replace it. Requires `--force` at the CLI.
    Replace,
}

/// Whether output permissions are tightened.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Permissions {
    /// Owner read/write only (`0600` on Unix).
    ///
    /// The default, and the decision recorded in ADR-0019. A stripped file is the *more*
    /// sensitive artefact of the pair, not the less: the user is about to publish it, and a
    /// world-readable copy sitting in a shared directory in the meantime is an avoidable
    /// exposure. Source timestamps and permissions are never copied onto the output —
    /// modification time is itself metadata, and preserving it would hand back a fact the
    /// user believed they had just removed.
    OwnerOnly,
    /// Whatever the platform's default for a new file is (the process umask on Unix).
    Inherit,
}

/// A file being written through a temporary alongside its destination, replaced by an atomic
/// rename only once the content is complete and durable.
///
/// Nothing partial ever appears at the destination path. If the process dies mid-write, the
/// destination is untouched and a `.strypt-*.tmp` file is left behind — visible, obviously
/// incomplete, and adjacent to where it belongs, rather than a silently truncated file the
/// user might publish.
#[derive(Debug)]
pub struct AtomicWrite {
    destination: PathBuf,
    temporary: PathBuf,
    file: Option<File>,
    permissions: Permissions,
}

impl AtomicWrite {
    /// Begin writing to `destination`.
    ///
    /// # Errors
    ///
    /// [`StryptError::Io`] if the destination exists and `overwrite` is
    /// [`Overwrite::Refuse`], or if the temporary file cannot be created.
    pub fn begin(
        destination: &Path,
        overwrite: Overwrite,
        permissions: Permissions,
    ) -> Result<Self> {
        // A pre-check, not a guarantee: another process can create the file between here and
        // the rename. Closing that race needs a link/rename dance that behaves differently on
        // every platform, and the realistic failure it would prevent — a user racing
        // themselves in two terminals — is not the threat this tool is defending against. The
        // honest position is that this is a courtesy check; the atomicity that matters is
        // that the destination is never *partially* written.
        if overwrite == Overwrite::Refuse && destination.exists() {
            return Err(StryptError::Io {
                action: IoAction::CreatingTemporary,
                source: std::io::Error::new(
                    std::io::ErrorKind::AlreadyExists,
                    "destination exists",
                ),
            });
        }

        let temporary = temporary_path_for(destination);
        let file = create_private(&temporary, permissions)?;
        Ok(Self {
            destination: destination.to_path_buf(),
            temporary,
            file: Some(file),
            permissions,
        })
    }

    /// Write bytes into the temporary file.
    ///
    /// # Errors
    ///
    /// [`StryptError::Io`] if the write fails.
    pub fn write_all(&mut self, bytes: &[u8]) -> Result<()> {
        let Some(file) = self.file.as_mut() else {
            return Err(StryptError::Io {
                action: IoAction::WritingOutput,
                source: std::io::Error::other("write after the file was finished"),
            });
        };
        file.write_all(bytes).map_err(|source| StryptError::Io {
            action: IoAction::WritingOutput,
            source,
        })
    }

    /// Flush, synchronise, and atomically move the temporary into place.
    ///
    /// The `sync_all` is not ceremony. Without it the rename can be durable while the
    /// content behind it is not, so a crash at the wrong moment leaves a file that exists,
    /// has the right name, and contains nothing — which for this tool means a user with a
    /// file they believe is a stripped copy of their document.
    ///
    /// # Errors
    ///
    /// [`StryptError::Io`] if syncing or renaming fails. The temporary is removed either way.
    pub fn commit(mut self) -> Result<()> {
        let Some(file) = self.file.take() else {
            return Err(StryptError::Io {
                action: IoAction::SyncingOutput,
                source: std::io::Error::other("already finished"),
            });
        };
        if let Err(source) = file.sync_all() {
            self.discard_temporary();
            return Err(StryptError::Io {
                action: IoAction::SyncingOutput,
                source,
            });
        }
        drop(file);

        if let Err(source) = std::fs::rename(&self.temporary, &self.destination) {
            self.discard_temporary();
            return Err(StryptError::Io {
                action: IoAction::ReplacingDestination,
                source,
            });
        }
        // Re-assert permissions after the rename. On Unix the mode travels with the inode so
        // this is a no-op, but stating it here keeps the guarantee in one place rather than
        // resting on a platform detail.
        apply_permissions(&self.destination, self.permissions)?;
        Ok(())
    }

    /// Abandon the write, leaving the destination untouched.
    pub fn abort(mut self) {
        self.file = None;
        self.discard_temporary();
    }

    fn discard_temporary(&mut self) {
        self.file = None;
        // A failure to clean up is not worth failing the operation over — the caller already
        // has a real error to report, and a leftover `.tmp` is visible rather than dangerous.
        let _ = std::fs::remove_file(&self.temporary);
    }
}

impl Drop for AtomicWrite {
    /// Removes the temporary if the writer was neither committed nor aborted.
    ///
    /// This is the path taken when a handler returns `Err` mid-write, which is the normal way
    /// a fail-closed handler gives up. Without it, every failed strip would litter a partial
    /// file next to the user's document.
    fn drop(&mut self) {
        if self.file.is_some() {
            self.discard_temporary();
        }
    }
}

/// Build a temporary path alongside `destination`.
///
/// Uniqueness comes from the process id, a monotonic counter, and the clock. This does not
/// need to be unpredictable — the file is created with `create_new`, so a collision is a
/// failed creation rather than a clobbered file — it only needs to avoid colliding with
/// strypt's own concurrent writes. That is also why no random-number dependency is pulled in
/// for it (ADR-0008).
fn temporary_path_for(destination: &Path) -> PathBuf {
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let nonce = COUNTER.fetch_add(1, Ordering::Relaxed);
    let clock: u32 = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.subsec_nanos());
    let name = format!(".strypt-{}-{clock}-{nonce}.tmp", std::process::id());
    destination.parent().unwrap_or(Path::new(".")).join(name)
}

/// Create a new file, applying restrictive permissions at creation time on Unix.
///
/// Setting the mode in the open call rather than afterwards closes the window in which the
/// file exists with the umask's permissions — a window another local process can read
/// through, and one that is entirely avoidable.
fn create_private(path: &Path, permissions: Permissions) -> Result<File> {
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);

    #[cfg(unix)]
    if permissions == Permissions::OwnerOnly {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }

    let file = options.open(path).map_err(|source| StryptError::Io {
        action: IoAction::CreatingTemporary,
        source,
    })?;

    // On Windows the ACL model has no umask equivalent and the new file inherits the parent
    // directory's ACL. strypt does not currently narrow that, so `Permissions::OwnerOnly` is
    // weaker there than on Unix. Recorded as a known limitation rather than papered over
    // (ADR-0019); Phase 3's platform validation is where it gets addressed.
    let _ = permissions;
    Ok(file)
}

/// Apply permissions to an existing path. A no-op off Unix.
fn apply_permissions(path: &Path, permissions: Permissions) -> Result<()> {
    #[cfg(unix)]
    if permissions == Permissions::OwnerOnly {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).map_err(
            |source| StryptError::Io {
                action: IoAction::SettingPermissions,
                source,
            },
        )?;
    }
    let _ = (path, permissions);
    Ok(())
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    /// A scratch directory that removes itself, so tests never depend on an external crate
    /// or leave files behind.
    struct Scratch(PathBuf);

    impl Scratch {
        fn new(tag: &str) -> Self {
            let path = std::env::temp_dir().join(format!(
                "strypt-test-{tag}-{}-{:?}",
                std::process::id(),
                std::thread::current().id()
            ));
            std::fs::create_dir_all(&path).unwrap();
            Self(path)
        }
        fn join(&self, name: &str) -> PathBuf {
            self.0.join(name)
        }
    }

    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn a_file_over_the_limit_is_refused_not_truncated() {
        let dir = Scratch::new("limit");
        let path = dir.join("big.bin");
        std::fs::write(&path, vec![0u8; 4096]).unwrap();

        let err = read_bounded(
            &path,
            Limits {
                max_input_bytes: 1024,
            },
        )
        .unwrap_err();
        assert!(
            matches!(
                err,
                StryptError::InputTooLarge {
                    limit: 1024,
                    actual: Some(4096)
                }
            ),
            "got {err:?}"
        );
    }

    #[test]
    fn a_lying_size_hint_cannot_get_past_the_ceiling() {
        // Models a source whose metadata understates its real length. Truncating silently
        // here would hand a partial file to a handler, which would then report confidently on
        // content that was never examined.
        let data = vec![0u8; 4096];
        let err = read_bounded_from(
            data.as_slice(),
            Limits {
                max_input_bytes: 1024,
            },
            Some(16),
        )
        .unwrap_err();
        assert!(
            matches!(err, StryptError::InputTooLarge { .. }),
            "got {err:?}"
        );
    }

    #[test]
    fn a_file_exactly_at_the_limit_is_accepted() {
        let dir = Scratch::new("exact");
        let path = dir.join("exact.bin");
        std::fs::write(&path, vec![7u8; 1024]).unwrap();
        let got = read_bounded(
            &path,
            Limits {
                max_input_bytes: 1024,
            },
        )
        .unwrap();
        assert_eq!(got.len(), 1024);
    }

    #[test]
    fn nothing_appears_at_the_destination_until_commit() {
        let dir = Scratch::new("atomic");
        let dest = dir.join("out.bin");

        let mut w = AtomicWrite::begin(&dest, Overwrite::Refuse, Permissions::OwnerOnly).unwrap();
        w.write_all(b"partial").unwrap();
        assert!(
            !dest.exists(),
            "a half-written file must never be visible at the destination path"
        );
        w.commit().unwrap();
        assert_eq!(std::fs::read(&dest).unwrap(), b"partial");
    }

    #[test]
    fn an_abandoned_write_leaves_no_temporary_behind() {
        let dir = Scratch::new("abort");
        let dest = dir.join("out.bin");

        let mut w = AtomicWrite::begin(&dest, Overwrite::Refuse, Permissions::OwnerOnly).unwrap();
        w.write_all(b"doomed").unwrap();
        w.abort();

        assert!(!dest.exists());
        let leftovers: Vec<_> = std::fs::read_dir(&dir.0)
            .unwrap()
            .filter_map(std::result::Result::ok)
            .filter(|e| e.file_name().to_string_lossy().starts_with(".strypt-"))
            .collect();
        assert!(leftovers.is_empty(), "temporary files were left behind");
    }

    #[test]
    fn dropping_a_writer_mid_failure_cleans_up() {
        // The path a fail-closed handler takes when it gives up part-way through.
        let dir = Scratch::new("drop");
        let dest = dir.join("out.bin");
        {
            let mut w =
                AtomicWrite::begin(&dest, Overwrite::Refuse, Permissions::OwnerOnly).unwrap();
            w.write_all(b"incomplete").unwrap();
        }
        assert!(!dest.exists());
        let count = std::fs::read_dir(&dir.0).unwrap().count();
        assert_eq!(
            count, 0,
            "the temporary should have been dropped with the writer"
        );
    }

    #[test]
    fn an_existing_destination_is_refused_by_default() {
        let dir = Scratch::new("refuse");
        let dest = dir.join("out.bin");
        std::fs::write(&dest, b"the user's file").unwrap();

        let err = AtomicWrite::begin(&dest, Overwrite::Refuse, Permissions::OwnerOnly).unwrap_err();
        assert!(matches!(err, StryptError::Io { .. }));
        assert_eq!(
            std::fs::read(&dest).unwrap(),
            b"the user's file",
            "the existing file must be untouched"
        );
    }

    #[test]
    fn replace_is_available_when_the_caller_asks_for_it() {
        let dir = Scratch::new("replace");
        let dest = dir.join("out.bin");
        std::fs::write(&dest, b"old").unwrap();

        let mut w = AtomicWrite::begin(&dest, Overwrite::Replace, Permissions::OwnerOnly).unwrap();
        w.write_all(b"new").unwrap();
        w.commit().unwrap();
        assert_eq!(std::fs::read(&dest).unwrap(), b"new");
    }

    #[cfg(unix)]
    #[test]
    fn output_is_not_readable_by_anyone_else() {
        use std::os::unix::fs::PermissionsExt as _;

        let dir = Scratch::new("perms");
        let dest = dir.join("out.bin");
        let mut w = AtomicWrite::begin(&dest, Overwrite::Refuse, Permissions::OwnerOnly).unwrap();
        w.write_all(b"sensitive").unwrap();
        w.commit().unwrap();

        let mode = std::fs::metadata(&dest).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "ADR-0019: stripped output is owner-only");
    }

    #[cfg(unix)]
    #[test]
    fn the_temporary_is_private_while_it_is_being_written() {
        // The window that matters: the file is at its most exposed before it is finished,
        // because that is when the user is not yet watching it.
        use std::os::unix::fs::PermissionsExt as _;

        let dir = Scratch::new("temp-perms");
        let dest = dir.join("out.bin");
        let w = AtomicWrite::begin(&dest, Overwrite::Refuse, Permissions::OwnerOnly).unwrap();
        let mode = std::fs::metadata(&w.temporary)
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600);
        w.abort();
    }

    #[test]
    fn the_temporary_sits_beside_the_destination_not_in_tmpdir() {
        // Writing a copy of a sensitive document somewhere the user did not choose is a leak
        // in its own right (docs/ARCHITECTURE.md §8).
        let dir = Scratch::new("location");
        let dest = dir.join("out.bin");
        let w = AtomicWrite::begin(&dest, Overwrite::Refuse, Permissions::OwnerOnly).unwrap();
        assert_eq!(w.temporary.parent(), dest.parent());
        w.abort();
    }
}
