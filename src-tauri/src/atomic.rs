//! Crash-safe file writes, for every file the user would miss: `.ppx`
//! profiles, settings, and user detection rules.
//!
//! 1. Optionally copy the existing file to `<name>.bak` (best effort).
//! 2. Write to a unique `<name>.tmp-<n>` and `fsync`, so the content is
//!    durable before anything is swapped.
//! 3. Rename the temp file over the target.
//!
//! Step 3 is the atomic one: `fs::rename` replaces an existing file on POSIX
//! and modern Windows, so a reader sees the old file or the new one, never a
//! missing or half-written one. Never hand-roll `remove_file` + `rename`,
//! which leaves a window where the file is gone.

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

use tracing::warn;

use crate::error::AppError;

/// Whether to keep a `.bak` copy of the previous contents.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Backup {
    /// Keep `<name>.bak`. Used for `.ppx` profiles, where the previous
    /// contents are the user's own hand-tuned work.
    Keep,
    /// No backup. Used for files the app can regenerate or the user can
    /// retype cheaply.
    Skip,
}

/// Write `contents` to `target`, replacing it atomically.
pub fn write(target: &Path, contents: &[u8], backup: Backup) -> Result<(), AppError> {
    if backup == Backup::Keep && target.exists() {
        let bak = with_suffix(target, ".bak");
        if let Err(e) = fs::copy(target, &bak) {
            warn!(?bak, "backup copy failed, proceeding anyway: {e}");
        }
    }

    let tmp = temp_sibling(target);
    {
        let mut f = fs::OpenOptions::new().create_new(true).write(true).open(&tmp)?;
        f.write_all(contents)?;
        // Durability before visibility: without this the rename can land
        // while the contents are still only in the page cache.
        f.sync_all()?;
    }

    if let Err(e) = fs::rename(&tmp, target) {
        // Clean up rather than leaving a stray `.tmp-N` behind; the original
        // target is untouched, so the caller's data is still intact.
        let _ = fs::remove_file(&tmp);
        return Err(AppError::Io(e));
    }
    Ok(())
}

fn with_suffix(path: &Path, extra: &str) -> PathBuf {
    let mut s: std::ffi::OsString = path.as_os_str().to_os_string();
    s.push(extra);
    PathBuf::from(s)
}

/// A temp path next to `target` that no one else holds.
///
/// Next to the target, not in the system temp dir, so the final step is a
/// same-volume rename — a cross-device rename is a copy, which is not atomic.
///
/// The counter matters: deriving the temp name from the target alone means
/// `foo.yml` and `foo.yaml` collide on `foo.yml.tmp`, and two concurrent
/// saves of the same file race. `create_new` below turns any residual
/// collision into an error rather than silent corruption.
fn temp_sibling(target: &Path) -> PathBuf {
    use std::sync::atomic::{AtomicU64, Ordering};
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let n = COUNTER.fetch_add(1, Ordering::Relaxed);
    let pid = std::process::id();
    with_suffix(target, &format!(".tmp-{pid}-{n}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn replaces_existing_file() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("thing.json");
        write(&target, b"first", Backup::Skip).unwrap();
        write(&target, b"second", Backup::Skip).unwrap();
        assert_eq!(fs::read(&target).unwrap(), b"second");
    }

    #[test]
    fn keeps_a_backup_when_asked() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("profile.ppx");
        write(&target, b"old", Backup::Keep).unwrap();
        write(&target, b"new", Backup::Keep).unwrap();
        assert_eq!(fs::read(&target).unwrap(), b"new");
        assert_eq!(
            fs::read(dir.path().join("profile.ppx.bak")).unwrap(),
            b"old",
            "the .bak should hold the contents from before the last write"
        );
    }

    #[test]
    fn skips_the_backup_when_asked() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("settings.json");
        write(&target, b"a", Backup::Skip).unwrap();
        write(&target, b"b", Backup::Skip).unwrap();
        assert!(!dir.path().join("settings.json.bak").exists());
    }

    /// `foo.yml` and `foo.yaml` used to derive the same `.tmp` path, so
    /// saving both could corrupt one.
    #[test]
    fn similar_names_do_not_share_a_temp_file() {
        let dir = tempfile::tempdir().unwrap();
        let yml = dir.path().join("rule.yml");
        let yaml = dir.path().join("rule.yaml");
        write(&yml, b"short extension", Backup::Skip).unwrap();
        write(&yaml, b"long extension", Backup::Skip).unwrap();
        assert_eq!(fs::read(&yml).unwrap(), b"short extension");
        assert_eq!(fs::read(&yaml).unwrap(), b"long extension");
    }

    #[test]
    fn leaves_no_temp_files_behind() {
        let dir = tempfile::tempdir().unwrap();
        write(&dir.path().join("x.txt"), b"hello", Backup::Skip).unwrap();
        let strays: Vec<_> = fs::read_dir(dir.path())
            .unwrap()
            .filter_map(Result::ok)
            .filter(|e| e.file_name().to_string_lossy().contains(".tmp-"))
            .collect();
        assert!(strays.is_empty(), "temp files left behind: {strays:?}");
    }
}
