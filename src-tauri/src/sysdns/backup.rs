//! The backup of Windows DNS taken before Sieve points it at itself, and
//! the standalone `restore-dns.ps1` written next to it, in
//! `<app data>/system-dns/`. The backup exists exactly while Sieve may have
//! Windows pointed at it: point writes it first, a full restore deletes it.
//!
//! Files are written whole to a temporary name and renamed into place, so a
//! crash never leaves half a backup.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use super::{InterfaceDns, SysDnsError, script};

pub const DIR: &str = "system-dns";
pub const BACKUP_FILE: &str = "backup.json";
pub const RESTORE_FILE: &str = "restore-dns.ps1";
pub const POINT_FILE: &str = "point-dns.ps1";
pub const BACKUP_VERSION: u32 = 1;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Backup {
    pub v: u32,
    /// When it was taken, ms since the Unix epoch.
    pub made_at: u64,
    pub interfaces: Vec<InterfaceDns>,
}

pub fn dir_in(app_data: &Path) -> PathBuf {
    app_data.join(DIR)
}

pub fn backup_path(dir: &Path) -> PathBuf {
    dir.join(BACKUP_FILE)
}

pub fn restore_path(dir: &Path) -> PathBuf {
    dir.join(RESTORE_FILE)
}

pub fn point_path(dir: &Path) -> PathBuf {
    dir.join(POINT_FILE)
}

pub fn exists(dir: &Path) -> bool {
    backup_path(dir).is_file()
}

fn io(path: &Path) -> impl FnOnce(std::io::Error) -> SysDnsError + '_ {
    move |source| SysDnsError::Io { path: path.display().to_string(), source }
}

/// Write `text` to `path` through a temporary file and a rename.
pub fn write_whole(path: &Path, text: &str) -> Result<(), SysDnsError> {
    let tmp = path.with_extension("tmp");
    std::fs::write(&tmp, text).map_err(io(&tmp))?;
    std::fs::rename(&tmp, path).map_err(io(path))
}

/// Writes a PowerShell script as UTF-8 WITH a byte order mark. Windows
/// PowerShell 5.1 reads a script without one in the ANSI code page, where
/// UTF-8 continuation bytes 0x91 and 0x92 read as the quotes U+2018 and
/// U+2019: an alias with, say, a non-breaking hyphen (E2 80 91) would end
/// its quoted string early.
pub fn write_script(path: &Path, text: &str) -> Result<(), SysDnsError> {
    write_whole(path, &format!("\u{FEFF}{text}"))
}

/// Saves the backup and the restore script made from it. Refuses to replace
/// an existing backup: that one holds the DNS from before Sieve.
pub fn write(dir: &Path, backup: &Backup) -> Result<(), SysDnsError> {
    std::fs::create_dir_all(dir).map_err(io(dir))?;
    let path = backup_path(dir);
    if path.exists() {
        return Err(SysDnsError::Refused(format!(
            "a backup from an earlier change exists ({}); restore it first",
            path.display()
        )));
    }
    let json = serde_json::to_string_pretty(backup)
        .map_err(|e| SysDnsError::BadBackup { path: path.display().to_string(), why: e.to_string() })?;
    // The restore script first: a backup with no way back is worse than none.
    write_script(&restore_path(dir), &script::restore_script(&backup.interfaces, &path))?;
    write_whole(&path, &json)
}

pub fn read(dir: &Path) -> Result<Option<Backup>, SysDnsError> {
    let path = backup_path(dir);
    let text = match std::fs::read_to_string(&path) {
        Ok(t) => t,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(io(&path)(e)),
    };
    let backup: Backup = serde_json::from_str(&text)
        .map_err(|e| SysDnsError::BadBackup { path: path.display().to_string(), why: e.to_string() })?;
    if backup.v != BACKUP_VERSION {
        return Err(SysDnsError::BadBackup { path: path.display().to_string(), why: format!("version {} is not {BACKUP_VERSION}", backup.v) });
    }
    Ok(Some(backup))
}

/// Forget the backup (after a full restore, or when the point was declined
/// and nothing changed). The restore script goes with it.
pub fn remove(dir: &Path) -> Result<(), SysDnsError> {
    for path in [backup_path(dir), restore_path(dir)] {
        match std::fs::remove_file(&path) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(io(&path)(e)),
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::super::tests::sample;
    use super::*;

    fn backup() -> Backup {
        Backup { v: BACKUP_VERSION, made_at: 1_800_000_000_000, interfaces: sample() }
    }

    #[test]
    fn write_read_round_trip_with_the_restore_script_beside_it() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let dir = dir_in(tmp.path());
        assert!(!exists(&dir));
        assert_eq!(read(&dir).expect("read"), None);
        write(&dir, &backup()).expect("write");
        assert!(exists(&dir));
        assert_eq!(read(&dir).expect("read"), Some(backup()));
        let restore = std::fs::read(restore_path(&dir)).expect("restore script");
        assert_eq!(&restore[..3], [0xEF, 0xBB, 0xBF], "UTF-8 with a BOM, so Windows PowerShell 5.1 reads it as UTF-8");
        assert_eq!(String::from_utf8(restore[3..].to_vec()).expect("utf8"), script::restore_script(&sample(), &backup_path(&dir)));
        assert!(!dir.join("backup.tmp").exists() && !dir.join("restore-dns.tmp").exists());
    }

    #[test]
    fn an_existing_backup_is_never_overwritten() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let dir = dir_in(tmp.path());
        write(&dir, &backup()).expect("write");
        let mut later = backup();
        later.interfaces[0].v4.servers = vec!["127.0.0.1".into()];
        assert!(matches!(write(&dir, &later), Err(SysDnsError::Refused(_))));
        assert_eq!(read(&dir).expect("read"), Some(backup()), "the first backup stands");
    }

    #[test]
    fn remove_takes_backup_and_script_and_is_idempotent() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let dir = dir_in(tmp.path());
        write(&dir, &backup()).expect("write");
        remove(&dir).expect("remove");
        assert!(!exists(&dir) && !restore_path(&dir).exists());
        remove(&dir).expect("again");
    }

    #[test]
    fn a_corrupt_or_newer_backup_is_an_error_not_an_absence() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let dir = dir_in(tmp.path());
        std::fs::create_dir_all(&dir).expect("dir");
        std::fs::write(backup_path(&dir), "{not json").expect("write");
        assert!(matches!(read(&dir), Err(SysDnsError::BadBackup { .. })));
        let mut newer = serde_json::to_value(backup()).expect("json");
        newer["v"] = serde_json::json!(2);
        std::fs::write(backup_path(&dir), newer.to_string()).expect("write");
        assert!(matches!(read(&dir), Err(SysDnsError::BadBackup { .. })));
    }
}
