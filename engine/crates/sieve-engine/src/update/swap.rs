//! The only file replacement of an update, behind an [`Fs`] seam a test can
//! fail at any step.
//!
//! Data kinds: one rename of the verified file over the real one. Releases:
//! copy the current files to `*.old`, then rename the verified file over the
//! real name with the service stopped. A complete exe stays at the ImagePath at
//! every instant (plan 7.5 said rename aside first, which leaves a moment with
//! none; recorded there). Rollback renames `.old` over the real name the same
//! way. Only a file that refuses that, a running `sieve.exe` (renamed, not
//! replaced), first moves to `.failed`, so rollback cannot jam on it.

use std::io;
use std::path::{Path, PathBuf};

use super::Kind;
use crate::service::image::MARKER_FILE;

pub const OLD_SUFFIX: &str = ".old";
pub const FAILED_SUFFIX: &str = ".failed";
/// Inside the install folder, so a staged file inherits the lock and a rename
/// out of it stays on one volume.
pub const STAGING_DIR: &str = "update-staging";
/// The supervisor runs from a copy of the current exe in staging, so the swap
/// can replace `sieve-engine.exe`.
pub const SUPERVISOR_EXE: &str = "update-finish.exe";
pub const ENGINE_EXE: &str = "sieve-engine.exe";
/// Under `ProgramData\Sieve\engine`: data kinds land here.
pub const DATA_DIR: &str = "updates";
pub const DATA_STAGING_DIR: &str = "staging";

pub trait Fs {
    fn copy(&self, from: &Path, to: &Path) -> io::Result<()>;
    fn rename(&self, from: &Path, to: &Path) -> io::Result<()>;
    fn remove_file(&self, path: &Path) -> io::Result<()>;
    fn exists(&self, path: &Path) -> bool;
    /// The regular files directly inside `dir`, by name.
    fn files(&self, dir: &Path) -> io::Result<Vec<String>>;
    fn read(&self, path: &Path) -> io::Result<Vec<u8>> {
        std::fs::read(path)
    }
}

pub struct RealFs;

impl Fs for RealFs {
    /// On disk before it returns: a `.old` may be all that is left after a power
    /// loss. A copy that cannot be opened for writing (a read-only source's
    /// attribute comes along) is kept unflushed rather than failing the update.
    fn copy(&self, from: &Path, to: &Path) -> io::Result<()> {
        std::fs::copy(from, to)?;
        match std::fs::OpenOptions::new().write(true).open(to) {
            Ok(file) => file.sync_all(),
            Err(_) => Ok(()),
        }
    }

    /// `MoveFileExW` with replace, atomic on one volume.
    fn rename(&self, from: &Path, to: &Path) -> io::Result<()> {
        std::fs::rename(from, to)
    }

    fn remove_file(&self, path: &Path) -> io::Result<()> {
        std::fs::remove_file(path)
    }

    fn exists(&self, path: &Path) -> bool {
        path.exists()
    }

    fn files(&self, dir: &Path) -> io::Result<Vec<String>> {
        let mut names = Vec::new();
        for entry in std::fs::read_dir(dir)? {
            let entry = entry?;
            if entry.file_type()?.is_file() {
                names.push(entry.file_name().to_string_lossy().into_owned());
            }
        }
        Ok(names)
    }
}

fn with_suffix(install: &Path, name: &str, suffix: &str) -> PathBuf {
    install.join(format!("{name}{suffix}"))
}

fn is_leftover(name: &str) -> bool {
    name.ends_with(OLD_SUFFIX) || name.ends_with(FAILED_SUFFIX)
}

fn named(path: &Path, e: &io::Error) -> String {
    format!("{}: {e}", path.display())
}

/// What an `app` release put in the folder that the set as listed did not have.
fn added<'a>(names: &'a [String], aside: &'a [String]) -> impl Iterator<Item = &'a String> {
    names.iter().filter(|n| !n.eq_ignore_ascii_case(MARKER_FILE) && !is_leftover(n) && !aside.contains(n))
}

/// Whether the real files are still the set that was set aside. Asked only once
/// the set-aside finished, so every `.old` is whole. A file that cannot be read
/// counts as changed: restoring from a whole `.old` is safe either way, and
/// dropping the release would delete the only copy.
pub fn set_changed(fs: &dyn Fs, install: &Path, kind: &Kind, aside: &[String]) -> bool {
    let differs = |name: &String| {
        let old = with_suffix(install, name, OLD_SUFFIX);
        fs.exists(&old) && !matches!((fs.read(&install.join(name)), fs.read(&old)), (Ok(real), Ok(kept)) if real == kept)
    };
    if aside.iter().any(differs) {
        return true;
    }
    *kind == Kind::App
        && match fs.files(install) {
            Ok(names) => added(&names, aside).next().is_some(),
            Err(_) => true,
        }
}

/// The files a release replaces, derived from the kind and the listing: `engine`
/// swaps the exe only (a wintun change ships in an `app` release), `app` every
/// regular file but the marker.
pub fn release_set(fs: &dyn Fs, install: &Path, kind: &Kind) -> Result<Vec<String>, String> {
    if *kind == Kind::Engine {
        return Ok(vec![ENGINE_EXE.to_string()]);
    }
    let mut names = fs.files(install).map_err(|e| named(install, &e))?;
    names.retain(|n| !n.eq_ignore_ascii_case(MARKER_FILE) && !is_leftover(n));
    names.sort();
    Ok(names)
}

/// Copies every file of the set to `<name>.old`. On failure nothing of it is
/// kept, a partial copy is never restored, and the real files were not touched.
pub fn set_aside(fs: &dyn Fs, install: &Path, set: &[String]) -> Result<(), String> {
    for name in set {
        let old = with_suffix(install, name, OLD_SUFFIX);
        if let Err(e) = fs.copy(&install.join(name), &old) {
            let why = named(&old, &e);
            let _ = clear_leftovers(fs, install);
            return Err(why);
        }
    }
    Ok(())
}

/// One atomic rename of a verified file over the real one.
pub fn replace(fs: &dyn Fs, staged: &Path, target: &Path) -> Result<(), String> {
    fs.rename(staged, target).map_err(|e| named(target, &e))
}

/// Back to the set as listed in `aside`: the one primitive for both kinds.
/// Rerunning it after an interruption finishes the job: a file whose `.old` is
/// gone was restored already. For an `app` release a file the installer added
/// also moves out, so the set is wholly the old one. A file stays at each name
/// unless `.old` could not be moved even after the real file went aside and the
/// real file could not then come back.
pub fn rollback(fs: &dyn Fs, install: &Path, kind: &Kind, aside: &[String]) -> Result<(), String> {
    for name in aside {
        let (real, old) = (install.join(name), with_suffix(install, name, OLD_SUFFIX));
        if !fs.exists(&old) || fs.rename(&old, &real).is_ok() {
            continue;
        }
        let failed = with_suffix(install, name, FAILED_SUFFIX);
        fs.rename(&real, &failed).map_err(|e| named(&failed, &e))?;
        if let Err(e) = fs.rename(&old, &real) {
            let _ = fs.rename(&failed, &real);
            return Err(named(&real, &e));
        }
    }
    if *kind == Kind::App {
        let names = fs.files(install).map_err(|e| named(install, &e))?;
        for name in added(&names, aside) {
            let failed = with_suffix(install, name, FAILED_SUFFIX);
            fs.rename(&install.join(name), &failed).map_err(|e| named(&failed, &e))?;
        }
    }
    Ok(())
}

/// Deletes every `.old` and `.failed` file. Runs only when no release is in
/// flight, or after one was decided. A `.failed` that is still running stays
/// until the next pass; that is not an error of the update.
pub fn clear_leftovers(fs: &dyn Fs, install: &Path) -> Result<(), String> {
    let names = fs.files(install).map_err(|e| named(install, &e))?;
    let mut failed = None;
    for name in names.iter().filter(|n| is_leftover(n)) {
        let path = install.join(name);
        if let Err(e) = fs.remove_file(&path) {
            failed.get_or_insert_with(|| named(&path, &e));
        }
    }
    failed.map_or(Ok(()), Err)
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use std::cell::Cell;
    use std::collections::BTreeMap;

    /// Real files, except that step `fail_at` (0-based, over every mutating
    /// call) fails, and a failing copy leaves half the bytes behind.
    pub struct FailingFs {
        pub fail_at: usize,
        pub step: Cell<usize>,
    }

    impl FailingFs {
        pub fn at(fail_at: usize) -> Self {
            Self { fail_at, step: Cell::new(0) }
        }

        fn tick(&self) -> io::Result<()> {
            let step = self.step.get();
            self.step.set(step + 1);
            if step == self.fail_at { Err(io::Error::other(format!("injected at step {step}"))) } else { Ok(()) }
        }

        pub fn fired(&self) -> bool {
            self.step.get() > self.fail_at
        }
    }

    impl Fs for FailingFs {
        fn copy(&self, from: &Path, to: &Path) -> io::Result<()> {
            if let Err(e) = self.tick() {
                let bytes = std::fs::read(from)?;
                std::fs::write(to, &bytes[..bytes.len() / 2])?;
                return Err(e);
            }
            RealFs.copy(from, to)
        }

        fn rename(&self, from: &Path, to: &Path) -> io::Result<()> {
            self.tick()?;
            RealFs.rename(from, to)
        }

        fn remove_file(&self, path: &Path) -> io::Result<()> {
            self.tick()?;
            RealFs.remove_file(path)
        }

        fn exists(&self, path: &Path) -> bool {
            RealFs.exists(path)
        }

        fn files(&self, dir: &Path) -> io::Result<Vec<String>> {
            RealFs.files(dir)
        }
    }

    pub const OLD_ENGINE: &[u8] = b"old engine bytes";
    pub const NEW_ENGINE: &[u8] = b"new engine bytes, longer";
    const OLD_APP: &[u8] = b"old app";
    const NEW_APP: &[u8] = b"new app";

    fn read_all(dir: &Path) -> BTreeMap<String, Vec<u8>> {
        std::fs::read_dir(dir)
            .unwrap()
            .map(Result::unwrap)
            .filter(|e| e.file_type().unwrap().is_file())
            .map(|e| (e.file_name().to_string_lossy().into_owned(), std::fs::read(e.path()).unwrap()))
            .collect()
    }

    fn real_files(dir: &Path) -> BTreeMap<String, Vec<u8>> {
        read_all(dir).into_iter().filter(|(n, _)| !is_leftover(n)).collect()
    }

    fn engine_setup() -> (tempfile::TempDir, PathBuf, PathBuf) {
        let dir = tempfile::tempdir().unwrap();
        let install = dir.path().join("install");
        std::fs::create_dir(&install).unwrap();
        std::fs::write(install.join(ENGINE_EXE), OLD_ENGINE).unwrap();
        std::fs::write(install.join(MARKER_FILE), b"").unwrap();
        let staged = dir.path().join("staged");
        std::fs::write(&staged, NEW_ENGINE).unwrap();
        (dir, install, staged)
    }

    fn engine_bytes(install: &Path) -> Vec<u8> {
        std::fs::read(install.join(ENGINE_EXE)).expect("a complete exe at the ImagePath at every instant")
    }

    /// Set aside, swap, then the new engine fails and rolls back; failing at
    /// every step k. The exe is whole at every point, and rerunning recovery
    /// always ends on wholly the old set.
    #[test]
    fn every_interrupted_step_leaves_a_whole_set() {
        let set = vec![ENGINE_EXE.to_string()];
        let mut k = 0;
        loop {
            let (_guard, install, staged) = engine_setup();
            let target = install.join(ENGINE_EXE);
            let fs = FailingFs::at(k);
            let done = (|| {
                set_aside(&fs, &install, &set).map_err(|_| "set aside")?;
                assert_eq!(engine_bytes(&install), OLD_ENGINE);
                replace(&fs, &staged, &target).map_err(|_| "swap")?;
                assert_eq!(engine_bytes(&install), NEW_ENGINE);
                rollback(&fs, &install, &Kind::Engine, &set).map_err(|_| "rollback")?;
                Ok::<(), &str>(())
            })();
            match done {
                // A rollback whose first rename failed went on the other way.
                Ok(()) => {}
                Err("set aside") => {
                    assert_eq!(engine_bytes(&install), OLD_ENGINE, "the real file was not touched");
                    assert_eq!(clear_leftovers(&RealFs, &install), Ok(()));
                }
                Err("swap") => {
                    assert_eq!(engine_bytes(&install), OLD_ENGINE, "a failed rename changed nothing");
                    rollback(&RealFs, &install, &Kind::Engine, &set).unwrap();
                }
                Err(_) => rollback(&RealFs, &install, &Kind::Engine, &set).unwrap(),
            }
            assert_eq!(engine_bytes(&install), OLD_ENGINE, "step {k}");
            clear_leftovers(&RealFs, &install).unwrap();
            assert_eq!(read_all(&install).keys().cloned().collect::<Vec<_>>(), [ENGINE_EXE, MARKER_FILE], "step {k}");
            if !fs.fired() {
                assert!(k >= 3, "the sequence must have had steps to fail: {k}");
                break;
            }
            k += 1;
        }
    }

    /// The healthy end: the new set stays and every `.old` goes; a deletion that
    /// fails is retried and never touches the real files.
    #[test]
    fn an_interrupted_commit_keeps_the_new_set() {
        let set = vec![ENGINE_EXE.to_string()];
        for k in 0..2 {
            let (_guard, install, staged) = engine_setup();
            set_aside(&RealFs, &install, &set).unwrap();
            replace(&RealFs, &staged, &install.join(ENGINE_EXE)).unwrap();
            let _ = clear_leftovers(&FailingFs::at(k), &install);
            assert_eq!(engine_bytes(&install), NEW_ENGINE);
            clear_leftovers(&RealFs, &install).unwrap();
            assert!(!install.join(format!("{ENGINE_EXE}{OLD_SUFFIX}")).exists());
        }
    }

    fn app_setup() -> (tempfile::TempDir, PathBuf, Vec<String>) {
        let dir = tempfile::tempdir().unwrap();
        let install = dir.path().to_path_buf();
        for (name, bytes) in [(ENGINE_EXE, OLD_ENGINE), ("sieve.exe", OLD_APP), ("uninstall.exe", OLD_APP), (MARKER_FILE, b"".as_slice())] {
            std::fs::write(install.join(name), bytes).unwrap();
        }
        std::fs::create_dir(install.join(STAGING_DIR)).unwrap();
        let set = release_set(&RealFs, &install, &Kind::App).unwrap();
        (dir, install, set)
    }

    #[test]
    fn the_app_set_is_derived_from_the_listing_and_engine_is_the_exe_only() {
        let (_guard, install, set) = app_setup();
        std::fs::write(install.join("stale.exe.old"), b"x").unwrap();
        assert_eq!(set, [ENGINE_EXE, "sieve.exe", "uninstall.exe"], "no marker, no folder");
        assert_eq!(release_set(&RealFs, &install, &Kind::App).unwrap(), set, "no leftover");
        assert_eq!(release_set(&RealFs, &install, &Kind::Engine).unwrap(), [ENGINE_EXE]);
    }

    /// What an installer leaves, partly or wholly: rollback restores every file
    /// of the set and moves out any it added; failing at every step of the
    /// rollback and rerunning it ends in the same place.
    #[test]
    fn an_app_rollback_restores_the_whole_set_from_any_interruption() {
        let mut k = 0;
        loop {
            let (_guard, install, set) = app_setup();
            let before = real_files(&install);
            set_aside(&RealFs, &install, &set).unwrap();
            std::fs::write(install.join("sieve.exe"), NEW_APP).unwrap();
            std::fs::write(install.join(ENGINE_EXE), NEW_ENGINE).unwrap();
            std::fs::remove_file(install.join("uninstall.exe")).unwrap();
            std::fs::write(install.join("added.dll"), NEW_APP).unwrap();
            let fs = FailingFs::at(k);
            let failed = rollback(&fs, &install, &Kind::App, &set).is_err();
            if failed {
                rollback(&RealFs, &install, &Kind::App, &set).unwrap();
            }
            assert_eq!(real_files(&install), before, "step {k}");
            if !fs.fired() {
                assert!(!failed && k >= 4, "{k}");
                break;
            }
            k += 1;
        }
    }

    /// Real files, except that a rename out of a `.old` always fails, as with a
    /// scanner holding it.
    struct OldLocked;

    impl Fs for OldLocked {
        fn copy(&self, from: &Path, to: &Path) -> io::Result<()> {
            RealFs.copy(from, to)
        }
        fn rename(&self, from: &Path, to: &Path) -> io::Result<()> {
            if from.to_string_lossy().ends_with(OLD_SUFFIX) { Err(io::Error::other("locked")) } else { RealFs.rename(from, to) }
        }
        fn remove_file(&self, path: &Path) -> io::Result<()> {
            RealFs.remove_file(path)
        }
        fn exists(&self, path: &Path) -> bool {
            RealFs.exists(path)
        }
        fn files(&self, dir: &Path) -> io::Result<Vec<String>> {
            RealFs.files(dir)
        }
    }

    /// With the service stopped a stopped exe is replaced at once, with no gap for
    /// a power loss, and a locked `.old` leaves the real file for the service to
    /// start and carry the rollback on.
    #[test]
    fn a_rollback_never_leaves_the_image_path_empty() {
        let (_guard, install, staged) = engine_setup();
        let set = vec![ENGINE_EXE.to_string()];
        set_aside(&RealFs, &install, &set).unwrap();
        replace(&RealFs, &staged, &install.join(ENGINE_EXE)).unwrap();

        assert!(rollback(&OldLocked, &install, &Kind::Engine, &set).is_err());
        assert_eq!(engine_bytes(&install), NEW_ENGINE, "still there, to start");
        assert!(install.join(format!("{ENGINE_EXE}{OLD_SUFFIX}")).exists(), "and the rollback can be rerun");

        rollback(&RealFs, &install, &Kind::Engine, &set).unwrap();
        assert_eq!(engine_bytes(&install), OLD_ENGINE);
        assert!(!install.join(format!("{ENGINE_EXE}{FAILED_SUFFIX}")).exists(), "no aside: one atomic rename");
    }

    /// What each part of an interrupted `app` install looks like, from a whole
    /// set-aside: an untouched set, each kind of change, and a file nobody can read.
    #[test]
    fn set_changed_reads_the_real_files_against_the_set_aside() {
        struct Unreadable(&'static str);
        impl Fs for Unreadable {
            fn copy(&self, from: &Path, to: &Path) -> io::Result<()> {
                RealFs.copy(from, to)
            }
            fn rename(&self, from: &Path, to: &Path) -> io::Result<()> {
                RealFs.rename(from, to)
            }
            fn remove_file(&self, path: &Path) -> io::Result<()> {
                RealFs.remove_file(path)
            }
            fn exists(&self, path: &Path) -> bool {
                RealFs.exists(path)
            }
            fn files(&self, dir: &Path) -> io::Result<Vec<String>> {
                RealFs.files(dir)
            }
            fn read(&self, path: &Path) -> io::Result<Vec<u8>> {
                if path.ends_with(self.0) { Err(io::Error::other("sharing violation")) } else { RealFs.read(path) }
            }
        }

        let changed = |change: &dyn Fn(&Path), kind: &Kind| {
            let (_guard, install, set) = app_setup();
            set_aside(&RealFs, &install, &set).unwrap();
            change(&install);
            set_changed(&RealFs, &install, kind, &set)
        };
        assert!(!changed(&|_| {}, &Kind::App), "untouched");
        assert!(changed(&|i| std::fs::write(i.join("sieve.exe"), NEW_APP).unwrap(), &Kind::App), "one file new");
        assert!(changed(&|i| std::fs::remove_file(i.join("uninstall.exe")).unwrap(), &Kind::App), "one file gone");
        assert!(changed(&|i| std::fs::write(i.join("added.dll"), NEW_APP).unwrap(), &Kind::App), "one file added");
        assert!(!changed(&|i| std::fs::write(i.join("added.dll"), NEW_APP).unwrap(), &Kind::Engine), "an engine release sets aside the exe only");
        assert!(!changed(&|i| std::fs::write(i.join("sieve.exe.failed"), NEW_APP).unwrap(), &Kind::App), "a leftover is not part of the set");

        let (_guard, install, set) = app_setup();
        set_aside(&RealFs, &install, &set).unwrap();
        assert!(set_changed(&Unreadable("sieve.exe"), &install, &Kind::App, &set), "unknown is not unchanged");
    }

    #[test]
    fn a_failed_set_aside_keeps_no_partial_copy() {
        let (_guard, install, staged) = engine_setup();
        let set = vec![ENGINE_EXE.to_string()];
        assert!(set_aside(&FailingFs::at(0), &install, &set).is_err());
        assert!(!install.join(format!("{ENGINE_EXE}{OLD_SUFFIX}")).exists());
        assert_eq!(engine_bytes(&install), OLD_ENGINE);
        assert!(staged.exists());
    }

    /// Pins the fact D12 and D17 rest on, with real files and a real running
    /// image: a temp copy of a harmless System32 tool that waits on its stdin
    /// and touches no network.
    #[cfg(windows)]
    #[test]
    fn a_running_image_can_be_renamed_but_not_replaced() {
        use std::process::{Command, Stdio};
        let dir = tempfile::tempdir().unwrap();
        let system = std::env::var_os("SystemRoot").map(PathBuf::from).unwrap().join("System32").join("sort.exe");
        let image = dir.path().join("running.exe");
        std::fs::copy(system, &image).unwrap();
        let replacement = dir.path().join("replacement.exe");
        std::fs::write(&replacement, b"not an image").unwrap();
        let mut child = Command::new(&image).stdin(Stdio::piped()).stdout(Stdio::null()).stderr(Stdio::null()).spawn().unwrap();
        std::thread::sleep(std::time::Duration::from_millis(200));
        let running = child.try_wait().unwrap().is_none();
        let replaced = std::fs::rename(&replacement, &image);
        let aside = dir.path().join("running.exe.old");
        let renamed = std::fs::rename(&image, &aside);
        let moved_in = std::fs::rename(&replacement, &image);
        let _ = child.kill();
        let _ = child.wait();
        assert!(running, "the tool must still be running for this to prove anything");
        assert!(replaced.is_err(), "a running image cannot be replaced");
        renamed.expect("a running image can be renamed away");
        moved_in.expect("and its name is then free");
        assert_eq!(std::fs::read(&image).unwrap(), b"not an image");
    }

    /// The plain case the same fact depends on: a rename replaces atomically.
    #[test]
    fn a_rename_replaces_the_destination() {
        let dir = tempfile::tempdir().unwrap();
        let (from, to) = (dir.path().join("a"), dir.path().join("b"));
        std::fs::write(&from, b"new").unwrap();
        std::fs::write(&to, b"old").unwrap();
        replace(&RealFs, &from, &to).unwrap();
        assert_eq!(std::fs::read(&to).unwrap(), b"new");
        assert!(!from.exists());
    }
}
