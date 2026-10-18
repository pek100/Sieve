//! Who can change what the LocalSystem service runs (plan 1.5 and 7.1).
//!
//! The service runs `sieve-engine.exe` as SYSTEM, so anyone who can replace
//! that file, add a file beside it (a planted DLL loads from the exe's own
//! folder first), or swap one of the folders on its path owns SYSTEM. Found
//! live on 2026-10-18: Sieve installed to `E:\Sieve`, which inherited
//! "Authenticated Users: Modify" from the drive root.
//!
//! The installer may use any folder: its hook locks the folder it installs to
//! (`acl::INSTALL_DIR_SDDL`, before any file is copied) and leaves
//! [`MARKER_FILE`] in it. This module is the seatbelt that proves the lock
//! held. [`verdict`] is the one rule, a pure function over parsed security
//! descriptors (owner, and the DACL as SIDs, access masks and ACE flags); the
//! `install` verb runs it before registering the service and the service runs
//! it at every start ([`check_install`]). Only SYSTEM, Administrators and
//! TrustedInstaller may hold a right that changes what runs:
//! - the exe, and every other entry in its folder, the marker included
//!   ([`Role::Image`]): any write, delete or ACL right;
//! - the folder ([`Role::Folder`]): the same, plus inheritable grants, which
//!   every file put there later (an update, `wintun.dll`) would receive. A
//!   `CREATOR OWNER` inheritable grant is allowed: only someone who can
//!   already create files there becomes that owner, and that is checked;
//! - every folder above ([`Role::Ancestor`]): the rights that rename or delete
//!   it or its children, or rewrite its ACL. Adding unrelated folders beside
//!   ours (`Authenticated Users: AD` on `C:\`) changes nothing on the path;
//! - the drive root ([`Role::Root`]): the same, without DELETE, since a root
//!   cannot be renamed (`E:\` grants Authenticated Users Modify on itself).
//!
//! The owner of every one of them must be one of the three as well: an owner
//! can always rewrite the DACL. Inherited ACEs count exactly like explicit
//! ones; deny ACEs grant nothing (and are not used to cancel a grant); an ACE
//! type this check cannot read, or a NULL DACL, refuses. Nothing here changes
//! an ACL.

use std::path::{Path, PathBuf};

pub const SYSTEM: &str = "S-1-5-18";
pub const ADMINISTRATORS: &str = "S-1-5-32-544";
pub const TRUSTED_INSTALLER: &str = "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464";
pub const CREATOR_OWNER: &str = "S-1-3-0";

/// The only principals that may change the service's image or its path.
pub const TRUSTED: [&str; 3] = [SYSTEM, ADMINISTRATORS, TRUSTED_INSTALLER];

/// Written by the installer's hook into a folder it created empty and locked
/// (`src-tauri/windows/hooks.nsh`, `SIEVE_MARKER`). An install folder without
/// it was not prepared by Sieve; a non-empty folder without it is never
/// locked, because re-ACLing someone else's files could break them.
pub const MARKER_FILE: &str = "sieve-install.marker";

// Access mask bits (winnt.h). On a folder WRITE_DATA is "add file" and
// APPEND_DATA "add subfolder".
const FILE_WRITE_DATA: u32 = 0x0002;
const FILE_APPEND_DATA: u32 = 0x0004;
const FILE_WRITE_EA: u32 = 0x0010;
const FILE_DELETE_CHILD: u32 = 0x0040;
const FILE_WRITE_ATTRIBUTES: u32 = 0x0100;
const DELETE: u32 = 0x0001_0000;
const WRITE_DAC: u32 = 0x0004_0000;
const WRITE_OWNER: u32 = 0x0008_0000;
const MAXIMUM_ALLOWED: u32 = 0x0200_0000;
const GENERIC_ALL: u32 = 0x1000_0000;
const GENERIC_WRITE: u32 = 0x4000_0000;

/// Rights that change a file or folder: its content, its children, its
/// attributes, its ACL or owner, or delete it.
pub const WRITE_RIGHTS: u32 = FILE_WRITE_DATA
    | FILE_APPEND_DATA
    | FILE_WRITE_EA
    | FILE_DELETE_CHILD
    | FILE_WRITE_ATTRIBUTES
    | DELETE
    | WRITE_DAC
    | WRITE_OWNER
    | MAXIMUM_ALLOWED
    | GENERIC_ALL
    | GENERIC_WRITE;

/// Rights on a folder above ours that swap the path: rename or delete the
/// folder or a child, or take over its ACL.
pub const SWAP_RIGHTS: u32 = DELETE | FILE_DELETE_CHILD | WRITE_DAC | WRITE_OWNER | MAXIMUM_ALLOWED | GENERIC_ALL;

/// ACE flags (winnt.h). Inherit-only: the ACE grants nothing here.
pub const OBJECT_INHERIT: u8 = 0x01;
pub const CONTAINER_INHERIT: u8 = 0x02;
pub const INHERIT_ONLY: u8 = 0x08;
pub const INHERITED: u8 = 0x10;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AceKind {
    /// ACCESS_ALLOWED and its callback form.
    Allow,
    /// ACCESS_DENIED and its callback form.
    Deny,
    /// Any other ACE type (object ACEs never appear on files): refused.
    Unknown(u8),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ace {
    pub kind: AceKind,
    pub flags: u8,
    pub mask: u32,
    /// String SID (`S-1-5-18`).
    pub sid: String,
}

/// The parts of a security descriptor the rule reads.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Descriptor {
    pub owner: Option<String>,
    /// `None` is a NULL DACL: everybody has every right.
    pub dacl: Option<Vec<Ace>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    /// The service's exe, or another entry of its folder.
    Image,
    /// The folder the exe is in.
    Folder,
    /// A folder above it.
    Ancestor,
    /// The drive root.
    Root,
}

/// A folder as the image's folder, then every folder above it, root last.
pub fn folder_chain(folder: &Path) -> Vec<(PathBuf, Role)> {
    folder
        .ancestors()
        .enumerate()
        .map(|(i, p)| {
            let role = match (i, p.parent()) {
                (_, None) => Role::Root,
                (0, _) => Role::Folder,
                _ => Role::Ancestor,
            };
            (p.to_path_buf(), role)
        })
        .collect()
}

/// The objects whose ACLs decide what the service at `exe` runs: the exe,
/// every other entry of its folder (`entries`, as listed), the folder, then
/// every folder above. Refused when the folder holds no [`MARKER_FILE`].
pub fn install_chain(exe: &Path, entries: &[PathBuf]) -> Result<Vec<(PathBuf, Role)>, String> {
    let folder = exe.parent().filter(|p| !p.as_os_str().is_empty()).ok_or_else(|| format!("{}: no folder", exe.display()))?;
    let name_is = |p: &Path, name: &std::ffi::OsStr| p.file_name().is_some_and(|n| n.eq_ignore_ascii_case(name));
    if !entries.iter().any(|e| name_is(e, MARKER_FILE.as_ref())) {
        return Err(format!(
            "refused: {} holds no {MARKER_FILE}, so Sieve's installer did not create and lock it. \
             Install Sieve with its installer, into an empty or new folder",
            folder.display()
        ));
    }
    let exe_name = exe.file_name().unwrap_or_default();
    let mut out = vec![(exe.to_path_buf(), Role::Image)];
    out.extend(entries.iter().filter(|e| !name_is(e, exe_name)).map(|e| (e.clone(), Role::Image)));
    out.extend(folder_chain(folder));
    Ok(out)
}

fn is_trusted(sid: &str) -> bool {
    TRUSTED.contains(&sid)
}

/// A readable name for the SIDs a refusal usually names; the SID otherwise.
pub fn sid_name(sid: &str) -> String {
    let name = match sid {
        "S-1-1-0" => "Everyone",
        "S-1-3-0" => "CREATOR OWNER",
        "S-1-3-1" => "CREATOR GROUP",
        "S-1-3-4" => "OWNER RIGHTS",
        "S-1-5-4" => "INTERACTIVE",
        "S-1-5-11" => "Authenticated Users",
        "S-1-5-32-545" => "Users",
        "S-1-5-32-547" => "Power Users",
        _ => return sid.to_string(),
    };
    format!("{name} ({sid})")
}

/// The rights that matter on an object in `role`.
fn needed(role: Role) -> u32 {
    match role {
        Role::Image | Role::Folder => WRITE_RIGHTS,
        Role::Ancestor => SWAP_RIGHTS,
        Role::Root => SWAP_RIGHTS & !DELETE,
    }
}

/// Why `ace` lets a non-admin change what runs, at an object in `role`, or
/// None when it does not.
fn ace_problem(role: Role, ace: &Ace) -> Option<String> {
    let applies_here = ace.flags & INHERIT_ONLY == 0;
    match ace.kind {
        AceKind::Deny => None,
        AceKind::Unknown(t) => Some(format!("an ACE of type {t} this check cannot read")),
        AceKind::Allow if is_trusted(&ace.sid) => None,
        AceKind::Allow if applies_here && ace.mask & needed(role) != 0 => {
            Some(format!("{} may change it (access mask {:#x})", sid_name(&ace.sid), ace.mask))
        }
        AceKind::Allow if !applies_here && role == Role::Folder && ace.sid != CREATOR_OWNER && ace.mask & WRITE_RIGHTS != 0 => {
            Some(format!(
                "{} would be able to change every file added later (inheritable, access mask {:#x})",
                sid_name(&ace.sid),
                ace.mask
            ))
        }
        AceKind::Allow => None,
    }
}

/// Everything wrong with one object, empty when it is safe in `role`.
pub fn problems(role: Role, d: &Descriptor) -> Vec<String> {
    let mut out = Vec::new();
    match d.owner.as_deref() {
        Some(o) if is_trusted(o) => {}
        Some(o) => out.push(format!("owned by {}, who can rewrite its ACL", sid_name(o))),
        None => out.push("it has no owner".into()),
    }
    match &d.dacl {
        None => out.push("a NULL DACL gives everybody every right".into()),
        Some(aces) => out.extend(aces.iter().filter_map(|a| ace_problem(role, a))),
    }
    out
}

/// The rule: Ok when only SYSTEM, Administrators and TrustedInstaller can
/// change what runs; else every reason, by path.
pub fn verdict(chain: &[(PathBuf, Role, Descriptor)]) -> Result<(), String> {
    let found: Vec<String> = chain
        .iter()
        .flat_map(|(path, role, d)| problems(*role, d).into_iter().map(move |p| format!("{}: {p}", path.display())))
        .collect();
    if found.is_empty() {
        return Ok(());
    }
    Err(format!(
        "refused: users who are not administrators can change what this LocalSystem service runs ({}). \
         Sieve's installer locks the folder it installs to; reinstall Sieve with it, into an empty or new folder",
        found.join("; ")
    ))
}

#[cfg(windows)]
pub use win::{check_folder, check_install, check_this_exe, read_descriptor};

#[cfg(windows)]
mod win {
    use std::ffi::c_void;
    use std::os::windows::ffi::OsStrExt;
    use std::path::{Path, PathBuf};

    use windows::Win32::Foundation::{HLOCAL, LocalFree};
    use windows::Win32::Security::Authorization::{ConvertSidToStringSidW, GetNamedSecurityInfoW, SE_FILE_OBJECT};
    use windows::Win32::Security::{
        ACCESS_ALLOWED_ACE, ACE_HEADER, ACL, DACL_SECURITY_INFORMATION, GetAce, GetSecurityDescriptorDacl,
        GetSecurityDescriptorOwner, IsValidSid, OWNER_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, PSID,
    };
    use windows::core::{PCWSTR, PWSTR};

    use super::{Ace, AceKind, Descriptor, Role, folder_chain, install_chain, verdict};

    // ACE types (winnt.h) whose layout is header, mask, SID.
    const ACCESS_ALLOWED: u8 = 0;
    const ACCESS_DENIED: u8 = 1;
    const ACCESS_ALLOWED_CALLBACK: u8 = 9;
    const ACCESS_DENIED_CALLBACK: u8 = 10;

    fn sid_string(sid: PSID) -> Result<String, String> {
        // SAFETY: `sid` points into a live security descriptor.
        if !unsafe { IsValidSid(sid) }.as_bool() {
            return Err("invalid SID".into());
        }
        let mut text = PWSTR::null();
        // SAFETY: valid SID; `text` is LocalAlloc'd by Windows, freed below.
        unsafe { ConvertSidToStringSidW(sid, &mut text) }.map_err(|e| e.to_string())?;
        // SAFETY: NUL-terminated string from Windows.
        let s = unsafe { text.to_string() }.map_err(|e| e.to_string());
        // SAFETY: freed once.
        unsafe {
            let _ = LocalFree(Some(HLOCAL(text.0.cast())));
        }
        s
    }

    /// Owner and DACL of a security descriptor in memory.
    pub(crate) fn descriptor_of(sd: PSECURITY_DESCRIPTOR) -> Result<Descriptor, String> {
        let mut owner = PSID::default();
        let mut dacl: *mut ACL = std::ptr::null_mut();
        let (mut present, mut defaulted) = (false.into(), false.into());
        // SAFETY: `sd` is a valid descriptor; the out pointers point into it.
        unsafe {
            GetSecurityDescriptorOwner(sd, &mut owner, &mut defaulted).map_err(|e| e.to_string())?;
            GetSecurityDescriptorDacl(sd, &mut present, &mut dacl, &mut defaulted).map_err(|e| e.to_string())?;
        }
        let owner = if owner.0.is_null() { None } else { Some(sid_string(owner)?) };
        // Absent DACL or a present NULL one: both mean no protection.
        if !present.as_bool() || dacl.is_null() {
            return Ok(Descriptor { owner, dacl: None });
        }
        // SAFETY: a present, non-null DACL inside `sd`.
        let count = unsafe { (*dacl).AceCount };
        let mut aces = Vec::with_capacity(count.into());
        for i in 0..u32::from(count) {
            let mut raw: *mut c_void = std::ptr::null_mut();
            // SAFETY: `i` < AceCount of a valid ACL.
            unsafe { GetAce(dacl, i, &mut raw) }.map_err(|e| format!("ACE {i}: {e}"))?;
            // SAFETY: every ACE starts with an ACE_HEADER.
            let header = unsafe { &*raw.cast::<ACE_HEADER>() };
            let kind = match header.AceType {
                ACCESS_ALLOWED | ACCESS_ALLOWED_CALLBACK => AceKind::Allow,
                ACCESS_DENIED | ACCESS_DENIED_CALLBACK => AceKind::Deny,
                other => AceKind::Unknown(other),
            };
            let (mask, sid) = if matches!(kind, AceKind::Unknown(_)) {
                (0, String::new())
            } else {
                // SAFETY: these four types share ACCESS_ALLOWED_ACE's layout;
                // the SID starts at SidStart.
                let ace = unsafe { &*raw.cast::<ACCESS_ALLOWED_ACE>() };
                let sid = PSID((&raw const ace.SidStart).cast_mut().cast());
                (ace.Mask, sid_string(sid)?)
            };
            aces.push(Ace { kind, flags: header.AceFlags, mask, sid });
        }
        Ok(Descriptor { owner, dacl: Some(aces) })
    }

    /// Reads the owner and DACL of a file or folder (READ_CONTROL only).
    pub fn read_descriptor(path: &Path) -> Result<Descriptor, String> {
        let wide: Vec<u16> = path.as_os_str().encode_wide().chain(std::iter::once(0)).collect();
        let mut sd = PSECURITY_DESCRIPTOR::default();
        // SAFETY: `wide` is NUL-terminated; Windows allocates `sd` with
        // LocalAlloc, freed below; owner and DACL are read from `sd` itself.
        let code = unsafe {
            GetNamedSecurityInfoW(
                PCWSTR(wide.as_ptr()),
                SE_FILE_OBJECT,
                OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
                None,
                None,
                None,
                None,
                &mut sd,
            )
        };
        if code.is_err() {
            return Err(format!("{}: could not read its ACL ({code:?})", path.display()));
        }
        let out = descriptor_of(sd).map_err(|e| format!("{}: {e}", path.display()));
        // SAFETY: allocated by GetNamedSecurityInfoW, freed once.
        unsafe {
            let _ = LocalFree(Some(HLOCAL(sd.0)));
        }
        out
    }

    fn check(chain: Vec<(PathBuf, Role)>) -> Result<usize, String> {
        let read = chain
            .into_iter()
            .map(|(p, role)| read_descriptor(&p).map(|d| (p, role, d)))
            .collect::<Result<Vec<_>, String>>()
            .map_err(|e| format!("refused: {e}"))?;
        verdict(&read)?;
        Ok(read.len())
    }

    /// The rule on the real ACLs of `exe`, everything beside it, its folder
    /// and every folder above (the install verb and every service start).
    pub fn check_install(exe: &Path) -> Result<String, String> {
        let folder = exe.parent().ok_or_else(|| format!("refused: {}: no folder", exe.display()))?;
        let entries = std::fs::read_dir(folder)
            .and_then(|it| it.map(|e| e.map(|e| e.path())).collect::<Result<Vec<_>, _>>())
            .map_err(|e| format!("refused: {}: {e}", folder.display()))?;
        let n = check(install_chain(exe, &entries)?)?;
        Ok(format!("{}: only SYSTEM, Administrators and TrustedInstaller can change it ({n} ACLs read)", folder.display()))
    }

    /// [`check_install`] on the running exe: what the install verb and every
    /// service start run.
    pub fn check_this_exe() -> Result<String, String> {
        let exe = std::env::current_exe().map_err(|e| format!("refused: own path: {e}"))?;
        check_install(&exe)
    }

    /// The rule on a folder as an image folder and every folder above it.
    pub fn check_folder(folder: &Path) -> Result<String, String> {
        let n = check(folder_chain(folder))?;
        Ok(format!("{}: only SYSTEM, Administrators and TrustedInstaller can change it ({n} ACLs read)", folder.display()))
    }
}

/// SDDL through the same binary walker as the real ACLs, for tests.
#[cfg(all(windows, test))]
pub(crate) mod tests_support {
    use super::Descriptor;
    use crate::service::acl::SecurityDescriptor;

    pub fn parse_sddl(sddl: &str) -> Descriptor {
        let sd = SecurityDescriptor::from_sddl(sddl).unwrap();
        super::win::descriptor_of(sd.raw()).unwrap()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const AU: &str = "S-1-5-11";
    const BU: &str = "S-1-5-32-545";
    const EVERYONE: &str = "S-1-1-0";
    const AC: &str = "S-1-15-2-1";
    const RAC: &str = "S-1-15-2-2";
    const USER: &str = "S-1-5-21-614836189-3801837370-3127290126-1000";
    // Mapped rights as Windows stores them on effective ACEs.
    const FULL: u32 = 0x001f_01ff;
    const MODIFY: u32 = 0x0013_01bf;
    const READ_EXECUTE: u32 = 0x0012_00a9;
    const GENERIC_READ_EXECUTE: u32 = 0xa000_0000;
    /// SDGXGWGR, the inheritable Modify on `C:\` and `E:\`.
    const GENERIC_MODIFY: u32 = 0xe001_0000;
    const OICI: u8 = OBJECT_INHERIT | CONTAINER_INHERIT;
    const IO: u8 = INHERIT_ONLY;
    const I: u8 = INHERITED;

    fn allow(flags: u8, mask: u32, sid: &str) -> Ace {
        Ace { kind: AceKind::Allow, flags, mask, sid: sid.into() }
    }

    fn deny(flags: u8, mask: u32, sid: &str) -> Ace {
        Ace { kind: AceKind::Deny, flags, mask, sid: sid.into() }
    }

    fn sd(owner: &str, aces: Vec<Ace>) -> Descriptor {
        Descriptor { owner: Some(owner.into()), dacl: Some(aces) }
    }

    /// `C:\` on this machine (Get-Acl, 2026-10-18): Authenticated Users may
    /// add folders (AD) and inherit Modify into new ones.
    fn c_root() -> Descriptor {
        sd(
            TRUSTED_INSTALLER,
            vec![
                allow(0, FILE_APPEND_DATA, AU),
                allow(OICI | IO, GENERIC_MODIFY, AU),
                allow(OICI, FULL, SYSTEM),
                allow(OICI, FULL, ADMINISTRATORS),
                allow(OICI, READ_EXECUTE, BU),
            ],
        )
    }

    /// `C:\Program Files` (Get-Acl, 2026-10-18).
    fn program_files() -> Descriptor {
        sd(
            TRUSTED_INSTALLER,
            vec![
                allow(OICI | IO, GENERIC_ALL, CREATOR_OWNER),
                allow(OICI | IO, GENERIC_ALL, SYSTEM),
                allow(0, MODIFY, SYSTEM),
                allow(OICI | IO, GENERIC_ALL, ADMINISTRATORS),
                allow(0, MODIFY, ADMINISTRATORS),
                allow(OICI | IO, GENERIC_READ_EXECUTE, BU),
                allow(0, READ_EXECUTE, BU),
                allow(CONTAINER_INHERIT | IO, GENERIC_ALL, TRUSTED_INSTALLER),
                allow(0, FULL, TRUSTED_INSTALLER),
                allow(0, READ_EXECUTE, AC),
                allow(OICI | IO, GENERIC_READ_EXECUTE, AC),
                allow(0, READ_EXECUTE, RAC),
                allow(OICI | IO, GENERIC_READ_EXECUTE, RAC),
            ],
        )
    }

    /// `C:\Program Files\Sieve` as an elevated process creates it, with no
    /// lock: owner Administrators, everything inherited from Program Files.
    fn program_files_sieve_default() -> Descriptor {
        sd(
            ADMINISTRATORS,
            vec![
                allow(I, FULL, ADMINISTRATORS),
                allow(OICI | IO | I, GENERIC_ALL, CREATOR_OWNER),
                allow(I, FULL, SYSTEM),
                allow(OICI | IO | I, GENERIC_ALL, SYSTEM),
                allow(OICI | IO | I, GENERIC_ALL, ADMINISTRATORS),
                allow(I, READ_EXECUTE, BU),
                allow(OICI | IO | I, GENERIC_READ_EXECUTE, BU),
                allow(I, FULL, TRUSTED_INSTALLER),
                allow(CONTAINER_INHERIT | IO | I, GENERIC_ALL, TRUSTED_INSTALLER),
                allow(I, READ_EXECUTE, AC),
                allow(OICI | IO | I, GENERIC_READ_EXECUTE, AC),
            ],
        )
    }

    /// A file inheriting from either Program Files folder.
    fn program_files_file() -> Descriptor {
        sd(
            ADMINISTRATORS,
            vec![
                allow(I, FULL, SYSTEM),
                allow(I, FULL, ADMINISTRATORS),
                allow(I, READ_EXECUTE, BU),
                allow(I, READ_EXECUTE, AC),
                allow(I, READ_EXECUTE, RAC),
            ],
        )
    }

    /// `E:\` on this machine (Get-Acl, 2026-10-18).
    fn e_root() -> Descriptor {
        sd(
            SYSTEM,
            vec![
                allow(OICI | IO, GENERIC_MODIFY, AU),
                allow(0, MODIFY, AU),
                allow(0, FULL, SYSTEM),
                allow(OICI | IO, GENERIC_ALL, SYSTEM),
                allow(OICI | IO, GENERIC_ALL, ADMINISTRATORS),
                allow(0, FULL, ADMINISTRATORS),
                allow(0, READ_EXECUTE, BU),
                allow(OICI | IO, GENERIC_READ_EXECUTE, BU),
            ],
        )
    }

    /// `E:\Sieve` as the live install left it: "Authenticated Users:(I)(M)".
    fn e_sieve_inherited() -> Descriptor {
        sd(
            ADMINISTRATORS,
            vec![
                allow(I, MODIFY, AU),
                allow(OICI | IO | I, GENERIC_MODIFY, AU),
                allow(I, FULL, SYSTEM),
                allow(OICI | IO | I, GENERIC_ALL, SYSTEM),
                allow(I, FULL, ADMINISTRATORS),
                allow(OICI | IO | I, GENERIC_ALL, ADMINISTRATORS),
                allow(I, READ_EXECUTE, BU),
                allow(OICI | IO | I, GENERIC_READ_EXECUTE, BU),
            ],
        )
    }

    fn e_sieve_inherited_file() -> Descriptor {
        sd(
            ADMINISTRATORS,
            vec![allow(I, MODIFY, AU), allow(I, FULL, SYSTEM), allow(I, FULL, ADMINISTRATORS), allow(I, READ_EXECUTE, BU)],
        )
    }

    /// `E:\Sieve` after the hook's lock (`acl::INSTALL_DIR_SDDL`): owner
    /// Administrators, protected, SYSTEM and Administrators full control,
    /// Users read and execute, all inherited by what goes inside.
    fn e_sieve_locked() -> Descriptor {
        sd(ADMINISTRATORS, vec![allow(OICI, FULL, SYSTEM), allow(OICI, FULL, ADMINISTRATORS), allow(OICI, READ_EXECUTE, BU)])
    }

    fn e_sieve_locked_file() -> Descriptor {
        sd(ADMINISTRATORS, vec![allow(I, FULL, SYSTEM), allow(I, FULL, ADMINISTRATORS), allow(I, READ_EXECUTE, BU)])
    }

    fn entries(folder: &str, names: &[&str]) -> Vec<PathBuf> {
        names.iter().map(|n| Path::new(folder).join(n)).collect()
    }

    /// Pairs the chain of an install with descriptors given by role: files
    /// (`Image`) get `file`, the folder `folder`, and the rest in order.
    fn installed(exe: &str, names: &[&str], file: Descriptor, folder: Descriptor, above: Vec<Descriptor>) -> Vec<(PathBuf, Role, Descriptor)> {
        let dir = Path::new(exe).parent().unwrap().to_str().unwrap();
        let c = install_chain(Path::new(exe), &entries(dir, names)).unwrap();
        let mut above = above.into_iter();
        c.into_iter()
            .map(|(p, r)| {
                let d = match r {
                    Role::Image => file.clone(),
                    Role::Folder => folder.clone(),
                    Role::Ancestor | Role::Root => above.next().expect("one descriptor per folder above"),
                };
                (p, r, d)
            })
            .collect()
    }

    const INSTALLED: [&str; 4] = ["sieve.exe", "sieve-engine.exe", "uninstall.exe", MARKER_FILE];

    #[test]
    fn the_chain_is_the_exe_the_rest_of_its_folder_the_folder_then_up_to_the_root() {
        let exe = Path::new(r"C:\Program Files\Sieve\sieve-engine.exe");
        let c = install_chain(exe, &entries(r"C:\Program Files\Sieve", &["SIEVE-ENGINE.EXE", "sieve.exe", MARKER_FILE])).unwrap();
        let expect = [
            (r"C:\Program Files\Sieve\sieve-engine.exe", Role::Image),
            (r"C:\Program Files\Sieve\sieve.exe", Role::Image),
            (r"C:\Program Files\Sieve\sieve-install.marker", Role::Image),
            (r"C:\Program Files\Sieve", Role::Folder),
            (r"C:\Program Files", Role::Ancestor),
            (r"C:\", Role::Root),
        ];
        assert_eq!(c, expect.map(|(p, r)| (PathBuf::from(p), r)));
        assert!(install_chain(Path::new("sieve-engine.exe"), &[]).is_err());
    }

    #[test]
    fn a_folder_without_the_installers_marker_is_refused() {
        let why = install_chain(Path::new(r"E:\Sieve\sieve-engine.exe"), &entries(r"E:\Sieve", &["sieve.exe"])).unwrap_err();
        assert!(why.starts_with(r"refused: E:\Sieve holds no sieve-install.marker"), "{why}");
    }

    #[test]
    fn the_program_files_default_is_accepted_unchanged() {
        let c = installed(
            r"C:\Program Files\Sieve\sieve-engine.exe",
            &INSTALLED,
            program_files_file(),
            program_files_sieve_default(),
            vec![program_files(), c_root()],
        );
        assert_eq!(verdict(&c), Ok(()));
    }

    #[test]
    fn a_folder_sieve_locked_on_an_e_drive_is_accepted() {
        let c = installed(r"E:\Sieve\sieve-engine.exe", &INSTALLED, e_sieve_locked_file(), e_sieve_locked(), vec![e_root()]);
        assert_eq!(verdict(&c), Ok(()));
    }

    /// The live finding, 2026-10-18.
    #[test]
    fn an_e_drive_folder_inheriting_authenticated_users_modify_is_refused() {
        let c = installed(
            r"E:\Sieve\sieve-engine.exe",
            &INSTALLED,
            e_sieve_inherited_file(),
            e_sieve_inherited(),
            vec![e_root()],
        );
        let why = verdict(&c).unwrap_err();
        assert!(why.starts_with("refused: "), "{why}");
        assert!(why.contains(r"E:\Sieve\sieve-engine.exe: Authenticated Users (S-1-5-11) may change it (access mask 0x1301bf)"), "{why}");
        assert!(why.contains(r"E:\Sieve: Authenticated Users (S-1-5-11) may change it"), "{why}");
        assert!(why.contains(r"E:\Sieve: Authenticated Users (S-1-5-11) would be able to change every file added later"), "{why}");
        // The root's own Modify is not a reason: a root cannot be renamed.
        assert!(!why.contains(r"E:\: "), "{why}");
    }

    /// A pre-existing folder someone else filled is never locked by the
    /// installer; if Sieve still ended up in it, their files keep their own
    /// owner and the seatbelt refuses.
    #[test]
    fn a_locked_folder_holding_someone_elses_file_is_refused() {
        let mut c = installed(r"E:\Sieve\sieve-engine.exe", &INSTALLED, e_sieve_locked_file(), e_sieve_locked(), vec![e_root()]);
        c.insert(1, (PathBuf::from(r"E:\Sieve\version.dll"), Role::Image, sd(USER, vec![allow(I, FULL, SYSTEM)])));
        let why = verdict(&c).unwrap_err();
        assert!(why.contains(&format!(r"E:\Sieve\version.dll: owned by {USER}, who can rewrite its ACL")), "{why}");
    }

    #[test]
    fn an_explicit_users_write_ace_is_refused_on_the_exe_and_on_its_folder() {
        for role in [Role::Image, Role::Folder] {
            let mut d = program_files_file();
            d.dacl.as_mut().unwrap().push(allow(0, FILE_WRITE_DATA, BU));
            assert_eq!(problems(role, &d), [format!("Users ({BU}) may change it (access mask 0x2)")], "{role:?}");
        }
    }

    #[test]
    fn every_write_right_alone_is_a_grant_and_read_execute_is_not() {
        for right in [
            FILE_WRITE_DATA,
            FILE_APPEND_DATA,
            FILE_WRITE_EA,
            FILE_DELETE_CHILD,
            FILE_WRITE_ATTRIBUTES,
            DELETE,
            WRITE_DAC,
            WRITE_OWNER,
            MAXIMUM_ALLOWED,
            GENERIC_ALL,
            GENERIC_WRITE,
        ] {
            assert_eq!(problems(Role::Image, &sd(SYSTEM, vec![allow(0, right, EVERYONE)])).len(), 1, "{right:#x}");
        }
        assert!(problems(Role::Image, &sd(SYSTEM, vec![allow(0, READ_EXECUTE | GENERIC_READ_EXECUTE, EVERYONE)])).is_empty());
    }

    #[test]
    fn a_deny_ace_is_not_a_grant() {
        let d = sd(SYSTEM, vec![deny(0, FULL, EVERYONE), deny(OICI, MODIFY, AU), allow(0, FULL, SYSTEM)]);
        for role in [Role::Image, Role::Folder, Role::Ancestor, Role::Root] {
            assert!(problems(role, &d).is_empty(), "{role:?}");
        }
        // A deny never cancels a grant: the allow is refused regardless.
        let both = sd(SYSTEM, vec![deny(0, MODIFY, AU), allow(0, MODIFY, AU)]);
        assert_eq!(problems(Role::Image, &both).len(), 1);
    }

    #[test]
    fn trusted_installer_owned_is_accepted_and_a_user_owner_is_refused() {
        let ti = sd(TRUSTED_INSTALLER, vec![allow(0, FULL, TRUSTED_INSTALLER), allow(0, READ_EXECUTE, BU)]);
        for role in [Role::Image, Role::Folder, Role::Ancestor, Role::Root] {
            assert!(problems(role, &ti).is_empty(), "{role:?}");
        }
        let mine = sd(USER, vec![allow(0, FULL, SYSTEM)]);
        assert_eq!(problems(Role::Image, &mine), [format!("owned by {USER}, who can rewrite its ACL")]);
        assert_eq!(problems(Role::Image, &Descriptor { owner: None, dacl: Some(vec![]) }), ["it has no owner"]);
    }

    #[test]
    fn a_user_sid_inherited_grant_is_refused_like_an_explicit_one() {
        for flags in [0, I] {
            assert_eq!(problems(Role::Image, &sd(SYSTEM, vec![allow(flags, MODIFY, USER)])).len(), 1, "flags {flags:#x}");
        }
    }

    #[test]
    fn inheritable_grants_count_on_the_folder_except_creator_owner() {
        let folder = sd(ADMINISTRATORS, vec![allow(OICI | IO, MODIFY, BU)]);
        assert_eq!(
            problems(Role::Folder, &folder),
            [format!("Users ({BU}) would be able to change every file added later (inheritable, access mask 0x1301bf)")]
        );
        // Inherit-only grants nothing on the object itself, and on a folder
        // above ours it only reaches new folders, not the path.
        for role in [Role::Image, Role::Ancestor, Role::Root] {
            assert!(problems(role, &folder).is_empty(), "{role:?}");
        }
        let co = sd(ADMINISTRATORS, vec![allow(OICI | IO, GENERIC_ALL, CREATOR_OWNER)]);
        assert!(problems(Role::Folder, &co).is_empty());
        // CREATOR OWNER on the object itself is still not trusted.
        assert_eq!(problems(Role::Image, &sd(SYSTEM, vec![allow(0, FULL, CREATOR_OWNER)])).len(), 1);
    }

    #[test]
    fn a_folder_above_counts_only_for_rights_that_swap_the_path() {
        // C:\ lets Authenticated Users add folders: harmless to our path.
        assert!(problems(Role::Root, &c_root()).is_empty());
        assert!(problems(Role::Root, &e_root()).is_empty());
        for right in [DELETE, FILE_DELETE_CHILD, WRITE_DAC, WRITE_OWNER, GENERIC_ALL] {
            assert_eq!(problems(Role::Ancestor, &sd(SYSTEM, vec![allow(0, right, AU)])).len(), 1, "{right:#x}");
        }
        for right in [FILE_DELETE_CHILD, WRITE_DAC, WRITE_OWNER, GENERIC_ALL] {
            assert_eq!(problems(Role::Root, &sd(SYSTEM, vec![allow(0, right, AU)])).len(), 1, "{right:#x}");
        }
        assert!(problems(Role::Root, &sd(SYSTEM, vec![allow(0, DELETE, AU)])).is_empty(), "a root cannot be renamed");
        assert!(problems(Role::Ancestor, &sd(SYSTEM, vec![allow(0, FILE_WRITE_DATA | FILE_APPEND_DATA, AU)])).is_empty());
        // The same grant on our own folder is refused (DLL planting).
        assert_eq!(problems(Role::Folder, &sd(SYSTEM, vec![allow(0, FILE_WRITE_DATA, AU)])).len(), 1);
    }

    #[test]
    fn a_folder_above_ours_that_users_can_rename_is_refused() {
        // E:\Apps grants Users Modify, which includes DELETE: E:\Apps can be
        // renamed away and replaced, Sieve's locked folder and all.
        let apps = sd(ADMINISTRATORS, vec![allow(0, MODIFY, BU)]);
        let c = installed(r"E:\Apps\Sieve\sieve-engine.exe", &INSTALLED, e_sieve_locked_file(), e_sieve_locked(), vec![apps, e_root()]);
        let why = verdict(&c).unwrap_err();
        assert!(why.contains(r"E:\Apps: Users (S-1-5-32-545) may change it"), "{why}");
    }

    #[test]
    fn a_null_dacl_and_an_unreadable_ace_are_refused_and_an_empty_dacl_is_not() {
        let null = Descriptor { owner: Some(SYSTEM.into()), dacl: None };
        assert_eq!(problems(Role::Ancestor, &null), ["a NULL DACL gives everybody every right"]);
        let odd = sd(SYSTEM, vec![Ace { kind: AceKind::Unknown(5), flags: 0, mask: 0, sid: String::new() }]);
        assert_eq!(problems(Role::Image, &odd), ["an ACE of type 5 this check cannot read"]);
        assert!(problems(Role::Image, &sd(SYSTEM, vec![])).is_empty());
    }

    #[test]
    fn the_rights_sets_are_what_the_doc_says() {
        assert_eq!(WRITE_RIGHTS, 0x520d_0156);
        assert_eq!(SWAP_RIGHTS, 0x120d_0040);
        assert_eq!(SWAP_RIGHTS & !WRITE_RIGHTS, 0, "swapping the path is a kind of writing");
        assert_ne!(MODIFY & WRITE_RIGHTS, 0);
        assert_ne!(FULL & SWAP_RIGHTS, 0);
        assert_eq!(READ_EXECUTE & WRITE_RIGHTS, 0);
    }

    #[cfg(windows)]
    mod real {
        use super::super::*;
        use super::*;
        use crate::service::acl::{INSTALL_DIR_SDDL, token_user_sid};
        use crate::service::image::tests_support::parse_sddl as win_parse;

        /// The binary walker reads what SDDL says: the live E:\Sieve exe, the
        /// install lock, and a deny and an inherit-only ACE.
        #[test]
        fn the_walker_parses_real_descriptors_into_the_fixtures() {
            let live = "O:BAD:AI(A;ID;0x1301bf;;;AU)(A;ID;FA;;;SY)(A;ID;FA;;;BA)(A;ID;0x1200a9;;;BU)";
            assert_eq!(win_parse(live), e_sieve_inherited_file());
            assert_eq!(win_parse(INSTALL_DIR_SDDL), e_sieve_locked());
            let more = win_parse("O:SYD:(D;;FA;;;WD)(A;OICIIO;GA;;;CO)");
            assert_eq!(more, sd(SYSTEM, vec![deny(0, FULL, EVERYONE), allow(OICI | IO, GENERIC_ALL, CREATOR_OWNER)]));
            assert_eq!(win_parse("O:SYD:NO_ACCESS_CONTROL").dacl, None);
        }

        /// Read only: the real `C:\Program Files`, as an image folder with
        /// `C:\` above it, passes.
        #[test]
        fn the_real_program_files_folder_is_accepted() {
            let pf = std::env::var_os("ProgramFiles").map(PathBuf::from).unwrap();
            let ok = check_folder(&pf).unwrap();
            assert!(ok.contains("2 ACLs read"), "{ok}");
        }

        /// A folder this test creates under %TEMP% is the user's own: refused,
        /// naming the user, even with the installer's marker in it. Nothing
        /// outside it is changed.
        #[test]
        fn a_real_temp_folder_is_refused() {
            let dir = tempfile::tempdir().unwrap();
            let exe = dir.path().join("sieve-engine.exe");
            std::fs::write(&exe, b"not a program").unwrap();
            std::fs::write(dir.path().join(MARKER_FILE), b"").unwrap();
            let me = token_user_sid().unwrap();
            let why = check_folder(dir.path()).unwrap_err();
            assert!(why.starts_with("refused: ") && why.contains(&me), "{why}");
            let why = check_install(&exe).unwrap_err();
            assert!(why.contains(&format!("{}: owned by {me}", exe.display())), "{why}");
            assert!(why.contains(&format!("{}: owned by {me}", dir.path().join(MARKER_FILE).display())), "{why}");
        }

        #[test]
        fn a_missing_marker_or_folder_is_refused_with_its_path() {
            let dir = tempfile::tempdir().unwrap();
            let exe = dir.path().join("sieve-engine.exe");
            std::fs::write(&exe, b"not a program").unwrap();
            let why = check_install(&exe).unwrap_err();
            assert!(why.contains("holds no sieve-install.marker"), "{why}");
            let why = check_install(&dir.path().join(r"gone\sieve-engine.exe")).unwrap_err();
            assert!(why.starts_with("refused: ") && why.contains("gone"), "{why}");
        }
    }
}
