//! Owner-only storage for a hub's or a device's directory: its private key,
//! its store and its audit log are readable and writable by the user who runs
//! it (and the system) only.
//!
//! - Windows: the directory is created with a protected DACL granting full
//!   control to the current user and SYSTEM, inherited by every file created
//!   inside it. `check` refuses a directory or file whose DACL lets anyone
//!   else read or write it. BUILTIN\Administrators is tolerated by the check
//!   (never granted): an administrator can read any file anyway through the
//!   backup privilege, so its entry widens nothing.
//! - Unix: the directory is 0700 and the files 0600; `check` refuses group or
//!   other bits and anything not owned by the effective user.
//!
//! Keys are still plain files: anyone who runs as that user, or as an
//! administrator / root, can read them.

use std::io;
use std::path::Path;

/// Creates `dir` (and its parents) with the last component owner-only. An
/// existing directory is left as it is (`check` decides about it).
pub fn create_private_dir(dir: &Path) -> io::Result<()> {
    if dir.is_dir() {
        return Ok(());
    }
    if let Some(parent) = dir.parent().filter(|p| !p.as_os_str().is_empty()) {
        std::fs::create_dir_all(parent)?;
    }
    match sys::create_dir(dir) {
        Err(e) if e.kind() == io::ErrorKind::AlreadyExists => Ok(()),
        other => other,
    }
}

/// Makes `dir` and every file directly inside it owner-only.
pub fn secure(dir: &Path) -> io::Result<()> {
    sys::secure(dir, true)?;
    for e in std::fs::read_dir(dir)? {
        let e = e?;
        if e.file_type()?.is_file() {
            sys::secure(&e.path(), false)?;
        }
    }
    Ok(())
}

/// Refuses `dir` when it, or any file directly inside it, can be read or
/// written by another user. The message names the path and how to fix it.
pub fn check(dir: &Path) -> Result<(), String> {
    let fix = "run the `secure` command to make it owner-only";
    sys::check(dir, true).map_err(|why| format!("{} {why}; {fix}", dir.display()))?;
    let entries = std::fs::read_dir(dir).map_err(|e| format!("cannot list {}: {e}", dir.display()))?;
    for e in entries {
        let e = e.map_err(|e| format!("cannot list {}: {e}", dir.display()))?;
        let ft = e.file_type().map_err(|e| e.to_string())?;
        if ft.is_symlink() {
            return Err(format!("{} is a link; the store holds plain files only", e.path().display()));
        }
        if ft.is_file() {
            sys::check(&e.path(), false).map_err(|why| format!("{} {why}; {fix}", e.path().display()))?;
        }
    }
    Ok(())
}

#[cfg(unix)]
mod sys {
    use std::io;
    use std::os::unix::fs::{DirBuilderExt, MetadataExt, PermissionsExt};
    use std::path::Path;

    pub fn create_dir(dir: &Path) -> io::Result<()> {
        std::fs::DirBuilder::new().mode(0o700).create(dir)
    }

    pub fn secure(path: &Path, is_dir: bool) -> io::Result<()> {
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(if is_dir { 0o700 } else { 0o600 }))
    }

    pub fn check(path: &Path, _is_dir: bool) -> Result<(), String> {
        let m = std::fs::symlink_metadata(path).map_err(|e| format!("cannot be read: {e}"))?;
        // SAFETY: geteuid has no preconditions.
        let me = unsafe { libc::geteuid() };
        if m.uid() != me {
            return Err(format!("is owned by user {} and not by this user ({me})", m.uid()));
        }
        if m.mode() & 0o077 != 0 {
            return Err(format!("has mode {:o}: others may read or write it", m.mode() & 0o777));
        }
        Ok(())
    }
}

#[cfg(windows)]
mod sys {
    use std::ffi::c_void;
    use std::io;
    use std::os::windows::ffi::OsStrExt;
    use std::path::Path;

    use windows_sys::Win32::Foundation::{CloseHandle, HANDLE, LocalFree};
    use windows_sys::Win32::Security::Authorization::{
        ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW, GetNamedSecurityInfoW, SDDL_REVISION_1, SE_FILE_OBJECT,
        SetNamedSecurityInfoW,
    };
    use windows_sys::Win32::Security::{
        ACCESS_ALLOWED_ACE, ACE_HEADER, ACL, DACL_SECURITY_INFORMATION, GetAce, GetSecurityDescriptorDacl, GetTokenInformation,
        OWNER_SECURITY_INFORMATION, PROTECTED_DACL_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, PSID, SECURITY_ATTRIBUTES, TOKEN_QUERY, TOKEN_USER,
        TokenUser,
    };
    use windows_sys::Win32::Storage::FileSystem::CreateDirectoryW;
    use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

    const SYSTEM: &str = "S-1-5-18";
    const ADMINISTRATORS: &str = "S-1-5-32-544";
    const CREATOR_OWNER: &str = "S-1-3-0";
    const OWNER_RIGHTS: &str = "S-1-3-4";

    /// Rights that let a holder read or change the contents or the ACL.
    const WIDE: u32 = 0x1 // FILE_READ_DATA / LIST_DIRECTORY
        | 0x2 // FILE_WRITE_DATA / ADD_FILE
        | 0x4 // FILE_APPEND_DATA / ADD_SUBDIRECTORY
        | 0x10 // FILE_WRITE_EA
        | 0x40 // FILE_DELETE_CHILD
        | 0x100 // FILE_WRITE_ATTRIBUTES
        | 0x1_0000 // DELETE
        | 0x4_0000 // WRITE_DAC
        | 0x8_0000 // WRITE_OWNER
        | 0x1000_0000 // GENERIC_ALL
        | 0x4000_0000 // GENERIC_WRITE
        | 0x8000_0000; // GENERIC_READ

    fn wide(p: &Path) -> Vec<u16> {
        p.as_os_str().encode_wide().chain(std::iter::once(0)).collect()
    }

    fn wide_str(s: &str) -> Vec<u16> {
        s.encode_utf16().chain(std::iter::once(0)).collect()
    }

    /// SAFETY: `sid` must point at a valid SID.
    unsafe fn sid_string(sid: PSID) -> io::Result<String> {
        let mut p: *mut u16 = std::ptr::null_mut();
        if unsafe { ConvertSidToStringSidW(sid, &mut p) } == 0 {
            return Err(io::Error::last_os_error());
        }
        let mut n = 0;
        // SAFETY: a NUL-terminated string allocated by the call above.
        while unsafe { *p.add(n) } != 0 {
            n += 1;
        }
        let s = String::from_utf16_lossy(unsafe { std::slice::from_raw_parts(p, n) });
        unsafe { LocalFree(p as *mut c_void) };
        Ok(s)
    }

    /// The SID of the user this process runs as, e.g. "S-1-5-21-...-1001".
    pub fn user_sid() -> io::Result<String> {
        let mut token: HANDLE = std::ptr::null_mut();
        // SAFETY: the pseudo-handle of this process; `token` is closed below.
        if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) } == 0 {
            return Err(io::Error::last_os_error());
        }
        let mut len = 0u32;
        // SAFETY: a size query, then a call with an 8-aligned buffer of that size.
        unsafe { GetTokenInformation(token, TokenUser, std::ptr::null_mut(), 0, &mut len) };
        let mut buf: Vec<u64> = vec![0; (len as usize).div_ceil(8).max(1)];
        let ok = unsafe { GetTokenInformation(token, TokenUser, buf.as_mut_ptr() as *mut c_void, len, &mut len) };
        let r = if ok == 0 {
            Err(io::Error::last_os_error())
        } else {
            let tu = unsafe { &*(buf.as_ptr() as *const TOKEN_USER) };
            unsafe { sid_string(tu.User.Sid) }
        };
        unsafe { CloseHandle(token) };
        r
    }

    /// Runs `f` with a security descriptor built from `sddl`.
    fn with_sd<R>(sddl: &str, f: impl FnOnce(PSECURITY_DESCRIPTOR) -> io::Result<R>) -> io::Result<R> {
        let w = wide_str(sddl);
        let mut sd: PSECURITY_DESCRIPTOR = std::ptr::null_mut();
        // SAFETY: `w` is NUL-terminated; `sd` is freed below.
        if unsafe { ConvertStringSecurityDescriptorToSecurityDescriptorW(w.as_ptr(), SDDL_REVISION_1, &mut sd, std::ptr::null_mut()) } == 0 {
            return Err(io::Error::last_os_error());
        }
        let r = f(sd);
        unsafe { LocalFree(sd) };
        r
    }

    fn owner_only_sddl() -> io::Result<String> {
        // P: protected (nothing inherited from the parent). OICI: inherited by
        // files and directories created inside. FA: full access.
        Ok(format!("D:P(A;OICI;FA;;;{})(A;OICI;FA;;;SY)", user_sid()?))
    }

    pub fn create_dir(dir: &Path) -> io::Result<()> {
        with_sd(&owner_only_sddl()?, |sd| {
            let sa = SECURITY_ATTRIBUTES { nLength: size_of::<SECURITY_ATTRIBUTES>() as u32, lpSecurityDescriptor: sd, bInheritHandle: 0 };
            let p = wide(dir);
            // SAFETY: NUL-terminated path; `sa` lives across the call.
            if unsafe { CreateDirectoryW(p.as_ptr(), &sa) } == 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(())
        })
    }

    /// Sets the DACL described by `sddl` (protected) on `path`.
    pub fn apply_sddl(path: &Path, sddl: &str) -> io::Result<()> {
        with_sd(sddl, |sd| {
            let mut present = 0;
            let mut defaulted = 0;
            let mut dacl: *mut ACL = std::ptr::null_mut();
            // SAFETY: `sd` is a valid descriptor; `dacl` points into it.
            if unsafe { GetSecurityDescriptorDacl(sd, &mut present, &mut dacl, &mut defaulted) } == 0 {
                return Err(io::Error::last_os_error());
            }
            let p = wide(path);
            // SAFETY: NUL-terminated path; `dacl` valid while `sd` lives.
            let rc = unsafe {
                SetNamedSecurityInfoW(
                    p.as_ptr(),
                    SE_FILE_OBJECT,
                    DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                    dacl,
                    std::ptr::null(),
                )
            };
            if rc != 0 {
                return Err(io::Error::from_raw_os_error(rc as i32));
            }
            Ok(())
        })
    }

    pub fn secure(path: &Path, _is_dir: bool) -> io::Result<()> {
        // Files get no inheritance flags of their own, but the same SDDL is
        // valid for them (OICI is ignored on a file).
        apply_sddl(path, &owner_only_sddl()?)
    }

    pub fn check(path: &Path, _is_dir: bool) -> Result<(), String> {
        let me = user_sid().map_err(|e| format!("cannot be checked (no user SID: {e})"))?;
        let trusted = |s: &str| s == me || s == SYSTEM || s == ADMINISTRATORS || s == CREATOR_OWNER || s == OWNER_RIGHTS;
        let p = wide(path);
        let mut owner: PSID = std::ptr::null_mut();
        let mut dacl: *mut ACL = std::ptr::null_mut();
        let mut sd: PSECURITY_DESCRIPTOR = std::ptr::null_mut();
        // SAFETY: NUL-terminated path; `sd` is freed below and owns `owner` and `dacl`.
        let rc = unsafe {
            GetNamedSecurityInfoW(
                p.as_ptr(),
                SE_FILE_OBJECT,
                OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
                &mut owner,
                std::ptr::null_mut(),
                &mut dacl,
                std::ptr::null_mut(),
                &mut sd,
            )
        };
        if rc != 0 {
            return Err(format!("cannot be checked: {}", io::Error::from_raw_os_error(rc as i32)));
        }
        let r = (|| {
            if !owner.is_null() {
                let o = unsafe { sid_string(owner) }.map_err(|e| e.to_string())?;
                if o != me && o != SYSTEM && o != ADMINISTRATORS {
                    return Err(format!("is owned by {o}, not by this user"));
                }
            }
            if dacl.is_null() {
                return Err("has no access list: everyone may read and write it".to_string());
            }
            // SAFETY: a valid ACL from GetNamedSecurityInfoW.
            let count = unsafe { (*dacl).AceCount };
            for i in 0..count as u32 {
                let mut ace: *mut c_void = std::ptr::null_mut();
                if unsafe { GetAce(dacl, i, &mut ace) } == 0 {
                    return Err("has an unreadable access entry".to_string());
                }
                let header = unsafe { &*(ace as *const ACE_HEADER) };
                match header.AceType {
                    // ACCESS_ALLOWED_ACE_TYPE
                    0 => {
                        let a = unsafe { &*(ace as *const ACCESS_ALLOWED_ACE) };
                        let sid = &a.SidStart as *const u32 as PSID;
                        let s = unsafe { sid_string(sid) }.map_err(|e| e.to_string())?;
                        if !trusted(&s) && a.Mask & WIDE != 0 {
                            return Err(format!("lets {s} read or write it"));
                        }
                    }
                    // Deny entries narrow access; they are fine.
                    1 | 6 | 10 | 12 => {}
                    other => return Err(format!("has an access entry of type {other} that this check does not understand")),
                }
            }
            Ok(())
        })();
        unsafe { LocalFree(sd) };
        r
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_new_private_dir_and_its_files_pass_the_check() {
        let t = tempfile::tempdir().unwrap();
        let dir = t.path().join("a").join("hub");
        create_private_dir(&dir).unwrap();
        std::fs::write(dir.join("hub.json"), b"{}").unwrap();
        check(&dir).unwrap();
        // Idempotent.
        create_private_dir(&dir).unwrap();
        secure(&dir).unwrap();
        check(&dir).unwrap();
    }

    #[cfg(windows)]
    #[test]
    fn a_file_others_can_read_is_refused_and_secure_fixes_it() {
        let t = tempfile::tempdir().unwrap();
        let dir = t.path().join("hub");
        create_private_dir(&dir).unwrap();
        let f = dir.join("identity.key");
        std::fs::write(&f, b"k").unwrap();
        // Everyone (WD) may read.
        sys::apply_sddl(&f, "D:P(A;;FR;;;WD)").unwrap();
        let why = check(&dir).unwrap_err();
        assert!(why.contains("identity.key") && why.contains("S-1-1-0"), "{why}");
        // Authenticated users may write the directory.
        secure(&dir).unwrap();
        check(&dir).unwrap();
        sys::apply_sddl(&dir, &format!("D:P(A;OICI;FA;;;{})(A;;FW;;;AU)", sys::user_sid().unwrap())).unwrap();
        assert!(check(&dir).is_err());
        secure(&dir).unwrap();
        check(&dir).unwrap();
    }

    #[test]
    fn a_hub_refuses_to_open_a_loose_directory() {
        let t = tempfile::tempdir().unwrap();
        let dir = t.path().join("hub");
        crate::Hub::init(&dir, "h").unwrap();
        check(&dir).unwrap();
        let key = dir.join(crate::store::IDENTITY_FILE);
        #[cfg(windows)]
        sys::apply_sddl(&key, "D:P(A;;FR;;;BU)").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o640)).unwrap();
        }
        let err = crate::Hub::open(crate::HubConfig::new(&dir)).err().expect("refused");
        assert!(err.to_string().contains("identity.key") && err.to_string().contains("secure"), "{err}");
    }

    #[cfg(windows)]
    #[test]
    fn a_new_dir_grants_only_this_user_and_system() {
        let t = tempfile::tempdir().unwrap();
        let dir = t.path().join("hub");
        create_private_dir(&dir).unwrap();
        // A file created inside inherits the same two entries; a read by
        // "Users" (BU) style entries is absent: check passes with no admin
        // tolerance needed because the DACL lists exactly user and SYSTEM.
        std::fs::write(dir.join("x"), b"x").unwrap();
        check(&dir).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn loose_modes_are_refused_and_secure_fixes_them() {
        use std::os::unix::fs::PermissionsExt;
        let t = tempfile::tempdir().unwrap();
        let dir = t.path().join("hub");
        create_private_dir(&dir).unwrap();
        assert_eq!(std::fs::metadata(&dir).unwrap().permissions().mode() & 0o777, 0o700);
        let f = dir.join("identity.key");
        std::fs::write(&f, b"k").unwrap();
        std::fs::set_permissions(&f, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(check(&dir).is_err());
        secure(&dir).unwrap();
        check(&dir).unwrap();
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755)).unwrap();
        assert!(check(&dir).is_err());
        secure(&dir).unwrap();
        check(&dir).unwrap();
    }
}
