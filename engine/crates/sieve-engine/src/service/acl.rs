//! Access control for what the engine owns, as SDDL (plan 1.3, 1.5, 7.1).
//!
//! - The pipe: SYSTEM and Administrators get full control, the user who
//!   installed Sieve read and write; nobody else is listed, so everybody
//!   else is denied. The DACL is protected (`P`): nothing is inherited.
//! - `ProgramData\Sieve`: owned by Administrators, SYSTEM and Administrators
//!   only, inherited by every folder and file below (`OICI`), protected.
//!
//! - The install folder (whatever the user picked): owner Administrators,
//!   SYSTEM and Administrators full control, Users read and execute,
//!   inherited by everything inside, protected. The installer's hook sets it
//!   with icacls before any file is copied (`src-tauri/windows/hooks.nsh`);
//!   a test runs the hook's own icacls lines and compares the result with
//!   this string. `service::image` checks it held.
//!
//! The strings are built here and tested; [`SecurityDescriptor`] turns one
//! into the binary form Windows takes.

/// Owner Administrators; protected DACL: SYSTEM and Administrators full
/// control, inherited by subfolders and files.
pub const PROGRAM_DATA_SDDL: &str = "O:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)";

/// The install folder's lock: owner Administrators; protected DACL: SYSTEM
/// and Administrators full control, Users read and execute (0x1200a9, what
/// icacls calls RX), inherited by subfolders and files.
pub const INSTALL_DIR_SDDL: &str = "O:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x1200a9;;;BU)";

/// A string SID (`S-1-5-21-...`): `S-1-`, then dash-separated decimal parts.
/// Anything else is refused, so a recorded value can never inject SDDL.
pub fn is_string_sid(sid: &str) -> bool {
    let Some(rest) = sid.strip_prefix("S-1-") else { return false };
    !rest.is_empty() && rest.split('-').all(|p| !p.is_empty() && p.len() <= 10 && p.bytes().all(|b| b.is_ascii_digit()))
}

/// The pipe's DACL. Without a recorded owner only SYSTEM and Administrators
/// may connect.
pub fn pipe_sddl(owner_sid: Option<&str>) -> Result<String, String> {
    let mut sddl = String::from("D:P(A;;GA;;;SY)(A;;GA;;;BA)");
    if let Some(sid) = owner_sid {
        if !is_string_sid(sid) {
            return Err(format!("not a SID: {sid:?}"));
        }
        sddl.push_str(&format!("(A;;GRGW;;;{sid})"));
    }
    Ok(sddl)
}

#[cfg(windows)]
pub use win::{SecurityDescriptor, set_dir_security, token_user_sid};

#[cfg(windows)]
mod win {
    use std::ffi::c_void;
    use std::os::windows::ffi::OsStrExt;
    use std::path::Path;

    use windows::Win32::Foundation::{CloseHandle, HLOCAL, LocalFree};
    use windows::Win32::Security::Authorization::{
        ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1, SE_FILE_OBJECT,
        SetNamedSecurityInfoW,
    };
    use windows::Win32::Security::{
        DACL_SECURITY_INFORMATION, GetSecurityDescriptorDacl, GetSecurityDescriptorOwner, GetTokenInformation,
        OWNER_SECURITY_INFORMATION, PROTECTED_DACL_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, PSID, SECURITY_ATTRIBUTES,
        TOKEN_QUERY, TOKEN_USER, TokenUser,
    };
    use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};
    use windows::core::{PCWSTR, PWSTR};

    fn wide(s: &str) -> Vec<u16> {
        s.encode_utf16().chain(std::iter::once(0)).collect()
    }

    /// A self-relative security descriptor made from SDDL, freed on drop.
    pub struct SecurityDescriptor(PSECURITY_DESCRIPTOR);

    // SAFETY: the descriptor is an immutable block of memory owned by this
    // value; Windows only reads it.
    unsafe impl Send for SecurityDescriptor {}
    unsafe impl Sync for SecurityDescriptor {}

    impl SecurityDescriptor {
        pub fn from_sddl(sddl: &str) -> Result<Self, String> {
            let text = wide(sddl);
            let mut sd = PSECURITY_DESCRIPTOR::default();
            // SAFETY: `text` is NUL-terminated and outlives the call; Windows
            // allocates `sd` with LocalAlloc, freed in Drop.
            unsafe {
                ConvertStringSecurityDescriptorToSecurityDescriptorW(PCWSTR(text.as_ptr()), SDDL_REVISION_1, &mut sd, None)
            }
            .map_err(|e| format!("bad SDDL {sddl:?}: {e}"))?;
            Ok(Self(sd))
        }

        /// The descriptor itself; valid while `self` lives.
        pub fn raw(&self) -> PSECURITY_DESCRIPTOR {
            self.0
        }

        /// SECURITY_ATTRIBUTES pointing at this descriptor; valid while
        /// `self` lives.
        pub fn attributes(&self) -> SECURITY_ATTRIBUTES {
            SECURITY_ATTRIBUTES {
                nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
                lpSecurityDescriptor: self.0.0,
                bInheritHandle: false.into(),
            }
        }
    }

    impl Drop for SecurityDescriptor {
        fn drop(&mut self) {
            // SAFETY: allocated by ConvertStringSecurityDescriptor... with
            // LocalAlloc and freed once.
            unsafe {
                let _ = LocalFree(Some(HLOCAL(self.0.0)));
            }
        }
    }

    /// Sets the owner and the protected DACL of a folder from SDDL.
    pub fn set_dir_security(dir: &Path, sddl: &str) -> Result<(), String> {
        let sd = SecurityDescriptor::from_sddl(sddl)?;
        let mut owner = PSID::default();
        let mut dacl = std::ptr::null_mut();
        let (mut present, mut defaulted) = (false.into(), false.into());
        // SAFETY: `sd` is a valid descriptor; the out pointers point into it.
        unsafe {
            GetSecurityDescriptorOwner(sd.0, &mut owner, &mut defaulted).map_err(|e| e.to_string())?;
            GetSecurityDescriptorDacl(sd.0, &mut present, &mut dacl, &mut defaulted).map_err(|e| e.to_string())?;
        }
        let path: Vec<u16> = dir.as_os_str().encode_wide().chain(std::iter::once(0)).collect();
        let info = OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION;
        // SAFETY: `path` is NUL-terminated; owner and dacl live in `sd`.
        let code = unsafe {
            SetNamedSecurityInfoW(PCWSTR(path.as_ptr()), SE_FILE_OBJECT, info, Some(owner), None, Some(dacl), None)
        };
        if code.is_ok() { Ok(()) } else { Err(format!("SetNamedSecurityInfo {}: {code:?}", dir.display())) }
    }

    /// The string SID of the user this process runs as.
    pub fn token_user_sid() -> Result<String, String> {
        let mut token = Default::default();
        // SAFETY: plain calls; the token handle is closed below.
        unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) }.map_err(|e| e.to_string())?;
        let mut len = 0u32;
        // SAFETY: size probe with no buffer.
        let _ = unsafe { GetTokenInformation(token, TokenUser, None, 0, &mut len) };
        let mut buf = vec![0u8; len as usize];
        // SAFETY: `buf` holds `len` bytes.
        let read = unsafe { GetTokenInformation(token, TokenUser, Some(buf.as_mut_ptr().cast::<c_void>()), len, &mut len) };
        // SAFETY: the handle came from OpenProcessToken and is closed once.
        let _ = unsafe { CloseHandle(token) };
        read.map_err(|e| e.to_string())?;
        // SAFETY: Windows wrote a TOKEN_USER at the start of `buf`.
        let user = unsafe { &*buf.as_ptr().cast::<TOKEN_USER>() };
        let mut text = PWSTR::null();
        // SAFETY: the SID points into `buf`; `text` is LocalAlloc'd, freed below.
        unsafe { ConvertSidToStringSidW(user.User.Sid, &mut text) }.map_err(|e| e.to_string())?;
        // SAFETY: `text` is a NUL-terminated string from Windows.
        let sid = unsafe { text.to_string() }.map_err(|e| e.to_string());
        // SAFETY: freed once.
        unsafe {
            let _ = LocalFree(Some(HLOCAL(text.0.cast())));
        }
        sid
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const USER: &str = "S-1-5-21-1004336348-1177238915-682003330-1001";

    #[test]
    fn pipe_dacl_is_system_admins_and_the_installing_user_only() {
        assert_eq!(pipe_sddl(Some(USER)).unwrap(), format!("D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GRGW;;;{USER})"));
        assert_eq!(pipe_sddl(None).unwrap(), "D:P(A;;GA;;;SY)(A;;GA;;;BA)");
    }

    #[test]
    fn a_recorded_value_that_is_not_a_sid_is_refused() {
        for bad in ["", "S-1-", "S-1-5-", "WD", "S-1-5-21-1)(A;;GA;;;WD", "s-1-5-18", "S-1-5-x", "S-1-5-12345678901"] {
            assert!(pipe_sddl(Some(bad)).is_err(), "{bad:?}");
        }
        assert!(is_string_sid("S-1-5-18"));
    }

    #[test]
    fn program_data_is_admin_owned_admin_only_and_inherited() {
        assert_eq!(PROGRAM_DATA_SDDL, "O:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)");
        assert!(!PROGRAM_DATA_SDDL.contains(";;;BU)") && !PROGRAM_DATA_SDDL.contains(";;;WD)"));
    }

    #[test]
    fn the_install_lock_is_admin_owned_protected_and_users_read_only() {
        assert_eq!(INSTALL_DIR_SDDL, "O:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x1200a9;;;BU)");
        assert!(!INSTALL_DIR_SDDL.contains(";;;AU)") && !INSTALL_DIR_SDDL.contains(";;;WD)"));
    }

    /// The hook's icacls lines, in order, with `$INSTDIR` as `dir`. The
    /// owner line is skipped: an unelevated test cannot give a folder to
    /// Administrators (the verb's check covers the owner).
    #[cfg(windows)]
    fn hook_icacls_lines() -> Vec<String> {
        let hooks = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../src-tauri/windows/hooks.nsh");
        let text = std::fs::read_to_string(&hooks).unwrap();
        let lines: Vec<String> = text
            .lines()
            .filter_map(|l| l.trim().strip_prefix("!insertmacro SIEVE_ICACLS '"))
            .filter_map(|l| l.strip_suffix('\''))
            .map(str::to_string)
            .collect();
        assert_eq!(lines.len(), 4, "the hook locks with four icacls calls: {lines:?}");
        assert_eq!(lines[0], "/setowner *S-1-5-32-544", "owner first");
        lines
    }

    /// Runs the hook's own icacls lines on a folder this test creates under
    /// %TEMP% (nothing else is touched) and reads back exactly the DACL of
    /// INSTALL_DIR_SDDL: the NSIS side and the Rust constant cannot drift.
    #[cfg(windows)]
    #[test]
    fn the_hooks_icacls_lines_give_the_install_lock() {
        use super::super::image::read_descriptor;
        let parent = tempfile::tempdir().unwrap();
        let dir = parent.path().join("Sieve");
        std::fs::create_dir(&dir).unwrap();
        let icacls = std::path::Path::new(&std::env::var_os("SystemRoot").unwrap()).join(r"System32\icacls.exe");
        for line in hook_icacls_lines().iter().skip(1) {
            let out = std::process::Command::new(&icacls).arg(&dir).args(line.split_whitespace()).output().unwrap();
            assert!(out.status.success(), "icacls {line}: {}", String::from_utf8_lossy(&out.stdout));
        }
        // Same ACEs; icacls orders them its own way, which does not matter
        // for a DACL of allow ACEs only.
        let sorted = |d: super::super::image::Descriptor| {
            let mut aces = d.dacl.expect("a DACL");
            aces.sort_by(|a, b| a.sid.cmp(&b.sid));
            aces
        };
        let got = sorted(read_descriptor(&dir).unwrap());
        let want = sorted(super::super::image::tests_support::parse_sddl(INSTALL_DIR_SDDL));
        assert!(want.iter().all(|a| a.kind == super::super::image::AceKind::Allow));
        assert_eq!(got, want);
        // The folder is empty and its parent is ours, so it can be removed.
        std::fs::remove_dir(&dir).unwrap();
    }

    #[cfg(windows)]
    #[test]
    fn windows_accepts_every_sddl_we_build() {
        for sddl in [
            PROGRAM_DATA_SDDL.to_string(),
            INSTALL_DIR_SDDL.to_string(),
            pipe_sddl(Some(USER)).unwrap(),
            pipe_sddl(None).unwrap(),
        ] {
            let sd = SecurityDescriptor::from_sddl(&sddl).unwrap();
            assert!(!sd.attributes().lpSecurityDescriptor.is_null());
        }
        assert!(SecurityDescriptor::from_sddl("D:P(nonsense)").is_err());
    }

    #[cfg(windows)]
    #[test]
    fn the_test_process_has_a_string_sid() {
        assert!(is_string_sid(&token_user_sid().unwrap()));
    }
}
