//! Browsers first (the user's decision, task D8): only the exes Windows itself
//! declares as browsers are decrypted. Derived from
//! `Clients\StartMenuInternet\*\shell\open\command` under HKLM and each loaded
//! user hive, so there is no list of names (S49). An Electron app is not
//! registered and is not caught; a Tor Browser or a portable build stays
//! undecrypted, which is the safe direction. Read only.

use std::collections::HashSet;

/// Where the registered commands come from.
pub trait BrowserRegistry: Send + Sync {
    fn commands(&self) -> Vec<String>;
}

/// The exes Windows declares as browsers, by full path, case folded.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct BrowserSet(HashSet<String>);

/// The exe of a registered command line: quoted, or up to the first space
/// after `.exe`. A value without an exe declares nothing.
fn exe_of(command: &str) -> Option<String> {
    const EXE: &str = ".exe";
    let command = command.trim();
    let path = match command.strip_prefix('"') {
        Some(rest) => rest.split_once('"')?.0.to_string(),
        None => {
            let lower = command.to_ascii_lowercase();
            command[..lower.find(EXE)? + EXE.len()].to_string()
        }
    };
    path.to_ascii_lowercase().ends_with(EXE).then_some(path)
}

impl BrowserSet {
    pub fn read(registry: &dyn BrowserRegistry) -> Self {
        Self(registry.commands().iter().filter_map(|c| exe_of(c)).map(|p| p.to_ascii_lowercase()).collect())
    }

    /// Compared by full path: a file named `chrome.exe` elsewhere is not Chrome.
    pub fn contains(&self, exe: &str) -> bool {
        self.0.contains(&exe.to_ascii_lowercase())
    }

    /// The full paths, lower case and sorted: what `contains` compares, for the app.
    pub fn paths(&self) -> Vec<String> {
        let mut paths: Vec<String> = self.0.iter().cloned().collect();
        paths.sort();
        paths
    }
}

/// The machine's registry (Windows). Reading is always allowed; each hive that
/// cannot be read simply declares nothing.
#[cfg(windows)]
pub struct WindowsRegistry;

#[cfg(windows)]
mod os {
    use windows::Win32::Foundation::{ERROR_NO_MORE_ITEMS, ERROR_SUCCESS};
    use windows::Win32::System::Registry::{HKEY, HKEY_LOCAL_MACHINE, HKEY_USERS, KEY_READ, RRF_RT_REG_SZ, RegCloseKey, RegEnumKeyExW, RegGetValueW, RegOpenKeyExW};
    use windows::core::{HSTRING, PCWSTR, PWSTR};

    const CLIENTS: &str = r"Software\Clients\StartMenuInternet";
    const COMMAND: &str = r"shell\open\command";
    /// RFC-free but generous: a registry key name is at most 255 characters.
    const NAME_CHARS: usize = 256;
    /// A command line is at most this many characters.
    const VALUE_CHARS: usize = 2_048;

    fn subkeys(root: HKEY, path: &str) -> Vec<String> {
        let mut key = HKEY::default();
        // SAFETY: plain call with an out pointer; the key is closed below.
        if unsafe { RegOpenKeyExW(root, &HSTRING::from(path), None, KEY_READ, &mut key) } != ERROR_SUCCESS {
            return Vec::new();
        }
        let mut names = Vec::new();
        for index in 0u32.. {
            let mut name = [0u16; NAME_CHARS];
            let mut len = NAME_CHARS as u32;
            // SAFETY: the buffer and its length are this frame's.
            let status = unsafe { RegEnumKeyExW(key, index, Some(PWSTR(name.as_mut_ptr())), &mut len, None, None, None, None) };
            if status == ERROR_NO_MORE_ITEMS || status != ERROR_SUCCESS {
                break;
            }
            names.push(String::from_utf16_lossy(&name[..len as usize]));
        }
        // SAFETY: the key was opened above.
        let _ = unsafe { RegCloseKey(key) };
        names
    }

    fn default_value(root: HKEY, path: &str) -> Option<String> {
        let mut value = vec![0u16; VALUE_CHARS];
        let mut bytes = (VALUE_CHARS * 2) as u32;
        // SAFETY: the buffer and its byte length are this frame's.
        let status = unsafe { RegGetValueW(root, &HSTRING::from(path), PCWSTR::null(), RRF_RT_REG_SZ, None, Some(value.as_mut_ptr().cast()), Some(&mut bytes)) };
        if status != ERROR_SUCCESS {
            return None;
        }
        let chars = (bytes as usize / 2).saturating_sub(1);
        Some(String::from_utf16_lossy(&value[..chars]))
    }

    fn commands_under(root: HKEY, prefix: &str, out: &mut Vec<String>) {
        let clients = format!("{prefix}{CLIENTS}");
        for browser in subkeys(root, &clients) {
            out.extend(default_value(root, &format!(r"{clients}\{browser}\{COMMAND}")));
        }
    }

    pub(super) fn commands() -> Vec<String> {
        let mut out = Vec::new();
        commands_under(HKEY_LOCAL_MACHINE, "", &mut out);
        for sid in subkeys(HKEY_USERS, "") {
            commands_under(HKEY_USERS, &format!(r"{sid}\"), &mut out);
        }
        out
    }
}

#[cfg(windows)]
impl BrowserRegistry for WindowsRegistry {
    fn commands(&self) -> Vec<String> {
        os::commands()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Fake(&'static [&'static str]);

    impl BrowserRegistry for Fake {
        fn commands(&self) -> Vec<String> {
            self.0.iter().map(|s| s.to_string()).collect()
        }
    }

    const CHROME: &str = r"C:\Program Files\Google\Chrome\Application\chrome.exe";

    #[test]
    fn browser_set_reads_a_fake_registry() {
        let set = BrowserSet::read(&Fake(&[
            r#""C:\Program Files\Google\Chrome\Application\chrome.exe""#,
            r#""C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe" --single-argument %1"#,
            r"C:\Program Files\Mozilla Firefox\firefox.exe -osint -url %1",
            "not a command",
            r#""C:\unterminated.exe"#,
        ]));
        assert!(set.contains(CHROME));
        assert!(set.contains(r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe"));
        assert!(set.contains(r"c:\program files\mozilla firefox\FIREFOX.EXE"), "case folded");
        assert_eq!(set.0.len(), 3);
    }

    #[test]
    fn browser_match_is_by_full_path() {
        let set = BrowserSet::read(&Fake(&[r#""C:\Program Files\Google\Chrome\Application\chrome.exe""#]));
        assert!(set.contains(CHROME));
        assert!(!set.contains(r"C:\Users\me\Downloads\chrome.exe"), "the same file name elsewhere");
        assert!(!set.contains("chrome.exe"));
        assert!(!BrowserSet::default().contains(CHROME));
    }
}
