//! The resolver list as `dns.json` holds it, beside `policy.json`. The same
//! rule as the policy: only a newer revision is taken. A missing file means the
//! defaults; a bad one means the defaults plus a reason. An absent or broken
//! list is never read as plain DNS, or as off. A person may write the file by
//! hand from an admin prompt, so it is read as [`crate::hand_file`] says.

use std::collections::HashSet;
use std::path::Path;

use sieve_ipc::DnsUpstreams;

use super::upstream::{DEFAULTS, MAX_UPSTREAMS, Upstream};
use crate::hand_file;
use crate::policy::write_atomic;

pub const DNS_FILE: &str = "dns.json";
/// [`MAX_UPSTREAMS`] addresses of a few KB each. [`validate`] holds the saved
/// form of a list to it, so a list the pipe accepts is one the next start reads.
pub const FILE_MAX: u64 = 32 * 1024;

/// [`DEFAULTS`], revision 0.
pub fn defaults() -> DnsUpstreams {
    DnsUpstreams { revision: 0, upstreams: DEFAULTS.iter().map(|d| d.url.to_string()).collect() }
}

/// The list as upstreams, or why it is refused. The one normalizer of the list:
/// the pipe and the file both come through here.
pub fn validate(list: &DnsUpstreams) -> Result<Vec<Upstream>, String> {
    if list.upstreams.is_empty() {
        return Err("the encrypted DNS list is empty; plain DNS is never used instead".into());
    }
    if list.upstreams.len() > MAX_UPSTREAMS {
        return Err(format!("the encrypted DNS list holds {}, the limit is {MAX_UPSTREAMS}", list.upstreams.len()));
    }
    if file_form(list)?.len() as u64 > FILE_MAX {
        return Err(format!("the encrypted DNS list is larger than {FILE_MAX} bytes"));
    }
    let parsed = list.upstreams.iter().map(|address| address.parse::<Upstream>().map_err(|why| format!("{address}: {why}"))).collect::<Result<Vec<_>, _>>()?;
    let mut seen = HashSet::new();
    if let Some(repeat) = list.upstreams.iter().zip(&parsed).find(|(_, u)| !seen.insert(u.to_string())) {
        return Err(format!("{}: listed twice", repeat.0));
    }
    Ok(parsed)
}

/// What [`save`] writes.
fn file_form(list: &DnsUpstreams) -> Result<Vec<u8>, String> {
    serde_json::to_vec_pretty(list).map_err(|e| e.to_string())
}

/// `asked`, when it is newer than `current` and valid.
pub fn accept(current: &DnsUpstreams, asked: DnsUpstreams) -> Result<(DnsUpstreams, Vec<Upstream>), String> {
    if asked.revision <= current.revision {
        return Err(format!("stale encrypted DNS revision {} (the engine holds {})", asked.revision, current.revision));
    }
    let parsed = validate(&asked)?;
    Ok((asked, parsed))
}

/// The list and the reason when a present file was not used.
pub fn load(dir: &Path) -> (DnsUpstreams, Option<String>) {
    let path = dir.join(DNS_FILE);
    let bad = |why: String| (defaults(), Some(format!("{}: {why}; read as the defaults", path.display())));
    match hand_file::read_capped(&path, FILE_MAX) {
        Ok(None) => (defaults(), None),
        Err(why) => bad(why),
        Ok(Some(bytes)) => match parse(&bytes) {
            Ok(list) => (list, None),
            Err(why) => bad(why),
        },
    }
}

fn parse(bytes: &[u8]) -> Result<DnsUpstreams, String> {
    let list = serde_json::from_slice(hand_file::content(bytes)?).map_err(|e| e.to_string())?;
    validate(&list)?;
    Ok(list)
}

pub fn save(dir: &Path, list: &DnsUpstreams) -> Result<(), String> {
    write_atomic(&dir.join(DNS_FILE), &file_form(list)?)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn list(revision: u64, upstreams: &[&str]) -> DnsUpstreams {
        DnsUpstreams { revision, upstreams: upstreams.iter().map(|s| s.to_string()).collect() }
    }

    #[test]
    fn an_empty_list_too_long_a_list_or_a_plaintext_address_is_refused_with_its_reason() {
        assert!(validate(&list(1, &[])).unwrap_err().contains("empty"));
        let long: Vec<String> = (0..=MAX_UPSTREAMS).map(|i| format!("tls://{i}.example")).collect();
        let too_long = DnsUpstreams { revision: 1, upstreams: long };
        assert!(validate(&too_long).unwrap_err().contains("limit"));
        for plain in ["1.1.1.1", "udp://1.1.1.1", "http://dns.example/dns-query"] {
            let why = validate(&list(1, &["tls://dns.example", plain])).unwrap_err();
            assert!(why.contains(plain), "{why}");
        }
        assert!(validate(&list(1, &["tls://dns.example", "tls://DNS.example:853"])).unwrap_err().contains("twice"));
        assert_eq!(validate(&list(1, &["tls://dns.example", "quic://[2001:db8::1]"])).unwrap().len(), 2);
    }

    #[test]
    fn the_defaults_are_a_valid_list_at_revision_zero() {
        let d = defaults();
        assert_eq!(d.revision, 0);
        assert_eq!(validate(&d).unwrap().len(), DEFAULTS.len());
    }

    /// The settings stream reads its default from the shared fixture.
    #[test]
    fn the_fixtures_held_list_is_the_defaults() {
        let fixture: serde_json::Value = serde_json::from_str(include_str!("../../../../../src/data/fixtures/engine-ipc-v3.json")).unwrap();
        let held = fixture["engine"].as_array().unwrap().iter().find(|m| m["type"] == "dns_upstreams").unwrap();
        let wire = sieve_ipc::EngineMessage::DnsUpstreams(defaults());
        assert_eq!(&serde_json::to_value(wire).unwrap(), held);
    }

    #[test]
    fn a_missing_file_reads_as_defaults_and_a_bad_file_reads_as_defaults_with_a_reason() {
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(load(dir.path()), (defaults(), None));
        for bad in [&b"garbage"[..], br#"{"revision":3}"#, br#"{"revision":3,"upstreams":[]}"#, br#"{"revision":3,"upstreams":["udp://1.1.1.1"]}"#] {
            std::fs::write(dir.path().join(DNS_FILE), bad).unwrap();
            let (read, why) = load(dir.path());
            assert_eq!(read, defaults());
            assert!(why.unwrap().contains("read as the defaults"));
        }
    }

    /// The runbook's list as Windows PowerShell 5.1 saves it: `Set-Content
    /// -Encoding utf8` and `Out-File -Encoding utf8` write a BOM first.
    #[test]
    fn a_file_with_a_utf8_bom_is_the_list_it_holds() {
        let dir = tempfile::tempdir().unwrap();
        let held = br#"{ "revision": 1, "upstreams": ["https://192.0.2.1/dns-query", "https://dns.example/dns-query"] }"#;
        std::fs::write(dir.path().join(DNS_FILE), [b"\xEF\xBB\xBF".as_slice(), held].concat()).unwrap();
        let (read, why) = load(dir.path());
        assert_eq!(why, None);
        assert_eq!(read, list(1, &["https://192.0.2.1/dns-query", "https://dns.example/dns-query"]));
    }

    #[test]
    fn a_utf16_file_reads_as_the_defaults_and_says_utf16() {
        let dir = tempfile::tempdir().unwrap();
        let text = r#"{"revision":1,"upstreams":["tls://dns.example"]}"#;
        let little: Vec<u8> = [0xFF, 0xFE].into_iter().chain(text.encode_utf16().flat_map(u16::to_le_bytes)).collect();
        let big: Vec<u8> = [0xFE, 0xFF].into_iter().chain(text.encode_utf16().flat_map(u16::to_be_bytes)).collect();
        for bytes in [little, big] {
            std::fs::write(dir.path().join(DNS_FILE), bytes).unwrap();
            let (read, why) = load(dir.path());
            assert_eq!(read, defaults());
            let why = why.unwrap();
            assert!(why.contains("UTF-16") && why.contains(DNS_FILE) && why.contains("read as the defaults"), "{why}");
        }
    }

    #[test]
    fn a_file_over_the_cap_reads_as_the_defaults_and_says_so() {
        let dir = tempfile::tempdir().unwrap();
        let mut bytes = br#"{"revision":1,"upstreams":["tls://dns.example"]}"#.to_vec();
        bytes.resize(FILE_MAX as usize, b' ');
        std::fs::write(dir.path().join(DNS_FILE), &bytes).unwrap();
        assert_eq!(load(dir.path()), (list(1, &["tls://dns.example"]), None), "exactly the cap is read");
        bytes.push(b' ');
        std::fs::write(dir.path().join(DNS_FILE), &bytes).unwrap();
        let (read, why) = load(dir.path());
        assert_eq!(read, defaults());
        assert!(why.unwrap().contains("larger than"));
    }

    /// The cap must not turn a list the pipe accepted into a bad file at the
    /// next start, so the pipe and the file share one limit.
    #[test]
    fn the_largest_list_accepted_is_one_the_next_start_reads() {
        let dir = tempfile::tempdir().unwrap();
        let sized = |extra: usize| {
            let address = format!("https://dns.example/q?{}", "a".repeat(extra));
            DnsUpstreams { revision: 1, upstreams: vec![address] }
        };
        let room = FILE_MAX as usize - file_form(&sized(0)).unwrap().len();
        let largest = sized(room);
        validate(&largest).unwrap();
        save(dir.path(), &largest).unwrap();
        assert_eq!(load(dir.path()), (largest, None));
        assert!(validate(&sized(room + 1)).unwrap_err().contains("larger than"));
    }

    #[test]
    fn a_saved_list_round_trips() {
        let dir = tempfile::tempdir().unwrap();
        let mine = list(4, &["tls://dns.example"]);
        save(dir.path(), &mine).unwrap();
        assert_eq!(load(dir.path()), (mine, None));
    }

    #[test]
    fn an_older_revision_is_refused() {
        let held = list(4, &["tls://dns.example"]);
        assert!(accept(&held, list(4, &["tls://other.example"])).unwrap_err().contains("stale"));
        assert!(accept(&held, list(3, &["tls://other.example"])).unwrap_err().contains("stale"));
        let (taken, parsed) = accept(&held, list(5, &["tls://other.example"])).unwrap();
        assert_eq!((taken.revision, parsed[0].host.as_str()), (5, "other.example"));
    }
}
