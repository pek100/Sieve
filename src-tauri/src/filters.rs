//! Filter lists and user rules, the app's read of the engine's knowledge (plan
//! D1, D6). `sieve_filter::catalogue::LISTS` is the one table: this module
//! serialises it, never copies it. Every `report` is null until the engine sends
//! real counts (absent is not zero). `rule_check` asks the engine's own parser
//! about user rules, as untrusted text, so the app has no second parser.

use serde::Serialize;
use sieve_filter::catalogue::{self, LISTS};
use sieve_filter::rules::{ListText, RuleEngine};

const CATALOGUE_VERSION: u32 = 1;
/// The id user rules compile under; reports are keyed by it.
const USER_RULES: &str = "user-rules";

/// What compiling one list did, once the engine reports it.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct ListReport {
    pub applied: usize,
    pub skipped: usize,
    /// The parser's reason to how many rules it skipped.
    pub reasons: std::collections::BTreeMap<String, usize>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct FilterList {
    pub id: &'static str,
    pub title: &'static str,
    pub url: &'static str,
    pub licence: &'static str,
    /// `on`, `off` or `gated` (off until the named slice's live acceptance).
    pub default: &'static str,
    pub trusted: bool,
    /// `ads`, `tracking`, `annoyances`, `security` or `language`.
    pub kind: &'static str,
    /// The lowest profile that turns it on: `minimal`, `balanced`, `strict`, or `optional` for none.
    pub level: &'static str,
    pub description: &'static str,
    pub languages: &'static [&'static str],
    pub report: Option<ListReport>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct FilterCatalogue {
    pub v: u32,
    pub lists: Vec<FilterList>,
}

const fn default_name(d: catalogue::Default) -> &'static str {
    match d {
        catalogue::Default::On => "on",
        catalogue::Default::Off => "off",
        catalogue::Default::Gated(_) => "gated",
    }
}

const fn kind_name(k: catalogue::Kind) -> &'static str {
    match k {
        catalogue::Kind::Ads => "ads",
        catalogue::Kind::Tracking => "tracking",
        catalogue::Kind::Annoyances => "annoyances",
        catalogue::Kind::Security => "security",
        catalogue::Kind::Language => "language",
    }
}

const fn level_name(l: catalogue::Level) -> &'static str {
    match l {
        catalogue::Level::Minimal => "minimal",
        catalogue::Level::Balanced => "balanced",
        catalogue::Level::Strict => "strict",
        catalogue::Level::Optional => "optional",
    }
}

/// The catalogue as the UI reads it.
pub fn catalogue() -> FilterCatalogue {
    let lists = LISTS
        .iter()
        .map(|l| FilterList {
            id: l.id,
            title: l.title,
            url: l.url,
            licence: l.licence,
            default: default_name(l.default),
            trusted: l.trusted,
            kind: kind_name(l.kind),
            level: level_name(l.level),
            description: l.description,
            languages: l.languages,
            report: None,
        })
        .collect();
    FilterCatalogue { v: CATALOGUE_VERSION, lists }
}

/// One rule line the parser refused. `line` counts from 1.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct RuleProblem {
    pub line: usize,
    /// The parser's own words.
    pub reason: String,
}

fn first_skip(text: &str) -> Option<String> {
    let engine = RuleEngine::compile(&[ListText { id: USER_RULES, text, trusted: false }]);
    let report = engine.reports().first()?;
    (report.skipped > 0).then(|| report.skip_reasons.keys().next().cloned().unwrap_or_default())
}

/// What the parser refuses in `lines`. The whole text compiles first and only a
/// text with a refusal is walked line by line.
pub fn rule_problems(lines: &[String]) -> Vec<RuleProblem> {
    if first_skip(&lines.join("\n")).is_none() {
        return Vec::new();
    }
    lines
        .iter()
        .enumerate()
        .filter_map(|(i, line)| first_skip(line).map(|reason| RuleProblem { line: i + 1, reason }))
        .collect()
}

/// The name an imported list starts with: the file's own name, cut to what the
/// engine holds.
fn import_name(path: &std::path::Path) -> String {
    let stem = path.file_stem().map(|s| s.to_string_lossy().trim().to_string()).filter(|s| !s.is_empty()).unwrap_or_else(|| "Imported list".into());
    stem.chars().filter(|c| !c.is_control()).take(sieve_ipc::CUSTOM_TITLE_MAX).collect()
}

/// A file the user picked to import: its name and text, or why it cannot go to
/// the engine. The size is read before the file is, and the words for too large
/// and not UTF-8 are the engine's own (`sieve_filter::lists::judge_text`), so the
/// app explains each refusal one way. The engine judges the rest.
pub fn read_import(path: &std::path::Path) -> Result<(String, String), String> {
    let max = sieve_ipc::MAX_IMPORT_BYTES;
    let len = std::fs::metadata(path).map_err(|e| format!("{}: {e}", path.display()))?.len();
    if len > max as u64 {
        return Err(format!("{len} bytes is over the {max} byte limit"));
    }
    let bytes = std::fs::read(path).map_err(|e| format!("{}: {e}", path.display()))?;
    let text = String::from_utf8(bytes).map_err(|e| format!("not UTF-8: {e}"))?;
    // The longest id there is, so a text that fits here fits under any id.
    let longest = format!("{}{}", sieve_ipc::CUSTOM_LIST_PREFIX, "a".repeat(sieve_ipc::CUSTOM_ID_MAX));
    sieve_ipc::encode(&sieve_ipc::ClientMessage::ListImport { id: longest, text: text.clone() }).map_err(|e| format!("{len} bytes is over the {max} byte limit once written for the engine ({e})"))?;
    Ok((import_name(path), text))
}

#[tauri::command]
pub async fn filter_catalogue() -> Result<FilterCatalogue, String> {
    Ok(catalogue())
}

#[tauri::command]
pub async fn rule_check(lines: Vec<String>) -> Result<Vec<RuleProblem>, String> {
    tauri::async_runtime::spawn_blocking(move || rule_problems(&lines)).await.map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;
    use sieve_filter::rules::{DomainKind, HostVerdict, domain_rule};

    fn fixture(text: &str) -> Value {
        serde_json::from_str(text).expect("fixture json")
    }

    #[test]
    fn the_catalogue_serialises_to_the_fixtures_pending_example_exactly() {
        let lists = fixture(include_str!("../../src/data/fixtures/filter-lists-v1.json"));
        let got = serde_json::to_value(catalogue()).expect("serialise");
        assert_eq!(got, lists["examples"]["pending"]);
        assert!(catalogue().lists.iter().all(|l| l.report.is_none()));
        assert_eq!(catalogue().lists.len(), LISTS.len());
    }

    #[test]
    fn a_picked_file_is_read_by_size_first_and_named_after_itself() {
        let dir = tempfile::tempdir().expect("temp dir");
        let good = dir.path().join("My own list.txt");
        std::fs::write(&good, "! Title: x\n||ads.example^\n").expect("write");
        assert_eq!(read_import(&good).expect("read"), ("My own list".to_string(), "! Title: x\n||ads.example^\n".to_string()));
        let big = dir.path().join("big.txt");
        std::fs::write(&big, vec![b'a'; sieve_ipc::MAX_IMPORT_BYTES + 1]).expect("write");
        assert!(read_import(&big).unwrap_err().contains("byte limit"));
        let binary = dir.path().join("b.txt");
        std::fs::write(&binary, [0xff, 0xfe, 0x00]).expect("write");
        assert!(read_import(&binary).unwrap_err().starts_with("not UTF-8"));
        // Every byte escaped to six on the wire: within the size, over the frame.
        let escaped = dir.path().join("e.txt");
        std::fs::write(&escaped, "\u{1}".repeat(sieve_ipc::MAX_IMPORT_BYTES)).expect("write");
        assert!(read_import(&escaped).unwrap_err().contains("written for the engine"));
        assert!(read_import(&dir.path().join("missing.txt")).is_err());
        assert_eq!(import_name(std::path::Path::new(&format!("{}.txt", "n".repeat(100)))).chars().count(), sieve_ipc::CUSTOM_TITLE_MAX);
    }

    #[test]
    fn the_parser_gives_the_recorded_answer_for_each_user_rule_case() {
        let cases = fixture(include_str!("../../src/data/fixtures/user-rules-v1.json"));
        let rules = cases["rules"].as_array().expect("rules");
        assert!(rules.len() >= 11);
        for case in rules {
            let line = case["line"].as_str().expect("line");
            let got = rule_problems(&[line.to_string()]).first().map(|p| p.reason.clone());
            assert_eq!(got.as_deref(), case["parser"].as_str(), "{line}");
        }
    }

    #[test]
    fn a_refusal_names_its_line_and_a_clean_text_has_none() {
        let lines: Vec<String> = ["! note", "||a.example^", "||bad$unknown-option-xyz", "||b.example^"].map(String::from).to_vec();
        let problems = rule_problems(&lines);
        assert_eq!(problems.len(), 1);
        assert_eq!(problems[0].line, 3);
        assert!(rule_problems(&["||a.example^".to_string()]).is_empty());
        assert!(rule_problems(&[]).is_empty());
    }

    /// What an allowlist entry means, against the engine that will carry it out
    /// (allowRule in src/core/rules.ts; the fixture is the shared table).
    #[test]
    fn an_allowlist_rule_means_what_the_fixture_says_in_a_real_engine() {
        let cases = fixture(include_str!("../../src/data/fixtures/user-rules-v1.json"));
        let allow = &cases["allowlist"];
        let rule = allow["rule"].as_str().expect("rule");
        let table = allow["cases"].as_array().expect("cases");
        assert!(table.len() >= 5);
        for case in table {
            let list = case["list"].as_str().expect("list");
            let ask = case["ask"].as_str().expect("ask");
            let got = RuleEngine::compile(&[
                ListText { id: "list", text: list, trusted: true },
                ListText { id: USER_RULES, text: rule, trusted: false },
            ])
            .check_host(ask).verdict;
            let want = match case["verdict"].as_str().expect("verdict") {
                "allow" => HostVerdict::Allow,
                "block" => HostVerdict::Block,
                other => panic!("verdict {other}"),
            };
            assert_eq!(got, want, "{list} with {rule}, asking {ask}");
        }
    }

    /// What the Filters page's rule form writes (formRules in src/core/rules.ts)
    /// decides in a real engine: with subdomains the host and every name under
    /// it, without them the host alone, for a block and for an allow.
    #[test]
    fn the_rule_forms_lines_decide_what_the_fixture_says_in_a_real_engine() {
        let cases = fixture(include_str!("../../src/data/fixtures/user-rules-v1.json"));
        let table = cases["form"].as_array().expect("form");
        assert!(table.len() >= 4);
        for case in table {
            let rules: Vec<String> = case["rules"].as_array().expect("rules").iter().map(|r| r.as_str().expect("rule").to_string()).collect();
            assert!(rule_problems(&rules).is_empty(), "the parser takes every line: {rules:?}");
            let text = rules.join("\n");
            let list = case["list"].as_str().expect("list");
            let engine = RuleEngine::compile(&[ListText { id: "list", text: list, trusted: true }, ListText { id: USER_RULES, text: &text, trusted: false }]);
            for ask in case["ask"].as_array().expect("ask") {
                let host = ask["host"].as_str().expect("host");
                let want = match ask["verdict"].as_str().expect("verdict") {
                    "block" => HostVerdict::Block,
                    "allow" => HostVerdict::Allow,
                    "none" => HostVerdict::None,
                    other => panic!("verdict {other}"),
                };
                assert_eq!(engine.check_host(host).verdict, want, "{rules:?} over {list:?}, asking {host}");
            }
        }
    }

    /// Why allowRule carries no `$important`: on an exception it wins nothing. The
    /// crate files any exception before it reads the option, and skips exceptions
    /// once an important block matched.
    #[test]
    fn important_on_an_exception_does_not_beat_an_important_block() {
        let got = RuleEngine::compile(&[ListText { id: "list", text: "||a.example^$important\n@@||a.example^$important\n", trusted: true }]);
        assert_eq!(got.check_host("a.example").verdict, HostVerdict::Block);
    }

    #[test]
    fn the_domain_table_agrees_with_the_engines_host_rule() {
        let cases = fixture(include_str!("../../src/data/fixtures/user-rules-v1.json"));
        for case in cases["domains"].as_array().expect("domains") {
            let raw = case["raw"].as_str().expect("raw");
            match case["host"].as_str() {
                // A pasted URL is the app's own convenience; the host it gives is what must pass.
                Some(host) => assert_eq!(domain_rule(host, DomainKind::Block), Some(format!("||{host}^")), "{raw}"),
                // The app's table is the stricter (localhost, a bare IP are its own refusals);
                // what the engine does take is that host alone, never rule syntax.
                None => {
                    if let Some(rule) = domain_rule(raw, DomainKind::Block) {
                        assert_eq!(rule, format!("||{}^", raw.trim().trim_end_matches('.').to_lowercase()), "{raw}");
                    }
                }
            }
        }
    }
}
