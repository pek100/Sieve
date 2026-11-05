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
    use crate::dns::rules::host_name;
    use serde_json::Value;

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

    #[test]
    fn the_domain_table_agrees_with_the_dns_host_rule() {
        let cases = fixture(include_str!("../../src/data/fixtures/user-rules-v1.json"));
        for case in cases["domains"].as_array().expect("domains") {
            let raw = case["raw"].as_str().expect("raw");
            match case["host"].as_str() {
                // A pasted URL is the app's own convenience; the host it gives is what must pass.
                Some(host) => assert_eq!(host_name(host).as_deref(), Ok(host), "{raw}"),
                None => assert!(host_name(raw).is_err(), "{raw}"),
            }
        }
    }
}
