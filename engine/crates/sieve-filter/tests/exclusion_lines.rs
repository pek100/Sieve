//! The exclusion line grammar, one table held to both parsers:
//! `src/data/fixtures/exclusion-lines.json` is read here and by
//! `tests/laws/exclusion-lines.test.ts`.

use serde_json::Value;
use sieve_filter::exclusions::{Pattern, parse_line};

const TABLE: &str = include_str!("../../../../src/data/fixtures/exclusion-lines.json");

#[test]
fn every_line_of_the_shared_table_reads_as_it_says() {
    let table: Value = serde_json::from_str(TABLE).unwrap();
    let lines = table["lines"].as_array().unwrap();
    assert!(lines.len() >= 20);
    for case in lines {
        let line = case["line"].as_str().unwrap();
        let got = parse_line(line);
        if let Some(refused) = case["refused"].as_str() {
            assert_eq!(format!("{:?}", got.as_ref().err()), format!("Some({refused})"), "{line}");
            continue;
        }
        let entry = got.unwrap_or_else(|why| panic!("{line}: {why:?}"));
        let (kind, value) = match &entry.pattern {
            Pattern::Subdomains(h) => ("subdomains", h.clone()),
            Pattern::Exact(h) => ("exact", h.clone()),
            Pattern::Wildcard(g) => ("wildcard", g.clone()),
            Pattern::Ip(ip) => ("ip", ip.to_string()),
        };
        assert_eq!(kind, case["kind"].as_str().unwrap(), "{line}");
        assert_eq!(value, case["value"].as_str().unwrap(), "{line}");
        let apps: Vec<&str> = case["apps"].as_array().unwrap().iter().map(|a| a.as_str().unwrap()).collect();
        assert_eq!(entry.apps, apps, "{line}");
    }
}
