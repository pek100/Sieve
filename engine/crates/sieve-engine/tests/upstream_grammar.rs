//! Law: the engine and the app read one upstream grammar (plan 1.4, contract
//! C3). The table is the app's fixture; `tests/laws/upstream-grammar.test.ts`
//! feeds the same file to the app's `parseUpstream`.

use sieve_engine::dns::upstream::{MAX_UPSTREAMS, Upstream};

const TABLE: &str = include_str!("../../../../src/data/fixtures/upstream-grammar.json");

fn column(name: &str) -> Vec<String> {
    let table: serde_json::Value = serde_json::from_str(TABLE).expect("the table parses");
    let rows = table[name].as_array().expect("the column is a list");
    assert!(!rows.is_empty(), "{name} is empty: the law would pass vacuously");
    rows.iter().map(|row| row.as_str().expect("a row is a string").to_owned()).collect()
}

#[test]
fn the_table_states_the_engines_limit() {
    let table: serde_json::Value = serde_json::from_str(TABLE).expect("the table parses");
    assert_eq!(table["max"].as_u64(), Some(MAX_UPSTREAMS as u64));
}

#[test]
fn accepts_every_form_the_table_accepts() {
    let wrong: Vec<_> = column("accept").into_iter().filter(|raw| raw.parse::<Upstream>().is_err()).collect();
    assert!(wrong.is_empty(), "refused: {wrong:?}");
}

#[test]
fn refuses_every_form_the_table_refuses() {
    let wrong: Vec<_> = column("refuse").into_iter().filter(|raw| raw.parse::<Upstream>().is_ok()).collect();
    assert!(wrong.is_empty(), "accepted: {wrong:?}");
}
