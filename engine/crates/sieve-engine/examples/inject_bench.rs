//! The slice 9 budget report (task doc, A9):
//!   cargo run --release -p sieve-engine --example inject_bench
//! Prints time to first output byte (budget 1 ms or less), rewrite throughput on a
//! 1 MB page (100 MB/s or more), and the generic stylesheet's bytes and render
//! time at 30k synthetic selectors. Medians, so a watchdog pause moves them little.

use std::sync::Arc;
use std::time::{Duration, Instant};

use http::{HeaderMap, HeaderValue, Method, StatusCode};
use sieve_engine::inject::{InjectLimits, PageRequest, begin};
use sieve_filter::rules::{ListText, RuleEngine, RuleSet};

const SELECTORS: usize = 30_000;
const SITE_RULES: usize = 2_000;
const RUNS: usize = 31;
const PAGE_BYTES: usize = 1024 * 1024;
const CHUNK_BYTES: usize = 16 * 1024;
const URL: &str = "https://bench.sieve-test.invalid/page";

fn rules_text(extra: &str) -> String {
    let mut text = String::new();
    for i in 0..SELECTORS {
        text.push_str(&format!("##.ad-slot-{i}\n"));
    }
    for i in 0..SITE_RULES {
        text.push_str(&format!("site-{i}.sieve-test.invalid##.site-rule-{i}\n"));
    }
    text.push_str("bench.sieve-test.invalid##.bench-rule\n");
    text.push_str(extra);
    text
}

fn page() -> Vec<u8> {
    let mut page = b"<!doctype html><html><head><meta charset=utf-8><title>t</title></head><body>".to_vec();
    while page.len() < PAGE_BYTES {
        page.extend_from_slice(b"<div class=\"item\"><a href=\"/x\">some ordinary text</a></div>\n");
    }
    page
}

fn median(mut samples: Vec<Duration>) -> Duration {
    samples.sort_unstable();
    samples[samples.len() / 2]
}

fn headers() -> HeaderMap {
    let mut headers = HeaderMap::new();
    headers.insert("content-type", HeaderValue::from_static("text/html; charset=utf-8"));
    headers
}

/// Runs one page: returns time to the first output byte and the whole time.
fn run_once(engine: &RuleSet, body: &[u8]) -> (Duration, Duration, usize) {
    let get = Method::GET;
    let request = PageRequest { url: URL, method: &get, is_document: true };
    let mut response_headers = headers();
    let start = Instant::now();
    let mut rewriter = begin(engine, &request, StatusCode::OK, &mut response_headers, body, &InjectLimits::default()).expect("the page qualifies");
    let mut first = None;
    let mut out_bytes = 0;
    for chunk in body.chunks(CHUNK_BYTES) {
        let out = rewriter.push(chunk).expect("rewrite");
        if first.is_none() && !out.is_empty() {
            first = Some(start.elapsed());
        }
        out_bytes += out.len();
    }
    out_bytes += rewriter.finish().expect("finish").len();
    (first.expect("output appeared"), start.elapsed(), out_bytes)
}

fn main() {
    let compile_start = Instant::now();
    let text = rules_text("");
    let engine = RuleSet { user: Arc::new(RuleEngine::empty()), lists: Arc::new(RuleEngine::compile(&[ListText { id: "bench", text: &text, trusted: true }])) };
    println!("compile, {SELECTORS} generic + {SITE_RULES} site rules: {:?}", compile_start.elapsed());

    let body = page();
    let (mut first, mut whole) = (Vec::new(), Vec::new());
    let mut out_bytes = 0;
    for _ in 0..RUNS {
        let (f, w, o) = run_once(&engine, &body);
        first.push(f);
        whole.push(w);
        out_bytes = o;
    }
    let first = median(first);
    let whole = median(whole);
    println!("time to first output byte: {first:?} (budget 1 ms)");
    let throughput = body.len() as f64 / whole.saturating_sub(first).as_secs_f64() / 1e6;
    println!("whole page: {whole:?}; after the first byte {throughput:.0} MB/s (budget 100 MB/s)");
    println!("output {out_bytes} bytes for a {} byte page", body.len());

    let cosmetics = engine.page_cosmetics(URL);
    println!("generic stylesheet: {} bytes at {SELECTORS} selectors", cosmetics.generic_css.len());

    let mut shared = Vec::new();
    for _ in 0..RUNS {
        let start = Instant::now();
        std::hint::black_box(engine.page_cosmetics(URL));
        shared.push(start.elapsed());
    }
    println!("page_cosmetics, stylesheet shared: {:?}", median(shared));

    let excepted_text = rules_text("bench.sieve-test.invalid#@#.ad-slot-7\n");
    let excepted = RuleEngine::compile(&[ListText { id: "bench", text: &excepted_text, trusted: true }]);
    let mut rendered = Vec::new();
    for _ in 0..RUNS {
        let start = Instant::now();
        let page = excepted.page_cosmetics(URL);
        rendered.push(start.elapsed());
        assert!(!page.generic_css.contains(".ad-slot-7{"));
    }
    println!("page_cosmetics, stylesheet copied minus one exception: {:?}", median(rendered));
}
