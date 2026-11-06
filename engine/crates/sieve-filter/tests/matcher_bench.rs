//! The matcher benchmark (plan 5.3, slice 4). Run in release only:
//!   cargo test -p sieve-filter --release --test matcher_bench -- --ignored --nocapture
//!
//! Offline input is a deterministic generator on `.example` names, so the
//! number is a floor for the matcher's cost and not the plan's acceptance on
//! real data. For the real run, set `SIEVE_BENCH_LISTS` to the engine's
//! `lists` folder (each `<id>.txt` is compiled and its skipped exceptions are
//! printed) and `SIEVE_BENCH_CORPUS` to a file of `url<TAB>type<TAB>initiator`
//! lines. A corpus line is scrubbed before use; nothing here is committed.
//!
//! Heap bytes come from a counting allocator: `sieve-filter` makes no Windows
//! calls, so RSS is a live check. A slow run can be the machine's CPU watchdog
//! suspending the process: report it and rerun, never raise the threshold.

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Instant;

use sieve_filter::rules::{HostVerdict, ListText, RuleEngine, RuleSet};

const P99_LIMIT_NS: u64 = 20_000;
const GENERATED_RULES: usize = 120_000;
const GENERATED_TUPLES: usize = 50_000;
const SITES: usize = 5_000;
const ROUNDS: usize = 3;
const MAX_SHOWN_EXCEPTIONS: usize = 50;
/// A numeric path segment at least this long is reduced to its shape.
const MIN_HEX_SEGMENT: usize = 8;

struct Counting;

static LIVE: AtomicUsize = AtomicUsize::new(0);
static PEAK: AtomicUsize = AtomicUsize::new(0);

// SAFETY: every call forwards to the System allocator unchanged; only counters
// are added.
unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let live = LIVE.fetch_add(layout.size(), Ordering::Relaxed) + layout.size();
        PEAK.fetch_max(live, Ordering::Relaxed);
        // SAFETY: the caller's layout contract passes through.
        unsafe { System.alloc(layout) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        LIVE.fetch_sub(layout.size(), Ordering::Relaxed);
        // SAFETY: `ptr` came from `alloc` above with this layout.
        unsafe { System.dealloc(ptr, layout) }
    }
}

#[global_allocator]
static ALLOCATOR: Counting = Counting;

/// A small deterministic generator (the corpus must not change between runs).
struct Lcg(u64);

impl Lcg {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_mul(6_364_136_223_846_793_005).wrapping_add(1_442_695_040_888_963_407);
        self.0 >> 33
    }

    fn below(&mut self, n: usize) -> usize {
        (self.next() % n as u64) as usize
    }
}

/// Rule shapes in about the proportions of the default lists: mostly host
/// anchors, then constrained hosts, path patterns, exceptions and cosmetics.
fn generated_list(rules: usize) -> String {
    let mut r = Lcg(1);
    let mut out = String::with_capacity(rules * 40);
    for i in 0..rules {
        let site = i % SITES;
        let line = match i % 20 {
            0..=12 => format!("||ads{i}.net{site}.example^"),
            13 => format!("||track{i}.net{site}.example^$third-party"),
            14 => format!("||cdn{site}.example/lib{i}/*$script,domain=site{}.example", r.below(5_000)),
            15 => format!("/banner{i}/*$image"),
            16 => format!("-ad-{i}-"),
            17 => format!("@@||ok{i}.net{site}.example^"),
            18 => format!("||x{i}.net{site}.example^$important"),
            _ => format!("site{site}.example##.ad-{i}"),
        };
        out.push_str(&line);
        out.push('\n');
    }
    out
}

/// A URL reduced to host and path shape: no query, no fragment, numeric and
/// long hex segments replaced (plan 5.3, S27).
fn scrub_url(url: &str) -> String {
    let url = url.split(['?', '#']).next().unwrap_or(url);
    let Some((scheme, rest)) = url.split_once("://") else { return url.to_string() };
    let mut parts = rest.split('/');
    let host = parts.next().unwrap_or_default();
    let path: Vec<String> = parts
        .map(|s| {
            if !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit()) {
                "N".to_string()
            } else if s.len() >= MIN_HEX_SEGMENT && s.bytes().all(|b| b.is_ascii_hexdigit()) {
                "H".to_string()
            } else {
                s.to_string()
            }
        })
        .collect();
    if path.is_empty() { format!("{scheme}://{host}") } else { format!("{scheme}://{host}/{}", path.join("/")) }
}

struct Tuple {
    url: String,
    request_type: String,
    initiator: String,
}

impl Tuple {
    fn host(&self) -> &str {
        self.url.split("://").nth(1).and_then(|r| r.split('/').next()).unwrap_or_default()
    }
}

const TYPES: [&str; 6] = ["script", "image", "stylesheet", "xmlhttprequest", "document", "other"];

/// A mix of blocked hosts, near misses and unrelated names.
fn generated_tuples(n: usize) -> Vec<Tuple> {
    let mut r = Lcg(2);
    (0..n)
        .map(|_| {
            let id = r.below(GENERATED_RULES);
            let site = id % SITES;
            let host = match r.below(4) {
                0 => format!("ads{id}.net{site}.example"),
                1 => format!("cdn{site}.example"),
                _ => format!("www{}.a{}.b.site{site}.example", r.below(9), r.below(99)),
            };
            let path = match r.below(3) {
                0 => format!("banner{id}/a.png"),
                1 => format!("lib{id}/app.js"),
                _ => format!("assets/{}/main.css", r.below(1_000)),
            };
            Tuple { url: format!("https://{host}/{path}"), request_type: TYPES[r.below(TYPES.len())].to_string(), initiator: format!("https://site{}.example/", r.below(5_000)) }
        })
        .collect()
}

fn read_corpus(path: &str) -> Vec<Tuple> {
    std::fs::read_to_string(path)
        .unwrap_or_else(|e| panic!("{path}: {e}"))
        .lines()
        .filter_map(|l| {
            let mut f = l.split('\t');
            Some(Tuple { url: scrub_url(f.next()?), request_type: f.next()?.to_string(), initiator: scrub_url(f.next().unwrap_or_default()) })
        })
        .collect()
}

struct Numbers {
    p50: u64,
    p99: u64,
    max: u64,
}

fn measure(tuples: &[Tuple], mut ask: impl FnMut(&Tuple)) -> Numbers {
    let mut ns = Vec::with_capacity(tuples.len() * ROUNDS);
    for _ in 0..ROUNDS {
        for t in tuples {
            let start = Instant::now();
            ask(t);
            ns.push(u64::try_from(start.elapsed().as_nanos()).unwrap_or(u64::MAX));
        }
    }
    ns.sort_unstable();
    let at = |q: f64| ns[((ns.len() as f64 * q) as usize).min(ns.len() - 1)];
    Numbers { p50: at(0.50), p99: at(0.99), max: *ns.last().unwrap_or(&0) }
}

fn mib(bytes: usize) -> f64 {
    bytes as f64 / (1024.0 * 1024.0)
}

fn list_texts() -> Vec<(String, String)> {
    let Ok(dir) = std::env::var("SIEVE_BENCH_LISTS") else {
        return vec![("generated".to_string(), generated_list(GENERATED_RULES))];
    };
    std::fs::read_dir(&dir)
        .unwrap_or_else(|e| panic!("{dir}: {e}"))
        .flatten()
        .filter(|e| e.path().extension().is_some_and(|x| x == "txt"))
        .map(|e| (e.path().file_stem().unwrap_or_default().to_string_lossy().into_owned(), std::fs::read_to_string(e.path()).unwrap_or_default()))
        .collect()
}

#[test]
#[ignore = "benchmark: run in release with --ignored --nocapture"]
fn matcher_p99_is_under_the_limit() {
    if cfg!(debug_assertions) {
        panic!("a debug build's numbers mean nothing: pass --release");
    }

    let lists = list_texts();
    let before = LIVE.load(Ordering::Relaxed);
    PEAK.store(before, Ordering::Relaxed);
    let compile_started = Instant::now();
    let texts: Vec<ListText<'_>> = lists.iter().map(|(id, text)| ListText { id, text, trusted: true }).collect();
    let engine = RuleEngine::compile(&texts);
    let compile_ms = compile_started.elapsed().as_millis();
    let (live, peak) = (LIVE.load(Ordering::Relaxed) - before, PEAK.load(Ordering::Relaxed) - before);

    let set = RuleSet { user: std::sync::Arc::new(RuleEngine::empty()), lists: std::sync::Arc::new(engine) };
    let reports = set.lists.reports();
    let rules: usize = reports.iter().map(|r| r.network + r.cosmetic).sum();
    println!("rules: {rules} parsed ({} network, {} cosmetic, {} skipped)", reports.iter().map(|r| r.network).sum::<usize>(), reports.iter().map(|r| r.cosmetic).sum::<usize>(), reports.iter().map(|r| r.skipped).sum::<usize>());
    println!("compile: {compile_ms} ms");
    println!("heap: {:.1} MiB live, {:.1} MiB peak (rule text retained for provenance)", mib(live), mib(peak));
    for r in reports {
        println!("list {}: {} network, {} cosmetic, {} skipped, {} skipped exceptions", r.id, r.network, r.cosmetic, r.skipped, r.skipped_exceptions_total);
        for line in r.skipped_exceptions.iter().take(MAX_SHOWN_EXCEPTIONS) {
            println!("  skipped exception: {line}");
        }
    }

    let tuples = match std::env::var("SIEVE_BENCH_CORPUS") {
        Ok(path) => read_corpus(&path),
        Err(_) => generated_tuples(GENERATED_TUPLES),
    };
    println!("corpus: {} tuples", tuples.len());
    let mut blocked = 0usize;
    let host = measure(&tuples, |t| {
        if set.check_host(t.host()).verdict == HostVerdict::Block {
            blocked += 1;
        }
    });
    let url = measure(&tuples, |t| {
        std::hint::black_box(set.lists.check_url(&t.url, &t.initiator, &t.request_type));
    });
    println!("host decisions ({blocked} blocked over {ROUNDS} rounds): p50 {} ns, p99 {} ns, max {} ns", host.p50, host.p99, host.max);
    println!("URL decisions: p50 {} ns, p99 {} ns, max {} ns", url.p50, url.p99, url.max);

    assert!(rules >= 100_000 || std::env::var("SIEVE_BENCH_LISTS").is_ok(), "at least 100k rules on generated input");
    assert!(blocked > 0, "the corpus must exercise the block path");
    assert!(host.p99 < P99_LIMIT_NS, "host p99 {} ns over {P99_LIMIT_NS} ns", host.p99);
    assert!(url.p99 < P99_LIMIT_NS, "URL p99 {} ns over {P99_LIMIT_NS} ns", url.p99);
}

#[test]
fn scrub_url_keeps_only_host_and_path_shape() {
    assert_eq!(scrub_url("https://a.example/x/123/deadbeef01/y?q=secret#frag"), "https://a.example/x/N/H/y");
    assert_eq!(scrub_url("https://a.example"), "https://a.example");
    assert_eq!(scrub_url("https://a.example/?token=abc"), "https://a.example/");
    assert_eq!(scrub_url("https://a.example/abc/cafe"), "https://a.example/abc/cafe", "a short hex-like word stays");
}

#[test]
fn the_generator_is_deterministic_and_large_enough() {
    assert_eq!(generated_list(100), generated_list(100));
    let a = generated_tuples(10);
    let b = generated_tuples(10);
    assert!(a.iter().zip(&b).all(|(x, y)| x.url == y.url));
    assert_eq!(generated_list(GENERATED_RULES).lines().count(), GENERATED_RULES);
    const { assert!(GENERATED_TUPLES >= 50_000) };
}
