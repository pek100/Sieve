//! Slice 9 integration, loopback only: a server on `127.0.0.1:0` serves one
//! fixture page per encoding, with a strict header CSP, a meta CSP and Trusted
//! Types. The response is read over a raw socket and rewritten by the library,
//! as slice 6 will do. Structure is proved by parsing the output; the script is
//! run under node. What a browser does with it stays UNVERIFIED (task doc).

use std::cell::RefCell;
use std::io::Write as _;
use std::process::{Command, Stdio};
use std::rc::Rc;

use http::{HeaderMap, HeaderName, HeaderValue, Method, StatusCode};
use sieve_engine::inject::{InjectLimits, PageRequest, begin};
use sieve_filter::resources::{load_bundle, sha256_hex};
use sieve_filter::rules::{ListText, RuleEngine};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

const PAGE_URL: &str = "https://page.sieve-test.invalid/article";
const BUNDLE: &[u8] = include_bytes!("../../sieve-filter/testdata/resources-fixture.json");
const RULES: &str = "\
##.sieve-generic
page.sieve-test.invalid##.sieve-hidden
page.sieve-test.invalid##.sieve-procedural:has-text(sponsored)
page.sieve-test.invalid##+js(sieve-set-flag, ran, yes)
";
const HEADER_CSP: &str = "default-src 'none'; script-src 'nonce-page' 'strict-dynamic'; style-src 'self'; require-trusted-types-for 'script'";
const HEAD_OPEN: &str = "<head>";
const AFTER_HEAD: &str = r#"<meta http-equiv="Content-Security-Policy" content="default-src 'none'; require-trusted-types-for 'script'"><title>Fixture</title></head>
<body>
<div class="sieve-hidden">hide me</div>
<div class="sieve-generic">hide me too</div>
<div class="sieve-procedural">sponsored</div>
<p>caf&eacute; content</p>
<script nonce="page">var pageScript = "</head><head>";</script>
</body></html>
"#;

fn page() -> String {
    format!("<!doctype html><html lang=\"en\">{HEAD_OPEN}{AFTER_HEAD}")
}

fn engine() -> RuleEngine {
    let mut rules = RuleEngine::compile(&[ListText { id: "fixture", text: RULES, trusted: false }]);
    rules.use_resources(&load_bundle(BUNDLE, &sha256_hex(BUNDLE)).unwrap());
    rules
}

fn compress(encoding: &str, body: &[u8]) -> Vec<u8> {
    use flate2::Compression;
    use flate2::write::{GzEncoder, ZlibEncoder};
    match encoding {
        "" => body.to_vec(),
        "gzip" => {
            let mut e = GzEncoder::new(Vec::new(), Compression::default());
            e.write_all(body).unwrap();
            e.finish().unwrap()
        }
        "deflate" => {
            let mut e = ZlibEncoder::new(Vec::new(), Compression::default());
            e.write_all(body).unwrap();
            e.finish().unwrap()
        }
        "br" => {
            let mut out = Vec::new();
            brotli::CompressorWriter::new(&mut out, 4096, 5, 22).write_all(body).unwrap();
            out
        }
        "zstd" => zstd::stream::encode_all(body, 3).unwrap(),
        other => panic!("no fixture encoder for {other}"),
    }
}

/// Serves the page once per connection, in the encoding the path names.
async fn serve(listener: TcpListener) {
    loop {
        let Ok((mut stream, _)) = listener.accept().await else {
            return;
        };
        tokio::spawn(async move {
            let mut request = Vec::new();
            let mut byte = [0u8; 1];
            while !request.ends_with(b"\r\n\r\n") {
                if stream.read(&mut byte).await.unwrap_or(0) == 0 {
                    return;
                }
                request.push(byte[0]);
            }
            let request = String::from_utf8_lossy(&request).into_owned();
            let path = request.split_whitespace().nth(1).unwrap_or("/");
            let encoding = path.trim_start_matches('/');
            let body = compress(encoding, page().as_bytes());
            let encoding_line = if encoding.is_empty() { String::new() } else { format!("Content-Encoding: {encoding}\r\n") };
            let head = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\n{encoding_line}Content-Length: {}\r\nContent-Security-Policy: {HEADER_CSP}\r\nContent-Security-Policy-Report-Only: {HEADER_CSP}\r\nConnection: close\r\n\r\n",
                body.len()
            );
            // Two writes with the head apart, so the reader sees real chunking.
            let _ = stream.write_all(head.as_bytes()).await;
            let (first, rest) = body.split_at(body.len() / 2);
            let _ = stream.write_all(first).await;
            let _ = stream.flush().await;
            let _ = stream.write_all(rest).await;
        });
    }
}

struct Fetched {
    headers: HeaderMap,
    output: Vec<u8>,
}

/// One response through the library, chunk by chunk as it arrives.
async fn fetch_and_rewrite(port: u16, encoding: &str, rules: &RuleEngine) -> Fetched {
    let mut stream = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    stream.write_all(format!("GET /{encoding} HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n").as_bytes()).await.unwrap();

    let mut received = Vec::new();
    let mut buffer = [0u8; 2048];
    let head_end = loop {
        if let Some(at) = received.windows(4).position(|w| w == b"\r\n\r\n") {
            break at;
        }
        let read = stream.read(&mut buffer).await.unwrap();
        assert_ne!(read, 0, "connection closed inside the head");
        received.extend_from_slice(&buffer[..read]);
    };
    let head = String::from_utf8(received[..head_end].to_vec()).unwrap();
    let mut lines = head.split("\r\n");
    let status: u16 = lines.next().unwrap().split_whitespace().nth(1).unwrap().parse().unwrap();
    let mut headers = HeaderMap::new();
    for line in lines {
        let (name, value) = line.split_once(": ").unwrap();
        headers.append(HeaderName::from_bytes(name.as_bytes()).unwrap(), HeaderValue::from_str(value).unwrap());
    }
    let body_start = received[head_end + 4..].to_vec();

    let get = Method::GET;
    let request = PageRequest { url: PAGE_URL, method: &get, is_document: true };
    let limits = InjectLimits::default();
    let mut rewriter = begin(rules, &request, StatusCode::from_u16(status).unwrap(), &mut headers, &body_start, &limits).expect("the fixture page qualifies");

    let mut output = rewriter.push(&body_start).unwrap();
    loop {
        let read = stream.read(&mut buffer).await.unwrap();
        if read == 0 {
            break;
        }
        output.extend(rewriter.push(&buffer[..read]).unwrap());
    }
    output.extend(rewriter.finish().unwrap());
    Fetched { headers, output }
}

/// What a parser sees in the output.
#[derive(Default)]
struct Parsed {
    elements: Vec<String>,
    style_nonce: Option<String>,
    style_text: String,
    /// Only the first script: ours.
    script_nonce: Option<String>,
    script_text: String,
    scripts_seen: usize,
    hidden_elements: usize,
}

fn parse(html: &str) -> Parsed {
    let parsed = Rc::new(RefCell::new(Parsed::default()));
    let (a, b, c, d) = (parsed.clone(), parsed.clone(), parsed.clone(), parsed.clone());
    lol_html::rewrite_str(
        html,
        lol_html::RewriteStrSettings::new()
            .append_element_content_handler(lol_html::element!("*", move |el| {
                let mut p = a.borrow_mut();
                let tag = el.tag_name();
                if tag == "style" {
                    p.style_nonce = el.get_attribute("nonce");
                }
                if tag == "script" {
                    p.scripts_seen += 1;
                    if p.scripts_seen == 1 {
                        p.script_nonce = el.get_attribute("nonce");
                    }
                }
                if el.get_attribute("class").as_deref() == Some("sieve-hidden") {
                    p.hidden_elements += 1;
                }
                p.elements.push(tag);
                Ok(())
            }))
            .append_element_content_handler(lol_html::text!("style", move |t| {
                b.borrow_mut().style_text.push_str(t.as_str());
                Ok(())
            }))
            .append_element_content_handler(lol_html::text!("script", move |t| {
                let mut p = c.borrow_mut();
                if p.scripts_seen == 1 {
                    p.script_text.push_str(t.as_str());
                }
                Ok(())
            }))
            .append_element_content_handler(lol_html::comments!("*", move |_| {
                let _ = d.borrow();
                Ok(())
            })),
    )
    .unwrap();
    Rc::try_unwrap(parsed).ok().unwrap().into_inner()
}

fn nonce_from(policy: &str) -> String {
    // The page's own nonce is 'nonce-page'; ours is the other one.
    let sources = policy.split(|c: char| c == ';' || c.is_ascii_whitespace());
    let ours: Vec<&str> = sources.filter_map(|s| s.strip_prefix("'nonce-")).filter(|s| *s != "page'").collect();
    assert_eq!(ours.len(), 2, "one nonce each in script-src and style-src: {policy}");
    assert_eq!(ours[0], ours[1], "{policy}");
    ours[0].trim_end_matches('\'').to_string()
}

fn check_rewritten(encoding: &str, fetched: &Fetched) {
    let label = format!("encoding {encoding:?}");
    let html = String::from_utf8(fetched.output.clone()).unwrap();
    let parsed = parse(&html);

    // The header CSP holds every original token, plus the one nonce.
    let policy = fetched.headers.get("content-security-policy").unwrap().to_str().unwrap();
    let nonce = nonce_from(policy);
    let kept: Vec<&str> = policy.split(|c: char| c == ';' || c.is_ascii_whitespace()).collect();
    for token in HEADER_CSP.split(|c: char| c == ';' || c.is_ascii_whitespace()).filter(|t| !t.is_empty()) {
        assert!(kept.contains(&token), "{label}: {token} lost from {policy}");
    }
    assert_eq!(fetched.headers.get("content-security-policy-report-only").unwrap(), HEADER_CSP, "{label}");
    assert!(fetched.headers.get("content-encoding").is_none(), "{label}");
    assert!(fetched.headers.get("content-length").is_none(), "{label}");

    // Both elements come before the meta CSP, and carry that nonce.
    let at = |name: &str| parsed.elements.iter().position(|e| e == name).unwrap_or_else(|| panic!("{label}: no {name} in {html}"));
    assert!(at("head") < at("style") && at("style") < at("script") && at("script") < at("meta"), "{label}: {:?}", parsed.elements);
    assert_eq!(parsed.style_nonce.as_deref(), Some(nonce.as_str()), "{label}");
    assert_eq!(parsed.script_nonce.as_deref(), Some(nonce.as_str()), "{label}");

    // The fixture's hidden class is in the CSS and on an element in the page.
    assert!(parsed.style_text.contains(".sieve-hidden{display:none!important}"), "{label}: {}", parsed.style_text);
    assert!(parsed.style_text.contains(".sieve-generic{display:none!important}"), "{label}: {}", parsed.style_text);
    assert_eq!(parsed.hidden_elements, 1, "{label}");

    // The scriptlet and the applier with its filter are in the script.
    assert!(parsed.script_text.contains("sieveSetFlag(\"ran\", \"yes\")"), "{label}: {}", parsed.script_text);
    assert!(parsed.script_text.contains("sieveRunProcedural(sieveApplier,["), "{label}");

    // Everything after the injection point is byte-identical.
    let script_close = html.find("</script>").unwrap() + "</script>".len();
    assert_eq!(&html[script_close..], AFTER_HEAD, "{label}");
    let start = html.find("<style").unwrap();
    assert!(html[..start].ends_with(HEAD_OPEN), "{label}: {}", &html[..start]);
    assert!(html[..start].starts_with("<!doctype html><html"), "{label}");
}

fn loopback_server() -> (u16, tokio::task::JoinHandle<()>) {
    let std_listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    std_listener.set_nonblocking(true).unwrap();
    let port = std_listener.local_addr().unwrap().port();
    let listener = TcpListener::from_std(std_listener).unwrap();
    (port, tokio::spawn(serve(listener)))
}

#[tokio::test]
async fn every_encoding_gets_the_elements_before_the_meta_csp_with_the_nonce() {
    let (port, server) = loopback_server();
    let rules = engine();
    for encoding in ["", "gzip", "deflate", "br", "zstd"] {
        check_rewritten(encoding, &fetch_and_rewrite(port, encoding, &rules).await);
    }
    server.abort();
}

/// A11: the script a page gets is valid JS and runs. A trust stub stands in for
/// the DOM, so the scriptlet and the applier's load are real, its DOM work not.
#[tokio::test]
async fn the_assembled_script_runs_and_sets_the_scriptlet_flag() {
    let (port, server) = loopback_server();
    let fetched = fetch_and_rewrite(port, "gzip", &engine()).await;
    server.abort();

    let parsed = parse(&String::from_utf8(fetched.output).unwrap());
    const RUNNER: &str = r#"
const vm = require("node:vm");
let code = "";
process.stdin.on("data", (d) => (code += d));
process.stdin.on("end", () => {
  const listeners = [];
  const stub = {
    window: {},
    document: { readyState: "loading", addEventListener: (name) => listeners.push(name) },
  };
  vm.runInNewContext(code, stub);
  console.log(JSON.stringify({ flag: stub.sieveFixture_ran, listeners, leaked: Object.keys(stub).filter((k) => k.startsWith("sieve") && k !== "sieveFixture_ran") }));
});
"#;
    let mut node = Command::new("node")
        .args(["-e", RUNNER])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("node is required for this test and was not found on PATH");
    node.stdin.take().unwrap().write_all(parsed.script_text.as_bytes()).unwrap();
    let output = node.wait_with_output().unwrap();
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(output.status.success(), "the script did not run: {stderr}");
    let result: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(result["flag"], "yes", "{result}");
    assert_eq!(result["listeners"][0], "DOMContentLoaded", "the applier's bootstrap reached its first step: {result}");
    assert_eq!(result["leaked"].as_array().unwrap().len(), 0, "helpers stay out of the page's globals: {result}");
}
