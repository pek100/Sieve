//! Plaintext HTTP/1.x: the Host of the first request on a TCP connection.
//!
//! The stream must start with a known method and a space; anything else is
//! `NotThis`. The request head (up to the blank line) must fit in
//! [`MAX_HEAD`]. The host comes from the `Host` header (case-insensitive
//! name); when there is none, from an absolute-form target
//! (`GET http://host/ HTTP/1.1`, proxy style) or the CONNECT authority. The
//! port and IPv6 brackets are stripped; an IP literal is reported as is
//! (it is still what the flow targets, a rule may match it).

use crate::flow::Progress;

pub const MAX_HEAD: usize = 8 * 1024;

const METHODS: [&str; 9] = ["GET", "POST", "HEAD", "PUT", "DELETE", "OPTIONS", "PATCH", "CONNECT", "TRACE"];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Request {
    pub method: String,
    pub host: String,
}

pub fn parse_request(stream: &[u8]) -> Progress<Request> {
    let method_ok = METHODS.iter().any(|m| {
        let m = m.as_bytes();
        let n = stream.len().min(m.len() + 1);
        let want: Vec<u8> = m.iter().copied().chain(std::iter::once(b' ')).collect();
        stream[..n] == want[..n]
    });
    if !method_ok || stream.is_empty() {
        return Progress::NotThis;
    }
    let Some(head_end) = find(stream, b"\r\n\r\n") else {
        return if stream.len() >= MAX_HEAD {
            Progress::Invalid("request head larger than the cap")
        } else {
            Progress::NeedMore
        };
    };
    let Ok(head) = std::str::from_utf8(&stream[..head_end]) else {
        return Progress::Invalid("request head is not UTF-8");
    };
    let mut lines = head.split("\r\n");
    let request_line = lines.next().unwrap_or_default();
    let mut parts = request_line.split(' ');
    let (Some(method), Some(target), Some(version)) = (parts.next(), parts.next(), parts.next()) else {
        return Progress::Invalid("request line");
    };
    if parts.next().is_some() || !version.starts_with("HTTP/1.") {
        return Progress::Invalid("request line");
    }
    let mut host_header: Option<&str> = None;
    for line in lines {
        let Some((name, value)) = line.split_once(':') else {
            return Progress::Invalid("header line without colon");
        };
        if name.trim().eq_ignore_ascii_case("host") {
            if host_header.is_some() {
                return Progress::Invalid("two Host headers");
            }
            host_header = Some(value.trim());
        }
    }
    let authority = match host_header {
        Some(h) => h,
        None if method == "CONNECT" => target,
        None => match target.split_once("://") {
            Some((_, rest)) => rest.split(['/', '?']).next().unwrap_or_default(),
            None => return Progress::Invalid("no Host header"),
        },
    };
    match host_of(authority) {
        Some(host) => Progress::Done(Request { method: method.to_string(), host }),
        None => Progress::Invalid("Host is not a host name"),
    }
}

/// `host`, `host:port`, `[v6]:port`, `user@host` -> lower-case host.
fn host_of(authority: &str) -> Option<String> {
    let a = authority.rsplit_once('@').map_or(authority, |(_, h)| h);
    if let Some(rest) = a.strip_prefix('[') {
        let (v6, _) = rest.split_once(']')?;
        let ip: std::net::Ipv6Addr = v6.parse().ok()?;
        return Some(ip.to_string());
    }
    let host = a.rsplit_once(':').map_or(a, |(h, port)| if port.bytes().all(|b| b.is_ascii_digit()) { h } else { a });
    crate::flow::sni::host_name(host.as_bytes())
}

fn find(hay: &[u8], needle: &[u8]) -> Option<usize> {
    hay.windows(needle.len()).position(|w| w == needle)
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    fn host(p: Progress<Request>) -> String {
        match p {
            Progress::Done(r) => r.host,
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn host_header_is_found_any_case_with_port_stripped() {
        let req = b"GET /x HTTP/1.1\r\nUser-Agent: curl\r\nhOsT:  WWW.Example.org:8080 \r\n\r\n";
        assert_eq!(host(parse_request(req)), "www.example.org");
    }

    #[test]
    fn every_prefix_needs_more() {
        let req = b"POST /a HTTP/1.1\r\nHost: p.example\r\nContent-Length: 2\r\n\r\nhi";
        for cut in 1..req.len() - 4 {
            assert_eq!(parse_request(&req[..cut]), Progress::NeedMore, "cut {cut}");
        }
        assert_eq!(host(parse_request(req)), "p.example");
    }

    #[test]
    fn absolute_form_and_connect_without_host_header() {
        assert_eq!(host(parse_request(b"GET http://abs.example:81/p?q HTTP/1.1\r\n\r\n")), "abs.example");
        assert_eq!(host(parse_request(b"CONNECT tunnel.example:443 HTTP/1.1\r\n\r\n")), "tunnel.example");
    }

    #[test]
    fn ipv6_and_ip_literals() {
        assert_eq!(host(parse_request(b"GET / HTTP/1.1\r\nHost: [::1]:80\r\n\r\n")), "::1");
        assert_eq!(host(parse_request(b"GET / HTTP/1.1\r\nHost: 10.0.0.1\r\n\r\n")), "10.0.0.1");
    }

    #[test]
    fn not_http_and_invalid() {
        assert_eq!(parse_request(b"\x16\x03\x01"), Progress::NotThis);
        assert_eq!(parse_request(b"GETX / HTTP/1.1\r\n"), Progress::NotThis);
        assert_eq!(parse_request(b""), Progress::NotThis);
        assert!(matches!(parse_request(b"GET / HTTP/1.1\r\n\r\n"), Progress::Invalid(_)));
        assert!(matches!(parse_request(b"GET / HTTP/2\r\nHost: a.b\r\n\r\n"), Progress::Invalid(_)));
        assert!(matches!(parse_request(b"GET / HTTP/1.1\r\nHost: a.b\r\nHost: c.d\r\n\r\n"), Progress::Invalid(_)));
        assert!(matches!(parse_request(b"GET / HTTP/1.1\r\nHost: bad host\r\n\r\n"), Progress::Invalid(_)));
        let mut big = b"GET / HTTP/1.1\r\nX: ".to_vec();
        big.resize(MAX_HEAD, b'a');
        assert!(matches!(parse_request(&big), Progress::Invalid(_)));
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(4096))]
        #[test]
        fn arbitrary_bytes_never_panic(bytes in proptest::collection::vec(any::<u8>(), 0..2000)) {
            let _ = parse_request(&bytes);
            let mut g = b"GET ".to_vec();
            g.extend(&bytes);
            let _ = parse_request(&g);
        }
    }
}
