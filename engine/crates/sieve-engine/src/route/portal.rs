//! A sign-in page found without DNS: the second, independent fact of
//! `route::sign_in`.
//!
//! Why it is needed: while the DNS Client capture holds, Windows' own
//! connectivity test (NCSI) resolves its names through Sieve, so whenever
//! encrypted DNS is unreachable Windows says "connected, no internet" and never
//! gets to see a sign-in page. "No internet" then only repeats "encrypted DNS
//! fails", on a portal, on a network that blocks the resolvers and in an outage
//! alike. This check asks the network itself, with no name to look up.
//!
//! How: a plain HTTP request to port 80 of documentation addresses (RFC 5737
//! `192.0.2.1` and `198.51.100.1`, RFC 3849 `2001:db8::1` and `2001:db8::2`),
//! which belong to no one and are routed nowhere on the internet, so on a
//! working network, a network that blocks encrypted DNS and in an outage alike
//! nothing answers. A captive portal intercepts every port-80 connection of a
//! device that has not signed in, whatever its address, and answers it with a
//! redirect to its sign-in page or with the page itself: that, from at least two
//! of the addresses ([`portal`]), is the fact. One answering address alone is no
//! verdict (some odd network routing one of them). The request names Windows'
//! own test, `GET /connecttest.txt` with `Host: www.msftconnecttest.com`, so a
//! transparent proxy that forwards by the Host header fetches Microsoft's real
//! file and reads as online, never as a portal ([`classify`]); a proxy's own
//! error page (4xx, 5xx) is no portal either.
//!
//! Each socket goes out through `stack::egress` (bound to the physical adapter's
//! source and pinned to it, Sieve's routes ignored), so it cannot loop into
//! Sieve's adapter. It runs only while `SignIn::needs_verdict` (encrypted DNS
//! failing, or a notice or pause standing), at most every
//! `sign_in::PORTAL_EVERY`, each address bounded by [`ASK_WITHIN`].
//!
//! What it reveals to the network: that this machine checks for a sign-in page,
//! as Windows itself does on every network. Up to four TCP connections to port
//! 80 of addresses that lead nowhere, from the machine's own address, and on
//! each that connects the same request Windows' own test sends, with no cookie,
//! no user agent and nothing of the user. Nothing leaves when encrypted DNS
//! works.
//!
//! Not seen by it: a portal that only answers DNS with its own address and
//! intercepts nothing else. There no notice shows, and the unreachable-DNS
//! banner keeps saying what is true.

use std::future::Future;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// The addresses asked, two per family (documentation ranges: never routed).
pub const TARGETS: [SocketAddr; 4] = [
    SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)), 80),
    SocketAddr::new(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 1)), 80),
    SocketAddr::new(IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)), 80),
    SocketAddr::new(IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 2)), 80),
];
/// Windows' own test, by name: a proxy that forwards by Host fetches the real one.
pub const TEST_HOST: &str = "www.msftconnecttest.com";
/// The body of Windows' real test file.
pub const EXPECTED: &[u8] = b"Microsoft Connect Test";
/// The whole request: nothing of the user.
pub const REQUEST: &[u8] = b"GET /connecttest.txt HTTP/1.1\r\nHost: www.msftconnecttest.com\r\nConnection: close\r\n\r\n";
/// One address's connect, request and answer, all of it. A portal on the local
/// network answers in milliseconds; an address that leads nowhere is given up.
pub const ASK_WITHIN: Duration = Duration::from_secs(3);
/// At most this much of an answer is read: a status line, headers and the start
/// of a page say all there is to say.
const READ_MAX: usize = 8 * 1024;
/// A 200's body is judged once this much past [`EXPECTED`] came (a chunk-size
/// line, a page's start), or at its Content-Length, or at the end.
const BODY_ENOUGH: usize = EXPECTED.len() + 16;

/// What one address answered.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Answer {
    /// A sign-in page or a redirect to one: something on this network answered
    /// for an address that leads nowhere.
    Portal,
    /// Windows' real test file, or a redirect to its host: a proxy that forwards.
    Online,
    /// No connection, no answer in time, or one that says neither.
    Nothing,
}

/// The network intercepts port 80 for addresses that lead nowhere: at least two
/// addresses answered as a portal, and none as online.
pub fn portal(answers: &[Answer]) -> bool {
    answers.iter().filter(|a| **a == Answer::Portal).count() >= 2 && !answers.contains(&Answer::Online)
}

/// The DNS-free check: every [`TARGETS`] address asked at once through `dial`
/// (the egress in production), each bounded by [`ASK_WITHIN`]; true for a portal
/// ([`portal`]). A dial that fails (no route of that family) is [`Answer::Nothing`].
pub async fn probe<S, F, Fut>(dial: F) -> bool
where
    F: Fn(SocketAddr) -> Fut,
    Fut: Future<Output = Result<S, String>>,
    S: AsyncRead + AsyncWrite + Unpin,
{
    let [a, b, c, d] = TARGETS;
    let (a, b, c, d) = tokio::join!(ask(&dial, a), ask(&dial, b), ask(&dial, c), ask(&dial, d));
    portal(&[a, b, c, d])
}

/// One address: connect, send [`REQUEST`], read until the answer says enough.
pub async fn ask<S, F, Fut>(dial: &F, target: SocketAddr) -> Answer
where
    F: Fn(SocketAddr) -> Fut,
    Fut: Future<Output = Result<S, String>>,
    S: AsyncRead + AsyncWrite + Unpin,
{
    let asked = async {
        let mut stream = dial(target).await.ok()?;
        stream.write_all(REQUEST).await.ok()?;
        let mut reply = Vec::with_capacity(1024);
        let mut chunk = [0u8; 2048];
        loop {
            let n = stream.read(&mut chunk).await.ok()?;
            if n == 0 {
                return Some(classify(&reply));
            }
            reply.extend_from_slice(&chunk[..n.min(READ_MAX - reply.len())]);
            if reply.len() >= READ_MAX || enough(&reply) {
                return Some(classify(&reply));
            }
        }
    };
    tokio::time::timeout(ASK_WITHIN, asked).await.ok().flatten().unwrap_or(Answer::Nothing)
}

/// The head of an answer: status code, Location, Content-Length, chunked; and
/// where the body starts.
struct Head<'a> {
    code: u16,
    location: Option<&'a str>,
    length: Option<usize>,
    chunked: bool,
    body_at: usize,
}

fn head(reply: &[u8]) -> Option<Head<'_>> {
    let end = reply.windows(4).position(|w| w == b"\r\n\r\n")?;
    let text = std::str::from_utf8(&reply[..end]).ok()?;
    let mut lines = text.split("\r\n");
    let mut status = lines.next()?.splitn(3, ' ');
    if !status.next()?.starts_with("HTTP/1.") {
        return None;
    }
    let code = status.next()?.parse().ok()?;
    let mut h = Head { code, location: None, length: None, chunked: false, body_at: end + 4 };
    for line in lines {
        let Some((name, value)) = line.split_once(':') else { continue };
        let (name, value) = (name.trim(), value.trim());
        if name.eq_ignore_ascii_case("location") {
            h.location = Some(value);
        } else if name.eq_ignore_ascii_case("content-length") {
            h.length = value.parse().ok();
        } else if name.eq_ignore_ascii_case("transfer-encoding") {
            h.chunked = value.to_ascii_lowercase().contains("chunked");
        }
    }
    Some(h)
}

/// The answer says enough to be judged before the peer closes.
fn enough(reply: &[u8]) -> bool {
    let Some(h) = head(reply) else { return false };
    let body = reply.len() - h.body_at;
    h.code != 200 || body >= BODY_ENOUGH || h.length.is_some_and(|l| body >= l)
}

/// What one answer says. A 200 is Windows' file or a portal's page; a redirect
/// goes to Windows' test host (a forwarding proxy: online) or elsewhere,
/// relative ones included (a portal serving at the address it took); 511 is the
/// status made for a sign-in (RFC 6585). Anything else, or no HTTP, is nothing.
pub fn classify(reply: &[u8]) -> Answer {
    let Some(h) = head(reply) else { return Answer::Nothing };
    let mut body = &reply[h.body_at..];
    if h.chunked {
        // The first chunk's size line goes before its data.
        body = body.windows(2).position(|w| w == b"\r\n").map_or(&[][..], |at| &body[at + 2..]);
    }
    match h.code {
        200 if body.starts_with(EXPECTED) => Answer::Online,
        200 => Answer::Portal,
        301 | 302 | 303 | 307 | 308 => match h.location {
            None => Answer::Nothing,
            Some(l) if host_of(l).is_some_and(|host| host.eq_ignore_ascii_case(TEST_HOST)) => Answer::Online,
            Some(_) => Answer::Portal,
        },
        511 => Answer::Portal,
        _ => Answer::Nothing,
    }
}

/// The host of an absolute `http(s)://` Location; None for a relative one.
fn host_of(location: &str) -> Option<&str> {
    let lower = location.get(..8).map(str::to_ascii_lowercase).unwrap_or_default();
    let rest = if lower.starts_with("http://") {
        &location[7..]
    } else if lower.starts_with("https://") {
        &location[8..]
    } else {
        return None;
    };
    let authority = rest.split(['/', '?', '#']).next().unwrap_or("");
    let host = authority.rsplit('@').next().unwrap_or("");
    Some(host.split(':').next().unwrap_or(""))
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::sync::{Arc, Mutex};

    use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};

    use super::*;

    const REDIRECT: &[u8] = b"HTTP/1.1 302 Found\r\nLocation: http://portal.hotel.example/login?next=x\r\nContent-Length: 0\r\n\r\n";
    const PAGE: &[u8] = b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<html><body>Welcome to Hotel Wi-Fi, please sign in</body></html>";
    const REAL: &[u8] = b"HTTP/1.1 200 OK\r\nContent-Length: 22\r\nContent-Type: text/plain\r\n\r\nMicrosoft Connect Test";

    #[test]
    fn an_answer_reads_as_a_portal_only_when_it_is_a_page_or_a_redirect_elsewhere() {
        assert_eq!(classify(REDIRECT), Answer::Portal);
        assert_eq!(classify(PAGE), Answer::Portal);
        assert_eq!(classify(b"HTTP/1.1 307 Temporary\r\nLocation: /login\r\n\r\n"), Answer::Portal, "relative: the portal serves at the address it took");
        assert_eq!(classify(b"HTTP/1.0 511 Network Authentication Required\r\n\r\n<a href=x>sign in</a>"), Answer::Portal);
        assert_eq!(classify(REAL), Answer::Online, "a proxy that forwards by Host fetched the real file");
        assert_eq!(classify(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n16\r\nMicrosoft Connect Test\r\n0\r\n\r\n"), Answer::Online, "chunked by a proxy");
        assert_eq!(classify(b"HTTP/1.1 301 Moved\r\nLocation: HTTPS://WWW.msftconnecttest.com:443/connecttest.txt\r\n\r\n"), Answer::Online, "to the test's own host");
        for nothing in [&b"HTTP/1.1 502 Bad Gateway\r\n\r\nupstream unreachable"[..], b"HTTP/1.1 403 Forbidden\r\n\r\n", b"HTTP/1.1 302 Found\r\n\r\n", b"SSH-2.0-OpenSSH\r\n", b"HTTP/1.1 302 Found\r\nLocation: http://x/", b""] {
            assert_eq!(classify(nothing), Answer::Nothing, "{}", String::from_utf8_lossy(nothing));
        }
    }

    #[test]
    fn two_addresses_must_agree_and_none_may_say_online() {
        use Answer::{Nothing, Online, Portal};
        assert!(portal(&[Portal, Portal, Nothing, Nothing]), "an IPv4-only portal");
        assert!(!portal(&[Portal, Nothing, Nothing, Nothing]), "one address alone is no verdict");
        assert!(!portal(&[Portal, Portal, Online, Nothing]), "a forwarding proxy beside it");
        assert!(!portal(&[Nothing; 4]), "a network that blocks encrypted DNS, or an outage: nothing answers for addresses that lead nowhere");
    }

    /// A network as the dial sees it: per address, an answer, or no connection.
    #[derive(Clone, Default)]
    struct Network {
        answers: HashMap<SocketAddr, &'static [u8]>,
        silent: Vec<SocketAddr>,
        asked: Arc<Mutex<Vec<Vec<u8>>>>,
    }

    impl Network {
        fn answering(answer: &'static [u8], at: &[SocketAddr]) -> Self {
            Self { answers: at.iter().map(|a| (*a, answer)).collect(), ..Self::default() }
        }

        async fn dial(&self, target: SocketAddr) -> Result<DuplexStream, String> {
            let silent = self.silent.contains(&target);
            let Some(answer) = self.answers.get(&target).copied() else {
                if silent {
                    // Connected, never answers: the bound gives it up.
                    let (mine, theirs) = tokio::io::duplex(64);
                    tokio::spawn(async move {
                        let _held = theirs;
                        std::future::pending::<()>().await;
                    });
                    return Ok(mine);
                }
                return Err(format!("connect {target}: timeout"));
            };
            let (mine, mut theirs) = tokio::io::duplex(16 * 1024);
            let asked = self.asked.clone();
            tokio::spawn(async move {
                let mut request = vec![0u8; REQUEST.len()];
                if theirs.read_exact(&mut request).await.is_ok() {
                    asked.lock().unwrap().push(request);
                    let _ = theirs.write_all(answer).await;
                }
            });
            Ok(mine)
        }
    }

    async fn probed(network: &Network) -> bool {
        probe(|t| network.dial(t)).await
    }

    /// The four cases of the finding, end to end through the probe.
    #[tokio::test(start_paused = true)]
    async fn a_portal_answers_for_addresses_that_lead_nowhere_and_nothing_else_does() {
        assert!(!probed(&Network::default()).await, "resolvers blocked, plain DNS fine: port 80 to nowhere still goes nowhere");
        assert!(!probed(&Network { silent: TARGETS.to_vec(), ..Network::default() }).await, "an outage, or a firewall that holds the connection: the bound gives up");
        let hotel = Network::answering(REDIRECT, &TARGETS[..2]);
        assert!(probed(&hotel).await, "a real portal, IPv4 only");
        assert!(hotel.asked.lock().unwrap().iter().all(|r| r == REQUEST), "the request and nothing else");
        assert!(probed(&Network::answering(PAGE, &TARGETS)).await, "a portal that serves its page in place");
        assert!(!probed(&Network::answering(REAL, &TARGETS)).await, "a transparent proxy that forwards: online");
        assert!(!probed(&Network::answering(REDIRECT, &TARGETS[..1])).await, "one address alone");
        assert!(!probed(&Network::default()).await, "signed in: the portal lets port 80 through, to nowhere");
    }

    /// A peer that keeps the connection open after a complete answer is judged at once.
    #[tokio::test(start_paused = true)]
    async fn a_complete_answer_is_judged_without_waiting_for_the_close() {
        let (mine, mut theirs) = tokio::io::duplex(4096);
        let slot = Mutex::new(Some(mine));
        let dial = |_t| {
            let s = slot.lock().unwrap().take();
            async move { s.ok_or_else(|| "once".to_string()) }
        };
        let keep = tokio::spawn(async move {
            let mut request = vec![0u8; REQUEST.len()];
            theirs.read_exact(&mut request).await.unwrap();
            theirs.write_all(REAL).await.unwrap();
            std::future::pending::<()>().await;
        });
        let started = tokio::time::Instant::now();
        let answer = ask(&dial, TARGETS[0]).await;
        assert_eq!(answer, Answer::Online);
        assert!(started.elapsed() < ASK_WITHIN, "judged at its Content-Length");
        keep.abort();
    }
}
