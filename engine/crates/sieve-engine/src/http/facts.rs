//! What one request is, for the rules, the log and the content hook (plan 5.2,
//! task D13): `Sec-Fetch-Dest` where the browser says, else `Accept` and the
//! extension. The one owner of these facts (S29).

use ::http::header::{ACCEPT, HOST, ORIGIN, REFERER, UPGRADE};
use ::http::{HeaderMap, Request};

const DEST: &str = "sec-fetch-dest";
const MODE: &str = "sec-fetch-mode";
const WEBSOCKET: &str = "websocket";
const DOCUMENT: &str = "document";
const NO_ORIGIN: &str = "null";

/// A request as the rule engine and the content hook read it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RequestFacts<'a> {
    pub url: &'a str,
    pub method: &'a str,
    pub is_document: bool,
    /// adblock's request type.
    pub request_type: &'a str,
    /// The page that made it; empty for a navigation.
    pub initiator: &'a str,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OwnedFacts {
    pub url: String,
    pub method: String,
    pub request_type: &'static str,
    pub initiator: String,
}

impl OwnedFacts {
    pub fn borrowed(&self) -> RequestFacts<'_> {
        RequestFacts { url: &self.url, method: &self.method, is_document: self.request_type == DOCUMENT, request_type: self.request_type, initiator: &self.initiator }
    }
}

fn header(headers: &HeaderMap, name: impl ::http::header::AsHeaderName) -> Option<&str> {
    headers.get(name).and_then(|v| v.to_str().ok()).map(str::trim)
}

/// `Sec-Fetch-Dest`, per the Fetch standard's list of destinations; `empty` is
/// what `fetch`, XHR and beacons send.
fn from_dest(dest: &str) -> Option<&'static str> {
    Some(match dest {
        DOCUMENT => DOCUMENT,
        "iframe" | "frame" | "fencedframe" => "sub_frame",
        "script" | "worker" | "sharedworker" | "serviceworker" | "audioworklet" | "paintworklet" => "script",
        "style" | "xslt" => "stylesheet",
        "image" => "image",
        "font" => "font",
        "audio" | "video" | "track" => "media",
        "object" | "embed" => "object",
        "report" => "ping",
        "manifest" => "other",
        "empty" | "webidentity" => "xhr",
        WEBSOCKET => WEBSOCKET,
        _ => return None,
    })
}

fn from_accept(accept: &str) -> Option<&'static str> {
    let first = accept.split(',').next().unwrap_or("").trim().split(';').next().unwrap_or("").trim();
    Some(match first {
        "text/html" | "application/xhtml+xml" => DOCUMENT,
        "text/css" => "stylesheet",
        "application/javascript" | "text/javascript" => "script",
        "application/json" => "xhr",
        _ if first.starts_with("image/") => "image",
        _ if first.starts_with("font/") => "font",
        _ if first.starts_with("audio/") || first.starts_with("video/") => "media",
        _ => return None,
    })
}

fn from_extension(path: &str) -> Option<&'static str> {
    let file = path.split(['?', '#']).next().unwrap_or(path).rsplit('/').next().unwrap_or("");
    let (_, extension) = file.rsplit_once('.')?;
    Some(match extension.to_ascii_lowercase().as_str() {
        "js" | "mjs" => "script",
        "css" => "stylesheet",
        "png" | "jpg" | "jpeg" | "gif" | "webp" | "avif" | "svg" | "ico" | "bmp" => "image",
        "woff" | "woff2" | "ttf" | "otf" | "eot" => "font",
        "mp4" | "webm" | "mp3" | "m4a" | "ogg" | "m3u8" | "ts" => "media",
        "html" | "htm" => DOCUMENT,
        _ => return None,
    })
}

/// The adblock type of a request.
pub fn request_type(headers: &HeaderMap, path: &str) -> &'static str {
    let upgrade = header(headers, UPGRADE).is_some_and(|u| u.eq_ignore_ascii_case(WEBSOCKET));
    if upgrade || header(headers, MODE) == Some(WEBSOCKET) {
        return WEBSOCKET;
    }
    header(headers, DEST)
        .and_then(from_dest)
        .or_else(|| header(headers, ACCEPT).and_then(from_accept))
        .or_else(|| from_extension(path))
        .unwrap_or("other")
}

/// `Origin`, else `Referer`, as the page that made the request.
fn initiator(headers: &HeaderMap, request_type: &str) -> String {
    if request_type == DOCUMENT {
        return String::new();
    }
    let origin = header(headers, ORIGIN).filter(|o| *o != NO_ORIGIN);
    origin.or_else(|| header(headers, REFERER)).unwrap_or_default().to_string()
}

/// The authority of a request: the h2 `:authority` (or an absolute-form h1
/// target), else `Host`.
pub fn authority_of<B>(req: &Request<B>) -> Option<String> {
    req.uri().authority().map(|a| a.as_str().to_string()).or_else(|| header(req.headers(), HOST).map(str::to_string))
}

/// The facts of a request whose authority is `authority`.
pub fn of<B>(req: &Request<B>, authority: &str) -> OwnedFacts {
    let path = req.uri().path_and_query().map_or("/", ::http::uri::PathAndQuery::as_str);
    let request_type = request_type(req.headers(), path);
    // What the page asked for, which rules anchor on: a socket's scheme is `wss`.
    let scheme = if request_type == WEBSOCKET { "wss" } else { "https" };
    OwnedFacts { url: format!("{scheme}://{authority}{path}"), method: req.method().as_str().to_string(), request_type, initiator: initiator(req.headers(), request_type) }
}
