//! Tracking protection on decrypted requests (plan 2026-11-09, parity rows 26 to
//! 30). Pure: what each protection does to a request's head or a response's,
//! and the change it reports for the log. [`super::serve`] calls it only for
//! requests that were decrypted, so nothing here can reach a flow the floor or an
//! exclusion keeps whole.
//!
//! Third-party is the browser's own `Sec-Fetch-Site: cross-site`; without that
//! header a request reads as first-party, so nothing is changed on a guess. For
//! cookies a top-level navigation is always first-party ([`cookie_party`]).

use std::time::{SystemTime, UNIX_EPOCH};

use ::http::header::{HeaderName, HeaderValue, REFERER, SET_COOKIE};
use ::http::HeaderMap;
use sieve_ipc::{LogChange, TRACKING_NAMES};

const SEC_FETCH_SITE: &str = "sec-fetch-site";
const CROSS_SITE: &str = "cross-site";
const SEC_FETCH_DEST: &str = "sec-fetch-dest";
const DOCUMENT: &str = "document";
/// Global Privacy Control only: `DNT` is retired (no legal weight, and one
/// more bit that sets a browser apart), so it is neither added nor touched.
const SEC_GPC: &str = "sec-gpc";
const SIGNAL_ON: &str = "1";
const X_CLIENT_DATA: &str = "x-client-data";
/// How long a capped cookie lives: an hour (the registry's words say so).
pub const COOKIE_MAX_AGE_S: u64 = 3600;
const MAX_AGE: &str = "max-age";
const EXPIRES: &str = "expires";

/// One protection, in [`TRACKING_NAMES`] order: the discriminant is its index.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Protection {
    Gpc,
    SearchQueries,
    ClientData,
    Referrer,
    ThirdPartyCookies,
    WebRtc,
    Push,
    Location,
    QueryParams,
    FirstPartyCookies,
}

impl Protection {
    pub const ALL: [Self; 10] = [Self::Gpc, Self::SearchQueries, Self::ClientData, Self::Referrer, Self::ThirdPartyCookies, Self::WebRtc, Self::Push, Self::Location, Self::QueryParams, Self::FirstPartyCookies];

    /// Its name in the policy and the log.
    pub fn name(self) -> &'static str {
        TRACKING_NAMES[self as usize]
    }

    fn bit(self) -> u16 {
        1 << self as u16
    }
}

/// The protections on, as the policy names them.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Protections(u16);

impl Protections {
    pub const NONE: Self = Self(0);

    /// The ones these names say; a name no protection has is no protection
    /// (`policy::accept` refuses it before it gets here).
    pub fn from_names(names: &[String]) -> Self {
        Self(Protection::ALL.iter().filter(|p| names.iter().any(|n| n == p.name())).fold(0, |bits, p| bits | p.bit()))
    }

    pub fn of(list: &[Protection]) -> Self {
        Self(list.iter().fold(0, |bits, p| bits | p.bit()))
    }

    pub fn has(self, p: Protection) -> bool {
        self.0 & p.bit() != 0
    }

    pub fn is_empty(self) -> bool {
        self.0 == 0
    }
}

/// What the protections changed in one request and its response, one entry per
/// protection, in the order they acted.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Changes(Vec<LogChange>);

impl Changes {
    pub fn add(&mut self, p: Protection, count: u32) {
        if count == 0 {
            return;
        }
        match self.0.iter_mut().find(|c| c.what == p.name()) {
            Some(c) => c.count = c.count.saturating_add(count),
            None => self.0.push(LogChange { what: p.name().to_string(), count }),
        }
    }

    pub fn extend(&mut self, other: Vec<LogChange>) {
        for c in other {
            if let Some(p) = Protection::ALL.into_iter().find(|p| p.name() == c.what) {
                self.add(p, c.count);
            }
        }
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub fn into_vec(self) -> Vec<LogChange> {
        self.0
    }
}

/// Whose request this is, by the browser's word.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Party {
    First,
    Third,
}

fn header_is(headers: &HeaderMap, name: &str, value: &str) -> bool {
    headers.get(name).and_then(|v| v.to_str().ok()).is_some_and(|v| v.trim().eq_ignore_ascii_case(value))
}

/// The party as the referrer options read it: the raw `Sec-Fetch-Site`.
pub fn party(headers: &HeaderMap) -> Party {
    if header_is(headers, SEC_FETCH_SITE, CROSS_SITE) { Party::Third } else { Party::First }
}

/// The party as the cookie options read it. A top-level navigation
/// (`Sec-Fetch-Dest: document`) is the site the user opened, whoever linked to
/// it: a sign-in callback, a mail link and a search click arrive cross-site, and
/// what their responses set is that site's own cookie. A frame (`iframe`) or a
/// subresource from another site stays third-party.
pub fn cookie_party(headers: &HeaderMap) -> Party {
    if header_is(headers, SEC_FETCH_DEST, DOCUMENT) { Party::First } else { party(headers) }
}

/// A cookie protection that applies to this request's response.
pub fn cookie_cap(on: Protections, party: Party) -> Option<Protection> {
    let p = match party {
        Party::Third => Protection::ThirdPartyCookies,
        Party::First => Protection::FirstPartyCookies,
    };
    on.has(p).then_some(p)
}

/// The request's own changes, before it goes upstream: the GPC signal, the
/// header Chrome adds, and the referrer of a cross-site request.
pub fn prepare_request(on: Protections, party: Party, headers: &mut HeaderMap, changes: &mut Changes) {
    if on.has(Protection::Gpc) && !headers.contains_key(SEC_GPC) {
        headers.insert(HeaderName::from_static(SEC_GPC), HeaderValue::from_static(SIGNAL_ON));
        changes.add(Protection::Gpc, 1);
    }
    if on.has(Protection::ClientData) {
        let removed = headers.get_all(X_CLIENT_DATA).iter().count();
        headers.remove(X_CLIENT_DATA);
        changes.add(Protection::ClientData, u32::try_from(removed).unwrap_or(u32::MAX));
    }
    if party != Party::Third || !headers.contains_key(REFERER) {
        return;
    }
    if on.has(Protection::Referrer) {
        headers.remove(REFERER);
        changes.add(Protection::Referrer, 1);
    } else if on.has(Protection::SearchQueries)
        && let Some(origin) = headers.get(REFERER).and_then(|v| v.to_str().ok()).and_then(origin_only)
        && let Ok(value) = HeaderValue::from_str(&origin)
    {
        headers.insert(REFERER, value);
        changes.add(Protection::SearchQueries, 1);
    }
}

/// A referrer cut to its origin, when it says more than that; None for one that
/// says only its origin or does not parse (left alone).
fn origin_only(referrer: &str) -> Option<String> {
    let url = url::Url::parse(referrer.trim()).ok()?;
    let origin = url.origin();
    if !origin.is_tuple() {
        return None;
    }
    let cut = format!("{}/", origin.ascii_serialization());
    (cut != url.as_str()).then_some(cut)
}

/// The wall clock, in seconds since the Unix epoch.
pub fn now_s() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |d| d.as_secs())
}

/// Caps every `Set-Cookie` in `headers` at [`COOKIE_MAX_AGE_S`]; how many it changed.
pub fn cap_set_cookies(headers: &mut HeaderMap, now_s: u64) -> u32 {
    if !headers.contains_key(SET_COOKIE) {
        return 0;
    }
    let mut capped = 0u32;
    let values: Vec<HeaderValue> = headers
        .get_all(SET_COOKIE)
        .iter()
        .map(|v| match v.to_str().ok().and_then(|s| capped_cookie(s, COOKIE_MAX_AGE_S, now_s)).and_then(|s| HeaderValue::from_str(&s).ok()) {
            Some(new) => {
                capped += 1;
                new
            }
            None => v.clone(),
        })
        .collect();
    if capped > 0 {
        headers.remove(SET_COOKIE);
        for v in values {
            headers.append(SET_COOKIE, v);
        }
    }
    capped
}

/// One `Set-Cookie` with a lifetime of at most `cap_s`, or None when it already
/// has one (a deletion included) or is a session cookie. RFC 6265 5.2 and 5.3: an
/// attribute whose value does not read is ignored, the last valid `Max-Age` wins
/// over `Expires`, and a cookie with neither ends with the browser's session,
/// which is the browser's to end: it is left alone.
fn capped_cookie(value: &str, cap_s: u64, now_s: u64) -> Option<String> {
    let mut parts = value.split(';');
    let pair = parts.next()?;
    let attributes: Vec<&str> = parts.collect();
    let named = |a: &str, name: &str| a.split_once('=').is_some_and(|(n, _)| n.trim().eq_ignore_ascii_case(name));
    fn value_of(a: &str) -> &str {
        a.split_once('=').map_or("", |(_, v)| v.trim())
    }
    let max_age = attributes.iter().rev().filter(|a| named(a, MAX_AGE)).find_map(|a| parse_max_age(value_of(a)));
    let expires = || attributes.iter().rev().filter(|a| named(a, EXPIRES)).find_map(|a| cookie_date(value_of(a))).map(|t| i128::from(t) - i128::from(now_s));
    let lifetime_s = max_age.or_else(expires)?;
    if lifetime_s <= i128::from(cap_s) {
        return None;
    }
    let mut out = pair.to_string();
    for a in attributes.iter().filter(|a| !named(a, MAX_AGE)) {
        out.push(';');
        out.push_str(a);
    }
    out.push_str(&format!("; Max-Age={cap_s}"));
    Some(out)
}

/// RFC 6265 5.2.2: an optional `-` and digits; anything else is no Max-Age.
fn parse_max_age(v: &str) -> Option<i128> {
    let digits = v.strip_prefix('-').unwrap_or(v);
    if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    // Longer than any lifetime matters: read it as very long.
    Some(v.parse::<i128>().unwrap_or(i128::MAX))
}

/// A cookie date (RFC 6265 5.1.1), in seconds since the Unix epoch.
fn cookie_date(text: &str) -> Option<i64> {
    let delimiter = |c: char| matches!(c, '\t' | ' '..='/' | ';'..='@' | '['..='`' | '{'..='~');
    let (mut time, mut day, mut month, mut year) = (None, None, None, None);
    for token in text.split(delimiter).filter(|t| !t.is_empty()) {
        if time.is_none()
            && let Some(t) = time_of(token)
        {
            time = Some(t);
        } else if day.is_none() && (1..=2).contains(&leading_digits(token)) {
            day = token[..leading_digits(token)].parse::<u32>().ok();
        } else if month.is_none() && let Some(m) = month_of(token) {
            month = Some(m);
        } else if year.is_none() && (2..=4).contains(&leading_digits(token)) {
            year = token[..leading_digits(token)].parse::<i64>().ok();
        }
    }
    let (h, m, s) = time?;
    let (day, month) = (day?, month?);
    let year = match year? {
        y @ 70..=99 => y + 1900,
        y @ 0..=69 => y + 2000,
        y => y,
    };
    if !(1..=31).contains(&day) || year < 1601 || h > 23 || m > 59 || s > 59 {
        return None;
    }
    Some(days_from_civil(year, month, day) * 86_400 + i64::from(h * 3600 + m * 60 + s))
}

fn leading_digits(token: &str) -> usize {
    token.bytes().take_while(u8::is_ascii_digit).count()
}

/// `h:m:s`, each one or two digits.
fn time_of(token: &str) -> Option<(u32, u32, u32)> {
    let mut parts = token.splitn(3, ':');
    let mut field = || {
        let p = parts.next()?;
        let n = leading_digits(p);
        (1..=2).contains(&n).then(|| p[..n].parse::<u32>().ok()).flatten()
    };
    let (h, m, s) = (field()?, field()?, field()?);
    Some((h, m, s))
}

fn month_of(token: &str) -> Option<u32> {
    const MONTHS: [&str; 12] = ["jan", "feb", "mar", "apr", "may", "jun", "jul", "aug", "sep", "oct", "nov", "dec"];
    let start = token.get(..3)?.to_ascii_lowercase();
    MONTHS.iter().position(|m| *m == start).map(|i| i as u32 + 1)
}

/// Days since 1970-01-01 of a proleptic Gregorian date (Howard Hinnant's algorithm).
fn days_from_civil(year: i64, month: u32, day: u32) -> i64 {
    let y = if month <= 2 { year - 1 } else { year };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let mp = i64::from((month + 9) % 12);
    let doy = (153 * mp + 2) / 5 + i64::from(day) - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 2026-11-09T00:00:00Z.
    const NOW: u64 = 1_794_182_400;

    fn names(list: &[&str]) -> Vec<String> {
        list.iter().map(|s| (*s).to_string()).collect()
    }

    fn all() -> Protections {
        Protections::of(&Protection::ALL)
    }

    /// What a browser sends for a cross-site subresource, as it sends it.
    fn browser_request(site: &str) -> HeaderMap {
        let mut h = HeaderMap::new();
        h.insert("accept", "image/avif,image/webp,*/*".parse().unwrap());
        h.insert("referer", "https://search.example/results?q=private+question&lang=en".parse().unwrap());
        h.insert("sec-fetch-dest", "image".parse().unwrap());
        h.insert("sec-fetch-mode", "no-cors".parse().unwrap());
        h.insert("sec-fetch-site", site.parse().unwrap());
        h.insert("x-client-data", "CJa2yQEIpLbJAQ==".parse().unwrap());
        h.insert("cookie", "sid=abc".parse().unwrap());
        h
    }

    fn changes_of(c: Changes) -> Vec<(String, u32)> {
        c.into_vec().into_iter().map(|c| (c.what, c.count)).collect()
    }

    #[test]
    fn every_protection_has_its_policy_name_by_index() {
        assert_eq!(Protection::ALL.len(), TRACKING_NAMES.len());
        for (i, p) in Protection::ALL.iter().enumerate() {
            assert_eq!(p.name(), TRACKING_NAMES[i]);
            assert_eq!(*p as usize, i);
        }
        let on = Protections::from_names(&names(&["gpc", "referrer", "mind-reading"]));
        assert!(on.has(Protection::Gpc) && on.has(Protection::Referrer) && !on.has(Protection::QueryParams));
        assert!(Protections::from_names(&[]).is_empty());
    }

    #[test]
    fn the_party_is_the_browsers_word_and_none_is_first_party() {
        assert_eq!(party(&browser_request("cross-site")), Party::Third);
        for site in ["same-origin", "same-site", "none"] {
            assert_eq!(party(&browser_request(site)), Party::First, "{site}");
        }
        assert_eq!(party(&HeaderMap::new()), Party::First, "no header, no guess");
    }

    #[test]
    fn gpc_adds_only_sec_gpc_once_and_never_touches_dnt() {
        let mut h = browser_request("same-origin");
        let mut c = Changes::default();
        prepare_request(Protections::of(&[Protection::Gpc]), Party::First, &mut h, &mut c);
        assert_eq!(h.get("sec-gpc").unwrap(), &HeaderValue::from_static("1"));
        assert!(!h.contains_key("dnt"), "DNT is no longer added");
        assert_eq!(changes_of(c), [("gpc".to_string(), 1)]);
        // A browser that already sends GPC: nothing added, nothing counted.
        let mut h = browser_request("same-origin");
        h.insert("sec-gpc", "1".parse().unwrap());
        let mut c = Changes::default();
        prepare_request(Protections::of(&[Protection::Gpc]), Party::First, &mut h, &mut c);
        assert!(c.is_empty());
        assert_eq!(h.get_all("sec-gpc").iter().count(), 1);
        // A browser's own DNT is the browser's: neither removed nor changed.
        let mut h = browser_request("same-origin");
        h.insert("dnt", "0".parse().unwrap());
        prepare_request(Protections::of(&[Protection::Gpc]), Party::First, &mut h, &mut Changes::default());
        assert_eq!(h.get("dnt").unwrap(), "0");
    }

    #[test]
    fn client_data_goes_from_every_request() {
        for site in ["cross-site", "same-origin"] {
            let mut h = browser_request(site);
            let mut c = Changes::default();
            prepare_request(Protections::of(&[Protection::ClientData]), party(&h), &mut h, &mut c);
            assert!(!h.contains_key("x-client-data"), "{site}");
            assert_eq!(changes_of(c), [("clientData".to_string(), 1)]);
        }
        let mut none = HeaderMap::new();
        let mut c = Changes::default();
        prepare_request(Protections::of(&[Protection::ClientData]), Party::First, &mut none, &mut c);
        assert!(c.is_empty(), "nothing to remove is no change");
    }

    #[test]
    fn search_queries_cut_a_cross_site_referrer_to_its_origin() {
        let mut h = browser_request("cross-site");
        let mut c = Changes::default();
        prepare_request(Protections::of(&[Protection::SearchQueries]), Party::Third, &mut h, &mut c);
        assert_eq!(h.get("referer").unwrap(), "https://search.example/");
        assert_eq!(changes_of(c), [("searchQueries".to_string(), 1)]);
        // Already an origin: nothing to cut. Same site: the site's own business.
        let mut origin = browser_request("cross-site");
        origin.insert("referer", "https://search.example/".parse().unwrap());
        let mut c = Changes::default();
        prepare_request(Protections::of(&[Protection::SearchQueries]), Party::Third, &mut origin, &mut c);
        assert!(c.is_empty());
        let mut same = browser_request("same-origin");
        prepare_request(Protections::of(&[Protection::SearchQueries]), Party::First, &mut same, &mut c);
        assert_eq!(same.get("referer").unwrap(), "https://search.example/results?q=private+question&lang=en");
        assert!(c.is_empty());
        // A referrer that does not parse is left alone.
        let mut odd = browser_request("cross-site");
        odd.insert("referer", "not a url".parse().unwrap());
        prepare_request(Protections::of(&[Protection::SearchQueries]), Party::Third, &mut odd, &mut c);
        assert_eq!(odd.get("referer").unwrap(), "not a url");
    }

    #[test]
    fn referrer_removes_a_cross_site_referrer_and_wins_over_cutting_it() {
        let mut h = browser_request("cross-site");
        let mut c = Changes::default();
        prepare_request(Protections::of(&[Protection::Referrer, Protection::SearchQueries]), Party::Third, &mut h, &mut c);
        assert!(!h.contains_key("referer"));
        assert_eq!(changes_of(c), [("referrer".to_string(), 1)]);
        let mut same = browser_request("same-site");
        let mut c = Changes::default();
        prepare_request(Protections::of(&[Protection::Referrer]), Party::First, &mut same, &mut c);
        assert!(same.contains_key("referer") && c.is_empty(), "a same-site referrer stays");
    }

    #[test]
    fn nothing_on_changes_nothing() {
        let before = browser_request("cross-site");
        let mut h = before.clone();
        let mut c = Changes::default();
        prepare_request(Protections::NONE, Party::Third, &mut h, &mut c);
        assert_eq!(h, before);
        assert!(c.is_empty());
        // The cookie and the request's other headers are never touched by any protection.
        prepare_request(all(), Party::Third, &mut h, &mut c);
        for name in ["accept", "cookie", "sec-fetch-dest", "sec-fetch-mode", "sec-fetch-site"] {
            assert_eq!(h.get(name), before.get(name), "{name}");
        }
    }

    #[test]
    fn the_cookie_protection_follows_the_party() {
        let on = Protections::of(&[Protection::ThirdPartyCookies]);
        assert_eq!(cookie_cap(on, Party::Third), Some(Protection::ThirdPartyCookies));
        assert_eq!(cookie_cap(on, Party::First), None);
        assert_eq!(cookie_cap(Protections::of(&[Protection::FirstPartyCookies]), Party::First), Some(Protection::FirstPartyCookies));
        assert_eq!(cookie_cap(all(), Party::Third), Some(Protection::ThirdPartyCookies));
    }

    fn cap(value: &str) -> Option<String> {
        capped_cookie(value, COOKIE_MAX_AGE_S, NOW)
    }

    #[test]
    fn a_long_cookie_is_capped_at_an_hour_and_keeps_its_other_attributes() {
        assert_eq!(cap("id=1; Max-Age=31536000; Path=/; Secure; SameSite=None").as_deref(), Some("id=1; Path=/; Secure; SameSite=None; Max-Age=3600"));
        assert_eq!(cap("id=1; Expires=Wed, 09 Nov 2027 00:00:00 GMT; Path=/").as_deref(), Some("id=1; Expires=Wed, 09 Nov 2027 00:00:00 GMT; Path=/; Max-Age=3600"));
        assert_eq!(cap("id=1; expires=Tue, 09-Nov-2027 00:00:00 GMT").as_deref(), Some("id=1; expires=Tue, 09-Nov-2027 00:00:00 GMT; Max-Age=3600"), "the Netscape form");
        assert_eq!(cap("id=1; max-age=5; MAX-AGE=99999").as_deref(), Some("id=1; Max-Age=3600"), "the last Max-Age is the one in force");
    }

    /// RFC 6265 5.2.2: a Max-Age that does not read is ignored, so the cookie lives
    /// by its Expires, or by the last Max-Age that does read.
    #[test]
    fn a_max_age_that_does_not_read_falls_back_to_expires() {
        assert_eq!(cap("id=1; Max-Age=soon; Expires=Wed, 09 Nov 2050 00:00:00 GMT").as_deref(), Some("id=1; Expires=Wed, 09 Nov 2050 00:00:00 GMT; Max-Age=3600"));
        assert_eq!(cap("id=1; Max-Age=99999; Max-Age=soon").as_deref(), Some("id=1; Max-Age=3600"), "the last valid one");
        assert_eq!(cap("id=1; Max-Age=soon; Expires=Mon, 09 Nov 2026 00:30:00 GMT"), None, "an Expires inside the hour stands");
        assert_eq!(cap("id=1; Max-Age=60; Max-Age=soon"), None);
    }

    /// A cookie with no lifetime ends with the browser's session: the browser's to
    /// end, and an hour could cut it short (a sign-in, a basket).
    #[test]
    fn a_session_cookie_is_left_alone() {
        for value in ["id=1", "id=1; Path=/; Secure; HttpOnly", "id=1; Max-Age=soon", "id=1; Expires=someday"] {
            assert_eq!(cap(value), None, "{value}");
        }
        let mut h = HeaderMap::new();
        h.append("set-cookie", "sid=1; Path=/; Secure".parse().unwrap());
        assert_eq!(cap_set_cookies(&mut h, NOW), 0);
        assert_eq!(h.get("set-cookie").unwrap(), "sid=1; Path=/; Secure");
    }

    /// A sign-in callback, a mail link or a search click is a top-level navigation
    /// that arrives cross-site; its cookies are the opened site's own. Frames and
    /// subresources from another site stay third-party, and the referrer options
    /// keep reading the raw header.
    #[test]
    fn a_top_level_navigation_is_first_party_for_cookies_only() {
        let mut nav = browser_request("cross-site");
        nav.insert("sec-fetch-dest", "document".parse().unwrap());
        assert_eq!(cookie_party(&nav), Party::First);
        assert_eq!(party(&nav), Party::Third, "the referrer options keep the raw header");
        for dest in ["iframe", "image", "script", "empty"] {
            let mut h = browser_request("cross-site");
            h.insert("sec-fetch-dest", dest.parse().unwrap());
            assert_eq!(cookie_party(&h), Party::Third, "{dest}");
        }
        assert_eq!(cookie_party(&browser_request("same-site")), Party::First);
        assert_eq!(cookie_cap(Protections::of(&[Protection::ThirdPartyCookies]), cookie_party(&nav)), None, "Strict leaves a sign-in's cookies alone");
    }

    #[test]
    fn a_short_cookie_a_deletion_or_one_that_cannot_be_read_is_left_alone() {
        for value in [
            "id=1; Max-Age=60",
            "id=1; Max-Age=3600",
            "id=1; Max-Age=0",
            "id=1; Max-Age=-1",
            "id=; Expires=Thu, 01 Jan 1970 00:00:00 GMT",
            "id=1; Expires=Mon, 09 Nov 2026 00:30:00 GMT",
            "id=1; Max-Age=soon",
            "id=1; Expires=someday",
            "id=1; Max-Age=60; Expires=Wed, 09 Nov 2050 00:00:00 GMT",
        ] {
            assert_eq!(cap(value), None, "{value}");
        }
    }

    #[test]
    fn every_set_cookie_of_a_response_is_capped_and_counted() {
        let mut h = HeaderMap::new();
        h.append("set-cookie", "a=1; Max-Age=86400".parse().unwrap());
        h.append("set-cookie", "b=2; Max-Age=10".parse().unwrap());
        h.append("set-cookie", "c=3; Expires=Wed, 09 Nov 2050 00:00:00 GMT".parse().unwrap());
        h.insert("content-type", "text/html".parse().unwrap());
        assert_eq!(cap_set_cookies(&mut h, NOW), 2);
        let all: Vec<&str> = h.get_all("set-cookie").iter().map(|v| v.to_str().unwrap()).collect();
        assert_eq!(all, ["a=1; Max-Age=3600", "b=2; Max-Age=10", "c=3; Expires=Wed, 09 Nov 2050 00:00:00 GMT; Max-Age=3600"]);
        assert_eq!(h.get("content-type").unwrap(), "text/html");
        let mut none = HeaderMap::new();
        assert_eq!(cap_set_cookies(&mut none, NOW), 0);
    }

    #[test]
    fn cookie_dates_read_as_rfc_6265_reads_them() {
        assert_eq!(cookie_date("Thu, 01 Jan 1970 00:00:00 GMT"), Some(0));
        assert_eq!(cookie_date("Mon, 09 Nov 2026 00:00:00 GMT"), Some(NOW as i64));
        assert_eq!(cookie_date("Monday, 09-Nov-26 00:00:00 GMT"), Some(NOW as i64), "two-digit year");
        assert_eq!(cookie_date("Mon Nov  9 00:00:00 2026"), Some(NOW as i64), "asctime");
        assert_eq!(cookie_date("Sun, 29 Feb 2032 12:30:15 GMT"), Some(1_961_670_615));
        for bad in ["", "tomorrow", "Mon, 32 Nov 2026 00:00:00 GMT", "Mon, 09 Nov 2026", "Mon, 09 Nov 2026 25:00:00 GMT"] {
            assert_eq!(cookie_date(bad), None, "{bad}");
        }
    }

    #[test]
    fn a_header_value_that_is_not_text_is_left_alone() {
        let mut h = HeaderMap::new();
        h.append("set-cookie", HeaderValue::from_bytes(b"a=\xff; Max-Age=86400").unwrap());
        assert_eq!(cap_set_cookies(&mut h, NOW), 0);
        assert_eq!(h.get("set-cookie").unwrap().as_bytes(), b"a=\xff; Max-Age=86400");
    }
}
