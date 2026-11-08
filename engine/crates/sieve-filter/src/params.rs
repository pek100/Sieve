//! Tracking parameters (plan 2026-11-09, tracking protection's `queryParams`):
//! the built-in list `data/tracking-params.txt`, and taking its names out of a
//! URL's query. Everything else in the URL stays byte for byte: the order and
//! spelling of the other parameters, an empty one, the fragment.

use std::sync::LazyLock;

const BUILT_IN: &str = include_str!("../data/tracking-params.txt");
const COMMENT: char = '#';
const PREFIX: char = '*';

/// Names to remove: exact ones and prefixes, lower case.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ParamList {
    exact: Vec<String>,
    prefixes: Vec<String>,
}

impl ParamList {
    /// One name a line, `#` comments, a trailing `*` for a prefix.
    pub fn parse(text: &str) -> Self {
        let mut list = Self::default();
        for line in text.lines().map(str::trim).filter(|l| !l.is_empty() && !l.starts_with(COMMENT)) {
            let name = line.to_ascii_lowercase();
            match name.strip_suffix(PREFIX) {
                Some(prefix) if !prefix.is_empty() => list.prefixes.push(prefix.to_string()),
                Some(_) => {}
                None => list.exact.push(name),
            }
        }
        list
    }

    /// The list Sieve ships.
    pub fn built_in() -> &'static Self {
        static LIST: LazyLock<ParamList> = LazyLock::new(|| ParamList::parse(BUILT_IN));
        &LIST
    }

    pub fn matches(&self, name: &str) -> bool {
        let name = name.to_ascii_lowercase();
        self.exact.contains(&name) ||self.prefixes.iter().any(|p| name.starts_with(p.as_str()))
    }

    /// `url` without the listed parameters, and how many went; None when none did.
    /// A parameter's name is read as written: a percent-encoded name is no match.
    pub fn strip(&self, url: &str) -> Option<(String, u32)> {
        self.strip_keeping(url, |_| false)
    }

    /// [`ParamList::strip`], leaving the listed names `keep` says to keep (an
    /// exception for them, [`crate::rules::KeptParams`]).
    pub fn strip_keeping(&self, url: &str, keep: impl Fn(&str) -> bool) -> Option<(String, u32)> {
        let (before_fragment, fragment) = match url.split_once('#') {
            Some((b, f)) => (b, Some(f)),
            None => (url, None),
        };
        let (base, query) = before_fragment.split_once('?')?;
        let mut removed = 0u32;
        let kept: Vec<&str> = query
            .split('&')
            .filter(|pair| {
                let name = pair.split_once('=').map_or(*pair, |(n, _)| n);
                let drop = !name.is_empty() && self.matches(name) && !keep(name);
                removed += u32::from(drop);
                !drop
            })
            .collect();
        if removed == 0 {
            return None;
        }
        let mut out = base.to_string();
        if !(kept.is_empty() || kept == [""]) {
            out.push('?');
            out.push_str(&kept.join("&"));
        }
        if let Some(fragment) = fragment {
            out.push('#');
            out.push_str(fragment);
        }
        Some((out, removed))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_built_in_list_has_the_campaign_tags_and_the_click_ids() {
        let list = ParamList::built_in();
        for name in ["utm_source", "utm_medium", "utm_campaign", "UTM_Content", "fbclid", "gclid", "msclkid", "yclid", "mc_cid"] {
            assert!(list.matches(name), "{name}");
        }
        for name in ["q", "id", "page", "utm", "ref", "token", "v", "s", ""] {
            assert!(!list.matches(name), "{name}: a page may need it");
        }
    }

    /// A mail link's recipient id or token signs the reader in, unsubscribes them or
    /// fills a form: the page needs it, so only a list's `$removeparam` may take it.
    #[test]
    fn names_that_carry_a_recipient_or_a_token_are_not_built_in() {
        let list = ParamList::built_in();
        for name in ["mkt_tok", "_hsenc", "_hsmi", "vero_id", "oly_enc_id", "oly_anon_id", "mc_eid"] {
            assert!(!list.matches(name), "{name}");
        }
    }

    #[test]
    fn a_kept_name_stays_and_the_rest_go() {
        let list = ParamList::built_in();
        let (clean, n) = list.strip_keeping("https://news.example/?utm_source=a&fbclid=b&id=1", |name| name == "fbclid").unwrap();
        assert_eq!((clean.as_str(), n), ("https://news.example/?fbclid=b&id=1", 1));
        assert_eq!(list.strip_keeping("https://news.example/?fbclid=b", |_| true), None, "every name kept is no change");
    }

    #[test]
    fn listed_parameters_go_and_everything_else_stays_as_written() {
        let list = ParamList::built_in();
        let (clean, n) = list.strip("https://news.example/a/42?id=7&utm_source=mail&utm_medium=x&fbclid=AbC&b=&q=a%20b#top").unwrap();
        assert_eq!(clean, "https://news.example/a/42?id=7&b=&q=a%20b#top");
        assert_eq!(n, 3);
        assert_eq!(list.strip("https://news.example/?utm_source=a&gclid=b").unwrap(), ("https://news.example/".to_string(), 2), "no query left, no `?`");
        assert_eq!(list.strip("https://news.example/?gclid").unwrap(), ("https://news.example/".to_string(), 1), "a name with no value");
        assert_eq!(list.strip("https://news.example/?a=1&&fbclid=2").unwrap().0, "https://news.example/?a=1&", "an empty pair is kept");
    }

    #[test]
    fn nothing_listed_is_none() {
        let list = ParamList::built_in();
        for url in ["https://news.example/", "https://news.example/?id=1", "https://news.example/#utm_source=a", "https://news.example/?q=utm_source", "https://news.example/?%75tm_source=a"] {
            assert_eq!(list.strip(url), None, "{url}");
        }
    }

    #[test]
    fn the_parser_reads_comments_prefixes_and_case() {
        let list = ParamList::parse("# a comment\n\n  Foo_*  \nBAR\n*\n");
        assert!(list.matches("foo_x") && list.matches("FOO_") && list.matches("bar"));
        assert!(!list.matches("foo") && !list.matches("anything"), "a bare * is no prefix of everything");
    }
}
