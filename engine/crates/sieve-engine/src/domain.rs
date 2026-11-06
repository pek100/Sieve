//! The one per-flow decision (plan slice 4, 1.4, 4.4). DNS is never a blocking
//! decision: Windows shares its DNS client between apps, so blocking a lookup
//! would also block an app whose policy is Off. A decoded name wins over the
//! shared IP map; an unnamed flow is blocked only if every live name blocks.
//!
//! An ECH flow is decided by its outer name, with no fallback to the IP map:
//! `sni.rs` reports `ech` whenever the extension is present, Chrome's GREASE
//! ECH makes that common while the SNI is the real name, and treating these as
//! unnamed would move ordinary traffic onto the shared-IP rule. A real ECH
//! inner name stays unblocked, a limit ECH stripping reduces (plan 1.4).

use std::collections::HashSet;
use std::net::IpAddr;
use std::sync::{Arc, Mutex};

pub use sieve_ipc::FlowReason as Reason;
use sieve_filter::rules::{DomainKind, HostDecision, HostVerdict, RuleEngine, RuleSet};
use sieve_ipc::{DomainListKind, Policy, vm_key};
use tokio::sync::watch;

use crate::dns::NameMap;
use crate::flow::classify::Decoded;
use crate::flow::flows::Action;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Decision {
    pub action: Action,
    pub reason: Reason,
    /// The rule that decided, when one did.
    pub rule: Option<String>,
    /// The id of the list holding that rule.
    pub list: Option<String>,
}

impl Decision {
    fn pass(reason: Reason) -> Self {
        Self { action: Action::Pass, reason, rule: None, list: None }
    }

    fn from_host(d: HostDecision, reason: Reason) -> Self {
        let action = if d.verdict == HostVerdict::Block { Action::Drop } else { Action::Pass };
        Self { action, reason, rule: d.rule, list: d.list }
    }
}

/// Who a flow belongs to. Only `App` checks an app row. A guest is filtered by
/// domain only, has its own row, is never decrypted and never inherits a host
/// app's exemption. An unattributed flow gets the default: sieved.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Owner<'a> {
    App { key: &'a str },
    Forwarded { vm: Option<&'a str> },
    Unknown,
}

impl Owner<'_> {
    /// Whether HTTPS interception may ever apply to this flow.
    pub fn may_decrypt(&self) -> bool {
        !matches!(self, Owner::Forwarded { .. })
    }
}

/// Inputs known for a new TCP or UDP flow. `name` is SNI, HTTP Host or QUIC
/// SNI, never the name from an unrelated DNS request.
#[derive(Debug, Clone, Copy)]
pub struct Flow<'a> {
    pub dns: bool,
    pub name: Option<&'a str>,
    pub remote: IpAddr,
    pub owner: Owner<'a>,
}

impl<'a> Flow<'a> {
    pub fn from_decoded(decoded: &'a Decoded, dns: bool, remote: IpAddr, owner: Owner<'a>) -> Self {
        Self { dns, name: decoded.domain.as_deref(), remote, owner }
    }
}

/// One immutable decision snapshot. An Off-app change swaps it without
/// recompiling anything: the engines are shared.
#[derive(Debug, Clone)]
pub struct DomainFilter {
    /// The global Sieve switch.
    pub enabled: bool,
    /// `filtering.content`: decrypted pages get their cosmetics. In this snapshot
    /// so the switch and the rules it applies are read as one.
    pub content: bool,
    off: HashSet<String>,
    pub rules: RuleSet,
}

fn off_keys(policy: &Policy) -> HashSet<String> {
    policy.off_apps.iter().map(|k| k.to_lowercase()).collect()
}

/// The user's enabled domain lists and own rule lines as one engine (B6).
pub fn user_engine(policy: &Policy) -> RuleEngine {
    let kind = |k| match k {
        DomainListKind::Block => DomainKind::Block,
        DomainListKind::Allow => DomainKind::Allow,
    };
    let enabled = policy.domain_lists.iter().filter(|l| l.enabled);
    RuleEngine::compile_user_rules(enabled.flat_map(|l| l.entries.iter().map(move |e| (kind(l.kind), e.as_str()))), policy.user_rules.iter().map(String::as_str))
}

/// Whether going from `before` to `now` changes what [`user_engine`] compiles.
pub fn user_rules_changed(before: &Policy, now: &Policy) -> bool {
    before.domain_lists != now.domain_lists || before.user_rules != now.user_rules
}

impl DomainFilter {
    pub fn new(policy: &Policy, rules: RuleSet) -> Self {
        Self { enabled: policy.sieving, content: policy.content, off: off_keys(policy), rules }
    }

    /// A snapshot that blocks nothing (the switch reads off).
    pub fn inert() -> Self {
        Self { enabled: false, content: false, off: HashSet::new(), rules: RuleSet::empty() }
    }

    /// The same snapshot with newly compiled lists.
    pub fn with_lists(&self, lists: Arc<RuleEngine>) -> Self {
        Self { rules: RuleSet { user: self.rules.user.clone(), lists }, ..self.clone() }
    }

    /// At least one rule can decide a flow, and the switch is on.
    pub fn blocks_anything(&self) -> bool {
        let any = |e: &RuleEngine| e.reports().iter().any(|r| r.network > 0);
        self.enabled && (any(&self.rules.user) || any(&self.rules.lists))
    }

    pub fn is_off(&self, owner: Owner<'_>) -> bool {
        match owner {
            Owner::App { key } => self.off.contains(&key.to_lowercase()),
            Owner::Forwarded { vm } => self.off.contains(&vm_key(vm)),
            Owner::Unknown => false,
        }
    }

    /// `names` is locked only for an unnamed flow, and not while rules are asked.
    pub fn decide(&self, flow: Flow<'_>, names: &Mutex<NameMap>, now_ms: u64) -> Decision {
        if !self.enabled {
            return Decision::pass(Reason::Disabled);
        }
        if flow.dns {
            return Decision::pass(Reason::Dns);
        }
        if self.is_off(flow.owner) {
            return Decision::pass(Reason::AppExempt);
        }
        if let Some(name) = flow.name {
            let d = self.rules.check_host(name);
            let reason = match d.verdict {
                HostVerdict::Block => Reason::NamedBlock,
                HostVerdict::Allow => Reason::NamedAllow,
                HostVerdict::None => Reason::NamedNoRule,
            };
            return Decision::from_host(d, reason);
        }
        let live: Vec<String> = {
            let names = names.lock().unwrap_or_else(|p| p.into_inner());
            names.names(flow.remote, now_ms).into_iter().map(str::to_string).collect()
        };
        let Some(first) = live.first() else {
            return Decision::pass(Reason::UnknownDomain);
        };
        let decided = self.rules.check_host(first);
        if decided.verdict == HostVerdict::Block && live[1..].iter().all(|name| self.rules.check_host(name).verdict == HostVerdict::Block) {
            return Decision::from_host(decided, Reason::AllResolvedNamesBlocked);
        }
        Decision::pass(Reason::MixedResolvedNames)
    }
}

/// The current snapshot, read once per flow and swapped atomically: flows
/// already decided keep their decision. A watch, not an ArcSwap, because the
/// read is per flow and not per packet, no new dependency is needed, and a
/// decrypted flow has to hear its app turn Off ([`Self::until_off`]).
#[derive(Debug)]
pub struct FilterSlot(watch::Sender<Arc<DomainFilter>>);

impl FilterSlot {
    pub fn new(filter: DomainFilter) -> Self {
        Self(watch::channel(Arc::new(filter)).0)
    }

    pub fn get(&self) -> Arc<DomainFilter> {
        self.0.borrow().clone()
    }

    /// Replaces the snapshot with what `f` makes of the current one.
    pub fn update(&self, f: impl FnOnce(&DomainFilter) -> DomainFilter) {
        self.0.send_modify(|slot| *slot = Arc::new(f(slot)));
    }

    /// Resolves once the snapshot says this owner is Off, at once if it does
    /// now. So no swap can fall between a look at the snapshot and this wait.
    pub async fn until_off(&self, owner: Owner<'_>) {
        // It can only fail with the sender gone, and `self` holds the sender.
        let _ = self.0.subscribe().wait_for(|filter| filter.is_off(owner)).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::flow::classify::{Kind, TcpClassifier, UdpClassifier};
    use crate::flow::quic::{VERSION_1, crypto_frame, seal_client_initial};
    use crate::flow::sni::build;
    use sieve_filter::rules::ListText;
    use sieve_ipc::DomainList;

    const BROWSER: &str = "browser";
    const OFF_APP: &str = "off app";
    const BLOCKED: &str = "ads.example";
    const ALLOWED: &str = "ok.ads.example";
    const OTHER: &str = "news.example";

    fn rules() -> RuleSet {
        let lists = RuleEngine::compile(&[ListText { id: "test", text: "||ads.example^\n@@||ok.ads.example^\n", trusted: false }]);
        RuleSet { user: Arc::new(RuleEngine::empty()), lists: Arc::new(lists) }
    }

    fn filter() -> DomainFilter {
        let policy = Policy { sieving: true, off_apps: vec![OFF_APP.to_string(), "vm:guest off".to_string()], ..Policy::default() };
        DomainFilter::new(&policy, rules())
    }

    fn remote() -> IpAddr {
        "192.0.2.1".parse().unwrap()
    }

    fn names() -> Mutex<NameMap> {
        Mutex::new(NameMap::default())
    }

    fn named(name: Option<&str>, owner: Owner<'static>) -> Decision {
        let f = Flow { dns: false, name, remote: remote(), owner };
        filter().decide(f, &names(), 0)
    }

    fn tls(host: &str) -> Decoded {
        TcpClassifier::new().push(&build::typical(host)).unwrap()
    }

    fn http(host: &str) -> Decoded {
        TcpClassifier::new().push(format!("GET / HTTP/1.1\r\nHost: {host}\r\n\r\n").as_bytes()).unwrap()
    }

    fn quic(host: &str) -> Decoded {
        let hello = build::handshake(&[build::sni_ext(host), build::alpn_ext(&["h3"])]);
        let mut frames = crypto_frame(0, &hello);
        frames.resize(1100, 0);
        UdpClassifier::new().push(&seal_client_initial(VERSION_1, &[9u8; 8], &[], 0, 1, &frames)).unwrap()
    }

    /// Every protocol through the real classifier, with the kind it must decode.
    fn decoded_forms(host: &str) -> [(Decoded, Kind); 3] {
        [(tls(host), Kind::Tls), (http(host), Kind::Http), (quic(host), Kind::Quic)]
    }

    #[test]
    fn off_app_flow_to_a_blocked_host_is_relayed() {
        for (d, kind) in decoded_forms(BLOCKED) {
            assert_eq!(d.kind, Some(kind));
            let got = filter().decide(Flow::from_decoded(&d, false, remote(), Owner::App { key: OFF_APP }), &names(), 0);
            assert_eq!((got.action, got.reason), (Action::Pass, Reason::AppExempt), "{kind:?}");
            assert_eq!(got.rule, None, "no rule decided an exempt flow");
        }
    }

    #[test]
    fn sieved_app_flow_to_a_blocked_host_is_closed() {
        for (d, kind) in decoded_forms(BLOCKED) {
            let got = filter().decide(Flow::from_decoded(&d, false, remote(), Owner::App { key: BROWSER }), &names(), 0);
            assert_eq!((got.action, got.reason), (Action::Drop, Reason::NamedBlock), "{kind:?}");
            assert_eq!((got.rule.as_deref(), got.list.as_deref()), (Some("||ads.example^"), Some("test")));
        }
    }

    #[test]
    fn a_sieved_apps_flow_to_an_unblocked_host_is_relayed_with_its_reason() {
        for (d, kind) in decoded_forms(OTHER) {
            let got = filter().decide(Flow::from_decoded(&d, false, remote(), Owner::App { key: BROWSER }), &names(), 0);
            assert_eq!((got.action, got.reason), (Action::Pass, Reason::NamedNoRule), "{kind:?}");
        }
        assert_eq!(named(Some(ALLOWED), Owner::App { key: BROWSER }).reason, Reason::NamedAllow);
    }

    #[test]
    fn a_decoded_name_beats_other_names_on_a_shared_address() {
        let f = filter();
        let map = names();
        map.lock().unwrap().record(BLOCKED, remote(), 60, 0);
        let flow = |name| Flow { dns: false, name: Some(name), remote: remote(), owner: Owner::Unknown };
        assert_eq!(f.decide(flow(OTHER), &map, 0).reason, Reason::NamedNoRule);
        assert_eq!(f.decide(flow(ALLOWED), &map, 0).reason, Reason::NamedAllow);
        map.lock().unwrap().record(OTHER, remote(), 60, 0);
        assert_eq!(f.decide(flow(BLOCKED), &map, 0).action, Action::Drop);
    }

    fn unnamed(owner: Owner<'static>) -> Flow<'static> {
        Flow { dns: false, name: None, remote: remote(), owner }
    }

    #[test]
    fn no_name_flow_every_name_blocked_is_closed() {
        let map = names();
        map.lock().unwrap().record(BLOCKED, remote(), 60, 0);
        map.lock().unwrap().record("other.ads.example", remote(), 60, 0);
        let got = filter().decide(unnamed(Owner::App { key: BROWSER }), &map, 0);
        assert_eq!((got.action, got.reason), (Action::Drop, Reason::AllResolvedNamesBlocked));
        assert_eq!(got.rule.as_deref(), Some("||ads.example^"));
        let off = filter().decide(unnamed(Owner::App { key: OFF_APP }), &map, 0);
        assert_eq!((off.action, off.reason), (Action::Pass, Reason::AppExempt));
    }

    #[test]
    fn no_name_flow_mixed_names_is_relayed() {
        let map = names();
        map.lock().unwrap().record(BLOCKED, remote(), 60, 0);
        map.lock().unwrap().record(OTHER, remote(), 60, 0);
        let got = filter().decide(unnamed(Owner::App { key: BROWSER }), &map, 0);
        assert_eq!((got.action, got.reason, got.rule), (Action::Pass, Reason::MixedResolvedNames, None));
        let map = names();
        map.lock().unwrap().record(OTHER, remote(), 60, 0);
        map.lock().unwrap().record(BLOCKED, remote(), 60, 0);
        assert_eq!(filter().decide(unnamed(Owner::Unknown), &map, 0).action, Action::Pass, "order does not matter");
    }

    #[test]
    fn no_name_flow_expired_or_no_names_is_relayed() {
        let map = names();
        assert_eq!(filter().decide(unnamed(Owner::Unknown), &map, 0).reason, Reason::UnknownDomain);
        map.lock().unwrap().record(BLOCKED, remote(), 60, 0);
        map.lock().unwrap().record(OTHER, remote(), 20, 0);
        assert_eq!(filter().decide(unnamed(Owner::Unknown), &map, 0).reason, Reason::MixedResolvedNames);
        assert_eq!(filter().decide(unnamed(Owner::Unknown), &map, 20_000).action, Action::Drop, "the other name expired");
        assert_eq!(filter().decide(unnamed(Owner::Unknown), &map, 60_000).reason, Reason::UnknownDomain, "all expired");
    }

    #[test]
    fn dns_is_never_blocked_even_for_a_blocked_question() {
        let question = Decoded { domain: Some(BLOCKED.to_string()), ..Decoded::default() };
        let got = filter().decide(Flow::from_decoded(&question, true, remote(), Owner::App { key: BROWSER }), &names(), 0);
        assert_eq!((got.action, got.reason), (Action::Pass, Reason::Dns));
    }

    #[test]
    fn forwarded_flow_is_domain_filtered_and_never_decryptable() {
        let owner = Owner::Forwarded { vm: Some("guest") };
        assert!(!owner.may_decrypt());
        assert!(!Owner::Forwarded { vm: None }.may_decrypt());
        assert!(Owner::App { key: BROWSER }.may_decrypt() && Owner::Unknown.may_decrypt());
        assert_eq!(named(Some(BLOCKED), owner).action, Action::Drop);
        assert_eq!(named(Some(OTHER), owner).action, Action::Pass);
    }

    #[test]
    fn forwarded_flow_never_inherits_a_host_apps_off() {
        // A guest named like an Off host app, unnamed or named, is still sieved.
        assert_eq!(named(Some(BLOCKED), Owner::Forwarded { vm: Some(OFF_APP) }).action, Action::Drop);
        assert_eq!(named(Some(BLOCKED), Owner::Forwarded { vm: None }).action, Action::Drop);
    }

    #[test]
    fn vm_row_off_relays_only_that_vm() {
        assert_eq!(named(Some(BLOCKED), Owner::Forwarded { vm: Some("Guest Off") }).reason, Reason::AppExempt);
        assert_eq!(named(Some(BLOCKED), Owner::Forwarded { vm: Some("other guest") }).action, Action::Drop);
        assert_eq!(named(Some(BLOCKED), Owner::App { key: "vm:guest off" }).reason, Reason::AppExempt, "only a literal row matches a key");
        let unidentified = Policy { sieving: true, off_apps: vec![vm_key(None)], ..Policy::default() };
        let f = DomainFilter::new(&unidentified, rules());
        let flow = |vm| Flow { dns: false, name: Some(BLOCKED), remote: remote(), owner: Owner::Forwarded { vm } };
        assert_eq!(f.decide(flow(None), &names(), 0).reason, Reason::AppExempt);
        assert_eq!(f.decide(flow(Some("named")), &names(), 0).action, Action::Drop);
    }

    #[test]
    fn unknown_owner_is_sieved() {
        assert_eq!(named(Some(BLOCKED), Owner::Unknown).action, Action::Drop);
    }

    #[test]
    fn global_switch_off_relays_everything() {
        let f = DomainFilter { enabled: false, ..filter() };
        for owner in [Owner::App { key: BROWSER }, Owner::Unknown, Owner::Forwarded { vm: None }] {
            let got = f.decide(Flow { dns: false, name: Some(BLOCKED), remote: remote(), owner }, &names(), 0);
            assert_eq!((got.action, got.reason), (Action::Pass, Reason::Disabled));
        }
        let got = DomainFilter::inert().decide(Flow { dns: false, name: Some(BLOCKED), remote: remote(), owner: Owner::Unknown }, &names(), 0);
        assert_eq!(got.action, Action::Pass);
    }

    #[test]
    fn ech_flow_is_decided_by_its_outer_name() {
        let hello = build::handshake(&[build::sni_ext(BLOCKED), build::ech_ext()]);
        let d = TcpClassifier::new().push(&build::records(&hello, 16_384)).unwrap();
        assert!(d.ech);
        let map = names();
        map.lock().unwrap().record(OTHER, remote(), 60, 0);
        let got = filter().decide(Flow::from_decoded(&d, false, remote(), Owner::Unknown), &map, 0);
        assert_eq!((got.action, got.reason), (Action::Drop, Reason::NamedBlock), "the outer name decides, not the IP map");
    }

    #[test]
    fn the_users_lists_compile_only_when_enabled() {
        let list = |kind, entry: &str, enabled| DomainList { kind, entries: vec![entry.to_string()], enabled };
        let policy = Policy {
            domain_lists: vec![list(DomainListKind::Block, "mine.example", true), list(DomainListKind::Allow, BLOCKED, true), list(DomainListKind::Block, "disabled.example", false)],
            sieving: true,
            ..Policy::default()
        };
        let rules = RuleSet { user: Arc::new(user_engine(&policy)), lists: rules().lists };
        let f = DomainFilter::new(&policy, rules);
        let flow = |name| Flow { dns: false, name: Some(name), remote: remote(), owner: Owner::Unknown };
        assert_eq!(f.decide(flow("mine.example"), &names(), 0).list.as_deref(), Some("user"));
        assert_eq!(f.decide(flow(BLOCKED), &names(), 0).reason, Reason::NamedAllow, "the user's allow beats the list");
        assert_eq!(f.decide(flow("disabled.example"), &names(), 0).action, Action::Pass);
    }

    #[test]
    fn an_off_app_change_swaps_the_snapshot_without_a_recompile() {
        let slot = FilterSlot::new(filter());
        let before = slot.get();
        let policy = Policy { sieving: true, off_apps: vec![BROWSER.to_string()], ..Policy::default() };
        slot.update(|f| DomainFilter::new(&policy, f.rules.clone()));
        let after = slot.get();
        assert!(Arc::ptr_eq(&before.rules.lists, &after.rules.lists), "the compiled engine is shared");
        let flow = Flow { dns: false, name: Some(BLOCKED), remote: remote(), owner: Owner::App { key: BROWSER } };
        assert_eq!(before.decide(flow, &names(), 0).action, Action::Drop, "a held snapshot keeps its decision");
        assert_eq!(after.decide(flow, &names(), 0).action, Action::Pass);
    }

    #[tokio::test]
    async fn a_wait_on_an_app_ends_when_it_turns_off_and_on_nothing_else() {
        const WAIT: std::time::Duration = std::time::Duration::from_millis(20);
        let slot = FilterSlot::new(filter());
        let browser = Owner::App { key: BROWSER };
        let waits = |owner| tokio::time::timeout(WAIT, slot.until_off(owner));
        waits(Owner::App { key: OFF_APP }).await.expect("already Off: at once");
        waits(Owner::Forwarded { vm: Some("Guest Off") }).await.expect("a guest's row too");

        let mut waiting = Box::pin(slot.until_off(browser));
        assert!(tokio::time::timeout(WAIT, &mut waiting).await.is_err(), "not Off");
        slot.update(|f| f.with_lists(Arc::new(RuleEngine::empty())));
        assert!(tokio::time::timeout(WAIT, &mut waiting).await.is_err(), "a swap that leaves it on");
        let other = Policy { sieving: true, off_apps: vec!["other".to_string()], ..Policy::default() };
        slot.update(|f| DomainFilter::new(&other, f.rules.clone()));
        assert!(tokio::time::timeout(WAIT, &mut waiting).await.is_err(), "another app's Off");
        let off = Policy { sieving: true, off_apps: vec![BROWSER.to_string()], ..Policy::default() };
        slot.update(|f| DomainFilter::new(&off, f.rules.clone()));
        tokio::time::timeout(WAIT, &mut waiting).await.expect("its own Off");
        assert!(waits(Owner::Unknown).await.is_err(), "an unattributed flow has no row to turn Off");
    }
}
