//! Slice 4's per-flow domain decision. DNS is never a blocking decision:
//! Windows shares its DNS client between apps, so blocking a lookup would
//! also block an app whose policy is Off. A decoded name wins over the
//! shared IP map; an unnamed flow is blocked only if every live name blocks.

use std::net::IpAddr;

use sieve_filter::rules::{HostVerdict, RuleEngine};

use crate::dns::NameMap;
use crate::flow::flows::{Action, AppPolicy, Level};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reason {
    Disabled,
    Dns,
    AppExempt,
    NamedBlock,
    NamedAllow,
    NamedNoRule,
    AllResolvedNamesBlocked,
    MixedResolvedNames,
    UnknownDomain,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Decision {
    pub action: Action,
    pub reason: Reason,
}

impl Decision {
    fn pass(reason: Reason) -> Self {
        Self {
            action: Action::Pass,
            reason,
        }
    }

    fn block(reason: Reason) -> Self {
        Self {
            action: Action::Drop,
            reason,
        }
    }
}

/// Inputs known for a new TCP or UDP flow. `name` is SNI, HTTP Host or
/// QUIC SNI, never the name from an unrelated DNS request.
pub struct Flow<'a> {
    pub dns: bool,
    pub name: Option<&'a str>,
    pub remote: IpAddr,
    pub exe: Option<&'a str>,
}

pub struct DomainFilter {
    pub enabled: bool,
    pub apps: AppPolicy,
    pub rules: RuleEngine,
}

impl DomainFilter {
    pub fn decide(&self, flow: Flow<'_>, names: &NameMap, now_ms: u64) -> Decision {
        if !self.enabled {
            return Decision::pass(Reason::Disabled);
        }
        if flow.dns {
            return Decision::pass(Reason::Dns);
        }
        if self.apps.level_of(flow.exe) != Level::Sieve {
            return Decision::pass(Reason::AppExempt);
        }
        if let Some(name) = flow.name {
            return match self.rules.check_host(name) {
                HostVerdict::Block => Decision::block(Reason::NamedBlock),
                HostVerdict::Allow => Decision::pass(Reason::NamedAllow),
                HostVerdict::None => Decision::pass(Reason::NamedNoRule),
            };
        }
        let live = names.names(flow.remote, now_ms);
        if live.is_empty() {
            return Decision::pass(Reason::UnknownDomain);
        }
        if live
            .iter()
            .all(|name| self.rules.check_host(name) == HostVerdict::Block)
        {
            Decision::block(Reason::AllResolvedNamesBlocked)
        } else {
            Decision::pass(Reason::MixedResolvedNames)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sieve_filter::rules::ListText;

    fn filter() -> DomainFilter {
        DomainFilter {
            enabled: true,
            apps: AppPolicy::new(Level::Sieve).set(r"C:\Apps\off.exe", Level::Off),
            rules: RuleEngine::compile(&[ListText {
                id: "test",
                text: "||ads.example^\n@@||ok.ads.example^\n",
                trusted: false,
            }]),
        }
    }

    fn flow(name: Option<&str>) -> Flow<'_> {
        Flow {
            dns: false,
            name,
            remote: "192.0.2.1".parse().unwrap(),
            exe: Some(r"C:\Apps\browser.exe"),
        }
    }

    #[test]
    fn filtered_flow_blocks_but_off_app_and_dns_pass() {
        let f = filter();
        let names = NameMap::default();
        assert_eq!(
            f.decide(flow(Some("ads.example")), &names, 0).action,
            Action::Drop
        );
        let exempt = Flow {
            exe: Some(r"c:/APPS/OFF.exe"),
            ..flow(Some("ads.example"))
        };
        assert_eq!(f.decide(exempt, &names, 0).reason, Reason::AppExempt);
        let dns = Flow {
            dns: true,
            ..flow(Some("ads.example"))
        };
        assert_eq!(f.decide(dns, &names, 0).reason, Reason::Dns);
    }

    #[test]
    fn a_decoded_name_beats_other_names_on_a_shared_address() {
        let f = filter();
        let mut names = NameMap::default();
        names.record("ads.example", flow(None).remote, 60, 0);
        assert_eq!(
            f.decide(flow(Some("news.example")), &names, 0).reason,
            Reason::NamedNoRule
        );
        assert_eq!(
            f.decide(flow(Some("ok.ads.example")), &names, 0).reason,
            Reason::NamedAllow
        );
        names.record("news.example", flow(None).remote, 60, 0);
        assert_eq!(
            f.decide(flow(Some("ads.example")), &names, 0).action,
            Action::Drop
        );
    }

    #[test]
    fn unnamed_flows_require_a_nonempty_unanimous_unexpired_set() {
        let f = filter();
        let mut names = NameMap::default();
        assert_eq!(
            f.decide(flow(None), &names, 0).reason,
            Reason::UnknownDomain
        );
        names.record("ads.example", flow(None).remote, 60, 0);
        names.record("other.ads.example", flow(None).remote, 60, 0);
        assert_eq!(
            f.decide(flow(None), &names, 0).reason,
            Reason::AllResolvedNamesBlocked
        );
        names.record("ok.ads.example", flow(None).remote, 20, 0);
        assert_eq!(
            f.decide(flow(None), &names, 0).reason,
            Reason::MixedResolvedNames
        );
        assert_eq!(f.decide(flow(None), &names, 20_000).action, Action::Drop);
        assert_eq!(
            f.decide(flow(None), &names, 60_000).reason,
            Reason::UnknownDomain
        );
    }

    #[test]
    fn exemptions_apply_even_without_an_executable_or_a_decoded_name() {
        let mut f = filter();
        let mut names = NameMap::default();
        names.record("ads.example", flow(None).remote, 60, 0);
        f.apps = AppPolicy::new(Level::Off);
        assert_eq!(
            f.decide(
                Flow {
                    exe: None,
                    ..flow(None)
                },
                &names,
                0
            )
            .reason,
            Reason::AppExempt
        );
        f.enabled = false;
        assert_eq!(
            f.decide(flow(Some("ads.example")), &names, 0).reason,
            Reason::Disabled
        );
    }
}
