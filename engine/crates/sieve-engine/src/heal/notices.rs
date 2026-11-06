//! One notice per app (plan 4.3, task D5): a new pinning exclusion joins the open
//! group of (session, exe), or opens one. The window runs from the group's first
//! exclusion and does not move, so a slow trickle cannot hold a group open. Memory
//! only: the rows stay, the toast is about now. Pure; the clock is passed in.

use std::collections::VecDeque;

use sieve_ipc::HealNotice;

use super::dials::{NOTICE_HOSTS_MAX, NOTICE_RING, NOTICE_WINDOW_MS};

#[derive(Debug)]
struct Group {
    notice: HealNotice,
    first_ms: u64,
}

/// The ring of groups, oldest first.
#[derive(Debug, Default)]
pub struct Notices {
    groups: VecDeque<Group>,
    next_id: u64,
    revision: u64,
}

impl Notices {
    /// A new exclusion of `host` by `exe` (the file name, lower case).
    pub fn push(&mut self, session: u32, exe: &str, host: &str, now_ms: u64) {
        self.revision += 1;
        let revision = self.revision;
        let open = self.groups.iter_mut().rev().find(|g| g.notice.session == session && g.notice.exe == exe && now_ms.saturating_sub(g.first_ms) < NOTICE_WINDOW_MS);
        if let Some(group) = open {
            let notice = &mut group.notice;
            notice.total = notice.total.saturating_add(1);
            notice.rev = revision;
            if notice.hosts.len() < NOTICE_HOSTS_MAX {
                notice.hosts.push(host.to_string());
            }
            return;
        }
        self.next_id += 1;
        let notice = HealNotice { id: self.next_id, session, exe: exe.to_string(), hosts: vec![host.to_string()], total: 1, rev: revision };
        self.groups.push_back(Group { notice, first_ms: now_ms });
        if self.groups.len() > NOTICE_RING {
            self.groups.pop_front();
        }
    }

    pub fn revision(&self) -> u64 {
        self.revision
    }

    /// The groups that changed after `after`. A cursor past the newest revision is
    /// from before a restart, so it reads from the start.
    pub fn after(&self, after: u64) -> Vec<HealNotice> {
        let after = if after > self.revision { 0 } else { after };
        self.groups.iter().filter(|g| g.notice.rev > after).map(|g| g.notice.clone()).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: u64 = 1_793_000_000_000;
    const APP: &str = "client.exe";

    fn pushed(items: &[(u32, &str, &str, u64)]) -> Notices {
        let mut notices = Notices::default();
        for (session, exe, host, at) in items {
            notices.push(*session, exe, host, *at);
        }
        notices
    }

    #[test]
    fn one_exclusion_one_notice() {
        let all = pushed(&[(1, APP, "a.example", NOW)]).after(0);
        assert_eq!(all, [HealNotice { id: 1, session: 1, exe: APP.into(), hosts: vec!["a.example".into()], total: 1, rev: 1 }]);
    }

    #[test]
    fn same_app_within_the_window_groups() {
        let all = pushed(&[(1, APP, "a.example", NOW), (1, APP, "b.example", NOW + NOTICE_WINDOW_MS - 1)]).after(0);
        assert_eq!(all.len(), 1);
        assert_eq!((all[0].id, all[0].total, all[0].rev), (1, 2, 2));
        assert_eq!(all[0].hosts, ["a.example", "b.example"]);
    }

    #[test]
    fn at_the_window_a_new_group_opens() {
        let all = pushed(&[(1, APP, "a.example", NOW), (1, APP, "b.example", NOW + NOTICE_WINDOW_MS)]).after(0);
        assert_eq!(all.iter().map(|n| (n.id, n.total)).collect::<Vec<_>>(), [(1, 1), (2, 1)]);
    }

    #[test]
    fn a_trickle_cannot_hold_a_group_open() {
        let step = NOTICE_WINDOW_MS / 2;
        let all = pushed(&[(1, APP, "a.example", NOW), (1, APP, "b.example", NOW + step), (1, APP, "c.example", NOW + 2 * step), (1, APP, "d.example", NOW + 3 * step)]).after(0);
        assert_eq!(all.iter().map(|n| n.total).collect::<Vec<_>>(), [2, 2], "the third is past the first's window, however recent the second");
    }

    #[test]
    fn other_app_other_group() {
        let all = pushed(&[(1, APP, "a.example", NOW), (1, "other.exe", "a.example", NOW)]).after(0);
        assert_eq!(all.len(), 2);
    }

    #[test]
    fn another_session_is_another_group() {
        assert_eq!(pushed(&[(1, APP, "a.example", NOW), (2, APP, "a.example", NOW)]).after(0).len(), 2);
    }

    #[test]
    fn hosts_are_capped_and_total_is_true() {
        let mut notices = Notices::default();
        for i in 0..NOTICE_HOSTS_MAX * 3 {
            notices.push(1, APP, &format!("h{i}.example"), NOW);
        }
        let all = notices.after(0);
        assert_eq!(all.len(), 1);
        assert_eq!(all[0].hosts.len(), NOTICE_HOSTS_MAX);
        assert_eq!(all[0].total as usize, NOTICE_HOSTS_MAX * 3);
    }

    #[test]
    fn the_ring_is_bounded() {
        let mut notices = Notices::default();
        for i in 0..NOTICE_RING * 3 {
            notices.push(1, &format!("app{i}.exe"), "a.example", NOW);
        }
        let all = notices.after(0);
        assert_eq!(all.len(), NOTICE_RING);
        assert_eq!(all.last().unwrap().exe, format!("app{}.exe", NOTICE_RING * 3 - 1), "the newest stayed");
    }

    #[test]
    fn a_cursor_reads_what_changed_after_it() {
        let notices = pushed(&[(1, APP, "a.example", NOW), (1, "other.exe", "a.example", NOW), (1, APP, "b.example", NOW)]);
        assert_eq!(notices.revision(), 3);
        assert!(notices.after(3).is_empty());
        let changed = notices.after(2);
        assert_eq!(changed.len(), 1);
        assert_eq!((changed[0].exe.as_str(), changed[0].rev), (APP, 3));
    }

    #[test]
    fn a_cursor_past_a_restart_reads_from_the_start() {
        let notices = pushed(&[(1, APP, "a.example", NOW)]);
        assert_eq!(notices.after(9000).len(), 1);
        assert!(Notices::default().after(9000).is_empty());
    }
}
