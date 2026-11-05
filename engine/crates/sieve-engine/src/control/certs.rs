//! The certificate loop: runs `Ca::reconcile` on a policy change, on the
//! user's Reinstall and every [`TICK`] while there is anything to hold; with
//! nothing to hold it waits with no timer at all (plan 6: idle CPU 0). This
//! is the one place that reads the wall clock for the CA.
//!
//! `wanted` is `policy.https` alone (plan 2.4): pausing `filtering.engine`
//! does not churn roots.

use std::sync::Arc;
use std::time::Duration;

use tokio::sync::watch;

use super::Engine;
use crate::ca::Ca;
use crate::policy::wall_ms;

/// Rotation, retiring and the Firefox policy are checked this often.
pub const TICK: Duration = Duration::from_secs(3_600);

/// Runs until `stop` turns true. Stopping removes nothing: the root is not
/// network state and changes nothing while the engine is stopped.
pub async fn run(engine: Arc<Engine>, ca: Arc<Ca>, mut stop: watch::Receiver<bool>) {
    loop {
        let wanted = engine.policy().https;
        let reinstall = engine.take_reinstall();
        let job = ca.clone();
        // The system calls block; the failures are in status.
        let done = tokio::task::spawn_blocking(move || {
            let _ = if reinstall && wanted { job.reinstall(wall_ms()) } else { job.reconcile(wanted, wall_ms()) };
            job.holding()
        });
        let holding = done.await.unwrap_or(true);
        let tick = async {
            if wanted || holding { tokio::time::sleep(TICK).await } else { std::future::pending::<()>().await }
        };
        tokio::select! {
            _ = engine.ca_wake.notified() => {}
            _ = tick => {}
            changed = stop.changed() => {
                // No sender left means nobody can ever ask again: stop too.
                if changed.is_err() {
                    return;
                }
            }
        }
        if *stop.borrow() {
            return;
        }
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use sieve_ipc::{CertState, Policy};

    use super::*;
    use crate::ca::key::MemoryKeyStore;
    use crate::ca::trust::{FakeFirefox, FakeRootStore};
    use crate::ca::{Seams, state};
    use crate::ipc::Backend;
    use crate::policy::Runs;

    struct Rig {
        dir: tempfile::TempDir,
        engine: Arc<Engine>,
        ca: Arc<Ca>,
        store: Arc<FakeRootStore>,
    }

    fn rig(policy: Policy) -> Rig {
        let dir = tempfile::tempdir().unwrap();
        let store = Arc::new(FakeRootStore::default());
        let seams = Seams { keys: Arc::new(MemoryKeyStore::default()), store: store.clone(), firefox: Arc::new(FakeFirefox::default()) };
        let ca = Arc::new(Ca::new(dir.path().to_path_buf(), "BOX".into(), seams).unwrap());
        let engine = Arc::new(Engine::new(None, PathBuf::new(), policy, Runs::default(), None));
        engine.attach_ca(ca.clone());
        Rig { dir, engine, ca, store }
    }

    async fn until(what: &str, check: impl Fn() -> bool) {
        for _ in 0..500 {
            if check() {
                return;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        panic!("never happened: {what}");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_policy_change_wakes_the_loop_and_off_removes_the_root() {
        let r = rig(Policy::default());
        let (stop, stop_rx) = watch::channel(false);
        let task = tokio::spawn(run(r.engine.clone(), r.ca.clone(), stop_rx));

        r.engine.set_policy(Policy { revision: 1, https: true, ..Policy::default() }).unwrap();
        until("the root is installed", || r.store.thumbprints().len() == 1).await;
        until("status says so", || r.engine.cert_status().state == CertState::Installed).await;

        r.engine.set_policy(Policy { revision: 2, https: false, ..Policy::default() }).unwrap();
        until("the root is removed", || r.store.thumbprints().is_empty()).await;
        until("the record is clear", || state::load(r.dir.path()).unwrap().is_clear()).await;

        stop.send(true).unwrap();
        task.await.unwrap();
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn install_root_makes_a_new_root_through_the_loop() {
        let r = rig(Policy { revision: 1, https: true, ..Policy::default() });
        let (stop, stop_rx) = watch::channel(false);
        let task = tokio::spawn(run(r.engine.clone(), r.ca.clone(), stop_rx));
        until("the root is installed", || r.store.thumbprints().len() == 1).await;
        let first = r.store.thumbprints();
        r.engine.install_root().unwrap();
        until("a new root replaced it", || r.store.thumbprints().len() == 1 && r.store.thumbprints() != first).await;
        stop.send(true).unwrap();
        task.await.unwrap();
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn stopping_the_loop_leaves_the_root_in_place() {
        let r = rig(Policy { revision: 1, https: true, ..Policy::default() });
        let (stop, stop_rx) = watch::channel(false);
        let task = tokio::spawn(run(r.engine.clone(), r.ca.clone(), stop_rx));
        until("the root is installed", || r.store.thumbprints().len() == 1).await;
        stop.send(true).unwrap();
        task.await.unwrap();
        assert_eq!(r.store.thumbprints().len(), 1);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_dropped_stop_sender_ends_the_loop_instead_of_spinning() {
        let r = rig(Policy { revision: 1, https: true, ..Policy::default() });
        let (stop, stop_rx) = watch::channel(false);
        let task = tokio::spawn(run(r.engine.clone(), r.ca.clone(), stop_rx));
        until("the root is installed", || r.store.thumbprints().len() == 1).await;
        drop(stop);
        tokio::time::timeout(Duration::from_secs(5), task).await.unwrap().unwrap();
    }

    #[test]
    fn install_root_is_refused_while_https_is_off() {
        let r = rig(Policy::default());
        assert!(r.engine.install_root().unwrap_err().contains("HTTPS filtering is off"));
        assert!(!r.engine.take_reinstall());
        assert!(r.store.thumbprints().is_empty());
    }

    #[test]
    fn with_no_ca_the_status_is_not_installed_and_install_is_refused() {
        let engine = Engine::new(None, PathBuf::new(), Policy { revision: 1, https: true, ..Policy::default() }, Runs::default(), None);
        assert_eq!(engine.cert_status(), sieve_ipc::CertStatus::default());
        assert!(engine.install_root().is_err());
    }
}
