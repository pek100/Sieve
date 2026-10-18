//! Flow tasks with a bounded shutdown.
//!
//! Live run 2 (AdGuard on, thousands of stuck flows) printed its summary and
//! then never exited: the probe left every flow task running and let the
//! tokio runtime's drop tear them down. Each task owned an ipstack TCP
//! stream, whose `Drop` uses `block_in_place` + `block_on` to wait for the
//! stream's own session task; while the runtime is shutting down nothing
//! drives that task any more, so the drop waits forever.
//!
//! [`FlowTasks`] keeps every flow task in one `JoinSet`. [`FlowTasks::shutdown`]
//! aborts them all and waits (bounded) for them to finish while the runtime
//! is still fully running, so those drops complete. The probe then shuts the
//! runtime down with a timeout, and a watchdog thread exits the process
//! after cleanup if anything still hangs.

use std::future::Future;
use std::time::Duration;

use tokio::task::JoinSet;

#[derive(Default)]
pub struct FlowTasks {
    set: JoinSet<()>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ShutdownReport {
    /// Flow tasks still running when shutdown began.
    pub live: usize,
    /// All of them finished within the bound.
    pub drained: bool,
}

impl FlowTasks {
    pub fn new() -> Self {
        Self::default()
    }

    /// Spawns a flow task (finished tasks are reaped first, so the set only
    /// holds live flows).
    pub fn spawn<F>(&mut self, flow: F)
    where
        F: Future<Output = ()> + Send + 'static,
    {
        while self.set.try_join_next().is_some() {}
        self.set.spawn(flow);
    }

    pub fn live(&mut self) -> usize {
        while self.set.try_join_next().is_some() {}
        self.set.len()
    }

    /// Aborts every flow task and waits up to `bound` for all of them to
    /// finish (their drops run on the still-running runtime).
    pub async fn shutdown(mut self, bound: Duration) -> ShutdownReport {
        let live = self.live();
        self.set.abort_all();
        let drained = tokio::time::timeout(bound, async { while self.set.join_next().await.is_some() {} }).await.is_ok();
        ShutdownReport { live, drained }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::flow::flows::Action;
    use crate::flow::relay::relay_tcp;
    use crate::flow::sni::build;
    use std::time::Instant;
    use tokio::io::AsyncWriteExt;
    use tokio::net::{TcpListener, TcpStream};

    /// A stand-in for ipstack's TCP stream: its Drop blocks the worker on a
    /// task of the runtime, exactly the pattern that hung run 2's exit.
    struct BlockingDrop;

    impl Drop for BlockingDrop {
        fn drop(&mut self) {
            let handle = tokio::runtime::Handle::current();
            let inner = handle.spawn(tokio::time::sleep(Duration::from_millis(20)));
            tokio::task::block_in_place(|| {
                let _ = handle.block_on(inner);
            });
        }
    }

    #[test]
    fn stuck_relays_and_connects_are_cancelled_within_a_bound() {
        let rt = tokio::runtime::Builder::new_multi_thread().worker_threads(2).enable_all().build().unwrap();
        let started = Instant::now();
        let report = rt.block_on(async {
            // An upstream that accepts and then never reads nor answers.
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = listener.local_addr().unwrap();
            let held = tokio::spawn(async move {
                let mut keep = Vec::new();
                while let Ok((s, _)) = listener.accept().await {
                    keep.push(s);
                }
            });
            let mut tasks = FlowTasks::new();
            let mut apps = Vec::new();
            for i in 0..40 {
                // A relay that decided pass and now waits forever on both sides.
                let up = TcpStream::connect(addr).await.unwrap();
                let (mut app, mut relay_side) = tokio::io::duplex(64 * 1024);
                app.write_all(&build::typical(&format!("stuck{i}.example"))).await.unwrap();
                apps.push(app);
                tasks.spawn(async move {
                    let _guard = BlockingDrop;
                    let _ = relay_tcp(&mut relay_side, up, Duration::from_secs(3600), |_| Action::Pass).await;
                });
                // A forwarder connect that never completes.
                tasks.spawn(async move {
                    let _guard = BlockingDrop;
                    std::future::pending::<()>().await;
                });
            }
            tokio::time::sleep(Duration::from_millis(300)).await;
            assert_eq!(tasks.live(), 80, "the flows really are stuck before shutdown");
            let report = tasks.shutdown(Duration::from_secs(3)).await;
            held.abort();
            drop(apps);
            report
        });
        rt.shutdown_timeout(Duration::from_secs(1));
        let took = started.elapsed();
        assert_eq!(report, ShutdownReport { live: 80, drained: true });
        assert!(took < Duration::from_secs(5), "shutdown took {took:?}");
    }

    #[test]
    fn finished_flows_are_reaped_and_an_empty_set_shuts_down_at_once() {
        let rt = tokio::runtime::Builder::new_multi_thread().worker_threads(1).enable_all().build().unwrap();
        rt.block_on(async {
            let mut tasks = FlowTasks::new();
            for _ in 0..10 {
                tasks.spawn(async {});
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
            assert_eq!(tasks.live(), 0);
            let t = Instant::now();
            assert_eq!(tasks.shutdown(Duration::from_secs(1)).await, ShutdownReport { live: 0, drained: true });
            assert!(t.elapsed() < Duration::from_millis(200));
        });
    }
}
