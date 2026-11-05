//! The new engine's report to its supervisor (plan 7.5). After a start with a
//! pending release it connects to its own pipe and reads one frame. The client
//! check rightly refuses anything but `sieve.exe`, so that frame is `NOT_ALLOWED`,
//! which proves the serve loop answers; `client_allowed` and `serve` are unchanged.
//! Then the version record rises and the pending file goes, which the supervisor
//! polls for.

use std::path::Path;
use std::time::Duration;

use sieve_ipc::EngineMessage;
use sieve_ipc::nonblocking::read_frame;
use tokio::net::windows::named_pipe::ClientOptions;

use super::state::{self, Pending};
use crate::ipc::NOT_ALLOWED;

/// The pipe comes up moments after the service reports Running.
const OPEN_TRIES: u32 = 200;
const OPEN_RETRY: Duration = Duration::from_millis(100);
const ANSWER_WAIT: Duration = Duration::from_secs(10);

/// True when the engine's own pipe answered with the frame a foreign exe gets.
pub async fn pipe_answers(pipe: &str, tries: u32) -> Result<(), String> {
    let mut client = open(pipe, tries).await?;
    let frame = tokio::time::timeout(ANSWER_WAIT, read_frame::<_, EngineMessage>(&mut client));
    match frame.await {
        Ok(Ok(EngineMessage::Error { message })) if message == NOT_ALLOWED => Ok(()),
        Ok(Ok(other)) => Err(format!("unexpected answer: {other:?}")),
        Ok(Err(e)) => Err(e.to_string()),
        Err(_) => Err("the pipe did not answer".into()),
    }
}

async fn open(pipe: &str, tries: u32) -> Result<tokio::net::windows::named_pipe::NamedPipeClient, String> {
    let mut last = String::from("no attempt");
    for _ in 0..tries {
        match ClientOptions::new().open(pipe) {
            Ok(client) => return Ok(client),
            Err(e) => last = e.to_string(),
        }
        tokio::time::sleep(OPEN_RETRY).await;
    }
    Err(format!("{pipe}: {last}"))
}

/// The whole report: the pipe answered, so this release is the running one.
pub async fn report(pipe: &str, dir: &Path, pending: &Pending) -> Result<(), String> {
    pipe_answers(pipe, OPEN_TRIES).await?;
    state::commit_healthy(dir, pending)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ipc::server::serve_named;
    use crate::service::acl::{pipe_sddl, token_user_sid};
    use std::sync::Arc;
    use tokio::sync::watch;

    fn pending() -> Pending {
        Pending { kind: "engine".into(), from_version: 1, to_version: 2, staged: "s".into(), aside: vec![] }
    }

    /// Live, on a real pipe with the engine's own DACL shape: the test binary is
    /// no `sieve.exe`, exactly as the engine is not, so it reads `NOT_ALLOWED`.
    #[tokio::test]
    async fn the_self_probe_is_answered_by_a_real_test_pipe() {
        let name = format!(r"\\.\pipe\sieve-engine-test-health-{}", std::process::id());
        let sddl = pipe_sddl(Some(&token_user_sid().unwrap())).unwrap();
        let engine = Arc::new(crate::control::Engine::new(None, std::path::PathBuf::new(), sieve_ipc::Policy::default(), Default::default(), None));
        let (stop, rx) = watch::channel(false);
        let served = {
            let name = name.clone();
            tokio::spawn(async move { serve_named(&name, &sddl, engine, rx).await })
        };
        let dir = tempfile::tempdir().unwrap();
        let p = pending();
        state::save_pending(dir.path(), &p).unwrap();
        report(&name, dir.path(), &p).await.unwrap();
        assert!(state::is_committed(dir.path(), &p).unwrap());
        assert_eq!(state::load_pending(dir.path()).unwrap(), None);
        stop.send(true).unwrap();
        served.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn no_pipe_is_no_report() {
        let dir = tempfile::tempdir().unwrap();
        let p = pending();
        state::save_pending(dir.path(), &p).unwrap();
        let name = format!(r"\\.\pipe\sieve-engine-test-nothing-{}", std::process::id());
        assert!(pipe_answers(&name, 2).await.is_err());
        assert_eq!(state::load_pending(dir.path()).unwrap(), Some(p), "and the record stays in flight");
    }
}
