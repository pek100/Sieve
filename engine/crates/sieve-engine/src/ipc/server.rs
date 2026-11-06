//! The named pipe server (plan 1.3): `\\.\pipe\sieve-engine` with the DACL
//! from `service::acl::pipe_sddl`, `FILE_FLAG_FIRST_PIPE_INSTANCE` on the
//! first instance (nobody can squat the name before the engine),
//! `PIPE_REJECT_REMOTE_CLIENTS`, then per connection: the client's process
//! id, its image path ([`super::client_allowed`]) and its Windows session.

use std::os::windows::io::AsRawHandle;

use std::sync::Arc;

use sieve_ipc::PIPE_NAME;
use tokio::net::windows::named_pipe::{NamedPipeServer, ServerOptions};
use tokio::sync::watch;
use windows::Win32::Foundation::HANDLE;
use windows::Win32::System::Pipes::GetNamedPipeClientProcessId;
use windows::Win32::System::RemoteDesktop::ProcessIdToSessionId;

use super::{Backend, NOT_ALLOWED, client_allowed, refuse, serve_client};
use crate::flow::flows::os::exe_path;
use crate::service::acl::SecurityDescriptor;

/// At most this many clients at once (the app's windows; one is the norm).
const MAX_INSTANCES: usize = 8;

fn create(name: &str, sd: &SecurityDescriptor, first: bool) -> std::io::Result<NamedPipeServer> {
    let mut attributes = sd.attributes();
    let mut options = ServerOptions::new();
    options.first_pipe_instance(first).reject_remote_clients(true).max_instances(MAX_INSTANCES);
    // SAFETY: `attributes` points at `sd`'s descriptor, which outlives the
    // call; Windows copies the descriptor into the pipe object.
    unsafe { options.create_with_security_attributes_raw(name, (&raw mut attributes).cast()) }
}

/// The client process of a connected pipe: (pid, image path, session).
fn client_of(pipe: &NamedPipeServer) -> Option<(u32, String, u32)> {
    let handle = HANDLE(pipe.as_raw_handle());
    let mut pid = 0u32;
    // SAFETY: `handle` is a connected pipe server handle owned by `pipe`.
    unsafe { GetNamedPipeClientProcessId(handle, &mut pid) }.ok()?;
    let image = exe_path(pid)?;
    let mut session = 0u32;
    // SAFETY: plain call with an out pointer.
    unsafe { ProcessIdToSessionId(pid, &mut session) }.ok()?;
    Some((pid, image, session))
}

async fn handle<B: Backend>(mut pipe: NamedPipeServer, engine_exe: String, backend: Arc<B>) {
    let result = match client_of(&pipe) {
        Some((_, image, session)) if client_allowed(&image, &engine_exe) => serve_client(&mut pipe, session, backend.as_ref()).await,
        _ => refuse(&mut pipe, NOT_ALLOWED).await,
    };
    // A client that went away mid-frame is not the engine's error.
    let _ = result;
    let _ = pipe.disconnect();
}

/// Serves [`PIPE_NAME`] until `stop` turns true.
pub async fn serve<B: Backend>(pipe_sddl: &str, backend: Arc<B>, stop: watch::Receiver<bool>) -> Result<(), String> {
    serve_named(PIPE_NAME, pipe_sddl, backend, stop).await
}

/// Serves the pipe `name` until `stop` turns true. Fails when the first
/// instance cannot be created (another process holds the name, or the DACL
/// is bad).
pub(crate) async fn serve_named<B: Backend>(name: &str, pipe_sddl: &str, backend: Arc<B>, mut stop: watch::Receiver<bool>) -> Result<(), String> {
    let sd = SecurityDescriptor::from_sddl(pipe_sddl)?;
    let engine_exe = std::env::current_exe().map_err(|e| e.to_string())?.display().to_string();
    let mut server = create(name, &sd, true).map_err(|e| format!("cannot create {name}: {e}"))?;
    loop {
        tokio::select! {
            _ = stop.wait_for(|s| *s) => return Ok(()),
            connected = server.connect() => {
                if let Err(e) = connected {
                    return Err(format!("pipe connect: {e}"));
                }
            }
        }
        let next = create(name, &sd, false).map_err(|e| format!("cannot create the next pipe instance: {e}"))?;
        let client = std::mem::replace(&mut server, next);
        tokio::spawn(handle(client, engine_exe.clone(), backend.clone()));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::service::acl::{pipe_sddl, token_user_sid};
    use sieve_ipc::nonblocking::{read_frame, write_frame};
    use sieve_ipc::{ClientMessage, EngineMessage, PROTOCOL};
    use tokio::net::windows::named_pipe::ClientOptions;
    use std::time::Duration;
    use windows::Win32::Foundation::ERROR_ACCESS_DENIED;

    /// An engine that routes nothing.
    fn idle() -> Arc<crate::control::Engine> {
        Arc::new(crate::control::Engine::new(None, std::path::PathBuf::new(), sieve_ipc::Policy::default(), Default::default(), None))
    }

    fn unique(tag: &str) -> String {
        format!(r"\\.\pipe\sieve-engine-test-{tag}-{}", std::process::id())
    }

    fn running(name: &str, sddl: String) -> (watch::Sender<bool>, tokio::task::JoinHandle<Result<(), String>>) {
        let (tx, rx) = watch::channel(false);
        let name = name.to_string();
        (tx, tokio::spawn(async move { serve_named(&name, &sddl, idle(), rx).await }))
    }

    /// Opens `name`, waiting (up to a second) for the server to create it.
    async fn open(name: &str) -> std::io::Result<tokio::net::windows::named_pipe::NamedPipeClient> {
        for _ in 0..200 {
            match ClientOptions::new().open(name) {
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => tokio::time::sleep(Duration::from_millis(5)).await,
                other => return other,
            }
        }
        ClientOptions::new().open(name)
    }

    /// Live, on a real pipe, run by the test's own (unprivileged) user: the
    /// DACL admits the recorded owner, and the client check then refuses this
    /// test binary, which is not Sieve.exe beside the engine.
    #[tokio::test]
    async fn the_owner_gets_through_the_dacl_and_a_foreign_exe_is_refused() {
        let name = unique("owner");
        let (stop, task) = running(&name, pipe_sddl(Some(&token_user_sid().unwrap())).unwrap());
        let mut client = open(&name).await.expect("the recorded owner may open the pipe");
        write_frame(&mut client, &ClientMessage::Hello { protocol: PROTOCOL, app_version: "test".into() }).await.unwrap();
        let reply: EngineMessage = read_frame(&mut client).await.unwrap();
        assert_eq!(reply, EngineMessage::Error { message: NOT_ALLOWED.into() });
        stop.send(true).unwrap();
        task.await.unwrap().unwrap();
    }

    /// Live: with no owner recorded only SYSTEM and Administrators are in the
    /// DACL, so this test's account (unelevated: its Administrators group is
    /// deny-only) is refused by Windows itself. A second Windows user is in
    /// the same position against the real pipe.
    #[tokio::test]
    async fn an_account_not_in_the_dacl_cannot_open_the_pipe() {
        if is_elevated() {
            eprintln!("skipped: elevated test process (Administrators is in the DACL)");
            return;
        }
        let name = unique("denied");
        let (stop, task) = running(&name, pipe_sddl(None).unwrap());
        let err = open(&name).await.expect_err("not in the DACL");
        assert_eq!(err.raw_os_error(), Some(ERROR_ACCESS_DENIED.0 as i32), "{err}");
        stop.send(true).unwrap();
        task.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn the_name_cannot_be_served_twice() {
        let name = unique("first");
        let sddl = pipe_sddl(Some(&token_user_sid().unwrap())).unwrap();
        let (stop, task) = running(&name, sddl.clone());
        let _client = open(&name).await.unwrap();
        let (_tx, rx) = watch::channel(false);
        let second = serve_named(&name, &sddl, idle(), rx).await;
        assert!(second.is_err(), "FILE_FLAG_FIRST_PIPE_INSTANCE refuses a squatter");
        stop.send(true).unwrap();
        task.await.unwrap().unwrap();
    }

    fn is_elevated() -> bool {
        use windows::Win32::Foundation::CloseHandle;
        use windows::Win32::Security::{GetTokenInformation, TOKEN_ELEVATION, TOKEN_QUERY, TokenElevation};
        use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};
        let mut token = Default::default();
        let mut e = TOKEN_ELEVATION::default();
        let mut len = 0u32;
        // SAFETY: plain calls; `e` is the out buffer of its own size; the
        // handle is closed once.
        unsafe {
            if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token).is_err() {
                return false;
            }
            let ok = GetTokenInformation(
                token,
                TokenElevation,
                Some((&raw mut e).cast()),
                std::mem::size_of::<TOKEN_ELEVATION>() as u32,
                &mut len,
            );
            let _ = CloseHandle(token);
            ok.is_ok() && e.TokenIsElevated != 0
        }
    }
}