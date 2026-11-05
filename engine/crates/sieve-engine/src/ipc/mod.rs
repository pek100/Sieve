//! The engine's side of the pipe (plan 1.3). [`serve_client`] runs one
//! connection over any stream against a [`Backend`], so the handshake, the
//! requests and the flow stream are tested in memory; `server` (Windows)
//! owns the real pipe, its DACL and the client check ([`client_allowed`]).

#[cfg(windows)]
pub mod server;

use std::sync::Arc;
use std::time::Duration;

use sieve_ipc::nonblocking::{read_frame, write_frame};
use sieve_ipc::{ClientMessage, DnsUpstreams, EngineMessage, EngineStatus, FLOWS_PER_FRAME, FlowEvent, FrameError, Policy, answer_hello};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::broadcast;

use crate::stack::book::visible_to;

pub const ENGINE_VERSION: &str = env!("CARGO_PKG_VERSION");
/// The app's executable as the installer lays it out: Tauri's main binary,
/// named after the src-tauri package (`!define MAINBINARYNAME "sieve"` in
/// the generated installer.nsi, read 2026-10-18). Compared case-insensitively.
pub const APP_EXE: &str = "sieve.exe";
/// A client that sends no Hello within this is dropped.
pub const HELLO_WAIT: Duration = Duration::from_secs(5);

pub const NOT_ALLOWED: &str = "only the installed Sieve app may connect to the engine";
pub const HELLO_FIRST: &str = "send hello first";
pub const HELLO_ONCE: &str = "hello was already sent";

/// What the pipe asks of the engine (the running engine is
/// `control::Engine`; tests use a fake).
pub trait Backend: Send + Sync + 'static {
    fn status(&self) -> EngineStatus;
    /// Applies a newer policy and answers the Status after it.
    fn set_policy(&self, policy: Policy) -> Result<EngineStatus, String>;
    /// Applies a newer, valid resolver list and answers the list then held.
    fn set_dns_upstreams(&self, list: DnsUpstreams) -> Result<DnsUpstreams, String>;
    /// The open flows now, every batch from now on, and whether routes are
    /// up (a subscription ends when they go down: the app then reads the
    /// connection tables again).
    fn subscribe(&self) -> Subscription;
}

pub struct Subscription {
    pub open: Vec<FlowEvent>,
    pub batches: broadcast::Receiver<Arc<Vec<FlowEvent>>>,
    pub routes_up: tokio::sync::watch::Receiver<bool>,
}

/// Normalises a Windows path for comparison: `/` to `\`, no `\\?\` prefix,
/// lower case. None when it has a `.` or `..` component, which a real image
/// path never has.
fn normalise(path: &str) -> Option<String> {
    let p = path.replace('/', "\\");
    let p = p.strip_prefix(r"\\?\").unwrap_or(&p).to_lowercase();
    (!p.split('\\').any(|c| c == "." || c == "..")).then_some(p)
}

/// The client check (plan 1.3): only Sieve's own app executable, from the
/// folder the engine itself was installed in (Program Files, writable only
/// by admins), may talk to the engine. A renamed copy, a copy elsewhere or
/// another program in that folder is refused.
pub fn client_allowed(client_image: &str, engine_exe: &str) -> bool {
    let (Some(client), Some(engine)) = (normalise(client_image), normalise(engine_exe)) else { return false };
    let (Some((client_dir, client_name)), Some((engine_dir, _))) = (client.rsplit_once('\\'), engine.rsplit_once('\\'))
    else {
        return false;
    };
    !engine_dir.is_empty() && client_dir == engine_dir && client_name == APP_EXE.to_lowercase()
}

/// Runs one client connection to its end: Hello first (within
/// [`HELLO_WAIT`]), then requests. An Incompatible answer, a request before
/// Hello and a malformed frame end the connection after one reply. After
/// `subscribe` the connection carries `flows` batches of the client's
/// session (and the services', session 0) until either side closes.
/// `session_id` is the client process's Windows session.
pub async fn serve_client<S, B>(stream: &mut S, session_id: u32, backend: &B) -> Result<(), FrameError>
where
    S: AsyncRead + AsyncWrite + Unpin,
    B: Backend + ?Sized,
{
    let first = match tokio::time::timeout(HELLO_WAIT, read_frame::<_, ClientMessage>(stream)).await {
        Err(_) => return Ok(()),
        Ok(first) => first,
    };
    match first {
        Ok(ClientMessage::Hello { protocol, .. }) => {
            let answer = answer_hello(protocol, ENGINE_VERSION, session_id);
            let welcomed = matches!(answer, EngineMessage::Welcome { .. });
            write_frame(stream, &answer).await?;
            if !welcomed {
                return Ok(());
            }
        }
        Ok(_) => return refuse(stream, HELLO_FIRST).await,
        Err(FrameError::Closed) => return Ok(()),
        Err(e) => return refuse(stream, &e.to_string()).await,
    }
    loop {
        let reply = match read_frame::<_, ClientMessage>(stream).await {
            Ok(ClientMessage::Status) => EngineMessage::Status(backend.status()),
            Ok(ClientMessage::SetPolicy(p)) => match backend.set_policy(p) {
                Ok(status) => EngineMessage::Status(status),
                Err(message) => EngineMessage::Error { message },
            },
            Ok(ClientMessage::SetDnsUpstreams(list)) => match backend.set_dns_upstreams(list) {
                Ok(held) => EngineMessage::DnsUpstreams(held),
                Err(message) => EngineMessage::Error { message },
            },
            Ok(ClientMessage::Subscribe) => return stream_flows(stream, session_id, backend).await,
            Ok(ClientMessage::Hello { .. }) => return refuse(stream, HELLO_ONCE).await,
            Err(FrameError::Closed) => return Ok(()),
            Err(e) => return refuse(stream, &e.to_string()).await,
        };
        write_frame(stream, &reply).await?;
    }
}

/// Sends `events` the client may see, in frames of at most FLOWS_PER_FRAME.
async fn send_flows<S: AsyncWrite + Unpin>(stream: &mut S, session_id: u32, events: &[FlowEvent]) -> Result<(), FrameError> {
    let mine: Vec<FlowEvent> = events.iter().filter(|e| visible_to(e, session_id)).cloned().collect();
    for chunk in mine.chunks(FLOWS_PER_FRAME) {
        write_frame(stream, &EngineMessage::Flows { flows: chunk.to_vec() }).await?;
    }
    Ok(())
}

/// The subscribed connection: the open flows first, then each batch. A
/// client that falls behind by more than the backlog is disconnected (it
/// reconnects and starts from the open flows again); a client that closes
/// or sends anything ends the stream.
async fn stream_flows<S, B>(stream: &mut S, session_id: u32, backend: &B) -> Result<(), FrameError>
where
    S: AsyncRead + AsyncWrite + Unpin,
    B: Backend + ?Sized,
{
    let Subscription { open, mut batches, mut routes_up } = backend.subscribe();
    send_flows(stream, session_id, &open).await?;
    let (mut reader, mut writer) = tokio::io::split(stream);
    let mut probe = [0u8; 1];
    loop {
        tokio::select! {
            batch = batches.recv() => match batch {
                Ok(b) => send_flows(&mut writer, session_id, &b).await?,
                Err(_) => return Ok(()),
            },
            _ = routes_down(&mut routes_up) => return Ok(()),
            _ = tokio::io::AsyncReadExt::read(&mut reader, &mut probe) => return Ok(()),
        }
    }
}

/// Resolves once the routes are down (or the engine dropped the sender).
async fn routes_down(routes_up: &mut tokio::sync::watch::Receiver<bool>) {
    loop {
        let up = *routes_up.borrow_and_update();
        if !up || routes_up.changed().await.is_err() {
            return;
        }
    }
}

/// One Error frame, then the connection ends.
pub async fn refuse<S: AsyncWrite + Unpin>(stream: &mut S, message: &str) -> Result<(), FrameError> {
    write_frame(stream, &EngineMessage::Error { message: message.to_string() }).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::stack::book::tests_event;
    use sieve_ipc::{PROTOCOL, SUPPORTED};
    use std::sync::Mutex;
    use tokio::io::{AsyncWriteExt, DuplexStream};

    const ENGINE: &str = r"C:\Program Files\Sieve\sieve-engine.exe";

    #[test]
    fn only_sieve_exe_beside_the_engine_is_allowed() {
        assert!(client_allowed(r"C:\Program Files\Sieve\Sieve.exe", ENGINE));
        assert!(client_allowed(r"c:\program files\sieve\SIEVE.EXE", ENGINE), "case-insensitive, as NTFS is");
        assert!(client_allowed(r"\\?\C:\Program Files\Sieve\Sieve.exe", ENGINE));
        assert!(client_allowed("C:/Program Files/Sieve/Sieve.exe", ENGINE));
        for refused in [
            r"C:\Users\me\Downloads\Sieve.exe",              // a copy elsewhere
            r"C:\Program Files\Sieve\sieve-engine.exe",      // another program in the folder
            r"C:\Program Files\Sieve\Sieve-renamed.exe",     // a renamed copy
            r"C:\Program Files\Sieve2\Sieve.exe",            // a look-alike folder
            r"C:\Program Files\Sieve\sub\Sieve.exe",         // a subfolder
            r"C:\Program Files\Sieve\..\Sieve\Sieve.exe",    // a dotted path
            r"C:\Program Files\Sieve\.\Sieve.exe",
            r"Sieve.exe",                                    // no folder at all
            "",
        ] {
            assert!(!client_allowed(refused, ENGINE), "{refused}");
        }
        assert!(!client_allowed(r"C:\Program Files\Sieve\Sieve.exe", "sieve-engine.exe"), "engine path without a folder");
    }

    /// Tauri names the bundled app after the src-tauri package; a rename
    /// there must reach the client check, or the installed app is refused.
    #[test]
    fn the_allowed_exe_is_the_src_tauri_package() {
        let manifest = include_str!("../../../../../src-tauri/Cargo.toml");
        let name = manifest.lines().find_map(|l| l.strip_prefix("name = \"")?.strip_suffix('"')).unwrap();
        assert_eq!(APP_EXE, format!("{name}.exe"));
    }

    /// A stand-in engine: a policy, and a flow channel the test drives.
    struct Fake {
        policy: Mutex<Policy>,
        open: Vec<FlowEvent>,
        flows: broadcast::Sender<Arc<Vec<FlowEvent>>>,
        routes: tokio::sync::watch::Sender<bool>,
    }

    impl Fake {
        fn new(open: Vec<FlowEvent>) -> Arc<Self> {
            let routes = tokio::sync::watch::channel(true).0;
            Arc::new(Self { policy: Mutex::new(Policy::default()), open, flows: broadcast::channel(4).0, routes })
        }
    }

    impl Backend for Fake {
        fn status(&self) -> EngineStatus {
            EngineStatus { policy: *self.policy.lock().unwrap(), ..EngineStatus::default() }
        }
        fn set_policy(&self, p: Policy) -> Result<EngineStatus, String> {
            let next = crate::policy::accept(*self.policy.lock().unwrap(), p)?;
            *self.policy.lock().unwrap() = next;
            Ok(self.status())
        }
        fn set_dns_upstreams(&self, list: DnsUpstreams) -> Result<DnsUpstreams, String> {
            Ok(list)
        }
        fn subscribe(&self) -> Subscription {
            Subscription { open: self.open.clone(), batches: self.flows.subscribe(), routes_up: self.routes.subscribe() }
        }
    }

    async fn send(s: &mut DuplexStream, m: &ClientMessage) {
        write_frame(s, m).await.unwrap();
    }

    async fn recv(s: &mut DuplexStream) -> EngineMessage {
        read_frame(s).await.unwrap()
    }

    fn start_with(session: u32, fake: Arc<Fake>) -> (DuplexStream, tokio::task::JoinHandle<Result<(), FrameError>>) {
        let (client, mut engine) = tokio::io::duplex(1 << 20);
        (client, tokio::spawn(async move { serve_client(&mut engine, session, fake.as_ref()).await }))
    }

    fn start(session: u32) -> (DuplexStream, tokio::task::JoinHandle<Result<(), FrameError>>) {
        start_with(session, Fake::new(vec![]))
    }

    fn hello(protocol: u32) -> ClientMessage {
        ClientMessage::Hello { protocol, app_version: "0.1.0".into() }
    }

    #[tokio::test]
    async fn hello_then_status_answers_from_facts() {
        let (mut c, task) = start(2);
        send(&mut c, &hello(PROTOCOL)).await;
        assert_eq!(
            recv(&mut c).await,
            EngineMessage::Welcome { protocol: PROTOCOL, engine_version: ENGINE_VERSION.into(), session_id: 2 }
        );
        for _ in 0..2 {
            send(&mut c, &ClientMessage::Status).await;
            assert_eq!(recv(&mut c).await, EngineMessage::Status(EngineStatus::default()));
        }
        drop(c);
        task.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn set_policy_answers_the_new_status_and_a_stale_one_is_an_error() {
        let (mut c, task) = start(1);
        send(&mut c, &hello(PROTOCOL)).await;
        recv(&mut c).await;
        let on = Policy { revision: 1, engine: true };
        send(&mut c, &ClientMessage::SetPolicy(on)).await;
        assert!(matches!(recv(&mut c).await, EngineMessage::Status(s) if s.policy == on));
        send(&mut c, &ClientMessage::SetPolicy(Policy { revision: 1, engine: false })).await;
        assert!(matches!(recv(&mut c).await, EngineMessage::Error { message } if message.contains("stale")));
        send(&mut c, &ClientMessage::Status).await;
        assert!(matches!(recv(&mut c).await, EngineMessage::Status(s) if s.policy == on), "the connection stays usable");
        drop(c);
        task.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn a_subscriber_gets_its_sessions_open_flows_then_batches_and_never_another_users() {
        let mut mine = tests_event(Some(1));
        mine.id = 1;
        let mut service = tests_event(Some(0));
        service.id = 2;
        let mut other_user = tests_event(Some(2));
        other_user.id = 3;
        let fake = Fake::new(vec![mine.clone(), other_user.clone()]);
        let (mut c, task) = start_with(1, fake.clone());
        send(&mut c, &hello(PROTOCOL)).await;
        recv(&mut c).await;
        send(&mut c, &ClientMessage::Subscribe).await;
        assert_eq!(recv(&mut c).await, EngineMessage::Flows { flows: vec![mine.clone()] });
        fake.flows.send(Arc::new(vec![other_user, service.clone()])).unwrap();
        assert_eq!(recv(&mut c).await, EngineMessage::Flows { flows: vec![service] });
        // A batch with nothing for this session sends no frame.
        fake.flows.send(Arc::new(vec![tests_event(Some(5))])).unwrap();
        let mut closing = mine;
        closing.open = false;
        fake.flows.send(Arc::new(vec![closing.clone()])).unwrap();
        assert_eq!(recv(&mut c).await, EngineMessage::Flows { flows: vec![closing] });
        drop(c);
        task.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn the_stream_ends_when_the_routes_go_down() {
        let fake = Fake::new(vec![]);
        let (mut c, task) = start_with(1, fake.clone());
        send(&mut c, &hello(PROTOCOL)).await;
        recv(&mut c).await;
        send(&mut c, &ClientMessage::Subscribe).await;
        tokio::task::yield_now().await;
        fake.routes.send(false).unwrap();
        task.await.unwrap().unwrap();
        assert!(matches!(read_frame::<_, EngineMessage>(&mut c).await, Err(FrameError::Closed)));
    }

    #[tokio::test]
    async fn a_big_batch_is_split_into_frames() {
        let events: Vec<FlowEvent> = (0..(FLOWS_PER_FRAME as u64 + 3))
            .map(|i| {
                let mut e = tests_event(Some(1));
                e.id = i;
                e
            })
            .collect();
        let (mut c, task) = start_with(1, Fake::new(events));
        send(&mut c, &hello(PROTOCOL)).await;
        recv(&mut c).await;
        send(&mut c, &ClientMessage::Subscribe).await;
        let sizes = [recv(&mut c).await, recv(&mut c).await].map(|m| match m {
            EngineMessage::Flows { flows } => flows.len(),
            other => panic!("{other:?}"),
        });
        assert_eq!(sizes, [FLOWS_PER_FRAME, 3]);
        drop(c);
        task.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn an_unsupported_protocol_gets_incompatible_and_the_pipe_closes() {
        let (mut c, task) = start(1);
        send(&mut c, &hello(SUPPORTED[1] + 1)).await;
        assert_eq!(recv(&mut c).await, EngineMessage::Incompatible { supported: SUPPORTED });
        task.await.unwrap().unwrap();
        assert!(matches!(read_frame::<_, EngineMessage>(&mut c).await, Err(FrameError::Closed)));
    }

    #[tokio::test]
    async fn a_request_before_hello_is_refused_and_closed() {
        let (mut c, task) = start(1);
        send(&mut c, &ClientMessage::Status).await;
        assert_eq!(recv(&mut c).await, EngineMessage::Error { message: HELLO_FIRST.into() });
        task.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn a_second_hello_and_garbage_are_refused() {
        let (mut c, task) = start(1);
        send(&mut c, &hello(PROTOCOL)).await;
        recv(&mut c).await;
        send(&mut c, &hello(PROTOCOL)).await;
        assert_eq!(recv(&mut c).await, EngineMessage::Error { message: HELLO_ONCE.into() });
        task.await.unwrap().unwrap();

        let (mut c, task) = start(1);
        c.write_all(&[3, 0, 0, 0, b'{', b'x', b'}']).await.unwrap();
        assert!(matches!(recv(&mut c).await, EngineMessage::Error { .. }));
        task.await.unwrap().unwrap();
    }

    #[tokio::test(start_paused = true)]
    async fn a_silent_client_is_dropped_after_the_hello_wait() {
        let (c, task) = start(1);
        tokio::time::advance(HELLO_WAIT + Duration::from_millis(1)).await;
        task.await.unwrap().unwrap();
        drop(c);
    }
}
