//! The engine's side of the pipe (plan 1.3). [`serve_client`] runs one
//! connection over any stream against a [`Backend`], so the handshake, the
//! requests and the flow stream are tested in memory; `server` (Windows)
//! owns the real pipe, its DACL and the client check ([`client_allowed`]).

#[cfg(windows)]
pub mod server;

use std::sync::Arc;
use std::time::Duration;

use sieve_ipc::nonblocking::{read_frame, write_frame};
use sieve_filter::exclusions::{AutoReason, exe_file_name, parse_line};
use sieve_ipc::{CertStatus, ClientMessage, DnsUpstreams, EngineMessage, EngineStatus, ExclusionsView, FLOWS_PER_FRAME, FlowEvent, FrameError, HealNotice, ListStatus, LogRow, Policy, answer_hello, exclusions_page, log_frames};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::broadcast;

use crate::heal::Retry;
use crate::stack::book::{log_visible_to, notice_visible_to, visible_to};

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
pub const RETRY_NOTHING: &str = "try again needs a line and its reason, or an app alone";

/// What the pipe asks of the engine (the running engine is
/// `control::Engine`; tests use a fake).
pub trait Backend: Send + Sync + 'static {
    fn status(&self) -> EngineStatus;
    /// Applies a newer policy and answers the Status after it.
    fn set_policy(&self, policy: Policy) -> Result<EngineStatus, String>;
    /// Applies a newer, valid resolver list and answers the list then held.
    fn set_dns_upstreams(&self, list: DnsUpstreams) -> Result<DnsUpstreams, String>;
    /// The resolver list the engine holds.
    fn dns_upstreams(&self) -> DnsUpstreams;
    /// The open flows now, every batch from now on, and whether routes are
    /// up (a subscription ends when they go down: the app then reads the
    /// connection tables again).
    fn subscribe(&self) -> Subscription;
    /// The per-list report, and the last compile's time.
    fn lists(&self) -> (Vec<ListStatus>, Option<u64>);
    /// Downloads every selected list at the next chance, whatever its age.
    fn lists_refresh(&self);
    /// Downloads one list at the next chance; refused for an unknown id or a list from a file.
    fn list_refresh(&self, id: &str) -> Result<(), String>;
    /// Judges and keeps a list from a file: how many rules it holds and skipped.
    fn list_import(&self, id: &str, text: &str) -> Result<(u64, u64), String>;
    /// The rules of a list's copy that hold query: the first ones, matched, total.
    fn list_rules(&self, id: &str, query: &str) -> Result<(Vec<String>, u64, u64), String>;
    /// The root certificate's status.
    fn cert_status(&self) -> CertStatus;
    /// Asks for a new root (refused unless `policy.https` is on) and answers
    /// the status as it stands; the certificate loop does the work.
    fn install_root(&self) -> Result<CertStatus, String>;
    /// `RequestUpdate`: a check, or applying the release on offer, decided from
    /// the engine's own state, answered at once with the Status. An error when
    /// asked again inside the cooldown.
    fn request_update(&self) -> Result<EngineStatus, String>;
    /// What is not decrypted, from the lists and the auto layer.
    ///
    /// TENSION: rows are machine-wide because the store is, so a second signed-in
    /// user who passes the pipe's DACL could see a host another session's app
    /// rejected. The DACL (plan 7.1) admits only the enabling user, SYSTEM and
    /// Administrators, so this is the same person or an admin. Notices stay session
    /// scoped (task Q4).
    fn exclusions(&self) -> ExclusionsView;
    /// "Try decrypting again". Only ever reaches `auto:*` entries.
    fn try_decrypt_again(&self, retry: Retry);
    /// This run's self-healing notices newer than `after`, of every session.
    fn heal_notices(&self, after: u64) -> HealAnswer;
}

/// What [`Backend::heal_notices`] answers; the fields of `EngineMessage::HealNotices`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HealAnswer {
    pub run: u64,
    pub revision: u64,
    pub exclusions_revision: u64,
    pub notices: Vec<HealNotice>,
}

pub struct Subscription {
    pub open: Vec<FlowEvent>,
    pub batches: broadcast::Receiver<Arc<Vec<FlowEvent>>>,
    /// Log rows from now on: the log has no backlog to replay (session only).
    pub log: broadcast::Receiver<Arc<Vec<LogRow>>>,
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
            Ok(ClientMessage::DnsUpstreams) => EngineMessage::DnsUpstreams(backend.dns_upstreams()),
            Ok(ClientMessage::RequestUpdate {}) => match backend.request_update() {
                Ok(status) => EngineMessage::Status(status),
                Err(message) => EngineMessage::Error { message },
            },
            Ok(ClientMessage::Subscribe) => return stream_flows(stream, session_id, backend).await,
            Ok(ClientMessage::Lists) => lists_answer(backend),
            Ok(ClientMessage::ListsRefresh) => {
                backend.lists_refresh();
                lists_answer(backend)
            }
            Ok(ClientMessage::CertStatus) => EngineMessage::CertStatus(backend.cert_status()),
            Ok(ClientMessage::InstallRoot) => match backend.install_root() {
                Ok(status) => EngineMessage::CertStatus(status),
                Err(message) => EngineMessage::Error { message },
            },
            Ok(ClientMessage::Exclusions { after }) => exclusions_page(&backend.exclusions(), after)?,
            Ok(ClientMessage::TryDecryptAgain { line, app, reason }) => match retry_of(line.as_deref(), app.as_deref(), reason.as_deref()) {
                Ok(retry) => {
                    backend.try_decrypt_again(retry);
                    exclusions_page(&backend.exclusions(), 0)?
                }
                Err(message) => EngineMessage::Error { message },
            },
            Ok(ClientMessage::ListRefresh { id }) => match backend.list_refresh(&id) {
                Ok(()) => lists_answer(backend),
                Err(message) => EngineMessage::Error { message },
            },
            Ok(ClientMessage::ListImport { id, text }) => match backend.list_import(&id, &text) {
                Ok((rules, skipped)) => EngineMessage::ListImported { id, rules, skipped },
                Err(message) => EngineMessage::Error { message },
            },
            Ok(ClientMessage::ListRules { id, query }) => match backend.list_rules(&id, &query) {
                Ok((lines, matched, total)) => EngineMessage::ListRules { id, lines, matched, total },
                Err(message) => EngineMessage::Error { message },
            },
            Ok(ClientMessage::HealNotices { after }) => {
                let HealAnswer { run, revision, exclusions_revision, notices } = backend.heal_notices(after);
                EngineMessage::HealNotices { run, revision, exclusions_revision, notices: notices.into_iter().filter(|n| notice_visible_to(n, session_id)).collect() }
            }
            Ok(ClientMessage::Hello { .. }) => return refuse(stream, HELLO_ONCE).await,
            Err(FrameError::Closed) => return Ok(()),
            Err(e) => return refuse(stream, &e.to_string()).await,
        };
        write_frame(stream, &reply).await?;
    }
}

/// What a `try_decrypt_again` names, or why it names nothing.
fn retry_of(line: Option<&str>, app: Option<&str>, reason: Option<&str>) -> Result<Retry, String> {
    let app = app.map(exe_file_name);
    match (line, app, reason) {
        (Some(line), app, Some(reason)) => {
            let entry = parse_line(line.trim()).map_err(|why| format!("not an exclusion line: {why:?}"))?;
            let reason = AutoReason::from_slug(reason).ok_or_else(|| format!("not a reason the engine writes: {reason}"))?;
            Ok(Retry::One { pattern: entry.pattern, app, reason })
        }
        (None, Some(app), None) => Ok(Retry::App { app }),
        _ => Err(RETRY_NOTHING.to_string()),
    }
}

fn lists_answer<B: Backend + ?Sized>(backend: &B) -> EngineMessage {
    let (lists, compile_ms) = backend.lists();
    EngineMessage::Lists { lists, compile_ms }
}

/// Sends `events` the client may see, in frames of at most FLOWS_PER_FRAME.
async fn send_flows<S: AsyncWrite + Unpin>(stream: &mut S, session_id: u32, events: &[FlowEvent]) -> Result<(), FrameError> {
    let mine: Vec<FlowEvent> = events.iter().filter(|e| visible_to(e, session_id)).cloned().collect();
    for chunk in mine.chunks(FLOWS_PER_FRAME) {
        write_frame(stream, &EngineMessage::Flows { flows: chunk.to_vec() }).await?;
    }
    Ok(())
}

/// Sends the rows the client may see, split by their encoded size. Rows are
/// built at the caps, so none is left out as oversized.
async fn send_log<S: AsyncWrite + Unpin>(stream: &mut S, session_id: u32, rows: &[LogRow]) -> Result<(), FrameError> {
    let mine: Vec<LogRow> = rows.iter().filter(|r| log_visible_to(r, session_id)).cloned().collect();
    for message in log_frames(&mine)?.messages {
        write_frame(stream, &message).await?;
    }
    Ok(())
}

/// The subscribed connection: the open flows first, then each batch of flows
/// and log rows. A client that falls behind by more than the backlog is
/// disconnected (it reconnects and starts from the open flows again); a client
/// that closes or sends anything ends the stream.
async fn stream_flows<S, B>(stream: &mut S, session_id: u32, backend: &B) -> Result<(), FrameError>
where
    S: AsyncRead + AsyncWrite + Unpin,
    B: Backend + ?Sized,
{
    let Subscription { open, mut batches, mut log, mut routes_up } = backend.subscribe();
    send_flows(stream, session_id, &open).await?;
    let (mut reader, mut writer) = tokio::io::split(stream);
    let mut probe = [0u8; 1];
    loop {
        tokio::select! {
            batch = batches.recv() => match batch {
                Ok(b) => send_flows(&mut writer, session_id, &b).await?,
                Err(_) => return Ok(()),
            },
            rows = log.recv() => match rows {
                Ok(r) => send_log(&mut writer, session_id, &r).await?,
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
        log: broadcast::Sender<Arc<Vec<LogRow>>>,
        routes: tokio::sync::watch::Sender<bool>,
        refreshes: Mutex<u64>,
        update_requests: Mutex<u32>,
        retries: Mutex<Vec<Retry>>,
        notices: Mutex<Vec<HealNotice>>,
    }

    impl Fake {
        fn new(open: Vec<FlowEvent>) -> Arc<Self> {
            let routes = tokio::sync::watch::channel(true).0;
            Arc::new(Self { policy: Mutex::new(Policy::default()), open, flows: broadcast::channel(4).0, log: broadcast::channel(4).0, routes, refreshes: Mutex::default(), update_requests: Mutex::new(0), retries: Mutex::default(), notices: Mutex::default() })
        }
    }

    impl Backend for Fake {
        fn status(&self) -> EngineStatus {
            EngineStatus { policy: self.policy.lock().unwrap().clone(), ..EngineStatus::default() }
        }
        fn set_policy(&self, p: Policy) -> Result<EngineStatus, String> {
            let next = crate::policy::accept(&self.policy.lock().unwrap(), p)?;
            *self.policy.lock().unwrap() = next;
            Ok(self.status())
        }
        fn set_dns_upstreams(&self, list: DnsUpstreams) -> Result<DnsUpstreams, String> {
            Ok(list)
        }
        fn dns_upstreams(&self) -> DnsUpstreams {
            DnsUpstreams { revision: 9, upstreams: vec!["tls://held.example".into()] }
        }
        fn subscribe(&self) -> Subscription {
            Subscription { open: self.open.clone(), batches: self.flows.subscribe(), log: self.log.subscribe(), routes_up: self.routes.subscribe() }
        }
        fn lists(&self) -> (Vec<ListStatus>, Option<u64>) {
            let refreshes = *self.refreshes.lock().unwrap();
            (vec![ListStatus { id: "adguard-dns".into(), network: refreshes, ..ListStatus::default() }], Some(5))
        }
        fn lists_refresh(&self) {
            *self.refreshes.lock().unwrap() += 1;
        }
        fn list_refresh(&self, id: &str) -> Result<(), String> {
            if id != "adguard-dns" {
                return Err("unknown".into());
            }
            *self.refreshes.lock().unwrap() += 10;
            Ok(())
        }
        fn list_import(&self, id: &str, text: &str) -> Result<(u64, u64), String> {
            if text.is_empty() { Err(format!("{id}: empty")) } else { Ok((2, 1)) }
        }
        fn list_rules(&self, _id: &str, query: &str) -> Result<(Vec<String>, u64, u64), String> {
            Ok((vec![format!("||{query}^")], 1, 9))
        }
        fn cert_status(&self) -> CertStatus {
            CertStatus { thumbprint: Some("abc".into()), ..CertStatus::default() }
        }
        fn install_root(&self) -> Result<CertStatus, String> {
            if self.policy.lock().unwrap().https { Ok(self.cert_status()) } else { Err("https is off".into()) }
        }
        fn request_update(&self) -> Result<EngineStatus, String> {
            let mut asked = self.update_requests.lock().unwrap();
            *asked += 1;
            if *asked > 1 {
                return Err("too soon".into());
            }
            Ok(EngineStatus { update: sieve_ipc::UpdateStatus::Checking, ..EngineStatus::default() })
        }
        fn exclusions(&self) -> ExclusionsView {
            let row = sieve_ipc::ExclusionRow { line: "\"pin.example\"".into(), apps: vec!["client.exe".into()], reason: "auto:pinning".into(), created_ms: Some(1), retries: 0 };
            ExclusionsView { revision: 4, rows: vec![row], ..ExclusionsView::default() }
        }
        fn try_decrypt_again(&self, retry: Retry) {
            self.retries.lock().unwrap().push(retry);
        }
        fn heal_notices(&self, after: u64) -> HealAnswer {
            let notices = self.notices.lock().unwrap();
            HealAnswer { run: 7, revision: notices.iter().map(|n| n.rev).max().unwrap_or(0), exclusions_revision: 4, notices: notices.iter().filter(|n| n.rev > after).cloned().collect() }
        }
    }

    fn notice(id: u64, session: u32) -> HealNotice {
        HealNotice { id, session, exe: "client.exe".into(), hosts: vec!["pin.example".into()], total: 1, rev: id }
    }

    async fn welcomed(fake: Arc<Fake>, session: u32) -> (DuplexStream, tokio::task::JoinHandle<Result<(), FrameError>>) {
        let (mut c, task) = start_with(session, fake);
        send(&mut c, &hello(PROTOCOL)).await;
        recv(&mut c).await;
        (c, task)
    }

    #[tokio::test]
    async fn try_decrypt_again_answers_over_the_pipe() {
        let fake = Fake::new(vec![]);
        let (mut c, task) = welcomed(fake.clone(), 1).await;
        send(&mut c, &ClientMessage::TryDecryptAgain { line: Some("\"pin.example\"".into()), app: Some(r"C:\Apps\Client.EXE".into()), reason: Some("auto:pinning".into()) }).await;
        assert!(matches!(recv(&mut c).await, EngineMessage::Exclusions { revision: 4, rows, next: None, .. } if rows.len() == 1), "the first page");
        send(&mut c, &ClientMessage::TryDecryptAgain { line: None, app: Some("client.exe".into()), reason: None }).await;
        assert!(matches!(recv(&mut c).await, EngineMessage::Exclusions { .. }));
        assert_eq!(
            *fake.retries.lock().unwrap(),
            [Retry::One { pattern: sieve_filter::exclusions::Pattern::Exact("pin.example".into()), app: Some("client.exe".into()), reason: AutoReason::Pinning }, Retry::App { app: "client.exe".into() }]
        );
        drop(c);
        task.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn an_unparsable_line_is_an_error_and_ends_nothing() {
        let fake = Fake::new(vec![]);
        let (mut c, task) = welcomed(fake.clone(), 1).await;
        send(&mut c, &ClientMessage::TryDecryptAgain { line: Some("not a host".into()), app: None, reason: Some("auto:pinning".into()) }).await;
        assert!(matches!(recv(&mut c).await, EngineMessage::Error { .. }));
        send(&mut c, &ClientMessage::Exclusions { after: 0 }).await;
        assert!(matches!(recv(&mut c).await, EngineMessage::Exclusions { .. }), "the pipe stays");
        assert!(fake.retries.lock().unwrap().is_empty());
        drop(c);
        task.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn both_none_is_refused() {
        let fake = Fake::new(vec![]);
        let (mut c, task) = welcomed(fake.clone(), 1).await;
        send(&mut c, &ClientMessage::TryDecryptAgain { line: None, app: None, reason: None }).await;
        assert_eq!(recv(&mut c).await, EngineMessage::Error { message: RETRY_NOTHING.into() });
        assert!(fake.retries.lock().unwrap().is_empty());
        drop(c);
        task.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn a_row_needs_a_reason_the_engine_writes_and_the_bulk_form_takes_none() {
        let fake = Fake::new(vec![]);
        let (mut c, task) = welcomed(fake.clone(), 1).await;
        let line = || Some("\"pin.example\"".to_string());
        for (line, reason) in [(line(), None), (line(), Some("list:sensitive")), (line(), Some("user")), (line(), Some("auto:someday")), (None, Some("auto:pinning"))] {
            send(&mut c, &ClientMessage::TryDecryptAgain { line, app: Some("client.exe".into()), reason: reason.map(str::to_string) }).await;
            assert!(matches!(recv(&mut c).await, EngineMessage::Error { .. }), "{reason:?}");
        }
        assert!(fake.retries.lock().unwrap().is_empty());
        drop(c);
        task.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn other_session_sees_nothing() {
        let fake = Fake::new(vec![]);
        fake.notices.lock().unwrap().extend([notice(1, 1), notice(2, 2)]);
        let (mut c, task) = welcomed(fake.clone(), 1).await;
        send(&mut c, &ClientMessage::HealNotices { after: 0 }).await;
        let EngineMessage::HealNotices { run, revision, exclusions_revision, notices } = recv(&mut c).await else { panic!("not notices") };
        assert_eq!((run, revision, exclusions_revision), (7, 2, 4));
        assert_eq!(notices, [notice(1, 1)], "its own session's");
        drop(c);
        task.await.unwrap().unwrap();
        let (mut c, task) = welcomed(fake, 3).await;
        send(&mut c, &ClientMessage::HealNotices { after: 0 }).await;
        assert!(matches!(recv(&mut c).await, EngineMessage::HealNotices { notices, .. } if notices.is_empty()), "the control's other side");
        drop(c);
        task.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn request_update_answers_status() {
        let (mut c, task) = start(1);
        send(&mut c, &hello(PROTOCOL)).await;
        recv(&mut c).await;
        send(&mut c, &ClientMessage::RequestUpdate {}).await;
        assert!(matches!(recv(&mut c).await, EngineMessage::Status(s) if s.update == sieve_ipc::UpdateStatus::Checking));
        send(&mut c, &ClientMessage::RequestUpdate {}).await;
        assert_eq!(recv(&mut c).await, EngineMessage::Error { message: "too soon".into() }, "over the limit: an error, and the pipe stays");
        send(&mut c, &ClientMessage::Status).await;
        assert!(matches!(recv(&mut c).await, EngineMessage::Status(_)));
        drop(c);
        task.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn request_update_with_any_field_is_refused() {
        let fake = Fake::new(vec![]);
        let (mut c, task) = start_with(1, fake.clone());
        send(&mut c, &hello(PROTOCOL)).await;
        recv(&mut c).await;
        let body = br#"{"type":"request_update","url":"https://elsewhere.example/x.exe"}"#;
        let mut frame = (body.len() as u32).to_le_bytes().to_vec();
        frame.extend_from_slice(body);
        c.write_all(&frame).await.unwrap();
        assert!(matches!(recv(&mut c).await, EngineMessage::Error { .. }));
        task.await.unwrap().unwrap();
        assert_eq!(*fake.update_requests.lock().unwrap(), 0, "the engine never saw a request");
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
        let on = Policy { revision: 1, engine: true, ..Policy::default() };
        send(&mut c, &ClientMessage::SetPolicy(on.clone())).await;
        assert!(matches!(recv(&mut c).await, EngineMessage::Status(s) if s.policy == on));
        send(&mut c, &ClientMessage::SetPolicy(Policy { revision: 1, engine: false, ..Policy::default() })).await;
        assert!(matches!(recv(&mut c).await, EngineMessage::Error { message } if message.contains("stale")));
        send(&mut c, &ClientMessage::Status).await;
        assert!(matches!(recv(&mut c).await, EngineMessage::Status(s) if s.policy == on), "the connection stays usable");
        drop(c);
        task.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn the_list_report_is_answered_and_a_refresh_reaches_the_engine() {
        let fake = Fake::new(vec![]);
        let (mut c, task) = start_with(1, fake.clone());
        send(&mut c, &hello(PROTOCOL)).await;
        recv(&mut c).await;
        send(&mut c, &ClientMessage::Lists).await;
        assert!(matches!(recv(&mut c).await, EngineMessage::Lists { lists, compile_ms: Some(5) } if lists[0].network == 0));
        send(&mut c, &ClientMessage::ListsRefresh).await;
        assert!(matches!(recv(&mut c).await, EngineMessage::Lists { lists, .. } if lists[0].network == 1));
        drop(c);
        task.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn one_list_refresh_an_import_and_a_rules_search_are_answered_and_a_refusal_ends_nothing() {
        let fake = Fake::new(vec![]);
        let (mut c, task) = welcomed(fake.clone(), 1).await;
        send(&mut c, &ClientMessage::ListRefresh { id: "adguard-dns".into() }).await;
        assert!(matches!(recv(&mut c).await, EngineMessage::Lists { lists, .. } if lists[0].network == 10));
        send(&mut c, &ClientMessage::ListRefresh { id: "nope".into() }).await;
        assert!(matches!(recv(&mut c).await, EngineMessage::Error { .. }));
        send(&mut c, &ClientMessage::ListImport { id: "custom-b2".into(), text: String::new() }).await;
        assert!(matches!(recv(&mut c).await, EngineMessage::Error { message } if message.contains("empty")));
        send(&mut c, &ClientMessage::ListImport { id: "custom-b2".into(), text: "||a^".into() }).await;
        assert_eq!(recv(&mut c).await, EngineMessage::ListImported { id: "custom-b2".into(), rules: 2, skipped: 1 });
        send(&mut c, &ClientMessage::ListRules { id: "adguard-dns".into(), query: "ads".into() }).await;
        assert_eq!(recv(&mut c).await, EngineMessage::ListRules { id: "adguard-dns".into(), lines: vec!["||ads^".into()], matched: 1, total: 9 });
        drop(c);
        task.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn cert_status_answers_over_the_pipe() {
        let (mut c, task) = start(1);
        send(&mut c, &hello(PROTOCOL)).await;
        recv(&mut c).await;
        send(&mut c, &ClientMessage::CertStatus).await;
        assert!(matches!(recv(&mut c).await, EngineMessage::CertStatus(s) if s.thumbprint.as_deref() == Some("abc")));
        drop(c);
        task.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn install_root_answers_the_status_or_the_refusal_and_the_pipe_stays_usable() {
        let (mut c, task) = start(1);
        send(&mut c, &hello(PROTOCOL)).await;
        recv(&mut c).await;
        send(&mut c, &ClientMessage::InstallRoot).await;
        assert!(matches!(recv(&mut c).await, EngineMessage::Error { message } if message.contains("off")));
        send(&mut c, &ClientMessage::SetPolicy(Policy { revision: 1, https: true, ..Policy::default() })).await;
        recv(&mut c).await;
        send(&mut c, &ClientMessage::InstallRoot).await;
        assert!(matches!(recv(&mut c).await, EngineMessage::CertStatus(_)));
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
    async fn the_held_resolver_list_is_answered_on_request() {
        let (mut c, task) = start(1);
        send(&mut c, &hello(PROTOCOL)).await;
        recv(&mut c).await;
        send(&mut c, &ClientMessage::DnsUpstreams).await;
        assert!(matches!(recv(&mut c).await, EngineMessage::DnsUpstreams(l) if l.revision == 9));
        drop(c);
        task.await.unwrap().unwrap();
    }

    fn log_row(id: u64, session: Option<u32>, forwarded: Option<sieve_ipc::Forwarded>) -> LogRow {
        LogRow {
            id,
            t: 1,
            flow_id: id,
            pid: None,
            exe: None,
            session,
            kind: sieve_ipc::FlowKind::Tls,
            host: "news.example".into(),
            remote: "192.0.2.1:443".into(),
            url: None,
            request_type: None,
            outcome: sieve_ipc::LogOutcome::Blocked,
            rule: None,
            list: None,
            forwarded,
        }
    }

    /// The log comes on the Subscribe connection and shows a client only its
    /// session's rows, the services' and the guests': browsing history is private.
    #[tokio::test]
    async fn log_rows_reach_the_subscriber_session_scoped() {
        let mut first = tests_event(Some(1));
        first.id = 1;
        let fake = Fake::new(vec![first]);
        let (mut c, task) = start_with(1, fake.clone());
        send(&mut c, &hello(PROTOCOL)).await;
        recv(&mut c).await;
        send(&mut c, &ClientMessage::Subscribe).await;
        recv(&mut c).await;
        let (mine, service, guest) = (log_row(1, Some(1), None), log_row(2, Some(0), None), log_row(5, None, Some(sieve_ipc::Forwarded { vm: None })));
        fake.log.send(Arc::new(vec![mine.clone(), service.clone(), log_row(3, Some(2), None), log_row(4, None, None), guest.clone()])).unwrap();
        assert_eq!(recv(&mut c).await, EngineMessage::Log { rows: vec![mine, service, guest] });
        fake.log.send(Arc::new(vec![log_row(6, Some(2), None)])).unwrap();
        let next = log_row(7, Some(1), None);
        fake.log.send(Arc::new(vec![next.clone()])).unwrap();
        assert_eq!(recv(&mut c).await, EngineMessage::Log { rows: vec![next] }, "a batch with nothing for this session sends no frame");
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
