//! The engine's side of the pipe (plan 1.3). [`serve_client`] runs one
//! connection over any stream, so the handshake and the requests are tested
//! in memory; `server` (Windows) owns the real pipe, its DACL and the client
//! check ([`client_allowed`]).

#[cfg(windows)]
pub mod server;

use std::time::Duration;

use sieve_ipc::nonblocking::{read_frame, write_frame};
use sieve_ipc::{ClientMessage, EngineMessage, EngineStatus, FrameError, answer_hello};
use tokio::io::{AsyncRead, AsyncWrite};

pub const ENGINE_VERSION: &str = env!("CARGO_PKG_VERSION");
/// The app's executable as the installer lays it out (Tauri's main binary,
/// named after `productName`).
pub const APP_EXE: &str = "Sieve.exe";
/// A client that sends no Hello within this is dropped.
pub const HELLO_WAIT: Duration = Duration::from_secs(5);

pub const NOT_ALLOWED: &str = "only the installed Sieve app may connect to the engine";
pub const HELLO_FIRST: &str = "send hello first";
pub const HELLO_ONCE: &str = "hello was already sent";

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
/// Hello and a malformed frame end the connection after one reply.
/// `session_id` is the client process's Windows session.
pub async fn serve_client<S, F>(stream: &mut S, session_id: u32, status: F) -> Result<(), FrameError>
where
    S: AsyncRead + AsyncWrite + Unpin,
    F: Fn() -> EngineStatus,
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
            Ok(ClientMessage::Status) => EngineMessage::Status(status()),
            Ok(ClientMessage::Hello { .. }) => return refuse(stream, HELLO_ONCE).await,
            Err(FrameError::Closed) => return Ok(()),
            Err(e) => return refuse(stream, &e.to_string()).await,
        };
        write_frame(stream, &reply).await?;
    }
}

/// One Error frame, then the connection ends.
pub async fn refuse<S: AsyncWrite + Unpin>(stream: &mut S, message: &str) -> Result<(), FrameError> {
    write_frame(stream, &EngineMessage::Error { message: message.to_string() }).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use sieve_ipc::{PROTOCOL, SUPPORTED};
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

    fn idle() -> EngineStatus {
        EngineStatus::default()
    }

    async fn send(s: &mut DuplexStream, m: &ClientMessage) {
        write_frame(s, m).await.unwrap();
    }

    async fn recv(s: &mut DuplexStream) -> EngineMessage {
        read_frame(s).await.unwrap()
    }

    fn start(session: u32) -> (DuplexStream, tokio::task::JoinHandle<Result<(), FrameError>>) {
        let (client, mut engine) = tokio::io::duplex(64 * 1024);
        (client, tokio::spawn(async move { serve_client(&mut engine, session, idle).await }))
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
            assert_eq!(recv(&mut c).await, EngineMessage::Status(idle()));
        }
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
