//! Whoever speaks first decides what a flow can be (task D4). The client's bytes
//! go to `TcpClassifier`, as on the plain path, and are held. A server that
//! speaks first is not TLS: its bytes are handed back so they can be forwarded
//! at once, and the flow can only splice. Every read has its own buffer, so
//! losing a `select!` loses nothing.

use std::time::Duration;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite};

use crate::flow::classify::{Decoded, TcpClassifier};
use crate::flow::relay::CLASSIFIER_READ;

/// How a flow began.
#[derive(Debug, PartialEq, Eq)]
pub enum First {
    /// The classifier answered; `held` is every client byte, tail included.
    Decoded { decoded: Decoded, held: Vec<u8> },
    /// The server spoke, or closed, while `held` is what the client said so far.
    ServerSpoke { server: Vec<u8>, held: Vec<u8> },
    /// The client closed before any answer.
    ClientGone,
}

/// A read that fills `buf` from whichever side has bytes.
pub async fn read_first<A, U>(app: &mut A, upstream: &mut U, wait: Duration) -> First
where
    A: AsyncRead + AsyncWrite + Unpin,
    U: AsyncRead + AsyncWrite + Unpin,
{
    let mut classifier = TcpClassifier::new();
    let mut client = vec![0u8; CLASSIFIER_READ];
    let mut server = vec![0u8; CLASSIFIER_READ];
    loop {
        let read = async {
            tokio::select! {
                n = app.read(&mut client) => (true, n),
                n = upstream.read(&mut server) => (false, n),
            }
        };
        match tokio::time::timeout(wait, read).await {
            Err(_) => return First::Decoded { decoded: Decoded { failure: Some("no client bytes in time"), ..Decoded::default() }, held: classifier.take_held() },
            Ok((false, Ok(n))) => return First::ServerSpoke { server: server[..n].to_vec(), held: classifier.take_held() },
            Ok((false, Err(_))) => return First::ServerSpoke { server: Vec::new(), held: classifier.take_held() },
            Ok((true, Ok(0) | Err(_))) => return First::ClientGone,
            Ok((true, Ok(n))) => {
                let before = classifier.held().len();
                if let Some(decoded) = classifier.push(&client[..n]) {
                    // The read that decides can carry a tail the classifier did not keep.
                    let kept = classifier.held().len() - before;
                    let mut held = classifier.take_held();
                    held.extend_from_slice(&client[kept..n]);
                    return First::Decoded { decoded, held };
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use tokio::io::AsyncWriteExt;

    use super::*;
    use crate::flow::classify::Kind;
    use crate::flow::sni::build;

    const WAIT: Duration = Duration::from_secs(5);

    #[tokio::test]
    async fn a_hello_split_across_writes_is_held_whole_with_its_tail() {
        let hello = build::records(&build::handshake(&[build::sni_ext("a.example")]), 1 << 14);
        let (mut client, mut app) = tokio::io::duplex(1 << 16);
        let (_server, mut up) = tokio::io::duplex(1 << 16);
        let (head, tail) = hello.split_at(20);
        client.write_all(head).await.unwrap();
        let reader = tokio::spawn(async move { read_first(&mut app, &mut up, WAIT).await });
        tokio::task::yield_now().await;
        client.write_all(tail).await.unwrap();
        client.write_all(b"TRAILING").await.unwrap();
        match reader.await.unwrap() {
            First::Decoded { decoded, held } => {
                assert_eq!((decoded.kind, decoded.domain.as_deref()), (Some(Kind::Tls), Some("a.example")));
                assert!(held.starts_with(&hello), "in order");
            }
            other => panic!("{other:?}"),
        }
    }

    #[tokio::test]
    async fn a_server_that_speaks_first_is_handed_back_with_what_the_client_said() {
        let (mut client, mut app) = tokio::io::duplex(1024);
        let (mut server, mut up) = tokio::io::duplex(1024);
        client.write_all(&[22]).await.unwrap();
        let reader = tokio::spawn(async move { read_first(&mut app, &mut up, WAIT).await });
        tokio::time::sleep(Duration::from_millis(20)).await;
        server.write_all(b"220 ready\r\n").await.unwrap();
        assert_eq!(reader.await.unwrap(), First::ServerSpoke { server: b"220 ready\r\n".to_vec(), held: vec![22] });
    }

    #[tokio::test(start_paused = true)]
    async fn silence_is_decoded_as_no_bytes_in_time() {
        let (_client, mut app) = tokio::io::duplex(1024);
        let (_server, mut up) = tokio::io::duplex(1024);
        match read_first(&mut app, &mut up, WAIT).await {
            First::Decoded { decoded, held } => assert_eq!((decoded.failure, held.len()), (Some("no client bytes in time"), 0)),
            other => panic!("{other:?}"),
        }
    }

    #[tokio::test]
    async fn a_closed_client_ends_it() {
        let (client, mut app) = tokio::io::duplex(1024);
        let (_server, mut up) = tokio::io::duplex(1024);
        drop(client);
        assert_eq!(read_first(&mut app, &mut up, WAIT).await, First::ClientGone);
    }
}
