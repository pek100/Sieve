//! The messages inside the link.
//!
//! Every yamux stream starts with one request frame from the device, which the
//! hub answers with one response frame; after an `Ok` to `Connect` the stream
//! carries raw bytes. A `Control` stream carries keep-alive pings instead.
//!
//! Frame: `u16` big-endian body length (1..=MAX_FRAME), then the body. The
//! body's first byte is its tag:
//!
//! | tag  | message  | rest of body                                         |
//! |------|----------|------------------------------------------------------|
//! | 0x01 | Control  | (nothing)                                            |
//! | 0x02 | Connect  | port u16, host length u8 (1..=253), host (ASCII)     |
//! | 0x03 | Pair     | proof [32], name length u8 (0..=64), name (UTF-8)    |
//! | 0x10 | Ping     | nonce u64                                            |
//! | 0x11 | Pong     | nonce u64                                            |
//! | 0x80 | Response | status u8, message length u8, message (UTF-8)        |
//!
//! A frame longer than MAX_FRAME is refused before its body is read, so a
//! peer cannot make the reader allocate; bodies land in a fixed stack buffer.
//! Every field is length-checked and trailing bytes are an error.

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// The TLS ALPN value, which is also the protocol version.
pub const ALPN: &[u8] = b"sieve-link/1";
/// The largest frame body accepted.
pub const MAX_FRAME: usize = 512;
const MAX_HOST: usize = 253;
const MAX_NAME: usize = 64;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Status {
    Ok,
    /// A rule refused the target.
    Denied,
    /// Too many new streams per minute.
    RateLimited,
    /// Too many open streams.
    Busy,
    /// The hub could not resolve or reach the target.
    Unreachable,
    BadRequest,
    /// The pairing proof matched no outstanding code.
    PairingRefused,
}

impl Status {
    fn to_u8(self) -> u8 {
        match self {
            Status::Ok => 0,
            Status::Denied => 1,
            Status::RateLimited => 2,
            Status::Busy => 3,
            Status::Unreachable => 4,
            Status::BadRequest => 5,
            Status::PairingRefused => 6,
        }
    }
    fn from_u8(b: u8) -> Option<Self> {
        Some(match b {
            0 => Status::Ok,
            1 => Status::Denied,
            2 => Status::RateLimited,
            3 => Status::Busy,
            4 => Status::Unreachable,
            5 => Status::BadRequest,
            6 => Status::PairingRefused,
            _ => return None,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Message {
    Control,
    Connect { host: String, port: u16 },
    Pair { proof: [u8; 32], name: String },
    Ping(u64),
    Pong(u64),
    Response { status: Status, message: String },
}

#[derive(Debug, thiserror::Error)]
pub enum WireError {
    #[error("frame length {0} out of range")]
    Length(usize),
    #[error("malformed frame: {0}")]
    Malformed(&'static str),
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

/// Whether `host` is an acceptable target name or address literal: ASCII
/// letters, digits, '.', '-', '_' and ':' (IPv6), 1..=253 bytes.
pub fn valid_host(host: &str) -> bool {
    !host.is_empty()
        && host.len() <= MAX_HOST
        && host.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'_' | b':'))
}

/// Cuts `s` to at most `max` bytes on a char boundary.
pub fn clip(s: &str, max: usize) -> &str {
    if s.len() <= max {
        return s;
    }
    let mut end = max;
    while !s.is_char_boundary(end) {
        end -= 1;
    }
    &s[..end]
}

impl Message {
    pub fn encode(&self) -> Result<Vec<u8>, WireError> {
        let mut b = Vec::with_capacity(64);
        match self {
            Message::Control => b.push(0x01),
            Message::Connect { host, port } => {
                if !valid_host(host) || *port == 0 {
                    return Err(WireError::Malformed("bad connect target"));
                }
                b.push(0x02);
                b.extend_from_slice(&port.to_be_bytes());
                b.push(host.len() as u8);
                b.extend_from_slice(host.as_bytes());
            }
            Message::Pair { proof, name } => {
                let name = clip(name, MAX_NAME);
                b.push(0x03);
                b.extend_from_slice(proof);
                b.push(name.len() as u8);
                b.extend_from_slice(name.as_bytes());
            }
            Message::Ping(n) => {
                b.push(0x10);
                b.extend_from_slice(&n.to_be_bytes());
            }
            Message::Pong(n) => {
                b.push(0x11);
                b.extend_from_slice(&n.to_be_bytes());
            }
            Message::Response { status, message } => {
                let m = clip(message, 255);
                b.push(0x80);
                b.push(status.to_u8());
                b.push(m.len() as u8);
                b.extend_from_slice(m.as_bytes());
            }
        }
        let mut out = Vec::with_capacity(2 + b.len());
        out.extend_from_slice(&(b.len() as u16).to_be_bytes());
        out.extend_from_slice(&b);
        Ok(out)
    }

    /// Decodes one frame body (without its length prefix).
    pub fn decode(body: &[u8]) -> Result<Message, WireError> {
        if body.is_empty() || body.len() > MAX_FRAME {
            return Err(WireError::Length(body.len()));
        }
        let mut r = Reader(&body[1..]);
        let msg = match body[0] {
            0x01 => Message::Control,
            0x02 => {
                let port = u16::from_be_bytes(r.take::<2>()?);
                let len = r.u8()? as usize;
                let host = r.bytes(len)?;
                let host = std::str::from_utf8(host).map_err(|_| WireError::Malformed("host"))?;
                if !valid_host(host) || port == 0 {
                    return Err(WireError::Malformed("bad connect target"));
                }
                Message::Connect { host: host.to_string(), port }
            }
            0x03 => {
                let proof = r.take::<32>()?;
                let len = r.u8()? as usize;
                if len > MAX_NAME {
                    return Err(WireError::Malformed("name too long"));
                }
                let name = std::str::from_utf8(r.bytes(len)?).map_err(|_| WireError::Malformed("name"))?;
                Message::Pair { proof, name: name.to_string() }
            }
            0x10 => Message::Ping(u64::from_be_bytes(r.take::<8>()?)),
            0x11 => Message::Pong(u64::from_be_bytes(r.take::<8>()?)),
            0x80 => {
                let status = Status::from_u8(r.u8()?).ok_or(WireError::Malformed("status"))?;
                let len = r.u8()? as usize;
                let m = std::str::from_utf8(r.bytes(len)?).map_err(|_| WireError::Malformed("message"))?;
                Message::Response { status, message: m.to_string() }
            }
            _ => return Err(WireError::Malformed("unknown tag")),
        };
        if !r.0.is_empty() {
            return Err(WireError::Malformed("trailing bytes"));
        }
        Ok(msg)
    }
}

struct Reader<'a>(&'a [u8]);

impl<'a> Reader<'a> {
    fn take<const N: usize>(&mut self) -> Result<[u8; N], WireError> {
        let b = self.bytes(N)?;
        let mut out = [0u8; N];
        out.copy_from_slice(b);
        Ok(out)
    }
    fn u8(&mut self) -> Result<u8, WireError> {
        Ok(self.take::<1>()?[0])
    }
    fn bytes(&mut self, n: usize) -> Result<&'a [u8], WireError> {
        if self.0.len() < n {
            return Err(WireError::Malformed("truncated"));
        }
        let (h, t) = self.0.split_at(n);
        self.0 = t;
        Ok(h)
    }
}

/// Reads one frame. The length is checked before any body byte is read.
pub async fn read_msg<R: AsyncRead + Unpin>(r: &mut R) -> Result<Message, WireError> {
    let mut len = [0u8; 2];
    r.read_exact(&mut len).await?;
    let len = u16::from_be_bytes(len) as usize;
    if len == 0 || len > MAX_FRAME {
        return Err(WireError::Length(len));
    }
    let mut buf = [0u8; MAX_FRAME];
    r.read_exact(&mut buf[..len]).await?;
    Message::decode(&buf[..len])
}

pub async fn write_msg<W: AsyncWrite + Unpin>(w: &mut W, m: &Message) -> Result<(), WireError> {
    let bytes = m.encode()?;
    w.write_all(&bytes).await?;
    w.flush().await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    fn roundtrip(m: Message) {
        let enc = m.encode().unwrap();
        assert_eq!(u16::from_be_bytes([enc[0], enc[1]]) as usize, enc.len() - 2);
        assert_eq!(Message::decode(&enc[2..]).unwrap(), m);
    }

    #[test]
    fn every_message_roundtrips() {
        roundtrip(Message::Control);
        roundtrip(Message::Connect { host: "example.com".into(), port: 443 });
        roundtrip(Message::Connect { host: "2001:db8::1".into(), port: 1 });
        roundtrip(Message::Pair { proof: [7; 32], name: "laptop".into() });
        roundtrip(Message::Ping(42));
        roundtrip(Message::Pong(u64::MAX));
        roundtrip(Message::Response { status: Status::Denied, message: "private address".into() });
    }

    #[test]
    fn bad_targets_are_refused_both_ways() {
        assert!(Message::Connect { host: "".into(), port: 1 }.encode().is_err());
        assert!(Message::Connect { host: "a b".into(), port: 1 }.encode().is_err());
        assert!(Message::Connect { host: "a".into(), port: 0 }.encode().is_err());
        assert!(Message::Connect { host: "a".repeat(254), port: 1 }.encode().is_err());
        // Port 0 on the wire.
        assert!(Message::decode(&[0x02, 0, 0, 1, b'a']).is_err());
        // Trailing byte.
        assert!(Message::decode(&[0x01, 0]).is_err());
        // Truncated.
        assert!(Message::decode(&[0x10, 1, 2]).is_err());
    }

    #[tokio::test]
    async fn oversized_length_is_refused_before_reading_the_body() {
        // Only the two length bytes exist; a reader that tried to read the
        // body would fail with EOF instead of Length.
        let mut r: &[u8] = &[0xff, 0xff];
        match read_msg(&mut r).await {
            Err(WireError::Length(65535)) => {}
            other => panic!("unexpected {other:?}"),
        }
        let mut r: &[u8] = &[0, 0];
        assert!(matches!(read_msg(&mut r).await, Err(WireError::Length(0))));
    }

    proptest! {
        #[test]
        fn decode_never_panics(body in proptest::collection::vec(any::<u8>(), 0..600)) {
            let _ = Message::decode(&body);
        }

        #[test]
        fn decoded_messages_reencode_identically(body in proptest::collection::vec(any::<u8>(), 1..80)) {
            if let Ok(m) = Message::decode(&body) {
                let enc = m.encode().unwrap();
                prop_assert_eq!(&enc[2..], &body[..]);
            }
        }

        #[test]
        fn connect_roundtrips(host in "[a-z0-9.-]{1,253}", port in 1u16..) {
            roundtrip(Message::Connect { host, port });
        }
    }
}
