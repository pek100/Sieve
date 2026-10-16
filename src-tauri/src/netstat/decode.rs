//! Pure decoding of the IP Helper owner-pid tables into protocol v1 flows.
//!
//! The input is the raw buffer `GetExtendedTcpTable` / `GetExtendedUdpTable`
//! filled: a `u32` row count, then fixed-size rows with no padding (every
//! field is 4-byte aligned). Field layouts, from the Windows SDK:
//!
//! | table | row | bytes |
//! |---|---|---|
//! | TCP v4 | state, local addr, local port, remote addr, remote port, pid | 24 |
//! | TCP v6 | local addr\[16\], local scope, local port, remote addr\[16\], remote scope, remote port, state, pid | 56 |
//! | UDP v4 | local addr, local port, pid | 12 |
//! | UDP v6 | local addr\[16\], local scope, local port, pid | 28 |
//!
//! Integers (count, state, pid, scope id) are little endian, as on every
//! Windows target. Addresses are in network order as stored. A port is a
//! `u32` whose first two bytes are the port in network order (big endian);
//! the upper two bytes are ignored.
//!
//! No Windows calls here, so this file is tested from byte fixtures on any host.

use std::net::{Ipv4Addr, Ipv6Addr};

use crate::protocol::{Endpoint, Family, Flow, FlowState, Proto};

/// Which table a buffer came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TableKind {
    Tcp4,
    Tcp6,
    Udp4,
    Udp6,
}

impl TableKind {
    pub const ALL: [TableKind; 4] = [TableKind::Tcp4, TableKind::Tcp6, TableKind::Udp4, TableKind::Udp6];

    /// Size in bytes of one row of this table.
    pub const fn row_size(self) -> usize {
        match self {
            TableKind::Tcp4 => 24,
            TableKind::Tcp6 => 56,
            TableKind::Udp4 => 12,
            TableKind::Udp6 => 28,
        }
    }

    pub const fn proto(self) -> Proto {
        match self {
            TableKind::Tcp4 | TableKind::Tcp6 => Proto::Tcp,
            TableKind::Udp4 | TableKind::Udp6 => Proto::Udp,
        }
    }

    pub const fn family(self) -> Family {
        match self {
            TableKind::Tcp4 | TableKind::Udp4 => Family::V4,
            TableKind::Tcp6 | TableKind::Udp6 => Family::V6,
        }
    }
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum DecodeError {
    #[error("{kind:?} table is truncated: {rows} rows need {need} bytes, buffer has {have}")]
    Truncated { kind: TableKind, rows: usize, need: usize, have: usize },
    #[error("{kind:?} table is shorter than its 4-byte row count ({have} bytes)")]
    NoHeader { kind: TableKind, have: usize },
    #[error("unknown TCP state code {0} (expected 1 to 12)")]
    UnknownTcpState(u32),
}

const HEADER: usize = 4;

/// Decode one whole table buffer into flows, in table order.
pub fn decode_table(kind: TableKind, buf: &[u8]) -> Result<Vec<Flow>, DecodeError> {
    let count_bytes = buf.get(..HEADER).ok_or(DecodeError::NoHeader { kind, have: buf.len() })?;
    let rows = le_u32(count_bytes, 0) as usize;
    // Saturating: an absurd count becomes a too-large need, never an overflow.
    let need = rows.saturating_mul(kind.row_size()).saturating_add(HEADER);
    if need > buf.len() {
        return Err(DecodeError::Truncated { kind, rows, need, have: buf.len() });
    }
    buf[HEADER..need]
        .chunks_exact(kind.row_size())
        .map(|row| decode_row(kind, row))
        .collect()
}

/// Decode one row. `row.len()` must equal `kind.row_size()` (decode_table
/// guarantees it, which is why this and the field readers stay private).
fn decode_row(kind: TableKind, row: &[u8]) -> Result<Flow, DecodeError> {
    let (pid, local, remote, state) = match kind {
        TableKind::Tcp4 => {
            let state = tcp_state(le_u32(row, 0))?;
            let local = Endpoint { addr: ipv4(row, 4), port: port(row, 8) };
            let remote = Endpoint { addr: ipv4(row, 12), port: port(row, 16) };
            (le_u32(row, 20), local, Some(remote), state)
        }
        TableKind::Tcp6 => {
            let local = Endpoint { addr: ipv6(row, 0, le_u32(row, 16)), port: port(row, 20) };
            let remote = Endpoint { addr: ipv6(row, 24, le_u32(row, 40)), port: port(row, 44) };
            let state = tcp_state(le_u32(row, 48))?;
            (le_u32(row, 52), local, Some(remote), state)
        }
        TableKind::Udp4 => {
            let local = Endpoint { addr: ipv4(row, 0), port: port(row, 4) };
            (le_u32(row, 8), local, None, FlowState::None)
        }
        TableKind::Udp6 => {
            let local = Endpoint { addr: ipv6(row, 0, le_u32(row, 16)), port: port(row, 20) };
            (le_u32(row, 24), local, None, FlowState::None)
        }
    };
    // A listening socket has no peer; the table reports 0.0.0.0:0 or [::]:0
    // there, which is not a remote anyone should count.
    let remote = if state == FlowState::Listen { None } else { remote };
    Ok(Flow { pid, proto: kind.proto(), family: kind.family(), local, remote, state })
}

/// MIB_TCP_STATE code (1 to 12) to the protocol state. Codes outside that
/// range are an error, never a guessed state.
pub fn tcp_state(code: u32) -> Result<FlowState, DecodeError> {
    match code {
        1..=12 => Ok(FlowState::ALL[(code - 1) as usize]),
        _ => Err(DecodeError::UnknownTcpState(code)),
    }
}

/// A port field: the first two bytes in network order.
fn port(row: &[u8], at: usize) -> u16 {
    u16::from_be_bytes([row[at], row[at + 1]])
}

/// An IPv4 address stored in network order.
fn ipv4(row: &[u8], at: usize) -> String {
    Ipv4Addr::new(row[at], row[at + 1], row[at + 2], row[at + 3]).to_string()
}

/// An IPv6 address stored in network order, with `%scope` appended when the
/// scope id is not zero (link-local addresses), as Windows tools print it.
fn ipv6(row: &[u8], at: usize, scope: u32) -> String {
    let mut octets = [0u8; 16];
    octets.copy_from_slice(&row[at..at + 16]);
    let addr = Ipv6Addr::from(octets);
    if scope == 0 { addr.to_string() } else { format!("{addr}%{scope}") }
}

fn le_u32(b: &[u8], at: usize) -> u32 {
    u32::from_le_bytes([b[at], b[at + 1], b[at + 2], b[at + 3]])
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::FLOW_STATE_NAMES;

    /// A table buffer: little-endian row count, then the rows.
    fn table(rows: &[Vec<u8>]) -> Vec<u8> {
        let mut out = (rows.len() as u32).to_le_bytes().to_vec();
        for r in rows {
            out.extend_from_slice(r);
        }
        out
    }

    fn le(n: u32) -> [u8; 4] {
        n.to_le_bytes()
    }

    /// Port field as Windows stores it: network-order port, then two junk bytes.
    fn net_port(p: u16) -> [u8; 4] {
        let [hi, lo] = p.to_be_bytes();
        [hi, lo, 0xAA, 0x55]
    }

    fn tcp4_row(state: u32, local: [u8; 4], lport: u16, remote: [u8; 4], rport: u16, pid: u32) -> Vec<u8> {
        [le(state), local, net_port(lport), remote, net_port(rport), le(pid)].concat()
    }

    #[test]
    fn port_bytes_0x01_0xbb_read_as_443() {
        assert_eq!(port(&[0x01, 0xBB, 0x00, 0x00], 0), 443);
        // The upper half of the u32 is not part of the port.
        assert_eq!(port(&[0x01, 0xBB, 0xFF, 0xFF], 0), 443);
    }

    #[test]
    fn ipv4_address_in_network_order() {
        assert_eq!(ipv4(&[203, 0, 113, 10], 0), "203.0.113.10");
    }

    #[test]
    fn ipv6_address_and_scope_id() {
        let addr: [u8; 16] = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x20];
        assert_eq!(ipv6(&addr, 0, 0), "2001:db8::20");
        let link: [u8; 16] = [0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01];
        assert_eq!(ipv6(&link, 0, 7), "fe80::1%7");
    }

    #[test]
    fn every_tcp_state_code_maps_to_its_protocol_name() {
        for code in 1..=12u32 {
            let state = tcp_state(code).expect("known code");
            let name = serde_json::to_value(state).expect("serialises");
            assert_eq!(name, FLOW_STATE_NAMES[(code - 1) as usize], "code {code}");
        }
        assert_eq!(tcp_state(1), Ok(FlowState::Closed));
        assert_eq!(tcp_state(2), Ok(FlowState::Listen));
        assert_eq!(tcp_state(5), Ok(FlowState::Established));
        assert_eq!(tcp_state(11), Ok(FlowState::TimeWait));
        assert_eq!(tcp_state(12), Ok(FlowState::DeleteTcb));
    }

    #[test]
    fn unknown_tcp_state_codes_are_errors() {
        assert_eq!(tcp_state(0), Err(DecodeError::UnknownTcpState(0)));
        assert_eq!(tcp_state(13), Err(DecodeError::UnknownTcpState(13)));
        let buf = table(&[tcp4_row(99, [127, 0, 0, 1], 80, [0; 4], 0, 1)]);
        assert_eq!(decode_table(TableKind::Tcp4, &buf), Err(DecodeError::UnknownTcpState(99)));
    }

    #[test]
    fn tcp4_established_row() {
        let buf = table(&[tcp4_row(5, [192, 168, 1, 20], 51544, [203, 0, 113, 10], 443, 9120)]);
        let flows = decode_table(TableKind::Tcp4, &buf).expect("decodes");
        assert_eq!(
            flows,
            vec![Flow {
                pid: 9120,
                proto: Proto::Tcp,
                family: Family::V4,
                local: Endpoint { addr: "192.168.1.20".into(), port: 51544 },
                remote: Some(Endpoint { addr: "203.0.113.10".into(), port: 443 }),
                state: FlowState::Established,
            }]
        );
    }

    #[test]
    fn literal_tcp4_bytes() {
        // One row, written out by hand: listen on 0.0.0.0:445, pid 4.
        let buf: [u8; 28] = [
            1, 0, 0, 0, // row count
            2, 0, 0, 0, // state 2 = listen
            0, 0, 0, 0, // local 0.0.0.0
            0x01, 0xBD, 0, 0, // local port 445
            0, 0, 0, 0, // remote 0.0.0.0
            0, 0, 0, 0, // remote port 0
            4, 0, 0, 0, // pid 4
        ];
        let flows = decode_table(TableKind::Tcp4, &buf).expect("decodes");
        assert_eq!(flows[0].local, Endpoint { addr: "0.0.0.0".into(), port: 445 });
        assert_eq!(flows[0].pid, 4);
        assert_eq!(flows[0].state, FlowState::Listen);
        assert_eq!(flows[0].remote, None);
    }

    #[test]
    fn listening_row_has_remote_null() {
        let buf = table(&[tcp4_row(2, [127, 0, 0, 1], 54012, [0; 4], 0, 14032)]);
        let flows = decode_table(TableKind::Tcp4, &buf).expect("decodes");
        assert_eq!(flows[0].state, FlowState::Listen);
        assert_eq!(flows[0].remote, None);
        let json = serde_json::to_value(&flows[0]).expect("serialises");
        assert!(json["remote"].is_null());
    }

    #[test]
    fn tcp6_row_with_scopes() {
        let local: [u8; 16] = [0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x02];
        let remote: [u8; 16] = [0x20, 0x01, 0x0d, 0xb8, 0, 0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0x04, 0x43];
        let row = [
            &local[..],
            &le(12),
            &net_port(51602),
            &remote[..],
            &le(0),
            &net_port(443),
            &le(11),
            &le(9188),
        ]
        .concat();
        assert_eq!(row.len(), TableKind::Tcp6.row_size());
        let flows = decode_table(TableKind::Tcp6, &table(&[row])).expect("decodes");
        assert_eq!(
            flows,
            vec![Flow {
                pid: 9188,
                proto: Proto::Tcp,
                family: Family::V6,
                local: Endpoint { addr: "fe80::2%12".into(), port: 51602 },
                remote: Some(Endpoint { addr: "2001:db8:1::443".into(), port: 443 }),
                state: FlowState::TimeWait,
            }]
        );
    }

    #[test]
    fn tcp6_listening_row_has_remote_null() {
        let row = [&[0u8; 16][..], &le(0), &net_port(8080), &[0u8; 16][..], &le(0), &net_port(0), &le(2), &le(77)].concat();
        let flows = decode_table(TableKind::Tcp6, &table(&[row])).expect("decodes");
        assert_eq!(flows[0].local, Endpoint { addr: "::".into(), port: 8080 });
        assert_eq!(flows[0].remote, None);
    }

    #[test]
    fn udp4_row_has_state_none_and_no_remote() {
        let row = [[0, 0, 0, 0], net_port(5353), le(1288)].concat();
        let flows = decode_table(TableKind::Udp4, &table(&[row])).expect("decodes");
        assert_eq!(
            flows,
            vec![Flow {
                pid: 1288,
                proto: Proto::Udp,
                family: Family::V4,
                local: Endpoint { addr: "0.0.0.0".into(), port: 5353 },
                remote: None,
                state: FlowState::None,
            }]
        );
    }

    #[test]
    fn udp6_row_has_state_none_and_no_remote() {
        let mut addr = [0u8; 16];
        addr[15] = 1;
        let row = [&addr[..], &le(0), &net_port(53), &le(2001)].concat();
        let flows = decode_table(TableKind::Udp6, &table(&[row])).expect("decodes");
        assert_eq!(flows[0].local, Endpoint { addr: "::1".into(), port: 53 });
        assert_eq!(flows[0].proto, Proto::Udp);
        assert_eq!(flows[0].family, Family::V6);
        assert_eq!(flows[0].state, FlowState::None);
        assert_eq!(flows[0].remote, None);
        assert_eq!(flows[0].pid, 2001);
    }

    #[test]
    fn several_rows_keep_table_order() {
        let buf = table(&[
            tcp4_row(2, [0; 4], 445, [0; 4], 0, 4),
            tcp4_row(5, [10, 0, 0, 2], 50000, [198, 51, 100, 7], 443, 14032),
            tcp4_row(3, [10, 0, 0, 2], 50001, [192, 0, 2, 55], 8080, 15500),
        ]);
        let flows = decode_table(TableKind::Tcp4, &buf).expect("decodes");
        let pids: Vec<u32> = flows.iter().map(|f| f.pid).collect();
        assert_eq!(pids, vec![4, 14032, 15500]);
        assert_eq!(flows[2].state, FlowState::SynSent);
    }

    #[test]
    fn empty_table_decodes_to_no_flows() {
        for kind in TableKind::ALL {
            assert_eq!(decode_table(kind, &le(0)), Ok(vec![]));
        }
    }

    #[test]
    fn short_buffers_are_errors_not_panics() {
        assert_eq!(decode_table(TableKind::Udp4, &[1, 0]), Err(DecodeError::NoHeader { kind: TableKind::Udp4, have: 2 }));
        // Claims two rows, carries one.
        let mut buf = table(&[[[0; 4], net_port(53), le(1)].concat()]);
        buf[0] = 2;
        assert_eq!(
            decode_table(TableKind::Udp4, &buf),
            Err(DecodeError::Truncated { kind: TableKind::Udp4, rows: 2, need: 28, have: 16 })
        );
        // An absurd row count does not overflow.
        let huge = le(u32::MAX);
        assert!(matches!(decode_table(TableKind::Tcp6, &huge), Err(DecodeError::Truncated { .. })));
    }

    #[test]
    fn trailing_bytes_after_the_rows_are_ignored() {
        // Windows may hand back a buffer larger than count * row size.
        let mut buf = table(&[[[0; 4], net_port(53), le(1)].concat()]);
        buf.extend_from_slice(&[0xEE; 9]);
        assert_eq!(decode_table(TableKind::Udp4, &buf).expect("decodes").len(), 1);
    }
}
