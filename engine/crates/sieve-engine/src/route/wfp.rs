//! Windows: the only code that calls the filtering platform (WFP), for
//! [`super::capture`]. The session is dynamic (`FWPM_SESSION_FLAG_DYNAMIC`): the
//! base filtering engine deletes its sublayer and filters when the handle closes,
//! on [`Drop`], an exit, a kill or a crash, so nothing it adds outlives the
//! engine's process. No object here is persistent, boot-time or a provider's.
//! Each filter matches the DNS Client service only (its service SID, through an
//! `ALE_USER_ID` access check), so no other program's DNS is ever blocked.
//! Law: `tests/laws/engine-network.test.ts`.

use std::net::IpAddr;

use windows::Win32::Foundation::{HANDLE, HLOCAL, LocalFree};
use windows::Win32::NetworkManagement::WindowsFilteringPlatform::{
    FWP_ACTION_BLOCK, FWP_BYTE_BLOB, FWP_CONDITION_VALUE0,
 FWP_CONDITION_VALUE0_0, FWP_MATCH_EQUAL, FWP_SECURITY_DESCRIPTOR_TYPE,
    FWP_UINT8, FWP_UINT16, FWP_UINT64, FWP_V4_ADDR_AND_MASK, FWP_V4_ADDR_MASK, FWP_V6_ADDR_AND_MASK, FWP_V6_ADDR_MASK, FWP_VALUE0,
    FWP_VALUE0_0, FWPM_ACTION0, FWPM_CONDITION_ALE_USER_ID, FWPM_CONDITION_IP_LOCAL_INTERFACE, FWPM_CONDITION_IP_PROTOCOL,
    FWPM_CONDITION_IP_REMOTE_ADDRESS, FWPM_CONDITION_IP_REMOTE_PORT, FWPM_DISPLAY_DATA0, FWPM_FILTER_CONDITION0, FWPM_FILTER_FLAGS,
    FWPM_FILTER0, FWPM_LAYER_ALE_AUTH_CONNECT_V4, FWPM_LAYER_ALE_AUTH_CONNECT_V6, FWPM_SESSION_FLAG_DYNAMIC, FWPM_SESSION0,
    FWPM_SUBLAYER0, FwpmEngineClose0, FwpmEngineOpen0, FwpmFilterAdd0, FwpmFilterDeleteById0, FwpmSubLayerAdd0, FwpmTransactionAbort0,
    FwpmTransactionBegin0, FwpmTransactionCommit0,
};
use windows::Win32::Security::Authorization::{ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1};
use windows::Win32::Security::{GetSecurityDescriptorLength, LookupAccountNameW, PSECURITY_DESCRIPTOR, PSID, SID_NAME_USE};
use windows::Win32::System::Rpc::RPC_C_AUTHN_WINNT;
use windows::core::{GUID, PCWSTR, PWSTR, w};

use super::capture::Block;

/// The capture's sublayer, in this session only.
const SUBLAYER: GUID = GUID::from_u128(0x7d1c4b2e_9f3a_4c61_8e57_2b6a0d93f4c1);
const SUBLAYER_WEIGHT: u16 = u16::MAX;
const NAME: PCWSTR = w!("Sieve DNS capture");
/// How long a transaction waits for another session's to finish before it fails
/// (the platform's default is unbounded).
const TXN_WAIT_MS: u32 = 2_000;
const DNS_PORT: u16 = 53;
const TCP: u8 = 6;
const UDP: u8 = 17;
/// The DNS Client service's account, whose service SID is in its token.
const DNS_CLIENT: PCWSTR = w!("NT SERVICE\\Dnscache");

fn check(code: u32, what: &str) -> Result<(), String> {
    if code == 0 { Ok(()) } else { Err(format!("{what}: error 0x{code:08x}")) }
}

fn display() -> FWPM_DISPLAY_DATA0 {
    // The engine only reads the name.
    FWPM_DISPLAY_DATA0 { name: PWSTR(NAME.0.cast_mut()), description: PWSTR::null() }
}

/// The open session, the filters it holds, and the descriptor that matches the DNS
/// Client's token.
pub struct Session {
    handle: HANDLE,
    filters: Vec<u64>,
    dns_client: Vec<u8>,
}

// SAFETY: the handle belongs to this value alone; the filtering engine's handles
// may be used from any thread, one call at a time, which `&mut self` ensures.
unsafe impl Send for Session {}

/// The SDDL that grants the DNS Client service's SID the right WFP checks
/// (`FWP_ACTRL_MATCH_FILTER`, SDDL `CC`).
fn dns_client_sddl() -> Result<String, String> {
    let (mut sid_len, mut domain_len, mut kind) = (0u32, 0u32, SID_NAME_USE::default());
    // SAFETY: a size probe with no buffers; it fails with the sizes filled in.
    let _ = unsafe { LookupAccountNameW(PCWSTR::null(), DNS_CLIENT, None, &mut sid_len, None, &mut domain_len, &mut kind) };
    let mut sid = vec![0u8; sid_len as usize];
    let mut domain = vec![0u16; domain_len as usize];
    // SAFETY: both buffers hold the sizes the probe asked for.
    unsafe { LookupAccountNameW(PCWSTR::null(), DNS_CLIENT, Some(PSID(sid.as_mut_ptr().cast())), &mut sid_len, Some(PWSTR(domain.as_mut_ptr())), &mut domain_len, &mut kind) }
        .map_err(|e| format!("the DNS Client's service SID: {e}"))?;
    let mut text = PWSTR::null();
    // SAFETY: `sid` holds the SID; `text` is LocalAlloc'd, freed below.
    unsafe { ConvertSidToStringSidW(PSID(sid.as_mut_ptr().cast()), &mut text) }.map_err(|e| e.to_string())?;
    // SAFETY: a NUL-terminated string from Windows.
    let sid_text = unsafe { text.to_string() }.map_err(|e| e.to_string());
    // SAFETY: freed once.
    let _ = unsafe { LocalFree(Some(HLOCAL(text.0.cast()))) };
    Ok(format!("D:(A;;CC;;;{})", sid_text?))
}

/// A self-relative descriptor's bytes, from SDDL.
fn descriptor(sddl: &str) -> Result<Vec<u8>, String> {
    let text: Vec<u16> = sddl.encode_utf16().chain(std::iter::once(0)).collect();
    let mut sd = PSECURITY_DESCRIPTOR::default();
    // SAFETY: `text` is NUL-terminated; `sd` is LocalAlloc'd, copied and freed below.
    unsafe { ConvertStringSecurityDescriptorToSecurityDescriptorW(PCWSTR(text.as_ptr()), SDDL_REVISION_1, &mut sd, None) }.map_err(|e| format!("{sddl}: {e}"))?;
    // SAFETY: a valid self-relative descriptor of that length.
    let bytes = unsafe { std::slice::from_raw_parts(sd.0.cast::<u8>(), GetSecurityDescriptorLength(sd) as usize) }.to_vec();
    // SAFETY: freed once.
    let _ = unsafe { LocalFree(Some(HLOCAL(sd.0))) };
    Ok(bytes)
}

/// Opens a dynamic session and adds the capture's sublayer to it.
pub fn open() -> Result<Session, String> {
    let dns_client = descriptor(&dns_client_sddl()?)?;
    let session = FWPM_SESSION0 { displayData: display(), flags: FWPM_SESSION_FLAG_DYNAMIC, txnWaitTimeoutInMSec: TXN_WAIT_MS, ..Default::default() };
    let mut handle = HANDLE::default();
    // SAFETY: `session` and `handle` outlive the call.
    check(unsafe { FwpmEngineOpen0(PCWSTR::null(), RPC_C_AUTHN_WINNT, None, Some(&session), &mut handle) }, "FwpmEngineOpen0")?;
    let opened = Session { handle, filters: Vec::new(), dns_client };
    let sublayer = FWPM_SUBLAYER0 { subLayerKey: SUBLAYER, displayData: display(), flags: 0, weight: SUBLAYER_WEIGHT, ..Default::default() };
    // SAFETY: `sublayer` outlives the call.
    check(unsafe { FwpmSubLayerAdd0(opened.handle, &sublayer, None) }, "FwpmSubLayerAdd0")?;
    Ok(opened)
}

impl Drop for Session {
    fn drop(&mut self) {
        // SAFETY: handed out by the filtering engine and closed once; the engine
        // then deletes every object of this dynamic session.
        unsafe { FwpmEngineClose0(self.handle) };
    }
}

fn equal(field: GUID, value: FWP_CONDITION_VALUE0) -> FWPM_FILTER_CONDITION0 {
    FWPM_FILTER_CONDITION0 { fieldKey: field, matchType: FWP_MATCH_EQUAL, conditionValue: value }
}

/// Host byte order, as the platform takes IPv4 values.
fn v4_mask(ip: std::net::Ipv4Addr, length: u8) -> FWP_V4_ADDR_AND_MASK {
    let mask = if length == 0 { 0 } else { u32::MAX << (32 - u32::from(length)) };
    FWP_V4_ADDR_AND_MASK { addr: u32::from(ip), mask }
}

impl Session {
    /// Replaces the session's filters with `blocks`, in one transaction: on any
    /// failure the old filters stay as they were and the error says why.
    pub fn set(&mut self, blocks: &[Block]) -> Result<(), String> {
        // SAFETY: an open handle.
        check(unsafe { FwpmTransactionBegin0(self.handle, 0) }, "FwpmTransactionBegin0")?;
        let mut added = Vec::new();
        let done = self.filters.iter().try_for_each(|id| {
            // SAFETY: an open handle.
            check(unsafe { FwpmFilterDeleteById0(self.handle, *id) }, "FwpmFilterDeleteById0")
        });
        let done = done.and_then(|()| blocks.iter().try_for_each(|b| self.add(b).map(|id| added.push(id))));

        // SAFETY: an open handle with a transaction open.
        let done = done.and_then(|()| check(unsafe { FwpmTransactionCommit0(self.handle) }, "FwpmTransactionCommit0"));
        match done {
            Ok(()) => {
                self.filters = added;
                Ok(())
            }
            Err(why) => {
                // SAFETY: an open handle; with no transaction open it only returns an error.
                let _ = unsafe { FwpmTransactionAbort0(self.handle) };
                Err(why)
            }
        }
    }

    /// The filters this session holds now.
    pub fn filters(&self) -> usize {
        self.filters.len()
    }

    fn add(&mut self, block: &Block) -> Result<u64, String> {
        // Every value a condition points at lives until FwpmFilterAdd0 returns:
        // the vectors are filled before any pointer into them is taken.
        let mut v4: Vec<FWP_V4_ADDR_AND_MASK> = Vec::new();
        let mut v6: Vec<FWP_V6_ADDR_AND_MASK> = Vec::new();
        for p in &block.to {
            match p.addr() {
                IpAddr::V4(ip) => v4.push(v4_mask(ip, p.length())),
                IpAddr::V6(ip) => v6.push(FWP_V6_ADDR_AND_MASK { addr: ip.octets(), prefixLength: p.length() }),
            }
        }
        let mut luids = block.on.clone();
        let mut user = FWP_BYTE_BLOB { size: u32::try_from(self.dns_client.len()).map_err(|_| "descriptor too large")?, data: self.dns_client.as_mut_ptr() };
        // Conditions on one field match when any does; different fields must all match.
        let mut conditions = vec![
            equal(FWPM_CONDITION_IP_REMOTE_PORT, FWP_CONDITION_VALUE0 { r#type: FWP_UINT16, Anonymous: FWP_CONDITION_VALUE0_0 { uint16: DNS_PORT } }),
            equal(FWPM_CONDITION_IP_PROTOCOL, FWP_CONDITION_VALUE0 { r#type: FWP_UINT8, Anonymous: FWP_CONDITION_VALUE0_0 { uint8: TCP } }),
            equal(FWPM_CONDITION_IP_PROTOCOL, FWP_CONDITION_VALUE0 { r#type: FWP_UINT8, Anonymous: FWP_CONDITION_VALUE0_0 { uint8: UDP } }),
            equal(FWPM_CONDITION_ALE_USER_ID, FWP_CONDITION_VALUE0 { r#type: FWP_SECURITY_DESCRIPTOR_TYPE, Anonymous: FWP_CONDITION_VALUE0_0 { sd: &mut user } }),
        ];
        for luid in &mut luids {
            conditions.push(equal(FWPM_CONDITION_IP_LOCAL_INTERFACE, FWP_CONDITION_VALUE0 { r#type: FWP_UINT64, Anonymous: FWP_CONDITION_VALUE0_0 { uint64: luid } }));
        }
        for mask in &mut v4 {
            conditions.push(equal(FWPM_CONDITION_IP_REMOTE_ADDRESS, FWP_CONDITION_VALUE0 { r#type: FWP_V4_ADDR_MASK, Anonymous: FWP_CONDITION_VALUE0_0 { v4AddrMask: mask } }));
        }
        for mask in &mut v6 {
            conditions.push(equal(FWPM_CONDITION_IP_REMOTE_ADDRESS, FWP_CONDITION_VALUE0 { r#type: FWP_V6_ADDR_MASK, Anonymous: FWP_CONDITION_VALUE0_0 { v6AddrMask: mask } }));
        }
        let row = FWPM_FILTER0 {
            displayData: display(),
            flags: FWPM_FILTER_FLAGS(0),
            layerKey: if block.v4 { FWPM_LAYER_ALE_AUTH_CONNECT_V4 } else { FWPM_LAYER_ALE_AUTH_CONNECT_V6 },
            subLayerKey: SUBLAYER,
            weight: FWP_VALUE0 { r#type: FWP_UINT8, Anonymous: FWP_VALUE0_0 { uint8: 15 } },
            numFilterConditions: u32::try_from(conditions.len()).map_err(|_| "too many conditions for one filter")?,
            filterCondition: conditions.as_mut_ptr(),
            action: FWPM_ACTION0 { r#type: FWP_ACTION_BLOCK, ..Default::default() },
            ..Default::default()
        };
        let mut id = 0u64;
        // SAFETY: `row` and everything its conditions point at outlive the call.
        check(unsafe { FwpmFilterAdd0(self.handle, &row, None, Some(&mut id)) }, "FwpmFilterAdd0")?;
        Ok(id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ipv4_masks_are_host_order_prefixes() {
        let m = v4_mask("192.168.7.1".parse().unwrap(), 32);
        assert_eq!((m.addr, m.mask), (0xc0a8_0701, u32::MAX));
        let m = v4_mask("128.0.0.0".parse().unwrap(), 1);
        assert_eq!((m.addr, m.mask), (0x8000_0000, 0x8000_0000));
        assert_eq!(v4_mask("0.0.0.0".parse().unwrap(), 0).mask, 0);
    }

    /// Reads the local account database only.
    #[test]
    fn the_dns_clients_descriptor_names_its_service_sid() {
        let sddl = dns_client_sddl().unwrap();
        assert!(sddl.starts_with("D:(A;;CC;;;S-1-5-80-"), "{sddl}");
        assert!(descriptor(&sddl).unwrap().len() > 20);
    }
}
