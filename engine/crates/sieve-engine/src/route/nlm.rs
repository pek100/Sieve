//! Windows' word on the network, read only (`route::sign_in`'s seam): which
//! network it is, and whether Windows itself found a sign-in page there.
//!
//! The documented Network List Manager API: `INetworkListManager`
//! (CLSID `NetworkListManager`) enumerates the connected network connections;
//! each `INetworkConnection` names its adapter (`GetAdapterId`) and its network
//! (`GetNetwork`, `INetwork::GetNetworkId`), and its `IPropertyBag` holds
//! `NA_InternetConnectivityV4` and `V6`, whose
//! `NLM_INTERNET_CONNECTIVITY_WEBHIJACK` flag is Windows' "this network has a
//! sign-in page" (Windows 10 1709 and later). Its `NLM_CONNECTIVITY` ("no
//! internet") is not read: while the capture holds it only repeats that
//! encrypted DNS fails (`route::sign_in`). Nothing is written, no event is
//! subscribed: one read, on a blocking thread with its own COM apartment, only
//! when `SignIn::needs_verdict` says so, and never a second while one still runs
//! (`control::routing`).

use windows::Win32::NetworkManagement::IpHelper::ConvertInterfaceGuidToLuid;
use windows::Win32::NetworkManagement::Ndis::NET_LUID_LH;
use windows::Win32::Networking::NetworkListManager::{
    INetworkConnection, INetworkListManager, NA_InternetConnectivityV4, NA_InternetConnectivityV6, NetworkListManager,
};
use windows::Win32::System::Com::StructuredStorage::IPropertyBag;
use windows::Win32::System::Com::{CLSCTX_ALL, CoCreateInstance};
use windows::Win32::System::Variant::{VARIANT, VT_I4, VT_UI4, VariantClear};
use windows::core::{GUID, Interface, PCWSTR};

use super::sign_in::{Verdict, hijacked};
use crate::flow::nat::os::ComApartment;

/// Connections read at most: a machine has a handful.
const MAX_CONNECTIONS: usize = 64;

/// Windows' verdict on the connected network of the adapter `luid`, or None when
/// that adapter has no connected network. Blocking: call it off the runtime.
pub fn verdict(luid: u64) -> Result<Option<Verdict>, String> {
    let _com = ComApartment::enter()?;
    read(luid)
}

fn read(luid: u64) -> Result<Option<Verdict>, String> {
    let text = |e: windows::core::Error| format!("Network List Manager: {e}");
    // SAFETY: COM is entered on this thread (`_com` in `verdict`, dropped after every object here).
    let manager: INetworkListManager = unsafe { CoCreateInstance(&NetworkListManager, None, CLSCTX_ALL) }.map_err(text)?;
    // SAFETY: a live manager.
    let connections = unsafe { manager.GetNetworkConnections() }.map_err(text)?;
    for _ in 0..MAX_CONNECTIONS {
        let mut slot = [None];
        let mut fetched = 0u32;
        // SAFETY: one slot and a live out count.
        unsafe { connections.Next(&mut slot, Some(&mut fetched)) }.map_err(text)?;
        let [Some(connection)] = slot else { return Ok(None) };
        if fetched == 0 {
            return Ok(None);
        }
        // SAFETY: a live connection.
        let adapter = unsafe { connection.GetAdapterId() }.map_err(text)?;
        if luid_of(&adapter) != Some(luid) {
            continue;
        }
        // SAFETY: a live connection; its network is a live object too.
        let network = unsafe { connection.GetNetwork().and_then(|n| n.GetNetworkId()) }.map_err(text)?;
        let (v4, v6) = (internet_flags(&connection, NA_InternetConnectivityV4), internet_flags(&connection, NA_InternetConnectivityV6));
        return Ok(Some(Verdict { network: braced(&network), luid, hijacked: hijacked(v4, v6) }));
    }
    Ok(None)
}

fn luid_of(adapter: &GUID) -> Option<u64> {
    let mut luid = NET_LUID_LH::default();
    // SAFETY: both pointers are live for the call.
    let code = unsafe { ConvertInterfaceGuidToLuid(adapter, &mut luid) };
    // SAFETY: the union's one member, written by the call.
    code.is_ok().then_some(unsafe { luid.Value })
}

/// `{XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX}`, as Windows writes a network id.
fn braced(id: &GUID) -> String {
    format!("{{{id:?}}}")
}

/// A VARIANT the property bag filled, cleared when dropped.
struct Value(VARIANT);

impl Drop for Value {
    fn drop(&mut self) {
        // SAFETY: initialized by `Read` or default, cleared once.
        let _ = unsafe { VariantClear(&mut self.0) };
    }
}

/// One `NA_InternetConnectivity*` value of the connection, when Windows has it
/// (it is absent before Windows has tested the network, and on older builds).
fn internet_flags(connection: &INetworkConnection, name: PCWSTR) -> Option<u32> {
    let bag: IPropertyBag = connection.cast().ok()?;
    let mut value = Value(VARIANT::default());
    // SAFETY: `name` is a static wide string; the VARIANT is live.
    unsafe { bag.Read(name, &mut value.0, None) }.ok()?;
    // SAFETY: `vt` says which union member is live; it is read only after that check.
    unsafe {
        let v = &value.0.Anonymous.Anonymous;
        match v.vt {
            VT_UI4 => Some(v.Anonymous.ulVal),
            VT_I4 => u32::try_from(v.Anonymous.lVal).ok(),
            _ => None,
        }
    }
}
