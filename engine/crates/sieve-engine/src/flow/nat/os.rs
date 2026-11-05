//! Windows: the real NAT sources and VM directory. Read only: WQL `ExecQuery`
//! and HCN/HCS queries, nothing else. Everything here runs on the NAT reader
//! thread ([`super::NatTable::spawn`]), which owns the COM apartment.
//!
//! - [`WmiNat`]: `MSFT_NetNatSession`, proven live for WSL.
//! - [`HostCompute`]: internal IP -> HCN endpoint -> VM id -> HCS compute
//!   system's `Owner`, then `Msvm_ComputerSystem.ElementName` when the system
//!   has one. The name always comes from the system, never from a list in
//!   source; a failed link is no name. UNVERIFIED until live proof L1, because
//!   these answer Access denied without elevation.
//!
//! `computenetwork.dll` and `computecore.dll` load at run time, from System32
//! only: a static import of an optional component would stop the service from
//! starting on a machine without it, which breaks fail-open.

use std::collections::HashMap;
use std::ffi::c_void;
use std::net::IpAddr;
use std::sync::{Arc, Mutex};

use windows::Win32::Foundation::{FreeLibrary, HMODULE, RPC_E_CHANGED_MODE};
use windows::Win32::System::Com::{
    CLSCTX_INPROC_SERVER, COINIT_MULTITHREADED, CoCreateInstance, CoInitializeEx, CoSetProxyBlanket, CoTaskMemFree, CoUninitialize,
    EOAC_NONE, RPC_C_AUTHN_LEVEL_CALL, RPC_C_IMP_LEVEL_IMPERSONATE,
};
use windows::Win32::System::LibraryLoader::{GetProcAddress, LOAD_LIBRARY_SEARCH_SYSTEM32, LoadLibraryExW};
use windows::Win32::System::Rpc::{RPC_C_AUTHN_WINNT, RPC_C_AUTHZ_NONE};
use windows::Win32::System::Variant::{VARIANT, VT_BSTR, VT_I4, VariantClear};
use windows::Win32::System::Wmi::{
    IEnumWbemClassObject, IWbemClassObject, IWbemLocator, IWbemServices, WBEM_FLAG_FORWARD_ONLY, WBEM_FLAG_RETURN_IMMEDIATELY, WbemLocator,
};
use windows::core::{BSTR, GUID, HRESULT, PCSTR, PCWSTR, PWSTR};

use super::{
    EndpointFacts, NatSession, NatSource, NoDirectory, VmDirectory, WinNatEvents, WinNatTable, is_guid, parse_compute_systems, parse_endpoint,
    parse_id_list, session_from_fields,
};

const NAMESPACE_NAT: &str = r"root\StandardCimv2";
const NAMESPACE_VIRTUALIZATION: &str = r"root\virtualization\v2";
const NAMESPACE_CIM: &str = r"root\cimv2";
const NAT_QUERY: &str = "SELECT Protocol, InternalSourceAddress, InternalSourcePort, ExternalSourceAddress, ExternalSourcePort, \
ExternalDestinationAddress, ExternalDestinationPort FROM MSFT_NetNatSession";
/// Next() waits this long per row: the reader's own bound.
const ROW_WAIT_MS: i32 = 900;
/// How long HCS may take to list compute systems.
const HCS_WAIT_MS: u32 = 900;
/// The directory re-reads HCN and HCS at most this often.
const DIRECTORY_MAX_AGE_MS: u64 = 5_000;

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

/// This thread's COM apartment, for as long as the reader lives.
pub struct ComApartment;

impl ComApartment {
    pub fn enter() -> Result<Self, String> {
        // SAFETY: plain call on this thread, paired with CoUninitialize in Drop.
        let hr = unsafe { CoInitializeEx(None, COINIT_MULTITHREADED) };
        if hr.is_err() && hr != RPC_E_CHANGED_MODE {
            return Err(format!("COM: {hr:?}"));
        }
        Ok(Self)
    }
}

impl Drop for ComApartment {
    fn drop(&mut self) {
        // SAFETY: this thread entered in `enter`.
        unsafe { CoUninitialize() };
    }
}

/// A connection to one WMI namespace.
struct Wmi {
    services: IWbemServices,
}

impl Wmi {
    fn connect(namespace: &str) -> Result<Self, String> {
        let text = |e: windows::core::Error| format!("WMI {namespace}: {e}");
        // SAFETY: COM is initialized on this thread (ComApartment).
        let locator: IWbemLocator = unsafe { CoCreateInstance(&WbemLocator, None, CLSCTX_INPROC_SERVER) }.map_err(text)?;
        let empty = BSTR::new();
        // SAFETY: every argument is a live BSTR.
        let services = unsafe { locator.ConnectServer(&BSTR::from(namespace), &empty, &empty, &empty, 0, &empty, None) }.map_err(text)?;
        // SAFETY: `services` is a live proxy; the constants are valid levels.
        unsafe {
            CoSetProxyBlanket(&services, RPC_C_AUTHN_WINNT, RPC_C_AUTHZ_NONE, PCWSTR::null(), RPC_C_AUTHN_LEVEL_CALL, RPC_C_IMP_LEVEL_IMPERSONATE, None, EOAC_NONE)
        }
        .map_err(text)?;
        Ok(Self { services })
    }

    /// The rows of one WQL query, read only.
    fn query(&self, wql: &str) -> Result<Vec<IWbemClassObject>, String> {
        let text = |e: windows::core::Error| format!("WMI query: {e}");
        // SAFETY: the BSTRs are live; flags are valid for ExecQuery.
        let rows: IEnumWbemClassObject = unsafe {
            self.services.ExecQuery(&BSTR::from("WQL"), &BSTR::from(wql), WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY, None)
        }
        .map_err(text)?;
        let mut out = Vec::new();
        loop {
            let mut slot = [None];
            let mut returned = 0u32;
            // SAFETY: `slot` holds one row and `returned` is a live out pointer.
            let hr = unsafe { rows.Next(ROW_WAIT_MS, &mut slot, &mut returned) };
            hr.ok().map_err(text)?;
            match slot[0].take() {
                Some(row) if returned > 0 => out.push(row),
                _ => return Ok(out),
            }
        }
    }
}

/// A VARIANT that WMI filled, cleared when read.
struct Property(VARIANT);

impl Drop for Property {
    fn drop(&mut self) {
        // SAFETY: a VARIANT `Get` initialized, cleared once.
        let _ = unsafe { VariantClear(&mut self.0) };
    }
}

fn property(row: &IWbemClassObject, name: &str) -> Option<Property> {
    let name = wide(name);
    let mut value = Property(VARIANT::default());
    // SAFETY: `name` is NUL-terminated and the VARIANT is live.
    unsafe { row.Get(PCWSTR(name.as_ptr()), 0, &mut value.0, None, None) }.ok()?;
    Some(value)
}

fn text_of(row: &IWbemClassObject, name: &str) -> Option<String> {
    let value = property(row, name)?;
    // SAFETY: `vt` says which union member is live; it is read only after that check.
    unsafe {
        let v = &value.0.Anonymous.Anonymous;
        (v.vt == VT_BSTR).then(|| v.Anonymous.bstrVal.to_string())
    }
}

/// WMI hands CIM uint16 and uint32 as VT_I4.
fn number_of(row: &IWbemClassObject, name: &str) -> Option<u32> {
    let value = property(row, name)?;
    // SAFETY: `vt` says which union member is live; it is read only after that check.
    let n = unsafe {
        let v = &value.0.Anonymous.Anonymous;
        (v.vt == VT_I4).then_some(v.Anonymous.lVal)
    }?;
    u32::try_from(n).ok()
}

fn session_of_row(row: &IWbemClassObject) -> Option<NatSession> {
    let port = |name: &str| number_of(row, name).and_then(|n| u16::try_from(n).ok());
    session_from_fields(
        number_of(row, "Protocol")?,
        (&text_of(row, "InternalSourceAddress")?, port("InternalSourcePort")?),
        (&text_of(row, "ExternalSourceAddress")?, port("ExternalSourcePort")?),
        (&text_of(row, "ExternalDestinationAddress")?, port("ExternalDestinationPort")?),
    )
}

/// `MSFT_NetNatSession`, connected on first use (a machine without WinNAT
/// never pays for it until an unknown flow asks).
#[derive(Default)]
pub struct WmiNat {
    wmi: Option<Wmi>,
}

impl NatSource for WmiNat {
    fn read(&mut self) -> Result<Vec<NatSession>, String> {
        if self.wmi.is_none() {
            self.wmi = Some(Wmi::connect(NAMESPACE_NAT)?);
        }
        let rows = self.wmi.as_ref().ok_or("no WMI connection")?.query(NAT_QUERY);
        if rows.is_err() {
            // A dead connection is not retried on a stale proxy: the next read reconnects.
            self.wmi = None;
        }
        Ok(rows?.iter().filter_map(session_of_row).collect())
    }
}

/// A System32 DLL loaded at run time; absent means that link has no answer.
struct OptionalDll(HMODULE);

impl OptionalDll {
    fn load(name: &str) -> Option<Self> {
        let name = wide(name);
        // SAFETY: `name` is NUL-terminated; the flag limits the search to System32.
        unsafe { LoadLibraryExW(PCWSTR(name.as_ptr()), None, LOAD_LIBRARY_SEARCH_SYSTEM32) }.ok().map(Self)
    }

    /// The export as `F`, a matching `unsafe extern "system" fn` type.
    ///
    /// # Safety
    /// `F` must be the export's real signature.
    unsafe fn export<F: Copy>(&self, name: &'static [u8]) -> Option<F> {
        debug_assert_eq!(name.last(), Some(&0), "NUL-terminated");
        debug_assert_eq!(size_of::<F>(), size_of::<usize>());
        // SAFETY: the name is NUL-terminated and the module is loaded.
        let found = unsafe { GetProcAddress(self.0, PCSTR(name.as_ptr())) }?;
        // SAFETY: the caller states `F` is its real signature; both are fn pointers.
        Some(unsafe { std::mem::transmute_copy(&found) })
    }
}

impl Drop for OptionalDll {
    fn drop(&mut self) {
        // SAFETY: loaded by `load`, freed once.
        let _ = unsafe { FreeLibrary(self.0) };
    }
}

type HcnEnumerateEndpoints = unsafe extern "system" fn(PCWSTR, *mut PWSTR, *mut PWSTR) -> HRESULT;
type HcnOpenEndpoint = unsafe extern "system" fn(*const GUID, *mut *mut c_void, *mut PWSTR) -> HRESULT;
type HcnQueryEndpointProperties = unsafe extern "system" fn(*mut c_void, PCWSTR, *mut PWSTR, *mut PWSTR) -> HRESULT;
type HcnCloseEndpoint = unsafe extern "system" fn(*mut c_void) -> HRESULT;
type HcsCreateOperation = unsafe extern "system" fn(*const c_void, *const c_void) -> *mut c_void;
type HcsCloseOperation = unsafe extern "system" fn(*mut c_void);
type HcsEnumerateComputeSystems = unsafe extern "system" fn(PCWSTR, *mut c_void) -> HRESULT;
type HcsWaitForOperationResult = unsafe extern "system" fn(*mut c_void, u32, *mut PWSTR) -> HRESULT;

/// A string the API allocated: read once, then freed.
fn take(p: PWSTR) -> Option<String> {
    if p.is_null() {
        return None;
    }
    // SAFETY: the API returned a NUL-terminated string it allocated for the caller.
    let text = unsafe { p.to_string() }.ok();
    // SAFETY: documented as CoTaskMemFree's to free; freed once.
    unsafe { CoTaskMemFree(Some(p.0 as *const c_void)) };
    text
}

fn endpoints(hcn: &OptionalDll) -> Option<Vec<EndpointFacts>> {
    // SAFETY: these are computenetwork.h's exports, with these signatures.
    let (enumerate, open, query, close) = unsafe {
        (
            hcn.export::<HcnEnumerateEndpoints>(b"HcnEnumerateEndpoints\0")?,
            hcn.export::<HcnOpenEndpoint>(b"HcnOpenEndpoint\0")?,
            hcn.export::<HcnQueryEndpointProperties>(b"HcnQueryEndpointProperties\0")?,
            hcn.export::<HcnCloseEndpoint>(b"HcnCloseEndpoint\0")?,
        )
    };
    let (mut list, mut error) = (PWSTR::null(), PWSTR::null());
    let no_query = wide("{}");
    // SAFETY: out pointers are live; the strings they receive are freed by `take`.
    let hr = unsafe { enumerate(PCWSTR(no_query.as_ptr()), &mut list, &mut error) };
    let _ = take(error);
    let list = take(list);
    hr.ok().ok()?;
    let mut facts = Vec::new();
    for id in parse_id_list(&list?) {
        let Ok(guid) = GUID::try_from(id.trim_matches(['{', '}'])) else { continue };
        let (mut endpoint, mut error) = (std::ptr::null_mut(), PWSTR::null());
        // SAFETY: `guid` and the out pointers are live.
        let hr = unsafe { open(&guid, &mut endpoint, &mut error) };
        let _ = take(error);
        if hr.is_err() {
            continue;
        }
        let (mut props, mut error) = (PWSTR::null(), PWSTR::null());
        // SAFETY: `endpoint` was just opened; out pointers are live.
        let hr = unsafe { query(endpoint, PCWSTR(no_query.as_ptr()), &mut props, &mut error) };
        let _ = take(error);
        let props = take(props);
        // SAFETY: opened above, closed once.
        let _ = unsafe { close(endpoint) };
        if hr.is_ok()
            && let Some(f) = props.as_deref().and_then(parse_endpoint)
        {
            facts.push(f);
        }
    }
    Some(facts)
}

fn compute_systems(hcs: &OptionalDll) -> Option<HashMap<String, String>> {
    // SAFETY: these are computecore.h's exports, with these signatures.
    let (create, close, enumerate, wait) = unsafe {
        (
            hcs.export::<HcsCreateOperation>(b"HcsCreateOperation\0")?,
            hcs.export::<HcsCloseOperation>(b"HcsCloseOperation\0")?,
            hcs.export::<HcsEnumerateComputeSystems>(b"HcsEnumerateComputeSystems\0")?,
            hcs.export::<HcsWaitForOperationResult>(b"HcsWaitForOperationResult\0")?,
        )
    };
    // SAFETY: a null context and callback make a plain waitable operation.
    let operation = unsafe { create(std::ptr::null(), std::ptr::null()) };
    if operation.is_null() {
        return None;
    }
    let mut result = PWSTR::null();
    // SAFETY: `operation` is live; a null query lists every system; `result` is a live out pointer.
    let hr = unsafe {
        let started = enumerate(PCWSTR::null(), operation);
        if started.is_err() { started } else { wait(operation, HCS_WAIT_MS, &mut result) }
    };
    let result = take(result);
    // SAFETY: created above, closed once.
    unsafe { close(operation) };
    hr.ok().ok()?;
    Some(parse_compute_systems(&result?))
}

/// The real directory, by the chain in the module docs. Every link is read
/// again at most every [`DIRECTORY_MAX_AGE_MS`].
pub struct HostCompute {
    hcn: Option<OptionalDll>,
    hcs: Option<OptionalDll>,
    /// Internal IP to VM id, and VM id to its owner.
    by_ip: HashMap<IpAddr, String>,
    owners: HashMap<String, String>,
    virtualization: Option<Wmi>,
    read_ms: Option<u64>,
}

impl HostCompute {
    pub fn load() -> Self {
        Self {
            hcn: OptionalDll::load("computenetwork.dll"),
            hcs: OptionalDll::load("computecore.dll"),
            by_ip: HashMap::new(),
            owners: HashMap::new(),
            virtualization: None,
            read_ms: None,
        }
    }

    fn refresh(&mut self) {
        let now = crate::watchdog::monotonic_ms();
        if self.read_ms.is_some_and(|at| now.saturating_sub(at) < DIRECTORY_MAX_AGE_MS) {
            return;
        }
        self.read_ms = Some(now);
        self.by_ip = self
            .hcn
            .as_ref()
            .and_then(endpoints)
            .unwrap_or_default()
            .into_iter()
            .flat_map(|f| f.ips.into_iter().map(move |ip| (ip, f.vm_id.to_lowercase())))
            .collect();
        self.owners = self.hcs.as_ref().and_then(compute_systems).unwrap_or_default();
    }

    /// `Msvm_ComputerSystem.ElementName` of a VM id, when this machine has that class.
    fn element_name(&mut self, vm_id: &str) -> Option<String> {
        if !is_guid(vm_id) {
            return None;
        }
        if self.virtualization.is_none() {
            self.virtualization = Wmi::connect(NAMESPACE_VIRTUALIZATION).ok();
        }
        let wql = format!("SELECT ElementName FROM Msvm_ComputerSystem WHERE Name = '{vm_id}'");
        let rows = self.virtualization.as_ref()?.query(&wql).ok()?;
        text_of(rows.first()?, "ElementName")
    }
}

impl VmDirectory for HostCompute {
    fn vm_of(&mut self, internal: IpAddr) -> Option<String> {
        self.refresh();
        let vm_id = self.by_ip.get(&internal.to_canonical())?.clone();
        self.element_name(&vm_id).or_else(|| self.owners.get(&vm_id).cloned())
    }
}

/// What the NAT reader thread runs: both sources behind the one trait, and
/// the directory. A failure to enter COM leaves the event table and no names.
pub fn reader_sources(winnat: Arc<Mutex<WinNatTable>>) -> (Vec<Box<dyn NatSource>>, Box<dyn VmDirectory>) {
    let events: Box<dyn NatSource> = Box::new(WinNatEvents(winnat));
    let Ok(apartment) = ComApartment::enter() else {
        return (vec![events], Box::new(NoDirectory));
    };
    // Lives as long as the reader thread, whose sources need it.
    std::mem::forget(apartment);
    (vec![Box::new(WmiNat::default()), events], Box::new(HostCompute::load()))
}

/// Proves COM and WMI load under the service's System32-only DLL search
/// (example `wmi_system32`): the caption of this Windows, by one plain query.
pub fn operating_system_caption() -> Result<String, String> {
    let _apartment = ComApartment::enter()?;
    let wmi = Wmi::connect(NAMESPACE_CIM)?;
    let rows = wmi.query("SELECT Caption FROM Win32_OperatingSystem")?;
    rows.first().and_then(|r| text_of(r, "Caption")).ok_or_else(|| "no Win32_OperatingSystem row".into())
}
