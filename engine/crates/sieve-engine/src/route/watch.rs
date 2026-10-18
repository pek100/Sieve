//! `NotifyRouteChange2` (plan 1.7): any change to the forwarding table (a
//! VPN coming up or going, a new network, the engine's own routes) wakes the
//! engine's control loop, which re-reads the tables and decides again. The
//! callback only flags the change; nothing runs on Windows' thread.

use std::ffi::c_void;
use std::sync::Arc;

use tokio::sync::Notify;
use windows::Win32::Foundation::{HANDLE, NO_ERROR};
use windows::Win32::NetworkManagement::IpHelper::{CancelMibChangeNotify2, MIB_IPFORWARD_ROW2, MIB_NOTIFICATION_TYPE, NotifyRouteChange2};
use windows::Win32::Networking::WinSock::AF_UNSPEC;

/// Registered while alive; dropping it cancels the notification.
pub struct RouteWatch {
    handle: HANDLE,
    context: *const Notify,
}

// SAFETY: the handle is only passed to CancelMibChangeNotify2, and the
// context is an Arc<Notify> (Send + Sync) kept alive until then.
unsafe impl Send for RouteWatch {}
// SAFETY: as above; no method touches either field through &self.
unsafe impl Sync for RouteWatch {}

unsafe extern "system" fn changed(context: *const c_void, _row: *const MIB_IPFORWARD_ROW2, _kind: MIB_NOTIFICATION_TYPE) {
    // SAFETY: `context` is the Notify `watch` registered, alive until the
    // registration is cancelled (Drop), which waits for running callbacks.
    let notify = unsafe { &*context.cast::<Notify>() };
    notify.notify_one();
}

/// Wakes `notify` on every route change, both families.
pub fn watch(notify: Arc<Notify>) -> Result<RouteWatch, String> {
    let context = Arc::into_raw(notify);
    let mut handle = HANDLE::default();
    // SAFETY: `changed` matches the callback type; `context` stays valid
    // until CancelMibChangeNotify2 in Drop.
    let code = unsafe { NotifyRouteChange2(AF_UNSPEC, Some(changed), context.cast(), false, &mut handle) };
    if code != NO_ERROR {
        // SAFETY: registration failed, so the raw Arc is ours again.
        drop(unsafe { Arc::from_raw(context) });
        return Err(format!("NotifyRouteChange2: Win32 error {}", code.0));
    }
    Ok(RouteWatch { handle, context })
}

impl Drop for RouteWatch {
    fn drop(&mut self) {
        // SAFETY: cancels the registration this value made; Windows waits for
        // a running callback, after which the context can be released.
        unsafe {
            let _ = CancelMibChangeNotify2(self.handle);
            drop(Arc::from_raw(self.context));
        }
    }
}
