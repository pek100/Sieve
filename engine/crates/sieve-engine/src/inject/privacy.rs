//! Tracking protection's page script (plan 2026-11-09): the browser APIs a page
//! may not use, put in the page's one injected `<script>` beside its scriptlets.
//! Each piece is plain ES5 in its own scope and does nothing when the API is
//! absent; it runs before the page's own scripts, as the content hook injects at
//! the start of the head.
//!
//! TENSION: a page can still reach an API through a frame it makes itself
//! (`about:blank`, a blob) or a worker, which no response carries; parity with what
//! an injected script can do. Pages that are not decrypted never get it.

use sieve_ipc::LogChange;

use crate::http::tracking::{Protection, Protections};

/// No peer connection can be made, so no candidate can name a local address.
const WEB_RTC: &str = "(function(){var n=['RTCPeerConnection','webkitRTCPeerConnection','mozRTCPeerConnection','RTCDataChannel'];for(var i=0;i<n.length;i++){try{Object.defineProperty(window,n[i],{value:undefined,writable:false,configurable:false});}catch(e){}}})();";
/// A subscription is refused and the permission reads denied, so no server can push.
const PUSH: &str = "(function(){if(typeof PushManager==='undefined'){return;}var p=PushManager.prototype;var no=function(){return Promise.reject(new DOMException('Push is blocked','NotAllowedError'));};try{p.subscribe=no;p.getSubscription=function(){return Promise.resolve(null);};p.permissionState=function(){return Promise.resolve('denied');};}catch(e){}})();";
/// Every request for the position answers "permission denied", as a refusal does.
const LOCATION: &str = "(function(){var g=navigator.geolocation;if(!g){return;}var denied={code:1,message:'User denied Geolocation',PERMISSION_DENIED:1,POSITION_UNAVAILABLE:2,TIMEOUT:3};var no=function(ok,fail){if(typeof fail==='function'){setTimeout(function(){fail(denied);},0);}};try{g.getCurrentPosition=no;g.watchPosition=function(ok,fail){no(ok,fail);return 0;};g.clearWatch=function(){};}catch(e){}})();";

const PIECES: [(Protection, &str); 3] = [(Protection::WebRtc, WEB_RTC), (Protection::Push, PUSH), (Protection::Location, LOCATION)];

/// The script for the protections on, and the change each makes; empty for none.
pub fn script(on: Protections) -> (String, Vec<LogChange>) {
    let mut js = String::new();
    let mut changes = Vec::new();
    for (p, piece) in PIECES {
        if on.has(p) {
            js.push_str(piece);
            js.push('\n');
            changes.push(LogChange { what: p.name().to_string(), count: 1 });
        }
    }
    (js, changes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn each_protection_adds_its_piece_and_its_change() {
        assert_eq!(script(Protections::NONE), (String::new(), Vec::new()));
        let (js, changes) = script(Protections::of(&[Protection::WebRtc, Protection::Location, Protection::Gpc]));
        assert!(js.contains("RTCPeerConnection") && js.contains("geolocation") && !js.contains("PushManager"));
        assert_eq!(changes.iter().map(|c| c.what.as_str()).collect::<Vec<_>>(), ["webRtc", "location"]);
    }

    /// The payload's escaping is for rule text; these pieces need none, so what
    /// the page runs is what is written here.
    #[test]
    fn the_pieces_are_ascii_and_close_nothing() {
        for (_, piece) in PIECES {
            assert!(piece.is_ascii());
            assert_eq!(super::super::payload::js_text(piece), piece);
        }
    }
}
