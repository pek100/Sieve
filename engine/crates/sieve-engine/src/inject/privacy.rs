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
/// Every request for the position answers "permission denied", as a refusal does,
/// and asking the permission's state reads denied, as it does after a refusal.
const LOCATION: &str = "(function(){var g=navigator.geolocation;if(!g){return;}var denied={code:1,message:'User denied Geolocation',PERMISSION_DENIED:1,POSITION_UNAVAILABLE:2,TIMEOUT:3};var no=function(ok,fail){if(typeof fail==='function'){setTimeout(function(){fail(denied);},0);}};try{g.getCurrentPosition=no;g.watchPosition=function(ok,fail){no(ok,fail);return 0;};g.clearWatch=function(){};}catch(e){}var P=navigator.permissions;if(!P||typeof P.query!=='function'){return;}var q=P.query;var state={name:'geolocation',state:'denied',status:'denied',onchange:null,addEventListener:function(){},removeEventListener:function(){},dispatchEvent:function(){return false;}};try{P.query=function(d){if(d&&d.name==='geolocation'){return Promise.resolve(state);}return q.apply(P,arguments);};}catch(e){}})();";
/// The page reads the signal the headers send: `navigator.globalPrivacyControl`
/// true. `navigator.doNotTrack` is the browser's own and is left alone.
const SIGNALS: &str = "(function(){if(typeof Navigator==='undefined'){return;}try{Object.defineProperty(Navigator.prototype,'globalPrivacyControl',{get:function(){return true;},configurable:true,enumerable:true});}catch(e){}})();";

const PIECES: [(Protection, &str); 3] = [(Protection::WebRtc, WEB_RTC), (Protection::Push, PUSH), (Protection::Location, LOCATION)];

/// Sieve's own script for one page.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PageScript {
    /// The browser-API protections: a page that has nothing else injected is
    /// rewritten for these.
    pub script: String,
    /// What `script` changes, for the log.
    pub changes: Vec<LogChange>,
    /// What rides along when the page is rewritten anyway (`gpc`'s signal, which
    /// is on at every level: rewriting every page for them alone would change
    /// pages that have nothing else to change). A page not rewritten keeps the
    /// browser's own values, unlike its headers.
    pub signals: String,
}

/// The script for the protections on; empty for none.
pub fn script(on: Protections) -> PageScript {
    let mut page = PageScript::default();
    for (p, piece) in PIECES {
        if on.has(p) {
            page.script.push_str(piece);
            page.script.push('\n');
            page.changes.push(LogChange { what: p.name().to_string(), count: 1 });
        }
    }
    if on.has(Protection::Gpc) {
        page.signals.push_str(SIGNALS);
        page.signals.push('\n');
    }
    page
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn each_protection_adds_its_piece_and_its_change() {
        assert_eq!(script(Protections::NONE), PageScript::default());
        let page = script(Protections::of(&[Protection::WebRtc, Protection::Location, Protection::Gpc]));
        assert!(page.script.contains("RTCPeerConnection") && page.script.contains("geolocation") && !page.script.contains("PushManager"));
        assert_eq!(page.changes.iter().map(|c| c.what.as_str()).collect::<Vec<_>>(), ["webRtc", "location"]);
        assert!(page.signals.contains("globalPrivacyControl") && !page.signals.contains("doNotTrack") && !page.script.contains("globalPrivacyControl"), "gpc rides along");
        assert!(script(Protections::of(&[Protection::WebRtc])).signals.is_empty());
    }

    #[test]
    fn location_answers_the_permission_query_as_denied() {
        assert!(LOCATION.contains("P.query=function(d){if(d&&d.name==='geolocation'){return Promise.resolve(state);}return q.apply(P,arguments);}"));
        assert!(LOCATION.contains("state:'denied'"));
    }

    /// The payload's escaping is for rule text; these pieces need none, so what
    /// the page runs is what is written here.
    #[test]
    fn the_pieces_are_ascii_and_close_nothing() {
        for piece in PIECES.map(|(_, p)| p).into_iter().chain([SIGNALS]) {
            assert!(piece.is_ascii());
            assert_eq!(super::super::payload::js_text(piece), piece);
        }
    }
}
