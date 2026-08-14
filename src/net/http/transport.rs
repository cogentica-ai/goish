// net/http/transport — the connection-pool addressing layer.
//
// FIRST SLICE of Go 1.25.5 net/http/transport.go, ported deliberately
// unwired: `Client.Do` still uses the existing dial-per-request path
// in client.rs, which has the whole example suite behind it. Rewiring
// happens once persistConn/readLoop/writeLoop land, not before — a
// half-migrated pool would be worse than the simple path it replaces.
// That is a staged migration, not the ported-but-unwired smell; the
// distinction is that nothing here CLAIMS to be live.
//
// What this slice covers: how a request becomes a pool key, and the
// two data structures the pool is built on.
//
//   connectMethod / connectMethodKey and their methods — the key
//   wantConnQueue — the per-host waiter queue (pure, no channels)
//   connLRU        — the idle-conn eviction order
//   canonicalAddr / schemePort / idnaASCIIFromURL
//   Transport.RegisterProtocol / useRegisteredProtocol /
//   alternateRoundTripper — the "file"/"ftp" scheme hook
//
// GOISH018/021 will report every transport.go declaration NOT in this
// file. That is the honest worklist, not noise: unlike server_tls.rs
// and responsewriter.rs, transport.rs IS the right home for all of
// transport.go — the rest simply is not written yet.

#![allow(non_snake_case, non_camel_case_types)]

extern crate alloc;

use alloc::sync::Arc;
use alloc::vec::Vec;

use crate::goslice::slice;
use crate::string;
use crate::types::int;

use super::client::{RoundTripper, Transport};
use super::request::Request;
use super::url::URL;

// go: sdk 1.25.5 net/http/transport.go:2937-2948 schemePort
/// The default port for a first-hop scheme. Empty for anything else —
/// `canonicalAddr` then produces a host with a trailing colon, which
/// is Go's behaviour and not an error here.
pub fn schemePort(scheme: string) -> string {
    if scheme == "http" {
        return string("80");
    }
    if scheme == "https" {
        return string("443");
    }
    if scheme == "socks5" || scheme == "socks5h" {
        return string("1080");
    }
    return string::new();
}

// go: sdk 1.25.5 net/http/transport.go:2950-2956 idnaASCIIFromURL
/// The URL's hostname in IDNA ASCII form, falling back to the raw
/// hostname when the conversion fails — Go discards the error here.
pub fn idnaASCIIFromURL(url: &URL) -> string {
    let addr = url.Hostname();
    let (v, err) = super::request::idnaASCII(addr.clone());
    if err.IsNil() {
        return v;
    }
    return addr;
}

// go: sdk 1.25.5 net/http/transport.go:2958-2965 canonicalAddr
/// Go: "canonicalAddr returns url.Host but always with a ':port'
/// suffix."
pub fn canonicalAddr(url: &URL) -> string {
    let mut port = url.Port();
    if port.Len() == 0 {
        port = schemePort(url.Scheme.clone());
    }
    return crate::net::JoinHostPort(idnaASCIIFromURL(url), port);
}

// ─── connectMethod ──────────────────────────────────────────────────

// goishlint:ignore GOISH019 connectMethod — Go's first field is
// `_ incomparable`, a zero-width marker that makes the struct
// uncomparable with ==. Rust structs are not comparable unless they
// derive it, so the marker has no counterpart and no purpose.
// go: sdk 1.25.5 net/http/transport.go:1994-2004 connectMethod
/// Go: "connectMethod is the map key (in its String form) for keeping
/// persistent TCP connections alive for subsequent HTTP requests."
///
/// Go's doc table of key shapes is the specification:
///
///     |http|foo.com                     http direct, no proxy
///     |https,h1|foo.com                 https direct, HTTP/2 disabled
///     http://proxy.com|https|foo.com    http proxy, then CONNECT
///     http://proxy.com|http             http proxy, http anywhere after
///     socks5://proxy.com|http|foo.com   socks5, then http
#[derive(Clone, Default)]
pub struct connectMethod {
    /// Go: "nil for no proxy, else full proxy URL"
    pub proxyURL: Option<Arc<URL>>,
    /// Go: `"http" or "https"`
    pub targetScheme: string,
    /// Go: "If proxyURL specifies an http or https proxy, and
    /// targetScheme is http (not https), then targetAddr is not
    /// included in the connect method key, because the socket can be
    /// reused for different targetAddr values."
    pub targetAddr: string,
    /// Go: "whether to disable HTTP/2 and force HTTP/1"
    pub onlyH1: bool,
}

impl connectMethod {
    // go: sdk 1.25.5 net/http/transport.go:2006-2021 connectMethod.key
    /// The pool key. The `targetAddr = ""` case is the load-bearing
    /// one: through an http/https proxy to an http target, ONE socket
    /// serves every destination, so the destination must not be part
    /// of the key. Getting that wrong either shares a socket that
    /// should not be shared (https/CONNECT) or refuses to share one
    /// that should be.
    pub fn key(&self) -> connectMethodKey {
        let mut proxyStr = string::new();
        let mut targetAddr = self.targetAddr.clone();
        if let Some(p) = self.proxyURL.as_ref() {
            proxyStr = p.String();
            if (p.Scheme == "http" || p.Scheme == "https") && self.targetScheme == "http" {
                targetAddr = string::new();
            }
        }
        return connectMethodKey {
            proxy: proxyStr,
            scheme: self.targetScheme.clone(),
            addr: targetAddr,
            onlyH1: self.onlyH1,
        };
    }

    // go: sdk 1.25.5 net/http/transport.go:2023-2029 connectMethod.scheme
    /// Go: "scheme returns the first hop scheme: http, https, or socks5"
    pub fn scheme(&self) -> string {
        if let Some(p) = self.proxyURL.as_ref() {
            return p.Scheme.clone();
        }
        return self.targetScheme.clone();
    }

    // go: sdk 1.25.5 net/http/transport.go:2031-2037 connectMethod.addr
    /// Go: "addr returns the first hop 'host:port' to which we need to
    /// TCP connect."
    pub fn addr(&self) -> string {
        if let Some(p) = self.proxyURL.as_ref() {
            return canonicalAddr(p);
        }
        return self.targetAddr.clone();
    }

    // go: sdk 1.25.5 net/http/transport.go:2039-2046 connectMethod.tlsHost
    /// Go: "tlsHost returns the host name to match against the peer's
    /// TLS certificate."
    pub fn tlsHost(&self) -> string {
        let h = self.targetAddr.clone();
        if super::http::hasPort(&h) {
            let b = h.as_bytes();
            if let Some(i) = b.iter().rposition(|&c| c == b':') {
                return string::from_bytes(&b[..i]);
            }
        }
        return h;
    }
}

// go: sdk 1.25.5 net/http/transport.go:2048-2054 connectMethodKey
/// Go: "connectMethodKey is the map key version of connectMethod, with
/// a stringified proxy URL (or the empty string) instead of a pointer
/// to a URL."
#[derive(Clone, Default, PartialEq, Eq, PartialOrd, Ord)]
pub struct connectMethodKey {
    pub proxy: string,
    pub scheme: string,
    pub addr: string,
    pub onlyH1: bool,
}

impl connectMethodKey {
    // go: sdk 1.25.5 net/http/transport.go:2056-2064 connectMethodKey.String
    /// Go's comment says "Only used by tests" — it is also what goish
    /// keys the idle map on, since goish has no struct-keyed map.
    pub fn String(&self) -> string {
        let h1 = if self.onlyH1 { ",h1" } else { "" };
        return crate::fmt::Sprintf!(
            "%s|%s%s|%s",
            self.proxy.clone(),
            self.scheme.clone(),
            string(h1),
            self.addr.clone()
        );
    }
}

// ─── wantConnQueue ──────────────────────────────────────────────────

// go: sdk 1.25.5 net/http/transport.go:1384-1398 wantConnQueue
/// Go: "a queue of wantConns", implemented as a head slice consumed
/// from `headPos` plus a tail slice, so pushes amortise and the front
/// pops without shifting.
///
/// The element type is a placeholder until `wantConn` lands with the
/// dial machinery; the QUEUE DISCIPLINE is what this slice ports, and
/// it is pure. `Waiter` stands in for the one method the queue calls
/// on its elements, so `cleanFrontNotWaiting` keeps Go's arity instead
/// of taking the predicate as an extra parameter.
// go: none — goish-only: Go calls `w.waiting()` on the concrete
// *wantConn. That type lands with the dial machinery; until then the
// queue is generic over anything that answers the same question.
pub trait Waiter {
    fn waiting(&self) -> bool;
}

#[derive(Default)]
pub struct wantConnQueue<T: Waiter> {
    /// Go: "This is a queue, not a deque. It is split into two stages
    /// - head[headPos:] and tail."
    head: Vec<Option<T>>,
    headPos: usize,
    tail: Vec<Option<T>>,
}

impl<T: Waiter> wantConnQueue<T> {
    // go: none — goish-only: Go zero-values wantConnQueue; Rust needs
    // an explicit constructor for the generic parameter.
    pub fn new() -> wantConnQueue<T> {
        return wantConnQueue {
            head: Vec::new(),
            headPos: 0,
            tail: Vec::new(),
        };
    }

    // go: sdk 1.25.5 net/http/transport.go:1401-1403 wantConnQueue.len
    pub fn len(&self) -> int {
        let n = self.head.len() - self.headPos + self.tail.len();
        return crate::int(crate::int64(n));
    }

    // go: sdk 1.25.5 net/http/transport.go:1406-1408 wantConnQueue.pushBack
    pub fn pushBack(&mut self, w: T) {
        self.tail.push(Some(w));
        return;
    }

    // go: sdk 1.25.5 net/http/transport.go:1411-1423 wantConnQueue.popFront
    /// Go swaps tail into head and reuses head's backing array as the
    /// new empty tail; the `head[headPos] = nil` clear is what stops
    /// the queue pinning a popped element.
    pub fn popFront(&mut self) -> Option<T> {
        if self.headPos >= self.head.len() {
            if self.tail.is_empty() {
                return None;
            }
            let mut newtail = core::mem::take(&mut self.head);
            newtail.clear();
            self.head = core::mem::replace(&mut self.tail, newtail);
            self.headPos = 0;
        }
        let w = self.head[self.headPos].take();
        self.headPos += 1;
        return w;
    }

    // go: sdk 1.25.5 net/http/transport.go:1426-1434 wantConnQueue.peekFront
    pub fn peekFront(&self) -> Option<&T> {
        if self.headPos < self.head.len() {
            return self.head[self.headPos].as_ref();
        }
        if !self.tail.is_empty() {
            return self.tail[0].as_ref();
        }
        return None;
    }

    // go: sdk 1.25.5 net/http/transport.go:1438-1447 wantConnQueue.cleanFrontNotWaiting
    /// Go: "pops any wantConns that are no longer waiting from the head
    /// of the queue, reporting whether any were popped." The predicate
    /// is `w.waiting()`, reached through the `Waiter` trait.
    pub fn cleanFrontNotWaiting(&mut self) -> bool {
        let mut cleaned = false;
        while let Some(w) = self.peekFront() {
            if w.waiting() {
                return cleaned;
            }
            self.popFront();
            cleaned = true;
        }
        return cleaned;
    }

    // go: sdk 1.25.5 net/http/transport.go:1462-1469 wantConnQueue.all
    /// Go: "iterates over all wantConns in the queue. The caller must
    /// not modify the queue while iterating."
    pub fn all<F: FnMut(&T)>(&self, mut f: F) {
        for w in self.head[self.headPos..].iter() {
            if let Some(w) = w.as_ref() {
                f(w);
            }
        }
        for w in self.tail.iter() {
            if let Some(w) = w.as_ref() {
                f(w);
            }
        }
        return;
    }
}

// ─── connLRU ────────────────────────────────────────────────────────

// goishlint:ignore GOISH019 connLRU — Go holds `ll *list.List` plus
// `m map[*persistConn]*list.Element`: an intrusive list with an index
// into it. goish has neither container/list nor pointer-keyed maps, so
// the pair collapses into one order-preserving Vec. Same three
// operations, same observable ordering.
// go: sdk 1.25.5 net/http/transport.go:3105-3108 connLRU
/// Go holds a `container/list` plus a map from *persistConn to its
/// element. goish has no intrusive list; a Vec in most-recent-first
/// order gives the same three operations (add front, remove oldest,
/// remove by identity) with the same observable ordering.
///
/// Element type is a placeholder until `persistConn` lands.
#[derive(Default)]
pub struct connLRU<T: PartialEq> {
    ll: Vec<T>,
}

impl<T: PartialEq> connLRU<T> {
    // go: none — goish-only: same reason as wantConnQueue::new.
    pub fn new() -> connLRU<T> {
        return connLRU { ll: Vec::new() };
    }

    // go: sdk 1.25.5 net/http/transport.go:3108-3121 connLRU.add
    /// Go panics if the conn is already present; so does this, because
    /// a double-add means the pool has lost track of a live socket.
    pub fn add(&mut self, pc: T) {
        if self.ll.iter().any(|x| *x == pc) {
            panic!("persistConn was already in LRU");
        }
        self.ll.insert(0, pc);
        return;
    }

    // go: sdk 1.25.5 net/http/transport.go:3123-3129 connLRU.removeOldest
    pub fn removeOldest(&mut self) -> Option<T> {
        return self.ll.pop();
    }

    // go: sdk 1.25.5 net/http/transport.go:3131-3137 connLRU.remove
    pub fn remove(&mut self, pc: &T) {
        self.ll.retain(|x| x != pc);
        return;
    }

    // go: sdk 1.25.5 net/http/transport.go:3139-3142 connLRU.len
    pub fn len(&self) -> int {
        return crate::int(crate::int64(self.ll.len()));
    }
}

// ─── registered protocols ───────────────────────────────────────────

impl Transport {
    // go: sdk 1.25.5 net/http/transport.go:541-552 Transport.useRegisteredProtocol
    /// Go: "reports whether an alternate protocol (as registered with
    /// Transport.RegisterProtocol) should be respected for this
    /// request."
    pub fn useRegisteredProtocol(&self, req: &Request) -> bool {
        if req.URL.Scheme == "https" && req.requiresHTTP1() {
            // Go: "If this request requires HTTP/1, don't use the
            // 'https' alternate protocol, which is used by the HTTP/2
            // code to take over requests if there's an existing cached
            // HTTP/2 connection."
            return false;
        }
        return true;
    }

    // go: sdk 1.25.5 net/http/transport.go:557-563 Transport.alternateRoundTripper
    /// Go: "returns the alternate RoundTripper to use for this request
    /// if the Request's URL scheme requires one, or nil for the normal
    /// case of using the Transport."
    pub fn alternateRoundTripper(&self, req: &Request) -> Option<Arc<dyn RoundTripper>> {
        if !self.useRegisteredProtocol(req) {
            return None;
        }
        let m = self.__alt_proto.Lock();
        return m.Get(req.URL.Scheme.clone()).0;
    }

    // go: sdk 1.25.5 net/http/transport.go:868-881 Transport.RegisterProtocol
    /// Go: "RegisterProtocol registers a new protocol with scheme. The
    /// Transport will pass requests using the given scheme to rt. […]
    /// It is a run-time error to register the same scheme twice."
    ///
    /// This is what makes `NewFileTransport` reachable the way Go's own
    /// doc example shows: `t.RegisterProtocol("file", …)`.
    pub fn RegisterProtocol(&self, scheme: string, rt: Arc<dyn RoundTripper>) {
        let mut m = self.__alt_proto.Lock();
        if m.Get(scheme.clone()).1 {
            panic!("protocol already registered");
        }
        m.Set(scheme, Some(rt));
        return;
    }
}

// go: none — goish-only: silences an unused-import warning for the
// slice type, which the rest of transport.go's port will use.
#[allow(dead_code)]
fn __unused() -> slice<string> {
    return slice::<string>::new();
}
