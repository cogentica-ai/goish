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

use crate::errors::{self, error};
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

// ─── wantConn ───────────────────────────────────────────────────────

// go: sdk 1.25.5 net/http/transport.go:1317-1321 connOrError
/// The value a waiter receives: exactly one of `pc` and `err` is set,
/// which `tryDeliver` enforces with a panic.
pub struct connOrError {
    pub pc: Option<Arc<persistConn>>,
    pub err: error,
    pub idleAt: crate::time::Time,
}

// goishlint:ignore GOISH019 wantConn — Go's wantConn carries
// `ctx context.Context` and `result chan connOrError` alongside the
// mutex-guarded `done`. The channel is the delivery half, which
// belongs with getConn/queueForIdleConn and is not ported yet; what
// lands here is the STATE machine those two coordinate through.
// go: sdk 1.25.5 net/http/transport.go:1300-1315 wantConn
/// Go: "A wantConn records state about a wanted connection (that is, a
/// connection that's not yet delivered)."
pub struct wantConn {
    state: crate::sync::Mutex<wantConnState>,
}

// go: none — goish-only: the payload of Go's `mu sync.Mutex` on
// wantConn, i.e. `done` plus the delivered result.
struct wantConnState {
    /// Go: `key connectMethodKey` — which pool bucket this waiter
    /// wants a conn from.
    key: connectMethodKey,
    done: bool,
    delivered: Option<Arc<persistConn>>,
    /// Go carries this in the delivered `connOrError`; goish keeps it
    /// beside the conn until the `result` channel lands with getConn.
    idleAt: crate::time::Time,
}

impl wantConn {
    // go: none — goish-only: Go zero-values wantConn in queueForIdleConn.
    pub fn __new() -> wantConn {
        return wantConn {
            state: crate::sync::Mutex::new(wantConnState {
                key: connectMethodKey::default(),
                done: false,
                delivered: None,
                idleAt: crate::time::Time::default(),
            }),
        };
    }

    // go: none — goish-only: set the pool bucket this waiter wants.
    // Go assigns `w.key` at the getConn call site.
    pub fn __set_key(&self, k: connectMethodKey) {
        self.state.Lock().key = k;
        return;
    }

    // go: none — goish-only: read `w.key` while the idle pool lock is
    // already held, so queueForIdleConn does not re-enter it.
    #[allow(dead_code)]
    pub fn __cache_key_for(&self, _pool: &idlePool) -> string {
        return self.state.Lock().key.String();
    }

    // go: sdk 1.25.5 net/http/transport.go:1323-1329 wantConn.waiting
    /// Go: "waiting reports whether w is still waiting for an answer
    /// (connection or error)."
    pub fn waiting(&self) -> bool {
        return !self.state.Lock().done;
    }

    // go: sdk 1.25.5 net/http/transport.go:1339-1357 wantConn.tryDeliver
    /// Go: "tryDeliver attempts to deliver pc, err to w and reports
    /// whether it succeeded."
    ///
    /// The `(pc == nil) == (err == nil)` panic is Go's, and it is a
    /// real invariant rather than a debug aid: a delivery with both
    /// set would leak the conn (the waiter takes the error path and
    /// nobody returns it to the pool), and one with neither would hang
    /// the waiter.
    ///
    /// Idempotent by design — a second delivery returns false, which
    /// is what lets several dials race for one waiter.
    pub fn tryDeliver(
        &self,
        pc: Option<Arc<persistConn>>,
        err: error,
        idleAt: crate::time::Time,
    ) -> bool {
        let mut st = self.state.Lock();
        if st.done {
            return false;
        }
        if pc.is_none() == err.IsNil() {
            panic!("net/http: internal error: misuse of tryDeliver");
        }
        st.done = true;
        st.idleAt = idleAt;
        st.delivered = pc;
        return true;
    }

    // go: sdk 1.25.5 net/http/transport.go:1359-1381 wantConn.cancel
    /// Go: "cancel marks w as no longer wanting a result (for example,
    /// due to cancellation). If a connection has been delivered
    /// already, cancel returns it with t.putOrCloseIdleConn."
    ///
    /// That hand-back is the point: cancelling AFTER a dial completed
    /// must not drop the connection on the floor.
    pub fn cancel(&self, t: &Transport) {
        let pc = {
            let mut st = self.state.Lock();
            let pc = if st.done { st.delivered.take() } else { None };
            st.done = true;
            pc
        };
        if let Some(pc) = pc {
            t.putOrCloseIdleConn(&pc);
        }
        return;
    }

    // go: none — goish-only: Go's waiter reads its result off the
    // `result` channel. That channel arrives with getConn; until then
    // the delivered conn is read directly.
    pub fn __delivered(&self) -> Option<Arc<persistConn>> {
        return self.state.Lock().delivered.clone();
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
/// it is pure. `Waiter` is the one method the queue calls on its
/// elements, so `cleanFrontNotWaiting` keeps Go's arity instead of
/// taking the predicate as an extra parameter.
// go: none — goish-only: Go's queue holds `*wantConn` concretely.
// goish keeps it generic over `Waiter` so the queue stays testable
// without the dial machinery; `wantConn` above is the real
// implementation and the only one in the tree.
pub trait Waiter {
    fn waiting(&self) -> bool;
}

impl Waiter for Arc<wantConn> {
    // go: none — goish-only: forwards to wantConn.waiting so the
    // queue's generic bound is satisfied by the real type.
    fn waiting(&self) -> bool {
        return wantConn::waiting(self);
    }
}

// Go's map holds wantConnQueue BY VALUE — its own comment says "q is
// a value (like a slice), so we have to store the updated q back into
// the map". Clone + Default give goish the same get-modify-put shape.
#[derive(Clone)]
pub struct wantConnQueue<T: Waiter + Clone> {
    /// Go: "This is a queue, not a deque. It is split into two stages
    /// - head[headPos:] and tail."
    head: Vec<Option<T>>,
    headPos: usize,
    tail: Vec<Option<T>>,
}

// go: none — goish-only: a derived Default would demand `T: Default`,
// which `Arc<wantConn>` cannot satisfy. Go's zero queue is just two
// empty slices, so write it by hand.
impl<T: Waiter + Clone> Default for wantConnQueue<T> {
    // go: none — see the note above.
    fn default() -> wantConnQueue<T> {
        return wantConnQueue::new();
    }
}

impl<T: Waiter + Clone> wantConnQueue<T> {
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

// go: sdk 1.25.5 net/http/transport.go:50 DefaultMaxIdleConnsPerHost
/// Go: "DefaultMaxIdleConnsPerHost is the default value of
/// Transport's MaxIdleConnsPerHost."
pub const DefaultMaxIdleConnsPerHost: int = 2;

// go: sdk 1.25.5 net/http/transport.go:2444-2452 is408Message
/// Go: whether `buf` starts an `HTTP/1.x 408` status line. Used to
/// tell a real 408 from a connection the server closed, so a request
/// is retried rather than surfaced as an error.
///
/// The offsets are Go's and are not obvious: bytes 0..7 must be
/// `"HTTP/1."` — byte 7 (the minor version) is skipped — and bytes
/// 8..12 must be `" 408"`.
pub fn is408Message(buf: &slice<crate::types::byte>) -> bool {
    if buf.Len() < 12 {
        return false;
    }
    let b: &[u8] = buf;
    if &b[..7] != b"HTTP/1." {
        return false;
    }
    return &b[8..12] == b" 408";
}

// go: sdk 1.25.5 net/http/transport.go:503-509 ProxyURL
/// Go: "ProxyURL returns a proxy function (for use in a Transport)
/// that always returns the same URL."
pub fn ProxyURL(
    fixedURL: URL,
) -> Arc<dyn Fn(&Request) -> (URL, error) + Send + Sync> {
    return Arc::new(move |_r: &Request| -> (URL, error) {
        return (fixedURL.clone(), errors::nil);
    });
}

// go: sdk 1.25.5 net/http/transport.go:565-579 validateHeaders
/// Returns a description of the FIRST invalid header, or "" when all
/// are well-formed. Go deliberately omits the offending VALUE from the
/// message — "it may be sensitive" — and this port keeps that.
pub fn validateHeaders(hdrs: &super::header::Header) -> string {
    for (k, vv) in crate::range!(hdrs) {
        if !super::http::isToken(k) {
            return crate::fmt::Sprintf!("field name %q", k.clone());
        }
        for i in 0..vv.Len() {
            if !super::http::ValidHeaderFieldValue(&vv[i]) {
                // Go: "Don't include the value in the error, because
                // it may be sensitive."
                return crate::fmt::Sprintf!("field value for %q", k.clone());
            }
        }
    }
    return string::new();
}

impl connectMethod {
    // go: sdk 1.25.5 net/http/transport.go:986-996 connectMethod.proxyAuth
    /// Go: "proxyAuth returns the Proxy-Authorization header to set on
    /// requests, if applicable."
    ///
    /// Always empty in goish today: `url::URL` has no `User` field —
    /// Parse discards userinfo — so a proxy URL can never carry
    /// credentials. Ported under its Go name so the rule lands in one
    /// place when URL.User arrives; see the note on refererForURL.
    pub fn proxyAuth(&self) -> string {
        if self.proxyURL.is_none() {
            return string::new();
        }
        return string::new();
    }
}

// ─── error sentinels ────────────────────────────────────────────────

crate::var! {
    // go: sdk 1.25.5 net/http/transport.go:999-1015 errKeepAlivesDisabled
    pub errKeepAlivesDisabled: error = "http: putIdleConn: keep alives disabled";
    // go: sdk 1.25.5 net/http/transport.go:999-1015 errConnBroken
    pub errConnBroken: error = "http: putIdleConn: connection is in bad state";
    // go: sdk 1.25.5 net/http/transport.go:999-1015 errCloseIdle
    pub errCloseIdle: error = "http: putIdleConn: CloseIdleConnections was called";
    // go: sdk 1.25.5 net/http/transport.go:999-1015 errTooManyIdle
    pub errTooManyIdle: error = "http: putIdleConn: too many idle connections";
    // go: sdk 1.25.5 net/http/transport.go:999-1015 errTooManyIdleHost
    pub errTooManyIdleHost: error = "http: putIdleConn: too many idle connections for host";
    // go: sdk 1.25.5 net/http/transport.go:999-1015 errCloseIdleConns
    pub errCloseIdleConns: error = "http: CloseIdleConnections called";
    // go: sdk 1.25.5 net/http/transport.go:999-1015 errReadLoopExiting
    pub errReadLoopExiting: error = "http: persistConn.readLoop exiting";
    // go: sdk 1.25.5 net/http/transport.go:999-1015 errIdleConnTimeout
    pub errIdleConnTimeout: error = "http: idle connection timeout";
    // go: sdk 1.25.5 net/http/transport.go:999-1015 errServerClosedIdle
    //
    // Go: "not seen by users for idempotent requests, but may be seen
    // by a user if the server shuts down an idle connection and sends
    // its FIN in flight with already-written POST body bytes from the
    // client." (golang/go#19943)
    pub errServerClosedIdle: error = "http: server closed idle connection";
    // go: sdk 1.25.5 net/http/transport.go:751 errCannotRewind
    pub errCannotRewind: error = "net/http: cannot rewind body after connection loss";
    // go: sdk 1.25.5 net/http/transport.go:2729 errRequestCanceled
    pub errRequestCanceled: error = "net/http: request canceled";
}

// go: sdk 1.25.5 net/http/transport.go:2589-2591 nothingWrittenError
// Go: "nothingWrittenError wraps a write errors which ended up
// writing zero bytes." Whether a retry is safe hinges on this: if
// nothing reached the wire, re-sending cannot duplicate a side
// effect. A sentinel because goish has no errors::As.
crate::var! {
    pub errNothingWritten: error = "http: nothing written";
}

// go: sdk 1.25.5 net/http/transport.go:1024-1026 transportReadFromServerError
// Go: "used by Transport.readLoop when the 1 byte peek read fails and
// we're actually anticipating a response. Usually this is just due to
// the inherent keep-alive shut down race."
crate::var! {
    pub errTransportReadFromServer: error = "http: transport read from server";
}

// ─── persistConn ────────────────────────────────────────────────────

// goishlint:ignore GOISH019 persistConn — Go's persistConn carries 24
// fields, most of them the goroutine machinery this slice deliberately
// stops short of: closech/writech/reqch channels, the bufio pair, the
// idleTimer, sawEOF/readLimit. What lands here is the STATE the pure
// methods below read, behind one Mutex because goish has no
// `mu sync.Mutex` + bare fields idiom.
// go: sdk 1.25.5 net/http/transport.go:2068-2109 persistConn
/// Go: "persistConn wraps a connection, usually a persistent one (but
/// may be used for non-keep-alive requests as well)."
///
/// Staged: the fields the connection POOL needs to reason about a
/// connection — is it reused, is it broken, why was it closed — with
/// the transport goroutines still to come. Nothing constructs one yet.
pub struct persistConn {
    /// Go: `cacheKey connectMethodKey` — which pool bucket this is in.
    pub cacheKey: connectMethodKey,
    state: crate::sync::Mutex<pcState>,
}

// go: none — goish-only: the payload of Go's `mu sync.Mutex`, i.e. the
// persistConn fields its comment marks as "guarded by mu".
struct pcState {
    /// Go: "whether conn has been used for a request/response"
    reused: bool,
    /// Go: "an error to which writes/reads should fail"
    broken: bool,
    /// Go: "set non-nil when conn is closed, before closech is closed"
    closed: error,
    /// Go: "set non-nil if the connection was closed due to
    /// CancelRequest or due to context cancellation"
    canceledErr: error,
    /// Go: `idleAt time.Time` — when this conn entered the idle pool.
    /// goish stores CLOCK_MONOTONIC ns; 0 means "never idled".
    idleAt: i64,
}

// go: none — goish-only. Go's pool compares `*persistConn` values,
// i.e. POINTER identity — `v != pconn` in removeIdleConnLocked and
// `exist == pconn` in tryPutIdleConn are both address comparisons, not
// field comparisons. Two distinct conns to the same host must NOT
// compare equal, so this is `ptr::eq` and nothing else.
impl PartialEq for persistConn {
    // go: none — see the note above: Go compares *persistConn by
    // address, so this is ptr::eq.
    fn eq(&self, other: &persistConn) -> bool {
        return core::ptr::eq(self, other);
    }
}

impl persistConn {
    // go: none — goish-only: Go zero-values persistConn inside
    // dialConn; that function is not ported yet, so the pool-facing
    // state needs an explicit constructor to be testable.
    pub fn __new(cacheKey: connectMethodKey) -> persistConn {
        return persistConn {
            cacheKey,
            state: crate::sync::Mutex::new(pcState {
                reused: false,
                broken: false,
                closed: errors::nil,
                canceledErr: errors::nil,
                idleAt: 0,
            }),
        };
    }

    // go: sdk 1.25.5 net/http/transport.go:2134-2139 persistConn.isBroken
    pub fn isBroken(&self) -> bool {
        return !self.state.Lock().closed.IsNil();
    }

    // go: none — goish-only: read/stamp Go's `idleAt` field.
    pub fn __idle_at(&self) -> i64 {
        return self.state.Lock().idleAt;
    }

    // go: none — see the note above.
    pub fn __set_idle_at(&self, ns: i64) {
        self.state.Lock().idleAt = ns;
        return;
    }

    // go: sdk 1.25.5 net/http/transport.go:2141-2147 persistConn.canceled
    /// Go: "canceled returns non-nil if the connection was closed due
    /// to CancelRequest or due to context cancellation."
    pub fn canceled(&self) -> error {
        return self.state.Lock().canceledErr.clone();
    }

    // go: sdk 1.25.5 net/http/transport.go:2150-2155 persistConn.isReused
    /// Whether this conn has already carried a request/response. This
    /// is the flag `shouldRetryRequest` turns on: a FRESH conn never
    /// retries.
    pub fn isReused(&self) -> bool {
        return self.state.Lock().reused;
    }

    // go: sdk 1.25.5 net/http/transport.go:2898-2903 persistConn.markReused
    /// Go: "marks this connection as having been successfully used for
    /// a request and response."
    pub fn markReused(&self) {
        self.state.Lock().reused = true;
        return;
    }

    // go: sdk 1.25.5 net/http/transport.go:2911-2915 persistConn.close
    /// Go: "The provided err is only for testing and debugging; in
    /// normal circumstances it should never be seen by users."
    pub fn close(&self, err: error) {
        self.closeLocked(err);
        return;
    }

    // go: sdk 1.25.5 net/http/transport.go:2917-2935 persistConn.closeLocked
    /// Go PANICS on a nil error, and this port keeps that: a
    /// close-without-reason means the caller lost track of why, and
    /// `closed` doubles as the is-broken flag, so nil would silently
    /// leave the conn readable.
    ///
    /// Only the FIRST close records its reason — Go guards on
    /// `pc.closed == nil` — so a later close cannot overwrite the
    /// error that actually explains the failure.
    pub fn closeLocked(&self, err: error) {
        if err.IsNil() {
            panic!("nil error");
        }
        let mut st = self.state.Lock();
        st.broken = true;
        if st.closed.IsNil() {
            st.closed = err;
        }
        return;
    }

    // go: none — goish-only: Go reads `pc.closed` directly under
    // `pc.mu` from inside the package. goish's field is behind the
    // state Mutex, so the read needs a name.
    pub fn __closed_err(&self) -> error {
        return self.state.Lock().closed.clone();
    }

    // go: sdk 1.25.5 net/http/transport.go:2157-2162 persistConn.cancelRequest
    pub fn cancelRequest(&self, err: error) {
        self.state.Lock().canceledErr = err;
        self.closeLocked(errRequestCanceled.into());
        return;
    }

    // go: sdk 1.25.5 net/http/transport.go:2111-2116 persistConn.maxHeaderResponseSize
    /// Go's default is 10 MiB — "conservative default; same as http2".
    /// The test is `!= 0`, like maxIdleConnsPerHost, so a negative
    /// MaxResponseHeaderBytes passes through rather than falling back.
    pub fn maxHeaderResponseSize(t: &Transport) -> i64 {
        let v = t.MaxResponseHeaderBytes;
        if v != 0 {
            return v;
        }
        return 10 << 20;
    }
}

// go: sdk 1.25.5 net/http/transport.go:3080-3080 fakeLocker
/// Go: "fakeLocker is a sync.Locker which does nothing. It's used to
/// guard test-only fields when not under test, to avoid runtime
/// atomic overhead."
pub struct fakeLocker;

impl fakeLocker {
    // go: sdk 1.25.5 net/http/transport.go:3082 fakeLocker.Lock
    pub fn Lock(&self) {
        return;
    }
    // go: sdk 1.25.5 net/http/transport.go:3083 fakeLocker.Unlock
    pub fn Unlock(&self) {
        return;
    }
}

// go: sdk 1.25.5 net/http/transport.go:3098-3103 cloneTLSConfig
/// Go: "returns a shallow clone of cfg, or a new zero tls.Config if
/// cfg is nil. This is safe to call even if cfg is in active use by a
/// TLS client or server."
///
/// goish's `Transport.TLSClientConfig` is a VALUE, not a pointer, so
/// there is no nil case to handle — the clone is the whole job.
pub fn cloneTLSConfig(cfg: &crate::crypto::tls::Config) -> crate::crypto::tls::Config {
    return cfg.clone();
}

// ─── the per-host connection limiter ────────────────────────────────

// go: none — goish-only: the payload of Go's `connsPerHostMu`, i.e.
// the two Transport fields it guards (transport.go:278-281). Keyed by
// `connectMethodKey.String()` for the same reason the idle pool is.
pub struct connsPerHost {
    /// Go: `connsPerHost map[connectMethodKey]int`
    pub counts: crate::gomap::map<string, int>,
    /// Go: `connsPerHostWait map[connectMethodKey]wantConnQueue`
    pub wait: crate::gomap::map<string, wantConnQueue<Arc<wantConn>>>,
}

impl connsPerHost {
    // go: none — goish-only constructor; Go zero-values both maps.
    pub fn new() -> connsPerHost {
        return connsPerHost {
            counts: crate::gomap::map::<string, int>::new(),
            wait: crate::gomap::map::<string, wantConnQueue<Arc<wantConn>>>::new(),
        };
    }
}

impl Transport {
    // go: sdk 1.25.5 net/http/transport.go:1633-1680 Transport.decConnsPerHost
    /// Give a per-host connection slot back. Go's comment on the
    /// underflow is worth keeping verbatim: "Shouldn't happen, but if
    /// it does, the counting is buggy and could easily lead to a
    /// silent DEADLOCK, so report the problem loudly." Hence a panic
    /// rather than a saturating decrement.
    ///
    /// The slot is handed to a still-waiting dialer if there is one,
    /// rather than decremented — Go: "Some goroutines on the wait list
    /// may have timed out or gotten a connection another way. If
    /// they're all gone, we don't want to kick off any spurious dial
    /// operations." Skipping the hand-off and always decrementing is
    /// not equivalent: a waiter would sit there while the count says
    /// a slot is free.
    ///
    /// Staged: `startDialConnForLocked` is not ported, so the handed-off
    /// waiter is delivered nothing yet — `__dec_conns_per_host_handoff`
    /// reports which waiter WOULD have been started, and the tests
    /// assert on that.
    pub fn decConnsPerHost(&self, key: &connectMethodKey) -> Option<Arc<wantConn>> {
        if self.MaxConnsPerHost <= 0 {
            return None;
        }
        let mut cph = self.__conns_per_host.Lock();
        let k = key.String();
        let n = cph.counts.Get(k.clone()).0;
        if n == 0 {
            panic!("net/http: internal error: connCount underflow");
        }

        // Go: "Can we hand this count to a goroutine still waiting to
        // dial?"
        let mut handed: Option<Arc<wantConn>> = None;
        if cph.wait.Get(k.clone()).1 {
            let mut q = cph.wait.Get(k.clone()).0;
            if q.len() > 0 {
                while q.len() > 0 {
                    match q.popFront() {
                        None => {
                            break;
                        }
                        Some(w) => {
                            if w.waiting() {
                                handed = Some(w);
                                break;
                            }
                        }
                    }
                }
                if q.len() == 0 {
                    cph.wait.Delete(k.clone());
                } else {
                    // Go: "q is a value (like a slice), so we have to
                    // store the updated q back into the map."
                    cph.wait.Set(k.clone(), q);
                }
                if handed.is_some() {
                    return handed;
                }
            }
        }

        // Go: "Otherwise, decrement the recorded count."
        let n = n - 1;
        if n == 0 {
            cph.counts.Delete(k);
        } else {
            cph.counts.Set(k, n);
        }
        return None;
    }

    // go: none — goish-only: the count half of Go's queueForDial
    // (transport.go:1571-1583), split out because the dial half needs
    // startDialConnForLocked. Returns whether a slot was taken; false
    // means the caller must queue.
    pub fn __take_conn_slot(&self, key: &connectMethodKey) -> bool {
        if self.MaxConnsPerHost <= 0 {
            return true;
        }
        let mut cph = self.__conns_per_host.Lock();
        let k = key.String();
        let n = cph.counts.Get(k.clone()).0;
        if n < self.MaxConnsPerHost {
            cph.counts.Set(k, n + 1);
            return true;
        }
        return false;
    }

    // go: none — goish-only: the queue half of the same Go function
    // (transport.go:1585-1591).
    pub fn __queue_for_slot(&self, key: &connectMethodKey, w: Arc<wantConn>) {
        let mut cph = self.__conns_per_host.Lock();
        let k = key.String();
        let mut q = cph.wait.Get(k.clone()).0;
        q.cleanFrontNotWaiting();
        q.pushBack(w);
        cph.wait.Set(k, q);
        return;
    }
}

// ─── the idle pool ──────────────────────────────────────────────────

// go: none — goish-only: the payload of Go's `idleMu sync.Mutex`, i.e.
// the four Transport fields its comment groups under it
// (transport.go:270-276). Go can key `idleConn` by the
// connectMethodKey STRUCT; goish has no struct-keyed map, so the key
// is `connectMethodKey.String()` — which is exactly what Go's own
// doc-comment table describes, and what its String() exists for.
pub struct idlePool {
    pub idleConn: crate::gomap::map<string, Vec<Arc<persistConn>>>,
    pub idleLRU: connLRU<Arc<persistConn>>,
    /// Go: "user has requested to close all idle conns"
    pub closeIdle: bool,
    /// Go: `idleConnWait map[connectMethodKey]wantConnQueue` —
    /// waiters registered for the NEXT conn that becomes idle.
    pub idleConnWait: crate::gomap::map<string, wantConnQueue<Arc<wantConn>>>,
}

impl idlePool {
    // go: none — goish-only constructor; Go zero-values the fields.
    pub fn new() -> idlePool {
        return idlePool {
            idleConn: crate::gomap::map::<string, Vec<Arc<persistConn>>>::new(),
            idleLRU: connLRU::new(),
            closeIdle: false,
            idleConnWait: crate::gomap::map::<string, wantConnQueue<Arc<wantConn>>>::new(),
        };
    }
}

impl Transport {
    // go: sdk 1.25.5 net/http/transport.go:1052-1143 Transport.tryPutIdleConn
    /// Go: "adds pconn to the list of idle persistent connections
    /// awaiting a new request. If pconn is no longer needed or not in
    /// a good state, tryPutIdleConn returns an error explaining why it
    /// wasn't registered."
    ///
    /// Every rejection is a NAMED error, and that is the point: a
    /// silent `return` here leaks the connection instead of closing
    /// it, because `putOrCloseIdleConn` closes exactly when this
    /// returns non-nil.
    ///
    /// Staged: Go's HTTP/2 `pconn.alt` branch and the IdleConnTimeout
    /// timer are not ported — both need machinery that is not here.
    pub fn tryPutIdleConn(&self, pconn: &Arc<persistConn>) -> error {
        if self.DisableKeepAlives || self.maxIdleConnsPerHost() < 0 {
            return errKeepAlivesDisabled.into();
        }
        if pconn.isBroken() {
            return errConnBroken.into();
        }
        pconn.markReused();

        let mut pool = self.__idle.Lock();
        if pool.closeIdle {
            return errCloseIdle.into();
        }
        let key = pconn.cacheKey.String();
        let idles = pool.idleConn.Get(key.clone()).0;
        if crate::int(crate::int64(idles.len())) >= self.maxIdleConnsPerHost() {
            return errTooManyIdleHost.into();
        }
        for exist in idles.iter() {
            if Arc::ptr_eq(exist, pconn) {
                // Go: log.Fatalf("dup idle pconn %p in freelist").
                panic!("dup idle pconn in freelist");
            }
        }
        let mut idles = idles;
        idles.push(pconn.clone());
        pool.idleConn.Set(key, idles);
        pool.idleLRU.add(pconn.clone());
        if self.MaxIdleConns != 0 && pool.idleLRU.len() > self.MaxIdleConns {
            if let Some(oldest) = pool.idleLRU.removeOldest() {
                oldest.close(errTooManyIdle.into());
                __removeIdleConnLocked(&mut pool, &oldest);
            }
        }
        return errors::nil;
    }

    // go: sdk 1.25.5 net/http/transport.go:1148-1231 Transport.queueForIdleConn
    /// Try to satisfy `w` from the idle pool; if nothing suitable is
    /// there, register it for the next conn that becomes idle.
    /// Reports whether a connection was delivered.
    ///
    /// I had claimed this was untestable until Client.Do is rewired.
    /// It is not: it is pool lookup plus delivery over structures
    /// already ported, and every branch below is observable.
    ///
    /// Three details that are not obvious:
    ///
    ///   - it scans from the END of the list, i.e. MOST recently used
    ///     first, so a warm conn is preferred over a cold one;
    ///   - a broken or too-old conn is SKIPPED and popped, and the
    ///     scan continues — Go's readLoop may have marked it broken
    ///     before removeIdleConn got to it;
    ///   - it clears `closeIdle`, undoing CloseIdleConnections, "we
    ///     might want one".
    ///
    /// Staged: Go launches `pconn.closeConnIfStillIdle()` on a
    /// goroutine for the too-old case, and has an `alt` branch that
    /// leaves an HTTP/2 conn in the list. Neither exists yet; a
    /// too-old conn is dropped from the list here and closed by the
    /// caller that owns it.
    pub fn queueForIdleConn(&self, w: &Arc<wantConn>) -> bool {
        if self.DisableKeepAlives {
            return false;
        }
        let mut pool = self.__idle.Lock();
        // Go: "Stop closing connections that become idle - we might
        // want one. (That is, undo the effect of
        // t.CloseIdleConnections.)"
        pool.closeIdle = false;

        // Go: "If IdleConnTimeout is set, calculate the oldest
        // persistConn.idleAt time we're willing to use."
        let old_ns: i64 = if self.IdleConnTimeout > crate::time::Duration(0) {
            crate::runtime::sysmon::monotonic_ns()
                .wrapping_sub(self.IdleConnTimeout.Nanoseconds())
        } else {
            0
        };

        let k = w.__cache_key_for(&pool);
        if pool.idleConn.Get(k.clone()).1 {
            let mut list = pool.idleConn.Get(k.clone()).0;
            let mut delivered = false;
            // Go: "Look for most recently-used idle connection."
            while !list.is_empty() {
                let pconn = list[list.len() - 1].clone();
                let tooOld = old_ns != 0 && pconn.__idle_at() != 0 && pconn.__idle_at() < old_ns;
                if pconn.isBroken() || tooOld {
                    // Go: "If either persistConn.readLoop has marked
                    // the connection broken, but
                    // Transport.removeIdleConn has not yet removed it
                    // from the idle list, or if this persistConn is
                    // too old […] then ignore it and look for
                    // another."
                    list.pop();
                    pool.idleLRU.remove(&pconn);
                    continue;
                }
                delivered = w.tryDeliver(Some(pconn.clone()), errors::nil, crate::time::Time::default());
                if delivered {
                    // Go: "HTTP/1: only one client can use pconn.
                    // Remove it from the list."
                    pool.idleLRU.remove(&pconn);
                    list.pop();
                }
                break;
            }
            if !list.is_empty() {
                pool.idleConn.Set(k.clone(), list);
            } else {
                pool.idleConn.Delete(k.clone());
            }
            if delivered {
                return true;
            }
        }

        // Go: "Register to receive next connection that becomes idle."
        let mut q = pool.idleConnWait.Get(k.clone()).0;
        q.cleanFrontNotWaiting();
        q.pushBack(w.clone());
        pool.idleConnWait.Set(k, q);
        return false;
    }

    // go: sdk 1.25.5 net/http/transport.go:1034-1038 Transport.putOrCloseIdleConn
    /// The only correct way to hand a finished conn back: if the pool
    /// refuses it, it is CLOSED rather than dropped.
    pub fn putOrCloseIdleConn(&self, pconn: &Arc<persistConn>) {
        let err = self.tryPutIdleConn(pconn);
        if !err.IsNil() {
            pconn.close(err);
        }
        return;
    }

    // go: sdk 1.25.5 net/http/transport.go:1242-1273 Transport.removeIdleConnLocked
    /// Go: "removes pconn from the idle list." Returns whether it was
    /// found there.
    pub fn removeIdleConnLocked(&self, pconn: &Arc<persistConn>) -> bool {
        let mut pool = self.__idle.Lock();
        return __removeIdleConnLocked(&mut pool, pconn);
    }

    // go: sdk 1.25.5 net/http/transport.go:329-373 Transport.Clone
    /// Go: "Clone returns a deep copy of t's exported fields."
    ///
    /// PARTIAL, and the omissions are Go fields goish's Transport does
    /// not have — OnProxyConnectResponse, Dial/DialTLS(Context),
    /// ResponseHeaderTimeout, ProxyConnectHeader,
    /// GetProxyConnectHeader, ForceAttemptHTTP2, HTTP2, Protocols,
    /// TLSNextProto. Every field that DOES exist is copied.
    ///
    /// Deep in the sense that matters: the clone gets a FRESH idle
    /// pool and its own registered-protocol map, so a mutation on one
    /// Transport cannot reach the other.
    pub fn Clone(&self) -> Transport {
        let mut t2 = Transport::default();
        t2.Proxy = self.Proxy.clone();
        t2.DialContext = self.DialContext.clone();
        t2.TLSHandshakeTimeout = self.TLSHandshakeTimeout;
        t2.DisableKeepAlives = self.DisableKeepAlives;
        t2.DisableCompression = self.DisableCompression;
        t2.MaxIdleConns = self.MaxIdleConns;
        t2.MaxIdleConnsPerHost = self.MaxIdleConnsPerHost;
        t2.MaxConnsPerHost = self.MaxConnsPerHost;
        t2.IdleConnTimeout = self.IdleConnTimeout;
        t2.ExpectContinueTimeout = self.ExpectContinueTimeout;
        t2.MaxResponseHeaderBytes = self.MaxResponseHeaderBytes;
        t2.WriteBufferSize = self.WriteBufferSize;
        t2.ReadBufferSize = self.ReadBufferSize;
        t2.Timeout = self.Timeout;
        // Go: `t2.TLSClientConfig = t.TLSClientConfig.Clone()`.
        t2.TLSClientConfig = cloneTLSConfig(&self.TLSClientConfig);
        // Go clones TLSNextProto with maps.Clone. The goish analogue is
        // the registered-protocol map, which must NOT be shared or a
        // RegisterProtocol on the clone would mutate the original.
        {
            let src = self.__alt_proto.Lock();
            let mut dst = t2.__alt_proto.Lock();
            for (k, v) in crate::range!(&*src) {
                dst.Set(k.clone(), v.clone());
            }
        }
        return t2;
    }

    // go: sdk 1.25.5 net/http/transport.go:887-910 Transport.CloseIdleConnections
    /// Go: "closes any connections which were previously connected
    /// from previous requests but are now sitting idle in a
    /// \"keep-alive\" state. It does not interrupt any connections
    /// currently in use."
    ///
    /// `closeIdle` stays set, so conns finishing AFTER this call are
    /// closed rather than pooled — Go's comment: "close newly idle
    /// connections".
    pub fn CloseIdleConnections(&self) {
        let conns: Vec<Arc<persistConn>> = {
            let mut pool = self.__idle.Lock();
            let mut all: Vec<Arc<persistConn>> = Vec::new();
            for (_, v) in crate::range!(&pool.idleConn) {
                for pc in v.iter() {
                    all.push(pc.clone());
                }
            }
            pool.idleConn = crate::gomap::map::<string, Vec<Arc<persistConn>>>::new();
            pool.closeIdle = true;
            pool.idleLRU = connLRU::new();
            all
        };
        for pc in conns.iter() {
            pc.close(errCloseIdleConns.into());
        }
        return;
    }
}

// go: none — goish-only: the body of removeIdleConnLocked, taking the
// already-locked pool so tryPutIdleConn can call it without
// re-entering a non-reentrant Mutex. Go relies on `idleMu` already
// being held by the caller, which the `Locked` suffix announces.
fn __removeIdleConnLocked(pool: &mut idlePool, pconn: &Arc<persistConn>) -> bool {
    pool.idleLRU.remove(pconn);
    let key = pconn.cacheKey.String();
    let pconns = pool.idleConn.Get(key.clone()).0;
    let mut removed = false;
    let mut kept: Vec<Arc<persistConn>> = Vec::new();
    for v in pconns.iter() {
        if !removed && Arc::ptr_eq(v, pconn) {
            // Go slides the tail down, "keeping most recently-used
            // conns at the end"; rebuilding in order preserves that.
            removed = true;
            continue;
        }
        kept.push(v.clone());
    }
    if kept.is_empty() {
        pool.idleConn.Delete(key);
    } else {
        pool.idleConn.Set(key, kept);
    }
    return removed;
}

// ─── retry decision ─────────────────────────────────────────────────

// go: sdk 1.25.5 net/http/transport.go:806-852 persistConn.shouldRetryRequest
/// Go: "whether we should retry sending a failed HTTP request on a new
/// connection."
///
/// Go's receiver is `*persistConn`, which is not ported yet; the only
/// thing it reads from it is `pc.isReused()`, so that arrives as a
/// parameter. Every other branch is verbatim.
///
/// The ordering matters and is not arbitrary. A FRESH connection never
/// retries — Go's comment: "if we retried now, we could loop forever
/// creating new connections and retrying if the server is just hanging
/// up on us because it doesn't like our request". And nothing-written
/// is checked BEFORE replayability, because a request that never
/// reached the wire is safe to re-send whatever its method.
pub fn shouldRetryRequest(
    req: &Request,
    err: error,
    isReused: bool,
) -> bool {
    if errors::Is(err.clone(), super::request::errMissingHost.clone()) {
        // Go: "User error."
        return false;
    }
    if !isReused {
        // Go: "This was a fresh connection. There's no reason the
        // server should've hung up on us."
        return false;
    }
    if errors::Is(err.clone(), errNothingWritten) {
        // Go: "We never wrote anything, so it's safe to retry, if
        // there's no body or we can 'rewind' the body with GetBody."
        //
        // goish's Request owns its body as a `slice<byte>`, which is
        // always replayable, so Go's `req.GetBody != nil` half is
        // always satisfied here.
        return true;
    }
    if !req.isReplayable() {
        // Go: "Don't retry non-idempotent requests."
        return false;
    }
    if errors::Is(err.clone(), errTransportReadFromServer) {
        // Go: "We got some non-EOF net.Conn.Read failure reading the
        // 1st response byte from the server."
        return true;
    }
    if errors::Is(err, errServerClosedIdle) {
        // Go: "The server replied with io.EOF while we were trying to
        // read the response. Probably an unfortunate keep-alive
        // timeout, just as the client was writing a request."
        return true;
    }
    // Go: "conservatively"
    return false;
}

// ─── registered protocols ───────────────────────────────────────────

impl Transport {
    // go: sdk 1.25.5 net/http/transport.go:314-319 Transport.writeBufferSize
    pub fn writeBufferSize(&self) -> int {
        if self.WriteBufferSize > 0 {
            return self.WriteBufferSize;
        }
        return 4 << 10;
    }

    // go: sdk 1.25.5 net/http/transport.go:321-326 Transport.readBufferSize
    pub fn readBufferSize(&self) -> int {
        if self.ReadBufferSize > 0 {
            return self.ReadBufferSize;
        }
        return 4 << 10;
    }

    // go: sdk 1.25.5 net/http/transport.go:385-387 Transport.hasCustomTLSDialer
    /// goish's Transport has no DialTLS/DialTLSContext fields yet, so
    /// this is constant false. Named now so the TLS dial path has a
    /// hook to fill rather than a condition to invent.
    pub fn hasCustomTLSDialer(&self) -> bool {
        return false;
    }

    // go: sdk 1.25.5 net/http/transport.go:1040-1045 Transport.maxIdleConnsPerHost
    /// Note the test is `!= 0`, not `> 0`: Go treats a NEGATIVE
    /// MaxIdleConnsPerHost as "no pool for this host", so it must pass
    /// through rather than fall back to the default.
    pub fn maxIdleConnsPerHost(&self) -> int {
        let v = self.MaxIdleConnsPerHost;
        if v != 0 {
            return v;
        }
        return DefaultMaxIdleConnsPerHost;
    }

    // go: sdk 1.25.5 net/http/transport.go:974-982 Transport.connectMethodForRequest
    /// Build the pool key inputs for a request. Go takes a
    /// `*transportRequest`; goish has no such wrapper yet, so it takes
    /// the Request directly — the wrapper only adds extra headers and
    /// an error cell, neither of which this reads.
    pub fn connectMethodForRequest(&self, req: &Request) -> (connectMethod, error) {
        let mut cm = connectMethod::default();
        cm.targetScheme = req.URL.Scheme.clone();
        cm.targetAddr = canonicalAddr(&req.URL);
        let mut err = errors::nil;
        if let Some(p) = self.Proxy.as_ref() {
            let (u, e) = p(req);
            err = e;
            if err.IsNil() && u.Host.Len() > 0 {
                cm.proxyURL = Some(Arc::new(u));
            }
        }
        cm.onlyH1 = req.requiresHTTP1();
        return (cm, err);
    }

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
