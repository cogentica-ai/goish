// net/http/transport — the connection-pool addressing layer.
//
// goishlint:ignore GOISH019 — one finding, on `transportRequest`: Go
// embeds *Request anonymously (Rust must name it) and carries
// trace/ctx/cancel/mu for the loops phase, documented on the struct;
// the rule has no line-scoped form. The other structs in this file
// pass the field check and stay covered by review.
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
// go: waived prepareTransportCancel — wraps the request's
// CancelCause into the reqCanceler map so the DEPRECATED
// Request.Cancel channel and pre-1.5 CancelRequest keep working.
// goish's Request carries no Cancel channel by design (see
// setRequestCancel) and context.CancelCause is unported; the direct
// CancelRequest path (cancelRequest) IS ported.
// go: waived awaitLegacyCancel — the goroutine that watches the
// deprecated Request.Cancel channel; same absent-by-design field.

// go: sdk 1.25.5 net/http/transport.go:514-524 transportRequest
/// Go: "transportRequest is a wrapper around a *Request that adds
/// extra headers to write and stores any error to return from
/// roundTrip."
pub struct transportRequest {
    /// Go embeds `*Request` — "original request, not to be mutated".
    pub Request: Request,
    /// Go: `extra Header — extra headers to write, or nil`.
    extra: crate::sync::Mutex<Option<super::header::Header>>,
    /// Go: `mu sync.Mutex; err error — first setError value for
    /// mapRoundTripError to consider`.
    err: crate::sync::Mutex<error>,
}

impl transportRequest {
    // go: none — goish-only constructor; Go writes the literal in
    // roundTrip.
    pub fn __new(req: Request) -> transportRequest {
        return transportRequest {
            Request: req,
            extra: crate::sync::Mutex::new(None),
            err: crate::sync::Mutex::new(errors::nil),
        };
    }

    // go: sdk 1.25.5 net/http/transport.go:526-531 transportRequest.extraHeaders
    /// Go lazily allocates and returns the map for the caller to
    /// mutate; goish's map handles share their backing, so the clone
    /// handed out writes through to the stored one.
    pub fn extraHeaders(&self) -> super::header::Header {
        let mut g = self.extra.Lock();
        if g.is_none() {
            *g = Some(super::header::Header::new());
        }
        return g.as_ref().unwrap().clone();
    }

    // go: sdk 1.25.5 net/http/transport.go:533-539 transportRequest.setError
    /// First error wins — later failures on the same request must not
    /// mask the one that actually explains it.
    pub fn setError(&self, err: error) {
        let mut g = self.err.Lock();
        if g.IsNil() {
            *g = err;
        }
        return;
    }

    // go: none — goish-only: mapRoundTripError reads Go's `req.err`
    // under mu directly.
    pub(crate) fn __err(&self) -> error {
        return self.err.Lock().clone();
    }
}

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
#[derive(Clone, Default)]
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
    /// Go: `result chan connOrError` — BUFFERED with cap 1, which is
    /// what lets `tryDeliver` complete without a receiver already
    /// parked. getConn relies on that: an idle-pool hit delivers and
    /// is picked up by the same goroutine a moment later.
    result: crate::gochan::chan<connOrError>,
}

// go: none — goish-only: the payload of Go's `mu sync.Mutex` on
// wantConn, i.e. `done` plus the delivered result.
struct wantConnState {
    /// Go: `key connectMethodKey` — which pool bucket this waiter
    /// wants a conn from.
    key: connectMethodKey,
    /// Go: `ctx context.Context — context for dial, cleared after
    /// delivered or canceled`. None doubles as Go's nil: dialConnFor
    /// reads it as "the waiter gave up".
    ctx: Option<Arc<dyn crate::context::Context>>,
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
            result: crate::make!(chan connOrError, 1),
            state: crate::sync::Mutex::new(wantConnState {
                key: connectMethodKey::default(),
                // Go constructs wantConn WITH the request ctx (getConn
                // literal); nil means "canceled". Background is the
                // live default until getConn stores the real one.
                ctx: Some(crate::context::Background()),
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

    // go: none — goish-only: read Go's `w.key`.
    pub fn __key(&self) -> connectMethodKey {
        return self.state.Lock().key.clone();
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

    // go: none — goish-only: getConn stores the request ctx here for
    // the dial goroutine (Go zero-values it in the wantConn literal).
    pub(crate) fn __set_ctx(&self, ctx: Arc<dyn crate::context::Context>) {
        self.state.Lock().ctx = Some(ctx);
        return;
    }

    // go: sdk 1.25.5 net/http/transport.go:1332-1338 wantConn.getCtxForDial
    /// Go: "context for dial, cleared after delivered or canceled" —
    /// None answers Go's nil, telling dialConnFor the waiter is gone.
    pub fn getCtxForDial(&self) -> Option<Arc<dyn crate::context::Context>> {
        return self.state.Lock().ctx.clone();
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
        st.delivered = pc.clone();
        // Go: `w.result <- connOrError{…}` then `close(w.result)`.
        // The send cannot block — cap 1, and `done` guards against a
        // second delivery ever reaching here.
        self.result.Send(connOrError { pc, err, idleAt });
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
            st.ctx = None;
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
    // go: none — goish-only: Go's cleanFrontCanceled tests
    // `w.cancelCtx != nil`; the goish marker is a live dial ctx.
    // Defaults to live so test waiter types are unaffected.
    fn dial_ctx_live(&self) -> bool {
        return true;
    }
}

impl Waiter for Arc<wantConn> {
    // go: none — goish-only: forwards to wantConn.waiting so the
    // queue's generic bound is satisfied by the real type.
    fn waiting(&self) -> bool {
        return wantConn::waiting(self);
    }

    // go: none — see the trait doc: wantConn.cancel clears the ctx.
    fn dial_ctx_live(&self) -> bool {
        return self.getCtxForDial().is_some();
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

    // go: sdk 1.25.5 net/http/transport.go:1450-1458 wantConnQueue.cleanFrontCanceled
    /// Go: "pops any wantConns with canceled dials from the head of
    /// the queue" — Go tests `w.cancelCtx != nil`; goish's canceled
    /// marker is the cleared dial ctx (Waiter::dial_ctx_live). Go's
    /// caller is the dialsInProgress bookkeeping queue, which goish's
    /// inline dial doesn't carry; the queue discipline is exercised
    /// by the connlimit smoke.
    pub fn cleanFrontCanceled(&mut self) {
        loop {
            let front_canceled = match self.peekFront() {
                None => return,
                Some(w) => !w.dial_ctx_live(),
            };
            if !front_canceled {
                return;
            }
            let _ = self.popFront();
        }
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

    // go: none — goish-only: Go tests membership via the `m` map
    // (`_, ok := t.idleLRU.m[pc]` in closeConnIfStillIdle); the
    // collapsed Vec answers the same question by scan.
    pub fn contains(&self, pc: &T) -> bool {
        for v in self.ll.iter() {
            if v == pc {
                return true;
            }
        }
        return false;
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
    // go: none — goish-only: see the dialConn placeholder.
    pub errDialNotPorted: error = "http: dialConn not yet ported";
    // go: none — goish-only: getConn returns this instead of blocking
    // on a dial that cannot happen yet. Not a Go sentinel; it exists
    // only while dialConn is unported and disappears with it.
    pub errNoIdleConn: error = "http: no idle connection available (dial not yet ported)";
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
    /// Go: `conn net.Conn` + `br *bufio.Reader` — goish's ConnSrc is
    /// exactly that pair (buffered remainder + conn). Present while
    /// the conn is IDLE in the pool; taken out for the request in
    /// flight (the response Body owns it until the bank-back).
    src: crate::sync::Mutex<Option<super::client::ConnSrc>>,
    /// Go: `idleTimer *time.Timer` — the IdleConnTimeout reaper for
    /// the CURRENT idle cycle; stopped when the conn is taken.
    idleTimer: crate::sync::Mutex<Option<crate::time::Timer>>,
    /// goish-only: the raw socket's netpoll watch target, captured at
    /// dial time BEFORE any TLS wrap (the tls.Conn hides the TCPConn,
    /// and the disconnect watch wants the PollDesc underneath).
    /// (fd, PollDesc address); (0, 0) when unavailable.
    watch_parts: crate::sync::Mutex<(i32, usize)>,
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
            src: crate::sync::Mutex::new(None),
            idleTimer: crate::sync::Mutex::new(None),
            watch_parts: crate::sync::Mutex::new((0, 0)),
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

    // go: none — goish-only: Go's pc.conn/pc.br live as bare fields
    // read by the loops; goish moves the pair in and out around each
    // request (the Body owns it mid-flight).
    pub(crate) fn __put_src(&self, src: super::client::ConnSrc) {
        *self.src.Lock() = Some(src);
        return;
    }

    // go: none — see __put_src. Also retires the idle timer: a conn
    // taken for a request must not be reaped by a stale
    // IdleConnTimeout firing (Go Stops pc.idleTimer on delivery).
    pub(crate) fn __take_src(&self) -> Option<super::client::ConnSrc> {
        if let Some(t) = self.idleTimer.Lock().take() {
            t.Stop();
        }
        return self.src.Lock().take();
    }

    // go: none — goish-only: Go's `pc.idleTimer.Reset(...)` slot; one
    // AfterFunc per idle cycle, stopped when the conn is taken.
    pub(crate) fn __arm_idle_timer(&self, t: crate::time::Timer) {
        let old = self.idleTimer.Lock().replace(t);
        if let Some(old) = old {
            old.Stop();
        }
        return;
    }

    // go: none — goish-only: see the watch_parts field.
    pub(crate) fn __set_watch_parts(&self, fd: i32, pd: usize) {
        *self.watch_parts.Lock() = (fd, pd);
        return;
    }

    // go: none — see __set_watch_parts.
    pub(crate) fn __watch_parts(&self) -> (i32, usize) {
        return *self.watch_parts.Lock();
    }

    // go: sdk 1.25.5 net/http/transport.go:1684-1731 persistConn.addTLS
    // goishlint:ignore GOISH020 addTLS — Go's ctx (HandshakeContext)
    // and trace params serve machinery goish's handshake doesn't take
    // yet; the handshake-deadline half of the timeout survives.
    /// Go: "Initiate TLS and check remote host name against
    /// certificate." The config clones, ServerName defaults to the
    /// dial name, and TLSHandshakeTimeout bounds the handshake —
    /// goish arms it as a socket deadline on the plain conn rather
    /// than Go's AfterFunc + goroutine race (the handshake is
    /// synchronous here and the deadline interrupts its reads).
    /// Go stores tlsState; goish's pc does not carry it yet.
    pub(crate) fn addTLS(
        &self,
        t: &Transport,
        name: crate::gostring::string,
        plain: crate::net::TCPConn,
    ) -> error {
        let mut cfg = t.TLSClientConfig.clone();
        if cfg.ServerName.Len() == 0 {
            cfg.ServerName = name;
        }
        if t.TLSHandshakeTimeout.0 > 0 {
            let _ = plain.SetDeadline(crate::time::Now().Add(t.TLSHandshakeTimeout));
        }
        let boxed: alloc::boxed::Box<dyn crate::net::Conn> = alloc::boxed::Box::new(plain);
        let mut tls_conn = crate::crypto::tls::Client(boxed, &cfg);
        let herr = tls_conn.Handshake();
        if !herr.IsNil() {
            let _ = tls_conn.Close();
            return herr;
        }
        let _ = tls_conn.SetDeadline(crate::time::Time::default());
        self.__put_src(super::client::ConnSrc::Tls(crate::bufio::NewReader(tls_conn)));
        return errors::nil;
    }

    // go: none — goish-only: the close reason `closeLocked` recorded;
    // Go's roundTrip reads `pc.closed` directly under mu.
    pub(crate) fn __closed_reason(&self) -> error {
        return self.state.Lock().closed.clone();
    }

    // go: sdk 1.25.5 net/http/transport.go:2420-2439 persistConn.readLoopPeekFailLocked
    // goishlint:ignore GOISH020 readLoopPeekFailLocked — Go's receiver
    // reads pc.br; goish's src is out with the request in flight, so
    // the caller peeks its own bufio and passes the bytes.
    /// Classify a failed peek where a response head should be: an
    /// unsolicited 408 or a bare EOF on the idle channel is Go's
    /// "server closed idle connection" (retryable); anything else is
    /// wrapped and terminal. The reason lands in `closed` via
    /// closeLocked, exactly like Go — read it back with
    /// `__closed_reason`.
    pub(crate) fn readLoopPeekFailLocked(&self, peekErr: error, buffered: &slice<crate::types::byte>) {
        if !self.state.Lock().closed.IsNil() {
            return;
        }
        if buffered.Len() > 0 {
            if is408Message(buffered) {
                self.closeLocked(errServerClosedIdle.into());
                return;
            }
            // Go: log.Printf("Unsolicited response received on idle
            // HTTP channel starting with %q; err=%v", buf, peekErr) —
            // goish has no default transport logger; fall through to
            // the wrapped close below.
        }
        if errors::Is(peekErr.clone(), crate::io::EOF)
            || errors::Is(peekErr.clone(), crate::io::ErrUnexpectedEOF)
        {
            // Go: "common case."
            self.closeLocked(errServerClosedIdle.into());
        } else {
            self.closeLocked(errors::New(crate::fmt::Sprintf!(
                "readLoopPeekFailLocked: %v",
                peekErr
            )));
        }
        return;
    }

    // go: sdk 1.25.5 net/http/transport.go:2529-2546 persistConn.waitForContinue
    // goishlint:ignore GOISH020 waitForContinue — ExpectContinueTimeout
    // lives on the Transport; Go reaches it through pc.t, goish's pc
    // carries no Transport back-pointer, so it arrives as a param.
    /// Go: "waitForContinue returns the function to block until any
    /// response, timeout or connection close. After any of them, the
    /// function returns a bool which indicates if the body should be
    /// sent." A nil continueCh (no Expect header) answers None, Go's
    /// nil func.
    ///
    /// goish deviations, both sequential-model: Go's readLoop CLOSES
    /// the channel for "final response arrived, skip the body" —
    /// goish's feeder sends the bool explicitly (the select macro's
    /// Recv arm binds the value, not the comma-ok). And Go's third
    /// arm watches pc.closech (the readLoop dying); with no
    /// concurrent closer, a conn already recorded broken answers
    /// false up front.
    pub(crate) fn waitForContinue(
        &self,
        t: &Transport,
        continueCh: Option<crate::gochan::chan<bool>>,
    ) -> Option<alloc::boxed::Box<dyn FnOnce() -> bool>> {
        let ch = match continueCh {
            None => return None,
            Some(c) => c,
        };
        if self.isBroken() {
            return Some(alloc::boxed::Box::new(|| false));
        }
        let timeout = t.ExpectContinueTimeout;
        return Some(alloc::boxed::Box::new(move || {
            let timer = crate::time::NewTimer(timeout);
            let out = crate::select! {
                let v = ch.Recv() => v,
                let _ = (timer.C).Recv() => true,
            };
            timer.Stop();
            return out;
        }));
    }

    // go: sdk 1.25.5 net/http/transport.go:2187-2235 persistConn.mapRoundTripError
    // goishlint:ignore GOISH020 mapRoundTripError — Go's middle param
    // is startBytesWritten for the nwrite comparison; the sequential
    // writer already knows the nothing-written fact as `head_failed`.
    /// Go: "returns the appropriate error value for
    /// persistConn.roundTrip." Cancellation beats network noise, an
    /// explicit setError beats the raw failure, errServerClosedIdle
    /// is never decorated, and a broken conn's error names the
    /// transport. The writeLoopDone join belongs to the loops phase.
    pub(crate) fn mapRoundTripError(
        &self,
        treq: &transportRequest,
        head_failed: bool,
        err: error,
    ) -> error {
        if err.IsNil() {
            return errors::nil;
        }
        // Go: "If the request was canceled, that's better than
        // network failures that were likely the result of tearing
        // down the connection."
        let cerr = self.canceled();
        if !cerr.IsNil() {
            return cerr;
        }
        // Go: "See if an error was set explicitly."
        let reqErr = treq.__err();
        if !reqErr.IsNil() {
            return reqErr;
        }
        if errors::Is(err.clone(), errServerClosedIdle) {
            // Go: "Don't decorate"
            return err;
        }
        if self.isBroken() {
            if head_failed {
                return errNothingWritten.into();
            }
            return errors::New(crate::fmt::Sprintf!(
                "net/http: HTTP/1.x transport connection broken: %v",
                err
            ));
        }
        return err;
    }

    // go: sdk 1.25.5 net/http/transport.go:2167-2177 persistConn.closeConnIfStillIdle
    // goishlint:ignore GOISH020 closeConnIfStillIdle — Go reaches the
    // pool through pc.t; goish's persistConn carries no Transport
    // back-pointer, so the Arc'd pool is a parameter.
    /// The IdleConnTimeout reaper: if this conn is STILL in the idle
    /// pool when the timer fires, evict and close it; a conn that was
    /// taken (or re-banked, which re-arms a fresh timer) is left
    /// alone.
    pub(crate) fn closeConnIfStillIdle(
        self: &Arc<Self>,
        idle: &Arc<crate::sync::Mutex<idlePool>>,
    ) {
        {
            let mut pool = idle.Lock();
            if !pool.idleLRU.contains(self) {
                // Go: "Not idle."
                return;
            }
            removeIdleConnLocked(&mut pool, self);
        }
        self.close(errIdleConnTimeout.into());
        return;
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
        drop(st);
        // Go: pc.conn.Close() — an evicted/broken idle conn must
        // release its fd, not leak it in the src slot.
        if let Some(mut src) = self.src.Lock().take() {
            let _ = src.close_conn();
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
    // go: sdk 1.25.5 net/http/transport.go:1565-1593 Transport.queueForDial
    /// Go: "queues w to wait for permission to begin dialing. Once w
    /// receives permission to dial, it will do so in a separate
    /// goroutine." With MaxConnsPerHost unset the dial starts
    /// immediately; at the cap the waiter queues until
    /// decConnsPerHost hands it a freed slot.
    ///
    /// KNOWN GAP while the transport loops are pending: a conn that
    /// dies ORGANICALLY (banked then broken, reaped, or closed after
    /// its response) does not release its per-host slot — Go does
    /// that from readLoop's deferred decConnsPerHost. Dial failures
    /// and canceled waiters DO release theirs (dialConnFor /
    /// wantConn.cancel), so MaxConnsPerHost=0 (the default,
    /// unlimited) is unaffected.
    /// goish note: Go dials on a fresh goroutine
    /// (startDialConnForLocked) so getConn's select can abandon a
    /// slow dial on ctx cancel; goish's net::Dial is not
    /// ctx-interruptible anyway, so the dial runs INLINE here and the
    /// delivery is buffered before getConn's select even starts. The
    /// goroutine form stays available on an Arc'd Transport.
    pub fn queueForDial(&self, w: &Arc<wantConn>) {
        // Go: w.beforeDial() — a test hook; goish has none.
        if self.__take_conn_slot(&w.__key()) {
            self.dialConnFor(w);
            return;
        }
        self.__queue_for_slot(&w.__key(), w.clone());
        return;
    }

    // go: none — goish-only: queueForDial's take-a-slot half,
    // factored so the accounting is unit-testable without a dial.
    // Always true when MaxConnsPerHost is unset (Go's <= 0 arm).
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

    // go: none — goish-only: queueForDial's at-capacity half
    // (transport.go:1585-1591), same factoring reason.
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
        return __try_put_idle(&self.__idle, &self.__bank_cfg(), pconn);
    }

    // go: none — goish-only: the Transport knobs tryPutIdleConn reads,
    // snapshotted so a response Body that outlives the RoundTrip
    // borrow can still bank its conn back (Go's bodyEOFSignal closes
    // over the *Transport; goish closes over this + the Arc'd pool).
    pub(crate) fn __bank_cfg(&self) -> idleBankCfg {
        return idleBankCfg {
            disable_keep_alives: self.DisableKeepAlives,
            max_idle_conns: self.MaxIdleConns,
            max_idle_per_host: self.maxIdleConnsPerHost(),
        };
    }

    // go: sdk 1.25.5 net/http/transport.go:1596-1605 Transport.startDialConnForLocked
    /// Launch a dial for `w` on its own goroutine. Go's `Locked`
    /// suffix means connsPerHostMu is already held by the caller;
    /// goish takes the same contract, so the spawn happens before any
    /// further lock is touched.
    pub fn startDialConnForLocked(self: &Arc<Self>, w: Arc<wantConn>) {
        let t = self.clone();
        crate::go!(stack(256 * 1024), move || {
            t.dialConnFor(&w);
        });
        return;
    }

    // go: sdk 1.25.5 net/http/transport.go:1610-1629 Transport.dialConnFor
    /// Go: "dials on behalf of w and delivers the result to w. […] If
    /// the dial is canceled or unsuccessful, dialConnFor decrements
    /// t.connCount[w.cm.key()]."
    ///
    /// That decrement is why this is worth porting ahead of dialConn:
    /// a FAILED dial must give its per-host slot back, or the count
    /// drifts up until the host is permanently at capacity and every
    /// later request queues forever. It is also the path into
    /// decConnsPerHost's underflow panic, so getting it wrong is loud
    /// rather than silent.
    ///
    /// The other branch is subtler: when the dial SUCCEEDS but the
    /// waiter has gone (cancelled, or served from the pool meanwhile),
    /// the conn goes to putOrCloseIdleConn rather than being dropped.
    ///
    /// Staged: `dialConn` is a placeholder, so this takes the failure
    /// path today. The accounting it drives is real and tested.
    pub fn dialConnFor(&self, w: &Arc<wantConn>) {
        // Go: ctx := w.getCtxForDial(); if ctx == nil — the waiter
        // gave up (canceled) before we got here: return its slot.
        let ctx = w.getCtxForDial();
        if ctx.is_none() {
            if let Some(next) = self.decConnsPerHost(&w.__key()) {
                self.dialConnFor(&next);
            }
            return;
        }

        let (pc, err) = self.dialConn(ctx, &w.__key());
        let delivered = w.tryDeliver(pc.clone(), err.clone(), crate::time::Time::default());
        if err.IsNil() {
            if !delivered {
                // Go: "pconn was not passed to w […] Add to the idle
                // connection pool."
                if let Some(pc) = pc {
                    self.putOrCloseIdleConn(&pc);
                }
            }
        } else {
            // A failed dial frees its slot — and the freed slot goes
            // straight to the next queued waiter (Go hands it via
            // startDialConnForLocked from decConnsPerHost's caller).
            if let Some(next) = self.decConnsPerHost(&w.__key()) {
                self.dialConnFor(&next);
            }
        }
        return;
    }

    // go: sdk 1.25.5 net/http/transport.go:1739-1954 Transport.dialConn
    /// PARTIAL: the TCP and TLS arms of Go's 232 lines; the
    /// proxy-CONNECT and ALPN arms still answer errDialNotPorted.
    /// The pc leaves here carrying its ConnSrc (Go's conn + br pair);
    /// readLoop/writeLoop spawning is the loops phase. Go's ctx
    /// reaches the handshake as HandshakeContext; goish arms the
    /// netpoll cancel watch + the ctx deadline on the raw socket for
    /// the handshake's duration, which interrupts it the same way.
    fn dialConn(
        &self,
        ctx: Option<Arc<dyn crate::context::Context>>,
        key: &connectMethodKey,
    ) -> (Option<Arc<persistConn>>, error) {
        if (key.scheme != "http" && key.scheme != "https") || key.proxy.Len() != 0 {
            return (None, errDialNotPorted.into());
        }
        // Go (dialConn): cm.scheme() == "https" && t.hasCustomTLSDialer()
        // — the hook dials AND handshakes; addTLS is skipped and the
        // conn arrives as the interface type (no PollDesc → the
        // disconnect watch stays disarmed on it).
        if key.scheme == "https" && self.hasCustomTLSDialer() {
            let (conn, derr) =
                self.customDialTLS(ctx.clone(), crate::string("tcp"), key.addr.clone());
            if !derr.IsNil() {
                return (None, derr);
            }
            let pc = Arc::new(persistConn::__new(key.clone()));
            pc.__put_src(super::client::ConnSrc::Dyn(crate::bufio::NewReader(
                super::client::DynConn(conn.unwrap()),
            )));
            return (Some(pc), errors::nil);
        }
        // Go: t.dial(ctx, "tcp", cm.addr()) — goish's DialContext
        // hook is not consulted here yet (nor was it on the inline
        // path this replaces).
        let (conn, derr) = crate::net::Dial(crate::string("tcp"), key.addr.clone());
        if !derr.IsNil() {
            return (None, derr);
        }
        let pc = Arc::new(persistConn::__new(key.clone()));
        // The disconnect watch wants the RAW socket's PollDesc —
        // captured before any TLS wrap hides the TCPConn.
        {
            let (fd, pd) = conn.__disconnect_watch_parts();
            pc.__set_watch_parts(fd, pd as usize);
        }
        if key.scheme == "https" {
            // Go: if cm.scheme() == "https" { pconn.addTLS(ctx, …) }
            // — SNI from the addr with the port stripped. The ctx
            // covers the HANDSHAKE: deadline folded onto the socket,
            // cancel watch armed for its duration.
            if let Some(c) = &ctx {
                if let Some(dl) = c.Deadline() {
                    let _ = conn.SetDeadline(dl);
                }
            }
            let watch =
                super::client::arm_cancel_watch(&ctx, conn.__disconnect_watch_parts());
            let name = super::client::host_without_port(&key.addr);
            let aerr = pc.addTLS(self, name, conn);
            super::client::stop_cancel_watch(watch);
            if !aerr.IsNil() {
                let ctx_err = ctx.map(|c| c.Err()).unwrap_or(errors::nil);
                if !ctx_err.IsNil() {
                    return (None, ctx_err);
                }
                return (None, aerr);
            }
            return (Some(pc), errors::nil);
        }
        pc.__put_src(super::client::ConnSrc::Tcp(crate::bufio::NewReader(conn)));
        return (Some(pc), errors::nil);
    }

    // go: sdk 1.25.5 net/http/transport.go:1487-1561 Transport.getConn
    /// Obtain a connection for `cm`: try the idle pool, else queue for
    /// a dial, then wait for whichever answers.
    ///
    /// The idle-HIT path completes with no dialing at all, because
    /// `w.result` is buffered (cap 1): queueForIdleConn -> tryDeliver
    /// sends without a receiver parked, and the receive below picks it
    /// up immediately. That is what makes this testable now.
    ///
    /// Staged: on a MISS this queues the waiter and returns
    /// `errNoIdleConn` rather than blocking, because
    /// startDialConnForLocked / dialConn are not ported — a real wait
    /// would hang forever. Go blocks in a `select` on the result
    /// channel and the request context. The waiter IS left on the
    /// queue, so a later putOrCloseIdleConn can still find it.
    /// Go's first parameter is `*transportRequest`, a wrapper that
    /// adds extra headers and an error cell around `*Request`. goish
    /// has no wrapper yet, so the Request arrives directly — the arity
    /// and the role are Go's. Nothing here reads it today; Go uses it
    /// for the httptrace hooks and the dial context.
    pub fn getConn(
        &self,
        req: &Request,
        cm: &connectMethod,
    ) -> (Option<Arc<persistConn>>, error) {
        let w = Arc::new(wantConn::__new());
        w.__set_key(cm.key());

        if self.queueForIdleConn(&w) {
            // Go: "case r := <-w.result:" — already buffered by
            // tryDeliver on the idle-hit path.
            let (r, ok) = w.result.Recv();
            if !ok {
                return (None, errNoIdleConn.into());
            }
            if !r.err.IsNil() {
                return (None, r.err);
            }
            return (r.pc, errors::nil);
        }

        // Miss: queue the dial and BLOCK for whichever answers first —
        // the dial goroutine's delivery or the request context. Go's
        // select also watches the test hooks and cancelation channel;
        // the ctx arm covers goish's cancelation model.
        w.__set_ctx(req.Context());
        self.queueForDial(&w);
        let done = req.Context().Done();
        let out = crate::select! {
            let r = (w.result).Recv() => {
                if !r.err.IsNil() {
                    (None, r.err)
                } else {
                    (r.pc, errors::nil)
                }
            },
            let _ = done.Recv() => {
                // Go: "case <-req.Context().Done(): … w.cancel(t)".
                w.cancel(self);
                (None, req.Context().Err())
            },
        };
        return out;
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

    // go: sdk 1.25.5 net/http/transport.go:1235-1240 Transport.removeIdleConn
    /// Go: "removes pconn from the idle list." Locks the pool, then
    /// delegates to the assumes-held body. Returns whether it was
    /// found there.
    pub fn removeIdleConn(&self, pconn: &Arc<persistConn>) -> bool {
        let mut pool = self.__idle.Lock();
        return removeIdleConnLocked(&mut pool, pconn);
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
fn removeIdleConnLocked(pool: &mut idlePool, pconn: &Arc<persistConn>) -> bool {
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

// go: none — goish-only: see Transport::__bank_cfg.
pub(crate) struct idleBankCfg {
    pub(crate) disable_keep_alives: bool,
    pub(crate) max_idle_conns: crate::types::int,
    pub(crate) max_idle_per_host: crate::types::int,
}

// go: none — goish-only: the body of Transport::tryPutIdleConn
// (transport.go:1052-1143), factored free so the response Body's
// bank-back closure — which cannot borrow the Transport — can reach
// it through the Arc'd pool + snapshotted knobs. The METHOD above is
// the anchored port; this is its one implementation.
pub(crate) fn __try_put_idle(
    idle: &Arc<crate::sync::Mutex<idlePool>>,
    cfg: &idleBankCfg,
    pconn: &Arc<persistConn>,
) -> error {
    if cfg.disable_keep_alives || cfg.max_idle_per_host < 0 {
        return errKeepAlivesDisabled.into();
    }
    if pconn.isBroken() {
        return errConnBroken.into();
    }
    pconn.markReused();

    let mut pool = idle.Lock();
    if pool.closeIdle {
        return errCloseIdle.into();
    }
    let key = pconn.cacheKey.String();
    let idles = pool.idleConn.Get(key.clone()).0;
    if crate::int(crate::int64(idles.len())) >= cfg.max_idle_per_host {
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
    // Go stamps idleAt here (pconn.idleAt = time.Now()); goish uses
    // monotonic ns.
    pconn.__set_idle_at(crate::runtime::sysmon::monotonic_ns());
    if cfg.max_idle_conns != 0 && crate::int(crate::int64(pool.idleLRU.len())) > cfg.max_idle_conns {
        if let Some(oldest) = pool.idleLRU.removeOldest() {
            oldest.close(errTooManyIdle.into());
            removeIdleConnLocked(&mut pool, &oldest);
        }
    }
    return errors::nil;
}

// go: sdk 1.25.5 net/http/transport.go:773-784 setupRewindBody
/// Go wraps the body in a readTrackingBody so rewindBody can tell
/// whether anything was consumed. goish's `Body` tracks its own
/// cursor (`__was_read`), so the setup is the identity — kept as the
/// roundTrip entry seam Go routes through.
pub(crate) fn setupRewindBody(req: &Request) -> Request {
    return req.clone();
}

// go: sdk 1.25.5 net/http/transport.go:786-806 rewindBody
/// Go: "returns a new request with the body rewound. It returns req
/// unmodified if the body does not need rewinding." A consumed body
/// is replayable only through GetBody; without it the retry must
/// fail (errCannotRewind) rather than resend an empty body.
pub(crate) fn rewindBody(req: &Request) -> (Request, error) {
    // Go: req.Body == nil || req.Body == NoBody || !didRead — an
    // untouched body needs nothing.
    if !req.Body.__was_read() {
        return (req.clone(), errors::nil);
    }
    let _ = req.Body.__close_shared();
    let gb = match &req.GetBody {
        None => return (req.clone(), errCannotRewind.into()),
        Some(gb) => gb.clone(),
    };
    let (body, err) = gb();
    if !err.IsNil() {
        return (req.clone(), err);
    }
    let mut newReq = req.clone();
    newReq.Body = body;
    return (newReq, errors::nil);
}

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
        return self.DialTLS.is_some() || self.DialTLSContext.is_some();
    }

    // go: sdk 1.25.5 net/http/transport.go:1471-1481 Transport.customDialTLS
    /// Go: DialTLSContext wins over the deprecated DialTLS, and a
    /// hook answering (nil, nil) is a hard error — a silent nil conn
    /// would NPE deep in the pool instead of naming the buggy hook.
    pub(crate) fn customDialTLS(
        &self,
        ctx: Option<Arc<dyn crate::context::Context>>,
        network: crate::gostring::string,
        addr: crate::gostring::string,
    ) -> (Option<alloc::boxed::Box<dyn crate::net::Conn>>, error) {
        let (conn, err) = if let Some(f) = &self.DialTLSContext {
            f(ctx, network, addr)
        } else if let Some(f) = &self.DialTLS {
            f(network, addr)
        } else {
            (None, errors::nil)
        };
        if conn.is_none() && err.IsNil() {
            return (
                None,
                errors::New(crate::string(
                    "net/http: Transport.DialTLS or DialTLSContext returned (nil, nil)",
                )),
            );
        }
        return (conn, err);
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

// go: sdk 1.25.5 net/http/transport.go:954-957 envProxyFuncValue
// go: sdk 1.25.5 net/http/transport.go:954-957 envProxyOnce
// goishlint:ignore GOISH014 envProxyOnce — one accessor carries Go's
// var PAIR (the Once folded into the Mutex<Option<…>> slot); the
// checker compares the nearest anchor's symbol only.
//
// Go pairs a sync.Once with the cached func value; goish folds the
// pair into one Mutex<Option<…>> slot — same once-semantics, and it
// lets resetProxyConfig actually reset (Go overwrites the Once).
fn envProxyFuncValue() -> &'static crate::sync::Mutex<
    Option<alloc::sync::Arc<dyn Fn(&super::url::URL) -> (Option<super::url::URL>, crate::errors::error) + Send + Sync>>,
> {
    static SLOT: crate::lazy::Lazy<
        crate::sync::Mutex<
            Option<
                alloc::sync::Arc<
                    dyn Fn(&super::url::URL) -> (Option<super::url::URL>, crate::errors::error)
                        + Send
                        + Sync,
                >,
            >,
        >,
    > = crate::lazy::Lazy::new(|| crate::sync::Mutex::new(None));
    return SLOT.get();
}

// go: sdk 1.25.5 net/http/transport.go:959-966 envProxyFunc
/// Go: "returns a function that reads the environment variable to
/// determine the proxy address" — computed once, cached; the
/// environment is only consulted on the first call.
pub(crate) fn envProxyFunc() -> alloc::sync::Arc<
    dyn Fn(&super::url::URL) -> (Option<super::url::URL>, crate::errors::error) + Send + Sync,
> {
    let mut g = envProxyFuncValue().Lock();
    if g.is_none() {
        *g = Some(super::httpproxy::FromEnvironment().ProxyFunc());
    }
    return g.as_ref().unwrap().clone();
}

// go: sdk 1.25.5 net/http/transport.go:968-972 resetProxyConfig
/// Go: "resetProxyConfig is used by tests."
pub fn resetProxyConfig() {
    *envProxyFuncValue().Lock() = None;
    return;
}

// go: sdk 1.25.5 net/http/transport.go:2548-2554 newReadWriteCloserBody
// goishlint:ignore GOISH020 newReadWriteCloserBody — Go takes the pair
// (br *bufio.Reader, body io.ReadWriteCloser); goish's ConnSrc IS that
// pair (bufio remainder + conn), so one parameter carries both.
//
/// Go: "newReadWriteCloserBody wraps a io.ReadWriteCloser as the
/// http.Response.Body … for the caller to speak the switched protocol
/// on" — a 101 response, where the connection becomes the body.
pub(crate) fn newReadWriteCloserBody(
    src: super::client::ConnSrc,
) -> super::client::Body {
    return super::client::__new_upgraded_body(src);
}

// go: none — goish-only: silences an unused-import warning for the
// slice type, which the rest of transport.go's port will use.
#[allow(dead_code)]
fn __unused() -> slice<string> {
    return slice::<string>::new();
}
