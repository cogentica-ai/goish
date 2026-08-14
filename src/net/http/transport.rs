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
