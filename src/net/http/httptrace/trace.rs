// go: package net/http/httptrace
//
// go: file net/http/httptrace/trace.go decls: ContextClientTrace, WithClientTrace, ClientTrace.compose, ClientTrace.hasNetHooks
//
// Go: "Package httptrace provides mechanisms to trace the events within
// HTTP client requests."
//
// Two structural deviations, both forced:
//
//   * `compose` is written out field by field. Go builds the composed
//     hook with reflect.MakeFunc over the struct's fields; goish's
//     reflect is a value tree with no MakeFunc and no Call, so the
//     dispatch has to be spelled. The ORDER Go's version produces is
//     what matters and is preserved: the new hook runs first, the old
//     one runs last, and for the one hook that returns a value it is
//     old's result that propagates.
//
//   * WithClientTrace does not install an internal/nettrace.Trace.
//     That package exists so net.Dialer can call connect/DNS hooks
//     without importing httptrace; goish has not ported it, so a goish
//     dialer would read ClientTrace out of the context directly. The
//     hasNetHooks predicate that gates it is ported regardless, so the
//     wiring is a one-line change once nettrace lands.
//
// Hook fields are `Option<Arc<dyn Fn(..) + Send + Sync>>` rather than
// bare fn pointers: Go's `func` values are closures that capture, and
// Arc is what lets compose clone a hook for chaining.
//
// goishlint:ignore GOISH019 ClientTrace — Go's field set is reproduced
// in full; the hook types are wrapped in Option<Arc<dyn Fn..>> per the
// note above, which the field checker reads as a rename.

#![allow(non_snake_case)]
#![allow(non_camel_case_types)]

extern crate alloc;

use alloc::sync::Arc;

use crate::context::{self, Context};
use crate::crypto::tls;
use crate::error;
use crate::goslice::slice;
use crate::gostring::string;
use crate::net::textproto::MIMEHeader;
use crate::net::{Conn, LookupIPAddr};
use crate::time::Duration;
use crate::types::int;

// go: none — Go uses `type clientEventContextKey struct{}`, an
// unexported empty type, so no other package can construct the key.
// goish's context keys are &str; namespacing with the full import path
// buys the same collision-freedom.
pub(crate) const CLIENT_EVENT_CONTEXT_KEY: &str = "net/http/httptrace.clientEventContextKey";

// ─── hook type aliases ───────────────────────────────────────────────────────

pub type GetConnHook = Arc<dyn Fn(string) + Send + Sync>;
pub type GotConnHook = Arc<dyn Fn(GotConnInfo) + Send + Sync>;
pub type PutIdleConnHook = Arc<dyn Fn(error) + Send + Sync>;
pub type GotFirstResponseByteHook = Arc<dyn Fn() + Send + Sync>;
pub type Got100ContinueHook = Arc<dyn Fn() + Send + Sync>;
pub type Got1xxResponseHook = Arc<dyn Fn(int, MIMEHeader) -> error + Send + Sync>;
pub type DNSStartHook = Arc<dyn Fn(DNSStartInfo) + Send + Sync>;
pub type DNSDoneHook = Arc<dyn Fn(DNSDoneInfo) + Send + Sync>;
pub type ConnectStartHook = Arc<dyn Fn(string, string) + Send + Sync>;
pub type ConnectDoneHook = Arc<dyn Fn(string, string, error) + Send + Sync>;
pub type TLSHandshakeStartHook = Arc<dyn Fn() + Send + Sync>;
pub type TLSHandshakeDoneHook = Arc<dyn Fn(tls::ConnectionState, error) + Send + Sync>;
pub type WroteHeaderFieldHook = Arc<dyn Fn(string, slice<string>) + Send + Sync>;
pub type WroteHeadersHook = Arc<dyn Fn() + Send + Sync>;
pub type Wait100ContinueHook = Arc<dyn Fn() + Send + Sync>;
pub type WroteRequestHook = Arc<dyn Fn(WroteRequestInfo) + Send + Sync>;

// ─── ClientTrace ─────────────────────────────────────────────────────────────

// go: sdk 1.25.5 net/http/httptrace/trace.go:80-164 ClientTrace
/// Go: "ClientTrace is a set of hooks to run at various stages of an
/// outgoing HTTP request. Any particular hook may be nil. Functions may
/// be called concurrently from different goroutines and some may be
/// called after the request has completed or failed."
#[derive(Clone, Default)]
pub struct ClientTrace {
    /// Go: "called before a connection is created or retrieved from an
    /// idle pool. The hostPort is the "host:port" of the target or
    /// proxy. GetConn is called even if there's already an idle cached
    /// connection available."
    pub GetConn: Option<GetConnHook>,

    /// Go: "called after a successful connection is obtained. There is
    /// no hook for failure to obtain a connection."
    pub GotConn: Option<GotConnHook>,

    /// Go: "called when the connection is returned to the idle pool. If
    /// err is nil, the connection was successfully returned."
    pub PutIdleConn: Option<PutIdleConnHook>,

    /// Go: "called when the first byte of the response headers is
    /// available."
    pub GotFirstResponseByte: Option<GotFirstResponseByteHook>,

    /// Go: "called if the server replies with a "100 Continue"
    /// response."
    pub Got100Continue: Option<Got100ContinueHook>,

    /// Go: "called for each 1xx informational response header returned
    /// before the final non-1xx response. If it returns an error, the
    /// client request is aborted with that error value."
    pub Got1xxResponse: Option<Got1xxResponseHook>,

    /// Go: "called when a DNS lookup begins."
    pub DNSStart: Option<DNSStartHook>,

    /// Go: "called when a DNS lookup ends."
    pub DNSDone: Option<DNSDoneHook>,

    /// Go: "called when a new connection's Dial begins. If
    /// net.Dialer.DualStack (IPv6 "Happy Eyeballs") support is enabled,
    /// this may be called multiple times."
    pub ConnectStart: Option<ConnectStartHook>,

    /// Go: "called when a new connection's Dial completes. The provided
    /// err indicates whether the connection completed successfully."
    pub ConnectDone: Option<ConnectDoneHook>,

    /// Go: "called when the TLS handshake is started. When connecting to
    /// an HTTPS site via an HTTP proxy, the handshake happens after the
    /// CONNECT request is processed by the proxy."
    pub TLSHandshakeStart: Option<TLSHandshakeStartHook>,

    /// Go: "called after the TLS handshake with either the successful
    /// handshake's connection state, or a non-nil error on handshake
    /// failure."
    pub TLSHandshakeDone: Option<TLSHandshakeDoneHook>,

    /// Go: "called after the Transport has written each request header.
    /// At the time of this call the values might be buffered and not yet
    /// written to the network."
    pub WroteHeaderField: Option<WroteHeaderFieldHook>,

    /// Go: "called after the Transport has written all request headers."
    pub WroteHeaders: Option<WroteHeadersHook>,

    /// Go: "called if the Request specified "Expect: 100-continue" and
    /// the Transport has written the request headers but is waiting for
    /// "100 Continue" from the server before writing the request body."
    pub Wait100Continue: Option<Wait100ContinueHook>,

    /// Go: "called with the result of writing the request and any body.
    /// It may be called multiple times in the case of retried requests."
    pub WroteRequest: Option<WroteRequestHook>,
}

// ─── info structs ────────────────────────────────────────────────────────────

// go: sdk 1.25.5 net/http/httptrace/trace.go:168-171 WroteRequestInfo
/// Go: "WroteRequestInfo contains information provided to the
/// WroteRequest hook."
#[derive(Clone)]
pub struct WroteRequestInfo {
    /// Go: "any error encountered while writing the Request."
    pub Err: error,
}

// go: sdk 1.25.5 net/http/httptrace/trace.go:211-213 DNSStartInfo
/// Go: "DNSStartInfo contains information about a DNS request."
#[derive(Clone)]
pub struct DNSStartInfo {
    pub Host: string,
}

// go: sdk 1.25.5 net/http/httptrace/trace.go:216-227 DNSDoneInfo
/// Go: "DNSDoneInfo contains information about the results of a DNS
/// lookup."
#[derive(Clone)]
pub struct DNSDoneInfo {
    /// Go: "the IPv4 and/or IPv6 addresses found in the DNS lookup. The
    /// contents of the slice should not be mutated."
    ///
    /// Go's element type is `net.IPAddr`; goish exports that struct as
    /// `net::LookupIPAddr` because `net::IPAddr` is taken by an internal
    /// resolver type.
    pub Addrs: slice<LookupIPAddr>,

    /// Go: "any error that occurred during the DNS lookup."
    pub Err: error,

    /// Go: "whether the Addrs were shared with another caller who was
    /// doing the same DNS lookup concurrently."
    pub Coalesced: bool,
}

// go: sdk 1.25.5 net/http/httptrace/trace.go:238-255 GotConnInfo
/// Go: "GotConnInfo is the argument to the [ClientTrace.GotConn]
/// function and contains information about the obtained connection."
///
/// goishlint:ignore GOISH019 GotConnInfo — `Conn` is `Arc<dyn Conn>`
/// rather than the bare `net.Conn` interface value, which is how goish
/// spells a stored interface.
#[derive(Clone)]
pub struct GotConnInfo {
    /// Go: "the connection that was obtained. It is owned by the
    /// http.Transport and should not be read, written or closed by users
    /// of ClientTrace."
    pub Conn: Arc<dyn Conn>,

    /// Go: "whether this connection has been previously used for another
    /// HTTP request."
    pub Reused: bool,

    /// Go: "whether this connection was obtained from an idle pool."
    pub WasIdle: bool,

    /// Go: "reports how long the connection was previously idle, if
    /// WasIdle is true."
    pub IdleTime: Duration,
}

// ─── compose ─────────────────────────────────────────────────────────────────

impl ClientTrace {
    // go: sdk 1.25.5 net/http/httptrace/trace.go:175-208 ClientTrace.compose
    /// Go: "compose modifies t such that it respects the
    /// previously-registered hooks in old, subject to the composition
    /// policy requested in t.Compose."
    ///
    /// Go reflects over the struct: for each func-typed field, adopt
    /// old's value if t's is nil, otherwise build a hook that calls t's
    /// copy and then returns old's result. Without MakeFunc that has to
    /// be written per hook shape — the helpers below are the four shapes
    /// that occur, plus the four hooks with unique signatures.
    pub fn compose(&mut self, old: &ClientTrace) {
        // Go returns early on a nil `old`; goish callers hold a
        // reference, so the nil check lives at the call site.

        // Hooks taking no arguments.
        merge_nullary(&mut self.GotFirstResponseByte, &old.GotFirstResponseByte);
        merge_nullary(&mut self.Got100Continue, &old.Got100Continue);
        merge_nullary(&mut self.TLSHandshakeStart, &old.TLSHandshakeStart);
        merge_nullary(&mut self.WroteHeaders, &old.WroteHeaders);
        merge_nullary(&mut self.Wait100Continue, &old.Wait100Continue);

        // Hooks taking one clonable argument.
        merge_1arg_string(&mut self.GetConn, &old.GetConn);
        merge_1arg_clone::<GotConnInfo>(&mut self.GotConn, &old.GotConn);
        merge_1arg_error(&mut self.PutIdleConn, &old.PutIdleConn);
        merge_1arg_clone::<DNSStartInfo>(&mut self.DNSStart, &old.DNSStart);
        merge_1arg_clone::<DNSDoneInfo>(&mut self.DNSDone, &old.DNSDone);
        merge_1arg_clone::<WroteRequestInfo>(&mut self.WroteRequest, &old.WroteRequest);

        // ConnectStart(network, addr string)
        match (self.ConnectStart.take(), old.ConnectStart.clone()) {
            (None, Some(o)) => self.ConnectStart = Some(o),
            (Some(t), Some(o)) => {
                let composed: ConnectStartHook = Arc::new(move |a: string, b: string| {
                    t(a.clone(), b.clone());
                    o(a, b);
                });
                self.ConnectStart = Some(composed);
            }
            (t, None) => self.ConnectStart = t,
        }

        // ConnectDone(network, addr string, err error)
        match (self.ConnectDone.take(), old.ConnectDone.clone()) {
            (None, Some(o)) => self.ConnectDone = Some(o),
            (Some(t), Some(o)) => {
                let composed: ConnectDoneHook =
                    Arc::new(move |a: string, b: string, e: error| {
                        t(a.clone(), b.clone(), e.clone());
                        o(a, b, e);
                    });
                self.ConnectDone = Some(composed);
            }
            (t, None) => self.ConnectDone = t,
        }

        // TLSHandshakeDone(tls.ConnectionState, error)
        match (self.TLSHandshakeDone.take(), old.TLSHandshakeDone.clone()) {
            (None, Some(o)) => self.TLSHandshakeDone = Some(o),
            (Some(t), Some(o)) => {
                let composed: TLSHandshakeDoneHook =
                    Arc::new(move |cs: tls::ConnectionState, e: error| {
                        t(cs.clone(), e.clone());
                        o(cs, e);
                    });
                self.TLSHandshakeDone = Some(composed);
            }
            (t, None) => self.TLSHandshakeDone = t,
        }

        // WroteHeaderField(key string, value []string)
        match (self.WroteHeaderField.take(), old.WroteHeaderField.clone()) {
            (None, Some(o)) => self.WroteHeaderField = Some(o),
            (Some(t), Some(o)) => {
                let composed: WroteHeaderFieldHook =
                    Arc::new(move |k: string, v: slice<string>| {
                        t(k.clone(), v.clone());
                        o(k, v);
                    });
                self.WroteHeaderField = Some(composed);
            }
            (t, None) => self.WroteHeaderField = t,
        }

        // Got1xxResponse(code int, header textproto.MIMEHeader) error —
        // the one hook with a result. Go discards t's and returns old's.
        match (self.Got1xxResponse.take(), old.Got1xxResponse.clone()) {
            (None, Some(o)) => self.Got1xxResponse = Some(o),
            (Some(t), Some(o)) => {
                let composed: Got1xxResponseHook =
                    Arc::new(move |code: int, h: MIMEHeader| -> error {
                        let _ = t(code, h.clone());
                        return o(code, h);
                    });
                self.Got1xxResponse = Some(composed);
            }
            (t, None) => self.Got1xxResponse = t,
        }
    }

    // go: sdk 1.25.5 net/http/httptrace/trace.go:229-234 ClientTrace.hasNetHooks
    /// Whether any DNS or Connect hook is set. Go's transport uses this
    /// to decide whether to attach an internal/nettrace.Trace.
    pub fn hasNetHooks(&self) -> bool {
        return self.DNSStart.is_some()
            || self.DNSDone.is_some()
            || self.ConnectStart.is_some()
            || self.ConnectDone.is_some();
    }
}

// ─── compose helpers ─────────────────────────────────────────────────────────
//
// These stand in for the single reflective loop in Go's compose: one
// helper per hook arity that repeats.

// go: none — goish-only, no Go counterpart: Go's compose is one
// reflect.MakeFunc loop over the struct's fields.
fn merge_nullary(
    t: &mut Option<Arc<dyn Fn() + Send + Sync>>,
    old: &Option<Arc<dyn Fn() + Send + Sync>>,
) {
    match (t.take(), old.clone()) {
        (None, Some(o)) => *t = Some(o),
        (Some(tf), Some(of)) => {
            *t = Some(Arc::new(move || {
                tf();
                of();
            }));
        }
        (tf, None) => *t = tf,
    }
}

// go: none — goish-only, see merge_nullary.
fn merge_1arg_string(
    t: &mut Option<Arc<dyn Fn(string) + Send + Sync>>,
    old: &Option<Arc<dyn Fn(string) + Send + Sync>>,
) {
    match (t.take(), old.clone()) {
        (None, Some(o)) => *t = Some(o),
        (Some(tf), Some(of)) => {
            *t = Some(Arc::new(move |s: string| {
                tf(s.clone());
                of(s);
            }));
        }
        (tf, None) => *t = tf,
    }
}

// go: none — goish-only, see merge_nullary.
fn merge_1arg_error(
    t: &mut Option<Arc<dyn Fn(error) + Send + Sync>>,
    old: &Option<Arc<dyn Fn(error) + Send + Sync>>,
) {
    match (t.take(), old.clone()) {
        (None, Some(o)) => *t = Some(o),
        (Some(tf), Some(of)) => {
            *t = Some(Arc::new(move |e: error| {
                tf(e.clone());
                of(e);
            }));
        }
        (tf, None) => *t = tf,
    }
}

// go: none — goish-only, see merge_nullary.
fn merge_1arg_clone<T: Clone + Send + Sync + 'static>(
    t: &mut Option<Arc<dyn Fn(T) + Send + Sync>>,
    old: &Option<Arc<dyn Fn(T) + Send + Sync>>,
) {
    match (t.take(), old.clone()) {
        (None, Some(o)) => *t = Some(o),
        (Some(tf), Some(of)) => {
            *t = Some(Arc::new(move |v: T| {
                tf(v.clone());
                of(v);
            }));
        }
        (tf, None) => *t = tf,
    }
}

// ─── public API ──────────────────────────────────────────────────────────────

// go: sdk 1.25.5 net/http/httptrace/trace.go:24-27 ContextClientTrace
/// Go: "ContextClientTrace returns the [ClientTrace] associated with the
/// provided context. If none, it returns nil."
pub fn ContextClientTrace(ctx: &Arc<dyn Context>) -> Option<Arc<ClientTrace>> {
    let v = match ctx.Value(CLIENT_EVENT_CONTEXT_KEY) {
        Some(v) => v,
        None => return None,
    };
    // Go's comma-ok type assertion to *ClientTrace; a value of some
    // other type under the same key yields nil, not a panic.
    return Arc::downcast::<ClientTrace>(v).ok();
}

// go: sdk 1.25.5 net/http/httptrace/trace.go:34-68 WithClientTrace
/// Go: "WithClientTrace returns a new context based on the provided
/// parent ctx. HTTP client requests made with the returned context will
/// use the provided trace hooks, in addition to any previous hooks
/// registered with ctx. Any hooks defined in the provided trace will be
/// called first."
///
/// Go panics on a nil trace. goish takes the value, which cannot be nil,
/// so the panic has no reachable case.
///
/// The nettrace.Trace half of Go's body is absent — see the module note.
pub fn WithClientTrace(ctx: Arc<dyn Context>, mut trace: ClientTrace) -> Arc<dyn Context> {
    let old = ContextClientTrace(&ctx);
    if let Some(o) = old.as_deref() {
        trace.compose(o);
    }
    return context::WithValue(ctx, CLIENT_EVENT_CONTEXT_KEY, trace);
}
