// httptrace — Go's `net/http/httptrace` package.
//
// Reference: /share/go/src/net/http/httptrace/trace.go.
//
// Provides hooks to trace events within HTTP client requests.
// A `ClientTrace` is attached to a request via `WithClientTrace(ctx, trace)`,
// stored as a context value, and looked up by transport code via
// `ContextClientTrace(ctx)`.
//
// Slim deviations from upstream:
//   * TLS hooks (`TLSHandshakeStart` / `TLSHandshakeDone`) — omitted; goish v1
//     does not yet implement crypto/tls.
//   * `internal/nettrace` forwarding — omitted. Go's transport reads a
//     parallel `nettrace.Trace` from `context.WithValue(ctx, nettrace.TraceKey{}, …)`
//     so that the Dialer (in `net`) can call connect/DNS hooks without
//     importing `httptrace`. Goish does not have that package boundary, so
//     a goish dialer would call ClientTrace hooks directly via
//     `ContextClientTrace(ctx)`.
//   * `compose()` is implemented as explicit per-field merging (Go uses
//     `reflect.MakeFunc`, which goish's slim `reflect` doesn't support).
//   * `DNSDoneInfo.Addrs` is `slice<net::IP>` rather than `slice<net.IPAddr>`
//     — goish does not have an `IPAddr` type. The IPv6 zone field is rarely
//     consulted by tracers, so this is acceptable for v1.
//   * Hook fields are `Option<Arc<dyn Fn(...) + Send + Sync>>` rather than
//     bare function pointers. This is the natural Goish shape — closures
//     can capture caller state, like Go's bound methods.

#![allow(non_snake_case)]
#![allow(non_camel_case_types)]

extern crate alloc;

use alloc::sync::Arc;

use crate::context::{self, Context};
use crate::error;
use crate::goslice::slice;
use crate::gostring::string;
use crate::net::textproto::MIMEHeader;
use crate::net::{Conn, IP};
use crate::time::Duration;
use crate::types::int;

// Go: trace.go:20 — `clientEventContextKey struct{}`. A unique unexported
// type prevents key collision across packages.
//
// Slim: goish context uses `&str` keys. Namespacing the key with the full
// import path keeps it unique against any other package's keys.
pub(crate) const CLIENT_EVENT_CONTEXT_KEY: &str =
    "net/http/httptrace.clientEventContextKey";

// ─── hook type aliases ───────────────────────────────────────────────────────
//
// Each Go hook is `func(...)` (a nullable function value). Goish models the
// nullability with `Option<...>` and the function value with
// `Arc<dyn Fn(...) + Send + Sync>`. Arc lets `compose()` clone the inner hook
// for chaining without giving up ownership.

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
pub type WroteHeaderFieldHook = Arc<dyn Fn(string, slice<string>) + Send + Sync>;
pub type WroteHeadersHook = Arc<dyn Fn() + Send + Sync>;
pub type Wait100ContinueHook = Arc<dyn Fn() + Send + Sync>;
pub type WroteRequestHook = Arc<dyn Fn(WroteRequestInfo) + Send + Sync>;

// ─── ClientTrace ─────────────────────────────────────────────────────────────

/// `ClientTrace` (trace.go:80) — set of hooks to run at various stages of an
/// outgoing HTTP request. Any particular hook may be `None`. Hooks may be
/// called concurrently from different goroutines and some may be called
/// after the request has completed or failed.
#[derive(Clone, Default)]
pub struct ClientTrace {
    /// `GetConn` (trace.go:85) — called before a connection is created or
    /// retrieved from an idle pool. The `hostPort` is the "host:port"
    /// of the target or proxy. Called even if there's already an idle
    /// cached connection available.
    pub GetConn: Option<GetConnHook>,

    /// `GotConn` (trace.go:91) — called after a successful connection is
    /// obtained. There is no hook for failure.
    pub GotConn: Option<GotConnHook>,

    /// `PutIdleConn` (trace.go:101) — called when the connection is returned
    /// to the idle pool. `err == nil` means it was returned successfully.
    pub PutIdleConn: Option<PutIdleConnHook>,

    /// `GotFirstResponseByte` (trace.go:105) — called when the first byte of
    /// the response headers is available.
    pub GotFirstResponseByte: Option<GotFirstResponseByteHook>,

    /// `Got100Continue` (trace.go:109) — called if the server replies with a
    /// "100 Continue" response.
    pub Got100Continue: Option<Got100ContinueHook>,

    /// `Got1xxResponse` (trace.go:115) — called for each 1xx informational
    /// response header returned before the final non-1xx response. Called
    /// for "100 Continue" responses too. Returning a non-nil error aborts
    /// the request.
    pub Got1xxResponse: Option<Got1xxResponseHook>,

    /// `DNSStart` (trace.go:118) — called when a DNS lookup begins.
    pub DNSStart: Option<DNSStartHook>,

    /// `DNSDone` (trace.go:121) — called when a DNS lookup ends.
    pub DNSDone: Option<DNSDoneHook>,

    /// `ConnectStart` (trace.go:126) — called when a new connection's Dial
    /// begins. May be called multiple times under Happy Eyeballs.
    pub ConnectStart: Option<ConnectStartHook>,

    /// `ConnectDone` (trace.go:133) — called when a new connection's Dial
    /// completes. `err` indicates success or failure.
    pub ConnectDone: Option<ConnectDoneHook>,

    // TLSHandshakeStart / TLSHandshakeDone — omitted (no goish TLS yet).

    /// `WroteHeaderField` (trace.go:148) — called after the Transport has
    /// written each request header. Values may be buffered.
    pub WroteHeaderField: Option<WroteHeaderFieldHook>,

    /// `WroteHeaders` (trace.go:152) — called after all request headers are
    /// written.
    pub WroteHeaders: Option<WroteHeadersHook>,

    /// `Wait100Continue` (trace.go:158) — called if the Request specified
    /// "Expect: 100-continue" and the Transport is waiting for the
    /// server's "100 Continue" before writing the request body.
    pub Wait100Continue: Option<Wait100ContinueHook>,

    /// `WroteRequest` (trace.go:163) — called with the result of writing the
    /// request and any body. May be called multiple times for retries.
    pub WroteRequest: Option<WroteRequestHook>,
}

// ─── info structs ────────────────────────────────────────────────────────────

/// `WroteRequestInfo` (trace.go:168) — passed to the `WroteRequest` hook.
#[derive(Clone)]
pub struct WroteRequestInfo {
    /// `Err` — any error encountered while writing the Request.
    pub Err: error,
}

/// `DNSStartInfo` (trace.go:211) — passed to the `DNSStart` hook.
#[derive(Clone)]
pub struct DNSStartInfo {
    /// `Host` — hostname being resolved.
    pub Host: string,
}

/// `DNSDoneInfo` (trace.go:216) — passed to the `DNSDone` hook.
///
/// Slim: Go uses `[]net.IPAddr`; goish has no `IPAddr` type, so we use
/// `slice<net::IP>`. Tracers that consult IPv6 zones won't get them — fine
/// for v1.
#[derive(Clone)]
pub struct DNSDoneInfo {
    /// `Addrs` — IPv4/IPv6 addresses found by the lookup. Should not be
    /// mutated by the hook.
    pub Addrs: slice<IP>,

    /// `Err` — any error that occurred during the DNS lookup.
    pub Err: error,

    /// `Coalesced` — whether the Addrs were shared with a concurrent caller
    /// doing the same DNS lookup.
    pub Coalesced: bool,
}

/// `GotConnInfo` (trace.go:238) — passed to the `GotConn` hook.
#[derive(Clone)]
pub struct GotConnInfo {
    /// `Conn` — the connection that was obtained. Owned by the Transport;
    /// callers must not read/write/close it.
    pub Conn: Arc<Conn>,

    /// `Reused` — whether this connection has been previously used for
    /// another HTTP request.
    pub Reused: bool,

    /// `WasIdle` — whether this connection was obtained from an idle pool.
    pub WasIdle: bool,

    /// `IdleTime` — how long the connection was previously idle, if WasIdle
    /// is true.
    pub IdleTime: Duration,
}

// ─── compose ─────────────────────────────────────────────────────────────────

impl ClientTrace {
    /// `compose` (trace.go:175) — modify `self` so that it respects the
    /// previously-registered hooks in `old`. For each hook field in `old`:
    ///   * if `self.field` is None → adopt old's value;
    ///   * if both are set → wrap a new closure that calls `self.field`
    ///     first, then `old.field` (matching Go's `reflect.MakeFunc`
    ///     behaviour: new is invoked first, old is invoked last).
    ///
    /// For hooks that return a value (only `Got1xxResponse` does), the
    /// composed closure returns old's result — matching Go's `return of.Call(args)`.
    pub fn compose(&mut self, old: &ClientTrace) {
        // Go: trace.go:177 — `if old == nil { return }`. Goish callers pass
        // by reference so the nil-check happens at the call-site.

        // ── nullary hooks ────────────────────────────────────────────
        merge_nullary(&mut self.GotFirstResponseByte, &old.GotFirstResponseByte);
        merge_nullary(&mut self.Got100Continue, &old.Got100Continue);
        merge_nullary(&mut self.WroteHeaders, &old.WroteHeaders);
        merge_nullary(&mut self.Wait100Continue, &old.Wait100Continue);

        // ── 1-arg by-value hooks ─────────────────────────────────────
        merge_1arg_string(&mut self.GetConn, &old.GetConn);
        merge_1arg_clone::<GotConnInfo>(&mut self.GotConn, &old.GotConn);
        merge_1arg_error(&mut self.PutIdleConn, &old.PutIdleConn);
        merge_1arg_clone::<DNSStartInfo>(&mut self.DNSStart, &old.DNSStart);
        merge_1arg_clone::<DNSDoneInfo>(&mut self.DNSDone, &old.DNSDone);
        merge_1arg_clone::<WroteRequestInfo>(&mut self.WroteRequest, &old.WroteRequest);

        // ── 2-arg(string, string) hook ───────────────────────────────
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

        // ── 3-arg(string, string, error) hook ────────────────────────
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

        // ── WroteHeaderField(string, slice<string>) ─────────────────
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

        // ── Got1xxResponse(int, MIMEHeader) -> error ────────────────
        // Go calls new first (discarding result), then returns old's error.
        match (self.Got1xxResponse.take(), old.Got1xxResponse.clone()) {
            (None, Some(o)) => self.Got1xxResponse = Some(o),
            (Some(t), Some(o)) => {
                let composed: Got1xxResponseHook =
                    Arc::new(move |code: int, h: MIMEHeader| -> error {
                        let _ = t(code, h.clone());
                        o(code, h)
                    });
                self.Got1xxResponse = Some(composed);
            }
            (t, None) => self.Got1xxResponse = t,
        }
    }

    /// `hasNetHooks` (trace.go:229) — true iff any DNS / Connect hook is
    /// set. Used by Go's transport to decide whether to wrap a
    /// `nettrace.Trace` into the context. Goish does not yet wire the
    /// Dialer to ClientTrace, but the predicate is kept for parity.
    pub fn hasNetHooks(&self) -> bool {
        self.DNSStart.is_some()
            || self.DNSDone.is_some()
            || self.ConnectStart.is_some()
            || self.ConnectDone.is_some()
    }
}

// ─── compose helpers ─────────────────────────────────────────────────────────

fn merge_nullary(t: &mut Option<Arc<dyn Fn() + Send + Sync>>, old: &Option<Arc<dyn Fn() + Send + Sync>>) {
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

/// `ContextClientTrace` (trace.go:24) — return the `ClientTrace` associated
/// with the provided context, or `None`.
pub fn ContextClientTrace(ctx: &Arc<dyn Context>) -> Option<Arc<ClientTrace>> {
    let v = ctx.Value(CLIENT_EVENT_CONTEXT_KEY)?;
    // Stored as Arc<ClientTrace>; Context::Value gives back Arc<dyn Any>.
    Arc::downcast::<ClientTrace>(v).ok()
}

/// `WithClientTrace` (trace.go:34) — return a new context based on `ctx`
/// with `trace`'s hooks merged on top of any previously-registered trace.
/// Hooks defined in `trace` are called first; older hooks called after.
///
/// Go panics on `nil trace`. Goish takes `ClientTrace` by value, which can't
/// be nil; the panic check happens implicitly by virtue of the type.
pub fn WithClientTrace(ctx: Arc<dyn Context>, mut trace: ClientTrace) -> Arc<dyn Context> {
    // Go: trace.go:38 — `old := ContextClientTrace(ctx)`.
    let old = ContextClientTrace(&ctx);
    // Go: trace.go:39 — `trace.compose(old)`.
    if let Some(o) = old.as_deref() {
        trace.compose(o);
    }
    // Go: trace.go:41 — `ctx = context.WithValue(ctx, clientEventContextKey{}, trace)`.
    // Slim: WithValue wraps the value in Arc internally; we pass `trace` itself
    // and recover via Arc::downcast<ClientTrace>.
    context::WithValue(ctx, CLIENT_EVENT_CONTEXT_KEY, trace)

    // Go: trace.go:42-66 — nettrace forwarding. Omitted (see module doc).
}
