// net/http/server — Handler trait, ServeMux, ListenAndServe.
//
// Slim port of Go's net/http.Server (server.go:2993),
// http.ServeMux (server.go:2486), and http.ListenAndServe
// (server.go:3702). Delivers the canonical Go-shape:
//
//   let mut mux = http::ServeMux::new();
//   mux.HandleFunc(string("/"), |w, r| {
//       let _ = w.Write(bytes("hello\n"));
//   });
//   let _ = http::ListenAndServe(string(":8080"), &mux);
//
// One goroutine per connection (`go!(stack(N), …)`), blocking I/O.
// HTTP/1.x only, no keep-alive in v1 (`Connection: close` injected
// by ResponseWriter). The mux uses a flat exact-match table plus
// longest-prefix tiebreak for `"/path/"` patterns — same algorithm
// shape as Go's `ServeMux` (Go 1.22 simple form, pre-`{wildcard}`
// patterns).

#![allow(non_snake_case, non_camel_case_types)]

extern crate alloc;

use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicI64, AtomicU8, AtomicUsize, Ordering};

use crate::bufio;
use crate::errors::{self, error};
use crate::go;
use crate::io::Closer;
use crate::net;
use crate::string;
use crate::strings;
use crate::sync::Mutex;
use crate::time;
use crate::types::int;

use super::request::{ReadRequestWithLimit, Request};
use super::response::{response, ResponseWriter};

/// `http.Handler` — types that can serve HTTP requests. Mirrors
/// Go's `type Handler interface { ServeHTTP(ResponseWriter, *Request) }`
/// (server.go:88).
#[goish::interface]
pub trait Handler: Send + Sync {
    fn ServeHTTP(&self, w: &(dyn ResponseWriter + Send + Sync + 'static), r: &Request);
}

// ─── blanket impls so Arc<T>/Box<T> satisfy `Handler` ───────────────
//
// Lets `mux.Handle(pat, h)` and `StripPrefix(pat, h)` (now generic over
// `H: Handler + 'static`) accept either a bare struct, a wrapped
// closure, or an already-`Arc<dyn Handler>` without the caller writing
// `Arc::new(...) as Arc<dyn Handler>`. Mirrors Go's interface-value
// passing where `*ServeMux` and `http.Handler` are interchangeable at
// call sites.

impl<T: Handler + ?Sized> Handler for Arc<T> {
    #[inline]
    fn ServeHTTP(&self, w: &(dyn ResponseWriter + Send + Sync + 'static), r: &Request) {
        (**self).ServeHTTP(w, r)
    }
}

impl<T: Handler + ?Sized> Handler for alloc::boxed::Box<T> {
    #[inline]
    fn ServeHTTP(&self, w: &(dyn ResponseWriter + Send + Sync + 'static), r: &Request) {
        (**self).ServeHTTP(w, r)
    }
}

/// `http.HandlerFunc` adapter — wrap a closure as a `Handler`.
/// Mirrors Go's `type HandlerFunc func(ResponseWriter, *Request)`.
pub struct HandlerFunc<F>(pub F)
where
    F: Fn(&(dyn ResponseWriter + Send + Sync + 'static), &Request) + Send + Sync;

impl<F> Handler for HandlerFunc<F>
where
    F: Fn(&(dyn ResponseWriter + Send + Sync + 'static), &Request) + Send + Sync,
{
    fn ServeHTTP(&self, w: &(dyn ResponseWriter + Send + Sync + 'static), r: &Request) {
        (self.0)(w, r);
    }
}

// ─── ServeMux ────────────────────────────────────────────────────────

/// `http.ServeMux` — pattern → Handler routing table.
///
/// Three pattern shapes:
///   - Exact: `"/about"` matches only `/about`.
///   - Prefix: `"/static/"` (trailing slash) matches any path
///     starting with `/static/`.
///   - Wildcard (Go 1.22): `"/users/{id}"` and `"/files/{path...}"`.
///     Optional `[METHOD ]` prefix (`"GET /users/{id}"`).
///
/// Match order: exact > prefix (longest-wins) > wildcard (registration
/// order). Wildcard bindings are exposed via `r.PathValue(name)`.
pub struct ServeMux {
    /// Inner state behind a Mutex so handlers can be added before
    /// `ListenAndServe` and `ServeMux` is `Send + Sync` for
    /// passing into the per-connection goroutine.
    state: Arc<Mutex<MuxState>>,
}

struct MuxState {
    /// Plain (literal) routes for exact + longest-prefix matching.
    /// Linear scan in `match_handler` is fine for typical route
    /// counts (<100).
    routes: Vec<(string, Arc<dyn Handler>)>,
    /// Wildcard routes. Stored separately because their precedence is
    /// after literal exact/prefix.
    pattern_routes: Vec<PatternRoute>,
}

struct PatternRoute {
    pattern: super::pattern::Pattern,
    handler: Arc<dyn Handler>,
}

impl ServeMux {
    pub fn new() -> Self {
        ServeMux {
            state: Arc::new(Mutex::new(MuxState {
                routes: Vec::new(),
                pattern_routes: Vec::new(),
            })),
        }
    }

    /// `mux.Handle(pattern, h)` — register a Handler. Patterns that
    /// contain `{` are parsed as Go 1.22 wildcards; any parse error
    /// causes the registration to be silently dropped (Go panics).
    /// If `pattern` already exists in the literal table, replaces it.
    ///
    /// Generic over `H: Handler + 'static` so callers can pass any
    /// `Handler` impl directly — bare structs, `Arc<dyn Handler>`,
    /// `Box<dyn Handler>` — without writing `Arc::new(...) as
    /// Arc<dyn http::Handler>` at the call site. Mirrors Go's
    /// `mux.Handle(pattern, h Handler)` interface-value semantics.
    pub fn Handle<P: Into<string>, H: Handler + 'static>(&self, pattern: P, h: H) {
        self.handle_arc(pattern.into(), Arc::new(h));
    }

    /// Internal: stores an already-arced handler. Used by `Handle`,
    /// `HandleFunc`, and other internal callers that already hold an
    /// `Arc<dyn Handler>`.
    fn handle_arc(&self, pattern: string, h: Arc<dyn Handler>) {
        // Wildcard or method-prefixed → parse as Pattern.
        let needs_pattern_parse = strings::Contains(pattern.clone(), string("{"))
            || strings::ContainsAny(pattern.clone(), string(" \t"));
        let mut s = self.state.Lock();
        if needs_pattern_parse {
            let (p, err) = super::pattern::parse_pattern(pattern);
            if err.IsNil() {
                s.pattern_routes.push(PatternRoute {
                    pattern: p,
                    handler: h,
                });
            }
            return;
        }
        for r in s.routes.iter_mut() {
            if r.0 == pattern {
                r.1 = h;
                return;
            }
        }
        s.routes.push((pattern, h));
    }

    /// `mux.HandleFunc(pattern, fn)` — register a closure handler.
    /// The closure must be `Send + Sync + 'static` to be safely
    /// shared across the per-connection worker goroutines.
    pub fn HandleFunc<P: Into<string>, F>(&self, pattern: P, f: F)
    where
        F: Fn(&(dyn ResponseWriter + Send + Sync + 'static), &Request) + Send + Sync + 'static,
    {
        self.handle_arc(pattern.into(), Arc::new(HandlerFunc(f)));
    }

    /// Internal: pick the handler for `r`. Returns the chosen handler
    /// and (for wildcard hits) any path-value bindings, or a 404
    /// stub with empty bindings.
    fn match_handler(
        &self,
        r: &Request,
    ) -> (
        Arc<dyn Handler>,
        crate::gomap::map<string, string>,
    ) {
        let s = self.state.Lock();
        // 1. Exact literal match.
        for route in s.routes.iter() {
            if route.0 == r.URL.Path {
                return (route.1.clone(), crate::gomap::map::<string, string>::new());
            }
        }
        // 2. Longest prefix-with-trailing-slash match — but skip the
        //    bare `/` catchall here so registered wildcards still win.
        //    Go 1.22's mux compares pattern specificity globally; we
        //    approximate by deferring `/` to step 4. A multi-segment
        //    literal prefix like `/api/users/` still pre-empts any
        //    wildcard registered later, matching Go's intent that
        //    longer literal prefixes are more specific.
        let path_b = r.URL.Path.as_bytes();
        let mut best_len: usize = 0;
        let mut best: Option<Arc<dyn Handler>> = None;
        for (pat, handler) in s.routes.iter() {
            let pb = pat.as_bytes();
            if pb.last() == Some(&b'/')
                && pb.len() > 1
                && path_b.starts_with(pb)
                && pb.len() > best_len
            {
                best_len = pb.len();
                best = Some(handler.clone());
            }
        }
        if let Some(h) = best {
            return (h, crate::gomap::map::<string, string>::new());
        }
        // 3. Wildcard pattern match (registration order).
        let host = r.Host.clone();
        for pr in s.pattern_routes.iter() {
            if let Some(bindings) = pr.pattern.Match(&r.Method, &host, &r.URL.Path) {
                return (pr.handler.clone(), bindings);
            }
        }
        // 4. Fallback to the bare `/` catchall, if registered.
        for (pat, handler) in s.routes.iter() {
            if pat.as_bytes() == b"/" {
                return (handler.clone(), crate::gomap::map::<string, string>::new());
            }
        }
        // 5. Method mismatch → 405 with an Allow header. Go's mux
        //    (routing errMethodMismatch, server.go:2746): when no
        //    pattern matched the request but at least one
        //    method-prefixed pattern matches the path under a
        //    different method, reply 405 listing the allowed methods
        //    instead of 404.
        if let Some(allow) = allowed_methods(&s, &host, &r.URL.Path) {
            return (
                Arc::new(methodNotAllowedHandler { allow }) as Arc<dyn Handler>,
                crate::gomap::map::<string, string>::new(),
            );
        }
        (
            Arc::new(notFoundHandler) as Arc<dyn Handler>,
            crate::gomap::map::<string, string>::new(),
        )
    }
}

/// Scan the wildcard-pattern table for method-prefixed patterns whose
/// host+path would match `r` under *their own* method. Returns the
/// deduplicated `Allow:` header value ("GET, POST"), or `None` if no
/// pattern matches the path at all (a plain 404). Mirrors
/// `mux.tree.matchingMethods` (Go routing_tree.go:229).
fn allowed_methods(s: &MuxState, host: &string, path: &string) -> Option<string> {
    let mut methods: Vec<string> = Vec::new();
    for pr in s.pattern_routes.iter() {
        if pr.pattern.Method.Len() == 0 {
            continue;
        }
        if pr.pattern.Match(&pr.pattern.Method, host, path).is_some()
            && !methods.iter().any(|m| *m == pr.pattern.Method)
        {
            methods.push(pr.pattern.Method.clone());
        }
    }
    if methods.is_empty() {
        return None;
    }
    // Go: strings.Join(methods, ", ")
    Some(strings::Join(
        crate::goslice::slice::<string>::__from_vec(methods),
        string(", "),
    ))
}

/// The 405 responder synthesized for method-mismatch routes
/// (Go server.go:2749).
struct methodNotAllowedHandler {
    allow: string,
}
impl Handler for methodNotAllowedHandler {
    fn ServeHTTP(&self, w: &(dyn ResponseWriter + Send + Sync + 'static), _r: &Request) {
        w.Header().Set(string("Allow"), self.allow.clone());
        Error(
            w,
            super::status::StatusText(super::status::StatusMethodNotAllowed),
            super::status::StatusMethodNotAllowed,
        );
    }
}

impl ServeMux {
    /// `mux.Handler(r) -> (Handler, pattern)` (server.go:2683) — return
    /// the handler that would dispatch `r`, along with the pattern that
    /// matched. For requests with no matching route, returns the
    /// `NotFoundHandler` and an empty pattern.
    ///
    /// Slim port: doesn't trigger redirects (Go's Handler synthesizes
    /// a `RedirectHandler` for missing-trailing-slash cases); doesn't
    /// populate path-value wildcards on `r`.
    pub fn Handler(&self, r: &Request) -> (Arc<dyn Handler>, string) {
        let s = self.state.Lock();
        // 1. Exact literal match.
        for route in s.routes.iter() {
            if route.0 == r.URL.Path {
                return (route.1.clone(), route.0.clone());
            }
        }
        // 2. Longest multi-segment prefix-with-trailing-slash match.
        //    `/` deferred to step 4 so wildcards can win.
        let path_b = r.URL.Path.as_bytes();
        let mut best_len: usize = 0;
        let mut best: Option<(Arc<dyn Handler>, string)> = None;
        for (pat, handler) in s.routes.iter() {
            let pb = pat.as_bytes();
            if pb.last() == Some(&b'/')
                && pb.len() > 1
                && path_b.starts_with(pb)
                && pb.len() > best_len
            {
                best_len = pb.len();
                best = Some((handler.clone(), pat.clone()));
            }
        }
        if let Some(b) = best {
            return b;
        }
        // 3. Wildcard pattern match.
        let host = r.Host.clone();
        for pr in s.pattern_routes.iter() {
            if pr
                .pattern
                .Match(&r.Method, &host, &r.URL.Path)
                .is_some()
            {
                return (pr.handler.clone(), pr.pattern.Str.clone());
            }
        }
        // 4. Fallback to bare `/` catchall, if any.
        for (pat, handler) in s.routes.iter() {
            if pat.as_bytes() == b"/" {
                return (handler.clone(), pat.clone());
            }
        }
        // 5. Method mismatch → synthesized 405 handler (Go returns
        //    it with an empty pattern string, server.go:2749).
        if let Some(allow) = allowed_methods(&s, &r.Host, &r.URL.Path) {
            return (
                Arc::new(methodNotAllowedHandler { allow }) as Arc<dyn Handler>,
                string::new(),
            );
        }
        (
            Arc::new(notFoundHandler) as Arc<dyn Handler>,
            string::new(),
        )
    }
}

impl Handler for ServeMux {
    fn ServeHTTP(&self, w: &(dyn ResponseWriter + Send + Sync + 'static), r: &Request) {
        let (h, bindings) = self.match_handler(r);
        if bindings.Len() == 0 {
            h.ServeHTTP(w, r);
        } else {
            // Clone the request and attach path-value bindings before
            // dispatching, so r.PathValue(name) inside the handler
            // sees the bindings from the matched pattern.
            let mut r2 = r.clone();
            r2.__set_path_values(bindings);
            h.ServeHTTP(w, &r2);
        }
    }
}

/// Default 404 handler. Internal type returned by Go's
/// `http.NotFoundHandler()`. The lowercase name keeps the public
/// surface symmetric with Go (which exposes only the function form
/// `NotFoundHandler() Handler`, not a struct of the same name).
struct notFoundHandler;
impl Handler for notFoundHandler {
    fn ServeHTTP(&self, w: &(dyn ResponseWriter + Send + Sync + 'static), _r: &Request) {
        w.WriteHeader(404);
        let _ = w.Write(crate::convert::bytes("404 page not found\n"));
    }
}

/// `http.Error(w, error, code)` (server.go:2337) — write a plain-text
/// HTTP error response. Resets Content-Type to text/plain, sets
/// X-Content-Type-Options: nosniff, deletes any prior Content-Length,
/// then writes status + body + trailing newline.
pub fn Error<S: Into<string>>(w: &(dyn ResponseWriter + Send + Sync + 'static), error: S, code: int) {
    // Go: h := w.Header(); h.Del("Content-Length")
    w.Header().Del(string("Content-Length"));
    // Go: h.Set("Content-Type", "text/plain; charset=utf-8")
    w.Header()
        .Set(string("Content-Type"), string("text/plain; charset=utf-8"));
    // Go: h.Set("X-Content-Type-Options", "nosniff")
    w.Header()
        .Set(string("X-Content-Type-Options"), string("nosniff"));
    // Go: w.WriteHeader(code)
    w.WriteHeader(code);
    // Go: fmt.Fprintln(w, error) — writes message + "\n"
    let _ = w.Write(crate::convert::bytes(error.into()));
    let _ = w.Write(crate::convert::bytes("\n"));
}

/// `http.NotFound(w, r)` (server.go:2358) — convenience wrapper.
pub fn NotFound(w: &(dyn ResponseWriter + Send + Sync + 'static), _r: &Request) {
    Error(w, string("404 page not found"), super::status::StatusNotFound);
}

/// `http.NotFoundHandler()` (server.go:2362) — returns a Handler that
/// replies to every request with a 404 not-found error. Faithfully
/// matches Go's `return HandlerFunc(NotFound)`; goish wraps the
/// internal `notFoundHandler` struct in `Arc<dyn Handler>` to fit
/// the same plumbing as `StripPrefix` / `RedirectHandler`.
pub fn NotFoundHandler() -> Arc<dyn Handler> {
    // Go: return HandlerFunc(NotFound)
    Arc::new(notFoundHandler)
}

// ─── NewServeMux ─────────────────────────────────────────────────────

/// `http.NewServeMux()` (server.go:2619) — allocates and returns a new
/// ServeMux. The Go form is `func NewServeMux() *ServeMux`; goish hands
/// back `Arc<ServeMux>` so the value can flow into `Server.Handler`
/// directly without an extra `Arc::new(...)` at the call site.
pub fn NewServeMux() -> Arc<ServeMux> {
    // Go: return &ServeMux{}
    Arc::new(ServeMux::new())
}

// ─── DefaultServeMux + Handle / HandleFunc free fns ──────────────────

/// `http.DefaultServeMux` (server.go:2570) — process-wide singleton
/// ServeMux. Used by the free `http::Handle` / `http::HandleFunc`
/// helpers so that small examples can register routes without
/// constructing a ServeMux manually.
pub fn DefaultServeMux() -> Arc<ServeMux> {
    use crate::runtime::spin::SpinLock;
    static SLOT: SpinLock<Option<Arc<ServeMux>>> = SpinLock::new(None);
    let mut g = SLOT.lock();
    if g.is_none() {
        *g = Some(Arc::new(ServeMux::new()));
    }
    g.as_ref().unwrap().clone()
}

/// `http.Handle(pattern, h)` (server.go:2576) — register on
/// DefaultServeMux. Mirrors the free function shape. Generic over
/// `H: Handler + 'static` so callers can pass bare structs.
pub fn Handle<H: Handler + 'static>(pattern: string, h: H) {
    DefaultServeMux().Handle(pattern, h);
}

/// `http::handler(h)` — wrap any `Handler + 'static` into the
/// `Arc<dyn Handler>` shape required by `Server.Handler` field
/// assignment. Saves the user from typing `Arc::new(h) as
/// Arc<dyn http::Handler>` at the boundary.
pub fn handler<H: Handler + 'static>(h: H) -> Arc<dyn Handler> {
    Arc::new(h)
}

/// `http.HandleFunc(pattern, fn)` (server.go:2583) — register a
/// closure on DefaultServeMux. Note this is a *free function*; the
/// same-named method on `ServeMux` registers on a specific mux.
pub fn HandleFunc<F>(pattern: string, f: F)
where
    F: Fn(&(dyn ResponseWriter + Send + Sync + 'static), &Request) + Send + Sync + 'static,
{
    DefaultServeMux().HandleFunc(pattern, f);
}

// ─── StripPrefix / Redirect / RedirectHandler ────────────────────────
//
// Line-by-line ports of net/http/server.go:2370 / :2403 / :2488.

/// `http.StripPrefix(prefix, h)` (server.go:2370). Returns a handler
/// that trims `prefix` from `r.URL.Path` (and `RawPath` if set)
/// before delegating to `h`. If the request path doesn't begin with
/// `prefix`, the handler replies with 404.
///
/// Generic over `H: Handler + 'static` — accepts bare structs,
/// `Arc<dyn Handler>`, etc. without explicit `Arc::new` at the call
/// site.
pub fn StripPrefix<P: Into<string>, H: Handler + 'static>(
    prefix: P,
    h: H,
) -> Arc<dyn Handler> {
    let prefix: string = prefix.into();
    let h: Arc<dyn Handler> = Arc::new(h);
    // Go: if prefix == "" { return h }
    if prefix.Len() == 0 {
        return h;
    }
    Arc::new(stripPrefixHandler { prefix, inner: h })
}

struct stripPrefixHandler {
    prefix: string,
    inner: Arc<dyn Handler>,
}

impl Handler for stripPrefixHandler {
    fn ServeHTTP(&self, w: &(dyn ResponseWriter + Send + Sync + 'static), r: &Request) {
        // Go: p := strings.TrimPrefix(r.URL.Path, prefix)
        let p = crate::strings::TrimPrefix(r.URL.Path.clone(), self.prefix.clone());
        // Go: rp := strings.TrimPrefix(r.URL.RawPath, prefix)
        let rp = crate::strings::TrimPrefix(r.URL.RawPath.clone(), self.prefix.clone());
        // Go: if len(p) < len(r.URL.Path) && (r.URL.RawPath == "" || len(rp) < len(r.URL.RawPath)) { … }
        if p.Len() < r.URL.Path.Len()
            && (r.URL.RawPath.Len() == 0 || rp.Len() < r.URL.RawPath.Len())
        {
            // Go: r2 := *r; r2.URL = *r.URL; r2.URL.Path = p; r2.URL.RawPath = rp
            let mut r2 = r.clone();
            r2.URL.Path = p;
            r2.URL.RawPath = rp;
            self.inner.ServeHTTP(w, &r2);
        } else {
            // Go: NotFound(w, r)
            notFoundHandler.ServeHTTP(w, r);
        }
    }
}

/// `http.TimeoutHandler(h, dt, msg)` (server.go:3775) — returns a
/// Handler that runs `h` with the given time limit.
///
/// The wrapped handler runs on its own goroutine against a buffered
/// writer. If it finishes within `dt`, the buffered status, headers,
/// and body are copied to the real ResponseWriter. If the deadline
/// fires first, the caller gets `503 Service Unavailable` with `msg`
/// as the body (or Go's default HTML timeout page when `msg` is
/// empty), and the handler's subsequent writes return
/// `ErrHandlerTimeout`. The handler observes the deadline through
/// `r.Context().Done()` — the request is re-parented under
/// `context.WithTimeout`, exactly like Go.
pub fn TimeoutHandler<H: Handler + 'static, S: Into<string>>(
    h: H,
    dt: time::Duration,
    msg: S,
) -> Arc<dyn Handler> {
    Arc::new(timeoutHandler {
        handler: Arc::new(h),
        body: msg.into(),
        dt,
    })
}

/// Go's unexported `timeoutHandler` (server.go:3808).
struct timeoutHandler {
    handler: Arc<dyn Handler>,
    body: string,
    dt: time::Duration,
}

impl timeoutHandler {
    /// `(h *timeoutHandler).errorBody()` (server.go:3821).
    fn errorBody(&self) -> string {
        if self.body.Len() > 0 {
            return self.body.clone();
        }
        string::from_static(
            "<html><head><title>Timeout</title></head><body><h1>Timeout</h1></body></html>",
        )
    }
}

impl Handler for timeoutHandler {
    fn ServeHTTP(&self, w: &(dyn ResponseWriter + Send + Sync + 'static), r: &Request) {
        // Go: ctx, cancelCtx = context.WithTimeout(r.Context(), h.dt); defer cancelCtx()
        let (ctx, cancel) = crate::context::WithTimeout(r.Context(), self.dt);
        // Go: r = r.WithContext(ctx)
        let r2 = r.WithContext(ctx.clone());

        // Go: done := make(chan struct{}); close(done) on completion.
        let done: crate::chan<()> = crate::chan::<()>::new_unbuffered();
        let tw = Arc::new(timeoutWriter::new());

        // Go: go func() { h.handler.ServeHTTP(tw, r); close(done) }()
        // (the panicChan arm is dropped: goish builds with
        // panic="abort", so a panicking handler ends the process
        // before recovery could run).
        {
            let handler = self.handler.clone();
            let tw = tw.clone();
            let done = done.clone();
            go!(move || {
                handler.ServeHTTP(&*tw, &r2);
                done.Close();
            });
        }

        // Go: case <-done: / case <-ctx.Done():
        let done_arm: bool = crate::select! {
            let _ = done.Recv() => true,
            let _ = (ctx.Done()).Recv() => false,
        };
        if done_arm {
            // Handler finished in time — replay its buffered response.
            tw.copy_to(w);
        } else {
            // Deadline fired first (ctx.Err() == DeadlineExceeded —
            // cancellation can't race us here because `cancel` is
            // only called below). Go: w.WriteHeader(503) + errorBody,
            // tw.err = ErrHandlerTimeout.
            tw.mark_timed_out();
            w.WriteHeader(super::status::StatusServiceUnavailable);
            let _ = w.Write(crate::convert::bytes(self.errorBody()));
        }
        cancel();
    }
}

/// Go's unexported `timeoutWriter` (server.go:3866) — the buffered
/// ResponseWriter handed to the wrapped handler.
struct timeoutWriter {
    /// tw.h — headers the handler sets while it still owns the budget.
    header: super::response::HeaderHandle,
    state: crate::runtime::spin::SpinLock<twState>,
}

struct twState {
    /// tw.wbuf — buffered body bytes.
    buf: Vec<u8>,
    /// tw.code / tw.wroteHeader.
    code: int,
    wrote_header: bool,
    /// tw.err — set to ErrHandlerTimeout once the deadline fired;
    /// later writes are discarded with that error.
    timed_out: bool,
}

impl timeoutWriter {
    fn new() -> Self {
        timeoutWriter {
            header: super::response::HeaderHandle::new(super::header::Header::new()),
            state: crate::runtime::spin::SpinLock::new(twState {
                buf: Vec::new(),
                code: 0,
                wrote_header: false,
                timed_out: false,
            }),
        }
    }

    fn mark_timed_out(&self) {
        self.state.lock().timed_out = true;
    }

    /// The `case <-done:` copy-out (server.go:3852): headers, then
    /// status (default 200), then the buffered body.
    fn copy_to(&self, w: &(dyn ResponseWriter + Send + Sync + 'static)) {
        let g = self.state.lock();
        let hdr = self.header.snapshot();
        let dst = w.Header();
        for (k, vv) in hdr.__inner().__iter() {
            for i in 0..vv.Len() {
                dst.Add(k.clone(), vv[i].clone());
            }
        }
        let code = if g.wrote_header {
            g.code
        } else {
            super::status::StatusOK
        };
        w.WriteHeader(code);
        let _ = w.Write(crate::goslice::slice::<crate::types::byte>::__from_vec(
            g.buf.clone(),
        ));
    }
}

impl ResponseWriter for timeoutWriter {
    fn Header(&self) -> super::response::HeaderHandle {
        self.header.clone()
    }

    fn Write(&self, p: crate::goslice::slice<crate::types::byte>) -> (int, error) {
        let mut g = self.state.lock();
        // Go: if tw.err != nil { return 0, tw.err }
        if g.timed_out {
            return (0, ErrHandlerTimeout.into());
        }
        g.buf.extend_from_slice(&*p);
        (p.len() as int, errors::nil)
    }

    fn WriteHeader(&self, statusCode: int) {
        let mut g = self.state.lock();
        // Go: if tw.err != nil || tw.wroteHeader { return }
        if g.timed_out || g.wrote_header {
            return;
        }
        g.wrote_header = true;
        g.code = statusCode;
    }

    fn __goish_as_dyn_any(&self) -> Option<&(dyn core::any::Any + Send + Sync)> {
        Some(self)
    }
}

/// `http.Redirect(w, r, url, code)` (server.go:2403). Replies with a
/// redirect to `url`. Slim port: relative paths are resolved against
/// `r.URL.Path` via `path::Clean` + `path::Split`.
pub fn Redirect<U: Into<string>>(w: &(dyn ResponseWriter + Send + Sync + 'static), r: &Request, url: U, code: int){
    let url: string = url.into();
    let mut url = url;

    // Go: if u, err := url.Parse(url); err == nil { … relative resolve … }
    // Slim: detect relative by absence of "://" and leading "/".
    let absolute = crate::strings::Contains(url.clone(), string("://"));
    if !absolute {
        let url_b = url.as_bytes();
        let leading_slash = !url_b.is_empty() && url_b[0] == b'/';
        if !leading_slash {
            // Go: olddir, _ := path.Split(oldpath); url = olddir + url
            let oldpath = if r.URL.Path.Len() == 0 {
                string("/")
            } else {
                r.URL.Path.clone()
            };
            let (olddir, _) = crate::path::Split(oldpath);
            let mut b = crate::strings::Builder::new();
            let _ = b.WriteString(olddir);
            let _ = b.WriteString(url);
            url = b.String();
        }
        // Go: split off ?query, clean, restore query
        let q_idx = crate::strings::Index(url.clone(), string("?"));
        let (path_part, query_part) = if q_idx >= 0 {
            let (p, q, _) = crate::strings::Cut(url.clone(), string("?"));
            (p, {
                let mut b = crate::strings::Builder::new();
                let _ = b.WriteByte(b'?');
                let _ = b.WriteString(q);
                b.String()
            })
        } else {
            (url, string::new())
        };
        // Go: trailing := strings.HasSuffix(url, "/"); url = path.Clean(url); if trailing { url += "/" }
        let trailing = crate::strings::HasSuffix(path_part.clone(), string("/"));
        let mut cleaned = crate::path::Clean(path_part);
        if trailing && !crate::strings::HasSuffix(cleaned.clone(), string("/")) {
            let mut b = crate::strings::Builder::new();
            let _ = b.WriteString(cleaned);
            let _ = b.WriteByte(b'/');
            cleaned = b.String();
        }
        let mut b = crate::strings::Builder::new();
        let _ = b.WriteString(cleaned);
        let _ = b.WriteString(query_part);
        url = b.String();
    }

    // Go: h := w.Header()
    let had_ct = w.Header().Get(string("Content-Type")).Len() > 0;
    // Go: h.Set("Location", hexEscapeNonASCII(url))
    w.Header().Set(string("Location"), url.clone());
    // Go: if !hadCT && (r.Method == "GET" || r.Method == "HEAD") { h.Set("Content-Type", "text/html; charset=utf-8") }
    if !had_ct && (r.Method == "GET" || r.Method == "HEAD") {
        w.Header()
            .Set(string("Content-Type"), string("text/html; charset=utf-8"));
    }
    // Go: w.WriteHeader(code)
    w.WriteHeader(code);
    // Go: if !hadCT && r.Method == "GET" { body := "<a href=\"...\">"+StatusText(code)+"</a>"; fmt.Fprintln(w, body) }
    if !had_ct && r.Method == "GET" {
        let mut b = crate::strings::Builder::new();
        let _ = b.WriteString("<a href=\"");
        let _ = b.WriteString(html_escape(url));
        let _ = b.WriteString("\">");
        let _ = b.WriteString(super::status::StatusText(code));
        let _ = b.WriteString("</a>.\n");
        let body = b.String();
        let _ = w.Write(crate::convert::bytes(body));
    }
}

/// `http.RedirectHandler(url, code)` (server.go:2488). Returns a
/// handler that redirects all requests to `url` with the given status.
pub fn RedirectHandler<U: Into<string>>(url: U, code: int) -> Arc<dyn Handler> {
    let url: string = url.into();
    Arc::new(redirectHandler { url, code })
}

struct redirectHandler {
    url: string,
    code: int,
}

impl Handler for redirectHandler {
    fn ServeHTTP(&self, w: &(dyn ResponseWriter + Send + Sync + 'static), r: &Request) {
        Redirect(w, r, self.url.clone(), self.code);
    }
}

// ─── AllowQuerySemicolons ────────────────────────────────────────────

/// `http.AllowQuerySemicolons(h)` (server.go:3354). Returns a handler
/// that converts unescaped `;` characters in `r.URL.RawQuery` to `&`
/// before delegating to `h`. Restores the pre-Go-1.17 query parsing
/// behavior. Should be invoked before `Request.ParseForm`.
pub fn AllowQuerySemicolons(h: Arc<dyn Handler>) -> Arc<dyn Handler> {
    Arc::new(allowQuerySemicolonsHandler { inner: h })
}

struct allowQuerySemicolonsHandler {
    inner: Arc<dyn Handler>,
}

impl Handler for allowQuerySemicolonsHandler {
    fn ServeHTTP(&self, w: &(dyn ResponseWriter + Send + Sync + 'static), r: &Request) {
        // Go: if strings.Contains(r.URL.RawQuery, ";") {
        if strings::Contains(r.URL.RawQuery.clone(), string(";")) {
            // Go: r2 := new(Request); *r2 = *r
            // Go: r2.URL = new(url.URL); *r2.URL = *r.URL
            // Go: r2.URL.RawQuery = strings.ReplaceAll(r.URL.RawQuery, ";", "&")
            let mut r2 = r.clone();
            r2.URL.RawQuery =
                strings::ReplaceAll(r.URL.RawQuery.clone(), string(";"), string("&"));
            // Go: h.ServeHTTP(w, r2)
            self.inner.ServeHTTP(w, &r2);
        } else {
            // Go: h.ServeHTTP(w, r)
            self.inner.ServeHTTP(w, r);
        }
    }
}

/// Line-by-line port of `htmlEscape` (server.go:2468) using a single
/// strings::Builder pass instead of strings.NewReplacer.
fn html_escape(s: string) -> string {
    let mut b = crate::strings::Builder::new();
    b.Grow(s.Len());
    for i in 0..s.Len() {
        let c: crate::types::byte = s[i];
        match c {
            b'&' => {
                let _ = b.WriteString("&amp;");
            }
            b'<' => {
                let _ = b.WriteString("&lt;");
            }
            b'>' => {
                let _ = b.WriteString("&gt;");
            }
            b'"' => {
                let _ = b.WriteString("&#34;");
            }
            b'\'' => {
                let _ = b.WriteString("&#39;");
            }
            _ => {
                let _ = b.WriteByte(c);
            }
        }
    }
    b.String()
}

// ─── Server ──────────────────────────────────────────────────────────

/// `http.Server` (server.go:2993). v1 subset of fields; the rest
/// (TLSConfig, ConnState, BaseContext, etc.) is deferred.
///
/// **Construction**: start from `Server::default()` (or
/// `Server::new(handler)`), mutate the public-config fields, then
/// `Arc::new(srv)`. The `..Default::default()` struct-update syntax
/// is unavailable from external crates because internal-state
/// fields are private; the default-and-mutate pattern is
/// equivalent.
///
/// ```ignore
/// let mut srv = http::Server::default();
/// srv.Addr = string(":8080");
/// srv.Handler = mux;
/// srv.ReadHeaderTimeout = time::Second * 5;
/// let srv = alloc::sync::Arc::new(srv);
/// let srv2 = srv.clone();
/// go!(stack(64 * KB), move || { let _ = srv2.ListenAndServe(); });
/// // ...
/// let _ = srv.Shutdown(time::Second * 5);
/// ```
pub struct Server {
    /// `host:port` to listen on. Empty = ":80".
    pub Addr: string,
    /// Handler that dispatches requests. Use a `ServeMux` for routing.
    pub Handler: Arc<dyn Handler>,
    /// Maximum duration for the entire request (header + body). Zero
    /// or negative disables. Mirrors `Server.ReadTimeout` (server.go:3015).
    pub ReadTimeout: time::Duration,
    /// Maximum duration to read the request headers. Zero falls back
    /// to `ReadTimeout`. If both are zero/negative, the v1 fallback
    /// `DEFAULT_READ_HEADER_TIMEOUT` (5s) prevents idle keep-alive
    /// conns from pinning goroutines forever — Go has no such
    /// implicit fallback (zero = no timeout) but goish v1 makes it
    /// explicit because there's no signal-driven cleanup yet.
    pub ReadHeaderTimeout: time::Duration,
    /// Maximum duration before timing out writes of the response.
    /// Reset whenever a new request's headers are read. Zero or
    /// negative = no timeout.
    pub WriteTimeout: time::Duration,
    /// Idle keep-alive timeout. Zero falls back to `ReadHeaderTimeout`.
    pub IdleTimeout: time::Duration,
    /// Cap on bytes per request line / per header line, in bytes.
    /// `<= 0` falls back to the parser default (8 KiB). Mirrors
    /// `Server.MaxHeaderBytes` (server.go:3072).
    pub MaxHeaderBytes: crate::types::int,
    /// Cap on the number of connections being served concurrently.
    /// `0` means unlimited (Go's default behavior).
    /// `> 0` makes the accept loop block once this many connections
    /// are in flight, providing backpressure under load instead of
    /// spawning unbounded goroutines.
    pub MaxConcurrentConns: crate::types::int,

    /// Internal runtime state. Bundled behind a single field so users
    /// can construct a `Server` with Go-style struct literal syntax —
    /// `Server { Addr, Handler, ..., ..Default::default() }` — without
    /// being blocked by E0451 ("private field") errors. The field is
    /// public-by-name but its type (`__ServerState`) is private, so
    /// outside callers can't directly construct or inspect it.
    #[doc(hidden)]
    pub __state: __ServerState,
}

/// Internal Server state — type is private, the holding field on
/// `Server` is `pub` only so struct-update literal syntax works.
#[doc(hidden)]
pub struct __ServerState {
    in_shutdown: AtomicBool,
    active_conns: AtomicUsize,
    /// Bounded semaphore for `MaxConcurrentConns`. `None` until Serve
    /// initializes it; capacity = `MaxConcurrentConns`. Each accepted
    /// conn pushes one token and drains it on completion. Send blocks
    /// when the chan is full ⇒ accept loop pauses.
    conn_sem: Mutex<Option<crate::gochan::chan<()>>>,
    /// Tracked listener for shutdown. `Mutex<Option<...>>` so the
    /// Serve goroutine can install it on entry and Shutdown can
    /// take it out (close it + wake parked Accept) from another
    /// goroutine. Held inside an `Arc<Listener>` because the Serve
    /// loop also needs read access to call Accept.
    tracked_listener: Mutex<Option<Arc<net::Listener>>>,
    /// Per-connection state registry — Go's `Server.activeConn` set
    /// (server.go:3097) backing `closeIdleConns` (server.go:3229).
    /// Each serve_conn inserts its `ConnTrack` on entry and removes
    /// it on exit; `Shutdown`/`Close` walk it to kick parked conns.
    tracked_conns: Mutex<Vec<Arc<ConnTrack>>>,
    /// `RegisterOnShutdown` callbacks — Go's `Server.onShutdown`
    /// (server.go:3101); each is spawned on its own goroutine once
    /// when Shutdown/Close begins.
    on_shutdown: Mutex<Vec<Arc<dyn Fn() + Send + Sync>>>,
}

/// Go `ConnState` subset tracked per connection (server.go:3520):
/// enough for `closeIdleConns`' quiescence test. Hooks
/// (`Server.ConnState`) stay deferred.
const CONN_STATE_NEW: u8 = 0;
const CONN_STATE_ACTIVE: u8 = 1;
const CONN_STATE_IDLE: u8 = 2;

/// Per-connection tracking record — goish's rendering of Go's
/// `conn.curState` packed atomic (server.go:299,
/// `packed (unixtime<<8|uint8(ConnState))`) plus the netpoll handle
/// the shutdown path needs to kick a parked reader.
pub(crate) struct ConnTrack {
    /// CONN_STATE_* value.
    state: AtomicU8,
    /// CLOCK_MONOTONIC ns of the last state transition (Go stores
    /// unix seconds; monotonic avoids wall-clock jumps and only
    /// differences are consulted).
    since_ns: AtomicI64,
    /// The conn's read-side PollDesc address, for the past-deadline
    /// kick (goish `aLongTimeAgo`). Go closes `c.rwc` outright; the
    /// deadline slam is the goish-safe equivalent — the owning
    /// serve_conn observes the timeout error and closes the fd
    /// itself, so the fd always has exactly one closer.
    pd_addr: AtomicUsize,
}

impl ConnTrack {
    fn set_state(&self, st: u8) {
        self.since_ns
            .store(crate::runtime::sysmon::monotonic_ns(), Ordering::Relaxed);
        self.state.store(st, Ordering::Release);
    }
}

crate::var! {
    /// `http.ErrServerClosed` (server.go:36).
    pub ErrServerClosed: error    = "http: Server closed";

    /// `http.ErrBodyNotAllowed` (server.go:43).
    pub ErrBodyNotAllowed: error  = "http: request method or response status code does not allow body";

    /// `http.ErrHijacked` (server.go:50).
    pub ErrHijacked: error        = "http: connection has been hijacked";

    /// `http.ErrContentLength` (server.go:56).
    pub ErrContentLength: error   = "http: wrote more than the declared Content-Length";

    /// `http.ErrAbortHandler` (server.go:1909).
    pub ErrAbortHandler: error    = "net/http: abort Handler";

    /// `http.ErrHandlerTimeout` (server.go:3829).
    pub ErrHandlerTimeout: error  = "http: Handler timeout";
}

/// v1 fallback when both ReadHeaderTimeout and ReadTimeout are zero
/// — bounds idle keep-alive at 5 seconds.
const DEFAULT_READ_HEADER_TIMEOUT_NS: i64 = 5_000_000_000;

/// Resolved wait policy for `Server::Shutdown`.
#[doc(hidden)]
pub enum __ShutdownWait {
    /// Absolute CLOCK_MONOTONIC deadline ns (`i64::MAX` = forever).
    Deadline(i64),
    /// Live context — Shutdown returns `ctx.Err()` once it is done.
    Ctx(Arc<dyn crate::context::Context>),
}

/// Argument polymorphism for `Server::Shutdown`: Go's signature is
/// `Shutdown(ctx context.Context)`; goish also keeps the original
/// `Shutdown(timeout time.Duration)` convenience for existing
/// callers. Same pattern as `impl Into<string>` parameters.
#[doc(hidden)]
pub trait __ShutdownArg {
    fn __into_shutdown_wait(self) -> __ShutdownWait;
}

impl __ShutdownArg for time::Duration {
    fn __into_shutdown_wait(self) -> __ShutdownWait {
        if self.0 > 0 {
            __ShutdownWait::Deadline(
                crate::runtime::sysmon::monotonic_ns().wrapping_add(self.0 as i64),
            )
        } else {
            __ShutdownWait::Deadline(i64::MAX)
        }
    }
}

impl __ShutdownArg for Arc<dyn crate::context::Context> {
    fn __into_shutdown_wait(self) -> __ShutdownWait {
        __ShutdownWait::Ctx(self)
    }
}

impl Default for Server {
    fn default() -> Self {
        Server {
            Addr: string::new(),
            Handler: Arc::new(notFoundHandler) as Arc<dyn Handler>,
            ReadTimeout: time::Duration(0),
            ReadHeaderTimeout: time::Duration(0),
            WriteTimeout: time::Duration(0),
            IdleTimeout: time::Duration(0),
            MaxHeaderBytes: 0,
            MaxConcurrentConns: 0,
            __state: __ServerState::default(),
        }
    }
}

impl Default for __ServerState {
    fn default() -> Self {
        __ServerState {
            in_shutdown: AtomicBool::new(false),
            active_conns: AtomicUsize::new(0),
            tracked_listener: Mutex::new(None),
            conn_sem: Mutex::new(None),
            tracked_conns: Mutex::new(Vec::new()),
            on_shutdown: Mutex::new(Vec::new()),
        }
    }
}

impl Server {
    /// Convenience constructor — equivalent to `Server::default()` with
    /// `Handler` set to `handler`. Other fields stay at their defaults
    /// (zero timeouts, empty Addr → `:80`).
    pub fn new(handler: Arc<dyn Handler>) -> Self {
        let mut s = Server::default();
        s.Handler = handler;
        s
    }

    /// `(*Server).ListenAndServe` (server.go:3377) — bind to `Addr`
    /// and run the accept loop. Returns ErrServerClosed after a
    /// successful Shutdown, or the underlying network error otherwise.
    pub fn ListenAndServe(self: Arc<Self>) -> error {
        let addr = if self.Addr.Len() == 0 {
            string(":80")
        } else {
            self.Addr.clone()
        };
        let (ln, err) = net::Listen(string("tcp"), addr);
        if !err.IsNil() {
            return err;
        }
        self.Serve(ln)
    }

    /// `(*Server).Serve(l)` (server.go:3433) — accept loop on a
    /// pre-bound Listener. Tracks the listener so `Shutdown` can
    /// break the Accept loop and close the socket.
    pub fn Serve(self: Arc<Self>, ln: net::Listener) -> error {
        let ln = Arc::new(ln);
        // Install tracked_listener + initialize conn_sem (if backpressure
        // configured) under one critical section; check in_shutdown
        // atomically. Without this, a Shutdown that wins the race vs
        // Serve's entry would observe an empty tracked_listener (so
        // __wake_accept and Close run on nothing), and Serve would
        // later install its listener and enter Accept on a fd that was
        // never closed → permanent park.
        {
            let mut tracked = self.__state.tracked_listener.Lock();
            if self.__state.in_shutdown.load(Ordering::Acquire) {
                return ErrServerClosed.into();
            }
            *tracked = Some(ln.clone());
            if self.MaxConcurrentConns > 0 {
                let cap = self.MaxConcurrentConns as usize;
                *self.__state.conn_sem.Lock() =
                    Some(crate::gochan::chan::<()>::new_buffered(cap));
            }
        }

        // Snapshot the chan handle once so subsequent Send/Recv on it
        // never hold the conn_sem mutex (Send blocks when the chan is
        // full; if we held the mutex we'd deadlock the workers'
        // drain side).
        let sem_handle: Option<crate::gochan::chan<()>> = if self.MaxConcurrentConns > 0 {
            self.__state.conn_sem.Lock().clone()
        } else {
            None
        };

        // Go's accept-failure backoff (server.go:3421-3446): on a
        // temporary error (EMFILE/ENFILE/resource exhaustion), sleep
        // 5ms doubling to 1s and retry instead of killing the server.
        let mut temp_delay_ns: i64 = 0;

        loop {
            // Backpressure: if MaxConcurrentConns is set, block here
            // until a slot opens up. Each per-conn goroutine drains
            // its slot on completion.
            if let Some(ref sem) = sem_handle {
                sem.Send(());
            }

            let (conn, err, temporary) = ln.__accept_classified();
            if !err.IsNil() {
                // Release the slot we just acquired since no goroutine
                // will drain it.
                if let Some(ref sem) = sem_handle {
                    let _ = sem.__try_recv();
                }
                if self.__state.in_shutdown.load(Ordering::Acquire) {
                    return ErrServerClosed.into();
                }
                if temporary {
                    if temp_delay_ns == 0 {
                        temp_delay_ns = 5_000_000; // 5ms
                    } else {
                        temp_delay_ns *= 2;
                    }
                    if temp_delay_ns > 1_000_000_000 {
                        temp_delay_ns = 1_000_000_000; // 1s cap
                    }
                    time::Sleep(time::Duration(temp_delay_ns));
                    continue;
                }
                return err;
            }
            temp_delay_ns = 0;
            let srv = self.clone();
            let release_sem = sem_handle.clone();
            // 64 KiB stack — ample for the per-handler chain.
            go!(stack(64 * 1024), move || {
                srv.serve_conn(conn);
                if let Some(ref sem) = release_sem {
                    let _ = sem.__try_recv();
                }
            });
        }
    }

    /// `(*Server).Shutdown(timeout)` — graceful shutdown. Closes the
    /// tracked listener (causing Accept to return ErrServerClosed),
    /// then polls active connection count until it reaches zero or
    /// `timeout` elapses. Mirrors Go's `Server.Shutdown(ctx)`
    /// (server.go:3179) with a Duration in place of context.
    ///
    /// `timeout <= 0` (Duration form) waits indefinitely. On expiry,
    /// the Duration form returns `"shutdown: timeout"`; the Context
    /// form returns `ctx.Err()` (Go parity, server.go:3208).
    ///
    /// **Drain semantics** (Go closeIdleConns, server.go:3229):
    /// connections parked waiting for the next keep-alive request
    /// are actively kicked — each poll round slams a past read
    /// deadline on every Idle conn (and every New conn that has not
    /// produced a request header within 5s — Go issue 22682), so the
    /// parked read returns immediately and the conn closes.
    pub fn Shutdown<A: __ShutdownArg>(self: Arc<Self>, arg: A) -> error {
        let wait = arg.__into_shutdown_wait();

        // Set the shutdown flag and take the listener under one lock
        // so Serve's mirror-image install/check sees a consistent
        // state. Without this, a Serve that hadn't reached its
        // tracked_listener install yet could install AFTER Shutdown
        // observed None and proceeded — leaving a fd open with no
        // wakeup.
        let listener = {
            let mut tracked = self.__state.tracked_listener.Lock();
            self.__state.in_shutdown.store(true, Ordering::Release);
            tracked.take()
        };

        // Order matters: wake first (so Accept's netpoll::block
        // returns Timedout and the goroutine resumes), then close
        // the fd (so the next Accept4 retry returns EBADF).
        if let Some(ln) = listener {
            ln.__wake_accept();
            let _ = ln.Close();
        }

        // Spawn RegisterOnShutdown callbacks, each on its own
        // goroutine (Go server.go:3184-3186).
        {
            let hooks: Vec<Arc<dyn Fn() + Send + Sync>> =
                self.__state.on_shutdown.Lock().clone();
            for f in hooks {
                go!(move || f());
            }
        }

        // Poll active_conns down to 0, kicking idle conns each round
        // (Go's Shutdown loop over closeIdleConns, server.go:3202).
        // Exponential backoff capped at 100ms. Re-kicking every round
        // also closes the small race where a conn re-arms its own
        // read deadline over our slam.
        let mut sleep_ns: i64 = 1_000_000; // 1ms
        loop {
            self.kick_tracked_conns(false);
            if self.__state.active_conns.load(Ordering::Acquire) == 0 {
                return errors::nil;
            }
            match &wait {
                __ShutdownWait::Deadline(d) => {
                    if crate::runtime::sysmon::monotonic_ns() >= *d {
                        return errors::New(string("shutdown: timeout"));
                    }
                }
                __ShutdownWait::Ctx(ctx) => {
                    let e = ctx.Err();
                    if !e.IsNil() {
                        return e;
                    }
                }
            }
            time::Sleep(time::Duration(sleep_ns));
            sleep_ns = (sleep_ns * 2).min(100_000_000); // cap 100ms
        }
    }

    /// `(*Server).Close` (server.go:3129) — immediately close the
    /// listener and kick every tracked connection regardless of
    /// state. Does not wait for handlers to finish (use `Shutdown`
    /// for graceful drain). In-flight handlers observe read/write
    /// errors on their next conn operation.
    pub fn Close(self: Arc<Self>) -> error {
        let listener = {
            let mut tracked = self.__state.tracked_listener.Lock();
            self.__state.in_shutdown.store(true, Ordering::Release);
            tracked.take()
        };
        if let Some(ln) = listener {
            ln.__wake_accept();
            let _ = ln.Close();
        }
        {
            let hooks: Vec<Arc<dyn Fn() + Send + Sync>> =
                self.__state.on_shutdown.Lock().clone();
            for f in hooks {
                go!(move || f());
            }
        }
        self.kick_tracked_conns(true);
        errors::nil
    }

    /// `(*Server).RegisterOnShutdown(f)` (server.go:3221) — register
    /// a callback to run (on its own goroutine) when `Shutdown` or
    /// `Close` begins.
    pub fn RegisterOnShutdown(&self, f: Arc<dyn Fn() + Send + Sync>) {
        self.__state.on_shutdown.Lock().push(f);
    }

    /// Kick tracked connections so their parked reads return — the
    /// working half of Go's `closeIdleConns` (server.go:3229). With
    /// `all == false`, kicks Idle conns plus New conns older than 5s
    /// (Go issue 22682: a conn that never sent a request header);
    /// with `all == true` (`Close`), kicks everything.
    ///
    /// The kick is a past netpoll read+write deadline rather than an
    /// out-of-band `close(2)`: the owning serve_conn sees the timeout
    /// error and closes the fd itself, keeping single-owner fd
    /// discipline (no close/reuse race with an in-flight read).
    fn kick_tracked_conns(&self, all: bool) {
        let now = crate::runtime::sysmon::monotonic_ns();
        let conns: Vec<Arc<ConnTrack>> = self.__state.tracked_conns.Lock().clone();
        for t in conns {
            let st = t.state.load(Ordering::Acquire);
            let kick = all
                || st == CONN_STATE_IDLE
                || (st == CONN_STATE_NEW
                    && now.wrapping_sub(t.since_ns.load(Ordering::Relaxed))
                        > 5_000_000_000);
            if !kick {
                continue;
            }
            let pd_addr = t.pd_addr.load(Ordering::Acquire);
            if pd_addr != 0 {
                let pd = unsafe { &*(pd_addr as *const crate::runtime::netpoll::PollDesc) };
                crate::runtime::netpoll::set_deadline(pd, -1, b'r');
                if all {
                    crate::runtime::netpoll::set_deadline(pd, -1, b'w');
                }
            }
        }
    }

    /// Per-connection serving loop. See keep-alive doc (M27f-β).
    fn serve_conn(self: Arc<Self>, mut conn: net::TCPConn) {
        // Drop guard ensures active_conns is decremented (and the
        // conn's tracking record removed) even if a handler panics or
        // an early return path is taken.
        struct ActiveGuard<'a> {
            count: &'a AtomicUsize,
            server: &'a __ServerState,
            track: Arc<ConnTrack>,
        }
        impl Drop for ActiveGuard<'_> {
            fn drop(&mut self) {
                self.server
                    .tracked_conns
                    .Lock()
                    .retain(|t| !Arc::ptr_eq(t, &self.track));
                self.count.fetch_sub(1, Ordering::AcqRel);
            }
        }
        self.__state.active_conns.fetch_add(1, Ordering::AcqRel);
        // Register the conn for shutdown kicks — Go's
        // `c.setState(StateNew)` + activeConn insert (server.go:3457).
        let (_, watch_pd_early) = conn.__disconnect_watch_parts();
        let track = Arc::new(ConnTrack {
            state: AtomicU8::new(CONN_STATE_NEW),
            since_ns: AtomicI64::new(crate::runtime::sysmon::monotonic_ns()),
            pd_addr: AtomicUsize::new(watch_pd_early as usize),
        });
        self.__state.tracked_conns.Lock().push(track.clone());
        let _guard = ActiveGuard {
            count: &self.__state.active_conns,
            server: &self.__state,
            track: track.clone(),
        };

        let read_header_ns = self.read_header_timeout_ns();
        let idle_ns = self.idle_timeout_ns();
        let write_timeout_ns = self.write_timeout_ns();
        let mut first_request = true;

        loop {
            if self.__state.in_shutdown.load(Ordering::Acquire) {
                let _ = conn.Close();
                return;
            }

            // Arm the wait-for-request read deadline. First request:
            // ReadHeaderTimeout. Between keep-alive requests: the
            // idle bound — Go arms `idleTimeout()` while waiting for
            // the next request's first byte (server.go:2135). Cleared
            // after the headers parse so handler body reads aren't
            // artificially capped (large uploads).
            let wait_ns = if first_request { read_header_ns } else { idle_ns };
            first_request = false;
            let dl = time::Now().Add(time::Duration(wait_ns));
            let _ = conn.SetReadDeadline(dl);

            let (mut req, err) = {
                let mut br = bufio::NewReader(&mut conn);
                ReadRequestWithLimit(&mut br, self.MaxHeaderBytes)
            };
            if !err.IsNil() {
                // EOF, parse error, or idle timeout — all close the conn.
                let _ = conn.Close();
                return;
            }
            // Clear the read deadline once headers are parsed.
            let _ = conn.SetReadDeadline(time::Time::default());
            // Request in flight — Go's `c.setState(StateActive)`
            // (server.go:2043): shutdown's idle-kick skips us now.
            track.set_state(CONN_STATE_ACTIVE);
            // Apply WriteTimeout for the response phase if configured.
            if write_timeout_ns > 0 {
                let wdl = time::Now().Add(time::Duration(write_timeout_ns));
                let _ = conn.SetWriteDeadline(wdl);
            }

            // ── per-request context (Go readRequest, server.go:1112) ──
            // Every incoming request carries a cancellable context:
            // canceled when the response is finished, or earlier by
            // the disconnect watcher below if the client goes away
            // while the handler is still running.
            let (req_ctx, req_cancel) = crate::context::WithCancel(crate::context::Background());
            req.ctx = Some(req_ctx);
            let req_cancel: Arc<crate::context::CancelFunc> = Arc::new(req_cancel);

            // ── client-disconnect watcher (Go startBackgroundRead,
            // server.go:735) ──  A helper goroutine MSG_PEEKs the
            // socket and parks on the netpoller; if the peer closes
            // or resets while the handler runs, it cancels the
            // request context. Aborted + joined right after the
            // handler returns (Go abortPendingRead) so the keep-alive
            // loop regains exclusive read ownership of the fd.
            let (watch_fd, watch_pd) = conn.__disconnect_watch_parts();
            let watcher_done: Option<crate::gochan::chan<()>> = if !watch_pd.is_null() {
                let ch = crate::gochan::chan::<()>::new_unbuffered();
                let ch2 = ch.clone();
                let cancel2 = req_cancel.clone();
                let pd_addr = watch_pd as usize;
                go!(move || {
                    if background_disconnect_watch(watch_fd, pd_addr) {
                        (cancel2)();
                    }
                    ch2.Close();
                });
                Some(ch)
            } else {
                None
            };

            let keep_alive = request_keep_alive(&req)
                && !self.__state.in_shutdown.load(Ordering::Acquire);
            let w = response::new(conn);
            w.__set_keep_alive(keep_alive);
            // HEAD: handler writes are eaten by the response writer
            // (Go's `isHEAD` at server.go:1302, eat-writes at :1339).
            w.__set_head(req.Method == string("HEAD"));

            // Close the conn fd if the handler panics. Without this,
            // gogo recovery abandons the `response` (whose Drop
            // is skipped under panic = "abort") and the client hangs
            // on Read forever waiting for data / EOF that never come.
            // The defer! body always runs at scope exit; `recover!()`
            // distinguishes the panic path from normal exit so the fd
            // survives for keep-alive reuse on success.
            let fd = w.__conn_fd();
            crate::defer!{
                if crate::recover!() != crate::nil {
                    let _ = crate::syscall::Close(fd);
                }
            }
            self.Handler.ServeHTTP(&w, &req);

            // Handler done — abort + join the watcher before touching
            // the conn's read side again (Go abortPendingRead,
            // server.go:756). set_deadline(-1) wakes a parked watcher
            // with Timedout; the Recv on its done chan is the join.
            if let Some(ch) = watcher_done {
                crate::runtime::netpoll::set_deadline(unsafe { &*watch_pd }, -1, b'r');
                let _ = ch.Recv();
            }

            conn = w.__take_conn();
            // Response finished → cancel the request context (Go
            // finishRequest → w.cancelCtx(), server.go:1683).
            (req_cancel)();

            if write_timeout_ns > 0 {
                let _ = conn.SetWriteDeadline(time::Time::default());
            }

            if !keep_alive {
                let _ = conn.Close();
                return;
            }
            // Response finished, conn waiting for its next request —
            // Go's `c.setState(StateIdle)` (server.go:2131): shutdown
            // may kick us from here on.
            track.set_state(CONN_STATE_IDLE);
        }
    }

    /// Resolve effective read-header timeout: `ReadHeaderTimeout` if
    /// set, else `ReadTimeout`, else the v1 default (5s).
    fn read_header_timeout_ns(&self) -> i64 {
        if self.ReadHeaderTimeout.0 > 0 {
            self.ReadHeaderTimeout.0 as i64
        } else if self.ReadTimeout.0 > 0 {
            self.ReadTimeout.0 as i64
        } else {
            DEFAULT_READ_HEADER_TIMEOUT_NS
        }
    }

    /// Resolve the idle keep-alive bound — Go's `Server.idleTimeout()`
    /// (server.go:3636): `IdleTimeout` if set, else `ReadTimeout`.
    /// goish keeps its v1 safety net when both are zero (Go leaves
    /// idle conns unbounded; goish falls back to the header timeout
    /// so an abandoned keep-alive conn always drains).
    fn idle_timeout_ns(&self) -> i64 {
        if self.IdleTimeout.0 > 0 {
            self.IdleTimeout.0 as i64
        } else if self.ReadTimeout.0 > 0 {
            self.ReadTimeout.0 as i64
        } else {
            self.read_header_timeout_ns()
        }
    }

    fn write_timeout_ns(&self) -> i64 {
        if self.WriteTimeout.0 > 0 {
            self.WriteTimeout.0 as i64
        } else {
            0
        }
    }
}

/// Client-disconnect watcher body — goish's rendering of Go's
/// `connReader.backgroundRead` (server.go:735). Runs on its own
/// goroutine while a handler executes. Probes the socket with
/// `recv(MSG_PEEK | MSG_DONTWAIT)` — peeking never consumes a
/// pipelined next request — and parks on the netpoller between
/// probes.
///
/// Returns `true` iff the client went away (EOF / reset) and the
/// request context should be canceled. Returns `false` when either
/// pipelined data shows up (next keep-alive request — stop watching,
/// the conn is fine) or the serve loop aborted the watch by setting
/// a past read deadline (`netpoll::set_deadline(pd, -1, 'r')` — the
/// goish `aLongTimeAgo` abort).
///
/// `pd_addr` is the conn's `PollDesc` as a usize (raw pointers are
/// not `Send`; the address crosses the `go!` closure instead). The
/// serve loop joins this goroutine before closing or reusing the
/// conn, so the PollDesc outlives every dereference here.
fn background_disconnect_watch(fd: i32, pd_addr: usize) -> bool {
    const EINTR: i32 = 4;
    const EAGAIN: i32 = 11;
    let pd = unsafe { &*(pd_addr as *const crate::runtime::netpoll::PollDesc) };
    let mut probe = [0u8; 1];
    loop {
        let n = crate::syscall::Recvfrom(
            fd,
            probe.as_mut_ptr(),
            1,
            crate::syscall::MSG_PEEK | crate::syscall::MSG_DONTWAIT,
        );
        if n > 0 {
            // Pipelined next request — client is alive; stop
            // watching (Go remembers the byte; peeking means we
            // don't have to).
            return false;
        }
        if n == 0 {
            // Orderly shutdown from the peer.
            return true;
        }
        let errno = -(n as i32);
        if errno == EINTR {
            continue;
        }
        if errno == EAGAIN {
            match crate::runtime::netpoll::block(pd, b'r') {
                // Readable edge (data or EOF/RDHUP) — loop and peek.
                crate::runtime::netpoll::BlockResult::Ready
                | crate::runtime::netpoll::BlockResult::Aborted => continue,
                // Past-deadline abort from the serve loop: handler
                // finished first.
                crate::runtime::netpoll::BlockResult::Timedout => return false,
            }
        }
        // ECONNRESET and friends — connection is gone.
        return true;
    }
}

// ─── Free-function wrappers (Go-faithful one-liners) ─────────────────

/// `http.ListenAndServe(addr, handler)` — bind + accept loop +
/// goroutine-per-connection dispatch. Blocks until the server is
/// shut down (returns ErrServerClosed) or the underlying Listen
/// fails.
///
/// Mirrors Go's `func ListenAndServe(addr string, handler Handler) error`
/// (server.go:3702). For per-server config (timeouts, shutdown), use
/// `http::Server` directly.
pub fn ListenAndServe<A: Into<string>>(addr: A, handler: Arc<dyn Handler>) -> error {
    let addr: string = addr.into();
    let srv = Arc::new(Server {
        Addr: addr,
        Handler: handler,
        ..Default::default()
    });
    srv.ListenAndServe()
}

/// `http.Serve(l, handler)` — accept loop on a pre-bound Listener.
/// Mirrors Go's `func Serve(l net.Listener, handler Handler) error`
/// (server.go:3676). For per-server config / shutdown, use
/// `http::Server::Serve`.
pub fn Serve(ln: net::Listener, handler: Arc<dyn Handler>) -> error {
    let srv = Arc::new(Server {
        Handler: handler,
        ..Default::default()
    });
    srv.Serve(ln)
}

/// Decide whether to keep the connection alive after this request.
/// Mirrors Go's `Request.shouldClose()` (request.go:1450) inverted.
///
/// HTTP/1.1: keep-alive default; `Connection: close` opts out.
/// HTTP/1.0: close default; `Connection: keep-alive` opts in.
fn request_keep_alive(req: &Request) -> bool {
    let conn_hdr = req.Header.Get(string("Connection"));
    let conn_bytes = conn_hdr.as_bytes();
    let says_close = ascii_eq_ignore_case(conn_bytes, b"close");
    let says_keep_alive = ascii_eq_ignore_case(conn_bytes, b"keep-alive");
    if req.ProtoMajor == 1 && req.ProtoMinor >= 1 {
        !says_close
    } else {
        says_keep_alive
    }
}

fn ascii_eq_ignore_case(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    for i in 0..a.len() {
        let x = a[i] | 0x20;
        let y = b[i] | 0x20;
        if x != y {
            return false;
        }
    }
    true
}
