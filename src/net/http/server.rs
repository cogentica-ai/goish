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

use super::request::Request;
use super::responsewriter::{response, ResponseWriter};

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
    /// Go's `ServeMux.tree routingNode` (server.go:2500) — the decision
    /// tree that decides precedence GLOBALLY by pattern specificity.
    ///
    /// This replaced a pair of `Vec`s scanned in five hand-rolled
    /// steps, whose own comment admitted "Go 1.22's mux compares
    /// pattern specificity globally; we approximate by deferring `/`
    /// to step 4". Under that scheme two patterns Go orders by
    /// specificity dispatched by REGISTRATION ORDER instead.
    tree: super::routing_tree::routingNode,
    /// Go's `ServeMux.index routingIndex` (server.go:2501) — narrows
    /// the conflict check to patterns that could possibly overlap, so
    /// registration stays sub-quadratic.
    index: super::routing_index::routingIndex,
}


impl ServeMux {
    pub fn new() -> Self {
        ServeMux {
            state: Arc::new(Mutex::new(MuxState {
                tree: super::routing_tree::routingNode::default(),
                index: super::routing_index::routingIndex::default(),
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
    // go: sdk 1.25.5 net/http/server.go:2915-2956 ServeMux.registerErr
    //
    /// Register `handler` for `pattern`, or return the reason it
    /// cannot be.
    ///
    /// The conflict check is the substance. Go rejects two patterns
    /// that both match some path where NEITHER is more specific —
    /// "/q/" and "/{a}/{b}" both match "/q/b", so registering both is
    /// an ERROR rather than a silent precedence coin-flip. goish
    /// previously kept a list of pattern strings and caught only the
    /// exact duplicate, so a genuine overlap was accepted and then
    /// resolved arbitrarily.
    ///
    /// Divergence: Go decorates each pattern with `runtime.Caller(3)`
    /// so the message names both registration SITES. goish has no
    /// caller introspection here, so the message carries the two
    /// patterns and the conflict description without file:line.
    fn registerErr(&self, patstr: string, h: Arc<dyn Handler>) -> error {
        if patstr == "" {
            return errors::New(string("http: invalid pattern"));
        }
        let (pat, perr) = super::pattern::parsePattern(patstr.clone());
        if !perr.IsNil() {
            return crate::fmt::Errorf!("parsing %q: %v", patstr, perr);
        }
        let mut st = self.state.Lock();
        // Go: check for conflict.
        let conflict = {
            let patref = &pat;
            let mut probe = |pat2: &super::pattern::pattern| -> error {
                if patref.conflictsWith(pat2) {
                    let d = super::pattern::describeConflict(patref, pat2);
                    return crate::fmt::Errorf!(
                        "pattern %q conflicts with pattern %q:\n%v",
                        patref.str.clone(),
                        pat2.str.clone(),
                        d
                    );
                }
                return errors::nil;
            };
            st.index.possiblyConflictingPatterns(patref, &mut probe)
        };
        if !conflict.IsNil() {
            return conflict;
        }
        st.tree.addPattern(&pat, h);
        st.index.addPattern(&pat);
        return errors::nil;
    }

    // go: sdk 1.25.5 net/http/server.go:2909-2913 ServeMux.register
    //
    // Go panics on registerErr's error, and so does this — a
    // conflicting or malformed pattern is a programming mistake that
    // Handle has no way to report.
    fn handle_arc(&self, pattern: string, h: Arc<dyn Handler>) {
        let err = self.registerErr(pattern, h);
        if !err.IsNil() {
            panic!("{}", err.Error());
        }
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
    // go: sdk 1.25.5 net/http/server.go:2695-2749 ServeMux.findHandler
    //
    // Go strips the port from the Host, cleans the path, then asks the
    // tree. The trailing-slash redirect (`matchOrRedirect`) and the
    // CONNECT special case are NOT yet implemented — noted rather than
    // faked, since both change which handler runs.
    fn match_handler(
        &self,
        r: &Request,
    ) -> (
        Arc<dyn Handler>,
        crate::gomap::map<string, string>,
    ) {
        let (h, _pat, binds) = self.find_node(r);
        return (h, binds);
    }

    /// Shared body of `match_handler` and `Handler`: resolve a request
    /// through the routing tree, returning the handler, the matched
    /// pattern string and the wildcard bindings.
    fn find_node(
        &self,
        r: &Request,
    ) -> (
        Arc<dyn Handler>,
        string,
        crate::gomap::map<string, string>,
    ) {
        let host = stripHostPort(r.Host.clone());
        let path = cleanPath(r.URL.Path.clone());
        let s = self.state.Lock();
        // Go: if the given path is /tree and its handler is not
        // registered, redirect for /tree/ (findHandler, server.go:2865).
        if let Some(u) = self.matchOrRedirect(&s, &host, &r.Method, &path, Some(&r.URL)) {
            let target = u.String();
            return (
                RedirectHandler(target.clone(), super::status::StatusMovedPermanently),
                target,
                crate::gomap::map::<string, string>::new(),
            );
        }
        // Go: if path != escapedPath { redirect to the cleaned path }
        // (findHandler, server.go:2879-2891).
        //
        // This branch was MISSING. goish cleaned the path for MATCHING
        // and then served the handler directly, so "/a/./b" and
        // "//double" returned 200 where Go returns 301 to "/a/b" and
        // "/double".
        //
        // The gap is not just a missing redirect. Because goish went
        // straight to the handler, the handler ran with the UNCLEANED
        // `r.URL.Path` while the mux had routed on the cleaned one —
        // so any handler or middleware doing its own prefix check on
        // r.URL.Path saw a different path than the routing decision
        // was made from. That mismatch is the classic shape of a
        // path-based access-control bypass.
        if path != r.URL.EscapedPath() {
            let mut u = super::url::URL::empty();
            u.Path = path.clone();
            u.RawPath = path.clone();
            u.RawQuery = r.URL.RawQuery.clone();
            let target = u.String();
            return (
                RedirectHandler(target.clone(), super::status::StatusMovedPermanently),
                target,
                crate::gomap::map::<string, string>::new(),
            );
        }
        let (n, matches) = s.tree.r#match(&host, &r.Method, &path);
        if let Some(n) = n {
            if let Some(h) = n.handler.clone() {
                let pat = n.pattern.as_ref();
                let mut binds: crate::gomap::map<string, string> =
                    crate::gomap::map::<string, string>::new();
                // The tree returns POSITIONAL matches; name them by
                // zipping against the pattern's wild segments, in
                // order, the way Go's ServeHTTP does with
                // r.SetPathValue.
                if let Some(p) = pat {
                    let mut mi: int = 0;
                    let segs = &p.segments;
                    let sn = crate::len(segs);
                    let mut si: int = 0;
                    while si < sn {
                        let seg = &segs[si];
                        si += 1;
                        if !seg.wild || seg.s.Len() == 0 {
                            continue;
                        }
                        if mi < crate::len(&matches) {
                            binds.Set(seg.s.clone(), matches[mi].clone());
                            mi += 1;
                        }
                    }
                }
                let patstr = match pat {
                    Some(p) => p.str.clone(),
                    None => string::new(),
                };
                return (h, patstr, binds);
            }
        }
        // Go: no pattern matched this method, but one may match the
        // path under a different method — reply 405 with Allow.
        let mut methodSet: crate::gomap::map<string, bool> =
            crate::gomap::map::<string, bool>::new();
        s.tree.matchingMethods(&host, &path, &mut methodSet);
        if methodSet.Len() > 0 {
            let mut allow: Vec<string> = Vec::new();
            for (m, _) in methodSet.__iter() {
                allow.push(m.clone());
            }
            allow.sort_by(|a, b| strings::Compare(a.clone(), b.clone()).cmp(&0));
            let joined = strings::Join(
                crate::goslice::slice::__from_vec(allow),
                string(", "),
            );
            return (
                Arc::new(methodNotAllowedHandler { allow: joined }) as Arc<dyn Handler>,
                string::new(),
                crate::gomap::map::<string, string>::new(),
            );
        }
        return (
            Arc::new(notFoundHandler) as Arc<dyn Handler>,
            string::new(),
            crate::gomap::map::<string, string>::new(),
        );
    }
}

// go: none — goish-only. Go builds the 405 inline in ServeMux.ServeHTTP
// rather than through a named handler type; this wraps the same
// response so `Handler(r)` can return it as a Handler.
struct methodNotAllowedHandler {
    allow: string,
}

impl Handler for methodNotAllowedHandler {
    // go: none — see above.
    fn ServeHTTP(&self, w: &(dyn ResponseWriter + Send + Sync + 'static), _r: &Request) {
        w.Header().Set(string("Allow"), self.allow.clone());
        Error(
            w,
            super::status::StatusText(super::status::StatusMethodNotAllowed),
            super::status::StatusMethodNotAllowed,
        );
    }
}

// go: sdk 1.25.5 net/http/server.go:2805-2827 exactMatch
//
/// Reports whether the node's pattern matched `path` EXACTLY — with an
/// empty match for a trailing multi wildcard.
///
/// Go's comment explains why the test is structural: "We can't
/// directly implement the definition (empty match for multi wildcard)
/// because we don't record a match for anonymous multis." A pattern
/// whose last segment is not a multi always matched exactly; a multi
/// matched emptily only when the path ends in '/' AND the pattern has
/// as many segments as the path has slashes. That last clause is what
/// makes "/a/b/{$}" and "/a/b/{rest...}" exact for "/a/b/" while "/a/"
/// is not.
pub fn exactMatch(n: Option<&super::routing_tree::routingNode>, path: &string) -> bool {
    let n = match n {
        None => return false,
        Some(n) => n,
    };
    let pat = match n.pattern.as_ref() {
        None => return false,
        Some(p) => p,
    };
    if !pat.lastSegment().multi {
        return true;
    }
    if path.Len() > 0 && path[path.Len() - 1] != b'/' {
        return false;
    }
    return crate::len(&pat.segments) == strings::Count(path.clone(), string("/"));
}

impl ServeMux {
    // go: sdk 1.25.5 net/http/server.go:2757-2777 ServeMux.matchOrRedirect
    //
    /// Match `path`; if it does not match exactly but the same path
    /// WITH a trailing slash does, return the URL to redirect to.
    ///
    /// This is why a request for "/dir" reaches a handler registered
    /// as "/dir/" — via a 301 to "/dir/", not by matching it directly.
    ///
    // goishlint:ignore GOISH020 matchOrRedirect — Go takes the lock
    // INSIDE this method (`mux.mu.RLock(); defer mux.mu.RUnlock()`);
    // goish's only caller, find_node, already holds the guard, so it
    // is passed in rather than re-acquired. Re-locking a non-reentrant
    // Mutex here would deadlock. Hence six parameters where Go has
    // five.
    fn matchOrRedirect(
        &self,
        s: &MuxState,
        host: &string,
        method: &string,
        path: &string,
        u: Option<&super::url::URL>,
    ) -> Option<super::url::URL> {
        let (n, _matches) = s.tree.r#match(host, method, path);
        // Go: if we have an exact match, or were asked not to try
        // trailing-slash redirection, or the URL already ends in one,
        // we are done.
        if !exactMatch(n, path) && u.is_some() && !strings::HasSuffix(path.clone(), string("/")) {
            let slashed = path.clone() + "/";
            let (n2, _) = s.tree.r#match(host, method, &slashed);
            if exactMatch(n2, &slashed) {
                let uu = u.unwrap();
                let mut redirect = super::url::URL::empty();
                redirect.Path = cleanPath(uu.Path.clone()) + "/";
                redirect.RawQuery = uu.RawQuery.clone();
                return Some(redirect);
            }
        }
        return None;
    }

    // go: sdk 1.25.5 net/http/server.go:2683-2689 ServeMux.Handler
    //
    /// Return the handler that would dispatch `r`, along with the
    /// pattern that matched. With no matching route, returns the
    /// NotFoundHandler and an empty pattern.
    ///
    /// Not yet faithful: Go's Handler synthesises a RedirectHandler
    /// for a missing trailing slash (`matchOrRedirect`); this does
    /// not.
    pub fn Handler(&self, r: &Request) -> (Arc<dyn Handler>, string) {
        let (h, pat, _binds) = self.find_node(r);
        return (h, pat);
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

// go: sdk 1.25.5 net/http/server.go:2337-2355 Error
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

// go: sdk 1.25.5 net/http/server.go:2358-2358 NotFound
/// `http.NotFound(w, r)` (server.go:2358) — convenience wrapper.
pub fn NotFound(w: &(dyn ResponseWriter + Send + Sync + 'static), _r: &Request) {
    Error(w, string("404 page not found"), super::status::StatusNotFound);
}

// go: sdk 1.25.5 net/http/server.go:2362-2362 NotFoundHandler
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

// go: sdk 1.25.5 net/http/server.go:2370-2389 StripPrefix
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

// go: sdk 1.25.5 net/http/server.go:3816-3822 TimeoutHandler
//
/// Returns a Handler that runs `h` with the given time limit.
///
/// Verified against goref on the three observables: a handler that
/// finishes in time passes its own status, headers and body through
/// untouched; one that overruns yields 503 with Go's DEFAULT HTML
/// timeout page when `msg` is empty, or `msg` verbatim when it is
/// not. The default page is a byte-exact string Go hard-codes — a
/// port that invented its own wording would look right in a browser
/// and differ on the wire.
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
// go: sdk 1.25.5 net/http/server.go:3828-3836 timeoutHandler
struct timeoutHandler {
    handler: Arc<dyn Handler>,
    body: string,
    dt: time::Duration,
}

impl timeoutHandler {
    /// `(h *timeoutHandler).errorBody()` (server.go:3821).
    // go: sdk 1.25.5 net/http/server.go:3838-3843 timeoutHandler.errorBody
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
    header: super::responsewriter::HeaderHandle,
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
            header: super::responsewriter::HeaderHandle::new(super::header::Header::new()),
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
    fn Header(&self) -> super::responsewriter::HeaderHandle {
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

// go: sdk 1.25.5 net/http/server.go:2403-2456 Redirect
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
    // Go: if !hadCT && r.Method == "GET" {
    //         body := "<a href=\""+htmlEscape(url)+"\">"+StatusText(code)+"</a>.\n"
    //         fmt.Fprintln(w, body) }
    //
    // TWO trailing newlines, not one: the literal already ends in "\n"
    // and Fprintln appends another. goish emitted a single "\n", which
    // is a one-byte difference in every GET redirect body.
    if !had_ct && r.Method == "GET" {
        let mut b = crate::strings::Builder::new();
        let _ = b.WriteString("<a href=\"");
        let _ = b.WriteString(htmlEscape(url));
        let _ = b.WriteString("\">");
        let _ = b.WriteString(super::status::StatusText(code));
        let _ = b.WriteString("</a>.\n");
        let _ = b.WriteString("\n");
        let body = b.String();
        let _ = w.Write(crate::convert::bytes(body));
    }
}

// go: sdk 1.25.5 net/http/server.go:2488-2490 RedirectHandler
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

// go: sdk 1.25.5 net/http/server.go:3354-3367 AllowQuerySemicolons
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

// go: sdk 1.25.5 net/http/server.go:2468-2470 htmlEscape
/// Line-by-line port of `htmlEscape` (server.go:2468) using a single
/// strings::Builder pass instead of strings.NewReplacer.
pub fn htmlEscape(s: string) -> string {
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
/// `Server.BaseContext`'s function shape (server.go:3081). Named
/// alias so the `Arc<dyn Fn>` plumbing stays out of user-facing
/// struct literals — same pattern as `client::ProxyResolver`.
pub type BaseContextFn = Arc<
    dyn Fn(&net::Listener) -> Arc<dyn crate::context::Context> + Send + Sync,
>;

/// `Server.ConnContext`'s function shape (server.go:3087).
pub type ConnContextFn = Arc<
    dyn Fn(Arc<dyn crate::context::Context>, &net::TCPConn) -> Arc<dyn crate::context::Context>
        + Send
        + Sync,
>;

pub struct Server {
    /// `host:port` to listen on. Empty = ":80".
    pub Addr: string,
    /// Handler that dispatches requests. Use a `ServeMux` for routing.
    pub Handler: Arc<dyn Handler>,
    /// `Server.DisableGeneralOptionsHandler` (server.go:3004) — Go: "if
    /// true, passes 'OPTIONS *' requests to the Handler, otherwise
    /// responds with 200 OK and Content-Length: 0."
    pub DisableGeneralOptionsHandler: bool,
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
    /// `Server.BaseContext` (server.go:3081) — optionally returns
    /// the base context for incoming requests on this server; called
    /// once per `Serve` with the listener. `None` → `Background()`.
    pub BaseContext: Option<BaseContextFn>,
    /// `Server.ConnContext` (server.go:3087) — optionally modifies
    /// the per-connection context derived from the base context;
    /// called once per accepted connection.
    pub ConnContext: Option<ConnContextFn>,
    /// `Server.ErrorLog` (server.go:3053) — optional logger for
    /// accept errors and handler panics. `None` → the `log` package's
    /// standard logger (stderr).
    pub ErrorLog: Option<Arc<crate::log::Logger>>,

    /// `Server.TLSConfig` (server.go:3006) — optional TLS
    /// configuration for `ServeTLS`/`ListenAndServeTLS`. When set,
    /// its `Certificates` are used; a cert/key file pair passed to
    /// `ServeTLS` still overrides. `None` → the file pair is the only
    /// certificate source.
    pub TLSConfig: Option<crate::crypto::tls::Config>,

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
    /// Go's `Server.disableKeepAlives atomic.Bool` (server.go:3092),
    /// flipped by SetKeepAlivesEnabled and read by doKeepAlives.
    disable_keep_alives: AtomicBool,
    active_conns: AtomicUsize,
    /// Bounded semaphore for `MaxConcurrentConns`. `None` until Serve
    /// initializes it; capacity = `MaxConcurrentConns`. Each accepted
    /// conn pushes one token and drains it on completion. Send blocks
    /// when the chan is full ⇒ accept loop pauses.
    conn_sem: Mutex<Option<crate::gochan::chan<()>>>,
    /// Tracked listeners for shutdown — Go's `Server.listeners`
    /// set (server.go:3096, `map[*net.Listener]struct{}` maintained
    /// by `trackListener` server.go:3253). A `Vec` so N reuseport
    /// listeners served by N `go srv.Serve(ln)` calls are ALL
    /// closed by Shutdown/Close (`closeListenersLocked`,
    /// server.go:3272). Each Serve goroutine installs its listener
    /// on entry and removes it on exit; Shutdown drains the whole
    /// vec (close + wake parked Accepts) from another goroutine.
    /// Entries are `Arc<Listener>` because the Serve loop also
    /// needs read access to call Accept.
    tracked_listeners: Mutex<Vec<Arc<net::Listener>>>,
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

// go: sdk 1.25.5 net/http/server.go:371-374 crlf
pub fn crlf() -> crate::goslice::slice<crate::types::byte> {
    return crate::convert::bytes(string("\r\n"));
}

/// `": "` — the header name/value separator.
pub fn colonSpace() -> crate::goslice::slice<crate::types::byte> {
    return crate::convert::bytes(string(": "));
}

// go: sdk 1.25.5 net/http/server.go:1255-1258 headerContentLength
pub fn headerContentLength() -> crate::goslice::slice<crate::types::byte> {
    return crate::convert::bytes(string("Content-Length: "));
}

/// `"Date: "` — written by extraHeader ahead of the map headers.
pub fn headerDate() -> crate::goslice::slice<crate::types::byte> {
    return crate::convert::bytes(string("Date: "));
}

// go: sdk 1.25.5 net/http/server.go:1240-1246 extraHeader
//
/// The headers the response writer emits from its own fields rather
/// than from the Header map — see [`extraHeaderKeys`], which names the
/// three string-valued ones in the SAME ORDER `Write` iterates them.
///
/// `date` and `contentLength` are byte slices because Go writes them
/// only "if not nil": an empty slice means the header is omitted
/// entirely, which is different from writing it with an empty value.
#[derive(Clone, Default)]
pub struct extraHeader {
    pub contentType: string,
    pub connection: string,
    pub transferEncoding: string,
    /// Written if non-empty.
    pub date: crate::goslice::slice<crate::types::byte>,
    /// Written if non-empty.
    pub contentLength: crate::goslice::slice<crate::types::byte>,
}

impl extraHeader {
    // go: sdk 1.25.5 net/http/server.go:1260-1284 extraHeader.Write
    //
    // Go's note on the value receiver is a performance point that does
    // not carry over: "This method has a value receiver, despite the
    // somewhat large size of h, because it prevents an allocation."
    // goish takes `&self`; there is no escape analysis to defeat.
    //
    // The ORDER is load-bearing: Date and Content-Length first, then
    // the three from extraHeaderKeys, which is why that slice and the
    // field iteration below must stay in step.
    pub fn Write<W: crate::io::Writer>(&self, w: &mut W) {
        if crate::len(&self.date) != 0 {
            let _ = w.Write(headerDate());
            let _ = w.Write(self.date.clone());
            let _ = w.Write(crlf());
        }
        if crate::len(&self.contentLength) != 0 {
            let _ = w.Write(headerContentLength());
            let _ = w.Write(self.contentLength.clone());
            let _ = w.Write(crlf());
        }
        let keys = extraHeaderKeys();
        let vals = [
            self.contentType.clone(),
            self.connection.clone(),
            self.transferEncoding.clone(),
        ];
        let mut i: int = 0;
        while i < 3 {
            let v = vals[i as usize].clone();
            if v != "" {
                let _ = w.Write(keys[i].clone());
                let _ = w.Write(colonSpace());
                let _ = w.Write(crate::convert::bytes(v));
                let _ = w.Write(crlf());
            }
            i += 1;
        }
    }
}

// go: sdk 1.25.5 net/http/server.go:2456-2466 htmlReplacer
//
/// The escaper Redirect's HTML body and dirList's link text go
/// through. Go's own comments explain two choices: `&#34;` is shorter
/// than `&quot;`, and `&#39;` is shorter than `&apos;` — which was not
/// in HTML until HTML5.
///
/// Quoting `'` and `"` is not optional: both goish callers
/// interpolate into an href ATTRIBUTE, where a bare quote escapes it.
pub fn htmlReplacer() -> crate::strings::Replacer {
    return crate::strings::NewReplacer(crate::goslice::slice::__from_vec(alloc::vec![
        string("&"), string("&amp;"),
        string("<"), string("&lt;"),
        string(">"), string("&gt;"),
        string("\""), string("&#34;"),
        string("'"), string("&#39;"),
    ]));
}

// go: sdk 1.25.5 net/http/server.go:834-834 copyBufPool
//
// Go pools fixed [copyBufPoolSize]byte ARRAYS, not slices, which is
// why putCopyBuf can reject a re-sliced buffer by length.
pub fn copyBufPool() -> &'static crate::sync::Pool<crate::goslice::slice<crate::types::byte>> {
    static POOL: crate::lazy::Lazy<crate::sync::Pool<crate::goslice::slice<crate::types::byte>>> =
        crate::lazy::Lazy::new(|| {
            crate::sync::Pool::new(|| {
                crate::goslice::slice::__from_vec(alloc::vec![0u8; copyBufPoolSize as usize])
            })
        });
    return POOL.get();
}

// go: sdk 1.25.5 net/http/server.go:836-838 getCopyBuf
pub fn getCopyBuf() -> crate::goslice::slice<crate::types::byte> {
    return copyBufPool().Get();
}

// go: sdk 1.25.5 net/http/server.go:840-845 putCopyBuf
//
/// Go PANICS on a wrong-sized buffer rather than accepting it: the
/// pool holds fixed arrays, and a short buffer returned to it would
/// later be handed out as if it were full length.
pub fn putCopyBuf(b: crate::goslice::slice<crate::types::byte>) {
    if crate::len(&b) != copyBufPoolSize {
        panic!("trying to put back buffer of the wrong size in the copyBufPool");
    }
    copyBufPool().Put(b);
}

// go: sdk 1.25.5 net/http/server.go:1808-1810 closeWriter
//
/// Go: "closeWriter is an interface that implements CloseWrite." The
/// server asserts a conn to it before the RST-avoidance shutdown, so a
/// transport without half-close is skipped rather than broken.
#[crate::interface] // goishlint:ignore GOISH022 - attribute macro path
pub trait closeWriter {
    fn CloseWrite(&self) -> error;
}

// go: sdk 1.25.5 net/http/server.go:1926-1930 connectionStater
//
/// Asserted on a conn to recover its TLS state without depending on
/// the concrete tls.Conn type.
#[crate::interface] // goishlint:ignore GOISH022 - attribute macro path
pub trait connectionStater {
    fn ConnectionState(&self) -> crate::crypto::tls::ConnectionState;
}

// goishlint:ignore GOISH021 onceCloseListener — the type IS ported,
// directly below; its `// go:` anchor is deliberately omitted so
// GOISH019 does not fire. Go EMBEDS `net.Listener` anonymously, and
// GOISH019's Go parser records no field name for an embedded field,
// so it reads goish's necessarily-named `Listener` field as an
// addition. GOISH019 only supports a FILE-WIDE waiver, which would
// blind every other struct in server.rs — dropping this one anchor is
// the narrower cost. The three methods below stay anchored.
//
/// Go: "onceCloseListener wraps a net.Listener, protecting it from
/// multiple Close calls." (server.go:3956)
///
/// This is not tidiness: Serve and Shutdown can both reach the
/// listener, and closing an fd twice can close a DIFFERENT fd that has
/// since taken the number. The Once makes the second Close a no-op
/// returning the first one's error.
pub struct onceCloseListener {
    pub Listener: Arc<net::Listener>,
    once: crate::sync::Once,
    closeErr: Mutex<error>,
}

impl onceCloseListener {
    // go: none — goish constructor; Go builds the struct literally.
    pub fn new(l: Arc<net::Listener>) -> Self {
        return onceCloseListener {
            Listener: l,
            once: crate::sync::Once::new(),
            closeErr: Mutex::new(errors::nil),
        };
    }

    // go: sdk 1.25.5 net/http/server.go:3964-3967 onceCloseListener.Close
    pub fn Close(&self) -> error {
        self.once.Do(|| {
            self.close();
        });
        return self.closeErr.Lock().clone();
    }

    // go: sdk 1.25.5 net/http/server.go:3969-3969 onceCloseListener.close
    fn close(&self) {
        *self.closeErr.Lock() = self.Listener.Close();
    }
}

// go: sdk 1.25.5 net/http/server.go:3318-3320 serverHandler
//
/// Go: "serverHandler delegates to either the server's Handler or
/// DefaultServeMux and also handles 'OPTIONS *' requests."
pub struct serverHandler {
    pub srv: Arc<Server>,
}

impl Handler for serverHandler {
    // go: sdk 1.25.5 net/http/server.go:3331-3341 serverHandler.ServeHTTP
    //
    // The OPTIONS test reads req.RequestURI, NOT req.URL.Path: the
    // request-target "*" is not a path and does not survive URL
    // parsing, so a check against URL.Path would never fire.
    fn ServeHTTP(&self, rw: &(dyn ResponseWriter + Send + Sync + 'static), req: &Request) {
        // Go: handler := sh.srv.Handler; if handler == nil { handler =
        // DefaultServeMux }. goish's Handler field is a non-optional
        // Arc, so "nil" is not representable and the fallback lives at
        // Server construction instead.
        if !self.srv.DisableGeneralOptionsHandler
            && req.RequestURI == "*"
            && req.Method == "OPTIONS"
        {
            globalOptionsHandler.ServeHTTP(rw, req);
            return;
        }
        self.srv.Handler.ServeHTTP(rw, req);
    }
}

// go: sdk 1.25.5 net/http/server.go:1896-1900 statusError
//
/// Go: "an error used to respond to a request with an HTTP status.
/// The text should be plain text WITHOUT user info or other embedded
/// errors." That constraint is the point — the text reaches the client
/// verbatim, so echoing a parse error into it would leak internals.
#[derive(Clone)]
pub struct statusError {
    pub code: int,
    pub text: string,
}

impl crate::errors::ErrorTrait for statusError {
    // go: sdk 1.25.5 net/http/server.go:1903-1903 statusError.Error
    fn Error(&self) -> string {
        return super::status::StatusText(self.code) + ": " + self.text.clone();
    }
}

// go: sdk 1.25.5 net/http/server.go:1894-1894 badRequestError
pub fn badRequestError<E: Into<string>>(e: E) -> error {
    return errors::New(
        super::status::StatusText(super::status::StatusBadRequest) + ": " + e.into(),
    );
}

// go: sdk 1.25.5 net/http/server.go:3972-3972 globalOptionsHandler
//
/// Handles a bare `OPTIONS *` request.
#[derive(Clone, Copy, Default)]
pub struct globalOptionsHandler;

impl Handler for globalOptionsHandler {
    // go: sdk 1.25.5 net/http/server.go:3974-3985 globalOptionsHandler.ServeHTTP
    //
    // Go reads up to 4 KiB of an OPTIONS body — "as mentioned in the
    // spec as being reserved for future use" — and treats anything
    // larger as "a waste of server resources (or an attack)", aborting
    // via MaxBytesReader's EOF behaviour. goish's Request.Body is an
    // already-read `slice<byte>`, so there is no stream to cap: the
    // bytes are bounded upstream by the server's own read limits, and
    // the drain is a no-op. The Content-Length: 0 reply is the
    // observable part and matches.
    fn ServeHTTP(&self, w: &(dyn ResponseWriter + Send + Sync + 'static), _r: &Request) {
        w.Header().Set(string("Content-Length"), string("0"));
    }
}

// go: sdk 1.25.5 net/http/server.go:512-525 TrailerPrefix
//
/// Go: "TrailerPrefix is a magic prefix for [ResponseWriter.Header]
/// map keys that, if present, signals that the map entry is actually
/// for the response trailers, and not the response headers. The prefix
/// is stripped after the ServeHTTP call finishes and the values are
/// sent in the trailers."
///
/// Go: "This mechanism is intended only for trailers that are NOT
/// known prior to the headers being written. If the set of trailers is
/// fixed or known before the header is written, the normal Go trailers
/// mechanism is preferred."
pub const TrailerPrefix: &str = "Trailer:";

// go: sdk 1.25.5 net/http/server.go:341-341 bufferBeforeChunkingSize
//
// Go: the chunkWriter buffers this much before deciding whether to
// chunk, so a small response can still get a Content-Length.
pub const bufferBeforeChunkingSize: int = 2048;

// go: sdk 1.25.5 net/http/server.go:631-631 debugServerConnections
pub const debugServerConnections: bool = false;

// go: sdk 1.25.5 net/http/server.go:832-832 copyBufPoolSize
pub const copyBufPoolSize: int = 32 * 1024;

// go: sdk 1.25.5 net/http/server.go:1009-1009 errTooLarge
crate::var! {
    pub errTooLarge: error = "http: request too large";
}

// go: sdk 1.25.5 net/http/server.go:1148-1148 maxPostHandlerReadBytes
//
// Go: the maximum number of bytes the server reads off an unread
// request body AFTER the handler returns, so the connection can be
// reused. Past this it gives up and closes instead.
pub const maxPostHandlerReadBytes: int = 256 << 10;

// go: sdk 1.25.5 net/http/server.go:1249-1253 extraHeaderKeys
//
// The header names writeHeader emits from its own `extraHeader`
// struct rather than the Header map, so both are not written.
pub fn extraHeaderKeys() -> crate::goslice::slice<crate::goslice::slice<crate::types::byte>> {
    return crate::goslice::slice::__from_vec(alloc::vec![
        crate::convert::bytes(string("Content-Type")),
        crate::convert::bytes(string("Connection")),
        crate::convert::bytes(string("Transfer-Encoding")),
    ]);
}

// go: sdk 1.25.5 net/http/server.go:1806-1806 rstAvoidanceDelay
//
// Go: how long to wait after a response before closing, so a client
// still writing a request body sees the response rather than a TCP
// RST. A `var` in Go because tests shorten it.
pub fn rstAvoidanceDelay() -> time::Duration {
    return time::Duration(500 * 1_000_000); // 500ms
}

// go: sdk 1.25.5 net/http/server.go:2192-2192 nextProtoUnencryptedHTTP2
pub const nextProtoUnencryptedHTTP2: &str = "unencrypted_http2";

// go: sdk 1.25.5 net/http/server.go:3157-3157 shutdownPollIntervalMax
//
// Go: Shutdown polls for idle connections on a backoff that starts
// small and caps here, so a fast shutdown is not delayed by a fixed
// long interval.
pub fn shutdownPollIntervalMax() -> time::Duration {
    return time::Duration(500 * 1_000_000); // 500ms
}

// go: sdk 1.25.5 net/http/server.go:3266-3266 ConnState
//
/// The state of a client connection to a server, as reported to the
/// `Server.ConnState` hook. The hook itself is still deferred; the
/// type and its states are Go's.
pub type ConnState = int;

// go: sdk 1.25.5 net/http/server.go:3268-3302 StateNew
//
/// Go: "StateNew represents a new connection that is expected to send
/// a request immediately. Connections begin at this state and then
/// transition to either StateActive or StateClosed."
pub const StateNew: ConnState = 0;

/// Go: "StateActive represents a connection that has read 1 or more
/// bytes of a request. […] After the request is handled, the state
/// transitions to StateClosed, StateHijacked, or StateIdle." Note
/// Go's caveat: for HTTP/2 it fires only on the zero-to-one
/// transition, so ConnState cannot be used for per-request work.
pub const StateActive: ConnState = 1;

/// Go: "StateIdle represents a connection that has finished handling
/// a request and is in the keep-alive state, waiting for a new
/// request."
pub const StateIdle: ConnState = 2;

/// Go: "StateHijacked represents a hijacked connection. This is a
/// TERMINAL state. It does not transition to StateClosed."
pub const StateHijacked: ConnState = 3;

/// Go: "StateClosed represents a closed connection. This is a
/// terminal state. Hijacked connections do not transition to
/// StateClosed."
pub const StateClosed: ConnState = 4;

// go: sdk 1.25.5 net/http/server.go:3304-3310 stateName
pub fn stateName() -> crate::gomap::map<ConnState, string> {
    let mut m: crate::gomap::map<ConnState, string> = crate::gomap::map::new();
    m.Set(StateNew, string("new"));
    m.Set(StateActive, string("active"));
    m.Set(StateIdle, string("idle"));
    m.Set(StateHijacked, string("hijacked"));
    m.Set(StateClosed, string("closed"));
    return m;
}

// go: sdk 1.25.5 net/http/server.go:3312-3314 ConnState.String
//
/// Go indexes `stateName` directly, so a value outside the five
/// returns the map's zero value — the EMPTY string, not a
/// "ConnState(7)" rendering. Preserved.
pub fn ConnStateString(c: ConnState) -> string {
    let (n, ok) = stateName().Get(c);
    if !ok {
        return string("");
    }
    return n;
}

// goish tracks the live state in an AtomicU8, which needs the same
// five values at that width. Written as literals rather than a cast of
// the ConnState consts because a const initializer cannot go through
// goish's call-cast; they are kept adjacent so a divergence is visible.
pub(crate) const CONN_STATE_NEW: u8 = 0; // StateNew
pub(crate) const CONN_STATE_ACTIVE: u8 = 1; // StateActive
pub(crate) const CONN_STATE_IDLE: u8 = 2; // StateIdle

/// Per-connection tracking record — goish's rendering of Go's
/// `conn.curState` packed atomic (server.go:299,
/// `packed (unixtime<<8|uint8(ConnState))`) plus the netpoll handle
/// the shutdown path needs to kick a parked reader.
// ─── connReader ─────────────────────────────────────────────────────

// goishlint:ignore GOISH019 connReader — Go's struct carries `rwc`,
// `conn`, `cond` and `byteBuf` alongside the guarded flags. The
// background-read goroutine that needs them is not ported (see the
// note on startBackgroundRead below), so what lands is the READ-LIMIT
// state machine, behind one Mutex rather than `mu` + bare fields.
// go: sdk 1.25.5 net/http/server.go:659-671 connReader
/// Go: "connReader is the io.Reader wrapper used by *conn. It combines
/// a selectively-activated io.LimitedReader (to bound request header
/// read sizes) with support for selectively keeping an io.Reader.Read
/// call blocked in a background goroutine to wait for activity and
/// trigger a CloseNotifier channel."
///
/// STAGED. goish's serve loop bounds the header read with a socket
/// read deadline instead, which is why this is not wired: swapping it
/// in means restructuring the hardened M31 serve loop, and the state
/// machine is worth having under test first.
///
/// Go's `lock()` / `unlock()` ARE ported, using `Mutex::LockManual` +
/// `Mutex::__locked_mut`. The Cond that Go's `lock()` lazily builds
/// lands with the background reader.
pub struct connReader {
    state: crate::sync::Mutex<connReaderState>,
}

// go: none — goish-only: the payload of Go's `mu sync.Mutex` on
// connReader, restricted to the fields this slice ports.
// The last three are Go's fields for the background reader, carried
// now so the struct does not have to change shape when it lands.
#[allow(dead_code)]
struct connReaderState {
    /// Go: "bytes remaining"
    remain: i64,
    /// Go: set while a Read is in flight; a second concurrent Read is
    /// a caller bug, not a race to tolerate.
    inRead: bool,
    /// Go: "set true before conn.rwc deadline is set to past"
    aborted: bool,
    hasByte: bool,
    /// Go nils `cr.conn` in releaseConn; goish records the transition
    /// until the `conn` back-pointer lands with the background reader.
    released: bool,
}

impl connReader {
    // go: none — goish-only: Go zero-values connReader inside newConn.
    pub fn __new() -> connReader {
        return connReader {
            state: crate::sync::Mutex::new(connReaderState {
                remain: 0,
                inRead: false,
                aborted: false,
                hasByte: false,
                released: false,
            }),
        };
    }

    // go: sdk 1.25.5 net/http/server.go:672-677 connReader.lock
    /// Go: acquires `cr.mu` and lazily builds `cr.cond` under it.
    /// goish has no Cond yet (it arrives with the background reader),
    /// so this is the acquire alone — a MANUAL lock, because Go's
    /// callers unlock in a different function than they lock in.
    pub fn lock(&self) {
        self.state.LockManual();
        return;
    }

    // go: sdk 1.25.5 net/http/server.go:679 connReader.unlock
    pub fn unlock(&self) {
        self.state.Unlock();
        return;
    }

    // go: sdk 1.25.5 net/http/server.go:681-685 connReader.releaseConn
    /// Go: "conn is nil after handler exit" — this is what nils it, so
    /// a later Read on a hijacked conn stops reaching back into the
    /// server. goish's `conn` field lands with the background reader;
    /// the lock discipline is what this ports, and it is the reason
    /// `lock`/`unlock` had to be real rather than a scoped guard.
    pub fn releaseConn(&self) {
        self.lock();
        // SAFETY: locked immediately above, released immediately
        // below, and the reference does not escape.
        unsafe {
            self.state.__locked_mut().released = true;
        }
        self.unlock();
        return;
    }

    // go: none — goish-only: reads the flag releaseConn sets, so a
    // test can observe the manual-lock path actually took effect.
    pub fn __released(&self) -> bool {
        return self.state.Lock().released;
    }

    // go: sdk 1.25.5 net/http/server.go:755 connReader.setReadLimit
    pub fn setReadLimit(&self, remain: i64) {
        self.state.Lock().remain = remain;
        return;
    }

    // go: sdk 1.25.5 net/http/server.go:756 connReader.setInfiniteReadLimit
    /// Go sets `maxInt64`, not "no limit" — so `hitReadLimit` keeps
    /// working without a special case, and the counter can still be
    /// decremented safely.
    pub fn setInfiniteReadLimit(&self) {
        self.state.Lock().remain = i64::MAX;
        return;
    }

    // go: sdk 1.25.5 net/http/server.go:757 connReader.hitReadLimit
    /// `<= 0`, not `== 0`: a Read that overshoots must stay limited.
    pub fn hitReadLimit(&self) -> bool {
        return self.state.Lock().remain <= 0;
    }

}

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
    // go: sdk 1.25.5 net/http/server.go:1886-1889 conn.getState
    /// Go packs `(unixtime<<8 | state)` into one atomic and unpacks it
    /// here; goish keeps the two in separate atomics, so this is the
    /// pair read. The nanosecond stamp is CLOCK_MONOTONIC, not unix
    /// seconds — only differences are ever consulted.
    pub(crate) fn getState(&self) -> (u8, i64) {
        let st = self.state.load(Ordering::Acquire);
        let since = self.since_ns.load(Ordering::Relaxed);
        return (st, since);
    }

    // go: sdk 1.25.5 net/http/server.go:1865-1884 conn.setState
    pub(crate) fn setState(&self, st: u8) {
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
            DisableGeneralOptionsHandler: false,
            Addr: string::new(),
            Handler: Arc::new(notFoundHandler) as Arc<dyn Handler>,
            ReadTimeout: time::Duration(0),
            ReadHeaderTimeout: time::Duration(0),
            WriteTimeout: time::Duration(0),
            IdleTimeout: time::Duration(0),
            MaxHeaderBytes: 0,
            MaxConcurrentConns: 0,
            BaseContext: None,
            ConnContext: None,
            ErrorLog: None,
            TLSConfig: None,
            __state: __ServerState::default(),
        }
    }
}

impl Default for __ServerState {
    fn default() -> Self {
        __ServerState {
            in_shutdown: AtomicBool::new(false),
            disable_keep_alives: AtomicBool::new(false),
            active_conns: AtomicUsize::new(0),
            tracked_listeners: Mutex::new(Vec::new()),
            conn_sem: Mutex::new(None),
            tracked_conns: Mutex::new(Vec::new()),
            on_shutdown: Mutex::new(Vec::new()),
        }
    }
}

// go: sdk 1.25.5 net/http/server.go:2629-2648 cleanPath
//
/// Return the canonical path for `p`, eliminating `.` and `..`
/// elements.
///
/// `path.Clean` strips a trailing slash except at root; cleanPath puts
/// it back, because for a mux "/dir" and "/dir/" are different
/// patterns and collapsing them would silently reroute a request.
pub fn cleanPath<P: Into<string>>(p: P) -> string {
    let mut p: string = p.into();
    if p == "" {
        return string("/");
    }
    if p[0] != b'/' {
        p = string("/") + p;
    }
    let mut np = crate::path::Clean(p.clone());
    // Go: path.Clean removes trailing slash except for root; put the
    // trailing slash back if necessary.
    if p[p.Len() - 1] == b'/' && np != "/" {
        // Go: fast path for the common case of p being what we want.
        if p.Len() == np.Len() + 1 && strings::HasPrefix(p.clone(), np.clone()) {
            np = p;
        } else {
            np = np + "/";
        }
    }
    return np;
}

// go: sdk 1.25.5 net/http/server.go:2651-2661 stripHostPort
//
/// Return `h` without any trailing ":<port>".
pub fn stripHostPort<H: Into<string>>(h: H) -> string {
    let h: string = h.into();
    // Go: if no port on host, return unchanged.
    if !strings::Contains(h.clone(), string(":")) {
        return h;
    }
    let (host, _port, err) = crate::net::SplitHostPort(h.clone());
    if !err.IsNil() {
        return h; // Go: on error, return unchanged
    }
    return host;
}

// go: sdk 1.25.5 net/http/server.go:1576-1590 foreachHeaderElement
//
/// Split a comma-separated header value and call `fn_` with each
/// non-empty, trimmed element. A value with no comma is passed whole
/// without splitting.
pub fn foreachHeaderElement<V: Into<string>, F: FnMut(string)>(v: V, mut fn_: F) {
    let v = crate::net::textproto::TrimString(v.into());
    if v == "" {
        return;
    }
    if !strings::Contains(v.clone(), string(",")) {
        fn_(v);
        return;
    }
    let parts = strings::Split(v, string(","));
    let n = crate::len(&parts);
    let mut i: int = 0;
    while i < n {
        let f = crate::net::textproto::TrimString(parts[i].clone());
        i += 1;
        if f != "" {
            fn_(f);
        }
    }
}

// go: sdk 1.25.5 net/http/server.go:1852-1858 validNextProto
//
/// Reports whether `proto` names an ALPN protocol that needs a
/// NextProtos handler. The HTTP/1 names and the empty string are
/// handled by the ordinary server loop, so they are NOT "next" protos.
pub fn validNextProto<P: Into<string>>(proto: P) -> bool {
    let proto: string = proto.into();
    if proto == "" || proto == "http/1.1" || proto == "http/1.0" {
        return false;
    }
    return true;
}

// go: sdk 1.25.5 net/http/server.go:4074-4083 numLeadingCRorLF
pub fn numLeadingCRorLF(v: crate::goslice::slice<crate::types::byte>) -> int {
    let mut n: int = 0;
    let ln = crate::len(&v);
    let mut i: int = 0;
    while i < ln {
        let b = v[i];
        i += 1;
        if b == b'\r' || b == b'\n' {
            n += 1;
            continue;
        }
        break;
    }
    return n;
}

// go: sdk 1.25.5 net/http/server.go:4087-4093 tlsRecordHeaderLooksLikeHTTP
//
/// Reports whether the first five bytes of what should be a TLS record
/// header look like plaintext HTTP instead — the check behind the
/// "client sent an HTTP request to an HTTPS server" diagnostic.
pub fn tlsRecordHeaderLooksLikeHTTP(hdr: [crate::types::byte; 5]) -> bool {
    let s = string::from_bytes(&hdr);
    if s == "GET /" || s == "HEAD " || s == "POST " || s == "PUT /" || s == "OPTIO" {
        return true;
    }
    return false;
}

// go: sdk 1.25.5 net/http/server.go:1150-1164 checkWriteHeaderCode
//
/// Panic on a status code that is not three digits.
///
/// Go's reasoning, kept because it explains the panic: "We used to send
/// 'HTTP/1.1 000 0' on the wire in responses but there's no equivalent
/// bogus thing we can realistically send in HTTP/2, so we'll
/// consistently panic instead and help people find their bugs early.
/// (We can't return an error from WriteHeader even if we wanted to.)"
pub fn checkWriteHeaderCode(code: int) {
    if code < 100 || code > 999 {
        panic!("invalid WriteHeader code {}", code);
    }
}

// go: sdk 1.25.5 net/http/server.go:928-931 DefaultMaxHeaderBytes
//
// DefaultMaxHeaderBytes is the maximum permitted size of the headers
// in an HTTP request.
// This can be overridden by setting [Server.MaxHeaderBytes].
pub const DefaultMaxHeaderBytes: crate::types::int = 1 << 20; // 1 MB

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
        return self.__serve_arc(Arc::new(ln));
    }

    // go: none — goish-only. Go's Serve takes a `net.Listener`
    // INTERFACE, so a caller (httptest.Server) can keep its own
    // reference and still Close it after handing it to Serve. goish's
    // Serve takes the listener by VALUE and consumed it, leaving such
    // a caller with nothing to close.
    //
    // The body already began with `Arc::new(ln)`, so lifting that to
    // the signature costs nothing and changes no public API: `Serve`
    // stays exactly as Go declares it and simply wraps.
    pub(crate) fn __serve_arc(self: Arc<Self>, ln: Arc<net::Listener>) -> error {
        // Install into tracked_listeners + initialize conn_sem (if
        // backpressure configured) under one critical section; check
        // in_shutdown atomically (Go `trackListener` returning false
        // when shuttingDown, server.go:3253). Without this, a
        // Shutdown that wins the race vs Serve's entry would observe
        // no listener (so __wake_accept and Close run on nothing),
        // and Serve would later install its listener and enter
        // Accept on a fd that was never closed → permanent park.
        {
            let mut tracked = self.__state.tracked_listeners.Lock();
            if self.__state.in_shutdown.load(Ordering::Acquire) {
                return ErrServerClosed.into();
            }
            tracked.push(ln.clone());
            if self.MaxConcurrentConns > 0 {
                // Shared across all Serve loops on this server —
                // only the first initializes it (serialized by the
                // tracked_listeners lock held here).
                let mut sem = self.__state.conn_sem.Lock();
                if sem.is_none() {
                    let cap = self.MaxConcurrentConns as usize;
                    *sem = Some(crate::gochan::chan::<()>::new_buffered(cap));
                }
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

        // Base context for every request served here — Go computes it
        // once per Serve from `BaseContext(listener)` (server.go:3450).
        let base_ctx: Arc<dyn crate::context::Context> = match &self.BaseContext {
            Some(f) => f(&ln),
            None => crate::context::Background(),
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
                    // Shutdown already drained tracked_listeners;
                    // untrack is a no-op here but kept for the
                    // deferred-trackListener(false) shape.
                    self.trackListener(&ln, false);
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
                    self.logf(crate::Sprintf!(
                        "http: Accept error: %v; retrying in %dms",
                        err,
                        temp_delay_ns / 1_000_000
                    ));
                    time::Sleep(time::Duration(temp_delay_ns));
                    continue;
                }
                // Fatal accept error: this Serve loop is done —
                // remove its listener so a later Shutdown doesn't
                // close a dead (possibly kernel-reused) fd (Go's
                // `defer srv.trackListener(&l, false)`).
                self.trackListener(&ln, false);
                return err;
            }
            temp_delay_ns = 0;
            // Per-connection context — Go's `ConnContext` hook runs
            // once per accepted conn (server.go:3467).
            let conn_ctx: Arc<dyn crate::context::Context> = match &self.ConnContext {
                Some(cc) => cc(base_ctx.clone(), &conn),
                None => base_ctx.clone(),
            };
            let srv = self.clone();
            let release_sem = sem_handle.clone();
            // 64 KiB stack — ample for the per-handler chain.
            go!(stack(64 * 1024), move || {
                srv.serve_conn(conn, conn_ctx);
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

        // Set the shutdown flag and take ALL listeners under one
        // lock so Serve's mirror-image install/check sees a
        // consistent state. Without this, a Serve that hadn't
        // reached its install yet could install AFTER Shutdown
        // observed an empty vec and proceeded — leaving a fd open
        // with no wakeup. Go: `closeListenersLocked` under
        // `s.mu` (server.go:3195/3272).
        {
            // The flag must be set under the SAME lock the listener
            // set is drained behind, or a Serve that has not reached
            // its trackListener yet could install after Shutdown saw
            // an empty set — leaving a fd open with no wakeup.
            let _tracked = self.__state.tracked_listeners.Lock();
            self.__state.in_shutdown.store(true, Ordering::Release);
        }
        let _ = self.closeListenersLocked();

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
            // Go's Shutdown loop is `if s.closeIdleConns() { return
            // lnerr }` (server.go:3202) — the quiescence verdict, not
            // a counter, is what ends the wait. goish also checks the
            // counter, since a conn can be tracked-but-not-yet-idle.
            let quiescent = self.closeIdleConns();
            if quiescent && self.__state.active_conns.load(Ordering::Acquire) == 0 {
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
        {
            // Same lock-ordering requirement as Shutdown: flag first,
            // under the listener lock, then drain.
            let _tracked = self.__state.tracked_listeners.Lock();
            self.__state.in_shutdown.store(true, Ordering::Release);
        }
        let _ = self.closeListenersLocked();
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

    // go: sdk 1.25.5 net/http/server.go:933-938 Server.maxHeaderBytes
    pub fn maxHeaderBytes(&self) -> crate::types::int {
        if self.MaxHeaderBytes > 0 {
            return self.MaxHeaderBytes;
        }
        return DefaultMaxHeaderBytes;
    }

    // go: sdk 1.25.5 net/http/server.go:940-942 Server.initialReadLimitSize
    pub fn initialReadLimitSize(&self) -> crate::types::int64 {
        return self.maxHeaderBytes() + 4096; // bufio slop
    }

    // go: sdk 1.25.5 net/http/server.go:944-964 Server.tlsHandshakeTimeout
    //
    // Go ranges a `[...]time.Duration{…}` array literal; goish walks the
    // same three fields in the same order, which is what fixes the
    // result when two are equal.
    pub fn tlsHandshakeTimeout(&self) -> time::Duration {
        let mut ret = time::Duration(0);
        for v in [
            self.ReadHeaderTimeout,
            self.ReadTimeout,
            self.WriteTimeout,
        ] {
            if v <= time::Duration(0) {
                continue;
            }
            if ret == time::Duration(0) || v < ret {
                ret = v;
            }
        }
        return ret;
    }

    // go: sdk 1.25.5 net/http/server.go:3636-3641 Server.idleTimeout
    //
    // Go falls back to ReadTimeout, NOT to ReadHeaderTimeout. goish's
    // own accept loop uses a separate v1 fallback documented on the
    // IdleTimeout field; this method is the Go-faithful one and is not
    // wired into that path.
    pub fn idleTimeout(&self) -> time::Duration {
        if self.IdleTimeout != time::Duration(0) {
            return self.IdleTimeout;
        }
        return self.ReadTimeout;
    }

    // go: sdk 1.25.5 net/http/server.go:3643-3648 Server.readHeaderTimeout
    pub fn readHeaderTimeout(&self) -> time::Duration {
        if self.ReadHeaderTimeout != time::Duration(0) {
            return self.ReadHeaderTimeout;
        }
        return self.ReadTimeout;
    }

    // go: sdk 1.25.5 net/http/server.go:3654-3656 Server.shuttingDown
    pub fn shuttingDown(&self) -> bool {
        return self.__state.in_shutdown.load(Ordering::Acquire);
    }

    // go: sdk 1.25.5 net/http/server.go:3662-3673 Server.SetKeepAlivesEnabled
    //
    // Controls whether HTTP keep-alives are enabled. By default,
    // keep-alives are always enabled. Only very resource-constrained
    // environments or servers in the process of shutting down should
    // disable them.
    //
    // Go's `v == false` path also calls `closeIdleConns` to hang up
    // conns already parked between requests. goish has no standalone
    // `closeIdleConns` — the idle-conn kick lives inside `Shutdown`
    // (see its "Drain semantics" note) — so already-parked conns here
    // stay parked until their own idle timeout fires. Callers that
    // need them gone should use `Shutdown`.
    pub fn SetKeepAlivesEnabled(&self, v: bool) {
        if v {
            self.__state.disable_keep_alives.store(false, Ordering::Release);
            return;
        }
        self.__state.disable_keep_alives.store(true, Ordering::Release);
    }

    // go: sdk 1.25.5 net/http/server.go:3650-3652 Server.doKeepAlives
    pub fn doKeepAlives(&self) -> bool {
        return !self.__state.disable_keep_alives.load(Ordering::Acquire)
            && !self.shuttingDown();
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
    fn serve_conn(
        self: Arc<Self>,
        mut conn: net::TCPConn,
        conn_ctx: Arc<dyn crate::context::Context>,
    ) {
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
        // Go stamps `c.remoteAddr` ONCE at conn.serve entry
        // (server.go:2076); readRequest copies it onto every request
        // (:1120). Formatting it per request cost an alloc each.
        let remote_addr = conn.RemoteAddr().String();
        // Recycled bufio backing buffer — the per-conn analogue of
        // Go's pooled `c.bufr` (newBufioReader, server.go:840). Each
        // request's reader borrows the conn, so the reader itself is
        // rebuilt per request, but the 4 KiB buffer survives.
        let mut rbuf: alloc::vec::Vec<u8> = alloc::vec::Vec::new();

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

            let conn_fd = conn.__fd();
            let (mut req, err) = {
                let mut br =
                    bufio::__new_reader_with_buf(&mut conn, core::mem::take(&mut rbuf));
                // Server variant: carries the fd so the parser can
                // emit `100 Continue` before the eager body read.
                let out = super::request::__read_request_server(
                    &mut br,
                    self.MaxHeaderBytes,
                    conn_fd,
                );
                rbuf = br.__into_buf();
                out
            };
            if !err.IsNil() {
                // Unknown Expect value → 417 + close (Go
                // sendExpectationFailed, server.go:2103).
                if errors::Is(err.clone(), super::request::ErrUnsupportedExpect) {
                    let w = response::new(conn);
                    w.__set_keep_alive(false);
                    w.WriteHeader(417);
                    let _ = w.close_conn();
                    return;
                }
                // EOF, parse error, or idle timeout — all close the conn.
                let _ = conn.Close();
                return;
            }
            // Clear the read deadline once headers are parsed.
            let _ = conn.SetReadDeadline(time::Time::default());
            // Request in flight — Go's `c.setState(StateActive)`
            // (server.go:2043): shutdown's idle-kick skips us now.
            track.setState(CONN_STATE_ACTIVE);
            // Apply WriteTimeout for the response phase if configured.
            if write_timeout_ns > 0 {
                let wdl = time::Now().Add(time::Duration(write_timeout_ns));
                let _ = conn.SetWriteDeadline(wdl);
            }

            // Go conn.serve stamps `c.remoteAddr` at entry and
            // readRequest copies it onto every request
            // (server.go:2076 / :1120).
            req.RemoteAddr = remote_addr.clone();

            // ── per-request context (Go readRequest, server.go:1112) ──
            // Every incoming request carries a cancellable context:
            // canceled when the response is finished, or earlier by
            // the disconnect watcher below if the client goes away
            // while the handler is still running.
            let (req_ctx, req_cancel) = crate::context::WithCancel(conn_ctx.clone());
            req.ctx = Some(req_ctx);
            let req_cancel: Arc<crate::context::CancelFunc> = Arc::new(req_cancel);

            // ── client-disconnect watcher (Go startBackgroundRead,
            // server.go:735) ──  A helper goroutine MSG_PEEKs the
            // socket and parks on the netpoller; if the peer closes
            // or resets while the handler runs, it cancels the
            // request context. Aborted + joined right after the
            // handler returns (Go abortPendingRead) so the keep-alive
            // loop regains exclusive read ownership of the fd.
            // ── client-disconnect watch (Go startBackgroundRead,
            // server.go:735) ──  Arm a cancel hook on the conn's
            // PollDesc: if a readable event lands mid-handler and an
            // MSG_PEEK probe (run by whichever M polls) shows
            // EOF/reset, the request context is canceled. No
            // goroutine, no handoffs — v1's per-request watcher
            // goroutine cost ~15% of server CPU in newproc/goexit
            // alone and its join added a wakeup round-trip per
            // request.
            let (_, watch_pd) = conn.__disconnect_watch_parts();
            if !watch_pd.is_null() {
                // `Arc<CancelFunc>` (`CancelFunc = Box<dyn Fn()…>`)
                // unsizes straight to `Arc<dyn Fn()…>` — no extra
                // wrapper closure allocation per request.
                let hook: Arc<dyn Fn() + Send + Sync> = req_cancel.clone();
                crate::runtime::netpoll::arm_watch(unsafe { &*watch_pd }, hook);
            }

            let keep_alive = request_keep_alive(&mut req)
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
            let panic_remote = req.RemoteAddr.clone();
            let panic_srv = self.clone();
            let panic_track = track.clone();
            crate::defer!{
                let pv = crate::recover!();
                if pv != crate::nil {
                    // Go logs "http: panic serving %v: %v\n%s" with a
                    // stack (server.go:1944); goish logs addr + value
                    // (the SIGSEGV/panic machinery prints its own
                    // diagnostics separately).
                    panic_srv.logf(crate::Sprintf!(
                        "http: panic serving %s: %v",
                        panic_remote,
                        pv
                    ));
                    let _ = crate::syscall::Close(fd);
                    // goish panic recovery longjmps to the goroutine
                    // entry without running Rust drops, so the
                    // ActiveGuard above never fires on this path —
                    // release the conn accounting here or Shutdown
                    // waits on a ghost conn forever.
                    panic_srv
                        .__state
                        .tracked_conns
                        .Lock()
                        .retain(|t| !Arc::ptr_eq(t, &panic_track));
                    panic_srv
                        .__state
                        .active_conns
                        .fetch_sub(1, Ordering::AcqRel);
                }
            }
            self.Handler.ServeHTTP(&w, &req);

            // Handler done — disarm the disconnect watch before
            // touching the conn's read side again (Go
            // abortPendingRead, server.go:756). Nothing to join: the
            // watch is a poller-side hook, and a racing disconnect
            // fire merely cancels a request context that is already
            // finishing (Go cancels it right below anyway).
            if !watch_pd.is_null() {
                crate::runtime::netpoll::disarm_watch(unsafe { &*watch_pd });
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
            track.setState(CONN_STATE_IDLE);
        }
    }

    /// Whether `Shutdown`/`Close` has been initiated. Read by the
    /// HTTPS serve loop (server_tls.rs) to stop accepting / draining.
    pub(crate) fn __state_in_shutdown(&self) -> bool {
        self.__state.in_shutdown.load(Ordering::Acquire)
    }

    /// Install a listener into the shutdown-tracked set — the same
    /// critical section `Serve` runs at entry, factored out so the
    /// HTTPS serve loop (server_tls.rs ServeTLS) gets identical
    /// `Shutdown`/`Close` wakeup semantics: Shutdown drains the
    /// tracked set, wakes each parked Accept, and closes each fd.
    /// Returns `false` if shutdown already began (caller must return
    /// `ErrServerClosed` without accepting). Go: `trackListener(ln,
    /// true)` (server.go:3253).
    // go: sdk 1.25.5 net/http/server.go:3604-3621 Server.trackListener
    /// Go: "trackListener adds or removes a net.Listener to the set of
    /// tracked listeners. Returns false if the server is shutting down."
    ///
    /// Was split into `__track_listener` / `__untrack_listener`, which
    /// no name-level check could match against Go. One function with
    /// Go's `add` flag, as Go writes it.
    ///
    /// goish has no `listenerGroup sync.WaitGroup`: Shutdown polls
    /// `active_conns` instead of waiting on a group, so the Add(1) /
    /// Done() pair has no counterpart.
    pub(crate) fn trackListener(&self, ln: &Arc<net::Listener>, add: bool) -> bool {
        let mut tracked = self.__state.tracked_listeners.Lock();
        if add {
            if self.__state.in_shutdown.load(Ordering::Acquire) {
                return false;
            }
            tracked.push(ln.clone());
        } else {
            tracked.retain(|t| !Arc::ptr_eq(t, ln));
        }
        return true;
    }

    // go: sdk 1.25.5 net/http/server.go:3623-3634 Server.trackConn
    /// Go: "trackConn adds or removes a conn from the set of active
    /// connections." Go's `add` case allocates the record; goish
    /// returns it, since the caller needs the handle for setState.
    /// The remove case is idempotent — `retain` is a no-op the second
    /// time, and `active_conns` only drops when the record was still
    /// present, which the panic path relies on.
    pub(crate) fn trackConn(&self, track: &Arc<ConnTrack>, add: bool) {
        if add {
            self.__state.active_conns.fetch_add(1, Ordering::AcqRel);
            self.__state.tracked_conns.Lock().push(track.clone());
            return;
        }
        {
            let t = track;
            let removed = {
                let mut g = self.__state.tracked_conns.Lock();
                let before = g.len();
                g.retain(|x| !Arc::ptr_eq(x, t));
                before != g.len()
            };
            if removed {
                self.__state.active_conns.fetch_sub(1, Ordering::AcqRel);
            }
        }
        return;
    }

    // go: sdk 1.25.5 net/http/server.go:634-643 Server.newConn
    /// Go: "Create new connection from rwc." Go's `conn` carries the
    /// server, the rwc and the per-conn state; goish's per-conn record
    /// is `ConnTrack`, so this builds that. `pd_addr` is the read-side
    /// PollDesc the shutdown kick needs — Go reaches `c.rwc` instead.
    pub(crate) fn newConn(&self, pd_addr: usize) -> Arc<ConnTrack> {
        return Arc::new(ConnTrack {
            state: AtomicU8::new(CONN_STATE_NEW),
            since_ns: AtomicI64::new(crate::runtime::sysmon::monotonic_ns()),
            pd_addr: AtomicUsize::new(pd_addr),
        });
    }

    // go: sdk 1.25.5 net/http/server.go:3254-3263 Server.closeListenersLocked
    /// Close every tracked listener, returning the FIRST error and
    /// still closing the rest — Go's `if cerr != nil && err == nil`.
    pub(crate) fn closeListenersLocked(&self) -> error {
        let mut err: error = errors::nil;
        // Go iterates `s.listeners` under `s.mu`; goish drains the set
        // so a racing Serve cannot re-install into a half-closed list.
        let listeners: Vec<Arc<net::Listener>> = {
            let mut tracked = self.__state.tracked_listeners.Lock();
            core::mem::take(&mut *tracked)
        };
        for ln in listeners.iter() {
            // goish-only, and load-bearing: Go closes the fd and the
            // kernel wakes the blocked Accept. goish's Accept parks on
            // the netpoller, so it must be woken FIRST or the
            // goroutine sleeps through the close.
            ln.__wake_accept();
            let cerr = ln.Close();
            if !cerr.IsNil() && err.IsNil() {
                err = cerr;
            }
        }
        return err;
    }

    // go: sdk 1.25.5 net/http/server.go:3230-3252 Server.closeIdleConns
    /// Go: "closeIdleConns closes all idle connections and reports
    /// whether the server is quiescent."
    ///
    /// Go closes `c.rwc` outright. goish slams the read deadline into
    /// the past instead and lets the owning serve loop observe the
    /// timeout and close its own fd, so an fd always has exactly one
    /// closer — see kick_tracked_conns. The QUIESCENCE verdict is
    /// Go's, including issue 22682: a StateNew conn older than 5s
    /// counts as idle.
    pub(crate) fn closeIdleConns(&self) -> bool {
        let now = crate::runtime::sysmon::monotonic_ns();
        let mut quiescent = true;
        let conns: Vec<Arc<ConnTrack>> = self.__state.tracked_conns.Lock().clone();
        for t in conns.iter() {
            let (mut st, since) = t.getState();
            // Go issue 22682: "treat StateNew connections as if they're
            // idle if we haven't read the first request's header in
            // over 5 seconds."
            if st == CONN_STATE_NEW && now.wrapping_sub(since) > 5_000_000_000 {
                st = CONN_STATE_IDLE;
            }
            if st != CONN_STATE_IDLE || since == 0 {
                quiescent = false;
                continue;
            }
            let pd_addr = t.pd_addr.load(Ordering::Acquire);
            if pd_addr != 0 {
                let pd = unsafe { &*(pd_addr as *const crate::runtime::netpoll::PollDesc) };
                crate::runtime::netpoll::set_deadline(pd, -1, b'r');
            }
        }
        return quiescent;
    }

    /// `(*Server).logf` (server.go:3691): route a message through
    /// `ErrorLog` when set, else the `log` package default (stderr).
    pub(crate) fn logf(&self, msg: string) {
        match &self.ErrorLog {
            Some(l) => {
                let _ = l.Output(2, msg);
            }
            None => {
                crate::log::println_impl(&[crate::fmt::FmtArg::Val(&msg)]);
            }
        }
    }

    /// Resolve effective read-header timeout: `ReadHeaderTimeout` if
    /// set, else `ReadTimeout`, else the v1 default (5s).
    pub(crate) fn read_header_timeout_ns(&self) -> i64 {
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
    pub(crate) fn idle_timeout_ns(&self) -> i64 {
        if self.IdleTimeout.0 > 0 {
            self.IdleTimeout.0 as i64
        } else if self.ReadTimeout.0 > 0 {
            self.ReadTimeout.0 as i64
        } else {
            self.read_header_timeout_ns()
        }
    }

    pub(crate) fn write_timeout_ns(&self) -> i64 {
        if self.WriteTimeout.0 > 0 {
            self.WriteTimeout.0 as i64
        } else {
            0
        }
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
/// `pub(crate)` wrapper over `request_keep_alive` for the HTTPS serve
/// loop in server_tls.rs.
pub(crate) fn request_keep_alive_pub(req: &mut Request) -> bool {
    return request_keep_alive(req);
}

/// Whether to reuse the connection after this request — the inverse of
/// Go's `shouldClose` (transfer.go:745), which is what Go's conn.serve
/// consults via `w.closeAfterReply`.
///
/// This used to be hand-rolled here, comparing the WHOLE `Connection`
/// value against "close" / "keep-alive" with `Get()`. Two divergences
/// from Go, both of which kept a connection alive that the client had
/// asked to close:
///
///   - `Connection: keep-alive, close` (a real spelling) matched
///     neither branch, so an HTTP/1.1 request took the `!says_close`
///     path and stayed alive. Go tokenises the value and closes.
///   - `Get()` returns only the FIRST header line, so a request
///     sending `Connection: keep-alive` and `Connection: close`
///     separately never saw the close. Go scans every value.
///
/// `removeCloseHeader` is false: the serve loop still needs to see the
/// header, and Go passes false when reading a request too.
fn request_keep_alive(req: &mut Request) -> bool {
    return !super::transfer::shouldClose(
        req.ProtoMajor,
        req.ProtoMinor,
        &mut req.Header,
        false,
    );
}


// go: none — goish idiom: fill the `#[goish::interface]` downcast
// registries for the types this package declares. See AGENTS.md §9b.
/// Register `net/http`'s concrete `Handler`s and body/conn types into
/// the `http` and `io` registries. Idempotent; called from
/// `goish::init()`.
pub fn register_http_impls() {
    __goish_register_Handler_impl::<ServeMux>();
    __goish_register_Handler_impl::<allowQuerySemicolonsHandler>();
    __goish_register_Handler_impl::<methodNotAllowedHandler>();
    __goish_register_Handler_impl::<notFoundHandler>();
    __goish_register_Handler_impl::<redirectHandler>();
    __goish_register_Handler_impl::<stripPrefixHandler>();
    __goish_register_Handler_impl::<timeoutHandler>();

    // The remaining Handlers are unexported in their own modules, so
    // each registers what only it can name.
    super::fs::register_fs_impls();
    super::csrf::register_csrf_impls();
    super::httputil::register_httputil_impls();
    super::client::register_client_impls();
}

// go: sdk 1.25.5 net/http/server.go:1596-1611 writeStatusLine
//
/// Builds the response status line: `HTTP/1.x <code> <text>\r\n`.
///
/// The branch worth having is the ELSE: when `StatusText(code)` is
/// empty — any non-standard code, which APIs do use — Go writes
/// `fmt.Fprintf(bw, "%03d status code %d\r\n", code, code)`, giving
/// `HTTP/1.1 599 status code 599`. goish previously substituted the
/// literal word "Status", putting `HTTP/1.1 599 Status` on the wire
/// for every vendor-specific code.
///
/// Two shape divergences, both to keep goish's own rules: Go writes
/// into a `*bufio.Writer` and takes a `scratch []byte` to avoid an
/// allocation in strconv.AppendInt. Returning the line instead keeps
/// a Rust container out of the signature (GOISH008) and costs one
/// small allocation per response head.
pub(crate) fn writeStatusLine(is11: bool, code: int) -> string {
    let mut out = if is11 {
        string("HTTP/1.1 ")
    } else {
        string("HTTP/1.0 ")
    };
    let text = super::status::StatusText(code);
    if text.Len() != 0 {
        return out + crate::fmt::Sprintf!("%d %s\r\n", code, text);
    }
    // Go: fmt.Fprintf(bw, "%03d status code %d\r\n", code, code) —
    // %03d zero-pads, so code 7 renders "007 status code 7". Not
    // reachable through WriteHeader, which rejects anything below
    // 100, but the format is Go's and is kept.
    if code < 100 {
        out = out + string("0");
        if code < 10 {
            out = out + string("0");
        }
    }
    return out + crate::fmt::Sprintf!("%d status code %d\r\n", code, code);
}
