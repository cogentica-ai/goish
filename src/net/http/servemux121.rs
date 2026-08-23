// net/http/servemux121 — the pre-Go 1.22 ServeMux, kept for the
// `httpmuxgo121` GODEBUG setting.
//
// Port of Go 1.25.5 net/http/servemux121.go. Go's header is worth
// repeating verbatim: "servemux121.go exists solely to provide a
// snapshot of the pre-Go 1.22 ServeMux implementation for backwards
// compatibility. Do not modify this file, it should remain frozen."
//
// The one thing that does not port is the switch itself: `use121` is
// set from `godebug.New("httpmuxgo121")` at init, and goish has no
// godebug. `use121()` is therefore always false and nothing routes
// here yet — this is the frozen implementation, available for a
// caller that wants 1.21 matching, not a live path. Stated plainly
// because an unwired port is normally a bug smell; here it is what Go
// itself does when the GODEBUG is unset.

#![allow(non_snake_case, non_camel_case_types)]

extern crate alloc;

use alloc::sync::Arc;
use alloc::vec::Vec;

use crate::goslice::slice;
use crate::string;
use crate::types::int;

use super::request::Request;
use super::responsewriter::ResponseWriter;
use super::server::{
    cleanPath, stripHostPort, Handler, HandlerFunc, NotFoundHandler, RedirectHandler,
};
use super::status::StatusMovedPermanently;
use super::url::URL;

// goishlint:ignore GOISH018 init — Go's `init()` (servemux121.go:29)
// reads the `httpmuxgo121` GODEBUG. goish has no internal/godebug, so
// there is nothing to read and nothing to port; `use121()` is a
// constant false. This is the file's only GOISH018 finding.

// go: sdk 1.25.5 net/http/servemux121.go:25 httpmuxgo121
//
// Go: `var httpmuxgo121 = godebug.New("httpmuxgo121")`. goish has no
// `internal/godebug`, so there is nothing to read; the name is kept so
// the setting is greppable. Go's `init()` (servemux121.go:29-35) is
// the other half and has no counterpart for the same reason.
pub const httpmuxgo121: &str = "httpmuxgo121";

// go: sdk 1.25.5 net/http/servemux121.go:27 use121
/// Go reads `httpmuxgo121` once at startup: "since dealing with
/// changes to it during program execution is too complex and
/// error-prone." goish has no `internal/godebug`, so this is a
/// constant false — see the module header.
pub fn use121() -> bool {
    return false;
}

// go: sdk 1.25.5 net/http/servemux121.go:46-49 muxEntry
#[derive(Clone, Default)]
pub struct muxEntry {
    pub h: Option<Arc<dyn Handler>>,
    pub pattern: string,
}

// goishlint:ignore GOISH019 serveMux121 — Go's `mu sync.RWMutex` and
// the three fields it guards (`m`, `es`, `hosts`) live together inside
// `state: Mutex<mux121State>`; goish has no RWMutex. Same grouping as
// cookiejar's Jar. This is the file's only GOISH019 finding.
// go: sdk 1.25.5 net/http/servemux121.go:39-44 serveMux121
/// Go: "serveMux121 holds the state of a ServeMux needed for Go 1.21
/// behavior."
pub struct serveMux121 {
    /// Go's `mu sync.RWMutex` plus the three fields it guards. goish
    /// has no RWMutex, so the guarded state sits inside one Mutex —
    /// the same grouping cookiejar's Jar uses.
    state: crate::sync::Mutex<mux121State>,
}

// go: none — goish-only: the payload of Go's `mu sync.RWMutex`, i.e.
// the three serveMux121 fields it guards.
struct mux121State {
    /// Go: `m map[string]muxEntry`
    m: crate::gomap::map<string, muxEntry>,
    /// Go: "slice of entries sorted from longest to shortest."
    es: slice<muxEntry>,
    /// Go: "whether any patterns contain hostnames"
    hosts: bool,
}

impl serveMux121 {
    // go: none — goish-only: Go zero-values `serveMux121` (its map is
    // lazily made in handle); goish needs an explicit constructor.
    pub fn new() -> serveMux121 {
        return serveMux121 {
            state: crate::sync::Mutex::new(mux121State {
                m: crate::gomap::map::<string, muxEntry>::new(),
                es: slice::<muxEntry>::new(),
                hosts: false,
            }),
        };
    }

    // go: sdk 1.25.5 net/http/servemux121.go:49-77 serveMux121.handle
    /// Go: "Formerly ServeMux.Handle."
    pub fn handle(&self, pattern: string, handler: Arc<dyn Handler>) {
        let mut st = self.state.Lock();

        if pattern == "" {
            panic!("http: invalid pattern");
        }
        let (existing, ok) = st.m.Get(pattern.clone());
        if ok && existing.h.is_some() {
            panic!("http: multiple registrations for pattern");
        }

        let e = muxEntry {
            h: Some(handler),
            pattern: pattern.clone(),
        };
        st.m.Set(pattern.clone(), e.clone());

        let pb = pattern.as_bytes();
        if pb[pb.len() - 1] == b'/' {
            let es = core::mem::replace(&mut st.es, slice::<muxEntry>::new());
            st.es = appendSorted(es, e);
        }

        if pb[0] != b'/' {
            st.hosts = true;
        }
        return;
    }

    // go: sdk 1.25.5 net/http/servemux121.go:94-101 serveMux121.handleFunc
    /// Go: "Formerly ServeMux.HandleFunc."
    pub fn handleFunc<F>(&self, pattern: string, handler: F)
    where
        F: Fn(&(dyn ResponseWriter + Send + Sync + 'static), &Request) + Send + Sync + 'static,
    {
        self.handle(pattern, Arc::new(HandlerFunc(handler)));
        return;
    }

    // go: sdk 1.25.5 net/http/servemux121.go:103-136 serveMux121.findHandler
    /// Go: "Formerly ServeMux.Handler."
    ///
    /// The CONNECT special case is load-bearing: Go does NOT clean the
    /// path for CONNECT, but DOES still apply the /tree -> /tree/
    /// redirect. Treating the two the same would silently change what
    /// a CONNECT request resolves to.
    pub fn findHandler(&self, r: &Request) -> (Arc<dyn Handler>, string) {
        // Go: "CONNECT requests are not canonicalized."
        if r.Method == "CONNECT" {
            let (u, ok) = self.redirectToPathSlash(r.URL.Host.clone(), r.URL.Path.clone(), &r.URL);
            if ok {
                return (
                    RedirectHandler(u.String(), StatusMovedPermanently),
                    u.Path.clone(),
                );
            }
            return self.handler(r.Host.clone(), r.URL.Path.clone());
        }

        // Go: "All other requests have any port stripped and path
        // cleaned before passing to mux.handler."
        let host = stripHostPort(r.Host.clone());
        let path = cleanPath(r.URL.Path.clone());

        // Go: "If the given path is /tree and its handler is not
        // registered, redirect for /tree/."
        let (u, ok) = self.redirectToPathSlash(host.clone(), path.clone(), &r.URL);
        if ok {
            return (
                RedirectHandler(u.String(), StatusMovedPermanently),
                u.Path.clone(),
            );
        }

        if path != r.URL.Path {
            let (_, pattern) = self.handler(host, path.clone());
            let mut u = URL::empty();
            u.Path = path;
            u.RawQuery = r.URL.RawQuery.clone();
            return (RedirectHandler(u.String(), StatusMovedPermanently), pattern);
        }

        return self.handler(host, r.URL.Path.clone());
    }

    // go: sdk 1.25.5 net/http/servemux121.go:138-155 serveMux121.handler
    /// Go: "handler is the main implementation of findHandler. The path
    /// is known to be in canonical form, except for CONNECT methods."
    pub fn handler(&self, host: string, path: string) -> (Arc<dyn Handler>, string) {
        let st = self.state.Lock();

        let mut found: Option<(Arc<dyn Handler>, string)> = None;
        // Go: "Host-specific pattern takes precedence over generic ones"
        if st.hosts {
            found = __match(&st, crate::fmt::Sprintf!("%s%s", host, path.clone()));
        }
        if found.is_none() {
            found = __match(&st, path);
        }
        if let Some((h, pattern)) = found {
            return (h, pattern);
        }
        return (NotFoundHandler(), string::new());
    }

    // go: sdk 1.25.5 net/http/servemux121.go:178-191 serveMux121.redirectToPathSlash
    /// Go: "redirectToPathSlash determines if the given path needs
    /// appending \"/\" to it. This occurs when a handler for path +
    /// \"/\" was already registered, but not for path itself."
    pub fn redirectToPathSlash(&self, host: string, path: string, u: &URL) -> (URL, bool) {
        let shouldRedirect = {
            let st = self.state.Lock();
            __shouldRedirectRLocked(&st, host, path.clone())
        };
        if !shouldRedirect {
            return (u.clone(), false);
        }
        let path = crate::fmt::Sprintf!("%s/", path);
        let mut nu = URL::empty();
        nu.Path = path;
        nu.RawQuery = u.RawQuery.clone();
        return (nu, true);
    }

    // go: sdk 1.25.5 net/http/servemux121.go:193-215 serveMux121.shouldRedirectRLocked
    /// Go: "reports whether the given path and host should be
    /// redirected to path+\"/\". This should happen if a handler is
    /// registered for path+\"/\" but not path."
    pub fn shouldRedirectRLocked(&self, host: string, path: string) -> bool {
        let st = self.state.Lock();
        return __shouldRedirectRLocked(&st, host, path);
    }
}

// go: sdk 1.25.5 net/http/servemux121.go:159-174 serveMux121.match
/// Go: "Find a handler on a handler map given a path string.
/// Most-specific (longest) pattern wins."
///
/// Free function taking the already-locked state: Go's method holds
/// the RLock from its caller, and goish's Mutex is not reentrant.
fn __match(st: &mux121State, path: string) -> Option<(Arc<dyn Handler>, string)> {
    // Go: "Check for exact match first."
    let (v, ok) = st.m.Get(path.clone());
    if ok {
        if let Some(h) = v.h.clone() {
            return Some((h, v.pattern.clone()));
        }
    }

    // Go: "Check for longest valid match. mux.es contains all patterns
    // that end in / sorted from longest to shortest."
    for i in 0..st.es.Len() {
        let e = &st.es[i];
        if crate::strings::HasPrefix(path.clone(), e.pattern.clone()) {
            if let Some(h) = e.h.clone() {
                return Some((h, e.pattern.clone()));
            }
        }
    }
    return None;
}

// go: none — goish-only: the body of shouldRedirectRLocked, taking the
// already-locked state so both the method and redirectToPathSlash can
// call it without re-entering a non-reentrant Mutex.
fn __shouldRedirectRLocked(st: &mux121State, host: string, path: string) -> bool {
    let p = [
        path.clone(),
        crate::fmt::Sprintf!("%s%s", host, path.clone()),
    ];

    for c in p.iter() {
        let (_, exist) = st.m.Get(c.clone());
        if exist {
            return false;
        }
    }

    let n = path.Len();
    if n == 0 {
        return false;
    }
    for c in p.iter() {
        let (_, exist) = st.m.Get(crate::fmt::Sprintf!("%s/", c.clone()));
        if exist {
            return path.as_bytes()[(n as usize) - 1] != b'/';
        }
    }

    return false;
}

// go: sdk 1.25.5 net/http/servemux121.go:80-93 appendSorted
/// Insert `e` keeping `es` ordered longest-pattern first. Go grows the
/// slice in place and memmoves; goish uses `Vec::insert`, which is the
/// same operation.
pub fn appendSorted(es: slice<muxEntry>, e: muxEntry) -> slice<muxEntry> {
    let n = es.Len();
    let mut v: Vec<muxEntry> = es.__into_vec();
    let target = e.pattern.Len();
    let i = crate::sort::Search(n, |i: int| -> bool {
        return v[crate::builtin::__make_size(i)].pattern.Len() < target;
    });
    if i == n {
        v.push(e);
        return slice::<muxEntry>::__from_vec(v);
    }
    // Go: "we now know that i points at where we want to insert"
    v.insert(crate::builtin::__make_size(i), e);
    return slice::<muxEntry>::__from_vec(v);
}
