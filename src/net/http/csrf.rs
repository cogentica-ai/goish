// net/http/csrf — Cross-Origin Request Forgery protection.
//
// Reference: net/http/csrf.go (Go 1.25.5).
//
// ─── What has been diffed against Go, 2026-09-06 ─────────────────────
//
//   clean  Check's control flow matches Go's exactly: safe methods
//          first, then the Sec-Fetch-Site switch with its empty /
//          same-origin / none / default arms, then the Origin fallback
//          with the fail-open note Go writes about HTTP->HTTPS.
//   clean  the comparisons are BYTE-EXACT. `check_str` and `string_eq`
//          both compare length then bytes, so `Sec-Fetch-Site:
//          Same-Origin` does not match `same-origin` — a
//          case-insensitive helper here would have been a CSRF bypass
//          reachable by changing one letter of a header, which is why
//          they were read rather than assumed.
//   clean  isRequestExempt's sentinel test. Go compares
//          `h == sentinelHandler` by identity; goish uses
//          `Arc::ptr_eq(&h, &sentinelHandler())`, which only works
//          because `sentinelHandler()` is a lazily-initialised
//          SINGLETON returning clones of one Arc. Were it rebuilt per
//          call — as `cookieNameSanitizer` legitimately is, being a
//          pure value — every bypass pattern would silently stop
//          matching.
//
// Line-by-line port. Slim deviations:
//
//   * Go uses `atomic.Pointer[Handler]` for the deny handler. Goish's
//     `atomic.Pointer<T>` requires `T: Sized + 'static`, so a `dyn
//     Handler` value can't go through it directly. We use a
//     `Mutex<Option<Arc<dyn Handler>>>` instead — same correctness,
//     adds a quick uncontended Mutex lock on the deny path.
//
//   * `sync.RWMutex` + `map[string]bool` collapsed into
//     `Mutex<map<string, bool>>`. The trusted-origin set is small and
//     the read path is brief; the lock-contention difference is
//     negligible. Lock acquisition order is identical.

#![allow(non_snake_case)]

extern crate alloc;

use alloc::sync::Arc;

use crate::error;
use crate::gomap::map;
use crate::gostring::string;
use crate::sync::atomic::Pointer;
use crate::sync::Mutex;

use super::request::Request;
use super::responsewriter::ResponseWriter;
use super::server::{Handler, HandlerFunc, ServeMux};
use super::status::StatusForbidden;
use super::url;

// go: sdk 1.25.5 net/http/csrf.go:36-41 CrossOriginProtection
/// `CrossOriginProtection` (csrf.go:36) — rejects non-safe cross-origin
/// browser requests using Sec-Fetch-Site / Origin header heuristics.
///
/// The zero value is valid: no trusted origins, no bypass patterns.
// goishlint:ignore GOISH019 — Go pairs a bare `trustedMu
// sync.RWMutex` with the `trusted` map it guards; goish puts the map
// INSIDE the lock, so the pairing cannot be forgotten at a call site.
// The field is absent rather than renamed, which is why GOISH019 reads
// it as dropped.
//
// This waiver is FILE-WIDE, not per-symbol: GOISH019 only supports
// `file_suppresses`, and naming a symbol silently turns the line into
// a per-symbol waiver the rule never consults. That is tolerable here
// only because csrf.go declares exactly one struct — in a file with
// several, this would blind the others to a real dropped field.
pub struct CrossOriginProtection {
    // Go: bypass atomic.Pointer[ServeMux]
    bypass: Pointer<ServeMux>,
    // Go: trustedMu sync.RWMutex; trusted map[string]bool — the mutex
    // and the map it guards, fused.
    trusted: Mutex<Option<map<string, bool>>>,
    // Go: deny atomic.Pointer[Handler]
    deny: Mutex<Option<Arc<dyn Handler>>>,
}

// go: sdk 1.25.5 net/http/csrf.go:44-46 NewCrossOriginProtection
/// `NewCrossOriginProtection` (csrf.go:44).
pub fn NewCrossOriginProtection() -> Arc<CrossOriginProtection> {
    Arc::new(CrossOriginProtection {
        bypass: Pointer::new(),
        trusted: Mutex::new(None),
        deny: Mutex::new(None),
    })
}

impl CrossOriginProtection {
    // go: sdk 1.25.5 net/http/csrf.go:57-78 CrossOriginProtection.AddTrustedOrigin
    /// `AddTrustedOrigin(origin)` (csrf.go:57). Origin must look like
    /// `scheme://host[:port]` — no path / query / fragment.
    pub fn AddTrustedOrigin<O: Into<string>>(&self, origin: O) -> error {
        let origin: string = origin.into();
        // Go: u, err := url.Parse(origin)
        let (u, err) = url::Parse(origin.clone());
        if !err.IsNil() {
            return crate::Errorf!("invalid origin %q: %w", origin, err);
        }
        // Go: if u.Scheme == "" { … "scheme is required" }
        if u.Scheme.Len() == 0 {
            return crate::Errorf!("invalid origin %q: scheme is required", origin);
        }
        // Go: if u.Host == "" { … "host is required" }
        if u.Host.Len() == 0 {
            return crate::Errorf!("invalid origin %q: host is required", origin);
        }
        // Go: if u.Path != "" || u.RawQuery != "" || u.Fragment != "" { … }
        if u.Path.Len() != 0 || u.RawQuery.Len() != 0 || u.Fragment.Len() != 0 {
            return crate::Errorf!(
                "invalid origin %q: path, query, and fragment are not allowed",
                origin
            );
        }
        // Go: c.trustedMu.Lock(); defer c.trustedMu.Unlock()
        let mut g = self.trusted.Lock();
        // Go: if c.trusted == nil { c.trusted = make(map[string]bool) }
        if g.is_none() {
            *g = Some(map::<string, bool>::new());
        }
        // Go: c.trusted[origin] = true
        if let Some(m) = g.as_mut() {
            m.Set(origin, true);
        }
        crate::errors::nil
    }

    // go: sdk 1.25.5 net/http/csrf.go:95-111 CrossOriginProtection.AddInsecureBypassPattern
    /// `AddInsecureBypassPattern(pattern)` (csrf.go:95). Permits all
    /// requests matching `pattern` (uses ServeMux match semantics).
    pub fn AddInsecureBypassPattern<P: Into<string>>(&self, pattern: P) {
        let pattern: string = pattern.into();
        // Go: lazy-init c.bypass via CAS loop.
        let bypass = loop {
            if let Some(b) = self.bypass.Load() {
                break b;
            }
            let fresh = Arc::new(ServeMux::new());
            if self.bypass.CompareAndSwap(None, Some(fresh.clone())) {
                break fresh;
            }
            // Lost race; loop reloads.
        };

        // Go: bypass.Handle(pattern, sentinelHandler)
        bypass.Handle(pattern, sentinelHandler());
    }

    // go: sdk 1.25.5 net/http/csrf.go:120-126 CrossOriginProtection.SetDenyHandler
    /// `SetDenyHandler(h)` (csrf.go:120). Set the handler invoked when a
    /// request is rejected. Pass `None` to clear (defaults to 403).
    pub fn SetDenyHandler(&self, h: Option<Arc<dyn Handler>>) {
        *self.deny.Lock() = h;
    }

    // go: sdk 1.25.5 net/http/csrf.go:130-171 CrossOriginProtection.Check
    /// `Check(req)` (csrf.go:130). Returns nil if the request passes
    /// cross-origin checks; otherwise an error describing the cause.
    pub fn Check(&self, req: &Request) -> error {
        // Go: switch req.Method { case "GET", "HEAD", "OPTIONS": return nil }
        let m = req.Method.clone();
        if check_str(&m, "GET") || check_str(&m, "HEAD") || check_str(&m, "OPTIONS") {
            return crate::errors::nil;
        }

        // Go: switch req.Header.Get("Sec-Fetch-Site") { … }
        let sfs = req.Header.Get(string::from_static("Sec-Fetch-Site"));
        if sfs.Len() == 0 {
            // Fall through to Origin check.
        } else if check_str(&sfs, "same-origin") || check_str(&sfs, "none") {
            return crate::errors::nil;
        } else {
            // cross-site / same-site / unknown — reject unless exempt.
            if self.isRequestExempt(req) {
                return crate::errors::nil;
            }
            return errCrossOriginRequest.into();
        }

        // Go: origin := req.Header.Get("Origin")
        let origin = req.Header.Get(string::from_static("Origin"));
        if origin.Len() == 0 {
            // Neither Sec-Fetch-Site nor Origin headers present.
            return crate::errors::nil;
        }

        // Go: if o, err := url.Parse(origin); err == nil && o.Host == req.Host { return nil }
        let (o, e) = url::Parse(origin.clone());
        if e.IsNil() && string_eq(&o.Host, &req.Host) {
            return crate::errors::nil;
        }

        if self.isRequestExempt(req) {
            return crate::errors::nil;
        }
        errCrossOriginRequestFromOldBrowser.into()
    }

    // go: sdk 1.25.5 net/http/csrf.go:181-194 CrossOriginProtection.isRequestExempt
    /// `isRequestExempt(req)` (csrf.go:181). Bypass-pattern + trusted
    /// origin check; lazy because both paths take a lock.
    fn isRequestExempt(&self, req: &Request) -> bool {
        // Go: if bypass := c.bypass.Load(); bypass != nil { … }
        if let Some(bypass) = self.bypass.Load() {
            // Go: if h, _ := bypass.Handler(req); h == sentinelHandler { return true }
            let (h, _) = bypass.Handler(req);
            if Arc::ptr_eq(&h, &sentinelHandler()) {
                return true;
            }
        }

        // Go: c.trustedMu.RLock(); defer c.trustedMu.RUnlock()
        let g = self.trusted.Lock();
        // Go: origin := req.Header.Get("Origin"); origin != "" && c.trusted[origin]
        let origin = req.Header.Get(string::from_static("Origin"));
        if origin.Len() == 0 {
            return false;
        }
        match g.as_ref() {
            Some(m) => m.Get(origin).0,
            None => false,
        }
    }

    // go: sdk 1.25.5 net/http/csrf.go:202-214 CrossOriginProtection.Handler
    /// `Handler(h)` (csrf.go:202) — wraps `h` in a handler that runs
    /// `Check(r)` first. On rejection, dispatches to the deny handler
    /// (default: 403 Forbidden).
    pub fn Handler(self_arc: Arc<Self>, h: Arc<dyn Handler>) -> Arc<dyn Handler> {
        Arc::new(HandlerFunc(
            move |w: &(dyn ResponseWriter + Send + Sync + 'static), r: &Request| {
                // Go: if err := c.Check(r); err != nil { … }
                let err = self_arc.Check(r);
                if !err.IsNil() {
                    // Go: if deny := c.deny.Load(); deny != nil { (*deny).ServeHTTP(w, r); return }
                    let deny = self_arc.deny.Lock().clone();
                    if let Some(d) = deny {
                        d.ServeHTTP(w, r);
                        return;
                    }
                    // Go: Error(w, err.Error(), StatusForbidden)
                    super::server::Error(w, err.Error(), StatusForbidden);
                    return;
                }
                h.ServeHTTP(w, r);
            },
        ))
    }
}

// ─── sentinel handler (csrf.go:80) ────────────────────────────────────

// go: sdk 1.25.5 net/http/csrf.go:80-80 noopHandler
/// `noopHandler` (csrf.go:80) — used as a sentinel value via pointer
/// identity to mark bypass-mux entries.
struct noopHandler;

impl Handler for noopHandler {
    // go: sdk 1.25.5 net/http/csrf.go:82-82 noopHandler.ServeHTTP
    fn ServeHTTP(&self, _w: &(dyn ResponseWriter + Send + Sync + 'static), _r: &Request) {}
}

// Go: var sentinelHandler Handler = &noopHandler{}
//
// We cache a single Arc behind a Mutex, populating it on first call.
// Pointer equality of `Arc::ptr_eq(returned, sentinelHandler())` is
// what `isRequestExempt` checks against, so the same Arc must come
// back every call.
static SENTINEL_HANDLER: Mutex<Option<Arc<dyn Handler>>> = Mutex::new(None);

// go: sdk 1.25.5 net/http/csrf.go:84-84 sentinelHandler
fn sentinelHandler() -> Arc<dyn Handler> {
    let mut g = SENTINEL_HANDLER.Lock();
    if g.is_none() {
        let h: Arc<dyn Handler> = Arc::new(noopHandler);
        *g = Some(h);
    }
    g.as_ref().unwrap().clone()
}

// ─── sentinel errors (csrf.go:173-177) ────────────────────────────────

/// `errCrossOriginRequest` (csrf.go:174).
crate::var! {
    pub errCrossOriginRequest: error = "cross-origin request detected from Sec-Fetch-Site header";
}

/// `errCrossOriginRequestFromOldBrowser` (csrf.go:175).
crate::var! {
    pub errCrossOriginRequestFromOldBrowser: error = "cross-origin request detected, and/or browser is out of date: Sec-Fetch-Site is missing, and Origin does not match Host";
}

// ─── helpers ──────────────────────────────────────────────────────────

fn check_str(got: &string, want: &str) -> bool {
    if got.Len() as usize != want.len() {
        return false;
    }
    let bytes = want.as_bytes();
    let mut i: crate::types::int = 0;
    while (i as usize) < want.len() {
        if got[i] != bytes[i as usize] {
            return false;
        }
        i += 1;
    }
    true
}

fn string_eq(a: &string, b: &string) -> bool {
    if a.Len() != b.Len() {
        return false;
    }
    let n = a.Len();
    let mut i: crate::types::int = 0;
    while i < n {
        if a[i] != b[i] {
            return false;
        }
        i += 1;
    }
    true
}

// go: none — goish idiom: `noopHandler` is unexported, so only this
// module can register it. See AGENTS.md §9b.
pub(super) fn register_csrf_impls() {
    super::server::__goish_register_Handler_impl::<noopHandler>();
}
