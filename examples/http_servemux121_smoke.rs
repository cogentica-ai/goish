// http_servemux121_smoke — net/http/servemux121.go, the frozen
// pre-Go-1.22 ServeMux.
//
// Every expectation is the output of the real Go 1.25.5 net/http
// package under scripts/goref.sh, against the same four registered
// patterns. The cases worth reading are the CONNECT ones: Go does NOT
// clean the path for CONNECT but DOES still apply the /tree -> /tree/
// redirect, so `//double` resolves differently for CONNECT than for
// GET.

#![no_std]
#![no_main]

extern crate alloc;
extern crate goish;

use alloc::sync::Arc;
use core::sync::atomic::{AtomicUsize, Ordering};

use goish::fmt;
use goish::net::http::servemux121::{appendSorted, muxEntry, serveMux121};
use goish::net::http::{NewRequest, ParseURL};
use goish::{slice, string};

static PASSED: AtomicUsize = AtomicUsize::new(0);
static FAILED: AtomicUsize = AtomicUsize::new(0);

fn check(name: &'static str, ok: bool, detail: goish::string) {
    if ok {
        PASSED.fetch_add(1, Ordering::Relaxed);
        fmt::Printf!("PASS: %s\n", name);
    } else {
        FAILED.fetch_add(1, Ordering::Relaxed);
        fmt::Printf!("FAIL: %s — %s\n", name, detail);
    }
}

#[goish::main]
fn main() {
    goish::go!(stack(512 * 1024), move || {
        run();
    });
    loop {
        goish::runtime::sched::Gosched();
    }
}

fn run() {
    let mux = Arc::new(serveMux121::new());
    for p in ["/", "/tree/", "/exact", "example.com/host"] {
        mux.handleFunc(string(p), move |w, _r| {
            let _ = w.Write(goish::bytes("x"));
        });
    }

    // ── findHandler ── (method, host, path, expected pattern)
    {
        let cases: &[(&'static str, &'static str, &'static str, &'static str)] = &[
            ("GET", "x.com", "/exact", "/exact"),
            ("GET", "x.com", "/tree/", "/tree/"),
            ("GET", "x.com", "/tree", "/tree/"), // -> /tree/ redirect
            ("GET", "x.com", "/tree/deep/er", "/tree/"), // longest prefix
            ("GET", "x.com", "/nope", "/"),
            ("GET", "x.com", "//double", "/"), // cleanPath, then redirect
            ("GET", "x.com", "/a/../exact", "/exact"), // cleanPath resolves ..
            ("GET", "example.com", "/host", "example.com/host"), // host wins
            ("GET", "x.com:8080", "/exact", "/exact"), // port stripped
            ("CONNECT", "x.com", "/tree", "/tree/"), // redirect still applies
            ("CONNECT", "x.com", "//double", "/"), // but NOT cleaned
            // The discriminating pairs: CONNECT skips cleanPath, so
            // the SAME path resolves to a different handler.
            ("CONNECT", "x.com", "//tree/", "/"),
            ("GET", "x.com", "//tree/", "/tree/"),
            ("CONNECT", "x.com", "/tree/../exact", "/tree/"),
            ("GET", "x.com", "/tree/../exact", "/exact"),
        ];
        let mut bad = string("");
        for (method, host, path, want) in cases {
            let raw = fmt::Sprintf!("http://%s%s", string(*host), string(*path));
            let (u, uerr) = ParseURL(raw.clone());
            if !uerr.IsNil() {
                bad = fmt::Sprintf!("parse %s: %v", raw, uerr);
                continue;
            }
            let (req, _) = NewRequest(string(*method), raw.clone(), slice::new());
            let mut req = req;
            req.Host = string(*host);
            req.URL = u;
            let (_, pat) = mux.findHandler(&req);
            if pat != *want {
                bad = fmt::Sprintf!(
                    "%s %s%s -> %q want %q",
                    string(*method),
                    string(*host),
                    string(*path),
                    pat,
                    string(*want)
                );
            }
        }
        check(
            "findHandler over 15 cases (incl. the CONNECT/GET pairs)",
            bad.Len() == 0,
            bad,
        );
    }

    // ── shouldRedirectRLocked ──
    {
        let cases: &[(&'static str, &'static str, bool)] = &[
            ("x.com", "/tree", true), // /tree/ registered, /tree not
            ("x.com", "/tree/", false),
            ("x.com", "/exact", false),
            ("x.com", "/nope", false),
            ("x.com", "", false),
            ("example.com", "/host", false),
        ];
        let mut bad = string("");
        for (host, path, want) in cases {
            let got = mux.shouldRedirectRLocked(string(*host), string(*path));
            if got != *want {
                bad = fmt::Sprintf!(
                    "%s %q -> %v want %v",
                    string(*host),
                    string(*path),
                    got,
                    *want
                );
            }
        }
        check("shouldRedirectRLocked over 6 cases", bad.Len() == 0, bad);
    }

    // ── appendSorted keeps longest-first ──
    {
        let mut es = slice::<muxEntry>::new();
        for p in ["/a/", "/aaa/", "/aa/", "/aaaa/", "/b/"] {
            es = appendSorted(
                es,
                muxEntry {
                    h: None,
                    pattern: string(p),
                },
            );
        }
        // Go: "/aaaa/" "/aaa/" "/aa/" "/a/" "/b/" — equal lengths keep
        // insertion order, so /b/ lands after /a/, not before.
        let want: &[&'static str] = &["/aaaa/", "/aaa/", "/aa/", "/a/", "/b/"];
        let mut ok = es.Len() == want.len() as goish::int;
        if ok {
            for i in 0..want.len() {
                if es[i as goish::int].pattern != want[i] {
                    ok = false;
                }
            }
        }
        let mut got = string("");
        for i in 0..es.Len() {
            got = fmt::Sprintf!("%s%q ", got, es[i].pattern.clone());
        }
        check("appendSorted orders longest-first, stable on ties", ok, got);
    }

    // ── redirectToPathSlash ──
    {
        let (u, _) = ParseURL(string("http://x.com/tree?q=1"));
        let (nu, ok) = mux.redirectToPathSlash(string("x.com"), string("/tree"), &u);
        check(
            "redirectToPathSlash builds a path-only URL keeping RawQuery",
            ok && nu.String() == "/tree/?q=1",
            fmt::Sprintf!("%q ok=%v", nu.String(), ok),
        );
        let (nu2, ok2) = mux.redirectToPathSlash(string("x.com"), string("/exact"), &u);
        check(
            "redirectToPathSlash returns the URL unchanged when no redirect",
            !ok2 && nu2.String() == "http://x.com/tree?q=1",
            fmt::Sprintf!("%q ok=%v", nu2.String(), ok2),
        );
    }

    let p = PASSED.load(Ordering::Relaxed);
    let f = FAILED.load(Ordering::Relaxed);
    fmt::Printf!("\n%d passed, %d failed\n", p as i64, f as i64);
    if f == 0 {
        fmt::Printf!("HTTP_SERVEMUX121_SMOKE_OK\n");
        goish::os::Exit(0);
    }
    fmt::Printf!("HTTP_SERVEMUX121_SMOKE_FAIL\n");
    goish::os::Exit(1);
}
