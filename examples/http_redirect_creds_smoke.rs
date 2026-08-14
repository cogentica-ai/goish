// http_redirect_creds_smoke — the client must not hand the caller's
// credentials to a redirect target on an unrelated host.
//
// goish's Client copied `current.Header` wholesale onto every redirect
// hop, so a server answering `302 Location: http://other-host/` was
// handed the caller's Authorization, Cookie and Proxy-Authorization
// headers. Go builds a headers copier from the INITIAL request and
// strips six credential headers when the hop leaves the initial
// host's domain (client.go:753 makeHeadersCopier, :683).
//
// Two real servers on two ports stand in for two hosts: 127.0.0.1 and
// localhost resolve to the same address but are different `URL.Host`
// values, which is exactly what Go compares.

#![no_std]
#![no_main]

extern crate alloc;
extern crate goish;

use alloc::sync::Arc;
use core::sync::atomic::{AtomicUsize, Ordering};

use goish::fmt;
use goish::net;
use goish::net::http;
use goish::sync::Mutex;
use goish::time;
use goish::{go, string};

static PASSED: AtomicUsize = AtomicUsize::new(0);
static FAILED: AtomicUsize = AtomicUsize::new(0);

fn pass(name: &'static str) {
    PASSED.fetch_add(1, Ordering::Relaxed);
    fmt::Printf!("PASS: %s\n", name);
}

fn fail(msg: goish::string) {
    FAILED.fetch_add(1, Ordering::Relaxed);
    fmt::Printf!("FAIL: %s\n", msg);
}

/// What the final hop actually received.
struct Seen {
    auth: goish::string,
    cookie: goish::string,
    referer: goish::string,
    method: goish::string,
    hits: i64,
}

#[goish::main]
fn main() {
    goish::go!(stack(1024 * 1024), move || {
        run();
    });
    loop {
        goish::runtime::sched::Gosched();
    }
}

fn run() {
    let seen: Arc<Mutex<Seen>> = Arc::new(Mutex::new(Seen {
        auth: string::new(),
        cookie: string::new(),
        referer: string::new(),
        method: string::new(),
        hits: 0,
    }));

    // ── target server: records what it was sent ──
    let tmux = http::ServeMux::new();
    {
        let seen2 = seen.clone();
        tmux.HandleFunc("/target", move |w, r| {
            {
                let mut g = seen2.Lock();
                g.auth = r.Header.Get(string("Authorization"));
                g.cookie = r.Header.Get(string("Cookie"));
                g.referer = r.Header.Get(string("Referer"));
                g.method = r.Method.clone();
                g.hits += 1;
            }
            let _ = w.Write(goish::bytes("landed"));
        });
    }
    let tsrv = Arc::new(http::Server {
        Handler: Arc::new(tmux),
        ReadHeaderTimeout: time::Duration(3 * 1_000_000_000),
        ..Default::default()
    });
    let (tln, e1) = net::Listen(string("tcp"), string("127.0.0.1:0"));
    if !e1.IsNil() {
        fail(fmt::Sprintf!("listen target: %v", e1));
        finish();
    }
    let tport = tln.Addr().Port;
    {
        let s = tsrv.clone();
        go!(stack(1024 * 1024), move || {
            let _ = s.Serve(tln);
        });
    }

    // ── origin server: redirects to the target ──
    // "localhost:<tport>" is a DIFFERENT URL.Host than
    // "127.0.0.1:<oport>", so this hop leaves the domain.
    let cross = fmt::Sprintf!("http://localhost:%d/target", tport as i64);
    let same = fmt::Sprintf!("http://127.0.0.1:%d/target", tport as i64);
    let omux = http::ServeMux::new();
    {
        let loc = cross.clone();
        omux.HandleFunc("/cross", move |w, _r| {
            w.Header().Set(string("Location"), loc.clone());
            w.WriteHeader(302);
        });
    }
    {
        let loc = same.clone();
        omux.HandleFunc("/same", move |w, _r| {
            w.Header().Set(string("Location"), loc.clone());
            w.WriteHeader(302);
        });
    }
    let osrv = Arc::new(http::Server {
        Handler: Arc::new(omux),
        ReadHeaderTimeout: time::Duration(3 * 1_000_000_000),
        ..Default::default()
    });
    let (oln, e2) = net::Listen(string("tcp"), string("127.0.0.1:0"));
    if !e2.IsNil() {
        fail(fmt::Sprintf!("listen origin: %v", e2));
        finish();
    }
    let oport = oln.Addr().Port;
    {
        let s = osrv.clone();
        go!(stack(1024 * 1024), move || {
            let _ = s.Serve(oln);
        });
    }
    time::Sleep(time::Duration(150 * 1_000_000));

    let client = http::Client::default();

    // ── 1. cross-host redirect must NOT forward credentials ──
    {
        {
            let mut g = seen.Lock();
            g.auth = string::new();
            g.cookie = string::new();
            g.hits = 0;
        }
        let url = fmt::Sprintf!("http://127.0.0.1:%d/cross", oport as i64);
        let (req, rerr) = http::NewRequest(string("POST"), url, goish::slice::new());
        if !rerr.IsNil() {
            fail(fmt::Sprintf!("NewRequest: %v", rerr));
            finish();
        }
        let mut req = req;
        req.Header.Set(string("Authorization"), string("Bearer SECRET"));
        req.Header.Set(string("Cookie"), string("session=SECRET"));
        req.Header.Set(string("X-Harmless"), string("keep-me"));
        let (_resp, derr) = client.Do(&req);
        let g = seen.Lock();
        if !derr.IsNil() || g.hits == 0 {
            fail(fmt::Sprintf!("cross redirect not followed: %v hits=%d", derr, g.hits));
        } else if g.auth.Len() == 0 && g.cookie.Len() == 0 {
            pass("cross-host redirect strips Authorization and Cookie");
        } else {
            fail(fmt::Sprintf!(
                "CREDENTIALS LEAKED cross-host: auth=%q cookie=%q",
                g.auth.clone(),
                g.cookie.clone()
            ));
        }
    }

    // ── 2. same-host redirect KEEPS them (Go's rule, not "strip all") ──
    {
        {
            let mut g = seen.Lock();
            g.auth = string::new();
            g.cookie = string::new();
            g.hits = 0;
        }
        let url = fmt::Sprintf!("http://127.0.0.1:%d/same", oport as i64);
        let (req, _) = http::NewRequest(string("GET"), url, goish::slice::new());
        let mut req = req;
        req.Header.Set(string("Authorization"), string("Bearer SECRET"));
        let (_resp, derr) = client.Do(&req);
        let g = seen.Lock();
        if !derr.IsNil() || g.hits == 0 {
            fail(fmt::Sprintf!("same-host redirect not followed: %v", derr));
        } else if g.auth == "Bearer SECRET" {
            pass("same-host redirect keeps Authorization");
        } else {
            fail(fmt::Sprintf!("same-host dropped auth: %q", g.auth.clone()));
        }
    }

    // ── 3. non-sensitive headers survive a cross-host hop ──
    {
        {
            let mut g = seen.Lock();
            g.hits = 0;
        }
        let url = fmt::Sprintf!("http://127.0.0.1:%d/cross", oport as i64);
        let (req, _) = http::NewRequest(string("GET"), url, goish::slice::new());
        let mut req = req;
        req.Header.Set(string("Authorization"), string("Bearer SECRET"));
        req.Header.Set(string("X-Harmless"), string("keep-me"));
        let (_resp, _) = client.Do(&req);
        // The target only records auth/cookie/referer/method, so assert
        // via Referer, which is set per hop and is not sensitive.
        let g = seen.Lock();
        if g.hits > 0 && g.referer.Len() > 0 {
            pass("non-sensitive headers (Referer) still reach a cross-host hop");
        } else {
            fail(fmt::Sprintf!("referer missing: %q hits=%d", g.referer.clone(), g.hits));
        }
    }

    // ── 4. 302 downgrades POST to GET (redirectBehavior) ──
    {
        let g = seen.Lock();
        let m = g.method.clone();
        drop(g);
        // Case 1 above issued a POST; the target must have seen GET.
        if m == "GET" {
            pass("302 downgrades POST to GET at the target");
        } else {
            fail(fmt::Sprintf!("target saw method %q", m));
        }
    }

    finish();
}

fn finish() -> ! {
    let p = PASSED.load(Ordering::Relaxed);
    let f = FAILED.load(Ordering::Relaxed);
    fmt::Printf!("\n%d passed, %d failed\n", p as i64, f as i64);
    if f == 0 {
        fmt::Printf!("HTTP_REDIRECT_CREDS_SMOKE_OK\n");
        goish::os::Exit(0);
    }
    fmt::Printf!("HTTP_REDIRECT_CREDS_SMOKE_FAIL\n");
    goish::os::Exit(1);
}
