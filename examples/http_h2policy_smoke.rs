// http_h2policy_smoke — the HTTP/2 setup POLICY functions.
//
// goish carries no HTTP/2 transport (it is a Go `nethttpomithttp2`
// build), but Go compiles this policy layer in BOTH build modes and
// so does goish: protocols() decides what the server claims to
// accept, shouldConfigureHTTP2ForServe gates auto-configuration, and
// adjustNextProtos is what a TLS listener config would be filtered
// through. Every expected value is a verbatim goref capture from Go
// 1.25.5 (unexported functions, run inside GOROOT). The cases that
// discriminate:
//
//   * the HISTORIC disable idiom — a non-nil TLSNextProto map with no
//     "h2" entry — must kill HTTP/2 while an "h2" entry keeps it;
//     a port that only checked nil-ness would get both wrong.
//   * shouldConfigureHTTP2ForServe: nil TLSConfig → true (Go 1.6
//     compat), TLSConfig without "h2" → false (Issue 15908: never
//     mutate a user's tls.Config), with "h2" → true.
//   * adjustNextProtos preserves order, filters disabled protocols,
//     appends missing ones h2-first, and passes unknown ALPN strings
//     ("foo") through untouched.
//   * setupHTTP2_Serve on a plain server returns nil — and is
//     idempotent through the Once.

#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

use alloc::sync::Arc;
use core::sync::atomic::{AtomicUsize, Ordering};

use goish::fmt;
use goish::net::http;
use goish::net::http::server::{adjustNextProtos, Server};
use goish::string;

static FAILED: AtomicUsize = AtomicUsize::new(0);

fn check(name: &'static str, got: goish::string, want: &'static str) {
    if (got.as_ref() as &str) == want {
        fmt::Printf!("PASS: %s\n", name);
    } else {
        FAILED.fetch_add(1, Ordering::Relaxed);
        fmt::Printf!("FAIL: %s — got %q want %q\n", name, got, string(want));
    }
}

fn protos_str(s: &Server) -> goish::string {
    let p = s.protocols();
    fmt::Sprintf!(
        "h1=%t h2=%t uh2=%t",
        p.HTTP1(),
        p.HTTP2(),
        p.UnencryptedHTTP2()
    )
}

fn render(s: goish::slice<goish::string>) -> goish::string {
    let mut out = string("[");
    let n = goish::len(&s);
    let mut i = 0;
    while i < n {
        if i > 0 {
            out = out + " ";
        }
        out = out + s[i].clone();
        i += 1;
    }
    out + "]"
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

fn run() -> ! {
    // ── protocols(): defaults and the historic disable idiom ──
    let zero = Server::default();
    check("nil server: h1+h2", protos_str(&zero), "h1=true h2=true uh2=false");

    let mut disabled = Server::default();
    disabled.TLSNextProto = Some(goish::map::new());
    check(
        "non-nil TLSNextProto without h2 disables HTTP/2",
        protos_str(&disabled),
        "h1=true h2=false uh2=false",
    );

    let mut with_h2 = Server::default();
    let mut m: goish::map<goish::string, http::server::TLSNextProtoFn> = goish::map::new();
    // Presence is what matters (goref used a nil fn too).
    m.Set(string("h2"), None);
    with_h2.TLSNextProto = Some(m);
    check(
        "an h2 entry keeps HTTP/2 enabled",
        protos_str(&with_h2),
        "h1=true h2=true uh2=false",
    );

    let mut explicit = Server::default();
    let mut p = http::Protocols::default();
    p.SetHTTP1(true);
    explicit.Protocols = Some(p);
    check(
        "explicit Protocols wins verbatim",
        protos_str(&explicit),
        "h1=true h2=false uh2=false",
    );

    // ── shouldConfigureHTTP2ForServe ──
    check(
        "no TLSConfig: configure (Go 1.6 compat)",
        fmt::Sprintf!("%t", zero.shouldConfigureHTTP2ForServe()),
        "true",
    );
    let mut no_h2 = Server::default();
    let mut cfg = goish::crypto::tls::Config::default();
    cfg.NextProtos = goish::slice::__from_vec(alloc::vec![string("http/1.1")]);
    no_h2.TLSConfig = Some(cfg);
    check(
        "TLSConfig without h2: do NOT configure (Issue 15908)",
        fmt::Sprintf!("%t", no_h2.shouldConfigureHTTP2ForServe()),
        "false",
    );
    let mut has_h2 = Server::default();
    let mut cfg2 = goish::crypto::tls::Config::default();
    cfg2.NextProtos =
        goish::slice::__from_vec(alloc::vec![string("h2"), string("http/1.1")]);
    has_h2.TLSConfig = Some(cfg2);
    check(
        "TLSConfig with h2: configure",
        fmt::Sprintf!("%t", has_h2.shouldConfigureHTTP2ForServe()),
        "true",
    );

    // ── adjustNextProtos: filter, preserve, append ──
    let mut both = http::Protocols::default();
    both.SetHTTP1(true);
    both.SetHTTP2(true);
    let mut h1 = http::Protocols::default();
    h1.SetHTTP1(true);
    check(
        "h2 filtered out when disabled, foo kept",
        render(adjustNextProtos(
            goish::slice::__from_vec(alloc::vec![
                string("h2"),
                string("http/1.1"),
                string("foo")
            ]),
            h1,
        )),
        "[http/1.1 foo]",
    );
    check(
        "missing protocols appended h2-first",
        render(adjustNextProtos(
            goish::slice::__from_vec(alloc::vec![string("foo")]),
            both,
        )),
        "[foo h2 http/1.1]",
    );
    check(
        "empty input grows both",
        render(adjustNextProtos(goish::slice::__from_vec(alloc::vec![]), both)),
        "[h2 http/1.1]",
    );
    check(
        "already-complete list untouched",
        render(adjustNextProtos(
            goish::slice::__from_vec(alloc::vec![string("http/1.1"), string("h2")]),
            both,
        )),
        "[http/1.1 h2]",
    );

    // ── setup is nil-error and Once-idempotent ──
    let s = Arc::new(Server::default());
    let e1 = s.setupHTTP2_Serve();
    let e2 = s.setupHTTP2_Serve();
    check(
        "setupHTTP2_Serve is nil twice through the Once",
        fmt::Sprintf!("%v/%v", e1, e2),
        "<nil>/<nil>",
    );

    let f = FAILED.load(Ordering::Relaxed);
    if f == 0 {
        fmt::Printf!("HTTP_H2POLICY_OK\n");
        goish::os::Exit(0);
    }
    fmt::Printf!("HTTP_H2POLICY_FAIL (%d)\n", f as i64);
    goish::os::Exit(1);
}
