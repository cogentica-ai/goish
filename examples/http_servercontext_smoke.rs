// http_servercontext_smoke — server.go's two context keys, and the
// httputil predicate that reads one of them.
//
// Go stamps the *Server on every request context once per Serve
// (server.go:3461) and the accepting local address once per conn
// (:1937). Neither was reachable from a goish handler before this,
// which is not just a missing field:
//
//   * `httputil.shouldPanicOnCopyError` decides between panicking
//     with ErrAbortHandler and returning the copy error by asking
//     whether ServerContextKey is present. With the key absent it
//     ALWAYS took the Go-1.10 branch, so a truncated proxied body
//     would have been reported to the client as a complete one.
//   * `LocalAddrContextKey` is the only way a handler on a server
//     bound to several addresses can tell which one a request
//     arrived on.
//
// The value types are Go's: *Server and net.Addr respectively.

#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicUsize, Ordering};

use goish::fmt;
use goish::io::{Closer, Reader, Writer};
use goish::net;
use goish::net::http;
use goish::net::http::httputil::reverseproxy::shouldPanicOnCopyError;
use goish::time;
use goish::{go, string};

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
    goish::go!(stack(1024 * 1024), move || {
        run();
    });
    loop {
        goish::runtime::sched::Gosched();
    }
}

fn run() -> ! {
    let mux = http::ServeMux::new();
    mux.HandleFunc("/ctx", |w, r| {
        let ctx = r.Context();
        // Go: `s, _ := r.Context().Value(ServerContextKey).(*Server)`
        // — the value is the Server itself, not a marker.
        let srv_seen = match ctx.Value(http::server::ServerContextKey) {
            None => string("absent"),
            Some(v) => match v.downcast_ref::<Arc<http::Server>>() {
                None => string("wrong-type"),
                Some(s) => fmt::Sprintf!("server-mhb=%d", s.MaxHeaderBytes as i64),
            },
        };
        let local = match ctx.Value(http::server::LocalAddrContextKey) {
            None => string("absent"),
            Some(v) => match v.downcast_ref::<net::TCPAddr>() {
                None => string("wrong-type"),
                Some(a) => a.String(),
            },
        };
        // The predicate that actually consumes the key.
        let panics = shouldPanicOnCopyError(r);
        let _ = w.Write(goish::convert::bytes(fmt::Sprintf!(
            "srv=%s local=%s panics=%v",
            srv_seen,
            local,
            panics
        )));
    });

    // A distinctive MaxHeaderBytes proves the handler reached THIS
    // server rather than some other value that happens to be present.
    let srv = Arc::new(http::Server {
        Handler: Arc::new(mux),
        MaxHeaderBytes: 4242,
        ReadHeaderTimeout: time::Duration(3 * 1_000_000_000),
        ..Default::default()
    });

    // Outside any server there is nobody to recover the panic, so Go
    // returns the copy error instead — the pre-1.11 behaviour.
    let (bare, _) = http::NewRequest(
        string("GET"),
        string("http://example.com/"),
        goish::goslice::slice::new(),
    );
    check(
        "shouldPanicOnCopyError is false off a server",
        !shouldPanicOnCopyError(&bare),
        string(""),
    );

    let (ln, lerr) = net::Listen(string("tcp"), string("127.0.0.1:0"));
    if !lerr.IsNil() {
        check("listen", false, fmt::Sprintf!("%v", lerr));
        finish();
    }
    let port = ln.Addr().Port;
    {
        let s = srv.clone();
        go!(stack(1024 * 1024), move || {
            let _ = s.Serve(ln);
        });
    }
    time::Sleep(time::Duration(150 * 1_000_000));

    let body = get(port, "/ctx");
    let b: &str = body.as_ref();

    check(
        "ServerContextKey carries the Server itself, not a marker",
        b.contains("srv=server-mhb=4242"),
        body.clone(),
    );
    check(
        "LocalAddrContextKey carries the accepting address",
        b.contains(fmt::Sprintf!("local=127.0.0.1:%d", port as i64).as_ref() as &str),
        body.clone(),
    );
    check(
        "shouldPanicOnCopyError is true under a server",
        b.contains("panics=true"),
        body.clone(),
    );

    finish();
}

fn get(port: goish::types::int, path: &'static str) -> goish::string {
    let addr = fmt::Sprintf!("127.0.0.1:%d", port as i64);
    let (mut c, e) = net::Dial(string("tcp"), addr);
    if !e.IsNil() {
        return fmt::Sprintf!("dial: %v", e);
    }
    let _ = c.SetReadDeadline(time::Now().Add(time::Duration(5 * 1_000_000_000)));
    let req = fmt::Sprintf!(
        "GET %s HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n",
        string(path)
    );
    let _ = c.Write(goish::convert::bytes(req));
    let mut raw: Vec<u8> = Vec::new();
    let mut buf = goish::make!([]goish::byte, 4096);
    loop {
        let (n, re) = c.Read(&mut buf);
        for i in 0..n {
            raw.push(buf[i]);
        }
        if !re.IsNil() || n == 0 {
            break;
        }
    }
    let _ = c.Close();
    return goish::string::from_bytes(&raw);
}

fn finish() -> ! {
    let p = PASSED.load(Ordering::Relaxed);
    let f = FAILED.load(Ordering::Relaxed);
    fmt::Printf!("\n%d passed, %d failed\n", p as i64, f as i64);
    if f == 0 {
        fmt::Printf!("HTTP_SERVERCONTEXT_SMOKE_OK\n");
        goish::os::Exit(0);
    }
    fmt::Printf!("HTTP_SERVERCONTEXT_SMOKE_FAIL\n");
    goish::os::Exit(1);
}
