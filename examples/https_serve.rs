// https_serve — a minimal HTTPS origin server driven by
// `http.Server.ListenAndServeTLS` (M32). Not a self-test: it runs
// until killed, so external tools (curl, browsers) can hit it.
//
//   PORT=8443 CERT=cert.pem KEY=key.pem \
//     ./https_serve
//   curl --cacert cert.pem https://localhost:8443/
//
// Routes:
//   GET /            → "hello over TLS 1.3\n"
//   GET /healthz     → "ok\n"
//   GET /echo?msg=.. → echoes the msg query param
//
// Reads the cert/key file paths from CERT/KEY env vars (defaults
// cert.pem / key.pem in the cwd) and the port from PORT (default 8443).

#![no_std]
#![no_main]

extern crate alloc;
extern crate goish;

use alloc::sync::Arc;

use goish::fmt;
use goish::net::http;
use goish::os;
use goish::{bytes, string};

#[goish::main]
fn main() {
    let port = {
        let p = os::Getenv("PORT");
        if p.Len() > 0 { p } else { string("8443") }
    };
    let cert = {
        let c = os::Getenv("CERT");
        if c.Len() > 0 { c } else { string("cert.pem") }
    };
    let key = {
        let k = os::Getenv("KEY");
        if k.Len() > 0 { k } else { string("key.pem") }
    };

    // Register specific routes before the `GET /` catch-all: goish's
    // ServeMux resolves wildcard patterns in registration order
    // (first match wins), and `GET /` parses to a match-any-path
    // pattern, so it must come last or it shadows everything.
    let mux = http::ServeMux::new();
    mux.HandleFunc("GET /healthz", |w, _r| {
        let _ = w.Write(bytes("ok\n"));
    });
    mux.HandleFunc("GET /echo", |w, r| {
        let (vals, ok) = r.URL.Query().Get(string("msg"));
        let msg = if ok && vals.Len() > 0 {
            vals[0 as goish::int].clone()
        } else {
            string("")
        };
        let _ = w.Write(goish::convert::bytes(fmt::Sprintf!("echo: %s\n", msg)));
    });
    mux.HandleFunc("GET /", |w, _r| {
        let _ = w.Write(bytes("hello over TLS 1.3\n"));
    });

    let mut srv = http::Server::new(Arc::new(mux));
    srv.Addr = fmt::Sprintf!(":%s", port);
    fmt::Printf!("https_serve listening on :%s (TLS 1.3)\n", port);
    let err = Arc::new(srv).ListenAndServeTLS(cert, key);
    if !err.IsNil() {
        fmt::Printf!("ListenAndServeTLS: %v\n", err);
        os::Exit(1);
    }
}
