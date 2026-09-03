//! Pinned against Go 1.25.5: `http.Transport.DialContext` is consulted.
//!
//! Go's `Transport.dial` (transport.go:1276) tries DialContext, then
//! the deprecated Dial, then a zero `net.Dialer`. The hook receives the
//! URL's `host:port` UNRESOLVED, and whatever conn it returns is the
//! one the request rides — which is why a hook can point a request at
//! a unix socket, a test server, or a different host entirely, and why
//! an error from it must reach the caller.
//!
//! goish accepted the field and ignored it. Worse, its type was
//! `Arc<dyn Fn()>` — no arguments, no return — so a hook could not
//! have dialed even if something had called it. A caller who set
//! DialContext to reach a test server silently got a real connection
//! to the real address instead.
//!
//! Reference generated with:
//!   scripts/goref.sh net/http <dialctx_ref_test.go>
//! The request names dialhook.invalid:9999, which resolves nowhere;
//! only a consulted hook can answer it.
#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

use alloc::sync::Arc;
use goish::net::http;
use goish::{errors, fmt, go, io, net, string, time};

/// Go's output, verbatim.
const GO: [&str; 5] = [
    "body           \"real dialhook.invalid:9999\"",
    "status         200",
    "hook-network   \"tcp\"",
    "hook-addr      \"dialhook.invalid:9999\"",
    "hook-err       Get \"http://dialhook.invalid:9999/y\": dial refused by hook",
];

static mut FAILED: i64 = 0;
static mut LINE: usize = 0;

#[goish::main]
fn main() {
    goish::go!(stack(2 * 1024 * 1024), move || {
        run();
    });
    loop {
        goish::runtime::sched::Gosched();
    }
}

fn run() {
    // A real server on an ephemeral port, echoing the Host header so
    // the reply proves which request reached it.
    let mux = http::ServeMux::new();
    mux.HandleFunc(string("/"), |w, r| {
        let _ = w.Write(goish::convert::bytes(string("real ") + r.Host.clone()));
    });
    let mux: Arc<dyn http::Handler> = Arc::new(mux);
    let (ln, lerr) = net::Listen(string("tcp"), string("127.0.0.1:0"));
    if !lerr.IsNil() {
        fmt::Printf!("setup: Listen: %v\n", lerr);
        goish::os::Exit(1);
    }
    let real_port = ln.Addr().Port;
    go!(stack(1024 * 1024), move || {
        let _ = http::Serve(ln, mux);
    });
    time::Sleep(time::Duration(80_000_000));

    let real_addr = fmt::Sprintf!("127.0.0.1:%d", real_port as i64);

    // ── the hook is consulted, and its conn is the one used ──
    let seen: Arc<goish::sync::Mutex<(string, string)>> =
        Arc::new(goish::sync::Mutex::new((string(""), string(""))));
    let seen_w = seen.clone();
    let dial_to = real_addr.clone();
    let mut tr = http::Transport::default();
    tr.DialContext = Some(Arc::new(move |_ctx, network: string, addr: string| {
        {
            let mut g = seen_w.Lock();
            *g = (network.clone(), addr.clone());
        }
        let (conn, err) = net::Dial(string("tcp"), dial_to.clone());
        if !err.IsNil() {
            return (None, err);
        }
        let boxed: alloc::boxed::Box<dyn net::Conn> = alloc::boxed::Box::new(conn);
        return (Some(boxed), errors::nil);
    }));
    let mut c = http::Client::default();
    c.Transport = Arc::new(tr);

    let (mut resp, err) = c.Get(string("http://dialhook.invalid:9999/x"));
    if !err.IsNil() {
        fmt::Printf!("get-err        %v\n", err);
        unsafe { FAILED += 1 };
    } else {
        let (b, _rerr) = io::ReadAll(&mut resp.Body);
        let _ = io::Closer::Close(&mut resp.Body);
        chk(fmt::Sprintf!("body           %q", string::from_bytes(&b.to_vec())));
        chk(fmt::Sprintf!("status         %d", resp.StatusCode as i64));
    }
    {
        let g = seen.Lock();
        chk(fmt::Sprintf!("hook-network   %q", g.0.clone()));
        chk(fmt::Sprintf!("hook-addr      %q", g.1.clone()));
    }

    // ── a hook that refuses: the error reaches the caller ──
    let mut tr2 = http::Transport::default();
    tr2.DialContext = Some(Arc::new(|_ctx, _network: string, _addr: string| {
        return (None, errors::New(string("dial refused by hook")));
    }));
    let mut c2 = http::Client::default();
    c2.Transport = Arc::new(tr2);
    let (_r2, e2) = c2.Get(string("http://dialhook.invalid:9999/y"));
    chk(fmt::Sprintf!("hook-err       %v", e2));

    let failed = unsafe { FAILED };
    if failed == 0 {
        fmt::Printf!("Transport.DialContext: %d/%d match Go\n", 5i64, 5i64);
        goish::os::Exit(0);
    }
    fmt::Printf!("FAIL: %d/%d diverge\n", failed, 5i64);
    goish::os::Exit(1);
}

/// Compare one rendered line against the Go reference, in order.
fn chk(got: string) {
    let i = unsafe { LINE };
    unsafe { LINE += 1 };
    let want = string::from_static(GO[i]);
    if got == want {
        return;
    }
    fmt::Printf!("DIFF go   : %s\n", want);
    fmt::Printf!("     goish: %s\n", got);
    unsafe { FAILED += 1 };
}
