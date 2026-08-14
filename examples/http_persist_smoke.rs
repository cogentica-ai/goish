// http_persist_smoke — httputil's deprecated ClientConn/ServerConn.
//
// The property worth pinning is OWNERSHIP: Hijack DETACHES the
// connection, so the ServerConn keeps no reference and a later Close
// cannot close a socket the caller now owns. Returning a clone instead
// would double-close it.

#![no_std]
#![no_main]

extern crate alloc;
extern crate goish;

use core::sync::atomic::{AtomicUsize, Ordering};

use goish::fmt;
use goish::net;
use goish::net::http::httputil::persist::{
    NewClientConn, NewProxyClientConn, NewServerConn,
};
use goish::{go, string, time};

static PASSED: AtomicUsize = AtomicUsize::new(0);
static FAILED: AtomicUsize = AtomicUsize::new(0);

fn check(name: &'static str, ok: bool, detail: goish::string) {
    if ok { PASSED.fetch_add(1, Ordering::Relaxed); fmt::Printf!("PASS: %s\n", name); }
    else { FAILED.fetch_add(1, Ordering::Relaxed); fmt::Printf!("FAIL: %s — %s\n", name, detail); }
}

#[goish::main]
fn main() {
    goish::go!(stack(512 * 1024), move || { run(); });
    loop { goish::runtime::sched::Gosched(); }
}

fn run() {
    let (ln, e) = net::Listen(string("tcp"), string("127.0.0.1:0"));
    if !e.IsNil() { check("listen", false, fmt::Sprintf!("%v", e)); finish(); }
    let port = ln.Addr().Port;
    go!(stack(256 * 1024), move || {
        loop {
            let (c, e) = ln.Accept();
            if !e.IsNil() { return; }
            let _ = c;
            time::Sleep(time::Duration(50 * 1_000_000));
        }
    });
    time::Sleep(time::Duration(100 * 1_000_000));
    let addr = fmt::Sprintf!("127.0.0.1:%d", port as i64);

    // Hijack detaches: the ServerConn no longer holds the conn.
    {
        let (c, _) = net::Dial(string("tcp"), addr.clone());
        let sc = NewServerConn(c, None);
        let taken = sc.Hijack();
        check("ServerConn.Hijack yields the connection", taken.is_some(), string(""));
        check("and a second Hijack yields nothing — it was detached, not cloned",
              sc.Hijack().is_none(), string(""));
        // Close after Hijack must be a no-op, not a double close.
        check("Close after Hijack is a no-op", sc.Close().IsNil(), string(""));
    }
    // Close without Hijack closes the conn.
    {
        let (c, _) = net::Dial(string("tcp"), addr.clone());
        let sc = NewServerConn(c, None);
        let err = sc.Close();
        check("Close without Hijack closes the connection",
              err.IsNil() && sc.Hijack().is_none(), fmt::Sprintf!("%v", err));
    }
    // ClientConn mirrors it, and the proxy form differs only in flag.
    {
        let (c1, _) = net::Dial(string("tcp"), addr.clone());
        let cc = NewClientConn(c1, None);
        let (c2, _) = net::Dial(string("tcp"), addr.clone());
        let pc = NewProxyClientConn(c2, None);
        check("NewProxyClientConn differs from NewClientConn only in request form",
              !cc.proxy && pc.proxy, string(""));
        check("ClientConn.Pending starts at 0", cc.Pending() == 0, string(""));
        check("ClientConn.Hijack detaches the same way",
              cc.Hijack().is_some() && cc.Hijack().is_none(), string(""));
        let _ = pc.Close();
    }

    finish();
}

fn finish() -> ! {
    let p = PASSED.load(Ordering::Relaxed);
    let f = FAILED.load(Ordering::Relaxed);
    fmt::Printf!("\n%d passed, %d failed\n", p as i64, f as i64);
    if f == 0 { fmt::Printf!("HTTP_PERSIST_SMOKE_OK\n"); goish::os::Exit(0); }
    fmt::Printf!("HTTP_PERSIST_SMOKE_FAIL\n");
    goish::os::Exit(1);
}
