//! Pinned against Go 1.25.5: the errors a *closed* TCP conn returns.
//!
//! Go's `poll.fdMutex` closes a descriptor exactly once. Every later
//! Close, Read or Write on it returns `ErrNetClosing` — "use of closed
//! network connection" — wrapped in an `OpError` naming the operation
//! and both addresses. It is deliberately NOT the kernel's EBADF:
//! `errors.Is(err, net.ErrClosed)` is how a caller tells "I closed
//! this" apart from a real network failure, and EBADF answers false.
//!
//! goish used to return nil from the second Close (no signal at all
//! that the conn was already gone) and `write: bad file descriptor`
//! from a write after close — untyped, so `errors.Is(err,
//! net.ErrClosed)` was false there too.
//!
//! Reference generated with:
//!   scripts/goref.sh net <closeerr_ref_test.go>
//! Addresses are ephemeral, so the probe rewrites them to LOCAL and
//! REMOTE before comparing.
#![no_std]
#![no_main]
extern crate alloc;
extern crate goish;
use goish::errors;
use goish::fmt;
use goish::net;
use goish::net::net as gnet;
use goish::{go, string, time};

/// Go's output, verbatim.
const GO: [&str; 3] = [
    "close-first      opErr=false op=\"\"       net=\"\"    isClosed=false msg=\"<nil>\"",
    "close-again      opErr=true  op=\"close\"  net=\"tcp\" isClosed=true  msg=\"close tcp LOCAL->REMOTE: use of closed network connection\"",
    "write-closed     opErr=true  op=\"write\"  net=\"tcp\" isClosed=true  msg=\"write tcp LOCAL->REMOTE: use of closed network connection\"",
];

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
    let (ln, le) = net::Listen(string("tcp"), string("127.0.0.1:0"));
    if !le.IsNil() {
        fmt::Printf!("FAIL listen: %v\n", le);
        goish::os::Exit(1);
    }
    let port = ln.Addr().Port;
    go!(stack(256 * 1024), move || {
        let (mut c, e) = ln.Accept();
        if e.IsNil() {
            // Hold the peer open past the local Close, so the write
            // below fails on OUR closed fd and not on a reset.
            time::Sleep(time::Duration(300_000_000));
            let _ = goish::io::Closer::Close(&mut c);
        }
    });
    time::Sleep(time::Duration(80_000_000));
    let addr = fmt::Sprintf!("127.0.0.1:%d", port as i64);
    let (mut c, de) = net::Dial(string("tcp"), addr);
    if !de.IsNil() {
        fmt::Printf!("FAIL dial: %v\n", de);
        goish::os::Exit(1);
    }
    let local = c.LocalAddr().String();
    let remote = c.RemoteAddr().String();

    let mut bad: i64 = 0;
    let e1 = goish::io::Closer::Close(&mut c);
    bad += chk(0, "close-first", e1, &local, &remote);
    let e2 = goish::io::Closer::Close(&mut c);
    bad += chk(1, "close-again", e2, &local, &remote);
    let (_n, e3) = goish::io::Writer::Write(&mut c, goish::convert::bytes(string("x")));
    bad += chk(2, "write-closed", e3, &local, &remote);

    if bad == 0 {
        fmt::Printf!("close error shape: %d/%d match Go\n", 3i64, 3i64);
        goish::os::Exit(0);
    }
    fmt::Printf!("FAIL: %d/%d diverge\n", bad, 3i64);
    goish::os::Exit(1);
}

/// Render one case the way the Go reference renders it and compare.
fn chk(
    i: usize,
    tag: &'static str,
    e: goish::error,
    local: &goish::string,
    remote: &goish::string,
) -> i64 {
    let oe = errors::AsConcrete::<gnet::OpError>(&e);
    let is_op = oe.is_some();
    let (op, nw) = match oe {
        Some(o) => (o.Op.clone(), o.Net.clone()),
        None => (string(""), string("")),
    };
    let msg = if e.IsNil() {
        string("<nil>")
    } else {
        e.Error()
    };
    let ms: &str = msg.as_ref();
    let l: &str = local.as_ref();
    let r: &str = remote.as_ref();
    let n1 = ms.replace(l, "LOCAL");
    let n2 = n1.replace(r, "REMOTE");
    let got = fmt::Sprintf!(
        "%-16s opErr=%-5v op=%-8q net=%-5q isClosed=%-5v msg=%q",
        string(tag),
        is_op,
        op,
        nw,
        errors::Is(e.clone(), goish::net::ErrClosed),
        goish::string::from_bytes(n2.as_bytes())
    );
    let want = string::from_static(GO[i]);
    if got == want {
        return 0;
    }
    fmt::Printf!("DIFF go  : %s\n", want);
    fmt::Printf!("     goish: %s\n", got);
    return 1;
}
