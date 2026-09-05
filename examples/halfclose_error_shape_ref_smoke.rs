//! Pinned against Go 1.25.5: what `CloseWrite` and `CloseRead` return.
//!
//! Two things the reference settles, and goish had both wrong:
//!
//!   * Go's Op is "close", NOT "shutdown". Go names the operation the
//!     caller asked for and keeps the syscall name for the
//!     os.SyscallError it wraps. Both half-closes report the same
//!     shape (net/tcpsock.go:186-206), which is why they share an Op.
//!   * On an already-closed conn, both return ErrClosed inside that
//!     OpError — not the kernel's EBADF. goish returned
//!     `errno_error("shutdown(write)", EBADF)`: wrong Op, no Net, no
//!     addresses, and errors.Is(err, net.ErrClosed) answered false.
//!
//! Shutting the same direction down twice on an OPEN conn is not an
//! error in Go, and is checked here so a fix cannot overshoot into
//! rejecting it.
//!
//! Reference generated with:
//!   scripts/goref.sh net <shutdown_ref_test.go>
//! Addresses are ephemeral, so the probe rewrites them to LOCAL and
//! REMOTE before comparing.
#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

use goish::errors;
use goish::net;
use goish::net::net as gnet;
use goish::{fmt, go, string, time};

/// Go's output, verbatim.
const GO: [&str; 5] = [
    "cw-open    opErr=false op=\"\"      net=\"\"    isClosed=false msg=\"<nil>\"",
    "cw-again   opErr=false op=\"\"      net=\"\"    isClosed=false msg=\"<nil>\"",
    "cr-open    opErr=false op=\"\"      net=\"\"    isClosed=false msg=\"<nil>\"",
    "cw-closed  opErr=true  op=\"close\" net=\"tcp\" isClosed=true  msg=\"close tcp LOCAL->REMOTE: use of closed network connection\"",
    "cr-closed  opErr=true  op=\"close\" net=\"tcp\" isClosed=true  msg=\"close tcp LOCAL->REMOTE: use of closed network connection\"",
];

static mut FAILED: i64 = 0;
static mut LINE: usize = 0;

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
    let (ln, lerr) = net::Listen(string("tcp"), string("127.0.0.1:0"));
    if !lerr.IsNil() {
        fmt::Printf!("setup: Listen: %v\n", lerr);
        goish::os::Exit(1);
    }
    let port = ln.Addr().Port;
    go!(stack(256 * 1024), move || {
        let (mut c, e) = ln.Accept();
        if e.IsNil() {
            // Hold the peer open past the local half-closes, so the
            // errors below come from OUR fd and not from a reset.
            time::Sleep(time::Duration(400_000_000));
            let _ = goish::io::Closer::Close(&mut c);
        }
    });
    time::Sleep(time::Duration(80_000_000));
    let addr = fmt::Sprintf!("127.0.0.1:%d", port as i64);
    let (mut c, de) = net::Dial(string("tcp"), addr);
    if !de.IsNil() {
        fmt::Printf!("setup: Dial: %v\n", de);
        goish::os::Exit(1);
    }
    let local = c.LocalAddr().String();
    let remote = c.RemoteAddr().String();

    show("cw-open", c.CloseWrite(), &local, &remote);
    show("cw-again", c.CloseWrite(), &local, &remote);
    show("cr-open", c.CloseRead(), &local, &remote);
    let _ = goish::io::Closer::Close(&mut c);
    show("cw-closed", c.CloseWrite(), &local, &remote);
    show("cr-closed", c.CloseRead(), &local, &remote);

    let failed = unsafe { FAILED };
    if failed == 0 {
        fmt::Printf!("half-close error shape: %d/%d match Go\n", 5i64, 5i64);
        goish::os::Exit(0);
    }
    fmt::Printf!("FAIL: %d/%d diverge\n", failed, 5i64);
    goish::os::Exit(1);
}

/// Render one case the way the Go reference renders it and compare.
fn show(tag: &'static str, e: goish::error, local: &string, remote: &string) {
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
    chk(fmt::Sprintf!(
        "%-10s opErr=%-5v op=%-7q net=%-5q isClosed=%-5v msg=%q",
        string::from_static(tag),
        is_op,
        op,
        nw,
        errors::Is(e.clone(), net::ErrClosed),
        string::from_bytes(n2.as_bytes())
    ));
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
