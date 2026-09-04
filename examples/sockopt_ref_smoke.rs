//! Pinned against Go 1.25.5: the four TCP socket-option setters.
//!
//! goish had none of them — `SetNoDelay`, `SetKeepAlive`,
//! `SetKeepAlivePeriod` and `SetLinger` are ordinary API a server
//! author reaches for, and net/tcpsock.go's whole named surface was
//! missing (eighteen declarations; these are the first four).
//!
//! Three details the reference settles, each one a plausible port gets
//! wrong:
//!
//!   * SetKeepAlivePeriod sets TCP_KEEPIDLE **only**. It calls
//!     setKeepAliveIdle and leaves TCP_KEEPINTVL alone — after
//!     SetKeepAlivePeriod(30s), KEEPIDLE is 30 and KEEPINTVL is still
//!     15. Older Go set both, and a port written from memory would.
//!   * SetLinger(-1) clears the option; 0 and positive both set it.
//!   * On a conn this side has closed, the error is ErrClosed inside
//!     `&OpError{Op: "set"}` — "set tcp L->R: use of closed network
//!     connection" — not the kernel's EBADF, and the Op is "set", not
//!     "setsockopt" (the syscall name Go keeps for the inner error).
//!
//! That last one is why this file's reference prints the whole
//! message. A first version collapsed it to a placeholder and would
//! have passed against an EBADF implementation.
//!
//! Reference generated with:
//!   scripts/goref.sh net <sockopt_ref_test.go>
#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

use goish::errors;
use goish::net;
use goish::net::net as gnet;
use goish::{fmt, go, string, syscall, time};

/// Go's output, verbatim.
const GO: [&str; 14] = [
    "default-nodelay        val=1",
    "default-keepalive      val=1",
    "nodelay-false        op=\"\"     isClosed=false val=0   msg=\"<nil>\"",
    "nodelay-true         op=\"\"     isClosed=false val=1   msg=\"<nil>\"",
    "keepalive-false      op=\"\"     isClosed=false val=0   msg=\"<nil>\"",
    "keepalive-true       op=\"\"     isClosed=false val=1   msg=\"<nil>\"",
    "keepaliveperiod-30s  op=\"\"     isClosed=false val=15  msg=\"<nil>\"",
    "  keepidle-after       val=30",
    "linger-neg           op=\"\"     isClosed=false val=0   msg=\"<nil>\"",
    "linger-0             op=\"\"     isClosed=false val=1   msg=\"<nil>\"",
    "linger-5             op=\"\"     isClosed=false val=1   msg=\"<nil>\"",
    "nodelay-closed       op=\"set\"  isClosed=true  val=-1  msg=\"set tcp LOCAL->REMOTE: use of closed network connection\"",
    "keepalive-closed     op=\"set\"  isClosed=true  val=-1  msg=\"set tcp LOCAL->REMOTE: use of closed network connection\"",
    "linger-closed        op=\"set\"  isClosed=true  val=-1  msg=\"set tcp LOCAL->REMOTE: use of closed network connection\"",
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
            time::Sleep(time::Duration(500_000_000));
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
    let fd = c.__fd();

    // The defaults set_tcp_conn_defaults leaves, which are Go's.
    plain(
        "default-nodelay",
        opt(fd, syscall::IPPROTO_TCP, syscall::TCP_NODELAY),
    );
    plain(
        "default-keepalive",
        opt(fd, syscall::SOL_SOCKET, syscall::SO_KEEPALIVE),
    );

    let e = c.SetNoDelay(false);
    show(
        "nodelay-false",
        e,
        opt(fd, syscall::IPPROTO_TCP, syscall::TCP_NODELAY),
        &local,
        &remote,
    );
    let e = c.SetNoDelay(true);
    show(
        "nodelay-true",
        e,
        opt(fd, syscall::IPPROTO_TCP, syscall::TCP_NODELAY),
        &local,
        &remote,
    );
    let e = c.SetKeepAlive(false);
    show(
        "keepalive-false",
        e,
        opt(fd, syscall::SOL_SOCKET, syscall::SO_KEEPALIVE),
        &local,
        &remote,
    );
    let e = c.SetKeepAlive(true);
    show(
        "keepalive-true",
        e,
        opt(fd, syscall::SOL_SOCKET, syscall::SO_KEEPALIVE),
        &local,
        &remote,
    );

    // KEEPINTVL must be untouched; KEEPIDLE must be the new value.
    let e = c.SetKeepAlivePeriod(time::Duration(30_000_000_000));
    show(
        "keepaliveperiod-30s",
        e,
        opt(fd, syscall::IPPROTO_TCP, syscall::TCP_KEEPINTVL),
        &local,
        &remote,
    );
    plain(
        "  keepidle-after",
        opt(fd, syscall::IPPROTO_TCP, syscall::TCP_KEEPIDLE),
    );

    let e = c.SetLinger(-1);
    show(
        "linger-neg",
        e,
        opt(fd, syscall::SOL_SOCKET, syscall::SO_LINGER),
        &local,
        &remote,
    );
    let e = c.SetLinger(0);
    show(
        "linger-0",
        e,
        opt(fd, syscall::SOL_SOCKET, syscall::SO_LINGER),
        &local,
        &remote,
    );
    let e = c.SetLinger(5);
    show(
        "linger-5",
        e,
        opt(fd, syscall::SOL_SOCKET, syscall::SO_LINGER),
        &local,
        &remote,
    );

    let _ = goish::io::Closer::Close(&mut c);
    let e = c.SetNoDelay(true);
    show("nodelay-closed", e, -1, &local, &remote);
    let e = c.SetKeepAlive(true);
    show("keepalive-closed", e, -1, &local, &remote);
    let e = c.SetLinger(0);
    show("linger-closed", e, -1, &local, &remote);

    let failed = unsafe { FAILED };
    let n = GO.len() as i64;
    if failed == 0 {
        fmt::Printf!("tcp socket options: %d/%d match Go\n", n, n);
        goish::os::Exit(0);
    }
    fmt::Printf!("FAIL: %d/%d diverge\n", failed, n);
    goish::os::Exit(1);
}

/// Read one socket option back as a single int, which is how the
/// effect of these setters is observable at all. SO_LINGER answers
/// the `onoff` field at this width, as Go's GetsockoptInt does.
fn opt(fd: i32, level: i32, name: i32) -> i64 {
    let mut v: i32 = -1;
    let mut len: u32 = core::mem::size_of::<i32>() as u32;
    let r = syscall::Getsockopt(fd, level, name, &mut v as *mut i32 as *mut u8, &mut len);
    if r < 0 {
        return -1;
    }
    return v as i64;
}

/// A line with no error column — the two defaults and the KEEPIDLE
/// readback, which Go's reference prints the same way.
fn plain(tag: &'static str, val: i64) {
    chk(fmt::Sprintf!("%-22s val=%d", string::from_static(tag), val));
}

/// Render one setter result the way the Go reference renders it.
fn show(tag: &'static str, e: goish::error, val: i64, local: &string, remote: &string) {
    let oe = errors::AsConcrete::<gnet::OpError>(&e);
    let op = match oe {
        Some(o) => o.Op.clone(),
        None => string(""),
    };
    let msg = if e.IsNil() {
        string("<nil>")
    } else {
        e.Error()
    };
    let ms: &str = msg.as_ref();
    let l: &str = local.as_ref();
    let r: &str = remote.as_ref();
    let n2 = ms.replace(l, "LOCAL").replace(r, "REMOTE");
    chk(fmt::Sprintf!(
        "%-20s op=%-6q isClosed=%-5v val=%-3d msg=%q",
        string::from_static(tag),
        op,
        errors::Is(e.clone(), net::ErrClosed),
        val,
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
