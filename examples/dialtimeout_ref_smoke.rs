//! Pinned against Go 1.25.5: `net.DialTimeout` and `Dialer.Timeout`.
//!
//! goish had neither. `grep -rn DialTimeout src/` found exactly one
//! hit — a comment in the dial path describing what a future
//! DialTimeout *would* do — so there was no way to bound a connect at
//! all, and a dial to an unroutable address blocked until the kernel
//! gave up minutes later.
//!
//! 192.0.2.1 is TEST-NET-1 (RFC 5737): routed nowhere, so the
//! handshake never completes and only the timeout ends the wait. The
//! elapsed time is bucketed at 400ms rather than pinned, so the
//! reference does not depend on scheduling.
//!
//! Three things the reference pins that are easy to get wrong:
//!   * the Op is "dial", not "connect" — Go names the operation the
//!     caller asked for, and keeps the syscall name for the
//!     os.SyscallError it wraps, which a timeout has none of;
//!   * a refused port stays REFUSED under a generous timeout, rather
//!     than being folded into a timeout;
//!   * a zero timeout means NO timeout, not an instant one.
//!
//! Reference generated with:
//!   scripts/goref.sh net <dialtimeout_ref_test.go>
#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

use goish::errors;
use goish::net;
use goish::net::net as gnet;
use goish::{fmt, string, time};

/// Go's output, with the ephemeral port rewritten to PORT.
const GO: [&str; 4] = [
    "blackhole      op=\"dial\" net=\"tcp\" timeout=true  elapsed=waited msg=\"dial tcp 192.0.2.1:80: i/o timeout\"",
    "refused        op=\"dial\" net=\"tcp\" timeout=false elapsed=fast   msg=\"dial tcp 127.0.0.1:PORT: connect: connection refused\"",
    "dialer-timeout op=\"dial\" net=\"tcp\" timeout=true  elapsed=waited msg=\"dial tcp 192.0.2.1:80: i/o timeout\"",
    "zero-timeout   op=\"\"     net=\"\"   timeout=false elapsed=fast   msg=\"<nil>\"",
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
    // 1. A blackholed address: only the timeout ends this.
    let t0 = time::Now();
    let (c, e) = net::DialTimeout(
        string("tcp"),
        string("192.0.2.1:80"),
        time::Duration(500_000_000),
    );
    show("blackhole", c, e, time::Since(t0), &string(""));

    // 2. A closed local port answers RST at once. Refused, not timed
    //    out, and the generous timeout must not recolour it.
    let (ln, _le) = net::Listen(string("tcp"), string("127.0.0.1:0"));
    let dead_addr = ln.Addr().String();
    let _ = ln.Close();
    let t0 = time::Now();
    let (c, e) = net::DialTimeout(
        string("tcp"),
        dead_addr.clone(),
        time::Duration(2_000_000_000),
    );
    show("refused", c, e, time::Since(t0), &dead_addr);

    // 3. Dialer.Timeout is the same clock by another name.
    let mut d = net::Dialer::default();
    d.Timeout = time::Duration(500_000_000);
    let t0 = time::Now();
    let (c, e) = d.Dial(string("tcp"), string("192.0.2.1:80"));
    show("dialer-timeout", c, e, time::Since(t0), &string(""));

    // 4. Zero timeout is NO timeout — this must connect.
    let (ln2, _le2) = net::Listen(string("tcp"), string("127.0.0.1:0"));
    let live_addr = ln2.Addr().String();
    let t0 = time::Now();
    let (c, e) = net::DialTimeout(string("tcp"), live_addr, time::Duration(0));
    show("zero-timeout", c, e, time::Since(t0), &string(""));

    let failed = unsafe { FAILED };
    if failed == 0 {
        fmt::Printf!("DialTimeout: %d/%d match Go\n", 4i64, 4i64);
        goish::os::Exit(0);
    }
    fmt::Printf!("FAIL: %d/%d diverge\n", failed, 4i64);
    goish::os::Exit(1);
}

/// Render one case the way the Go reference renders it and compare.
fn show(
    tag: &'static str,
    mut c: net::TCPConn,
    e: goish::error,
    took: time::Duration,
    ephemeral: &string,
) {
    let _ = goish::io::Closer::Close(&mut c);
    let oe = errors::AsConcrete::<gnet::OpError>(&e);
    let (op, nw) = match oe {
        Some(o) => (o.Op.clone(), o.Net.clone()),
        None => (string(""), string("")),
    };
    let (ne, okn) = errors::AsIface::<goish::d!(gnet::Error)>(&e);
    let msg = if e.IsNil() {
        string("<nil>")
    } else {
        e.Error()
    };
    // The refused case names an ephemeral port; Go's does too.
    let ms: &str = msg.as_ref();
    let msg = if ephemeral.Len() > 0 {
        let ep: &str = ephemeral.as_ref();
        let host_port = match ep.rfind(':') {
            Some(i) => &ep[i + 1..],
            None => ep,
        };
        string::from_bytes(ms.replace(host_port, "PORT").as_bytes())
    } else {
        msg.clone()
    };
    // Bucket the elapsed time so the reference is stable.
    let bucket = if took.0 > 400_000_000 {
        string("waited")
    } else {
        string("fast")
    };
    chk(fmt::Sprintf!(
        "%-14s op=%-6q net=%-4q timeout=%-5v elapsed=%-6s msg=%q",
        string::from_static(tag),
        op,
        nw,
        okn && ne.Timeout(),
        bucket,
        msg
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
