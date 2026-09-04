//! Pinned against Go 1.25.5: `signal.Notify` and `signal.Stop`.
//!
//! goish had Notify, Stop and NotifyContext with ZERO provenance
//! anchors — `port_coverage.py` flags all four names as UNVERIFIED,
//! matching Go by name only. Nothing here had ever been diffed, and
//! one of the six cases below was broken.
//!
//! What the reference settles:
//!
//!   * `Notify(c)` with an EMPTY signal list means ALL signals. Go's
//!     doc: "If no signals are provided, all incoming signals will be
//!     relayed to c." goish built an empty bitmap and installed no
//!     handler, so the call registered the channel for NOTHING — the
//!     exact opposite of what it asks for. That is the `notify-all`
//!     line, and it read `got=[]` before this fix.
//!   * Notify is ADDITIVE: a second call adds signals rather than
//!     replacing the set.
//!   * Every registered channel gets its own copy.
//!   * Delivery is NON-BLOCKING: five signals into a channel of
//!     capacity one yield one. This is why Go's doc insists on a
//!     buffered channel.
//!   * `Stop(c)` unregisters that channel only; others keep receiving.
//!
//! ── one case is measured but NOT run here ──
//!
//! Go also answers, for a signal no channel registered for:
//!
//!     unregistered               got=[]
//!
//! — the signal is delivered nowhere and the program CONTINUES. goish
//! cannot run that case: it installs a handler only for signals passed
//! to Notify, so an unregistered SIGUSR2 takes the kernel default and
//! KILLS the process. Go's runtime installs handlers for every
//! notifiable signal at startup and drops the ones nobody wants.
//!
//! Closing that gap means installing handlers at runtime init, not in
//! os/signal, so it is recorded here rather than fixed in passing —
//! and it is why this file's case list has a hole in it instead of a
//! quietly-omitted line.
//!
//! Reference generated with:
//!   CGO_ENABLED=0 scripts/goref.sh os/signal <signal_ref_test.go>
#![no_std]
#![no_main]
#![allow(non_snake_case)]
extern crate alloc;
extern crate goish;
use alloc::vec::Vec;
use goish::os::exec_posix::SignalString;
use goish::os::signal;
use goish::{fmt, string, syscall, time};

/// Go's output, verbatim.
const GO: [&str; 6] = [
    "one-signal                 got=[user defined signal 1]",
    "two-channels               c1=[user defined signal 1] c2=[user defined signal 1]",
    "notify-additive            got=[user defined signal 2]",
    "full-channel-drops         got=1",
    "stop-one-channel           c1=[user defined signal 1] c2=[]",
    "notify-all                 got=[user defined signal 1 user defined signal 2 window changed]",
];

static mut FAILED: i64 = 0;
static mut LINE: usize = 0;
fn drain(c: &goish::gochan::chan<i32>, ms: i64) -> string {
    time::Sleep(time::Duration(ms * 1_000_000));
    let mut names: Vec<string> = Vec::new();
    // Len() is the buffered count; drain exactly that many so the
    // probe never blocks on an empty channel.
    while c.Len() > 0 {
        let (s, ok) = c.Recv();
        if !ok {
            break;
        }
        names.push(SignalString(goish::int::from(s as i64)));
    }
    let mut out = string("[");
    for (i, n) in names.iter().enumerate() {
        if i > 0 {
            out = out + string(" ");
        }
        out = out + n.clone();
    }
    return out + string("]");
}
fn me(sig: i32) {
    let _ = syscall::Kill(syscall::Getpid(), sig);
}
#[goish::main]
fn main() {
    let c1 = goish::make!(chan i32, 4);
    signal::Notify(&c1, &[syscall::SIGUSR1]);
    me(syscall::SIGUSR1);
    chk(fmt::Sprintf!(
        "%-26s got=%s",
        string("one-signal"),
        drain(&c1, 200)
    ));

    let c2 = goish::make!(chan i32, 4);
    signal::Notify(&c2, &[syscall::SIGUSR1]);
    me(syscall::SIGUSR1);
    let g1 = drain(&c1, 200);
    let g2 = drain(&c2, 200);
    chk(fmt::Sprintf!(
        "%-26s c1=%s c2=%s",
        string("two-channels"),
        g1,
        g2
    ));

    signal::Notify(&c1, &[syscall::SIGUSR2]);
    me(syscall::SIGUSR2);
    chk(fmt::Sprintf!(
        "%-26s got=%s",
        string("notify-additive"),
        drain(&c1, 200)
    ));

    let _ = drain(&c1, 100);
    let _ = drain(&c2, 100);
    let c3 = goish::make!(chan i32, 1);
    signal::Notify(&c3, &[syscall::SIGUSR1]);
    for _ in 0..5 {
        me(syscall::SIGUSR1);
        time::Sleep(time::Duration(10_000_000));
    }
    let d3 = drain(&c3, 200);
    let ds: &str = d3.as_ref();
    let n = if ds == "[]" {
        0
    } else {
        ds.matches("signal").count()
    };
    chk(fmt::Sprintf!(
        "%-26s got=%d",
        string("full-channel-drops"),
        n as i64
    ));
    signal::Stop(&c3);

    let _ = drain(&c1, 100);
    let _ = drain(&c2, 100);
    signal::Stop(&c2);
    me(syscall::SIGUSR1);
    let g1b = drain(&c1, 200);
    let g2b = drain(&c2, 200);
    chk(fmt::Sprintf!(
        "%-26s c1=%s c2=%s",
        string("stop-one-channel"),
        g1b,
        g2b
    ));

    let c4 = goish::make!(chan i32, 8);
    signal::Notify(&c4, &[]);
    me(syscall::SIGUSR1);
    me(syscall::SIGUSR2);
    me(28);
    chk(fmt::Sprintf!(
        "%-26s got=%s",
        string("notify-all"),
        drain(&c4, 300)
    ));
    signal::Stop(&c4);
    signal::Stop(&c1);

    let failed = unsafe { FAILED };
    let n = GO.len() as i64;
    if failed == 0 {
        fmt::Printf!("signal.Notify: %d/%d match Go\n", n, n);
        goish::os::Exit(0);
    }
    fmt::Printf!("FAIL: %d/%d diverge\n", failed, n);
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
