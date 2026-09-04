//! Pinned against Go 1.25.5: `signal.Ignore`, `Ignored` and `Reset`.
//!
//! goish had none of the three — os/signal was Notify, Stop and
//! NotifyContext, all of them unanchored until 213d153.
//!
//! What the reference settles, and one line of it contradicted
//! intuition badly enough to be worth naming:
//!
//!   * `Ignore` does TWO things: it drops the registrations, and it
//!     sets the kernel DISPOSITION to SIG_IGN. Both are observable —
//!     a channel registered for the signal stops receiving, and the
//!     process survives the signal.
//!   * `Ignored` reports the DISPOSITION, not the registry.
//!   * **`Reset` does not undo `Ignore`.** After
//!     `Ignore(SIGUSR1); Reset(SIGUSR1)`, `Ignored(SIGUSR1)` is still
//!     TRUE. Go's `cancel(sig, disableSignal)` stops the runtime
//!     WANTING the signal; the disposition Ignore installed survives
//!     it. Only a later `Notify`, which reinstalls the handler, clears
//!     it — which is the `ignored-after-renotify` line.
//!
//!     I expected Reset to clear it. It does not, and a port written
//!     from the doc comment alone would have got this wrong in the
//!     direction that silently ignores signals forever.
//!
//! Reference generated with:
//!   CGO_ENABLED=0 scripts/goref.sh os/signal <signal_ignore_ref_test.go>
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
const GO: [&str; 9] = [
    "ignored-before           [false]",
    "ignored-after            [true]",
    "alive-after-ignored      [true]",
    "notify-then-ignore       [[]]",
    "ignored-usr2             [true]",
    "ignored-after-reset      [true]",
    "ignored-after-renotify   [false]",
    "renotify-delivers        [[user defined signal 2]]",
    "after-reset-delivers     [[]]",
];

static mut FAILED: i64 = 0;
static mut LINE: usize = 0;
fn drain(c: &goish::gochan::chan<i32>, ms: i64) -> string {
    time::Sleep(time::Duration(ms * 1_000_000));
    let mut names: Vec<string> = Vec::new();
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
fn line_b(tag: &'static str, v: bool) {
    chk(fmt::Sprintf!("%-24s [%v]", string::from_static(tag), v));
}
fn line_s(tag: &'static str, v: string) {
    chk(fmt::Sprintf!("%-24s [%s]", string::from_static(tag), v));
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
#[goish::main]
fn main() {
    line_b("ignored-before", signal::Ignored(syscall::SIGUSR1));

    signal::Ignore(&[syscall::SIGUSR1]);
    line_b("ignored-after", signal::Ignored(syscall::SIGUSR1));
    me(syscall::SIGUSR1);
    time::Sleep(time::Duration(100_000_000));
    line_b("alive-after-ignored", true);

    let c = goish::make!(chan i32, 4);
    signal::Notify(&c, &[syscall::SIGUSR2]);
    signal::Ignore(&[syscall::SIGUSR2]);
    me(syscall::SIGUSR2);
    line_s("notify-then-ignore", drain(&c, 200));
    line_b("ignored-usr2", signal::Ignored(syscall::SIGUSR2));

    signal::Reset(&[syscall::SIGUSR1]);
    line_b("ignored-after-reset", signal::Ignored(syscall::SIGUSR1));

    let c2 = goish::make!(chan i32, 4);
    signal::Notify(&c2, &[syscall::SIGUSR2]);
    line_b("ignored-after-renotify", signal::Ignored(syscall::SIGUSR2));
    me(syscall::SIGUSR2);
    line_s("renotify-delivers", drain(&c2, 200));

    signal::Reset(&[syscall::SIGUSR2]);
    me(syscall::SIGUSR2);
    line_s("after-reset-delivers", drain(&c2, 200));
    signal::Stop(&c2);
    signal::Stop(&c);

    let failed = unsafe { FAILED };
    let n = GO.len() as i64;
    if failed == 0 {
        fmt::Printf!("signal.Ignore/Reset: %d/%d match Go\n", n, n);
        goish::os::Exit(0);
    }
    fmt::Printf!("FAIL: %d/%d diverge\n", failed, n);
    goish::os::Exit(1);
}
