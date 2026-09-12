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
const GO: [&str; 7] = [
    "one-signal                 got=[user defined signal 1]",
    "unregistered               got=[]",
    "two-channels               c1=[user defined signal 1] c2=[user defined signal 1]",
    "notify-additive            got=[user defined signal 2]",
    "full-channel-drops         got=1",
    "stop-one-channel           c1=[user defined signal 1] c2=[]",
    "notify-all                 got={user defined signal 1, user defined signal 2, window changed}",
];

static mut FAILED: i64 = 0;
static mut LINE: usize = 0;
/// What the last `drain` pulled off the channel, so `drain_set` can ask
/// which signals arrived without a second Recv on an empty channel.
/// Single-threaded probe; `static mut` matches the two above.
static mut ARRIVED: Vec<i32> = Vec::new();
/// Wait for the delivered set to go QUIET, then drain it.
///
/// This used to be a flat `Sleep(ms)` and then a drain of whatever had
/// arrived. That encodes an assumption about how fast the kernel
/// redelivers a signal and how soon this goroutine is scheduled after
/// it, and the assumption does not hold on a loaded machine: the e2e
/// run on 2026-09-06 failed here on CI while passing five times out of
/// five locally, with 841 examples competing for the same cores.
///
/// Polling until the first signal arrives would be wrong in the other
/// direction — `notify-all` expects THREE and would return after one,
/// and `stop-one-channel` expects an empty channel and must not
/// return early at all. So the wait is for the buffered count to stop
/// CHANGING for `ms`, with ten times that as a ceiling. A row
/// expecting nothing still waits the full quiet window; a row
/// expecting three waits until all three have landed and no more
/// follow. Same comparison, no timing assumption.
fn drain(c: &goish::gochan::chan<i32>, ms: i64, want: i64) -> string {
    let quiet_ticks = if ms / 5 > 1 { ms / 5 } else { 1 };
    let max_ticks = quiet_ticks * 10;
    let mut last = c.Len();
    let mut stable: i64 = 0;
    let mut ticks: i64 = 0;
    while ticks < max_ticks {
        time::Sleep(time::Duration(5_000_000));
        ticks += 1;
        let n = c.Len();
        if n != last {
            last = n;
            stable = 0;
        } else {
            stable += 1;
        }
        // `want_any` is the part that was missing. Stability alone is
        // also true of a channel nothing has reached YET, so a row
        // expecting a signal returned empty as soon as ZERO had been
        // stable for the quiet window — at ~200ms, nowhere near the 2s
        // ceiling meant to cover a loaded machine. That is how this
        // smoke failed CI again on 2026-09-07 while passing locally,
        // one run after the quiet-window rewrite.
        //
        // It is a parameter and not a blanket `last > 0` because the
        // rows that expect an EMPTY channel — `unregistered`,
        // `stop-one-channel`'s c2 — would then wait the full ceiling
        // every time, and so would the three discarded flush drains.
        // That measured 9.9s against a 15s per-example e2e timeout,
        // which trades a flake for a timeout.
        //
        // It is a COUNT and not a bool as of 2026-09-12, after the
        // third CI flake here. `want_any` only waited for ONE signal,
        // and `notify-all` expects THREE: if the third lagged the
        // second by more than the quiet window, the count went stable
        // at two and the drain returned early with a plausible-looking
        // two-element list. Waiting for the number the row actually
        // expects removes the last "no more will arrive" assumption —
        // and a row that gets FEWER than it wants now spends the
        // ceiling and still reports what it saw, so the failure names
        // the shortfall instead of hiding it.
        if stable >= quiet_ticks && (last as i64) >= want {
            break;
        }
    }
    let mut names: Vec<string> = Vec::new();
    // Len() is the buffered count; drain exactly that many so the
    // probe never blocks on an empty channel.
    unsafe { ARRIVED.clear() };
    while c.Len() > 0 {
        let (s, ok) = c.Recv();
        if !ok {
            break;
        }
        unsafe { ARRIVED.push(s) };
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
/// `drain`, but reporting which of `want` arrived as an ORDER-FREE set.
///
/// ── why this is not a list ──
///
/// The `notify-all` row used to pin Go's exact sequence,
/// `[USR1 USR2 WINCH]`, and that is not a guarantee. Measured
/// (tools/gen_signal_order_ref.go, 200 trials each under goref.sh):
///
///   raising 10, 12, 28 in that order — FOUR distinct orders
///     USR1|USR2|WINCH        191
///     USR1|WINCH|USR2          6
///     USR1|USR2|WINCH|URG      2   (Go's own runtime SIGURG, caught
///                                   because notify-all means ALL)
///     USR2|USR1|WINCH          1
///
///   raising 28, 12, 10 — SIX distinct orders, including
///     USR2|WINCH|USR1         20
///
/// That last one is EXACTLY the sequence this row failed CI on. Go's
/// usual order is ascending by signal number because its `sigqueue`
/// snapshots the whole pending mask in one atomic word swap and then
/// serves the snapshot; but a signal landing during the serve still
/// comes out late, so the order is a tendency and not a contract.
/// POSIX does not specify it either.
///
/// So the row asserts the SET. A signal that never arrives still fails
/// it. Signals outside `want` are excluded rather than failing the row,
/// because notify-all legitimately catches the runtime's own — Go's
/// SIGURG showed up in 2 of 200 trials above.
///
/// goish's relay does NOT do Go's atomic snapshot: `dispatch_pending`
/// reads one per-signal counter at a time while scanning ascending, so
/// a signal arriving mid-scan is served a whole pass late. That makes
/// goish's order more variable than Go's without being outside what Go
/// permits. Recorded in ROADMAP rather than changed here, because
/// matching the snapshot also means matching Go's COALESCING, which is
/// a semantic change to every signal delivery.
fn drain_set(c: &goish::gochan::chan<i32>, ms: i64, want: &[i32]) -> string {
    let _ = drain(c, ms, want.len() as i64);
    let mut seen: Vec<i32> = Vec::new();
    for w in want.iter() {
        if unsafe { ARRIVED.contains(w) } {
            seen.push(*w);
        }
    }
    let mut out = string("{");
    for (i, sig) in seen.iter().enumerate() {
        if i > 0 {
            out = out + string(", ");
        }
        out = out + SignalString(goish::int::from(*sig as i64));
    }
    return out + string("}");
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
        drain(&c1, 200, 1)
    ));

    // A signal NOTHING registered for: delivered nowhere, and — since
    // the runtime now catches every notifiable signal — survivable.
    // Raising this used to kill the process outright.
    me(syscall::SIGUSR2);
    chk(fmt::Sprintf!(
        "%-26s got=%s",
        string("unregistered"),
        drain(&c1, 200, 0)
    ));

    let c2 = goish::make!(chan i32, 4);
    signal::Notify(&c2, &[syscall::SIGUSR1]);
    me(syscall::SIGUSR1);
    let g1 = drain(&c1, 200, 1);
    let g2 = drain(&c2, 200, 1);
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
        drain(&c1, 200, 1)
    ));

    let _ = drain(&c1, 100, 0);
    let _ = drain(&c2, 100, 0);
    let c3 = goish::make!(chan i32, 1);
    signal::Notify(&c3, &[syscall::SIGUSR1]);
    for _ in 0..5 {
        me(syscall::SIGUSR1);
        time::Sleep(time::Duration(10_000_000));
    }
    let d3 = drain(&c3, 200, 1);
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

    let _ = drain(&c1, 100, 0);
    let _ = drain(&c2, 100, 0);
    signal::Stop(&c2);
    me(syscall::SIGUSR1);
    let g1b = drain(&c1, 200, 1);
    let g2b = drain(&c2, 200, 0);
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
        drain_set(&c4, 300, &[syscall::SIGUSR1, syscall::SIGUSR2, 28])
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
