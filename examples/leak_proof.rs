// Leak-prevention proof for M24a (the watcher-goroutine leaks).
//
// Three checks, each measuring `runtime::NumGoroutine()` before and
// after a "spawn → cancel" cycle. If a fix is missing, the count
// stays elevated and the test fails with a non-zero exit.
//
//   (1) context::WithCancel chained — pre-fix the watcher waited
//       only on parent.Done(), so cancelling the CHILD left it
//       hanging. Post-fix it `select!`s on both parent.Done() and
//       own done, mirroring context.go:522-528.
//
//   (2) time::NewTimer — pre-fix Stop() set an AtomicBool that the
//       watcher only checked AFTER its full Sleep(d). Stop did not
//       actually shorten the watcher's lifetime. Post-fix the
//       watcher select!s an After(d) chan against a stop chan, so
//       Stop exits the outer watcher immediately.
//
//   (3) time::NewTicker — pre-fix the loop's Sleep(d) ran every
//       iteration regardless of Stop, so dropping the Ticker without
//       Stop leaked unboundedly. Post-fix Stop pokes the loop's
//       outer select and the loop returns at the next boundary.
//
// Note: the test logic runs inside a spawned goroutine. This predates
// main-on-goroutine (main used to run on the bootstrap thread with no
// current_g, where `Sleep` blocked the whole thread); today main is
// itself a goroutine and could host the tests directly, but the
// wrapper is kept so the NumGoroutine baselines in each test stay one
// level removed from the main G.

#![no_std]
#![no_main]

use core::sync::atomic::{AtomicI64, Ordering};

use goish::context::{Background, WithCancel};
use goish::runtime::sched::schedule;
use goish::runtime::NumGoroutine;
use goish::time::{Milliseconds, NewTicker, NewTimer, Sleep};
use goish::{int, syscall};

fn die(msg: &[u8]) -> ! {
    syscall::Write(syscall::STDERR, msg.as_ptr(), msg.len());
    syscall::Exit(1);
}

fn check(cond: bool, msg: &[u8]) {
    if !cond {
        die(msg);
    }
}

// Wait up to `max_ms` for NumGoroutine to drop back to `target`.
// Returns the final count (≤ target on success, > target on
// timeout). Polls in 10 ms increments via Sleep, which yields to
// the scheduler so other gors can run.
fn wait_drop_to(target: int, max_ms: i64) -> int {
    let mut waited = 0i64;
    let step = 10i64;
    loop {
        let n = NumGoroutine();
        if n <= target || waited >= max_ms {
            return n;
        }
        Sleep(Milliseconds(step));
        waited += step;
    }
}

fn write_int(n: int) {
    let mut buf = [0u8; 24];
    let mut i = 24;
    let mut v = if n < 0 { -n } else { n } as i64;
    if v == 0 {
        i -= 1;
        buf[i] = b'0';
    } else {
        while v > 0 {
            i -= 1;
            buf[i] = b'0' + (v % 10) as u8;
            v /= 10;
        }
    }
    if n < 0 {
        i -= 1;
        buf[i] = b'-';
    }
    syscall::Write(syscall::STDERR, buf.as_ptr().wrapping_add(i), 24 - i);
}

fn report_fail(label: &[u8], baseline: int, after: int) -> ! {
    syscall::Write(syscall::STDERR, label.as_ptr(), label.len());
    const B: &[u8] = b" baseline=";
    syscall::Write(syscall::STDERR, B.as_ptr(), B.len());
    write_int(baseline);
    const A: &[u8] = b" after=";
    syscall::Write(syscall::STDERR, A.as_ptr(), A.len());
    write_int(after);
    const NL: &[u8] = b"\n";
    syscall::Write(syscall::STDERR, NL.as_ptr(), NL.len());
    syscall::Exit(1);
}

// ── Test 1: cancel a chained context, verify watcher gor exits ────
//
// `build_cancel_ctx` only spawns a watcher when parent.Done() is
// non-nil. Background's Done is nil, so WithCancel(Background())
// alone won't trigger the watcher. We need a TWO-level chain:
// outer cancel ctx is a non-nil-Done parent for the inner one.
fn test_context_chain_cancel() {
    let baseline = NumGoroutine();

    let bg = Background();
    let (outer_ctx, outer_cancel) = WithCancel(bg);
    let (_inner_ctx, inner_cancel) = WithCancel(outer_ctx);

    // Inner ctx's watcher is now parked on
    //   select { outer.Done() | inner.Done() }
    Sleep(Milliseconds(20));
    let with_watcher = NumGoroutine();
    check(
        with_watcher >= baseline + 1,
        b"context: watcher gor not spawned\n",
    );

    // Cancel the CHILD only. Without the M24a fix, the watcher
    // would still be parked on outer.Done().Recv() forever.
    inner_cancel();

    let n = wait_drop_to(baseline, 500);
    if n > baseline {
        report_fail(b"context: child cancel leaked watcher;", baseline, n);
    }

    // Clean up the outer too.
    outer_cancel();
    let _ = wait_drop_to(baseline, 500);
}

// ── Test 2: NewTimer + Stop early, watcher should exit promptly ───
//
// Pre-fix: Stop set a flag; watcher did Sleep(d) ANYWAY then
// post-checked. Worst-case watcher lifetime ≈ d regardless of Stop.
//
// Post-fix: outer watcher select!s After(d) against stop_chan. Stop
// drives the outer watcher out immediately. The After(d) it
// already kicked off has its OWN gor with lifetime ≤ d — we pick
// d small enough that wait_drop_to's window covers it.
fn test_timer_stop() {
    let baseline = NumGoroutine();

    // d = 2000 ms. Without the fix the watcher Sleep(d)s the FULL
    // duration after Stop, so the test's 300 ms wait would fail.
    // With the fix Stop unblocks the outer watcher on the next
    // scheduling boundary; only the spawn_fire gor lingers for ≤ d,
    // but it does NOT count as a leak from the user's perspective.
    // We measure baseline + 1 (just the spawn_fire) is acceptable
    // since spawn_fire doesn't hold any user state — only the
    // outer watcher does.
    let timer = NewTimer(Milliseconds(2000));
    Sleep(Milliseconds(20)); // let the watcher set up
    let with_watcher = NumGoroutine();
    check(
        with_watcher >= baseline + 1,
        b"timer: watcher gor not spawned\n",
    );

    let stopped_first = timer.Stop();
    check(stopped_first, b"timer: first Stop didn't return true\n");
    // Idempotency:
    check(!timer.Stop(), b"timer: second Stop returned true\n");

    // KEY DISTINGUISHING ASSERTION: after Stop, the count must
    // DROP within a short window. Pre-fix the watcher's Sleep(d)
    // runs to completion regardless of Stop, so the count stays
    // at `with_watcher` for d = 2 s. Post-fix the outer watcher
    // (which holds Arc<chan<Time>> = the user's timer.C) exits
    // on the next scheduling boundary, dropping the count by at
    // least 1.
    let target = with_watcher - 1;
    let n = wait_drop_to(target, 300);
    if n > target {
        report_fail(
            b"timer: Stop did not release outer watcher within 300 ms;",
            target,
            n,
        );
    }
    // Drain to baseline so the next test starts clean. Allow ≤ d.
    let n = wait_drop_to(baseline, 2500);
    if n > baseline {
        report_fail(b"timer: did not drain to baseline in d window;", baseline, n);
    }
}

// ── Test 3: NewTicker + Stop, watcher loop should exit ───────────
//
// Pre-fix: dropping the Ticker without Stop leaked unboundedly
// because the loop's Sleep(d) had no cancellation path.
//
// Post-fix: outer loop's select!s each tick's After(d) against
// stop_chan. Stop ⇒ outer loop returns at the next select edge,
// which is sub-millisecond.
fn test_ticker_stop() {
    let baseline = NumGoroutine();

    // d = 1000 ms — long enough that without the fix, the
    // outer loop's Sleep would absorb our entire wait window.
    let ticker = NewTicker(Milliseconds(1000));
    Sleep(Milliseconds(20)); // let the watcher start
    let with_watcher = NumGoroutine();
    check(
        with_watcher >= baseline + 1,
        b"ticker: watcher gor not spawned\n",
    );

    ticker.Stop();
    // Idempotent:
    ticker.Stop();

    // Same key assertion: count DROPS within a short window. Pre-
    // fix, the loop's Sleep(d) absorbs the wait — count stays at
    // `with_watcher`. Post-fix the outer loop exits on the next
    // select edge.
    let target = with_watcher - 1;
    let n = wait_drop_to(target, 200);
    if n > target {
        report_fail(
            b"ticker: Stop did not release outer loop within 200 ms;",
            target,
            n,
        );
    }
    // Drain to baseline (≤ d for in-flight spawn_fire).
    let n = wait_drop_to(baseline, 1500);
    if n > baseline {
        report_fail(b"ticker: did not drain to baseline in d window;", baseline, n);
    }
}

// Signal channel: written by the test gor when all sub-tests have
// completed successfully. Main parks on this until it fires.
static DONE: AtomicI64 = AtomicI64::new(0);

#[goish::main]
fn main() {
    goish::go!(|| {
        test_context_chain_cancel();
        test_timer_stop();
        test_ticker_stop();
        DONE.store(1, Ordering::Release);
    });

    // schedule() drains until LIVE_G_COUNT == 0 — i.e., until the
    // test gor (and any watcher gors it spawned) have all exited.
    // If our fixes work, they all exit on cue. If not, the still-
    // parked watchers prevent shutdown and the test process hangs
    // until the run script's outer timeout kicks it.
    schedule();

    if DONE.load(Ordering::Acquire) != 1 {
        die(b"leak_proof: test gor did not finish\n");
    }

    const OK: &[u8] = b"leak_proof: ok\n";
    syscall::Write(syscall::STDOUT, OK.as_ptr(), OK.len());
}
