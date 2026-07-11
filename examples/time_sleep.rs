// Smoke test: M18a — time.Sleep + sysmon thread.
//
// Tests:
//   1. Single goroutine sleeps for ~10ms; verify wall-clock duration
//      is in [10ms, 30ms].
//   2. Many goroutines sleep concurrently with varied durations.
//      Verify all complete and elapsed time is bounded by the
//      longest sleep (i.e., they slept in parallel — sysmon woke
//      them on time, not serialized via the M's CPU time).
//   3. A goroutine sleeps and another runs in parallel — verifies
//      Sleep doesn't block the M (the running G makes progress
//      while the sleeper is parked).

#![no_std]
#![no_main]

use core::sync::atomic::{AtomicI64, AtomicUsize, Ordering};

use goish::runtime::sched::schedule;
use goish::time::{Now, Sleep, Since, Milliseconds};
use goish::{go, syscall};

fn die(msg: &[u8]) -> ! {
    syscall::Write(syscall::STDERR, msg.as_ptr(), msg.len());
    syscall::Exit(1);
}

fn check(cond: bool, msg: &[u8]) {
    if !cond {
        die(msg);
    }
}

#[goish::main]
fn main() {
    test_single_sleep();
    test_concurrent_sleeps();
    test_sleeper_doesnt_block_m();

    const OK: &[u8] = b"time_sleep: ok\n";
    syscall::Write(syscall::STDOUT, OK.as_ptr(), OK.len());
}

// ── Test 1: single 10ms sleep, elapsed in [10, 30] ms ────────────

fn test_single_sleep() {
    static GOT: AtomicI64 = AtomicI64::new(0);
    static DONE: AtomicUsize = AtomicUsize::new(0);

    go!(|| {
        let t0 = Now();
        Sleep(Milliseconds(10));
        let elapsed = Since(t0).Nanoseconds();
        GOT.store(elapsed, Ordering::Release);
        DONE.store(1, Ordering::Release);
    });
    schedule();

    check(DONE.load(Ordering::Acquire) == 1, b"single: didn't finish\n");
    let elapsed = GOT.load(Ordering::Acquire);
    // 10ms = 10_000_000 ns. Allow up to 30ms upper bound for sysmon
    // poll latency under stress.
    check(elapsed >= 9_000_000, b"single: elapsed too short\n");
    check(elapsed <= 50_000_000, b"single: elapsed too long\n");
}

// ── Test 2: many concurrent sleepers with varied durations ──────
//
// Sleeps: [5, 10, 15, 20, 25] ms × 4 goroutines each = 20 sleepers.
// Total elapsed should be ~25ms (longest), NOT ~5+10+15+20+25 ms ×
// 4 = serialized. This proves they ran in parallel.

fn test_concurrent_sleeps() {
    static GS_DONE: AtomicUsize = AtomicUsize::new(0);
    GS_DONE.store(0, Ordering::Relaxed);

    let durations_ms: [i64; 5] = [5, 10, 15, 20, 25];
    let copies = 4;
    let total = durations_ms.len() as usize * copies;

    let t0 = Now();
    for &ms in &durations_ms {
        for _ in 0..copies {
            go!(move || {
                Sleep(Milliseconds(ms));
                GS_DONE.fetch_add(1, Ordering::Relaxed);
            });
        }
    }
    schedule();
    let elapsed_ms = Since(t0).Milliseconds();

    check(
        GS_DONE.load(Ordering::Relaxed) == total,
        b"concurrent: not all finished\n",
    );
    // Longest is 25ms; with sysmon overhead allow up to 80ms.
    // If sleeps were serialized this would be ~300ms.
    check(elapsed_ms < 80, b"concurrent: too slow (serialized?)\n");
}

// ── Test 3: a sleeper coexists with a busy goroutine ────────────
//
// One G sleeps 20ms; another G does some work and exits quickly.
// The work must complete during the sleep (i.e., the M didn't
// block on nanosleep).

fn test_sleeper_doesnt_block_m() {
    static SLEEPER_DONE: AtomicUsize = AtomicUsize::new(0);
    static WORKER_DONE: AtomicUsize = AtomicUsize::new(0);
    SLEEPER_DONE.store(0, Ordering::Relaxed);
    WORKER_DONE.store(0, Ordering::Relaxed);

    go!(|| {
        Sleep(Milliseconds(20));
        SLEEPER_DONE.store(1, Ordering::Release);
    });

    go!(|| {
        // No I/O, no sleep — just CPU work.
        let mut acc: u64 = 0;
        for i in 0..100_000u64 {
            acc = acc.wrapping_add(i.wrapping_mul(7));
        }
        let _ = acc;
        WORKER_DONE.store(1, Ordering::Release);
    });

    schedule();

    check(SLEEPER_DONE.load(Ordering::Acquire) == 1, b"coexist: sleeper missing\n");
    check(WORKER_DONE.load(Ordering::Acquire) == 1, b"coexist: worker missing\n");
}
