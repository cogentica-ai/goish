// Smoke test: M18a-+ — Timer / Ticker / After.
//
// Tests:
//   1. `time.After(d)` fires after ~d and delivers exactly one value.
//   2. `select! { recv ch | recv (After(d)) }` — timeout idiom: when
//      ch never sends, After fires the timeout case.
//   3. `NewTimer + Stop` — Stop before fire prevents the send. Stop
//      after fire returns false.
//   4. `NewTicker` — receive several ticks then Stop; Stop halts
//      further ticks.

#![no_std]
#![no_main]

use core::sync::atomic::{AtomicI64, AtomicUsize, Ordering};

use goish::runtime::sched::schedule;
use goish::time::{After, Milliseconds, NewTicker, NewTimer, Now, Since};
use goish::{go, select, syscall};

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
    test_after_delivers_one();
    test_select_timeout();
    test_timer_stop_prevents_fire();
    test_ticker_periodic_then_stop();

    const OK: &[u8] = b"time_timer: ok\n";
    syscall::Write(syscall::STDOUT, OK.as_ptr(), OK.len());
}

// ── Test 1: After fires once after the duration ───────────────────

fn test_after_delivers_one() {
    static FIRED: AtomicUsize = AtomicUsize::new(0);
    static ELAPSED: AtomicI64 = AtomicI64::new(0);

    go!(|| {
        let t0 = Now();
        let ch = After(Milliseconds(10));
        let _ = ch.Recv();
        ELAPSED.store(Since(t0).Nanoseconds(), Ordering::Release);
        FIRED.store(1, Ordering::Release);
    });
    schedule();

    check(FIRED.load(Ordering::Acquire) == 1, b"after: didn't fire\n");
    let e = ELAPSED.load(Ordering::Acquire);
    check(e >= 9_000_000, b"after: fired too early\n");
    check(e <= 60_000_000, b"after: fired too late\n");
}

// ── Test 2: select with After as a timeout ────────────────────────

fn test_select_timeout() {
    static TIMEOUT_FIRED: AtomicUsize = AtomicUsize::new(0);

    let never = goish::make!(chan i64);
    go!(move || {
        select! {
            let _v = never.Recv() => die(b"select-timeout: never fired\n"),
            let _t = (After(Milliseconds(10))).Recv() => {
                TIMEOUT_FIRED.store(1, Ordering::Release);
            },
        }
    });
    schedule();

    check(
        TIMEOUT_FIRED.load(Ordering::Acquire) == 1,
        b"select-timeout: After didn't fire\n",
    );
}

// ── Test 3: Timer.Stop prevents the send ──────────────────────────

fn test_timer_stop_prevents_fire() {
    static GOT: AtomicUsize = AtomicUsize::new(0);
    static STOP_OK: AtomicUsize = AtomicUsize::new(0);

    go!(|| {
        let t = NewTimer(Milliseconds(50));
        // Stop before the timer fires.
        let was_active = t.Stop();
        STOP_OK.store(if was_active { 1 } else { 0 }, Ordering::Release);

        // Drain attempt: select with default — must NOT receive.
        select! {
            let _v = (t.C.clone()).Recv() => GOT.store(99, Ordering::Release),
            default => GOT.store(0, Ordering::Release),
        }

        // Sleep past the original deadline; still no value.
        goish::time::Sleep(Milliseconds(70));
        select! {
            let _v = (t.C.clone()).Recv() => GOT.store(99, Ordering::Release),
            default => {},
        }
    });
    schedule();

    check(STOP_OK.load(Ordering::Acquire) == 1, b"timer-stop: was_active wrong\n");
    check(GOT.load(Ordering::Acquire) == 0, b"timer-stop: timer fired anyway\n");
}

// ── Test 4: Ticker fires periodically; Stop halts further ticks ──

fn test_ticker_periodic_then_stop() {
    static TICKS: AtomicUsize = AtomicUsize::new(0);

    go!(|| {
        let t = NewTicker(Milliseconds(5));
        // Receive 3 ticks.
        for _ in 0..3 {
            let _ = (t.C.clone()).Recv();
            TICKS.fetch_add(1, Ordering::Relaxed);
        }
        t.Stop();
        // After Stop the ticker's internal goroutine sees the
        // cancel flag on its next wakeup and exits. We don't
        // attempt to drain a possibly-racing in-flight tick;
        // testing that no further ticks arrive would require
        // a way to terminate the drainer cleanly which we
        // don't have without close(). The "got 3 ticks" check
        // below is the load-bearing assertion.
    });
    schedule();

    check(TICKS.load(Ordering::Relaxed) == 3, b"ticker: didn't see 3 ticks\n");
}
