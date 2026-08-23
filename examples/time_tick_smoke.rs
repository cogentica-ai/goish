// time_tick_smoke — exercise time.Tick (tick.go:86). Convenience
// wrapper around NewTicker(d).C.
//
// Caveat: time.Tick returns just `<-chan Time`, leaving no Ticker
// handle to Stop. The watcher goroutine therefore lives until process
// exit. To make the smoke test terminate, we explicitly syscall::Exit
// after each test instead of falling out of main and letting the
// scheduler drain to LIVE_G_COUNT==0.

#![no_std]
#![no_main]
#![allow(non_snake_case)]
#![allow(unused_mut)]

extern crate alloc;
extern crate goish;

use core::sync::atomic::{AtomicUsize, Ordering};
use goish::runtime::sched::schedule;
use goish::time::{Milliseconds, Tick};
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
    test_tick_zero_never_ready();
    test_tick_negative_never_ready();
    test_tick_fires_periodically();

    const OK: &[u8] = b"time_tick: ok\n";
    syscall::Write(syscall::STDOUT, OK.as_ptr(), OK.len());
    // Explicit Exit — Tick(>0) leaks a watcher goroutine, so the
    // scheduler never sees LIVE_G_COUNT==0 on its own.
    syscall::Exit(0);
}

// ── Test 1: Tick(0) returns a never-ready channel ──────────────────

fn test_tick_zero_never_ready() {
    static FELL_THROUGH: AtomicUsize = AtomicUsize::new(0);
    static DONE: AtomicUsize = AtomicUsize::new(0);
    go!(|| {
        let c = Tick(Milliseconds(0));
        select! {
            let _v = c.Recv() => {
                die(b"tick(0): unexpected fire\n");
            },
            default => {
                FELL_THROUGH.store(1, Ordering::Release);
            },
        }
        DONE.store(1, Ordering::Release);
    });
    while DONE.load(Ordering::Acquire) == 0 {
        goish::runtime::sched::Gosched();
    }
    check(
        FELL_THROUGH.load(Ordering::Acquire) == 1,
        b"tick(0): didn't fall through to default\n",
    );
}

// ── Test 2: Tick(d<0) — same never-ready behavior ──────────────────

fn test_tick_negative_never_ready() {
    static FELL_THROUGH: AtomicUsize = AtomicUsize::new(0);
    static DONE: AtomicUsize = AtomicUsize::new(0);
    go!(|| {
        let c = Tick(Milliseconds(-1));
        select! {
            let _v = c.Recv() => {
                die(b"tick(<0): unexpected fire\n");
            },
            default => {
                FELL_THROUGH.store(1, Ordering::Release);
            },
        }
        DONE.store(1, Ordering::Release);
    });
    while DONE.load(Ordering::Acquire) == 0 {
        goish::runtime::sched::Gosched();
    }
    check(
        FELL_THROUGH.load(Ordering::Acquire) == 1,
        b"tick(<0): didn't fall through to default\n",
    );
}

// ── Test 3: Tick(d>0) fires periodically ───────────────────────────

fn test_tick_fires_periodically() {
    static TICKS: AtomicUsize = AtomicUsize::new(0);
    static DONE: AtomicUsize = AtomicUsize::new(0);
    go!(|| {
        let c = Tick(Milliseconds(5));
        for _ in 0..3 {
            let _ = (c.clone()).Recv();
            TICKS.fetch_add(1, Ordering::Relaxed);
        }
        DONE.store(1, Ordering::Release);
        // Watcher leaks until process exit (Tick has no Stop).
    });
    while DONE.load(Ordering::Acquire) == 0 {
        goish::runtime::sched::Gosched();
    }
    check(
        TICKS.load(Ordering::Relaxed) == 3,
        b"tick: didn't see 3 ticks\n",
    );
}

// Suppress the unused `schedule` import warning by referencing it from
// a path that always type-checks (defensive: keeps the exposed symbol
// in scope without becoming dead code).
#[allow(dead_code)]
fn _keep_schedule_alive() {
    let _ = schedule;
}
