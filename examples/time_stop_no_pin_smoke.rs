// time_stop_no_pin_smoke — Timer::Stop retires the sleeper.
//
// goish waits for LIVE_G_COUNT == 0 at process exit. The old timer
// design parked an uncancellable Sleep(d) goroutine, so a STOPPED 30s
// timer still pinned exit for 30 seconds — four declared crypto
// examples were busting e2e's 15s timeout on exactly this. The
// discriminator here is wall time: stop a 30s NewTimer and a 30s
// AfterFunc, then require the whole process (including the runtime's
// exit drain) to finish in a fraction of that. On the old design this
// example cannot pass; its exit alone would take 30 s.
//
// The Stop return values and the AfterFunc-not-run check ride along
// so a Stop that "works" by never arming the timer at all is caught.

#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

use core::sync::atomic::{AtomicUsize, Ordering};

use goish::fmt;
use goish::time;

static FAILED: AtomicUsize = AtomicUsize::new(0);
static FUNC_RAN: AtomicUsize = AtomicUsize::new(0);

fn check(name: &'static str, ok: bool) {
    if ok {
        fmt::Printf!("PASS: %s\n", name);
    } else {
        FAILED.fetch_add(1, Ordering::Relaxed);
        fmt::Printf!("FAIL: %s\n", name);
    }
}

#[goish::main]
fn main() {
    goish::go!(stack(256 * 1024), move || {
        run();
    });
    loop {
        goish::runtime::sched::Gosched();
    }
}

fn run() -> ! {
    let start = time::Now();

    let t = time::NewTimer(time::Duration(30 * 1_000_000_000));
    check("Stop before fire returns true", t.Stop());
    check("second Stop returns false", !t.Stop());

    let af = time::AfterFunc(time::Duration(30 * 1_000_000_000), || {
        FUNC_RAN.store(1, Ordering::Relaxed);
    });
    check("AfterFunc Stop before fire returns true", af.Stop());

    // A ticker stopped mid-flight must not hold its sleeper either.
    let tk = time::NewTicker(time::Duration(30 * 1_000_000_000));
    tk.Stop();

    // A short timer that is NOT stopped must still fire — proves the
    // cancellable park delivers, not just cancels.
    let short = time::NewTimer(time::Duration(50 * 1_000_000));
    let _ = short.C.Recv();
    check("unstopped timer still fires", true);
    check(
        "Stop after fire returns false",
        !short.Stop(),
    );

    // Give a mis-cancelled AfterFunc a moment to prove itself.
    time::Sleep(time::Duration(100 * 1_000_000));
    check("stopped AfterFunc never ran", FUNC_RAN.load(Ordering::Relaxed) == 0);

    // The point of the test: everything above plus process exit must
    // complete far below the 30 s the stopped timers asked for. The
    // in-process bound is 5 s; e2e's own 15 s timeout guards the
    // exit-drain tail after os::Exit is requested.
    let elapsed = time::Since(start);
    check("wall time is seconds, not the timer's 30s", elapsed.0 < 5_000_000_000);

    let f = FAILED.load(Ordering::Relaxed);
    if f == 0 {
        fmt::Printf!("TIME_STOP_NO_PIN_OK\n");
        goish::os::Exit(0);
    }
    fmt::Printf!("TIME_STOP_NO_PIN_FAIL\n");
    goish::os::Exit(1);
}
