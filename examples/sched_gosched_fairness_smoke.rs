// sched_gosched_fairness_smoke — Gosched must yield, not monopolise.
// (runtime/proc.go)
//
// The reference numbers are what a real Go 1.25.5 delivers, from
// `tools/gen_sched_fairness_ref.go` run in `package runtime_test` by
// `scripts/goref.sh`:
//
//   sleep_200ms_took_ms 200      sleep_within_2x true
//   dial_took_ms 0               dial_under_200ms true
//
// Go's `goschedImpl` puts the yielding goroutine on the GLOBAL run
// queue (proc.go:4307 `globrunqput`), behind every other runnable G.
// goish's `gosched_m` called `enqueue_runnable`, which routes to the
// current P's LOCAL queue — and `find_runnable` checks the local queue
// BEFORE the general global one, so the yielding G was handed straight
// back to the same M.
//
// A goroutine looping on `Gosched()` therefore starved everything else
// for as long as it ran. Measured before the fix: a `net::Dial` running
// alongside such a loop took 3000 ms and returned the instant the loop
// stopped; with the loop calling `Sleep(1ms)` instead, the same dial
// took 0.18 ms.
//
// That is what made http_closenotify_smoke fail. Its handler waits for
// the notification by looping on Gosched, which starved the client
// goroutine that was supposed to disconnect — so the disconnect landed
// after the handler had already given up. The CloseNotify machinery
// was correct the whole time; nothing in net/http was wrong.

#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

use alloc::sync::Arc;
use core::sync::atomic::{AtomicBool, Ordering};

use goish::io::Closer;
use goish::net;
use goish::time;
use goish::types::int;
use goish::{fmt, go, string, syscall};

// go: none — goish idiom: the smokes print one PASS/FAIL line per
//     numbered check; this is that line, hoisted.
fn report(failed: &mut int, ok: bool, n: &str, what: &str) {
    if ok {
        fmt::Println!("[", n, "]", what, "PASS");
    } else {
        fmt::Println!("[", n, "]", what, "FAIL");
        *failed += 1;
    }
}

#[goish::main]
fn main() {
    goish::go!(stack(1024 * 1024), move || {
        run();
    });
    loop {
        goish::runtime::sched::Gosched();
    }
}

fn run() -> ! {
    let mut failed = 0;

    // Two goroutines doing nothing but yielding, for the duration.
    let stop = Arc::new(AtomicBool::new(false));
    for _ in 0..2 {
        let s = stop.clone();
        go!(stack(1024 * 1024), move || {
            while !s.load(Ordering::Relaxed) {
                goish::runtime::sched::Gosched();
            }
        });
    }
    time::Sleep(time::Duration(50 * 1_000_000));

    // 1. A sleep alongside the spinners finishes on time. Go's took
    //    200 ms for a 200 ms request; the bound here is 2x, which is
    //    loose enough for a loaded CI box and nowhere near the 15x
    //    the starving scheduler produced.
    {
        let s0 = time::Now();
        time::Sleep(time::Duration(200 * 1_000_000));
        let took = time::Since(s0).0;
        let ok = took < 400 * 1_000_000;
        if !ok {
            fmt::Println!("   sleep took_ms", took / 1_000_000);
        }
        report(
            &mut failed,
            ok,
            " 1",
            "Sleep is not starved by Gosched loops",
        );
    }

    // 2. A dial alongside the spinners connects promptly. This is the
    //    one that failed hardest: 3000 ms, released exactly when the
    //    spinners stopped.
    {
        let (ln, lerr) = net::Listen(string("tcp"), string("127.0.0.1:0"));
        if !lerr.IsNil() {
            report(&mut failed, false, " 2", "listen");
        } else {
            let port = ln.Addr().Port;
            go!(stack(1024 * 1024), move || {
                let (mut c, e) = ln.Accept();
                if e.IsNil() {
                    time::Sleep(time::Duration(300 * 1_000_000));
                    let _ = c.Close();
                }
            });
            let addr = fmt::Sprintf!("127.0.0.1:%d", port as i64);
            let d0 = time::Now();
            let (mut c, derr) = net::Dial(string("tcp"), addr);
            let took = time::Since(d0).0;
            let ok = derr.IsNil() && took < 200 * 1_000_000;
            if !ok {
                fmt::Println!("   dial took_ms", took / 1_000_000);
            }
            let _ = c.Close();
            report(
                &mut failed,
                ok,
                " 2",
                "Dial is not starved by Gosched loops",
            );
        }
    }

    // 3. The spinners were really running — otherwise checks 1 and 2
    //    prove nothing. Each yield goes through the scheduler, so a
    //    live spinner racks up a large count in 550 ms.
    {
        let ticks = Arc::new(core::sync::atomic::AtomicI64::new(0));
        let t2 = ticks.clone();
        let s2 = Arc::new(AtomicBool::new(false));
        let s2c = s2.clone();
        go!(stack(1024 * 1024), move || {
            while !s2c.load(Ordering::Relaxed) {
                t2.fetch_add(1, Ordering::Relaxed);
                goish::runtime::sched::Gosched();
            }
        });
        time::Sleep(time::Duration(100 * 1_000_000));
        s2.store(true, Ordering::Relaxed);
        let n = ticks.load(Ordering::Relaxed);
        let ok = n > 100;
        if !ok {
            fmt::Println!("   spinner ticks", n);
        }
        report(&mut failed, ok, " 3", "the spinners really do spin");
    }

    stop.store(true, Ordering::Relaxed);
    time::Sleep(time::Duration(50 * 1_000_000));

    if failed == 0 {
        fmt::Println!("ok 3/3");
        syscall::Exit(0);
    } else {
        fmt::Println!("FAIL", failed, "of 3");
        syscall::Exit(1);
    }
}
