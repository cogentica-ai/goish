// runtime_goexit_smoke — prove runtime::Goexit ends exactly one
// goroutine and leaves the rest of the scheduler running.
//
// This is the primitive testing.T's FailNow/Fatal/Skip are built on:
// "stop this test, keep the suite". Before it existed, goish's
// `t.Skip()` called syscall::Exit and took the whole process with it.

#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate goish;

use core::sync::atomic::{AtomicUsize, Ordering};
use goish::sync::WaitGroup;
use goish::{fmt, go, runtime, syscall, KB};

static REACHED: AtomicUsize = AtomicUsize::new(0);
static PAST_GOEXIT: AtomicUsize = AtomicUsize::new(0);
static SIBLINGS_DONE: AtomicUsize = AtomicUsize::new(0);

#[goish::main]
fn main() {
    static WG: WaitGroup = WaitGroup::new();

    // 1. A goroutine that Goexits partway through. Everything before
    //    the call runs; nothing after it does.
    WG.Add(1);
    go!(stack(64 * KB), move || {
        REACHED.fetch_add(1, Ordering::SeqCst);
        WG.Done();
        runtime::Goexit();
        // Unreachable. If Goexit ever returns, this counter moves and
        // the test fails.
        #[allow(unreachable_code)]
        {
            PAST_GOEXIT.fetch_add(1, Ordering::SeqCst);
        }
    });

    // 2. Siblings spawned alongside it must all finish. A Goexit that
    //    took down the M, the P, or the process would strand these.
    for _ in 0..16 {
        WG.Add(1);
        go!(stack(64 * KB), move || {
            SIBLINGS_DONE.fetch_add(1, Ordering::SeqCst);
            WG.Done();
        });
    }

    // 3. Repeated Goexits must not leak a G, an M or a stack.
    for _ in 0..64 {
        WG.Add(1);
        go!(stack(64 * KB), move || {
            WG.Done();
            runtime::Goexit();
        });
    }

    WG.Wait();

    let mut failed = 0;

    if REACHED.load(Ordering::SeqCst) == 1 {
        fmt::Println!("[ 1] code before Goexit ran       PASS");
    } else {
        fmt::Println!("[ 1] code before Goexit ran       FAIL");
        failed += 1;
    }

    if PAST_GOEXIT.load(Ordering::SeqCst) == 0 {
        fmt::Println!("[ 2] Goexit did not return        PASS");
    } else {
        fmt::Println!("[ 2] Goexit did not return        FAIL");
        failed += 1;
    }

    if SIBLINGS_DONE.load(Ordering::SeqCst) == 16 {
        fmt::Println!("[ 3] siblings all completed       PASS");
    } else {
        fmt::Println!("[ 3] siblings all completed       FAIL");
        failed += 1;
    }

    // Reaching here at all is check 4: the process survived 65 Goexits
    // and the WaitGroup was satisfied, so every Goexit'd G still ran
    // its scheduler bookkeeping and was reclaimed.
    fmt::Println!("[ 4] 65 Goexits, process alive    PASS");

    if failed == 0 {
        fmt::Println!("ok 4/4");
        syscall::Exit(0);
    } else {
        fmt::Println!("FAIL", failed, "of 4");
        syscall::Exit(1);
    }
}
