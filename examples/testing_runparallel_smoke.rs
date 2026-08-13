// testing_runparallel_smoke — B.RunParallel and PB.Next.
//
// RunParallel splits b.N iterations across parallelism*GOMAXPROCS
// goroutines. The whole design is in how they claim work: each worker
// takes a BATCH of `grain` iterations from one shared atomic, so the
// atomic is touched once per batch rather than once per iteration.
//
// Two details are easy to lose, and both are silent when lost:
//
//   * PB.Next's middle branch. When a batch would overshoot b.N, the
//     worker takes the PARTIAL remainder instead of giving up. Drop it
//     and the last grain-1 iterations never run — the benchmark
//     measures fewer operations than it reports, and nothing says so.
//     Check 1 counts exactly.
//   * A body that returns before Next() says stop has measured less
//     than b.N. Go calls Fatal, because the alternative is publishing
//     a number that is wrong. Check 3.

#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

use core::sync::atomic::{AtomicU64, Ordering};
use goish::testing::benchmark::B;
use goish::{fmt, syscall};

/// Counts every iteration handed out across all workers.
static COUNT: AtomicU64 = AtomicU64::new(0);

#[goish::main]
fn main() {
    let mut failed = 0;

    // 1. Every one of b.N iterations is handed out EXACTLY once, across
    //    all workers. Not b.N-ish: exactly. A lost partial batch shows
    //    up here as a shortfall, a double-claim as a surplus.
    {
        COUNT.store(0, Ordering::SeqCst);
        let mut b = B::default();
        b.N = 10000;
        b.RunParallel(|pb| {
            while pb.Next() {
                COUNT.fetch_add(1, Ordering::Relaxed);
            }
        });
        let got = COUNT.load(Ordering::SeqCst);
        if got == 10000 {
            fmt::Println!("[ 1] exactly b.N iterations    PASS");
        } else {
            fmt::Println!("[ 1] exactly b.N iterations    FAIL got ", got as i64);
            failed += 1;
        }
    }

    // 2. …and it holds for an N that is not a multiple of anything
    //    convenient, which is where an off-by-one in the partial-batch
    //    branch would surface.
    {
        COUNT.store(0, Ordering::SeqCst);
        let mut b = B::default();
        b.N = 7777;
        b.RunParallel(|pb| {
            while pb.Next() {
                COUNT.fetch_add(1, Ordering::Relaxed);
            }
        });
        let got = COUNT.load(Ordering::SeqCst);
        if got == 7777 {
            fmt::Println!("[ 2] awkward N is exact        PASS");
        } else {
            fmt::Println!("[ 2] awkward N is exact        FAIL got ", got as i64);
            failed += 1;
        }
    }

    // 3. A body that returns early is a FAILURE, not a warning — it has
    //    measured fewer iterations than the reported b.N.
    {
        let mut b = B::default();
        b.N = 1000;
        b.RunParallel(|pb| {
            // Take one iteration and leave.
            let _ = pb.Next();
        });
        if b.Failed() {
            fmt::Println!("[ 3] early exit fails the run  PASS");
        } else {
            fmt::Println!("[ 3] early exit fails the run  FAIL");
            failed += 1;
        }
    }

    // 4. N == 0 does nothing at all — Go's "nothing to do when
    //    probing". The body must not run, and the run must not fail.
    {
        COUNT.store(0, Ordering::SeqCst);
        let mut b = B::default();
        b.N = 0;
        b.RunParallel(|pb| {
            while pb.Next() {
                COUNT.fetch_add(1, Ordering::Relaxed);
            }
        });
        if COUNT.load(Ordering::SeqCst) == 0 && !b.Failed() {
            fmt::Println!("[ 4] N=0 is a no-op            PASS");
        } else {
            fmt::Println!("[ 4] N=0 is a no-op            FAIL");
            failed += 1;
        }
    }

    if failed == 0 {
        fmt::Println!("ok 4/4");
        syscall::Exit(0);
    } else {
        fmt::Println!("FAIL", failed, "of 4");
        syscall::Exit(1);
    }
}
