// testing_allocs_smoke — testing.AllocsPerRun, CoverMode, Coverage.
//
// AllocsPerRun is portable only because runtime::ReadMemStats exists:
// its whole body is two MemStats samples with the calls in between.
//
// The warm-up run is the subtle part and check 3 is built for it. Go
// runs f() once *before* sampling and does not count it, so a lazy
// initialisation on the first call — a sync.Once, a map's first bucket,
// a cached table — is excluded. Without the warm-up the average is
// wrong by a constant, and wrong in a way that looks like a real
// measurement.

#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

use alloc::boxed::Box;
use core::sync::atomic::{AtomicUsize, Ordering};
use goish::gostring::string;
use goish::testing::{AllocsPerRun, CoverMode, Coverage};
use goish::{fmt, syscall};

fn s(x: &str) -> string {
    return string::from_bytes(x.as_bytes());
}

static CALLS: AtomicUsize = AtomicUsize::new(0);

#[goish::main]
fn main() {
    let mut failed = 0;

    // 1. A function that allocates nothing measures zero.
    {
        let n = AllocsPerRun(50, || {
            // Deliberately no allocation.
            let _ = core::hint::black_box(1u64 + 2);
        });
        if n == 0.0 {
            fmt::Println!("[ 1] no allocation is zero     PASS");
        } else {
            fmt::Println!("[ 1] no allocation is zero     FAIL");
            failed += 1;
        }
    }

    // 2. A function allocating once per call measures at least one,
    //    and the result is integral — Go guarantees that even though
    //    the return type is float64.
    {
        let n = AllocsPerRun(50, || {
            let b: Box<u64> = Box::new(7);
            let _ = core::hint::black_box(&b);
        });
        let integral = n == (n as i64) as f64;
        if n >= 1.0 && integral {
            fmt::Println!("[ 2] one alloc per run         PASS");
        } else {
            fmt::Println!("[ 2] one alloc per run         FAIL");
            failed += 1;
        }
    }

    // 3. The warm-up call happens and is NOT counted. f runs runs+1
    //    times in total, and the extra one is the warm-up.
    {
        CALLS.store(0, Ordering::SeqCst);
        let runs = 10;
        let _ = AllocsPerRun(runs, || {
            CALLS.fetch_add(1, Ordering::SeqCst);
        });
        if CALLS.load(Ordering::SeqCst) == (runs as usize) + 1 {
            fmt::Println!("[ 3] warm-up runs, uncounted   PASS");
        } else {
            fmt::Println!(
                "[ 3] warm-up runs, uncounted   FAIL got ",
                CALLS.load(Ordering::SeqCst) as i64
            );
            failed += 1;
        }
    }

    // 4. runs <= 0 must not divide by zero.
    {
        let n = AllocsPerRun(0, || {});
        if n == 0.0 {
            fmt::Println!("[ 4] zero runs is safe         PASS");
        } else {
            fmt::Println!("[ 4] zero runs is safe         FAIL");
            failed += 1;
        }
    }

    // 5. Coverage is not enabled and says so — the empty CoverMode is
    //    Go's own answer for an uninstrumented binary, so callers
    //    branching on it take the correct path.
    {
        if CoverMode() == s("") && Coverage() == 0.0 {
            fmt::Println!("[ 5] coverage reports disabled PASS");
        } else {
            fmt::Println!("[ 5] coverage reports disabled FAIL");
            failed += 1;
        }
    }

    if failed == 0 {
        fmt::Println!("ok 5/5");
        syscall::Exit(0);
    } else {
        fmt::Println!("FAIL", failed, "of 5");
        syscall::Exit(1);
    }
}
