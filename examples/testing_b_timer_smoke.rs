// testing_b_timer_smoke — testing.B's timer and allocation accounting.
//
// The point of StopTimer is not just the clock. Go samples
// runtime.MemStats in StartTimer and StopTimer too, so allocations made
// while the timer is stopped are excluded from allocs/op — that is what
// makes `StopTimer(); expensive_setup(); StartTimer()` mean anything.
// Check 3 is the one that would catch a port that only tracked time.

#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

use alloc::boxed::Box;
use alloc::vec::Vec;
use goish::gostring::string;
use goish::testing::benchmark::B;
use goish::{fmt, syscall};

fn s(x: &str) -> string {
    return string::from_bytes(x.as_bytes());
}

/// Allocate `n` boxes and keep them alive past the sample.
fn burn(n: usize) -> Vec<Box<[u8; 1024]>> {
    let mut v: Vec<Box<[u8; 1024]>> = Vec::with_capacity(n);
    for _ in 0..n {
        v.push(Box::new([3u8; 1024]));
    }
    return v;
}

#[goish::main]
fn main() {
    let mut failed = 0;

    // 1. Elapsed advances while the timer runs and freezes when it is
    //    stopped.
    {
        let mut b = B::default();
        b.StartTimer();
        let _k = burn(4);
        b.StopTimer();
        let d1 = b.Elapsed();
        // Time passes here, but the timer is off, so Elapsed must not
        // move.
        let _k2 = burn(64);
        let d2 = b.Elapsed();
        if d1.0 > 0 && d1.0 == d2.0 {
            fmt::Println!("[ 1] Elapsed freezes on stop   PASS");
        } else {
            fmt::Println!("[ 1] Elapsed freezes on stop   FAIL");
            failed += 1;
        }
    }

    // 2. ResetTimer zeroes the elapsed time and the allocation counters.
    {
        let mut b = B::default();
        b.StartTimer();
        let _k = burn(8);
        b.StopTimer();
        b.ResetTimer();
        let r = b.Result();
        if r.T.0 == 0 && r.MemAllocs == 0 && r.MemBytes == 0 {
            fmt::Println!("[ 2] ResetTimer zeroes all     PASS");
        } else {
            fmt::Println!("[ 2] ResetTimer zeroes all     FAIL");
            failed += 1;
        }
    }

    // 3. Allocations made while the timer is STOPPED are not charged.
    //    Two benchmarks allocate wildly different amounts overall; the
    //    one that does its extra work with the timer off must report
    //    the smaller allocation count.
    {
        let mut lean = B::default();
        lean.N = 1;
        lean.StartTimer();
        let _a = burn(2);
        lean.StopTimer();
        // Timer is off — this must not be charged.
        let _setup = burn(200);
        let lean_allocs = lean.Result().MemAllocs;

        let mut fat = B::default();
        fat.N = 1;
        fat.StartTimer();
        let _b = burn(202);
        fat.StopTimer();
        let fat_allocs = fat.Result().MemAllocs;

        if fat_allocs > lean_allocs {
            fmt::Println!("[ 3] stopped allocs excluded   PASS");
        } else {
            fmt::Println!("[ 3] stopped allocs excluded   FAIL");
            failed += 1;
        }
    }

    // 4. SetBytes feeds MB/s through the result.
    {
        let mut b = B::default();
        b.N = 100;
        b.SetBytes(1024);
        b.StartTimer();
        let _k = burn(1);
        b.StopTimer();
        let r = b.Result();
        if r.Bytes == 1024 && r.mbPerSec() > 0.0 {
            fmt::Println!("[ 4] SetBytes drives MB/s      PASS");
        } else {
            fmt::Println!("[ 4] SetBytes drives MB/s      FAIL");
            failed += 1;
        }
    }

    // 5. ReportMetric lands in Extra and overrides a built-in metric,
    //    which is what BenchmarkResult's accessors check first.
    {
        let mut b = B::default();
        b.N = 10;
        b.ResetTimer(); // allocates the extra map
        b.ReportMetric(42.0, &s("ns/op"));
        b.ReportMetric(1.25, &s("frobs/op"));
        let r = b.Result();
        let (custom, ok) = r.Extra.Get(s("frobs/op"));
        if r.NsPerOp() == 42 && ok && custom == 1.25 {
            fmt::Println!("[ 5] ReportMetric overrides    PASS");
        } else {
            fmt::Println!("[ 5] ReportMetric overrides    FAIL");
            failed += 1;
        }
    }

    // 6. StartTimer on an already-running timer is a no-op, and
    //    StopTimer on a stopped one likewise — Go guards both with a
    //    `timerOn` check, so a double call must not double-count.
    {
        let mut b = B::default();
        b.StartTimer();
        b.StartTimer();
        let _k = burn(4);
        b.StopTimer();
        let once = b.Elapsed();
        b.StopTimer();
        let twice = b.Elapsed();
        if once.0 == twice.0 {
            fmt::Println!("[ 6] double start/stop no-op   PASS");
        } else {
            fmt::Println!("[ 6] double start/stop no-op   FAIL");
            failed += 1;
        }
    }

    if failed == 0 {
        fmt::Println!("ok 6/6");
        syscall::Exit(0);
    } else {
        fmt::Println!("FAIL", failed, "of 6");
        syscall::Exit(1);
    }
}
