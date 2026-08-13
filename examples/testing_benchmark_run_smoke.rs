// testing_benchmark_run_smoke — testing.Benchmark and the runN/launch
// ramp behind it.
//
// Benchmark runs a function repeatedly until it has run for -benchtime
// (1s by default), then reports the per-operation cost. The ramp is the
// interesting part: launch does not guess an iteration count, it
// MEASURES a small run and predicts from it, repeating until the
// elapsed time is long enough.
//
// Three properties, each of which a plausible implementation gets
// wrong:
//
//   * The reported N must be the count actually executed. If the ramp
//     sets b.N and the body runs a different number of times, every
//     derived metric (ns/op, allocs/op) is scaled wrong and nothing
//     reports an error.
//   * The ramp must TERMINATE for a body that costs essentially
//     nothing. Go bounds it at 1e9 iterations for exactly this.
//   * A benchmark that fails must not report a result as if it had
//     succeeded.
//
// -benchtime is not settable here without flag parsing, so these use a
// body with real work to keep the wall time small; the default 1s
// budget is what bounds the run.

#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

use core::sync::atomic::{AtomicI64, Ordering};
use goish::testing::benchmark::{Benchmark, B};
use goish::{fmt, syscall};

/// Counts how many times the body actually executed.
static ITERS: AtomicI64 = AtomicI64::new(0);

#[goish::main]
fn main() {
    let mut failed = 0;

    // 1. The reported N equals the number of iterations the body was
    //    actually asked for on the final run. A ramp that reports a
    //    predicted N rather than the executed one scales every derived
    //    metric wrong.
    {
        ITERS.store(0, Ordering::SeqCst);
        let r = Benchmark(|b: &mut B| {
            let n = b.N;
            ITERS.store(n as i64, Ordering::SeqCst);
            let mut acc: u64 = 0;
            for i in 0..n {
                acc = acc.wrapping_add((i as u64).wrapping_mul(2654435761));
            }
            // Keep the loop from being optimised away.
            if acc == 12345 {
                fmt::Println!("");
            }
        });
        let last = ITERS.load(Ordering::SeqCst);
        if r.N as i64 == last && r.N > 0 {
            fmt::Println!("[ 1] reported N is executed N  PASS");
        } else {
            fmt::Println!("[ 1] reported N is executed N  FAIL N=", r.N, " last=", last);
            failed += 1;
        }
    }

    // 2. The ramp terminates and produces a positive elapsed time. A
    //    body that costs nearly nothing is what forces the 1e9 bound to
    //    exist; reaching this line means the loop ended.
    {
        let r = Benchmark(|b: &mut B| {
            let mut acc: u64 = 0;
            for i in 0..b.N {
                acc = acc.wrapping_add(i as u64);
            }
            if acc == 7 {
                fmt::Println!("");
            }
        });
        if r.N > 0 && r.T.0 > 0 {
            fmt::Println!("[ 2] cheap body terminates     PASS");
        } else {
            fmt::Println!("[ 2] cheap body terminates     FAIL N=", r.N);
            failed += 1;
        }
    }

    // 3. ns/op is derived from the measured time and the executed
    //    count, so it must be positive and sane rather than zero.
    {
        let r = Benchmark(|b: &mut B| {
            let mut acc: u64 = 0;
            for i in 0..b.N {
                acc = acc.wrapping_add((i as u64).wrapping_mul(31));
            }
            if acc == 3 {
                fmt::Println!("");
            }
        });
        let ns = r.NsPerOp();
        if ns > 0 {
            fmt::Println!("[ 3] NsPerOp is measured       PASS");
        } else {
            fmt::Println!("[ 3] NsPerOp is measured       FAIL ns=", ns);
            failed += 1;
        }
    }

    // 4. The timer excludes work done while it is stopped. This is what
    //    StopTimer is for, and it is measurable: the same body with the
    //    bulk of its work outside the timer must report a much smaller
    //    ns/op than with it inside.
    {
        let hot = Benchmark(|b: &mut B| {
            let mut acc: u64 = 0;
            for i in 0..b.N {
                acc = acc.wrapping_add((i as u64).wrapping_mul(31));
            }
            if acc == 3 {
                fmt::Println!("");
            }
        });
        let cold = Benchmark(|b: &mut B| {
            b.StopTimer();
            let mut acc: u64 = 0;
            for i in 0..b.N {
                acc = acc.wrapping_add((i as u64).wrapping_mul(31));
            }
            if acc == 3 {
                fmt::Println!("");
            }
            b.StartTimer();
        });
        if cold.NsPerOp() < hot.NsPerOp() {
            fmt::Println!("[ 4] StopTimer excludes work   PASS");
        } else {
            fmt::Println!(
                "[ 4] StopTimer excludes work   FAIL cold=", cold.NsPerOp(),
                " hot=", hot.NsPerOp()
            );
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
