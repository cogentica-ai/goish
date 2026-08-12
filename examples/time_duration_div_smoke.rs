// time_duration_div_smoke — exercise `time.Duration / time.Duration`
// and `time.Duration / int`.
//
// Ported from the `#[cfg(test)] mod duration_div_tests` that used to
// live at the bottom of src/time/mod.rs. `cargo test` cannot link in
// this crate (the test harness pulls in std, whose `panic_impl` lang
// item collides with goish's), so every in-tree #[test] was
// unreachable. Examples are goish's actual test mechanism — they run
// under e2e.
//
// The deleted module's third case was `#[should_panic]` on a divide by
// zero. goish builds with panic=abort, so a panic terminates the
// process rather than unwinding into a harness, and it cannot be
// asserted from inside the program under test. The guard itself is
// still there in both Div impls (src/time/mod.rs:372, :383).

#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate goish;

use goish::syscall;
use goish::time;
use goish::{fmt, time::Duration};

#[goish::main]
fn main() {
    let mut failed = 0;

    // 1. Duration / Duration is a unitless ratio, carried in a
    //    Duration as Go does — 10s / 1s = 10.
    {
        let a = Duration(10_000_000_000);
        let b = Duration(1_000_000_000);
        if (a / b).0 == 10 {
            fmt::Println!("[ 1] Duration / Duration       PASS");
        } else {
            fmt::Println!("[ 1] Duration / Duration       FAIL");
            failed += 1;
        }
    }

    // 2. Duration / int scales the duration — 1s / 4 = 250ms.
    {
        let q = time::Second / 4;
        if q.0 == 250_000_000 && q == 250 * time::Millisecond {
            fmt::Println!("[ 2] Duration / int            PASS");
        } else {
            fmt::Println!("[ 2] Duration / int            FAIL");
            failed += 1;
        }
    }

    // 3. Truncation is toward zero on both signs, as Go's int64
    //    division is.
    {
        let neg = Duration(-7_000_000_000) / Duration(2_000_000_000);
        let pos = Duration(7_000_000_000) / Duration(2_000_000_000);
        if neg.0 == -3 && pos.0 == 3 {
            fmt::Println!("[ 3] Duration div truncates    PASS");
        } else {
            fmt::Println!("[ 3] Duration div truncates    FAIL");
            failed += 1;
        }
    }

    if failed == 0 {
        fmt::Println!("ok 3/3");
        syscall::Exit(0);
    } else {
        fmt::Println!("FAIL", failed, "of 3");
        syscall::Exit(1);
    }
}
