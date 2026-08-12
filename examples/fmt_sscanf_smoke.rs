// fmt_sscanf_smoke — exercise fmt.Sscanf's %d / %f verbs, including
// scanning into a math/big.Rat through the fmt.Scanner interface.
//
// Ported from the `#[cfg(test)] mod sscanf_tests` that used to live at
// the bottom of src/fmt/mod.rs. `cargo test` cannot link in this crate
// (the test harness pulls in std, whose `panic_impl` lang item collides
// with goish's), so every in-tree #[test] was unreachable. Examples are
// goish's actual test mechanism — they run under e2e.

#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate goish;

use goish::errors::nil;
use goish::fmt;
use goish::math::big;
use goish::syscall;
use goish::types::int;

#[goish::main]
fn main() {
    let mut failed = 0;

    // 1. Sscanf("%f") into a big.Rat.
    {
        let mut val = big::Rat::default();
        let (n, err) = fmt::Sscanf("3.14", "%f", &mut val);
        // 3.14 → 314/100, reduced by big::Rat's GCD normalization to
        // 157/50.
        if n == 1 && err == nil && val.Num().Int64() == 157 && val.Denom().Int64() == 50 {
            fmt::Println!("[ 1] Sscanf %f -> big.Rat      PASS");
        } else {
            fmt::Println!("[ 1] Sscanf %f -> big.Rat      FAIL");
            failed += 1;
        }
    }

    // 2. Sscanf("%d") into an int.
    {
        let mut n: int = 0;
        let (count, err) = fmt::Sscanf("42", "%d", &mut n);
        if count == 1 && err == nil && n == 42 {
            fmt::Println!("[ 2] Sscanf %d -> int          PASS");
        } else {
            fmt::Println!("[ 2] Sscanf %d -> int          FAIL");
            failed += 1;
        }
    }

    // 3. Sscanf("%f") into a float64.
    {
        let mut x: goish::types::float64 = 0.0;
        let (count, err) = fmt::Sscanf("2.5", "%f", &mut x);
        // No float equality in the assertion — compare against a
        // tolerance, as the rest of the suite does.
        let close = (x - 2.5) < 1e-9 && (2.5 - x) < 1e-9;
        if count == 1 && err == nil && close {
            fmt::Println!("[ 3] Sscanf %f -> float64      PASS");
        } else {
            fmt::Println!("[ 3] Sscanf %f -> float64      FAIL");
            failed += 1;
        }
    }

    // 4. A parse failure reports 0 items scanned and a non-nil error.
    {
        let mut val = big::Rat::default();
        let (n, err) = fmt::Sscanf("not-a-num", "%f", &mut val);
        if n == 0 && err != nil {
            fmt::Println!("[ 4] Sscanf parse error        PASS");
        } else {
            fmt::Println!("[ 4] Sscanf parse error        FAIL");
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
