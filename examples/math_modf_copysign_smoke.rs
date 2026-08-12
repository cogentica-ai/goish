// math_modf_copysign_smoke — exercise math.Modf and math.Copysign,
// including the signed-zero and NaN edge cases that make Copysign
// worth a test at all.
//
// Ported from the `#[cfg(test)] mod tests` that used to live at the
// bottom of src/math/mod.rs. `cargo test` cannot link in this crate
// (the test harness pulls in std, whose `panic_impl` lang item collides
// with goish's), so every in-tree #[test] was unreachable. Examples are
// goish's actual test mechanism — they run under e2e.

#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate goish;

use goish::fmt;
use goish::math;
use goish::syscall;
use goish::types::float64;

/// `x` within 1e-12 of `want`, without leaning on float equality.
fn near(x: float64, want: float64) -> bool {
    let d = x - want;
    return d < 1e-12 && -d < 1e-12;
}

#[goish::main]
fn main() {
    let mut failed = 0;

    // 1. Modf splits into integer and fractional parts.
    {
        let (i1, f1) = math::Modf(3.75);
        let (i2, f2) = math::Modf(-2.25);
        let (i3, f3) = math::Modf(0.0);
        // Go: both results have the same sign as the argument.
        if near(i1, 3.0)
            && near(f1, 0.75)
            && near(i2, -2.0)
            && near(f2, -0.25)
            && near(i3, 0.0)
            && near(f3, 0.0)
        {
            fmt::Println!("[ 1] Modf integer/frac split   PASS");
        } else {
            fmt::Println!("[ 1] Modf integer/frac split   FAIL");
            failed += 1;
        }
    }

    // 2. Copysign takes the magnitude of x and the sign of y.
    {
        if near(math::Copysign(3.0, -1.0), -3.0) && near(math::Copysign(-3.0, 1.0), 3.0) {
            fmt::Println!("[ 2] Copysign magnitude/sign   PASS");
        } else {
            fmt::Println!("[ 2] Copysign magnitude/sign   FAIL");
            failed += 1;
        }
    }

    // 3. Copysign(0, -1) is negative zero — which `== 0.0` cannot see,
    //    so check the sign bit directly.
    {
        let nz = math::Copysign(0.0, -1.0);
        let pz = math::Copysign(0.0, 1.0);
        if nz.to_bits() == (-0.0f64).to_bits() && pz.to_bits() == (0.0f64).to_bits() {
            fmt::Println!("[ 3] Copysign signed zero      PASS");
        } else {
            fmt::Println!("[ 3] Copysign signed zero      FAIL");
            failed += 1;
        }
    }

    // 4. The result's sign follows `sign` even when the magnitude is
    //    NaN — Copysign is defined on the bit pattern, not the value.
    {
        let n = math::Copysign(math::NaN(), -1.0);
        let p = math::Copysign(math::NaN(), 1.0);
        if math::IsNaN(n) && n.is_sign_negative() && math::IsNaN(p) && p.is_sign_positive() {
            fmt::Println!("[ 4] Copysign NaN keeps sign   PASS");
        } else {
            fmt::Println!("[ 4] Copysign NaN keeps sign   FAIL");
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
