// math_special_ref_smoke — the documented special cases, against a
// running Go. (math/dim.go, math/modf.go, math/pow.go, math/atan2.go)
//
// Every expectation below is what a real Go 1.25.5 prints: the vectors
// are the output of `tools/gen_math_special_ref.go` run in `package
// math_test` by `scripts/goref.sh`.
//
// goish's `math` had no provenance anchors at all — 78 of Go's 159
// functions matched by NAME only — so nothing had ever diffed it. Four
// of them answered differently from Go, and every one returns a
// plausible number rather than an error:
//
//   * `Max(+Inf, NaN)` was NaN. Go tests +Inf FIRST and answers +Inf;
//     the order of the switch is the content of the function.
//   * `Max(+0, -0)` was -0, and `Min(-0, +0)` was +0. goish's doc
//     comment claimed "+0 > -0" while its code tested `x > y`, which is
//     false for that pair.
//   * `Dim(x, NaN)` and `Dim(±Inf, ±Inf)` were 0. Go reaches all four
//     NaN cases with one test — `if v <= 0 { return 0 }`, which is
//     FALSE for a NaN so the NaN falls through — and goish tested
//     `d > 0.0`, which is also false for a NaN, and returned 0.
//   * `Modf(-1)` was (-1, +0). Go computes the negative case as
//     `Modf(-f)` negated, so the fractional part carries the sign of
//     the input: (-1, -0). A signed zero survives into Signbit,
//     Copysign and the wire format of anything that stores the bits.
//
// The rest of the surface — Floor/Ceil/Round/Trunc at the halves and
// the zeros, all twenty of Pow's special cases, Log/Sqrt/Exp at their
// boundaries, Atan2's table, Frexp/Ldexp — already matched, which is
// what makes the four worth the anchors they now have.

#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

use goish::gostring::string;
use goish::math;
use goish::types::int;
use goish::{fmt, syscall};

fn s(x: &str) -> string {
    return string::from_bytes(x.as_bytes());
}

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

// go: none — goish idiom: `%v` of a float loses the sign of a zero,
//     which is exactly what several of these cases turn on, so the
//     rendering says it explicitly. Go's reference does the same.
fn z(v: f64) -> string {
    if v == 0.0 {
        return if math::Signbit(v) { s("-0") } else { s("+0") };
    }
    return fmt::Sprintf!("%v", v);
}

fn eq(ok: &mut bool, what: &str, got: string, want: &str) {
    if got != s(want) {
        fmt::Println!("   ", s(what), "got", got, "want", s(want));
        *ok = false;
    }
}

#[goish::main]
fn main() {
    let mut failed = 0;
    let nan = f64::NAN;
    let inf = f64::INFINITY;
    let ninf = f64::NEG_INFINITY;
    let nz = -0.0f64;

    // 1. Max and Min. Columns are Go's: (x, y, max, min).
    {
        let mut ok = true;
        let cases: [(f64, f64, &str, &str); 20] = [
            (1.0, 2.0, "2", "1"),
            (2.0, 1.0, "2", "1"),
            (1.0, 1.0, "1", "1"),
            // The signed zeros: +0 wins for Max, -0 for Min, whichever
            // side they are given on.
            (0.0, nz, "+0", "-0"),
            (nz, 0.0, "+0", "-0"),
            (nz, nz, "-0", "-0"),
            (nan, 1.0, "NaN", "NaN"),
            (1.0, nan, "NaN", "NaN"),
            (nan, nan, "NaN", "NaN"),
            (inf, 1.0, "+Inf", "1"),
            (1.0, inf, "+Inf", "1"),
            (ninf, 1.0, "1", "-Inf"),
            (1.0, ninf, "1", "-Inf"),
            (inf, inf, "+Inf", "+Inf"),
            (ninf, ninf, "-Inf", "-Inf"),
            (inf, ninf, "+Inf", "-Inf"),
            // The infinity beats the NaN, on the side it applies to.
            (inf, nan, "+Inf", "NaN"),
            (nan, inf, "+Inf", "NaN"),
            (ninf, nan, "NaN", "-Inf"),
            (nan, ninf, "NaN", "-Inf"),
        ];
        let mut i = 0usize;
        while i < cases.len() {
            let (x, y, wmax, wmin) = cases[i];
            eq(&mut ok, "Max", z(math::Max(x, y)), wmax);
            eq(&mut ok, "Min", z(math::Min(x, y)), wmin);
            i += 1;
        }
        report(
            &mut failed,
            ok,
            " 1",
            "Max/Min: infinity first, then NaN, then the zeros",
        );
    }

    // 2. Dim. Go: NaN for a NaN operand and for ±Inf minus itself,
    //    0 for anything that comes out negative.
    {
        let mut ok = true;
        let cases: [(f64, f64, &str); 12] = [
            (1.0, 2.0, "+0"),
            (2.0, 1.0, "1"),
            (1.0, 1.0, "+0"),
            (nan, 1.0, "NaN"),
            (1.0, nan, "NaN"),
            (nan, nan, "NaN"),
            (inf, 1.0, "+Inf"),
            (1.0, inf, "+0"),
            (1.0, ninf, "+Inf"),
            (inf, inf, "NaN"),
            (ninf, ninf, "NaN"),
            (inf, ninf, "+Inf"),
        ];
        let mut i = 0usize;
        while i < cases.len() {
            let (x, y, want) = cases[i];
            eq(&mut ok, "Dim", z(math::Dim(x, y)), want);
            i += 1;
        }
        report(&mut failed, ok, " 2", "Dim returns NaN, not 0, for a NaN");
    }

    // 3. Modf: both halves carry the sign of the input. Go:
    //    Modf(-0) = (-0, -0), Modf(-1) = (-1, -0),
    //    Modf(-1.5) = (-1, -0.5), Modf(±Inf) = (±Inf, NaN).
    {
        let mut ok = true;
        let cases: [(f64, &str, &str); 8] = [
            (0.0, "+0", "+0"),
            (nz, "-0", "-0"),
            (1.0, "1", "+0"),
            (-1.0, "-1", "-0"),
            (1.5, "1", "0.5"),
            (-1.5, "-1", "-0.5"),
            (inf, "+Inf", "NaN"),
            (nan, "NaN", "NaN"),
        ];
        let mut i = 0usize;
        while i < cases.len() {
            let (v, wi, wf) = cases[i];
            let (gi, gf) = math::Modf(v);
            eq(&mut ok, "Modf int", z(gi), wi);
            eq(&mut ok, "Modf frac", z(gf), wf);
            i += 1;
        }
        report(
            &mut failed,
            ok,
            " 3",
            "Modf's fraction keeps the input's sign",
        );
    }

    // 4. Rounding at the halves and the zeros — already correct, kept
    //    so the fixes above cannot disturb it. Go: Round(-0.4) = -0,
    //    Ceil(-0.5) = -0, Round(2.5) = 3 (half away from zero).
    {
        let mut ok = true;
        // (v, floor, ceil, round, trunc, abs)
        let cases: [(f64, &str, &str, &str, &str, &str); 10] = [
            (0.0, "+0", "+0", "+0", "+0", "+0"),
            (nz, "-0", "-0", "-0", "-0", "+0"),
            (0.5, "+0", "1", "1", "+0", "0.5"),
            (-0.5, "-1", "-0", "-1", "-0", "0.5"),
            (2.5, "2", "3", "3", "2", "2.5"),
            (-2.5, "-3", "-2", "-3", "-2", "2.5"),
            (0.4, "+0", "1", "+0", "+0", "0.4"),
            (-0.4, "-1", "-0", "-0", "-0", "0.4"),
            (inf, "+Inf", "+Inf", "+Inf", "+Inf", "+Inf"),
            (ninf, "-Inf", "-Inf", "-Inf", "-Inf", "+Inf"),
        ];
        let mut i = 0usize;
        while i < cases.len() {
            let (v, wfl, wce, wro, wtr, wab) = cases[i];
            eq(&mut ok, "Floor", z(math::Floor(v)), wfl);
            eq(&mut ok, "Ceil", z(math::Ceil(v)), wce);
            eq(&mut ok, "Round", z(math::Round(v)), wro);
            eq(&mut ok, "Trunc", z(math::Trunc(v)), wtr);
            eq(&mut ok, "Abs", z(math::Abs(v)), wab);
            i += 1;
        }
        report(&mut failed, ok, " 4", "rounding keeps the sign of a zero");
    }

    // 5. Pow's special cases — all twenty Go documents. These already
    //    matched; a table this size is exactly where a port drifts.
    {
        let mut ok = true;
        let cases: [(f64, f64, &str); 22] = [
            (2.0, 3.0, "8"),
            (-2.0, 3.0, "-8"),
            (-2.0, 0.5, "NaN"),
            (1.0, nan, "1"),
            (nan, 0.0, "1"),
            (1.0, inf, "1"),
            (-1.0, inf, "1"),
            (-1.0, ninf, "1"),
            (0.0, 3.0, "+0"),
            (0.0, -3.0, "+Inf"),
            (nz, 3.0, "-0"),
            (nz, -3.0, "-Inf"),
            (nz, 2.0, "+0"),
            (nz, -2.0, "+Inf"),
            (inf, 0.0, "1"),
            (0.0, 0.0, "1"),
            (nan, 1.0, "NaN"),
            (2.0, inf, "+Inf"),
            (0.5, inf, "+0"),
            (2.0, ninf, "+0"),
            (0.5, ninf, "+Inf"),
            (ninf, -3.0, "-0"),
        ];
        let mut i = 0usize;
        while i < cases.len() {
            let (x, y, want) = cases[i];
            eq(&mut ok, "Pow", z(math::Pow(x, y)), want);
            i += 1;
        }
        report(&mut failed, ok, " 5", "all of Pow's special cases");
    }

    // 6. Log, Sqrt and Hypot at their boundaries. Go: Log(-0) = -Inf,
    //    Sqrt(-0) = -0, and Hypot is +Inf for an infinite argument even
    //    when the other is NaN.
    {
        let mut ok = true;
        eq(&mut ok, "Log(+0)", z(math::Log(0.0)), "-Inf");
        eq(&mut ok, "Log(-0)", z(math::Log(nz)), "-Inf");
        eq(&mut ok, "Log(-1)", z(math::Log(-1.0)), "NaN");
        eq(&mut ok, "Log(1)", z(math::Log(1.0)), "+0");
        eq(&mut ok, "Log(-Inf)", z(math::Log(ninf)), "NaN");
        eq(&mut ok, "Sqrt(-0)", z(math::Sqrt(nz)), "-0");
        eq(&mut ok, "Sqrt(-1)", z(math::Sqrt(-1.0)), "NaN");
        eq(&mut ok, "Exp(-Inf)", z(math::Exp(ninf)), "+0");
        eq(&mut ok, "Hypot(Inf,NaN)", z(math::Hypot(inf, nan)), "+Inf");
        eq(&mut ok, "Hypot(NaN,Inf)", z(math::Hypot(nan, inf)), "+Inf");
        eq(&mut ok, "Hypot(NaN,1)", z(math::Hypot(nan, 1.0)), "NaN");
        eq(&mut ok, "Hypot(-0,-0)", z(math::Hypot(nz, nz)), "+0");
        report(&mut failed, ok, " 6", "Log/Sqrt/Hypot at the boundaries");
    }

    // 7. Atan2's table, and Mod/Remainder's signs. Go: Mod keeps the
    //    sign of x, Remainder rounds to the NEAREST multiple so its
    //    sign follows from that — Remainder(5, 3) is -1, not 2.
    {
        let mut ok = true;
        let at: [(f64, f64, &str); 10] = [
            (0.0, 0.0, "+0"),
            (0.0, nz, "3.141592653589793"),
            (nz, 0.0, "-0"),
            (nz, nz, "-3.141592653589793"),
            (1.0, 0.0, "1.5707963267948966"),
            (inf, inf, "0.7853981633974483"),
            (inf, ninf, "2.356194490192345"),
            (1.0, inf, "+0"),
            (1.0, ninf, "3.141592653589793"),
            (nan, 1.0, "NaN"),
        ];
        let mut i = 0usize;
        while i < at.len() {
            let (y, x, want) = at[i];
            eq(&mut ok, "Atan2", z(math::Atan2(y, x)), want);
            i += 1;
        }
        let md: [(f64, f64, &str, &str); 7] = [
            (5.0, 3.0, "2", "-1"),
            (-5.0, 3.0, "-2", "1"),
            (5.0, -3.0, "2", "-1"),
            (-5.0, -3.0, "-2", "1"),
            (5.0, 0.0, "NaN", "NaN"),
            (0.0, 5.0, "+0", "+0"),
            (5.5, 2.0, "1.5", "-0.5"),
        ];
        let mut k = 0usize;
        while k < md.len() {
            let (x, y, wm, wr) = md[k];
            eq(&mut ok, "Mod", z(math::Mod(x, y)), wm);
            eq(&mut ok, "Remainder", z(math::Remainder(x, y)), wr);
            k += 1;
        }
        // Go: Mod(1, +Inf) = 1 but Mod(+Inf, 1) = NaN.
        eq(&mut ok, "Mod(1,Inf)", z(math::Mod(1.0, inf)), "1");
        eq(&mut ok, "Mod(Inf,1)", z(math::Mod(inf, 1.0)), "NaN");
        report(&mut failed, ok, " 7", "Atan2's table, and Mod vs Remainder");
    }

    // 8. One divergence, recorded rather than hidden: goish routes the
    //    transcendentals through libm where Go ships its own, so a
    //    result can differ in the last bit. Go's `Exp(1)` is
    //    2.718281828459045 and goish's is 2.7182818284590455 — the two
    //    nearest doubles to e.
    //
    //    Asserted as it IS, so that closing the gap fails here.
    {
        let mut ok = true;
        eq(
            &mut ok,
            "Exp(1) (diverges)",
            z(math::Exp(1.0)),
            "2.7182818284590455",
        );
        // Everything either side of it agrees to the bit.
        eq(&mut ok, "Log(e)", z(math::Log(core::f64::consts::E)), "1");
        eq(&mut ok, "Sqrt(2)", z(math::Sqrt(2.0)), "1.4142135623730951");
        eq(
            &mut ok,
            "Pow(2,0.5)",
            z(math::Pow(2.0, 0.5)),
            "1.4142135623730951",
        );
        report(
            &mut failed,
            ok,
            " 8",
            "libm differs from Go in Exp's last bit",
        );
    }

    if failed == 0 {
        fmt::Println!("ok 8/8");
        syscall::Exit(0);
    } else {
        fmt::Println!("FAIL", failed, "of 8");
        syscall::Exit(1);
    }
}
