// fmt_float_prec_ref_smoke — float default precision against a running Go.
// (fmt/print.go fmtFloat, fmt/format.go fmtFloat)
//
// Every expectation below is what a real Go 1.25.5 prints: the vectors
// are the output of `tools/gen_fmt_float_ref.go` run in `package
// fmt_test` by `scripts/goref.sh`.
//
// Go's default precision is not "shortest" for every float verb. From
// the fmt documentation: "For %v the default is the smallest number of
// digits necessary to represent the value uniquely … %e, %E, %f, %F
// default to a precision of 6."
//
// goish passed -1 — FormatFloat's shortest-round-trip mode — for every
// verb. So `%f` of 1.5 printed "1.5" where Go prints "1.500000", `%e`
// of 0 printed "0e+00" where Go prints "0.000000e+00", and `%f` of
// 3.14159265358979 printed all fifteen digits where Go prints six.
//
// Nothing about that output looks wrong on its own, which is the point:
// every column-aligned numeric report a port produced was quietly
// misaligned, and a golden file compared against Go's would differ on
// every line.

#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

use goish::gostring::string;
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

// go: none — goish idiom: compare one rendering against Go's and say
//     what differed.
fn eq(ok: &mut bool, what: &str, got: string, want: &str) {
    if got != s(want) {
        fmt::Println!("   ", s(what), "got", got, "want", s(want));
        *ok = false;
    }
}

#[goish::main]
fn main() {
    let mut failed = 0;

    // 1. Every float verb at its default precision. Columns are Go's:
    //    (v, %v, %f, %F, %e, %E, %g, %G)
    {
        let mut ok = true;
        let cases: [(f64, &str, &str, &str, &str, &str, &str, &str); 8] = [
            (
                0.0,
                "0",
                "0.000000",
                "0.000000",
                "0.000000e+00",
                "0.000000E+00",
                "0",
                "0",
            ),
            (
                1.0,
                "1",
                "1.000000",
                "1.000000",
                "1.000000e+00",
                "1.000000E+00",
                "1",
                "1",
            ),
            (
                1.5,
                "1.5",
                "1.500000",
                "1.500000",
                "1.500000e+00",
                "1.500000E+00",
                "1.5",
                "1.5",
            ),
            (
                -1.5,
                "-1.5",
                "-1.500000",
                "-1.500000",
                "-1.500000e+00",
                "-1.500000E+00",
                "-1.5",
                "-1.5",
            ),
            (
                3.14159265358979,
                "3.14159265358979",
                "3.141593",
                "3.141593",
                "3.141593e+00",
                "3.141593E+00",
                "3.14159265358979",
                "3.14159265358979",
            ),
            (
                1e21,
                "1e+21",
                "1000000000000000000000.000000",
                "1000000000000000000000.000000",
                "1.000000e+21",
                "1.000000E+21",
                "1e+21",
                "1E+21",
            ),
            (
                1e-7,
                "1e-07",
                "0.000000",
                "0.000000",
                "1.000000e-07",
                "1.000000E-07",
                "1e-07",
                "1E-07",
            ),
            (
                100.0,
                "100",
                "100.000000",
                "100.000000",
                "1.000000e+02",
                "1.000000E+02",
                "100",
                "100",
            ),
        ];
        let mut i = 0usize;
        while i < cases.len() {
            let (v, wv, wf, wcf, we, wce, wg, wcg) = cases[i];
            eq(&mut ok, "%v", fmt::Sprintf!("%v", v), wv);
            eq(&mut ok, "%f", fmt::Sprintf!("%f", v), wf);
            eq(&mut ok, "%F", fmt::Sprintf!("%F", v), wcf);
            eq(&mut ok, "%e", fmt::Sprintf!("%e", v), we);
            eq(&mut ok, "%E", fmt::Sprintf!("%E", v), wce);
            eq(&mut ok, "%g", fmt::Sprintf!("%g", v), wg);
            eq(&mut ok, "%G", fmt::Sprintf!("%G", v), wcg);
            i += 1;
        }
        report(
            &mut failed,
            ok,
            " 1",
            "%f/%e default to six places, %v/%g to shortest",
        );
    }

    // 2. An explicit precision overrides the default in both
    //    directions, including down to zero.
    {
        let mut ok = true;
        eq(&mut ok, "%.0f", fmt::Sprintf!("%.0f", 1.5), "2");
        eq(&mut ok, "%.2f", fmt::Sprintf!("%.2f", 1.5), "1.50");
        eq(&mut ok, "%.9f", fmt::Sprintf!("%.9f", 1.5), "1.500000000");
        eq(&mut ok, "%.2e", fmt::Sprintf!("%.2e", 1.5), "1.50e+00");
        eq(&mut ok, "%.3g", fmt::Sprintf!("%.3g", 1.5), "1.5");
        let pi = 3.14159265358979f64;
        eq(&mut ok, "pi %.0f", fmt::Sprintf!("%.0f", pi), "3");
        eq(&mut ok, "pi %.2f", fmt::Sprintf!("%.2f", pi), "3.14");
        eq(&mut ok, "pi %.9f", fmt::Sprintf!("%.9f", pi), "3.141592654");
        eq(&mut ok, "pi %.2e", fmt::Sprintf!("%.2e", pi), "3.14e+00");
        eq(&mut ok, "pi %.3g", fmt::Sprintf!("%.3g", pi), "3.14");
        report(&mut failed, ok, " 2", "an explicit precision still wins");
    }

    // 3. Width and padding measure the DEFAULTED rendering, so they
    //    change once the default is right.
    {
        let mut ok = true;
        eq(&mut ok, "%10f", fmt::Sprintf!("%10f", 1.5), "  1.500000");
        eq(
            &mut ok,
            "%-10f",
            fmt::Sprintf!("%-10f|", 1.5),
            "1.500000  |",
        );
        eq(&mut ok, "%010f", fmt::Sprintf!("%010f", 1.5), "001.500000");
        eq(&mut ok, "%+f", fmt::Sprintf!("%+f", 1.5), "+1.500000");
        report(&mut failed, ok, " 3", "width measures the defaulted text");
    }

    // 4. float32 takes the same defaults.
    {
        let mut ok = true;
        let v: f32 = 1.5;
        eq(&mut ok, "f32 %v", fmt::Sprintf!("%v", v), "1.5");
        eq(&mut ok, "f32 %f", fmt::Sprintf!("%f", v), "1.500000");
        eq(&mut ok, "f32 %e", fmt::Sprintf!("%e", v), "1.500000e+00");
        eq(&mut ok, "f32 %g", fmt::Sprintf!("%g", v), "1.5");
        report(&mut failed, ok, " 4", "float32 takes the same defaults");
    }

    // 5. The special values ignore precision entirely — Go prints
    //    "+Inf", "-Inf" and "NaN" for every verb.
    {
        let mut ok = true;
        let inf = f64::INFINITY;
        let ninf = f64::NEG_INFINITY;
        let nan = f64::NAN;
        for (v, want) in [(inf, "+Inf"), (ninf, "-Inf"), (nan, "NaN")] {
            eq(&mut ok, "%v", fmt::Sprintf!("%v", v), want);
            eq(&mut ok, "%f", fmt::Sprintf!("%f", v), want);
            eq(&mut ok, "%e", fmt::Sprintf!("%e", v), want);
            eq(&mut ok, "%g", fmt::Sprintf!("%g", v), want);
        }
        report(&mut failed, ok, " 5", "Inf and NaN ignore the precision");
    }

    if failed == 0 {
        fmt::Println!("ok 5/5");
        syscall::Exit(0);
    } else {
        fmt::Println!("FAIL", failed, "of 5");
        syscall::Exit(1);
    }
}
