// strconv_complex_ref_smoke — FormatComplex/ParseComplex against Go.
// (strconv/ftoa.go, strconv/atoc.go)
//
// Every expectation below is what a real Go 1.25.5 prints: the vectors
// are the output of `tools/gen_complex_ref.go` run in `package
// strconv_test` by `scripts/goref.sh`.
//
// These were the last two PUBLIC functions missing from strconv. The
// rest of its gap is Ryu float-formatting internals, which goish does
// not use because it formats floats a different way — an
// implementation choice, not a hole.
//
// The pair is not symmetric, which is the interesting part:
//
//   * FormatComplex ALWAYS parenthesises and ALWAYS signs the imaginary
//     part, so a positive imaginary gets a '+' that FormatFloat did not
//     produce: (0+0i), not (0 0i).
//   * ParseComplex accepts far more than that — a bare real "1", a bare
//     imaginary "2i", and the unparenthesised "1+2i" — while refusing
//     several things that look reasonable: "i" alone, "1+2" with no
//     'i', "1+2j", "1 + 2i" with spaces, and doubled parentheses.
//   * A RANGE error is returned ALONGSIDE the value rather than instead
//     of it, so "1e400+1i" yields (+Inf, 1) and an error together.
//   * bitSize is the COMPLEX width and is halved before reaching
//     FormatFloat, because a complex64 is two float32s.

#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

use goish::gostring::string;
use goish::strconv;
use goish::types::int;
use goish::{fmt, syscall};

fn s(x: &str) -> string {
    return string::from_bytes(x.as_bytes());
}

fn eq(failed: &mut int, got: string, want: &str, what: &str) {
    if got == s(want) {
        return;
    }
    fmt::Printf!("[!!] %s FAIL got %q want %q\n", s(what), got, s(want));
    *failed += 1;
}

// go: none — goish idiom: NaN is not equal to itself, so a vector that
//     expects NaN has to ask whether it IS one.
fn feq(got: f64, want: f64) -> bool {
    if want.is_nan() {
        return got.is_nan();
    }
    return got == want;
}

#[goish::main]
fn main() {
    let mut failed = 0;

    // 1. FormatComplex.
    {
        eq(
            &mut failed,
            strconv::FormatComplex((1.0, 2.0), b'g', -1, 128),
            "(1+2i)",
            "fmt (1+2i)",
        );
        eq(
            &mut failed,
            strconv::FormatComplex((1.0, -2.0), b'g', -1, 128),
            "(1-2i)",
            "fmt (1-2i)",
        );
        eq(
            &mut failed,
            strconv::FormatComplex((0.0, 0.0), b'g', -1, 128),
            "(0+0i)",
            "fmt (0+0i)",
        );
        eq(
            &mut failed,
            strconv::FormatComplex((-1.5, 0.0), b'g', -1, 128),
            "(-1.5+0i)",
            "fmt (-1.5+0i)",
        );
        eq(
            &mut failed,
            strconv::FormatComplex((1.0, 2.0), b'f', 2, 128),
            "(1.00+2.00i)",
            "fmt (1.00+2.00i)",
        );
        eq(
            &mut failed,
            strconv::FormatComplex((1.0, 2.0), b'e', 3, 128),
            "(1.000e+00+2.000e+00i)",
            "fmt (1.000e+00+2.000e+00i)",
        );
        eq(
            &mut failed,
            strconv::FormatComplex((1.25, -0.5), b'g', -1, 64),
            "(1.25-0.5i)",
            "fmt (1.25-0.5i)",
        );
        eq(
            &mut failed,
            strconv::FormatComplex((0.0, 1.0), b'g', -1, 128),
            "(0+1i)",
            "fmt (0+1i)",
        );
        fmt::Println!("[  1 ] FormatComplex parenthesises and signs");
    }

    // 2. ParseComplex at bitSize 128.
    {
        {
            let (v, e) = strconv::ParseComplex("1+2i", 128);
            if !e.IsNil() {
                fmt::Printf!("[!!] %q %q\n", s("1+2i"), e.Error());
                failed += 1;
            } else if !feq(v.0, 1.0) || !feq(v.1, 2.0) {
                fmt::Printf!("[!!] %q parsed wrong\n", s("1+2i"));
                failed += 1;
            }
        }
        {
            let (v, e) = strconv::ParseComplex("(1+2i)", 128);
            if !e.IsNil() {
                fmt::Printf!("[!!] %q %q\n", s("(1+2i)"), e.Error());
                failed += 1;
            } else if !feq(v.0, 1.0) || !feq(v.1, 2.0) {
                fmt::Printf!("[!!] %q parsed wrong\n", s("(1+2i)"));
                failed += 1;
            }
        }
        {
            let (v, e) = strconv::ParseComplex("1-2i", 128);
            if !e.IsNil() {
                fmt::Printf!("[!!] %q %q\n", s("1-2i"), e.Error());
                failed += 1;
            } else if !feq(v.0, 1.0) || !feq(v.1, -2.0) {
                fmt::Printf!("[!!] %q parsed wrong\n", s("1-2i"));
                failed += 1;
            }
        }
        {
            let (v, e) = strconv::ParseComplex("1", 128);
            if !e.IsNil() {
                fmt::Printf!("[!!] %q %q\n", s("1"), e.Error());
                failed += 1;
            } else if !feq(v.0, 1.0) || !feq(v.1, 0.0) {
                fmt::Printf!("[!!] %q parsed wrong\n", s("1"));
                failed += 1;
            }
        }
        {
            let (v, e) = strconv::ParseComplex("2i", 128);
            if !e.IsNil() {
                fmt::Printf!("[!!] %q %q\n", s("2i"), e.Error());
                failed += 1;
            } else if !feq(v.0, 0.0) || !feq(v.1, 2.0) {
                fmt::Printf!("[!!] %q parsed wrong\n", s("2i"));
                failed += 1;
            }
        }
        {
            let (v, e) = strconv::ParseComplex("-2i", 128);
            if !e.IsNil() {
                fmt::Printf!("[!!] %q %q\n", s("-2i"), e.Error());
                failed += 1;
            } else if !feq(v.0, 0.0) || !feq(v.1, -2.0) {
                fmt::Printf!("[!!] %q parsed wrong\n", s("-2i"));
                failed += 1;
            }
        }
        {
            let (v, e) = strconv::ParseComplex("+2i", 128);
            if !e.IsNil() {
                fmt::Printf!("[!!] %q %q\n", s("+2i"), e.Error());
                failed += 1;
            } else if !feq(v.0, 0.0) || !feq(v.1, 2.0) {
                fmt::Printf!("[!!] %q parsed wrong\n", s("+2i"));
                failed += 1;
            }
        }
        {
            let (_, e) = strconv::ParseComplex("i", 128);
            if e.IsNil() {
                fmt::Printf!("[!!] %q expected error\n", s("i"));
                failed += 1;
            } else {
                eq(
                    &mut failed,
                    e.Error(),
                    "strconv.ParseComplex: parsing \"i\": invalid syntax",
                    "i",
                );
            }
        }
        {
            let (_, e) = strconv::ParseComplex("(1+2i", 128);
            if e.IsNil() {
                fmt::Printf!("[!!] %q expected error\n", s("(1+2i"));
                failed += 1;
            } else {
                eq(
                    &mut failed,
                    e.Error(),
                    "strconv.ParseComplex: parsing \"(1+2i\": invalid syntax",
                    "(1+2i",
                );
            }
        }
        {
            let (_, e) = strconv::ParseComplex("1+2i)", 128);
            if e.IsNil() {
                fmt::Printf!("[!!] %q expected error\n", s("1+2i)"));
                failed += 1;
            } else {
                eq(
                    &mut failed,
                    e.Error(),
                    "strconv.ParseComplex: parsing \"1+2i)\": invalid syntax",
                    "1+2i)",
                );
            }
        }
        {
            let (_, e) = strconv::ParseComplex("1+2", 128);
            if e.IsNil() {
                fmt::Printf!("[!!] %q expected error\n", s("1+2"));
                failed += 1;
            } else {
                eq(
                    &mut failed,
                    e.Error(),
                    "strconv.ParseComplex: parsing \"1+2\": invalid syntax",
                    "1+2",
                );
            }
        }
        {
            let (_, e) = strconv::ParseComplex("1++2i", 128);
            if e.IsNil() {
                fmt::Printf!("[!!] %q expected error\n", s("1++2i"));
                failed += 1;
            } else {
                eq(
                    &mut failed,
                    e.Error(),
                    "strconv.ParseComplex: parsing \"1++2i\": invalid syntax",
                    "1++2i",
                );
            }
        }
        {
            let (_, e) = strconv::ParseComplex("1+2j", 128);
            if e.IsNil() {
                fmt::Printf!("[!!] %q expected error\n", s("1+2j"));
                failed += 1;
            } else {
                eq(
                    &mut failed,
                    e.Error(),
                    "strconv.ParseComplex: parsing \"1+2j\": invalid syntax",
                    "1+2j",
                );
            }
        }
        {
            let (_, e) = strconv::ParseComplex("", 128);
            if e.IsNil() {
                fmt::Printf!("[!!] %q expected error\n", s(""));
                failed += 1;
            } else {
                eq(
                    &mut failed,
                    e.Error(),
                    "strconv.ParseComplex: parsing \"\": invalid syntax",
                    "",
                );
            }
        }
        {
            let (v, e) = strconv::ParseComplex("(0+0i)", 128);
            if !e.IsNil() {
                fmt::Printf!("[!!] %q %q\n", s("(0+0i)"), e.Error());
                failed += 1;
            } else if !feq(v.0, 0.0) || !feq(v.1, 0.0) {
                fmt::Printf!("[!!] %q parsed wrong\n", s("(0+0i)"));
                failed += 1;
            }
        }
        {
            let (v, e) = strconv::ParseComplex("0", 128);
            if !e.IsNil() {
                fmt::Printf!("[!!] %q %q\n", s("0"), e.Error());
                failed += 1;
            } else if !feq(v.0, 0.0) || !feq(v.1, 0.0) {
                fmt::Printf!("[!!] %q parsed wrong\n", s("0"));
                failed += 1;
            }
        }
        {
            let (v, e) = strconv::ParseComplex("1e10+1e-10i", 128);
            if !e.IsNil() {
                fmt::Printf!("[!!] %q %q\n", s("1e10+1e-10i"), e.Error());
                failed += 1;
            } else if !feq(v.0, 1e+10) || !feq(v.1, 1e-10) {
                fmt::Printf!("[!!] %q parsed wrong\n", s("1e10+1e-10i"));
                failed += 1;
            }
        }
        {
            let (v, e) = strconv::ParseComplex("+1+2i", 128);
            if !e.IsNil() {
                fmt::Printf!("[!!] %q %q\n", s("+1+2i"), e.Error());
                failed += 1;
            } else if !feq(v.0, 1.0) || !feq(v.1, 2.0) {
                fmt::Printf!("[!!] %q parsed wrong\n", s("+1+2i"));
                failed += 1;
            }
        }
        {
            let (v, e) = strconv::ParseComplex("-1-2i", 128);
            if !e.IsNil() {
                fmt::Printf!("[!!] %q %q\n", s("-1-2i"), e.Error());
                failed += 1;
            } else if !feq(v.0, -1.0) || !feq(v.1, -2.0) {
                fmt::Printf!("[!!] %q parsed wrong\n", s("-1-2i"));
                failed += 1;
            }
        }
        {
            let (v, e) = strconv::ParseComplex("NaN", 128);
            if !e.IsNil() {
                fmt::Printf!("[!!] %q %q\n", s("NaN"), e.Error());
                failed += 1;
            } else if !feq(v.0, f64::NAN) || !feq(v.1, 0.0) {
                fmt::Printf!("[!!] %q parsed wrong\n", s("NaN"));
                failed += 1;
            }
        }
        {
            let (v, e) = strconv::ParseComplex("Inf", 128);
            if !e.IsNil() {
                fmt::Printf!("[!!] %q %q\n", s("Inf"), e.Error());
                failed += 1;
            } else if !feq(v.0, f64::INFINITY) || !feq(v.1, 0.0) {
                fmt::Printf!("[!!] %q parsed wrong\n", s("Inf"));
                failed += 1;
            }
        }
        {
            let (v, e) = strconv::ParseComplex("(Inf+Infi)", 128);
            if !e.IsNil() {
                fmt::Printf!("[!!] %q %q\n", s("(Inf+Infi)"), e.Error());
                failed += 1;
            } else if !feq(v.0, f64::INFINITY) || !feq(v.1, f64::INFINITY) {
                fmt::Printf!("[!!] %q parsed wrong\n", s("(Inf+Infi)"));
                failed += 1;
            }
        }
        {
            let (v, e) = strconv::ParseComplex("1+NaNi", 128);
            if !e.IsNil() {
                fmt::Printf!("[!!] %q %q\n", s("1+NaNi"), e.Error());
                failed += 1;
            } else if !feq(v.0, 1.0) || !feq(v.1, f64::NAN) {
                fmt::Printf!("[!!] %q parsed wrong\n", s("1+NaNi"));
                failed += 1;
            }
        }
        {
            let (v, e) = strconv::ParseComplex("(NaN+NaNi)", 128);
            if !e.IsNil() {
                fmt::Printf!("[!!] %q %q\n", s("(NaN+NaNi)"), e.Error());
                failed += 1;
            } else if !feq(v.0, f64::NAN) || !feq(v.1, f64::NAN) {
                fmt::Printf!("[!!] %q parsed wrong\n", s("(NaN+NaNi)"));
                failed += 1;
            }
        }
        {
            let (_, e) = strconv::ParseComplex("1e400+1i", 128);
            if e.IsNil() {
                fmt::Printf!("[!!] %q expected error\n", s("1e400+1i"));
                failed += 1;
            } else {
                eq(
                    &mut failed,
                    e.Error(),
                    "strconv.ParseComplex: parsing \"1e400+1i\": value out of range",
                    "1e400+1i",
                );
            }
        }
        {
            let (_, e) = strconv::ParseComplex("1+1e400i", 128);
            if e.IsNil() {
                fmt::Printf!("[!!] %q expected error\n", s("1+1e400i"));
                failed += 1;
            } else {
                eq(
                    &mut failed,
                    e.Error(),
                    "strconv.ParseComplex: parsing \"1+1e400i\": value out of range",
                    "1+1e400i",
                );
            }
        }
        {
            let (_, e) = strconv::ParseComplex("(1+2i))", 128);
            if e.IsNil() {
                fmt::Printf!("[!!] %q expected error\n", s("(1+2i))"));
                failed += 1;
            } else {
                eq(
                    &mut failed,
                    e.Error(),
                    "strconv.ParseComplex: parsing \"(1+2i))\": invalid syntax",
                    "(1+2i))",
                );
            }
        }
        {
            let (_, e) = strconv::ParseComplex("((1+2i))", 128);
            if e.IsNil() {
                fmt::Printf!("[!!] %q expected error\n", s("((1+2i))"));
                failed += 1;
            } else {
                eq(
                    &mut failed,
                    e.Error(),
                    "strconv.ParseComplex: parsing \"((1+2i))\": invalid syntax",
                    "((1+2i))",
                );
            }
        }
        {
            let (_, e) = strconv::ParseComplex("1 + 2i", 128);
            if e.IsNil() {
                fmt::Printf!("[!!] %q expected error\n", s("1 + 2i"));
                failed += 1;
            } else {
                eq(
                    &mut failed,
                    e.Error(),
                    "strconv.ParseComplex: parsing \"1 + 2i\": invalid syntax",
                    "1 + 2i",
                );
            }
        }
        fmt::Println!("[  2 ] ParseComplex accepts and refuses like Go");
    }

    // 3. bitSize 64 narrows both parts to the float32 range, so a value
    //    a float64 holds happily is out of range here.
    {
        {
            let (v, e) = strconv::ParseComplex("1+2i", 64);
            if !e.IsNil() || !feq(v.0, 1.0) || !feq(v.1, 2.0) {
                fmt::Printf!("[!!] p64 %q wrong\n", s("1+2i"));
                failed += 1;
            }
        }
        {
            let (_, e) = strconv::ParseComplex("1e40+1i", 64);
            if e.IsNil() {
                fmt::Printf!("[!!] p64 %q expected error\n", s("1e40+1i"));
                failed += 1;
            } else {
                eq(
                    &mut failed,
                    e.Error(),
                    "strconv.ParseComplex: parsing \"1e40+1i\": value out of range",
                    "1e40+1i",
                );
            }
        }
        fmt::Println!("[  3 ] bitSize 64 narrows to float32");
    }

    // 4. The range error carries the VALUE back with it — a caller that
    //    only checks the error still has a usable number.
    {
        let (v, e) = strconv::ParseComplex("1e400+1i", 128);
        if e.IsNil() {
            fmt::Println!("[!!] expected a range error");
            failed += 1;
        }
        if v.0 != f64::INFINITY || v.1 != 1.0 {
            fmt::Println!("[!!] range error dropped the value");
            failed += 1;
        }
        fmt::Println!("[  4 ] a range error still returns the value");
    }

    if failed == 0 {
        fmt::Println!("ok - strconv complex matches Go");
        syscall::Exit(0);
    } else {
        fmt::Println!("FAIL", failed);
        syscall::Exit(1);
    }
}
