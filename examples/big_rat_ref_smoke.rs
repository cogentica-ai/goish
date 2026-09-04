// big_rat_ref_smoke — math/big's Rat against a running Go.
// (math/big/rat.go, math/big/ratconv.go)
//
// Every expectation below is what a real Go 1.25.5 prints: the lines in
// GO are the verbatim output of `tools/gen_bigrat_ref.go` run in
// `package big` by `scripts/goref.sh`.
//
// big.Rat is an EXACT rational, which makes its rules different from
// both Int and Float in ways a port tends to smooth over:
//
//   * It is always kept in LOWEST TERMS with a positive denominator, so
//     NewRat(2, 4) and NewRat(-1, -2) are the same value and print the
//     same way. A port that stores what it was handed answers "2/4".
//   * String and RatString are NOT the same function. String always
//     shows a denominator ("2/1"); RatString omits it for an integer
//     ("2"). Callers pick deliberately, and aliasing them breaks one.
//   * FloatString(n) rounds to n decimals HALF AWAY FROM ZERO — not the
//     banker's rounding Float uses, and not truncation.
//   * SetFloat64 is exact, because every finite float64 already IS a
//     rational: 0.1 becomes 3602879701896397/36028797018963968, not
//     1/10. A port that goes via decimal text produces a different
//     number that still looks right.
//   * Float64 returns an `exact` bool that is false whenever the
//     rational cannot be represented — which is the normal case.
//
// goish matched Go on all of that. Rat.SetString was wrong in two
// opposite directions, both of which a decimal-only test misses:
//
//   * It REJECTED the base-prefixed forms Go accepts. Go scans the
//     mantissa in base 0, so "0x10", "0b101", "0o17", "1_000" and the
//     hex-float "0x1p4" are all valid — the same literal grammar an Int
//     accepts. goish answered nil,false to every one.
//   * It ACCEPTED surrounding whitespace Go refuses: " 1" and "1 " both
//     parsed, because the decimal path began with a str::trim(). For a
//     parser, accepting what the reference rejects is the worse of the
//     two directions to be wrong in — it is the direction that lets
//     malformed input through.
//
// The fix routes the floating-point path through `float_scan`, the
// scanner Float::Parse already uses, and then ports Go's own exponent
// arithmetic (splitting powers of 10 into powers of 2 and 5 so the
// factors stay small), so the two entry points cannot drift apart.
//
// Two Go behaviours are not pinned line-for-line, because a panicking
// case cannot be compared in this harness: Inv(0) and SetFrac(1, 0).
// Both were checked by hand; goish panics with Go's exact message,
// "division by zero" — it previously prefixed that with the goish
// method name, which a recovered panic value would have shown.

#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

use goish::gostring::string;
use goish::math::big;
use goish::math::big::{Int, Rat};
use goish::types::int;
use goish::{fmt, syscall};

fn s(x: &str) -> string {
    return string::from_bytes(x.as_bytes());
}
fn r(a: i64, b: i64) -> Rat {
    return big::NewRat(a, b);
}
fn nr() -> Rat {
    return Rat::default();
}

// go: none — goish idiom: the reference lines, in the order Go printed
//     them. Comparing whole rendered lines keeps this smoke and the
//     generator in lockstep: a case added to one is a mismatch in the
//     other, never a silent pass.
const GO: [&str; 121] = [
    "norm    0/1    -> str=0/1        rat=0        num=0      den=1      sign=0  isint=true",
    "norm    1/1    -> str=1/1        rat=1        num=1      den=1      sign=1  isint=true",
    "norm    2/1    -> str=2/1        rat=2        num=2      den=1      sign=1  isint=true",
    "norm    1/2    -> str=1/2        rat=1/2      num=1      den=2      sign=1  isint=false",
    "norm    2/4    -> str=1/2        rat=1/2      num=1      den=2      sign=1  isint=false",
    "norm   -1/2    -> str=-1/2       rat=-1/2     num=-1     den=2      sign=-1 isint=false",
    "norm    1/-2   -> str=-1/2       rat=-1/2     num=-1     den=2      sign=-1 isint=false",
    "norm   -1/-2   -> str=1/2        rat=1/2      num=1      den=2      sign=1  isint=false",
    "norm   -2/4    -> str=-1/2       rat=-1/2     num=-1     den=2      sign=-1 isint=false",
    "norm    6/3    -> str=2/1        rat=2        num=2      den=1      sign=1  isint=true",
    "norm   -6/3    -> str=-2/1       rat=-2       num=-2     den=1      sign=-1 isint=true",
    "norm  100/10   -> str=10/1       rat=10       num=10     den=1      sign=1  isint=true",
    "norm    7/7    -> str=1/1        rat=1        num=1      den=1      sign=1  isint=true",
    "norm    0/5    -> str=0/1        rat=0        num=0      den=1      sign=0  isint=true",
    "norm    0/-5   -> str=0/1        rat=0        num=0      den=1      sign=0  isint=true",
    "norm    3/9    -> str=1/3        rat=1/3      num=1      den=3      sign=1  isint=false",
    "arith add    1/2     1/3   -> 5/6          rat=5/6",
    "arith add    1/2     1/2   -> 1/1          rat=1",
    "arith add    1/3     2/3   -> 1/1          rat=1",
    "arith sub    1/2     1/3   -> 1/6          rat=1/6",
    "arith sub    1/2     1/2   -> 0/1          rat=0",
    "arith mul    2/3     3/2   -> 1/1          rat=1",
    "arith mul    1/2     1/2   -> 1/4          rat=1/4",
    "arith quo    1/2     1/3   -> 3/2          rat=3/2",
    "arith quo    1/2     2/1   -> 1/4          rat=1/4",
    "arith quo   -1/2     1/3   -> -3/2         rat=-3/2",
    "arith add   -1/2     1/2   -> 0/1          rat=0",
    "arith mul    0/1     5/7   -> 0/1          rat=0",
    "unary   1/2   -> neg=-1/2     abs=1/2      inv=2/1     ",
    "unary  -1/2   -> neg=1/2      abs=1/2      inv=-2/1    ",
    "unary   3/1   -> neg=-3/1     abs=3/1      inv=1/3     ",
    "unary  -3/1   -> neg=3/1      abs=3/1      inv=-1/3    ",
    "floatstr    1/3    -> p0=0        p1=0.3       p2=0.33       p5=0.33333       p20=0.33333333333333333333",
    "floatstr    2/3    -> p0=1        p1=0.7       p2=0.67       p5=0.66667       p20=0.66666666666666666667",
    "floatstr    1/2    -> p0=1        p1=0.5       p2=0.50       p5=0.50000       p20=0.50000000000000000000",
    "floatstr   -1/2    -> p0=-1       p1=-0.5      p2=-0.50      p5=-0.50000      p20=-0.50000000000000000000",
    "floatstr    3/2    -> p0=2        p1=1.5       p2=1.50       p5=1.50000       p20=1.50000000000000000000",
    "floatstr   -3/2    -> p0=-2       p1=-1.5      p2=-1.50      p5=-1.50000      p20=-1.50000000000000000000",
    "floatstr    1/8    -> p0=0        p1=0.1       p2=0.13       p5=0.12500       p20=0.12500000000000000000",
    "floatstr    5/4    -> p0=1        p1=1.3       p2=1.25       p5=1.25000       p20=1.25000000000000000000",
    "floatstr   -5/4    -> p0=-1       p1=-1.3      p2=-1.25      p5=-1.25000      p20=-1.25000000000000000000",
    "floatstr    1/1    -> p0=1        p1=1.0       p2=1.00       p5=1.00000       p20=1.00000000000000000000",
    "floatstr    0/1    -> p0=0        p1=0.0       p2=0.00       p5=0.00000       p20=0.00000000000000000000",
    "floatstr   22/7    -> p0=3        p1=3.1       p2=3.14       p5=3.14286       p20=3.14285714285714285714",
    "floatprec    0/1     -> n=0    exact=true  str=0",
    "floatprec    1/1     -> n=0    exact=true  str=1",
    "floatprec    1/2     -> n=1    exact=true  str=0.5",
    "floatprec    1/3     -> n=0    exact=false str=0",
    "floatprec    1/4     -> n=2    exact=true  str=0.25",
    "floatprec    1/5     -> n=1    exact=true  str=0.2",
    "floatprec    1/8     -> n=3    exact=true  str=0.125",
    "floatprec    1/10    -> n=1    exact=true  str=0.1",
    "floatprec    1/6     -> n=1    exact=false str=0.2",
    "floatprec    1/7     -> n=0    exact=false str=0",
    "floatprec    3/8     -> n=3    exact=true  str=0.375",
    "floatprec    1/1000  -> n=3    exact=true  str=0.001",
    "floatprec    1/1024  -> n=10   exact=true  str=0.0009765625",
    "floatprec    7/20    -> n=2    exact=true  str=0.35",
    "setf64 0                      -> 0                                              back=0                      exact=true  f32=0              e32=true",
    "setf64 1                      -> 1                                              back=1                      exact=true  f32=1              e32=true",
    "setf64 -1                     -> -1                                             back=-1                     exact=true  f32=-1             e32=true",
    "setf64 0.5                    -> 1/2                                            back=0.5                    exact=true  f32=0.5            e32=true",
    "setf64 0.25                   -> 1/4                                            back=0.25                   exact=true  f32=0.25           e32=true",
    "setf64 0.1                    -> 3602879701896397/36028797018963968             back=0.1                    exact=true  f32=0.1            e32=false",
    "setf64 0.2                    -> 3602879701896397/18014398509481984             back=0.2                    exact=true  f32=0.2            e32=false",
    "setf64 0.3333333333333333     -> 6004799503160661/18014398509481984             back=0.3333333333333333     exact=true  f32=0.33333334     e32=false",
    "setf64 3.141592653589793      -> 884279719003555/281474976710656                back=3.141592653589793      exact=true  f32=3.1415927      e32=false",
    "setf64 1e+10                  -> 10000000000                                    back=1e+10                  exact=true  f32=1e+10          e32=true",
    "setf64 1e-10                  -> 7737125245533627/77371252455336267181195264    back=1e-10                  exact=true  f32=1e-10          e32=false",
    "setf64 12345.6789             -> 6787108751669409/549755813888                  back=12345.6789             exact=true  f32=12345.679      e32=false",
    "tof64   1/3   -> 0.3333333333333333       exact=false",
    "tof64   1/2   -> 0.5                      exact=true",
    "tof64   2/1   -> 2                        exact=true",
    "tof64   1/10  -> 0.1                      exact=false",
    "tof64   1/7   -> 0.14285714285714285      exact=false",
    "setstring \"0\"                      -> 0,true",
    "setstring \"1\"                      -> 1,true",
    "setstring \"-1\"                     -> -1,true",
    "setstring \"2/4\"                    -> 1/2,true",
    "setstring \"-2/4\"                   -> -1/2,true",
    "setstring \"2/-4\"                   -> nil,false",
    "setstring \"1/3\"                    -> 1/3,true",
    "setstring \"1.5\"                    -> 3/2,true",
    "setstring \"-1.5\"                   -> -3/2,true",
    "setstring \".5\"                     -> 1/2,true",
    "setstring \"5.\"                     -> 5,true",
    "setstring \"1e3\"                    -> 1000,true",
    "setstring \"1.5e-3\"                 -> 3/2000,true",
    "setstring \"1E3\"                    -> 1000,true",
    "setstring \"0x10\"                   -> 16,true",
    "setstring \"0b101\"                  -> 5,true",
    "setstring \"0o17\"                   -> 15,true",
    "setstring \"1_000\"                  -> 1000,true",
    "setstring \"0x1p4\"                  -> 16,true",
    "setstring \"\"                       -> nil,false",
    "setstring \"x\"                      -> nil,false",
    "setstring \"1/\"                     -> nil,false",
    "setstring \"/2\"                     -> nil,false",
    "setstring \"1/0\"                    -> nil,false",
    "setstring \"1.2.3\"                  -> nil,false",
    "setstring \"1/2/3\"                  -> nil,false",
    "setstring \" 1\"                     -> nil,false",
    "setstring \"1 \"                     -> nil,false",
    "setstring \"3/6\"                    -> 1/2,true",
    "setstring \"10/5\"                   -> 2,true",
    "setstring \"1e400\"                  -> 10000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000,true",
    "setstring \"0.000000000000000000001\" -> 1/1000000000000000000000,true",
    "setfrac big -> 13717421/109739369",
    "setfrac negden -> -1/2",
    "cmp 1/2        1/3        -> 1",
    "cmp 1/3        1/2        -> -1",
    "cmp 1/2        1/2        -> 0",
    "cmp -1/2       1/2        -> -1",
    "cmp -1/2       -1/3       -> -1",
    "cmp 0          0          -> 0",
    "cmp 1000000    1/1000000  -> 1",
    "cmp 1/1000000  1000000    -> -1",
    "text    0/1   -> \"0\" err=<nil> back=0 uerr=<nil>",
    "text    1/2   -> \"1/2\" err=<nil> back=1/2 uerr=<nil>",
    "text   -3/4   -> \"-3/4\" err=<nil> back=-3/4 uerr=<nil>",
    "text    5/1   -> \"5\" err=<nil> back=5 uerr=<nil>",
];

// go: none — goish idiom: one comparison, printing the divergence when
//     it is one, so a FAIL says what it got and not just that it did.
fn chk(failed: &mut int, ln: &mut int, got: string) {
    if *ln >= GO.len() as int {
        fmt::Printf!("[!!] extra line %d: %q\n", *ln + 1, got);
        *failed += 1;
        *ln += 1;
        return;
    }
    let want = s(GO[*ln as usize]);
    *ln += 1;
    if got == want {
        return;
    }
    fmt::Printf!("[!!] line %d FAIL\n  got  %q\n  want %q\n", *ln, got, want);
    *failed += 1;
}

#[goish::main]
fn main() {
    let mut failed: int = 0;
    let mut ln: int = 0;

    // 1
    for (a, b) in [
        (0i64, 1i64),
        (1, 1),
        (2, 1),
        (1, 2),
        (2, 4),
        (-1, 2),
        (1, -2),
        (-1, -2),
        (-2, 4),
        (6, 3),
        (-6, 3),
        (100, 10),
        (7, 7),
        (0, 5),
        (0, -5),
        (3, 9),
    ]
    .iter()
    {
        let x = r(*a, *b);
        chk(
            &mut failed,
            &mut ln,
            fmt::Sprintf!(
                "norm %4d/%-4d -> str=%-10s rat=%-8s num=%-6s den=%-6s sign=%-2d isint=%v",
                *a,
                *b,
                x.String(),
                x.RatString(),
                x.Num().String(),
                x.Denom().String(),
                x.Sign(),
                x.IsInt()
            ),
        );
    }
    // 2
    let ops: [(&str, i64, i64, i64, i64); 12] = [
        ("add", 1, 2, 1, 3),
        ("add", 1, 2, 1, 2),
        ("add", 1, 3, 2, 3),
        ("sub", 1, 2, 1, 3),
        ("sub", 1, 2, 1, 2),
        ("mul", 2, 3, 3, 2),
        ("mul", 1, 2, 1, 2),
        ("quo", 1, 2, 1, 3),
        ("quo", 1, 2, 2, 1),
        ("quo", -1, 2, 1, 3),
        ("add", -1, 2, 1, 2),
        ("mul", 0, 1, 5, 7),
    ];
    for (op, an, ad, bn, bd) in ops.iter() {
        let (x, y) = (r(*an, *ad), r(*bn, *bd));
        let mut z = nr();
        match *op {
            "add" => {
                z.Add(&x, &y);
            }
            "sub" => {
                z.Sub(&x, &y);
            }
            "mul" => {
                z.Mul(&x, &y);
            }
            _ => {
                z.Quo(&x, &y);
            }
        }
        chk(
            &mut failed,
            &mut ln,
            fmt::Sprintf!(
                "arith %-4s %3d/%-3d %3d/%-3d -> %-12s rat=%s",
                s(op),
                *an,
                *ad,
                *bn,
                *bd,
                z.String(),
                z.RatString()
            ),
        );
    }
    // 3
    for (a, b) in [(1i64, 2i64), (-1, 2), (3, 1), (-3, 1)].iter() {
        let x = r(*a, *b);
        let mut ng = nr();
        ng.Neg(&x);
        let mut ab = nr();
        ab.Abs(&x);
        let mut iv = nr();
        iv.Inv(&x);
        chk(
            &mut failed,
            &mut ln,
            fmt::Sprintf!(
                "unary %3d/%-3d -> neg=%-8s abs=%-8s inv=%-8s",
                *a,
                *b,
                ng.String(),
                ab.String(),
                iv.String()
            ),
        );
    }
    // 4
    for (a, b) in [
        (1i64, 3i64),
        (2, 3),
        (1, 2),
        (-1, 2),
        (3, 2),
        (-3, 2),
        (1, 8),
        (5, 4),
        (-5, 4),
        (1, 1),
        (0, 1),
        (22, 7),
    ]
    .iter()
    {
        let x = r(*a, *b);
        chk(
            &mut failed,
            &mut ln,
            fmt::Sprintf!(
                "floatstr %4d/%-4d -> p0=%-8s p1=%-9s p2=%-10s p5=%-13s p20=%s",
                *a,
                *b,
                x.FloatString(0),
                x.FloatString(1),
                x.FloatString(2),
                x.FloatString(5),
                x.FloatString(20)
            ),
        );
    }
    // 5
    for (a, b) in [
        (0i64, 1i64),
        (1, 1),
        (1, 2),
        (1, 3),
        (1, 4),
        (1, 5),
        (1, 8),
        (1, 10),
        (1, 6),
        (1, 7),
        (3, 8),
        (1, 1000),
        (1, 1024),
        (7, 20),
    ]
    .iter()
    {
        let x = r(*a, *b);
        let (nn, exact) = x.FloatPrec();
        chk(
            &mut failed,
            &mut ln,
            fmt::Sprintf!(
                "floatprec %4d/%-5d -> n=%-4d exact=%-5v str=%s",
                *a,
                *b,
                nn,
                exact,
                x.FloatString(nn)
            ),
        );
    }
    // 6
    for v in [
        0.0f64,
        1.0,
        -1.0,
        0.5,
        0.25,
        0.1,
        0.2,
        1.0 / 3.0,
        3.141592653589793,
        1e10,
        1e-10,
        12345.6789,
    ] {
        let mut x = nr();
        let ok = {
            let (_, ok) = x.SetFloat64(v);
            ok
        };
        if !ok {
            chk(
                &mut failed,
                &mut ln,
                fmt::Sprintf!("setf64 %-22g -> not-finite", v),
            );
            continue;
        }
        let (g, exact) = x.Float64();
        let (f32v, e32) = x.Float32();
        chk(
            &mut failed,
            &mut ln,
            fmt::Sprintf!(
                "setf64 %-22g -> %-46s back=%-22g exact=%-5v f32=%-14g e32=%v",
                v,
                x.RatString(),
                g,
                exact,
                f32v,
                e32
            ),
        );
    }
    // 7
    for (a, b) in [(1i64, 3i64), (1, 2), (2, 1), (1, 10), (1, 7)].iter() {
        let x = r(*a, *b);
        let (g, exact) = x.Float64();
        chk(
            &mut failed,
            &mut ln,
            fmt::Sprintf!("tof64 %3d/%-3d -> %-24g exact=%v", *a, *b, g, exact),
        );
    }
    // 8
    for st in [
        "0",
        "1",
        "-1",
        "2/4",
        "-2/4",
        "2/-4",
        "1/3",
        "1.5",
        "-1.5",
        ".5",
        "5.",
        "1e3",
        "1.5e-3",
        "1E3",
        "0x10",
        "0b101",
        "0o17",
        "1_000",
        "0x1p4",
        "",
        "x",
        "1/",
        "/2",
        "1/0",
        "1.2.3",
        "1/2/3",
        " 1",
        "1 ",
        "3/6",
        "10/5",
        "1e400",
        "0.000000000000000000001",
    ] {
        let mut x = nr();
        let ok = {
            let (_, ok) = x.SetString(st);
            ok
        };
        if !ok {
            chk(
                &mut failed,
                &mut ln,
                fmt::Sprintf!("setstring %-24q -> nil,false", s(st)),
            );
            continue;
        }
        chk(
            &mut failed,
            &mut ln,
            fmt::Sprintf!("setstring %-24q -> %s,true", s(st), x.RatString()),
        );
    }
    // 9
    {
        let mut a = Int::new();
        let _ = a.SetString("123456789012345678901234567890", 10);
        let mut b = Int::new();
        let _ = b.SetString("987654321098765432109876543210", 10);
        let mut z = nr();
        z.SetFrac(&a, &b);
        chk(
            &mut failed,
            &mut ln,
            fmt::Sprintf!("setfrac big -> %s", z.RatString()),
        );
        let mut z2 = nr();
        z2.SetFrac(&big::NewInt(1), &big::NewInt(-2));
        chk(
            &mut failed,
            &mut ln,
            fmt::Sprintf!("setfrac negden -> %s", z2.String()),
        );
    }
    // 10
    let pairs: [((i64, i64), (i64, i64)); 8] = [
        ((1, 2), (1, 3)),
        ((1, 3), (1, 2)),
        ((1, 2), (2, 4)),
        ((-1, 2), (1, 2)),
        ((-1, 2), (-1, 3)),
        ((0, 1), (0, 5)),
        ((1000000, 1), (1, 1000000)),
        ((1, 1000000), (1000000, 1)),
    ];
    for ((an, ad), (bn, bd)) in pairs.iter() {
        let (x, y) = (r(*an, *ad), r(*bn, *bd));
        chk(
            &mut failed,
            &mut ln,
            fmt::Sprintf!(
                "cmp %-10s %-10s -> %d",
                x.RatString(),
                y.RatString(),
                x.Cmp(&y)
            ),
        );
    }
    // 11
    for (a, b) in [(0i64, 1i64), (1, 2), (-3, 4), (5, 1)].iter() {
        let x = r(*a, *b);
        let (bt, err) = x.MarshalText();
        let mut back = nr();
        let uerr = back.UnmarshalText(bt.clone());
        chk(
            &mut failed,
            &mut ln,
            fmt::Sprintf!(
                "text %4d/%-3d -> %q err=%v back=%s uerr=%v",
                *a,
                *b,
                string::from_bytes(&bt),
                err,
                back.RatString(),
                uerr
            ),
        );
    }
    if ln != GO.len() as int {
        fmt::Printf!("[!!] produced %d lines, pinned %d\n", ln, GO.len() as int);
        failed += 1;
    }
    if failed == 0 {
        fmt::Printf!("ok %d/%d\n", ln, ln);
        return;
    }
    fmt::Printf!("FAILED %d of %d\n", failed, ln);
    syscall::Exit(1);
}
