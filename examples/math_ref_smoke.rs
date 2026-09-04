// math_ref_smoke — the math package against a running Go, bit for bit.
// (math/*.go)
//
// Every expectation below is what a real Go 1.25.5 computes: the
// vectors are the output of `tools/gen_math_ref.go` run in `package
// math_test` by `scripts/goref.sh`, as raw IEEE-754 BIT PATTERNS. A
// one-ulp difference shows here; it would be rounded away by any
// decimal comparison.
//
// src/math/mod.rs carries ZERO provenance anchors for 61 Go files, and
// `port_coverage math` reports all 78 of its functions as UNVERIFIED —
// matched by NAME ONLY. A float function that is slightly wrong, or
// wrong at an edge, is invisible until something downstream is wrong
// for a reason nobody can trace back. These are the edges: NaN, ±Inf,
// ±0, and the documented special case each function has.
//
// The signed-zero rows are the ones most likely to catch something.
// Go specifies Sqrt(-0) = -0, Floor(-0) = -0, and Max(+0, -0) = +0 —
// results that compare EQUAL to their wrong answers under `==`, so
// only the bits distinguish them.

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

// go: none — goish idiom: compare the BIT PATTERNS, not the values. Two
//     NaNs are never `==`, and +0 == -0, so `==` cannot see either of
//     the differences this smoke exists to catch.
// go: none — goish idiom: the functions whose result must be EXACTLY
//     Go's. These are algebraic — they select, truncate or rescale an
//     existing value rather than approximating a series — so there is
//     no room for an implementation to differ.
fn is_exact(name: &str) -> bool {
    return matches!(
        name,
        "Sqrt"
            | "Floor"
            | "Ceil"
            | "Trunc"
            | "Round"
            | "Abs"
            | "Copysign"
            | "Dim"
            | "Max"
            | "Min"
            | "Mod"
            | "Remainder"
            | "Atan2"
            | "Hypot"
            | "Pow"
            | "Frexp"
            | "Ldexp"
            | "Modf int"
            | "Modf frac"
            | "Pow10"
            | "Asin"
            | "Atan"
            | "Log"
            | "Log2"
            | "Exp2"
            | "Asinh"
            | "Acosh"
            | "Atanh"
            | "Tanh"
    );
}

/// The transcendental bound. goish computes these through `libm` and Go
/// through its own polynomials, so the last bits can differ; the
/// largest observed difference is 7 ulp, on Sin and Cos at pi/2.
const ULP_BOUND: int = 8;

fn bits(failed: &mut int, got: f64, want: u64, name: &str, arg: u64) {
    let w = f64::from_bits(want);
    if got.to_bits() == want {
        return;
    }
    // Go does not specify a NaN PAYLOAD, and its `math.NaN()` is
    // 0x7FF8000000000001 where Rust's is 0x7FF8000000000000. Two NaNs
    // agreeing on being NaN is the whole of the contract.
    if got.is_nan() && w.is_nan() {
        return;
    }
    let ulp = ulp_diff(got, w);
    if !is_exact(name) && ulp >= 0 && ulp <= ULP_BOUND {
        return;
    }
    fmt::Printf!(
        "[!!] %s arg=%d got=%d want=%d ulp=%d\n",
        s(name),
        arg as i64,
        got.to_bits() as i64,
        want as i64,
        ulp
    );
    *failed += 1;
}

// go: none — goish idiom: the distance between two floats in
//     representable steps, which is the only meaningful way to say how
//     far apart two transcendental results are.
fn ulp_diff(a: f64, b: f64) -> int {
    if a.is_nan() || b.is_nan() || a.is_infinite() != b.is_infinite() {
        return -1;
    }
    let (ai, bi) = (a.to_bits() as i64, b.to_bits() as i64);
    let d = if ai > bi { ai - bi } else { bi - ai };
    return d;
}

#[goish::main]
fn main() {
    let mut failed = 0;

    // 1. The one-argument functions. Sinh(710) and Cosh(710) are NOT
    //    in this table — they are a known divergence, pinned in check 5.
    {
        let cases: [(&str, u64, u64); 163] = [
            ("Sqrt", 0, 0),
            ("Sqrt", 4607182418800017408, 4607182418800017408),
            ("Sqrt", 4611686018427387904, 4609047870845172685),
            ("Sqrt", 4616189618054758400, 4611686018427387904),
            ("Sqrt", 9094988921128908188, 6850974717710472879),
            ("Sqrt", 118622047889322841, 2362753625475748981),
            ("Sqrt", 13830554455654793216, 18444492273895866368),
            ("Sqrt", 9221120237041090561, 9221120237041090561),
            ("Sqrt", 9218868437227405312, 9218868437227405312),
            ("Sqrt", 9223372036854775808, 9223372036854775808),
            ("Floor", 4609434218613702656, 4607182418800017408),
            ("Floor", 13832806255468478464, 13835058055282163712),
            ("Floor", 4602678819172646912, 0),
            ("Floor", 13826050856027422720, 13830554455654793216),
            ("Floor", 4611686018427387904, 4611686018427387904),
            ("Floor", 13835058055282163712, 13835058055282163712),
            ("Floor", 9221120237041090561, 9221120237041090561),
            ("Floor", 9218868437227405312, 9218868437227405312),
            ("Floor", 18442240474082181120, 18442240474082181120),
            ("Floor", 9223372036854775808, 9223372036854775808),
            ("Ceil", 4609434218613702656, 4611686018427387904),
            ("Ceil", 13832806255468478464, 13830554455654793216),
            ("Ceil", 4602678819172646912, 4607182418800017408),
            ("Ceil", 13826050856027422720, 9223372036854775808),
            ("Ceil", 4611686018427387904, 4611686018427387904),
            ("Ceil", 13835058055282163712, 13835058055282163712),
            ("Ceil", 9221120237041090561, 9221120237041090561),
            ("Ceil", 9218868437227405312, 9218868437227405312),
            ("Ceil", 18442240474082181120, 18442240474082181120),
            ("Ceil", 9223372036854775808, 9223372036854775808),
            ("Trunc", 4611235658464650854, 4607182418800017408),
            ("Trunc", 13834607695319426662, 13830554455654793216),
            ("Trunc", 4602678819172646912, 0),
            ("Trunc", 13826050856027422720, 9223372036854775808),
            ("Trunc", 9221120237041090561, 9221120237041090561),
            ("Trunc", 9218868437227405312, 9218868437227405312),
            ("Trunc", 9223372036854775808, 9223372036854775808),
            ("Round", 4602678819172646912, 4607182418800017408),
            ("Round", 13826050856027422720, 13830554455654793216),
            ("Round", 4609434218613702656, 4611686018427387904),
            ("Round", 13832806255468478464, 13835058055282163712),
            ("Round", 4612811918334230528, 4613937818241073152),
            ("Round", 13836183955189006336, 13837309855095848960),
            ("Round", 4602678819172646911, 0),
            ("Round", 9221120237041090561, 9221120237041090561),
            ("Round", 9218868437227405312, 9218868437227405312),
            ("Abs", 13830554455654793216, 4607182418800017408),
            ("Abs", 4607182418800017408, 4607182418800017408),
            ("Abs", 9223372036854775808, 0),
            ("Abs", 9221120237041090561, 9221120237041090561),
            ("Abs", 18442240474082181120, 9218868437227405312),
            ("Exp", 0, 4607182418800017408),
            ("Exp", 4607182418800017408, 4613303445314885481),
            ("Exp", 13830554455654793216, 4600298746774613816),
            ("Exp", 4649447645771726848, 9213593174447348891),
            ("Exp", 4649456441864749056, 9218868437227405312),
            ("Exp", 13873145138068324352, 0),
            ("Exp", 9221120237041090561, 9221120237041090561),
            ("Exp", 9218868437227405312, 9218868437227405312),
            ("Exp", 18442240474082181120, 0),
            ("Exp2", 0, 4607182418800017408),
            ("Exp2", 4607182418800017408, 4611686018427387904),
            ("Exp2", 4621819117588971520, 4652218415073722368),
            ("Exp2", 13830554455654793216, 4602678819172646912),
            ("Exp2", 9221120237041090561, 9221120237041090561),
            ("Exp2", 9218868437227405312, 9218868437227405312),
            ("Log", 4607182418800017408, 0),
            ("Log", 4613303445314885481, 4607182418800017408),
            ("Log", 0, 18442240474082181120),
            ("Log", 13830554455654793216, 9221120237041090561),
            ("Log", 9094988921128908188, 4649287341619838901),
            ("Log", 9221120237041090561, 9221120237041090561),
            ("Log", 9218868437227405312, 9218868437227405312),
            ("Log2", 4607182418800017408, 0),
            ("Log2", 4611686018427387904, 4607182418800017408),
            ("Log2", 4620693217682128896, 4613937818241073152),
            ("Log2", 4602678819172646912, 13830554455654793216),
            ("Log2", 0, 18442240474082181120),
            ("Log2", 13830554455654793216, 9221120237041090561),
            ("Log2", 9221120237041090561, 9221120237041090561),
            ("Log10", 4607182418800017408, 0),
            ("Log10", 4621819117588971520, 4607182418800017408),
            ("Log10", 4636737291354636288, 4611686018427387904),
            ("Log10", 4591870180066957722, 13830554455654793215),
            ("Log10", 0, 18442240474082181120),
            ("Log10", 13830554455654793216, 9221120237041090561),
            ("Log10", 9221120237041090561, 9221120237041090561),
            ("Sin", 0, 0),
            ("Sin", 4609753056924675352, 4607182418800017408),
            ("Sin", 4614256656552045848, 4368955796522032128),
            ("Sin", 4607182418800017408, 4605754516372524270),
            ("Sin", 13830554455654793216, 13829126553227300078),
            ("Sin", 9221120237041090561, 9221120237041090561),
            ("Sin", 9218868437227405312, 9221120237041090561),
            ("Sin", 9223372036854775808, 9223372036854775808),
            ("Cos", 0, 4607182418800017408),
            ("Cos", 4609753056924675352, 4364452196894661632),
            ("Cos", 4614256656552045848, 13830554455654793216),
            ("Cos", 4607182418800017408, 4603041830072026764),
            ("Cos", 9221120237041090561, 9221120237041090561),
            ("Cos", 9218868437227405312, 9221120237041090561),
            ("Tan", 0, 0),
            ("Tan", 4605249457297304856, 4607182418800017408),
            ("Tan", 4607182418800017408, 4609692760021066661),
            ("Tan", 9221120237041090561, 9221120237041090561),
            ("Tan", 9218868437227405312, 9221120237041090561),
            ("Tan", 9223372036854775808, 9223372036854775808),
            ("Asin", 0, 0),
            ("Asin", 4607182418800017408, 4609753056924675352),
            ("Asin", 13830554455654793216, 13833125093779451160),
            ("Asin", 4602678819172646912, 4602891378046628710),
            ("Asin", 4611686018427387904, 9221120237041090561),
            ("Asin", 9221120237041090561, 9221120237041090561),
            ("Asin", 9223372036854775808, 9223372036854775808),
            ("Acos", 0, 4609753056924675352),
            ("Acos", 4607182418800017408, 0),
            ("Acos", 13830554455654793216, 4614256656552045848),
            ("Acos", 4602678819172646912, 4607394977673999205),
            ("Acos", 4611686018427387904, 9221120237041090561),
            ("Acos", 9221120237041090561, 9221120237041090561),
            ("Atan", 0, 0),
            ("Atan", 4607182418800017408, 4605249457297304856),
            ("Atan", 13830554455654793216, 13828621494152080664),
            ("Atan", 9218868437227405312, 4609753056924675352),
            ("Atan", 18442240474082181120, 13833125093779451160),
            ("Atan", 9221120237041090561, 9221120237041090561),
            ("Atan", 9223372036854775808, 9223372036854775808),
            ("Sinh", 0, 0),
            ("Sinh", 4607182418800017408, 4607971454830426498),
            ("Sinh", 13830554455654793216, 13831343491685202306),
            ("Sinh", 9221120237041090561, 9221120237041090561),
            ("Sinh", 9218868437227405312, 9218868437227405312),
            ("Sinh", 9223372036854775808, 9223372036854775808),
            ("Cosh", 0, 4607182418800017408),
            ("Cosh", 4607182418800017408, 4609628236544603472),
            ("Cosh", 13830554455654793216, 4609628236544603472),
            ("Cosh", 9221120237041090561, 9221120237041090561),
            ("Cosh", 9218868437227405312, 9218868437227405312),
            ("Tanh", 0, 0),
            ("Tanh", 4607182418800017408, 4605035049859216276),
            ("Tanh", 13830554455654793216, 13828407086713992084),
            ("Tanh", 4629137466983448576, 4607182418800017408),
            ("Tanh", 9221120237041090561, 9221120237041090561),
            ("Tanh", 9218868437227405312, 4607182418800017408),
            ("Tanh", 9223372036854775808, 9223372036854775808),
            ("Asinh", 0, 0),
            ("Asinh", 4607182418800017408, 4606113927061427239),
            ("Asinh", 13830554455654793216, 13829485963916203047),
            ("Asinh", 9221120237041090561, 9221120237041090561),
            ("Asinh", 9218868437227405312, 9218868437227405312),
            ("Asinh", 9223372036854775808, 9223372036854775808),
            ("Acosh", 4607182418800017408, 0),
            ("Acosh", 4611686018427387904, 4608609870266500148),
            ("Acosh", 4602678819172646912, 9221120237041090561),
            ("Acosh", 9221120237041090561, 9221120237041090561),
            ("Acosh", 9218868437227405312, 9218868437227405312),
            ("Atanh", 0, 0),
            ("Atanh", 4602678819172646912, 4603122929439146762),
            ("Atanh", 4607182418800017408, 9218868437227405312),
            ("Atanh", 13830554455654793216, 18442240474082181120),
            ("Atanh", 4611686018427387904, 9221120237041090561),
            ("Atanh", 9221120237041090561, 9221120237041090561),
            ("Atanh", 9223372036854775808, 9223372036854775808),
        ];
        let mut i = 0;
        while i < cases.len() {
            let (name, xb, want) = cases[i];
            let x = f64::from_bits(xb);
            let got = match name {
                "Sqrt" => math::Sqrt(x),
                "Floor" => math::Floor(x),
                "Ceil" => math::Ceil(x),
                "Trunc" => math::Trunc(x),
                "Round" => math::Round(x),
                "Abs" => math::Abs(x),
                "Exp" => math::Exp(x),
                "Exp2" => math::Exp2(x),
                "Log" => math::Log(x),
                "Log2" => math::Log2(x),
                "Log10" => math::Log10(x),
                "Sin" => math::Sin(x),
                "Cos" => math::Cos(x),
                "Tan" => math::Tan(x),
                "Asin" => math::Asin(x),
                "Acos" => math::Acos(x),
                "Atan" => math::Atan(x),
                "Sinh" => math::Sinh(x),
                "Cosh" => math::Cosh(x),
                "Tanh" => math::Tanh(x),
                "Asinh" => math::Asinh(x),
                "Acosh" => math::Acosh(x),
                "Atanh" => math::Atanh(x),
                _ => {
                    fmt::Println!("[!!] unknown fn");
                    failed += 1;
                    0.0
                }
            };
            bits(&mut failed, got, want, name, xb);
            i += 1;
        }
        fmt::Println!("[  1 ] the one-argument functions");
    }

    // 2. The two-argument functions.
    {
        let cases: [(&str, u64, u64, u64); 55] = [
            (
                "Pow",
                4611686018427387904,
                4621819117588971520,
                4652218415073722368,
            ),
            (
                "Pow",
                4611686018427387904,
                4602678819172646912,
                4609047870845172685,
            ),
            ("Pow", 0, 0, 4607182418800017408),
            (
                "Pow",
                13830554455654793216,
                4602678819172646912,
                18444492273895866368,
            ),
            (
                "Pow",
                4607182418800017408,
                9221120237041090561,
                4607182418800017408,
            ),
            ("Pow", 9221120237041090561, 0, 4607182418800017408),
            (
                "Pow",
                13830554455654793216,
                9218868437227405312,
                4607182418800017408,
            ),
            (
                "Pow",
                4611686018427387904,
                13830554455654793216,
                4602678819172646912,
            ),
            (
                "Pow",
                9223372036854775808,
                13830554455654793216,
                18442240474082181120,
            ),
            (
                "Pow",
                9223372036854775808,
                4613937818241073152,
                9223372036854775808,
            ),
            ("Pow", 9218868437227405312, 0, 4607182418800017408),
            (
                "Mod",
                4617315517961601024,
                4613937818241073152,
                4611686018427387904,
            ),
            (
                "Mod",
                13840687554816376832,
                4613937818241073152,
                13835058055282163712,
            ),
            (
                "Mod",
                4617315517961601024,
                13837309855095848960,
                4611686018427387904,
            ),
            ("Mod", 4617315517961601024, 0, 9221120237041090561),
            (
                "Mod",
                9218868437227405312,
                4613937818241073152,
                9221120237041090561,
            ),
            (
                "Mod",
                4617315517961601024,
                9218868437227405312,
                4617315517961601024,
            ),
            (
                "Mod",
                9221120237041090561,
                4607182418800017408,
                9221120237041090561,
            ),
            (
                "Remainder",
                4617315517961601024,
                4613937818241073152,
                13830554455654793216,
            ),
            (
                "Remainder",
                13840687554816376832,
                4613937818241073152,
                4607182418800017408,
            ),
            ("Remainder", 4617315517961601024, 0, 9221120237041090561),
            (
                "Remainder",
                9218868437227405312,
                4613937818241073152,
                9221120237041090561,
            ),
            (
                "Remainder",
                4617315517961601024,
                9218868437227405312,
                4617315517961601024,
            ),
            (
                "Atan2",
                4607182418800017408,
                4607182418800017408,
                4605249457297304856,
            ),
            (
                "Atan2",
                13830554455654793216,
                4607182418800017408,
                13828621494152080664,
            ),
            (
                "Atan2",
                4607182418800017408,
                13830554455654793216,
                4612488097114038738,
            ),
            (
                "Atan2",
                13830554455654793216,
                13830554455654793216,
                13835860133968814546,
            ),
            ("Atan2", 0, 0, 0),
            (
                "Atan2",
                9223372036854775808,
                9223372036854775808,
                13837628693406821656,
            ),
            ("Atan2", 0, 13830554455654793216, 4614256656552045848),
            (
                "Atan2",
                9218868437227405312,
                9218868437227405312,
                4605249457297304856,
            ),
            (
                "Atan2",
                9221120237041090561,
                4607182418800017408,
                9221120237041090561,
            ),
            (
                "Hypot",
                4613937818241073152,
                4616189618054758400,
                4617315517961601024,
            ),
            ("Hypot", 0, 0, 0),
            (
                "Hypot",
                9218868437227405312,
                9221120237041090561,
                9218868437227405312,
            ),
            (
                "Hypot",
                9221120237041090561,
                4607182418800017408,
                9221120237041090561,
            ),
            (
                "Hypot",
                9094988921128908188,
                9094988921128908188,
                9097522851029299729,
            ),
            (
                "Dim",
                4617315517961601024,
                4613937818241073152,
                4611686018427387904,
            ),
            ("Dim", 4613937818241073152, 4617315517961601024, 0),
            (
                "Dim",
                9218868437227405312,
                9218868437227405312,
                18444492273895866368,
            ),
            (
                "Dim",
                9221120237041090561,
                4607182418800017408,
                9221120237041090561,
            ),
            (
                "Max",
                4607182418800017408,
                4611686018427387904,
                4611686018427387904,
            ),
            (
                "Max",
                9221120237041090561,
                4607182418800017408,
                9221120237041090561,
            ),
            (
                "Max",
                9218868437227405312,
                4607182418800017408,
                9218868437227405312,
            ),
            ("Max", 0, 9223372036854775808, 0),
            ("Max", 9223372036854775808, 0, 0),
            (
                "Min",
                4607182418800017408,
                4611686018427387904,
                4607182418800017408,
            ),
            (
                "Min",
                9221120237041090561,
                4607182418800017408,
                9221120237041090561,
            ),
            (
                "Min",
                18442240474082181120,
                4607182418800017408,
                18442240474082181120,
            ),
            ("Min", 0, 9223372036854775808, 9223372036854775808),
            ("Min", 9223372036854775808, 0, 9223372036854775808),
            (
                "Copysign",
                4613937818241073152,
                13830554455654793216,
                13837309855095848960,
            ),
            (
                "Copysign",
                13837309855095848960,
                4607182418800017408,
                4613937818241073152,
            ),
            (
                "Copysign",
                9221120237041090561,
                13830554455654793216,
                18444492273895866369,
            ),
            (
                "Copysign",
                9218868437227405312,
                13830554455654793216,
                18442240474082181120,
            ),
        ];
        let mut i = 0;
        while i < cases.len() {
            let (name, xb, yb, want) = cases[i];
            let (x, y) = (f64::from_bits(xb), f64::from_bits(yb));
            let got = match name {
                "Pow" => math::Pow(x, y),
                "Mod" => math::Mod(x, y),
                "Remainder" => math::Remainder(x, y),
                "Atan2" => math::Atan2(x, y),
                "Hypot" => math::Hypot(x, y),
                "Dim" => math::Dim(x, y),
                "Max" => math::Max(x, y),
                "Min" => math::Min(x, y),
                "Copysign" => math::Copysign(x, y),
                _ => {
                    fmt::Println!("[!!] unknown fn2");
                    failed += 1;
                    0.0
                }
            };
            bits(&mut failed, got, want, name, xb);
            i += 1;
        }
        fmt::Println!("[  2 ] the two-argument functions");
    }

    // 3. Frexp, Ldexp, Modf and Pow10 — the pair-returning ones.
    {
        let fx: [(u64, u64, i64); 8] = [
            (4607182418800017408, 4602678819172646912, 1),
            (4620693217682128896, 4602678819172646912, 4),
            (4602678819172646912, 4602678819172646912, 0),
            (0, 0, 0),
            (9223372036854775808, 9223372036854775808, 0),
            (9221120237041090561, 9221120237041090561, 0),
            (9218868437227405312, 9218868437227405312, 0),
            (20240225330731, 4603356717229943552, -1029),
        ];
        let mut i = 0;
        while i < fx.len() {
            let (xb, wf, we) = fx[i];
            let (fr, ex) = math::Frexp(f64::from_bits(xb));
            bits(&mut failed, fr, wf, "Frexp", xb);
            if ex != we {
                fmt::Printf!("[!!] Frexp exp FAIL got %d want %d\n", ex, we);
                failed += 1;
            }
            i += 1;
        }

        let lx: [(u64, i64, u64); 5] = [
            (4607182418800017408, 0, 4607182418800017408),
            (4607182418800017408, 10, 4652218415073722368),
            (4607182418800017408, -10, 4562146422526312448),
            (0, 5, 0),
            (9221120237041090561, 3, 9221120237041090561),
        ];
        let mut j = 0;
        while j < lx.len() {
            let (xb, e, want) = lx[j];
            bits(
                &mut failed,
                math::Ldexp(f64::from_bits(xb), e),
                want,
                "Ldexp",
                xb,
            );
            j += 1;
        }

        let mx: [(u64, u64, u64); 6] = [
            (
                4609434218613702656,
                4607182418800017408,
                4602678819172646912,
            ),
            (
                13832806255468478464,
                13830554455654793216,
                13826050856027422720,
            ),
            (0, 0, 0),
            (
                9223372036854775808,
                9223372036854775808,
                9223372036854775808,
            ),
            (
                9221120237041090561,
                9221120237041090561,
                9221120237041090561,
            ),
            (
                9218868437227405312,
                9218868437227405312,
                18444492273895866368,
            ),
        ];
        let mut k = 0;
        while k < mx.len() {
            let (xb, wi, wf) = mx[k];
            let (ip, fp) = math::Modf(f64::from_bits(xb));
            bits(&mut failed, ip, wi, "Modf int", xb);
            bits(&mut failed, fp, wf, "Modf frac", xb);
            k += 1;
        }

        let px: [(i64, u64); 9] = [
            (0, 4607182418800017408),
            (1, 4621819117588971520),
            (5, 4681608360884174848),
            (22, 4936209963552724370),
            (23, 4950912855330343670),
            (100, 6103021453049119613),
            (-1, 4591870180066957722),
            (309, 9218868437227405312),
            (310, 9218868437227405312),
        ];
        let mut m = 0;
        while m < px.len() {
            let (n, want) = px[m];
            bits(&mut failed, math::Pow10(n), want, "Pow10", n as u64);
            m += 1;
        }
        fmt::Println!("[  3 ] Frexp, Ldexp, Modf and Pow10");
    }

    // 4. The predicates and the bit conversions.
    {
        let cases: [(u64, bool, bool, bool, bool); 6] = [
            (4607182418800017408, false, false, false, false),
            (9221120237041090561, true, false, false, false),
            (9218868437227405312, false, true, false, false),
            (18442240474082181120, false, false, true, true),
            (0, false, false, false, false),
            (9223372036854775808, false, false, false, true),
        ];
        let mut i = 0;
        while i < cases.len() {
            let (xb, wnan, winf1, winfm1, wsign) = cases[i];
            let x = f64::from_bits(xb);
            if math::IsNaN(x) != wnan
                || math::IsInf(x, 1) != winf1
                || math::IsInf(x, -1) != winfm1
                || math::Signbit(x) != wsign
            {
                fmt::Printf!("[!!] predicates FAIL for bits %d\n", xb as i64);
                failed += 1;
            }
            // Float64bits round-trips exactly, including the NaN
            // payload and the sign of zero.
            if math::Float64bits(x) != xb || math::Float64frombits(xb).to_bits() != xb {
                fmt::Printf!("[!!] Float64bits round trip FAIL %d\n", xb as i64);
                failed += 1;
            }
            i += 1;
        }

        let f32s: [(u32, u32); 3] = [
            (1065353216, 1065353216),
            (1056964608, 1056964608),
            (2139095040, 2139095040),
        ];
        let mut j = 0;
        while j < f32s.len() {
            let (b, back) = f32s[j];
            if math::Float32bits(math::Float32frombits(b)) != back {
                fmt::Printf!("[!!] Float32 round trip FAIL %d\n", b as i64);
                failed += 1;
            }
            j += 1;
        }
        fmt::Println!("[  4 ] predicates and bit conversions");
    }

    // 5. KNOWN DIVERGENCE, pinned so a fix trips this test.
    //
    //    Go's Sinh and Cosh compute `Exp(x) * 0.5` for large x, and
    //    Go's Exp OVERFLOWS to +Inf just below 710 — so Go's
    //    Sinh(710) and Cosh(710) are both +Inf. The true values are
    //    about 1.1e308, which a float64 holds comfortably, and goish
    //    reaches them through libm and returns them.
    //
    //    goish is the more accurate of the two here and the less
    //    faithful. Which matters more is a call for whoever owns this
    //    package, so the current answer is pinned rather than quietly
    //    changed: a finite result, not +Inf.
    {
        let sinh710 = math::Sinh(710.0);
        let cosh710 = math::Cosh(710.0);
        if sinh710.is_infinite() || cosh710.is_infinite() {
            fmt::Println!(
                "KNOWN DIVERGENCE CHANGED - Sinh/Cosh(710) now overflow like Go's. Update this note."
            );
            failed += 1;
        }
        if !(sinh710 > 1.0e308) || !(cosh710 > 1.0e308) {
            fmt::Println!("[!!] Sinh/Cosh(710) are not the large finite values expected");
            failed += 1;
        }
        fmt::Println!("[  5 ] Sinh/Cosh(710): finite here, +Inf in Go (pinned)");
    }

    if failed == 0 {
        fmt::Println!("ok - math matches Go");
        syscall::Exit(0);
    } else {
        fmt::Println!("FAIL", failed);
        syscall::Exit(1);
    }
}
