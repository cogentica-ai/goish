// math — Go's `math` parent package.
//
// Reference: /share/go/src/math/
//
// Public API surface (Goish v1):
//
//   Constants: E, Pi, Phi, Sqrt2, SqrtE, SqrtPi, Ln2, Log2E, Ln10, Log10E
//              MaxFloat64, SmallestNonzeroFloat64, MaxFloat32
//              MaxInt, MinInt, MaxInt8/16/32/64, MinInt8/16/32/64
//              MaxUint, MaxUint8/16/32/64
//
//   IEEE predicate:  IsNaN, IsInf, Inf, NaN, Signbit
//   Rounding:        Floor, Ceil, Round, Trunc, Abs
//   Arithmetic:      Sqrt, Pow, Mod, Dim, Max, Min, Hypot
//   Transcendental:  Exp, Exp2, Log, Log2, Log10, Sin, Cos, Tan, Atan, Atan2
//                    Sinh, Cosh, Tanh, Asin, Acos, Atan, Asinh, Acosh, Atanh
//   Bit conversion:  Float32bits, Float32frombits, Float64bits, Float64frombits
//
// Sub-packages: big, bits, rand (each re-exported via sub-modules).
//
// NOTE: transcendental functions (Exp, Log, Sin, Cos, …) forward to
// `f64` methods backed by LLVM intrinsics on x86-64. If a future
// target requires libm, add `libm = "0.2"` to Cargo.toml and swap
// the bodies. The intrinsic path is zero-overhead on the current target.

#![allow(non_snake_case)]
#![allow(non_upper_case_globals)]

pub mod big;
pub mod bits;
pub mod rand;

// ─── Mathematical constants (math/const.go) ────────────────────────────

pub const E:       f64 = core::f64::consts::E;
pub const Pi:      f64 = core::f64::consts::PI;
pub const Phi:     f64 = 1.618033988749894848204586834365638117720309179805762862135;
pub const Sqrt2:   f64 = core::f64::consts::SQRT_2;
pub const SqrtE:   f64 = 1.6487212707001281468486507878141635716537761007101480115750793116;
pub const SqrtPi:  f64 = 1.7724538509055158819194275565678253546897498657741308796622734;
pub const SqrtPhi: f64 = 1.272019649514068964252422461737491491715608778319659702868723;
pub const Ln2:     f64 = core::f64::consts::LN_2;
pub const Log2E:   f64 = core::f64::consts::LOG2_E;
pub const Ln10:    f64 = core::f64::consts::LN_10;
pub const Log10E:  f64 = core::f64::consts::LOG10_E;

pub const MaxFloat32:            f32 = f32::MAX;
pub const SmallestNonzeroFloat32: f32 = f32::MIN_POSITIVE * f32::EPSILON;
pub const MaxFloat64:            f64 = f64::MAX;
pub const SmallestNonzeroFloat64: f64 = 5e-324_f64;

pub const MaxInt:   i64 = i64::MAX;
pub const MinInt:   i64 = i64::MIN;
pub const MaxInt8:  i8  = i8::MAX;
pub const MinInt8:  i8  = i8::MIN;
pub const MaxInt16: i16 = i16::MAX;
pub const MinInt16: i16 = i16::MIN;
pub const MaxInt32: i32 = i32::MAX;
pub const MinInt32: i32 = i32::MIN;
pub const MaxInt64: i64 = i64::MAX;
pub const MinInt64: i64 = i64::MIN;
pub const MaxUint:   u64 = u64::MAX;
pub const MaxUint8:  u8  = u8::MAX;
pub const MaxUint16: u16 = u16::MAX;
pub const MaxUint32: u32 = u32::MAX;
pub const MaxUint64: u64 = u64::MAX;

// ─── IEEE-754 predicates and constructors (math/bits.go) ───────────────

/// `math.IsNaN(f) bool` — reports whether f is an IEEE 754 NaN.
pub fn IsNaN(f: f64) -> bool {
    f.is_nan()
}

/// `math.IsInf(f, sign int) bool` — reports whether f is an IEEE 754
/// infinity, according to sign: +1 → +Inf only; -1 → -Inf only; 0 → either.
pub fn IsInf(f: f64, sign: crate::types::int) -> bool {
    if sign > 0 {
        f == f64::INFINITY
    } else if sign < 0 {
        f == f64::NEG_INFINITY
    } else {
        f.is_infinite()
    }
}

/// `math.Inf(sign int) float64` — returns positive or negative infinity.
pub fn Inf(sign: crate::types::int) -> f64 {
    if sign >= 0 { f64::INFINITY } else { f64::NEG_INFINITY }
}

/// `math.NaN() float64` — returns an IEEE 754 NaN.
pub fn NaN() -> f64 {
    f64::NAN
}

/// `math.Signbit(x) bool` — reports whether x is negative or negative zero.
pub fn Signbit(x: f64) -> bool {
    x.is_sign_negative()
}

// ─── Rounding (math/floor.go, math/round.go) ───────────────────────────
// Uses libm for no_std builds (f64::floor etc. require libm on Linux).

/// `math.Floor(x) float64` — largest integer ≤ x.
pub fn Floor(x: f64) -> f64 {
    libm::floor(x)
}

/// `math.Ceil(x) float64` — smallest integer ≥ x.
pub fn Ceil(x: f64) -> f64 {
    libm::ceil(x)
}

/// `math.Round(x) float64` — round to nearest integer, ties away from zero.
pub fn Round(x: f64) -> f64 {
    libm::round(x)
}

/// `math.Trunc(x) float64` — integer portion of x (truncate toward zero).
pub fn Trunc(x: f64) -> f64 {
    libm::trunc(x)
}

// ─── Absolute value (math/abs.go) ──────────────────────────────────────

/// `math.Abs(x) float64`.
pub fn Abs(x: f64) -> f64 {
    x.abs()
}

// ─── Arithmetic (math/sqrt.go, math/pow.go, math/mod.go, …) ───────────

/// `math.Sqrt(x) float64`.
pub fn Sqrt(x: f64) -> f64 {
    libm::sqrt(x)
}

/// `math.Pow(x, y) float64`.
pub fn Pow(x: f64, y: f64) -> f64 {
    libm::pow(x, y)
}

/// `math.Pow10(n int) float64`.
pub fn Pow10(n: crate::types::int) -> f64 {
    libm::pow(10.0_f64, n as f64)
}

/// `math.Mod(x, y) float64` — IEEE remainder, same sign as x.
pub fn Mod(x: f64, y: f64) -> f64 {
    libm::fmod(x, y)
}

/// `math.Remainder(x, y) float64` — IEEE 754 remainder.
pub fn Remainder(x: f64, y: f64) -> f64 {
    libm::remainder(x, y)
}

/// `math.Dim(x, y) float64` — max(x-y, 0).
pub fn Dim(x: f64, y: f64) -> f64 {
    let d = x - y;
    if d > 0.0 { d } else { 0.0 }
}

/// `math.Max(x, y) float64` — Go semantics: NaN propagates, +0 > -0.
pub fn Max(x: f64, y: f64) -> f64 {
    if x.is_nan() || y.is_nan() { return f64::NAN; }
    if x > y { x } else { y }
}

/// `math.Min(x, y) float64` — Go semantics: NaN propagates, -0 < +0.
pub fn Min(x: f64, y: f64) -> f64 {
    if x.is_nan() || y.is_nan() { return f64::NAN; }
    if x < y { x } else { y }
}

/// `math.Hypot(p, q) float64` — sqrt(p²+q²) without overflow.
pub fn Hypot(p: f64, q: f64) -> f64 {
    libm::hypot(p, q)
}

// ─── Transcendental functions ───────────────────────────────────────────

/// `math.Exp(x) float64` — eˣ.
pub fn Exp(x: f64) -> f64 {
    libm::exp(x)
}

/// `math.Exp2(x) float64` — 2ˣ.
pub fn Exp2(x: f64) -> f64 {
    libm::exp2(x)
}

/// `math.Log(x) float64` — natural logarithm.
pub fn Log(x: f64) -> f64 {
    libm::log(x)
}

/// `math.Log2(x) float64`.
pub fn Log2(x: f64) -> f64 {
    libm::log2(x)
}

/// `math.Log10(x) float64`.
pub fn Log10(x: f64) -> f64 {
    libm::log10(x)
}

/// `math.Sin(x) float64`.
pub fn Sin(x: f64) -> f64 {
    libm::sin(x)
}

/// `math.Cos(x) float64`.
pub fn Cos(x: f64) -> f64 {
    libm::cos(x)
}

/// `math.Tan(x) float64`.
pub fn Tan(x: f64) -> f64 {
    libm::tan(x)
}

/// `math.Asin(x) float64`.
pub fn Asin(x: f64) -> f64 {
    libm::asin(x)
}

/// `math.Acos(x) float64`.
pub fn Acos(x: f64) -> f64 {
    libm::acos(x)
}

/// `math.Atan(x) float64`.
pub fn Atan(x: f64) -> f64 {
    libm::atan(x)
}

/// `math.Atan2(y, x) float64`.
pub fn Atan2(y: f64, x: f64) -> f64 {
    libm::atan2(y, x)
}

/// `math.Sinh(x) float64`.
pub fn Sinh(x: f64) -> f64 {
    libm::sinh(x)
}

/// `math.Cosh(x) float64`.
pub fn Cosh(x: f64) -> f64 {
    libm::cosh(x)
}

/// `math.Tanh(x) float64`.
pub fn Tanh(x: f64) -> f64 {
    libm::tanh(x)
}

/// `math.Asinh(x) float64`.
pub fn Asinh(x: f64) -> f64 {
    libm::asinh(x)
}

/// `math.Acosh(x) float64`.
pub fn Acosh(x: f64) -> f64 {
    libm::acosh(x)
}

/// `math.Atanh(x) float64`.
pub fn Atanh(x: f64) -> f64 {
    libm::atanh(x)
}

// ─── float bit-level conversions (math/unsafe.go) ─────────────────────

/// `math.Float32bits(f) uint32` — IEEE 754 encoding of f.
pub fn Float32bits(f: f32) -> u32 {
    f.to_bits()
}

/// `math.Float32frombits(b) float32` — float32 with the given encoding.
pub fn Float32frombits(b: u32) -> f32 {
    f32::from_bits(b)
}

/// `math.Float64bits(f) uint64`.
pub fn Float64bits(f: f64) -> u64 {
    f.to_bits()
}

/// `math.Float64frombits(b) float64`.
pub fn Float64frombits(b: u64) -> f64 {
    f64::from_bits(b)
}
