// math — Go's `math` parent package.
//
// Reference: math/
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
//
// KNOWN DIVERGENCE from Go: Exp and Log are hand-written amd64
// assembly in Go (exp_amd64.s, log_amd64.s), so goish's libm-backed
// versions differ by up to 2 ULP. That leaks into Pow for fractional
// exponents only — Pow's integer path is Go's own algorithm and is
// bit-exact (examples/math_pow_diff.rs asserts both halves).

#![allow(non_snake_case)]
#![allow(non_upper_case_globals)]

pub mod big;
pub mod bits;
pub mod rand;

// ─── Mathematical constants (math/const.go) ────────────────────────────

pub const E: f64 = core::f64::consts::E;
pub const Pi: f64 = core::f64::consts::PI;
pub const Phi: f64 = 1.618033988749894848204586834365638117720309179805762862135;
pub const Sqrt2: f64 = core::f64::consts::SQRT_2;
pub const SqrtE: f64 = 1.6487212707001281468486507878141635716537761007101480115750793116;
pub const SqrtPi: f64 = 1.7724538509055158819194275565678253546897498657741308796622734;
pub const SqrtPhi: f64 = 1.272019649514068964252422461737491491715608778319659702868723;
pub const Ln2: f64 = core::f64::consts::LN_2;
pub const Log2E: f64 = core::f64::consts::LOG2_E;
pub const Ln10: f64 = core::f64::consts::LN_10;
pub const Log10E: f64 = core::f64::consts::LOG10_E;

pub const MaxFloat32: f32 = f32::MAX;
pub const SmallestNonzeroFloat32: f32 = f32::MIN_POSITIVE * f32::EPSILON;
pub const MaxFloat64: f64 = f64::MAX;
pub const SmallestNonzeroFloat64: f64 = 5e-324_f64;

pub const MaxInt: i64 = i64::MAX;
pub const MinInt: i64 = i64::MIN;
pub const MaxInt8: i8 = i8::MAX;
pub const MinInt8: i8 = i8::MIN;
pub const MaxInt16: i16 = i16::MAX;
pub const MinInt16: i16 = i16::MIN;
pub const MaxInt32: i32 = i32::MAX;
pub const MinInt32: i32 = i32::MIN;
pub const MaxInt64: i64 = i64::MAX;
pub const MinInt64: i64 = i64::MIN;
pub const MaxUint: u64 = u64::MAX;
pub const MaxUint8: u8 = u8::MAX;
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
    if sign >= 0 {
        f64::INFINITY
    } else {
        f64::NEG_INFINITY
    }
}

/// `math.NaN() float64` — returns an IEEE 754 NaN.
pub fn NaN() -> f64 {
    // Go: math/bits.go — `NaN() float64 { return Float64frombits(uvnan) }`
    // with uvnan = 0x7FF8000000000001. Rust's f64::NAN has payload 0,
    // which is a different bit pattern; anything comparing NaN bits
    // against Go output (differential sweeps, serialized floats) sees it.
    f64::from_bits(0x7FF8000000000001)
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
    if x < 0.0 {
        // Go compiles Sqrt to the SQRTSD instruction on amd64, whose
        // invalid-operation result is the x86 default NaN
        // (0xFFF8000000000000 — sign bit set). libm's software sqrt
        // returns a positive NaN instead, which differs bit-for-bit
        // from every Go reference produced on this target.
        return f64::from_bits(0xFFF8000000000000);
    }
    libm::sqrt(x)
}

/// `math.Pow(x, y) float64`.
pub fn Pow(x: f64, y: f64) -> f64 {
    // Go: math/pow.go:63 — ported verbatim. libm::pow (musl/fdlibm)
    // differs from Go by up to 1 ULP on integer exponents, e.g.
    // Pow(7, -2) yields 0.020408163265306124 there and
    // 0.02040816326530612 here (and in Go). Callers that compare
    // against Go output — typescript-go's jsnum.Exponentiate, which
    // feeds JS number formatting — see the difference.
    match () {
        _ if y == 0.0 || x == 1.0 => return 1.0,
        _ if y == 1.0 => return x,
        _ if IsNaN(x) || IsNaN(y) => return NaN(),
        _ if x == 0.0 => {
            if y < 0.0 {
                if Signbit(x) && isOddInt(y) {
                    return Inf(-1);
                }
                return Inf(1);
            }
            if y > 0.0 {
                if Signbit(x) && isOddInt(y) {
                    return x;
                }
                return 0.0;
            }
        }
        _ if IsInf(y, 0) => {
            if x == -1.0 {
                return 1.0;
            }
            if (Abs(x) < 1.0) == IsInf(y, 1) {
                return 0.0;
            }
            return Inf(1);
        }
        _ if IsInf(x, 0) => {
            if IsInf(x, -1) {
                return Pow(1.0 / x, -y); // Pow(-0, -y)
            }
            if y < 0.0 {
                return 0.0;
            }
            if y > 0.0 {
                return Inf(1);
            }
        }
        _ if y == 0.5 => return Sqrt(x),
        _ if y == -0.5 => return 1.0 / Sqrt(x),
        _ => {}
    }

    let (mut yi, mut yf) = Modf(Abs(y));
    if yf != 0.0 && x < 0.0 {
        return NaN();
    }
    if yi >= 9223372036854775808.0 {
        // 1<<63
        // yi is a large even int that will lead to overflow (or underflow to 0)
        // for all x except -1 (x == 1 was handled earlier)
        if x == -1.0 {
            return 1.0;
        }
        if (Abs(x) < 1.0) == (y > 0.0) {
            return 0.0;
        }
        return Inf(1);
    }

    // ans = a1 * 2**ae (= 1 for now).
    let mut a1 = 1.0_f64;
    // Go's `ae int` is 64-bit on the platforms goish targets.
    let mut ae: crate::types::int = 0;

    // ans *= x**yf
    if yf != 0.0 {
        if yf > 0.5 {
            yf -= 1.0;
            yi += 1.0;
        }
        a1 = Exp(yf * Log(x));
    }

    // ans *= x**yi
    // by multiplying in successive squarings
    // of x according to bits of yi.
    // accumulate powers of two into exp.
    let (mut x1, mut xe) = Frexp(x);
    let mut i = yi as i64;
    while i != 0 {
        if xe < -(1 << 12) || (1 << 12) < xe {
            // catch xe before it overflows the left shift below
            // Since i !=0 it has at least one bit still set, so ae will accumulate xe
            // on at least one more iteration, ae += xe is a lower bound on ae
            // the lower bound on ae exceeds the size of a float64 exp
            // so the final call to Ldexp will produce under/overflow (0/Inf)
            ae += xe;
            break;
        }
        if i & 1 == 1 {
            a1 *= x1;
            ae += xe;
        }
        x1 *= x1;
        xe <<= 1;
        if x1 < 0.5 {
            x1 += x1;
            xe -= 1;
        }
        i >>= 1;
    }

    // ans = a1*2**ae
    // if y < 0 { ans = 1 / ans }
    // but in the opposite order
    if y < 0.0 {
        a1 = 1.0 / a1;
        ae = -ae;
    }
    Ldexp(a1, ae)
}

/// `math.isOddInt(x)` (pow.go:7).
#[allow(non_snake_case)]
fn isOddInt(x: f64) -> bool {
    if Abs(x) >= 9007199254740992.0 {
        // 1 << 53 is the largest exact integer in the float64 format.
        // Any number outside this range will be truncated before the decimal point and therefore will always be
        // an even integer.
        return false;
    }
    let (xi, xf) = Modf(x);
    xf == 0.0 && (xi as i64) & 1 == 1
}

const _MATH_SHIFT: u64 = 64 - 11 - 1;
const _MATH_MASK: u64 = 0x7FF;
const _MATH_BIAS: i64 = 1023;

/// `math.normalize(x)` (bits.go:44).
#[allow(non_snake_case)]
fn normalize(x: f64) -> (f64, crate::types::int) {
    const SMALLEST_NORMAL: f64 = 2.2250738585072014e-308; // 2**-1022
    if Abs(x) < SMALLEST_NORMAL {
        return (x * ((1u64 << 52) as f64), -52);
    }
    (x, 0)
}

/// `math.Frexp(f) (frac float64, exp int)` (frexp.go:15) — breaks f into
/// a normalized fraction and an integral power of two, such that
/// `f == frac x 2**exp` with `|frac|` in [1/2, 1).
#[allow(non_snake_case)]
pub fn Frexp(f: f64) -> (f64, crate::types::int) {
    // special cases
    if f == 0.0 {
        return (f, 0); // correctly return -0
    }
    if IsInf(f, 0) || IsNaN(f) {
        return (f, 0);
    }
    let (f, mut exp) = normalize(f);
    let mut x = Float64bits(f);
    exp += ((x >> _MATH_SHIFT) & _MATH_MASK) as crate::types::int - _MATH_BIAS as crate::types::int
        + 1;
    x &= !(_MATH_MASK << _MATH_SHIFT);
    x |= ((-1 + _MATH_BIAS) as u64) << _MATH_SHIFT;
    (Float64frombits(x), exp)
}

/// `math.Ldexp(frac, exp) float64` (ldexp.go:12) — the inverse of
/// [`Frexp`]: returns `frac x 2**exp`.
#[allow(non_snake_case)]
pub fn Ldexp(frac: f64, exp: crate::types::int) -> f64 {
    // special cases
    if frac == 0.0 {
        return frac; // correctly return -0
    }
    if IsInf(frac, 0) || IsNaN(frac) {
        return frac;
    }
    let (frac, e) = normalize(frac);
    let mut exp = exp + e;
    let mut x = Float64bits(frac);
    // Go: `exp += int(x>>shift)&mask - bias` — Go's `&` binds tighter
    // than `-`, Rust's binds looser, so the parens are load-bearing.
    exp += (((x >> _MATH_SHIFT) as crate::types::int) & (_MATH_MASK as crate::types::int))
        - _MATH_BIAS as crate::types::int;
    if exp < -1075 {
        return Copysign(0.0, frac); // underflow
    }
    if exp > 1023 {
        // overflow
        if frac < 0.0 {
            return Inf(-1);
        }
        return Inf(1);
    }
    let mut m = 1.0_f64;
    if exp < -1022 {
        // denormal
        exp += 53;
        m = 1.0 / ((1u64 << 53) as f64); // 2**-53
    }
    x &= !(_MATH_MASK << _MATH_SHIFT);
    x |= ((exp + _MATH_BIAS as crate::types::int) as u64) << _MATH_SHIFT;
    m * Float64frombits(x)
}

/// `math.Pow10(n int) float64`.
pub fn Pow10(n: crate::types::int) -> f64 {
    libm::pow(10.0_f64, n as f64)
}

/// `math.Mod(x, y) float64` — IEEE remainder, same sign as x.
pub fn Mod(x: f64, y: f64) -> f64 {
    libm::fmod(x, y)
}

/// `math.Modf(f) (int float64, frac float64)` — splits `f` into integer
/// and fractional parts, each with the same sign as `f`. NaN propagates
/// to both halves; ±Inf returns (±Inf, NaN) per Go's `math/modf.go`.
pub fn Modf(f: f64) -> (f64, f64) {
    if f.is_nan() {
        return (f, f);
    }
    if f.is_infinite() {
        return (f, f64::NAN);
    }
    let i = libm::trunc(f);
    // Go computes the negative case as `int, frac = Modf(-f); return
    // -int, -frac`, so the fractional part carries the sign of the
    // INPUT: Modf(-1) is (-1, -0) and Modf(-0) is (-0, -0). `f - i` is
    // +0 for both, which is what goish returned — a signed zero that
    // survives into Copysign, Signbit and the wire format of any
    // encoder that stores the bit pattern.
    let frac = Copysign(f - i, f);
    return (i, frac);
}

/// `math.Copysign(magnitude, sign) float64` — returns a value with the
/// magnitude of `magnitude` and the sign of `sign`. Mirrors Go's
/// `math.Copysign` semantics including signed zeros and NaN sign.
pub fn Copysign(magnitude: f64, sign: f64) -> f64 {
    libm::copysign(magnitude, sign)
}

/// `math.Remainder(x, y) float64` — IEEE 754 remainder.
pub fn Remainder(x: f64, y: f64) -> f64 {
    libm::remainder(x, y)
}

/// `math.Dim(x, y) float64` — Go: "the maximum of x-y or 0."
///
/// Go's special cases are:
///
///     Dim(+Inf, +Inf) = NaN
///     Dim(-Inf, -Inf) = NaN
///     Dim(x, NaN) = Dim(NaN, y) = NaN
///
/// and it reaches all four with ONE test. Go's comment: "The special
/// cases result in NaN after the subtraction … v := x - y; if v <= 0 {
/// return 0 }; return v" — `v <= 0` is false for a NaN, so the NaN
/// falls through and is returned.
///
/// goish tested `d > 0.0` instead, which is ALSO false for a NaN, so
/// every one of those four cases returned 0. `Dim(+Inf, +Inf)` is the
/// one a caller is most likely to hit, and 0 is a plausible-looking
/// answer for it.
pub fn Dim(x: f64, y: f64) -> f64 {
    // Go: v := x - y; if v <= 0 { return 0 }; return v
    let v = x - y;
    if v <= 0.0 {
        return 0.0;
    }
    return v;
}

/// `math.Max(x, y) float64` — Go: "the larger of x or y."
///
/// The order of Go's switch is the whole content of this function:
///
///     Max(x, +Inf) = Max(+Inf, y) = +Inf
///     Max(x, NaN)  = Max(NaN, y)  = NaN
///     Max(+0, ±0)  = Max(±0, +0)  = +0
///     Max(-0, -0)  = -0
///
/// +Inf is tested FIRST, so `Max(+Inf, NaN)` is +Inf and not NaN.
/// goish tested NaN first and answered NaN, and had no zero case at all
/// — its doc comment claimed "+0 > -0" while `x > y` is false for that
/// pair, so `Max(+0, -0)` returned -0.
pub fn Max(x: f64, y: f64) -> f64 {
    // Go: case IsInf(x, 1) || IsInf(y, 1): return Inf(1)
    if IsInf(x, 1) || IsInf(y, 1) {
        return Inf(1);
    }
    // Go: case IsNaN(x) || IsNaN(y): return NaN()
    if x.is_nan() || y.is_nan() {
        return f64::NAN;
    }
    // Go: case x == 0 && x == y: if Signbit(x) { return y }; return x
    if x == 0.0 && x == y {
        if Signbit(x) {
            return y;
        }
        return x;
    }
    if x > y {
        return x;
    }
    return y;
}

/// `math.Min(x, y) float64` — Go: "the smaller of x or y."
///
///     Min(x, -Inf) = Min(-Inf, y) = -Inf
///     Min(x, NaN)  = Min(NaN, y)  = NaN
///     Min(-0, ±0)  = Min(±0, -0)  = -0
///
/// The mirror of [`Max`]; see the note there for what goish had.
pub fn Min(x: f64, y: f64) -> f64 {
    // Go: case IsInf(x, -1) || IsInf(y, -1): return Inf(-1)
    if IsInf(x, -1) || IsInf(y, -1) {
        return Inf(-1);
    }
    if x.is_nan() || y.is_nan() {
        return f64::NAN;
    }
    // Go: case x == 0 && x == y: if Signbit(x) { return x }; return y
    if x == 0.0 && x == y {
        if Signbit(x) {
            return x;
        }
        return y;
    }
    if x < y {
        return x;
    }
    return y;
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

// ─── Functions goish did not have ───────────────────────────────────
//
// Found by diffing this package against a running Go (see
// examples/math_ref_smoke.rs): each of these is a documented Go
// function with no counterpart here. Like the rest of this file they
// are UNANCHORED — src/math/mod.rs is one .rs for 61 .go files, and
// giving it a manifest would demand that split — so they carry the
// same status as their neighbours and the same reference smoke,
// examples/math2_ref_smoke.rs, establishes they agree with Go.

// go: sdk 1.25.5 math/cbrt.go:26-31 Cbrt
/// `math.Cbrt(x) float64` — the cube root. Go: "Cbrt(±0) = ±0,
/// Cbrt(±Inf) = ±Inf, Cbrt(NaN) = NaN."
pub fn Cbrt(x: f64) -> f64 {
    return libm::cbrt(x);
}

// go: sdk 1.25.5 math/expm1.go:126-131 Expm1
/// `math.Expm1(x) float64` — e**x - 1, accurate for tiny x where
/// `Exp(x) - 1` would lose every significant digit to cancellation.
/// Go: "Expm1(+Inf) = +Inf, Expm1(-Inf) = -1, Expm1(NaN) = NaN."
pub fn Expm1(x: f64) -> f64 {
    return libm::expm1(x);
}

// go: sdk 1.25.5 math/log1p.go:96-101 Log1p
/// `math.Log1p(x) float64` — log(1 + x), accurate for tiny x for the
/// same reason. Go: "Log1p(-1) = -Inf, Log1p(x < -1) = NaN."
pub fn Log1p(x: f64) -> f64 {
    return libm::log1p(x);
}

// go: sdk 1.25.5 math/erf.go:189-194 Erf
/// `math.Erf(x) float64` — the error function.
pub fn Erf(x: f64) -> f64 {
    return libm::erf(x);
}

// go: sdk 1.25.5 math/erf.go:274-279 Erfc
/// `math.Erfc(x) float64` — the complementary error function, 1 - Erf(x),
/// computed directly because the subtraction loses precision in the tail.
pub fn Erfc(x: f64) -> f64 {
    return libm::erfc(x);
}

// go: sdk 1.25.5 math/gamma.go:131-214 Gamma
/// `math.Gamma(x) float64` — the gamma function. Go: "Gamma(+Inf) =
/// +Inf, Gamma(+0) = +Inf, Gamma(-0) = -Inf, Gamma(x) = NaN for
/// integer x < 0, Gamma(-Inf) = NaN, Gamma(NaN) = NaN."
pub fn Gamma(x: f64) -> f64 {
    return libm::tgamma(x);
}

// go: sdk 1.25.5 math/lgamma.go:175-322 Lgamma
/// `math.Lgamma(x) (lgamma float64, sign int)` — the natural logarithm
/// and SIGN of Gamma(x). The sign is returned separately because the
/// logarithm cannot carry it.
pub fn Lgamma(x: f64) -> (f64, crate::types::int) {
    let (v, sign) = libm::lgamma_r(x);
    return (v, crate::int64(sign));
}

// go: sdk 1.25.5 math/logb.go:14-28 Logb
/// `math.Logb(x) float64` — the binary exponent of x, as a float.
/// Go: "Logb(±Inf) = +Inf, Logb(0) = -Inf, Logb(NaN) = NaN."
pub fn Logb(x: f64) -> f64 {
    if x == 0.0 {
        return f64::NEG_INFINITY;
    }
    if x.is_infinite() {
        return f64::INFINITY;
    }
    if x.is_nan() {
        return x;
    }
    return crate::float64(__ilogb(x));
}

// go: sdk 1.25.5 math/logb.go:34-48 Ilogb
/// `math.Ilogb(x) int` — the binary exponent of x, as an int.
/// Go: "Ilogb(±Inf) = MaxInt32, Ilogb(0) = MinInt32, Ilogb(NaN) =
/// MaxInt32." Those three are sentinels, not errors, and a caller that
/// forgets them reads a wildly wrong exponent.
pub fn Ilogb(x: f64) -> crate::types::int {
    if x == 0.0 {
        return crate::int64(i32::MIN);
    }
    if x.is_nan() || x.is_infinite() {
        return crate::int64(i32::MAX);
    }
    return __ilogb(x);
}

// go: none — goish idiom: Go's `ilogb` is the unexported worker both
//     `Logb` and `Ilogb` call after their own special cases.
fn __ilogb(x: f64) -> crate::types::int {
    // Go: normalize, then read the exponent field.
    let (frac, exp) = __normalize(x);
    return crate::int64((frac.to_bits() >> 52) & 0x7ff) - 1023 + exp;
}

// go: none — goish idiom: Go's `normalize` scales a subnormal into the
//     normal range and reports how far it moved.
fn __normalize(x: f64) -> (f64, crate::types::int) {
    // Go: SmallestNormal = 2**-1022
    const SMALLEST_NORMAL: f64 = 2.2250738585072014e-308;
    if Abs(x) < SMALLEST_NORMAL {
        // Go: x * (1 << 52), exp = -52
        return (x * 4503599627370496.0, -52);
    }
    return (x, 0);
}

// go: sdk 1.25.5 math/floor.go:121-151 RoundToEven
/// `math.RoundToEven(x) float64` — round half to EVEN, which is what
/// IEEE-754 arithmetic itself does. `Round` rounds half away from zero,
/// so the two disagree on exactly the halves: Round(2.5) is 3 and
/// RoundToEven(2.5) is 2.
pub fn RoundToEven(x: f64) -> f64 {
    if x.is_nan() || x.is_infinite() {
        return x;
    }
    // Go: "RoundToEven returns the nearest integer, rounding ties to
    // even." `no_std` has no `round_ties_even`, so this is the
    // floor/ceil pair with the tie broken toward the even one.
    let f = Floor(x);
    let diff = x - f;
    let r = if diff > 0.5 {
        f + 1.0
    } else if diff < 0.5 {
        f
    } else if Mod(f, 2.0) == 0.0 {
        f
    } else {
        f + 1.0
    };
    // Go keeps the sign of a zero result — RoundToEven(-0.5) is -0,
    // not +0 — and the arithmetic above loses it.
    if r == 0.0 {
        return Copysign(0.0, x);
    }
    return r;
}

// go: sdk 1.25.5 math/sincos.go:16-73 Sincos
/// `math.Sincos(x) (sin, cos float64)` — both at once, which is what
/// the underlying argument reduction produces anyway.
pub fn Sincos(x: f64) -> (f64, f64) {
    return (Sin(x), Cos(x));
}

// go: sdk 1.25.5 math/nextafter.go:37-55 Nextafter
/// `math.Nextafter(x, y) float64` — the next representable float64
/// after x in the direction of y. Go: "Nextafter(x, x) = x."
pub fn Nextafter(x: f64, y: f64) -> f64 {
    if x.is_nan() || y.is_nan() {
        return f64::NAN;
    }
    if x == y {
        return x;
    }
    if x == 0.0 {
        return Copysign(f64::from_bits(1), y);
    }
    // Go: walk the bit pattern one step, which is what makes the
    // spacing follow the exponent.
    let mut b = x.to_bits();
    if (y > x) == (x > 0.0) {
        b += 1;
    } else {
        b -= 1;
    }
    return f64::from_bits(b);
}

// go: sdk 1.25.5 math/nextafter.go:14-32 Nextafter32
/// `math.Nextafter32(x, y) float32` — as `Nextafter`, in float32.
pub fn Nextafter32(x: f32, y: f32) -> f32 {
    if x.is_nan() || y.is_nan() {
        return f32::NAN;
    }
    if x == y {
        return x;
    }
    if x == 0.0 {
        return crate::float32(Copysign(
            crate::float64(f32::from_bits(1)),
            crate::float64(y),
        ));
    }
    let mut b = x.to_bits();
    if (y > x) == (x > 0.0) {
        b += 1;
    } else {
        b -= 1;
    }
    return f32::from_bits(b);
}

// go: sdk 1.25.5 math/fma.go:95-182 FMA
/// `math.FMA(x, y, z) float64` — x*y+z computed with a SINGLE rounding.
/// That is the point: the intermediate product is not rounded, so the
/// result can differ from `x*y + z` written out.
pub fn FMA(x: f64, y: f64, z: f64) -> f64 {
    return libm::fma(x, y, z);
}

// go: sdk 1.25.5 math/j0.go:77-146 J0
/// `math.J0(x) float64` — the order-zero Bessel function of the first kind.
pub fn J0(x: f64) -> f64 {
    return libm::j0(x);
}

// go: sdk 1.25.5 math/j1.go:75-146 J1
/// `math.J1(x) float64` — order one, first kind.
pub fn J1(x: f64) -> f64 {
    return libm::j1(x);
}

// go: sdk 1.25.5 math/jn.go:54-224 Jn
/// `math.Jn(n, x) float64` — order n, first kind.
pub fn Jn(n: crate::types::int, x: f64) -> f64 {
    return libm::jn(crate::int32(n), x);
}

// go: sdk 1.25.5 math/j0.go:156-228 Y0
/// `math.Y0(x) float64` — order zero, SECOND kind. Go: "Y0(x < 0) =
/// NaN, Y0(0) = -Inf."
pub fn Y0(x: f64) -> f64 {
    return libm::y0(x);
}

// go: sdk 1.25.5 math/j1.go:156-223 Y1
/// `math.Y1(x) float64` — order one, second kind.
pub fn Y1(x: f64) -> f64 {
    return libm::y1(x);
}

// go: sdk 1.25.5 math/jn.go:235-306 Yn
/// `math.Yn(n, x) float64` — order n, second kind.
pub fn Yn(n: crate::types::int, x: f64) -> f64 {
    return libm::yn(crate::int32(n), x);
}
