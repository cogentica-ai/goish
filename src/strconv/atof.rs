// Decimal-to-binary floating point conversion — port of Go 1.25
// src/strconv/atof.go (slow path).
//
// Algorithm:
//   1) Store input in multiprecision decimal.
//   2) Multiply/divide decimal by powers of two until in range [0.5, 1).
//   3) Multiply by 2^precision and round to get mantissa.
//
// Skips Eisel-Lemire fast path (M11b-C) — slow path produces identical
// output. `optimize` is wired to false here so atof32/atof64 always
// take the slow path.

#![allow(non_snake_case, non_camel_case_types)]

use crate::errors::{error, nil};
use crate::gostring::string;
use crate::types::int;

use super::decimal::decimal;
use super::{rangeError, syntaxError};

const FN_PARSE_FLOAT: &str = "ParseFloat";

#[derive(Clone, Copy)]
pub(crate) struct floatInfo {
    pub mantbits: u32,
    pub expbits: u32,
    pub bias: i32,
}

pub(crate) const FLOAT32_INFO: floatInfo = floatInfo {
    mantbits: 23,
    expbits: 8,
    bias: -127,
};
pub(crate) const FLOAT64_INFO: floatInfo = floatInfo {
    mantbits: 52,
    expbits: 11,
    bias: -1023,
};

#[inline]
fn lower(c: u8) -> u8 {
    c | (b'x' - b'X')
}

fn common_prefix_len_ignore_case(s: &[u8], prefix: &[u8]) -> usize {
    let n = core::cmp::min(prefix.len(), s.len());
    for i in 0..n {
        let mut c = s[i];
        if c >= b'A' && c <= b'Z' {
            c += b'a' - b'A';
        }
        if c != prefix[i] {
            return i;
        }
    }
    n
}

fn special(s: &[u8]) -> (f64, usize, bool) {
    if s.is_empty() {
        return (0.0, 0, false);
    }
    let mut sign = 1.0_f64;
    let mut nsign: usize = 0;
    let mut sub = s;
    let first = sub[0];
    if first == b'+' || first == b'-' {
        if first == b'-' {
            sign = -1.0;
        }
        nsign = 1;
        sub = &sub[1..];
    }
    if sub.is_empty() {
        return (0.0, 0, false);
    }
    let lead = sub[0];
    if lead == b'i' || lead == b'I' {
        let n = common_prefix_len_ignore_case(sub, b"infinity");
        let n = if 3 < n && n < 8 { 3 } else { n };
        if n == 3 || n == 8 {
            return (sign * f64::INFINITY, nsign + n, true);
        }
        return (0.0, 0, false);
    }
    if (lead == b'n' || lead == b'N') && nsign == 0 {
        // NaN doesn't accept +/- prefix in Go.
        if common_prefix_len_ignore_case(sub, b"nan") == 3 {
            return (f64::NAN, 3, true);
        }
    }
    (0.0, 0, false)
}

/// readFloat — parses a decimal/hex mantissa+exponent prefix of `s`.
/// Returns (mantissa, exp, neg, trunc, hex, i, ok). `i` is bytes consumed.
fn read_float(s: &[u8]) -> (u64, i32, bool, bool, bool, usize, bool) {
    let mut underscores = false;
    let mut i: usize = 0;
    let mut neg = false;
    let mut mantissa: u64 = 0;
    let mut trunc = false;
    let mut hex = false;

    if i >= s.len() {
        return (0, 0, false, false, false, 0, false);
    }
    match s[i] {
        b'+' => i += 1,
        b'-' => {
            i += 1;
            neg = true;
        }
        _ => {}
    }

    let mut base: u64 = 10;
    let mut max_mant_digits: i32 = 19;
    let mut exp_char: u8 = b'e';
    if i + 2 < s.len() && s[i] == b'0' && lower(s[i + 1]) == b'x' {
        base = 16;
        max_mant_digits = 16;
        i += 2;
        exp_char = b'p';
        hex = true;
    }

    let mut sawdot = false;
    let mut sawdigits = false;
    let mut nd: i32 = 0;
    let mut nd_mant: i32 = 0;
    let mut dp: i32 = 0;

    while i < s.len() {
        let c = s[i];
        if c == b'_' {
            underscores = true;
            i += 1;
            continue;
        }
        if c == b'.' {
            if sawdot {
                break;
            }
            sawdot = true;
            dp = nd;
            i += 1;
            continue;
        }
        if c >= b'0' && c <= b'9' {
            sawdigits = true;
            if c == b'0' && nd == 0 {
                dp -= 1;
                i += 1;
                continue;
            }
            nd += 1;
            if nd_mant < max_mant_digits {
                mantissa = mantissa.wrapping_mul(base);
                mantissa = mantissa.wrapping_add((c - b'0') as u64);
                nd_mant += 1;
            } else if c != b'0' {
                trunc = true;
            }
            i += 1;
            continue;
        }
        if base == 16 && lower(c) >= b'a' && lower(c) <= b'f' {
            sawdigits = true;
            nd += 1;
            if nd_mant < max_mant_digits {
                mantissa = mantissa.wrapping_mul(16);
                mantissa = mantissa.wrapping_add((lower(c) - b'a' + 10) as u64);
                nd_mant += 1;
            } else {
                trunc = true;
            }
            i += 1;
            continue;
        }
        break;
    }

    if !sawdigits {
        return (0, 0, neg, false, false, i, false);
    }
    if !sawdot {
        dp = nd;
    }
    if base == 16 {
        dp *= 4;
        nd_mant *= 4;
    }

    // optional exponent
    if i < s.len() && lower(s[i]) == exp_char {
        i += 1;
        if i >= s.len() {
            return (0, 0, neg, false, false, i, false);
        }
        let mut esign: i32 = 1;
        match s[i] {
            b'+' => i += 1,
            b'-' => {
                i += 1;
                esign = -1;
            }
            _ => {}
        }
        if i >= s.len() || s[i] < b'0' || s[i] > b'9' {
            return (0, 0, neg, false, false, i, false);
        }
        let mut e: i32 = 0;
        while i < s.len() && ((s[i] >= b'0' && s[i] <= b'9') || s[i] == b'_') {
            if s[i] == b'_' {
                underscores = true;
                i += 1;
                continue;
            }
            if e < 10000 {
                e = e * 10 + (s[i] - b'0') as i32;
            }
            i += 1;
        }
        dp += e * esign;
    } else if base == 16 {
        // Hex float must have exponent.
        return (0, 0, neg, false, false, i, false);
    }

    let exp = if mantissa != 0 { dp - nd_mant } else { 0 };

    if underscores && !super::underscoreOK(&s[..i]) {
        return (0, 0, neg, false, false, i, false);
    }

    (mantissa, exp, neg, trunc, hex, i, true)
}

// Decimal → multiprecision-decimal `set`. Mirrors `(b *decimal) set(s)`.
fn decimal_set(b: &mut decimal, s: &[u8]) -> bool {
    let mut i: usize = 0;
    b.neg = false;
    b.trunc = false;

    if i >= s.len() {
        return false;
    }
    match s[i] {
        b'+' => i += 1,
        b'-' => {
            i += 1;
            b.neg = true;
        }
        _ => {}
    }

    let mut sawdot = false;
    let mut sawdigits = false;
    while i < s.len() {
        let c = s[i];
        if c == b'_' {
            i += 1;
            continue;
        }
        if c == b'.' {
            if sawdot {
                return false;
            }
            sawdot = true;
            b.dp = b.nd;
            i += 1;
            continue;
        }
        if c >= b'0' && c <= b'9' {
            sawdigits = true;
            if c == b'0' && b.nd == 0 {
                b.dp -= 1;
                i += 1;
                continue;
            }
            if (b.nd as usize) < b.d.len() {
                b.d[b.nd as usize] = c;
                b.nd += 1;
            } else if c != b'0' {
                b.trunc = true;
            }
            i += 1;
            continue;
        }
        break;
    }
    if !sawdigits {
        return false;
    }
    if !sawdot {
        b.dp = b.nd;
    }

    // optional exponent
    if i < s.len() && lower(s[i]) == b'e' {
        i += 1;
        if i >= s.len() {
            return false;
        }
        let mut esign: i32 = 1;
        match s[i] {
            b'+' => i += 1,
            b'-' => {
                i += 1;
                esign = -1;
            }
            _ => {}
        }
        if i >= s.len() || s[i] < b'0' || s[i] > b'9' {
            return false;
        }
        let mut e: i32 = 0;
        while i < s.len() && ((s[i] >= b'0' && s[i] <= b'9') || s[i] == b'_') {
            if s[i] == b'_' {
                i += 1;
                continue;
            }
            if e < 10000 {
                e = e * 10 + (s[i] - b'0') as i32;
            }
            i += 1;
        }
        b.dp += e * esign;
    }

    if i != s.len() {
        return false;
    }
    true
}

const POWTAB: &[i32] = &[1, 3, 6, 9, 13, 16, 19, 23, 26];

/// `(d *decimal) floatBits(flt *floatInfo)` — convert decimal to IEEE bits.
fn decimal_float_bits(d: &mut decimal, flt: &floatInfo) -> (u64, bool) {
    let mut exp: i32;
    let mut mant: u64;
    let mut overflow = false;

    if d.nd == 0 {
        mant = 0;
        exp = flt.bias;
    } else if d.dp > 310 {
        // overflow
        mant = 0;
        exp = (1i32 << flt.expbits) - 1 + flt.bias;
        overflow = true;
        return assemble(d.neg, mant, exp, flt, overflow);
    } else if d.dp < -330 {
        // zero
        mant = 0;
        exp = flt.bias;
    } else {
        // Scale by powers of two until in range [0.5, 1.0).
        exp = 0;
        while d.dp > 0 {
            let n: i32 = if d.dp >= POWTAB.len() as i32 {
                27
            } else {
                POWTAB[d.dp as usize]
            };
            d.Shift(-n);
            exp += n;
        }
        while d.dp < 0 || (d.dp == 0 && d.d[0] < b'5') {
            let n: i32 = if -d.dp >= POWTAB.len() as i32 {
                27
            } else {
                POWTAB[(-d.dp) as usize]
            };
            d.Shift(n);
            exp -= n;
        }

        // Our range is [0.5, 1) but floating point range is [1, 2).
        exp -= 1;

        // Minimum representable exponent is flt.bias + 1.
        if exp < flt.bias + 1 {
            let n = flt.bias + 1 - exp;
            d.Shift(-n);
            exp += n;
        }

        if exp - flt.bias >= (1i32 << flt.expbits) - 1 {
            mant = 0;
            exp = (1i32 << flt.expbits) - 1 + flt.bias;
            overflow = true;
            return assemble(d.neg, mant, exp, flt, overflow);
        }

        // Extract 1+flt.mantbits bits.
        d.Shift((1 + flt.mantbits) as i32);
        mant = d.RoundedInteger();

        // Rounding might have added a bit; shift down.
        if mant == 2u64 << flt.mantbits {
            mant >>= 1;
            exp += 1;
            if exp - flt.bias >= (1i32 << flt.expbits) - 1 {
                mant = 0;
                exp = (1i32 << flt.expbits) - 1 + flt.bias;
                overflow = true;
                return assemble(d.neg, mant, exp, flt, overflow);
            }
        }

        // Denormalized?
        if (mant & (1u64 << flt.mantbits)) == 0 {
            exp = flt.bias;
        }
    }

    assemble(d.neg, mant, exp, flt, overflow)
}

fn assemble(neg: bool, mant: u64, exp: i32, flt: &floatInfo, overflow: bool) -> (u64, bool) {
    let mut bits = mant & ((1u64 << flt.mantbits) - 1);
    bits |= ((exp - flt.bias) as u64 & ((1u64 << flt.expbits) - 1)) << flt.mantbits;
    if neg {
        bits |= 1u64 << flt.mantbits << flt.expbits;
    }
    (bits, overflow)
}

/// Exact powers of 10 (f64).
const FLOAT64_POW10: &[f64] = &[
    1e0, 1e1, 1e2, 1e3, 1e4, 1e5, 1e6, 1e7, 1e8, 1e9, 1e10, 1e11, 1e12, 1e13, 1e14, 1e15, 1e16,
    1e17, 1e18, 1e19, 1e20, 1e21, 1e22,
];
const FLOAT32_POW10: &[f32] = &[1e0, 1e1, 1e2, 1e3, 1e4, 1e5, 1e6, 1e7, 1e8, 1e9, 1e10];

/// Try exact conversion via plain floating-point math. Three common cases:
///   - exact integer
///   - exact integer * exact power of 10
///   - exact integer / exact power of 10
fn atof64_exact(mantissa: u64, exp: i32, neg: bool) -> (f64, bool) {
    if (mantissa >> FLOAT64_INFO.mantbits) != 0 {
        return (0.0, false);
    }
    let mut f = mantissa as f64;
    if neg {
        f = -f;
    }
    if exp == 0 {
        return (f, true);
    }
    if exp > 0 && exp <= 15 + 22 {
        let mut exp = exp;
        if exp > 22 {
            f *= FLOAT64_POW10[(exp - 22) as usize];
            exp = 22;
        }
        if f > 1e15 || f < -1e15 {
            return (0.0, false);
        }
        return (f * FLOAT64_POW10[exp as usize], true);
    }
    if exp < 0 && exp >= -22 {
        return (f / FLOAT64_POW10[(-exp) as usize], true);
    }
    (0.0, false)
}

fn atof32_exact(mantissa: u64, exp: i32, neg: bool) -> (f32, bool) {
    if (mantissa >> FLOAT32_INFO.mantbits) != 0 {
        return (0.0, false);
    }
    let mut f = mantissa as f32;
    if neg {
        f = -f;
    }
    if exp == 0 {
        return (f, true);
    }
    if exp > 0 && exp <= 7 + 10 {
        let mut exp = exp;
        if exp > 10 {
            f *= FLOAT32_POW10[(exp - 10) as usize];
            exp = 10;
        }
        if f > 1e7 || f < -1e7 {
            return (0.0, false);
        }
        return (f * FLOAT32_POW10[exp as usize], true);
    }
    if exp < 0 && exp >= -10 {
        return (f / FLOAT32_POW10[(-exp) as usize], true);
    }
    (0.0, false)
}

fn atof_hex(
    s: string,
    flt: &floatInfo,
    mut mantissa: u64,
    mut exp: i32,
    neg: bool,
    trunc: bool,
) -> (f64, error) {
    let max_exp = (1i32 << flt.expbits) + flt.bias - 2;
    let min_exp = flt.bias + 1;
    exp += flt.mantbits as i32;

    while mantissa != 0 && (mantissa >> (flt.mantbits + 2)) == 0 {
        mantissa <<= 1;
        exp -= 1;
    }
    if trunc {
        mantissa |= 1;
    }
    while (mantissa >> (1 + flt.mantbits + 2)) != 0 {
        mantissa = (mantissa >> 1) | (mantissa & 1);
        exp += 1;
    }

    while mantissa > 1 && exp < min_exp - 2 {
        mantissa = (mantissa >> 1) | (mantissa & 1);
        exp += 1;
    }

    let round = mantissa & 3;
    mantissa >>= 2;
    let round = round | (mantissa & 1);
    exp += 2;
    let mut mantissa = mantissa;
    if round == 3 {
        mantissa += 1;
        if mantissa == (1u64 << (1 + flt.mantbits)) {
            mantissa >>= 1;
            exp += 1;
        }
    }

    if (mantissa >> flt.mantbits) == 0 {
        exp = flt.bias;
    }
    let mut err: error = nil;
    let mut mant = mantissa;
    if exp > max_exp {
        mant = 1u64 << flt.mantbits;
        exp = max_exp + 1;
        err = rangeError(FN_PARSE_FLOAT, s.clone());
    }

    let mut bits = mant & ((1u64 << flt.mantbits) - 1);
    bits |= ((exp - flt.bias) as u64 & ((1u64 << flt.expbits) - 1)) << flt.mantbits;
    if neg {
        bits |= 1u64 << flt.mantbits << flt.expbits;
    }
    let f = if flt.expbits == 8 {
        f32::from_bits(bits as u32) as f64
    } else {
        f64::from_bits(bits)
    };
    (f, err)
}

pub(crate) fn atof64(s: &[u8], orig: &string) -> (f64, usize, error) {
    let (val, n, ok) = special(s);
    if ok {
        return (val, n, nil);
    }
    let (mantissa, exp, neg, trunc, hex, n, ok) = read_float(s);
    if !ok {
        return (0.0, n, syntaxError(FN_PARSE_FLOAT, orig.clone()));
    }
    if hex {
        let prefix = string::from_bytes(&s[..n]);
        let (f, err) = atof_hex(prefix, &FLOAT64_INFO, mantissa, exp, neg, trunc);
        return (f, n, err);
    }

    // Try exact conversion via plain f64 math.
    if !trunc {
        let (f, ok) = atof64_exact(mantissa, exp, neg);
        if ok {
            return (f, n, nil);
        }
    }

    // Slow fallback via multiprecision decimal.
    let mut d = decimal::new();
    if !decimal_set(&mut d, &s[..n]) {
        return (0.0, n, syntaxError(FN_PARSE_FLOAT, orig.clone()));
    }
    let (b, ovf) = decimal_float_bits(&mut d, &FLOAT64_INFO);
    let f = f64::from_bits(b);
    let err = if ovf {
        rangeError(FN_PARSE_FLOAT, orig.clone())
    } else {
        nil
    };
    (f, n, err)
}

pub(crate) fn atof32(s: &[u8], orig: &string) -> (f32, usize, error) {
    let (val, n, ok) = special(s);
    if ok {
        return (val as f32, n, nil);
    }
    let (mantissa, exp, neg, trunc, hex, n, ok) = read_float(s);
    if !ok {
        return (0.0, n, syntaxError(FN_PARSE_FLOAT, orig.clone()));
    }
    if hex {
        let prefix = string::from_bytes(&s[..n]);
        let (f64v, err) = atof_hex(prefix, &FLOAT32_INFO, mantissa, exp, neg, trunc);
        return (f64v as f32, n, err);
    }

    if !trunc {
        let (f, ok) = atof32_exact(mantissa, exp, neg);
        if ok {
            return (f, n, nil);
        }
    }

    let mut d = decimal::new();
    if !decimal_set(&mut d, &s[..n]) {
        return (0.0, n, syntaxError(FN_PARSE_FLOAT, orig.clone()));
    }
    let (b, ovf) = decimal_float_bits(&mut d, &FLOAT32_INFO);
    let f = f32::from_bits(b as u32);
    let err = if ovf {
        rangeError(FN_PARSE_FLOAT, orig.clone())
    } else {
        nil
    };
    (f, n, err)
}

/// `strconv.ParseFloat(s, bitSize)` — full-string float parse.
pub fn ParseFloat<S: Into<string>>(s: S, bit_size: int) -> (f64, error) {
    let s = s.into();
    let bytes = s.as_bytes();
    let (f, n, err) = if bit_size == 32 {
        let (f32v, n, e) = atof32(bytes, &s);
        (f32v as f64, n, e)
    } else {
        atof64(bytes, &s)
    };

    // If we didn't consume the full input and there was no other error,
    // it's a syntax error.
    if n != bytes.len() {
        let is_syntax = err == nil
            || !crate::errors::Is(err.clone(), super::ErrRange());
        if is_syntax {
            return (0.0, syntaxError(FN_PARSE_FLOAT, s));
        }
    }
    (f, err)
}
