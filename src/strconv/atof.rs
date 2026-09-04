// go: file strconv/atof.go decls: commonPrefixLenIgnoreCase, special, readFloat, decimal.set, decimal.floatBits, atof64exact, atof32exact, atofHex, atof32, atof64, ParseFloat, parseFloatPrefix
//
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

// goishlint:ignore GOISH021 optimize — `var optimize = true` gates the
// Eisel-Lemire fast path in atof32/atof64, which this file does not
// carry: it is the slow multiprecision path only. There is nothing for
// the flag to switch off.

#![allow(non_snake_case, non_camel_case_types)]

use crate::convert::{int32 as toint32, uint32 as touint32, uint64 as touint64};
use crate::errors::{error, nil};
use crate::gostring::string;
use crate::types::int;

use super::atoi::lower;
use super::decimal::decimal;
use super::ftoa::{float32info, float64info, floatInfo};
use super::{rangeError, syntaxError};

// go: sdk 1.25.5 strconv/atof.go:563-563 fnParseFloat
const fnParseFloat: &str = "ParseFloat";

// go: sdk 1.25.5 strconv/atof.go:19-32 commonPrefixLenIgnoreCase
/// Returns the length of the common prefix of `s` and `prefix`, with
/// the character case of `s` ignored. `prefix` is ASCII lower-case.
fn commonPrefixLenIgnoreCase(s: &[u8], prefix: &[u8]) -> usize {
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
    return n;
}

// go: sdk 1.25.5 strconv/atof.go:39-69 special
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
        let n = commonPrefixLenIgnoreCase(sub, b"infinity");
        let n = if 3 < n && n < 8 { 3 } else { n };
        if n == 3 || n == 8 {
            return (sign * f64::INFINITY, nsign + n, true);
        }
        return (0.0, 0, false);
    }
    if (lead == b'n' || lead == b'N') && nsign == 0 {
        // NaN doesn't accept +/- prefix in Go.
        if commonPrefixLenIgnoreCase(sub, b"nan") == 3 {
            return (f64::NAN, 3, true);
        }
    }
    return (0.0, 0, false);
}

// go: sdk 1.25.5 strconv/atof.go:167-307 readFloat
/// Reads a decimal or hexadecimal mantissa and exponent from a float
/// string representation in `s`; the number may be followed by other
/// characters. Reports the number of bytes consumed (`i`), and whether
/// it read a number (`ok`).
fn readFloat(s: &[u8]) -> (u64, i32, bool, bool, bool, usize, bool) {
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
                mantissa = mantissa.wrapping_add(touint64(c - b'0'));
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
                mantissa = mantissa.wrapping_add(touint64(lower(c) - b'a' + 10));
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
                e = e * 10 + toint32(s[i] - b'0');
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

    return (mantissa, exp, neg, trunc, hex, i, true);
}

// go: sdk 1.25.5 strconv/atof.go:311-311 powtab
const powtab: &[i32] = &[1, 3, 6, 9, 13, 16, 19, 23, 26];

impl decimal {
    // go: sdk 1.25.5 strconv/atof.go:70-170 decimal.set
    /// Reads a decimal mantissa and exponent from a decimal string
    /// representation. The number may be followed by other characters.
    /// Reports whether it read a number.
    fn set(b: &mut decimal, s: &[u8]) -> bool {
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
                    e = e * 10 + toint32(s[i] - b'0');
                }
                i += 1;
            }
            b.dp += e * esign;
        }

        if i != s.len() {
            return false;
        }
        return true;
    }

    // go: sdk 1.25.5 strconv/atof.go:313-409 decimal.floatBits
    /// Returns the bits of the float64 or float32 (depending on `flt`)
    /// nearest `d`, and whether the value overflowed.
    fn floatBits(d: &mut decimal, flt: &floatInfo) -> (u64, bool) {
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
                let n: i32 = if d.dp >= toint32(powtab.len()) {
                    27
                } else {
                    powtab[d.dp as usize]
                };
                d.Shift(-n);
                exp += n;
            }
            while d.dp < 0 || (d.dp == 0 && d.d[0] < b'5') {
                let n: i32 = if -d.dp >= toint32(powtab.len()) {
                    27
                } else {
                    powtab[(-d.dp) as usize]
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
            d.Shift(toint32(1 + flt.mantbits));
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

        return assemble(d.neg, mant, exp, flt, overflow);
    }
}

// go: none — goish idiom: Go writes these five lines out twice, once
//     at the end of `floatBits`' normal path and once at its `out:`
//     label. A Rust `goto` does not exist, so the shared tail is a
//     function.
fn assemble(neg: bool, mant: u64, exp: i32, flt: &floatInfo, overflow: bool) -> (u64, bool) {
    let mut bits = mant & ((1u64 << flt.mantbits) - 1);
    bits |= (touint64(exp - flt.bias) & ((1u64 << flt.expbits) - 1)) << flt.mantbits;
    if neg {
        bits |= 1u64 << flt.mantbits << flt.expbits;
    }
    return (bits, overflow);
}

/// Exact powers of 10 (f64).
// go: sdk 1.25.5 strconv/atof.go:411-416 float64pow10
/// Exact powers of ten.
const float64pow10: &[f64] = &[
    1e0, 1e1, 1e2, 1e3, 1e4, 1e5, 1e6, 1e7, 1e8, 1e9, 1e10, 1e11, 1e12, 1e13, 1e14, 1e15, 1e16,
    1e17, 1e18, 1e19, 1e20, 1e21, 1e22,
];
// go: sdk 1.25.5 strconv/atof.go:417-417 float32pow10
const float32pow10: &[f32] = &[1e0, 1e1, 1e2, 1e3, 1e4, 1e5, 1e6, 1e7, 1e8, 1e9, 1e10];

// go: sdk 1.25.5 strconv/atof.go:424-458 atof64exact
/// If possible to convert decimal representation to 64-bit float `f`
/// exactly, entirely in floating-point math, do so, avoiding the
/// expense of decimalToFloatBits. Three common cases:
///
///	value is exact integer
///	value is exact integer * exact power of ten
///	value is exact integer / exact power of ten
///
/// These all produce potentially inexact but correctly rounded answers.
fn atof64exact(mantissa: u64, exp: i32, neg: bool) -> (f64, bool) {
    if (mantissa >> float64info.mantbits) != 0 {
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
            f *= float64pow10[(exp - 22) as usize];
            exp = 22;
        }
        if f > 1e15 || f < -1e15 {
            return (0.0, false);
        }
        return (f * float64pow10[exp as usize], true);
    }
    if exp < 0 && exp >= -22 {
        return (f / float64pow10[(-exp) as usize], true);
    }
    return (0.0, false);
}

// go: sdk 1.25.5 strconv/atof.go:459-491 atof32exact
/// Exactly like atof64, but for float32.
fn atof32exact(mantissa: u64, exp: i32, neg: bool) -> (f32, bool) {
    if (mantissa >> float32info.mantbits) != 0 {
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
            f *= float32pow10[(exp - 10) as usize];
            exp = 10;
        }
        if f > 1e7 || f < -1e7 {
            return (0.0, false);
        }
        return (f * float32pow10[exp as usize], true);
    }
    if exp < 0 && exp >= -10 {
        return (f / float32pow10[(-exp) as usize], true);
    }
    return (0.0, false);
}

// go: sdk 1.25.5 strconv/atof.go:493-561 atofHex
/// Converts the hex floating-point string `s` to a rounded float32 or
/// float64 value (depending on `flt`), and returns it as a float64.
/// The string `s` has already been parsed into a mantissa, exponent,
/// and sign (`neg == true` for negative), and `trunc` records whether
/// digits beyond the mantissa were discarded.
fn atofHex(
    s: string,
    flt: &floatInfo,
    mut mantissa: u64,
    mut exp: i32,
    neg: bool,
    trunc: bool,
) -> (f64, error) {
    let max_exp = (1i32 << flt.expbits) + flt.bias - 2;
    let min_exp = flt.bias + 1;
    exp += toint32(flt.mantbits);

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
        err = rangeError(fnParseFloat, s.clone());
    }

    let mut bits = mant & ((1u64 << flt.mantbits) - 1);
    bits |= (touint64(exp - flt.bias) & ((1u64 << flt.expbits) - 1)) << flt.mantbits;
    if neg {
        bits |= 1u64 << flt.mantbits << flt.expbits;
    }
    let f = if flt.expbits == 8 {
        f32::from_bits(touint32(bits)) as f64
    } else {
        f64::from_bits(bits)
    };
    return (f, err);
}

// go: sdk 1.25.5 strconv/atof.go:616-665 atof64
fn atof64(s: &string) -> (f64, usize, error) {
    let orig = s;
    let s = s.as_bytes();
    let (val, n, ok) = special(s);
    if ok {
        return (val, n, nil);
    }
    let (mantissa, exp, neg, trunc, hex, n, ok) = readFloat(s);
    if !ok {
        return (0.0, n, syntaxError(fnParseFloat, orig.clone()));
    }
    if hex {
        let prefix = string::from_bytes(&s[..n]);
        let (f, err) = atofHex(prefix, &float64info, mantissa, exp, neg, trunc);
        return (f, n, err);
    }

    // Try exact conversion via plain f64 math.
    if !trunc {
        let (f, ok) = atof64exact(mantissa, exp, neg);
        if ok {
            return (f, n, nil);
        }
    }

    // Slow fallback via multiprecision decimal.
    let mut d = decimal::new();
    if !decimal::set(&mut d, &s[..n]) {
        return (0.0, n, syntaxError(fnParseFloat, orig.clone()));
    }
    let (b, ovf) = decimal::floatBits(&mut d, &float64info);
    let f = f64::from_bits(b);
    let err = if ovf {
        rangeError(fnParseFloat, orig.clone())
    } else {
        nil
    };
    return (f, n, err);
}

// go: sdk 1.25.5 strconv/atof.go:565-614 atof32
fn atof32(s: &string) -> (f32, usize, error) {
    let orig = s;
    let s = s.as_bytes();
    let (val, n, ok) = special(s);
    if ok {
        return (val as f32, n, nil);
    }
    let (mantissa, exp, neg, trunc, hex, n, ok) = readFloat(s);
    if !ok {
        return (0.0, n, syntaxError(fnParseFloat, orig.clone()));
    }
    if hex {
        let prefix = string::from_bytes(&s[..n]);
        let (f64v, err) = atofHex(prefix, &float32info, mantissa, exp, neg, trunc);
        return (f64v as f32, n, err);
    }

    if !trunc {
        let (f, ok) = atof32exact(mantissa, exp, neg);
        if ok {
            return (f, n, nil);
        }
    }

    let mut d = decimal::new();
    if !decimal::set(&mut d, &s[..n]) {
        return (0.0, n, syntaxError(fnParseFloat, orig.clone()));
    }
    let (b, ovf) = decimal::floatBits(&mut d, &float32info);
    let f = f32::from_bits(touint32(b));
    let err = if ovf {
        rangeError(fnParseFloat, orig.clone())
    } else {
        nil
    };
    return (f, n, err);
}

// go: sdk 1.25.5 strconv/atof.go:686-700 ParseFloat
/// `strconv.ParseFloat` converts the string `s` to a floating-point
/// number with the precision specified by `bit_size`: 32 for float32
/// or 64 for float64.
pub fn ParseFloat<S: Into<string>>(s: S, bit_size: int) -> (f64, error) {
    let s = s.into();
    let (f, n, err) = parseFloatPrefix(&s, bit_size);
    if n != s.as_bytes().len() && (err == nil || !crate::errors::Is(err.clone(), super::ErrSyntax))
    {
        return (0.0, syntaxError(fnParseFloat, s));
    }
    return (f, err);
}

// go: sdk 1.25.5 strconv/atof.go:702-708 parseFloatPrefix
pub(crate) fn parseFloatPrefix(s: &string, bit_size: int) -> (f64, usize, error) {
    if bit_size == 32 {
        let (f, n, err) = atof32(s);
        return (f as f64, n, err);
    }
    return atof64(s);
}
