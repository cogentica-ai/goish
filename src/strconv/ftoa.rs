// go: file strconv/ftoa.go decls: FormatFloat, AppendFloat, genericFtoa, bigFtoa, formatDigits, roundShortest, fmtE, fmtF, fmtB, fmtX
//
// Binary-to-decimal floating-point conversion — port of Go 1.25
// src/strconv/ftoa.go (slow path).
//
// Algorithm: assign mantissa to multiprecision decimal, shift by
// exponent, read digits out & format. `optimize` is wired to false
// here so genericFtoa always takes the slow path (`bigFtoa`). The
// Ryu fast path lands in M11b-B as a transparent perf upgrade.

#![allow(non_snake_case)]

extern crate alloc;
use alloc::vec::Vec;

use crate::convert::{
    float32 as tofloat32, int32 as toint32, int64 as toint64, uint32 as touint32,
    uint64 as touint64, uint8 as touint8,
};
use crate::gostring::string;
use crate::types::{byte, int};

use super::decimal::decimal;

// go: sdk 1.25.5 strconv/ftoa.go:15-20 floatInfo
/// TODO: move elsewhere?
pub(crate) struct floatInfo {
    pub mantbits: u32,
    pub expbits: u32,
    pub bias: i32,
}

// go: sdk 1.25.5 strconv/ftoa.go:22-22 float32info
pub(crate) const float32info: floatInfo = floatInfo {
    mantbits: 23,
    expbits: 8,
    bias: -127,
};

// go: sdk 1.25.5 strconv/ftoa.go:23-23 float64info
pub(crate) const float64info: floatInfo = floatInfo {
    mantbits: 52,
    expbits: 11,
    bias: -1023,
};

// go: sdk 1.25.5 strconv/ftoa.go:49-51 FormatFloat
/// `strconv.FormatFloat`.
pub fn FormatFloat(f: f64, fmt_b: byte, prec: int, bit_size: int) -> string {
    let cap = core::cmp::max(prec + 4, 24) as usize;
    let dst: Vec<byte> = Vec::with_capacity(cap);
    let bytes = genericFtoa(dst, f, fmt_b, toint32(prec), toint32(bit_size));
    return string::__from_vec(bytes);
}

// go: sdk 1.25.5 strconv/ftoa.go:55-57 AppendFloat
/// `strconv.AppendFloat`.
pub fn AppendFloat(
    dst: crate::goslice::slice<byte>,
    f: f64,
    fmt_b: byte,
    prec: int,
    bit_size: int,
) -> crate::goslice::slice<byte> {
    let v = dst.__into_vec();
    let v = genericFtoa(v, f, fmt_b, toint32(prec), toint32(bit_size));
    return crate::goslice::slice::__from_vec(v);
}

// go: sdk 1.25.5 strconv/ftoa.go:58-163 genericFtoa
fn genericFtoa(mut dst: Vec<byte>, val: f64, fmt_b: byte, prec: i32, bit_size: i32) -> Vec<byte> {
    let (bits, flt) = match bit_size {
        32 => (touint64(tofloat32(val).to_bits()), &float32info),
        64 => (val.to_bits(), &float64info),
        _ => panic!("strconv: illegal AppendFloat/FormatFloat bitSize"),
    };

    let neg = (bits >> (flt.expbits + flt.mantbits)) != 0;
    let mut exp = toint32((bits >> flt.mantbits) & ((1u64 << flt.expbits) - 1));
    let mut mant = bits & ((1u64 << flt.mantbits) - 1);

    if exp == (1i32 << flt.expbits) - 1 {
        // Inf, NaN
        let s: &[u8] = if mant != 0 {
            b"NaN"
        } else if neg {
            b"-Inf"
        } else {
            b"+Inf"
        };
        dst.extend_from_slice(s);
        return dst;
    } else if exp == 0 {
        // denormalized
        exp += 1;
    } else {
        // implicit top bit
        mant |= 1u64 << flt.mantbits;
    }
    exp += flt.bias;

    if fmt_b == b'b' {
        return fmtB(dst, neg, mant, exp, flt);
    }
    if fmt_b == b'x' || fmt_b == b'X' {
        return fmtX(dst, prec, fmt_b, neg, mant, exp, flt);
    }

    // Skip Ryu optimizations — slow path always.
    return bigFtoa(dst, prec, fmt_b, neg, mant, exp, flt);
}

// go: sdk 1.25.5 strconv/ftoa.go:164-199 bigFtoa
fn bigFtoa(
    dst: Vec<byte>,
    mut prec: i32,
    fmt_b: byte,
    neg: bool,
    mant: u64,
    exp: i32,
    flt: &floatInfo,
) -> Vec<byte> {
    let mut d = decimal::new();
    d.Assign(mant);
    d.Shift(exp - toint32(flt.mantbits));
    let shortest = prec < 0;
    if shortest {
        roundShortest(&mut d, mant, exp, flt);
        match fmt_b {
            b'e' | b'E' => prec = core::cmp::max(d.nd - 1, 0),
            b'f' => prec = core::cmp::max(d.nd - d.dp, 0),
            b'g' | b'G' => prec = d.nd,
            _ => {}
        }
    } else {
        match fmt_b {
            b'e' | b'E' => d.Round(prec + 1),
            b'f' => d.Round(d.dp + prec),
            b'g' | b'G' => {
                if prec == 0 {
                    prec = 1;
                }
                d.Round(prec);
            }
            _ => {}
        }
    }
    let digs = decimalSlice {
        d: &d.d[..],
        nd: d.nd,
        dp: d.dp,
    };
    return formatDigits(dst, shortest, neg, digs, prec, fmt_b);
}

// go: sdk 1.25.5 strconv/ftoa.go:200-236 formatDigits
fn formatDigits(
    dst: Vec<byte>,
    shortest: bool,
    neg: bool,
    digs: decimalSlice,
    mut prec: i32,
    fmt_b: byte,
) -> Vec<byte> {
    let (nd, dp) = (digs.nd, digs.dp);
    return match fmt_b {
        b'e' | b'E' => fmtE(dst, neg, digs, prec, fmt_b),
        b'f' => fmtF(dst, neg, digs, prec),
        b'g' | b'G' => {
            // trailing fractional zeros in 'e' form will be trimmed.
            let mut eprec = prec;
            if eprec > nd && nd >= dp {
                eprec = nd;
            }
            // %e is used if the exponent from the conversion is less than -4
            // or greater than or equal to the precision.
            if shortest {
                eprec = 6;
            }
            let exp = dp - 1;
            if exp < -4 || exp >= eprec {
                let mut p = prec;
                if p > nd {
                    p = nd;
                }
                // 'g' → 'e', 'G' → 'E'. Subtraction in i32 to avoid u8 underflow.
                let next_fmt = touint8(toint32(fmt_b) + (toint32(b'e') - toint32(b'g')));
                return fmtE(dst, neg, digs, p - 1, next_fmt);
            }
            if prec > dp {
                prec = nd;
            }
            fmtF(dst, neg, digs, core::cmp::max(prec - dp, 0))
        }
        _ => {
            // unknown format
            let mut dst = dst;
            dst.push(b'%');
            dst.push(fmt_b);
            dst
        }
    };
}

// go: sdk 1.25.5 strconv/ftoa.go:234-372 roundShortest
/// Round d (= mant * 2^exp) to the shortest number of digits that will
/// let the original floating point value be precisely reconstructed.
fn roundShortest(d: &mut decimal, mant: u64, exp: i32, flt: &floatInfo) {
    if mant == 0 {
        d.nd = 0;
        return;
    }
    let minexp = flt.bias + 1;
    if exp > minexp && 332 * (d.dp - d.nd) >= 100 * (exp - toint32(flt.mantbits)) {
        return;
    }

    // upper / lower decimal bounds
    let mut upper = decimal::new();
    upper.Assign(mant * 2 + 1);
    upper.Shift(exp - toint32(flt.mantbits) - 1);

    let (mantlo, explo) = if mant > (1u64 << flt.mantbits) || exp == minexp {
        (mant - 1, exp)
    } else {
        (mant * 2 - 1, exp - 1)
    };
    let mut lower = decimal::new();
    lower.Assign(mantlo * 2 + 1);
    lower.Shift(explo - toint32(flt.mantbits) - 1);

    let inclusive = mant % 2 == 0;

    let mut upperdelta: u8 = 0;
    let mut ui: i32 = 0;
    loop {
        let mi = ui - upper.dp + d.dp;
        if mi >= d.nd {
            break;
        }
        let li = ui - upper.dp + lower.dp;
        let l: u8 = if li >= 0 && li < lower.nd {
            lower.d[li as usize]
        } else {
            b'0'
        };
        let m: u8 = if mi >= 0 { d.d[mi as usize] } else { b'0' };
        let u: u8 = if ui < upper.nd {
            upper.d[ui as usize]
        } else {
            b'0'
        };

        let okdown = l != m || (inclusive && li + 1 == lower.nd);

        match upperdelta {
            0 if m + 1 < u => {
                upperdelta = 2;
            }
            0 if m != u => {
                upperdelta = 1;
            }
            1 if m != b'9' || u != b'0' => {
                upperdelta = 2;
            }
            _ => {}
        }
        let okup = upperdelta > 0 && (inclusive || upperdelta > 1 || ui + 1 < upper.nd);

        if okdown && okup {
            d.Round(mi + 1);
            return;
        } else if okdown {
            d.RoundDown(mi + 1);
            return;
        } else if okup {
            d.RoundUp(mi + 1);
            return;
        }
        ui += 1;
    }
}

// go: sdk 1.25.5 strconv/ftoa.go:374-378 decimalSlice
/// Go's `decimalSlice` is `{ d []byte; nd, dp int }` — the rounded
/// digits `bigFtoa` hands to the formatters. goish carried the three
/// fields as three separate parameters, which is why every formatter
/// below had two more arguments than the function it ports.
pub(crate) struct decimalSlice<'a> {
    pub d: &'a [byte],
    pub nd: i32,
    pub dp: i32,
}

// go: sdk 1.25.5 strconv/ftoa.go:380-434 fmtE
/// %e: -d.ddddde±dd
fn fmtE(mut dst: Vec<byte>, neg: bool, ds: decimalSlice, prec: i32, fmt_b: byte) -> Vec<byte> {
    let (d, nd, dp) = (ds.d, ds.nd, ds.dp);
    if neg {
        dst.push(b'-');
    }
    // first digit
    let ch = if nd != 0 { d[0] } else { b'0' };
    dst.push(ch);

    if prec > 0 {
        dst.push(b'.');
        let m = core::cmp::min(nd, prec + 1);
        let mut i: i32 = 1;
        if i < m {
            dst.extend_from_slice(&d[i as usize..m as usize]);
            i = m;
        }
        while i <= prec {
            dst.push(b'0');
            i += 1;
        }
    }

    dst.push(fmt_b);
    let mut exp = dp - 1;
    if nd == 0 {
        exp = 0;
    }
    if exp < 0 {
        dst.push(b'-');
        exp = -exp;
    } else {
        dst.push(b'+');
    }

    if exp < 10 {
        dst.push(b'0');
        dst.push(b'0' + touint8(exp));
    } else if exp < 100 {
        dst.push(b'0' + touint8(exp / 10));
        dst.push(b'0' + touint8(exp % 10));
    } else {
        dst.push(b'0' + touint8(exp / 100));
        dst.push(b'0' + touint8((exp / 10) % 10));
        dst.push(b'0' + touint8(exp % 10));
    }
    return dst;
}

// go: sdk 1.25.5 strconv/ftoa.go:435-467 fmtF
/// %f: -ddddddd.ddddd
fn fmtF(mut dst: Vec<byte>, neg: bool, ds: decimalSlice, prec: i32) -> Vec<byte> {
    let (d, nd, dp) = (ds.d, ds.nd, ds.dp);
    if neg {
        dst.push(b'-');
    }
    if dp > 0 {
        let m = core::cmp::min(nd, dp);
        dst.extend_from_slice(&d[..m as usize]);
        let mut k = m;
        while k < dp {
            dst.push(b'0');
            k += 1;
        }
    } else {
        dst.push(b'0');
    }

    if prec > 0 {
        dst.push(b'.');
        for i in 0..prec {
            let j = dp + i;
            let ch = if j >= 0 && j < nd {
                d[j as usize]
            } else {
                b'0'
            };
            dst.push(ch);
        }
    }
    return dst;
}

// go: sdk 1.25.5 strconv/ftoa.go:468-490 fmtB
/// %b: -ddddddddp±ddd
fn fmtB(mut dst: Vec<byte>, neg: bool, mant: u64, exp: i32, flt: &floatInfo) -> Vec<byte> {
    if neg {
        dst.push(b'-');
    }
    // mantissa
    dst.extend_from_slice(super::FormatUint(mant, 10).as_bytes());

    // p
    dst.push(b'p');

    // ±exponent
    let exp = exp - toint32(flt.mantbits);
    if exp >= 0 {
        dst.push(b'+');
    }
    dst.extend_from_slice(super::FormatInt(toint64(exp), 10).as_bytes());
    return dst;
}

// go: sdk 1.25.5 strconv/ftoa.go:491-571 fmtX
fn fmtX(
    mut dst: Vec<byte>,
    prec: i32,
    fmt_b: byte,
    neg: bool,
    mut mant: u64,
    mut exp: i32,
    flt: &floatInfo,
) -> Vec<byte> {
    if mant == 0 {
        exp = 0;
    }

    // Shift digits so leading 1 (if any) is at bit 1<<60.
    mant <<= 60 - flt.mantbits;
    while mant != 0 && (mant & (1u64 << 60)) == 0 {
        mant <<= 1;
        exp -= 1;
    }

    if prec >= 0 && prec < 15 {
        let shift = touint32(prec * 4);
        let extra = (mant << shift) & ((1u64 << 60) - 1);
        mant >>= 60 - shift;
        if extra | (mant & 1) > (1u64 << 59) {
            mant += 1;
        }
        mant <<= 60 - shift;
        if (mant & (1u64 << 61)) != 0 {
            mant >>= 1;
            exp += 1;
        }
    }

    let hex = if fmt_b == b'X' {
        super::quote::upperhex
    } else {
        super::quote::lowerhex
    };

    if neg {
        dst.push(b'-');
    }
    dst.extend_from_slice(&[b'0', fmt_b, b'0' + touint8((mant >> 60) & 1)]);

    mant <<= 4;
    if prec < 0 && mant != 0 {
        dst.push(b'.');
        while mant != 0 {
            dst.push(hex[((mant >> 60) & 15) as usize]);
            mant <<= 4;
        }
    } else if prec > 0 {
        dst.push(b'.');
        for _ in 0..prec {
            dst.push(hex[((mant >> 60) & 15) as usize]);
            mant <<= 4;
        }
    }

    let p_ch = if fmt_b == b'X' { b'P' } else { b'p' };
    dst.push(p_ch);
    if exp < 0 {
        dst.push(b'-');
        exp = -exp;
    } else {
        dst.push(b'+');
    }

    if exp < 100 {
        dst.push(b'0' + touint8(exp / 10));
        dst.push(b'0' + touint8(exp % 10));
    } else if exp < 1000 {
        dst.push(b'0' + touint8(exp / 100));
        dst.push(b'0' + touint8((exp / 10) % 10));
        dst.push(b'0' + touint8(exp % 10));
    } else {
        dst.push(b'0' + touint8(exp / 1000));
        dst.push(b'0' + touint8((exp / 100) % 10));
        dst.push(b'0' + touint8((exp / 10) % 10));
        dst.push(b'0' + touint8(exp % 10));
    }
    return dst;
}
