// go: file strconv/atoi.go decls: lower, NumError.Error, NumError.Unwrap, syntaxError, rangeError, baseError, bitSizeError, ParseUint, ParseInt, Atoi, underscoreOK
//
// atoi.go — ParseUint, ParseInt, Atoi, the NumError type and the
// three error constructors, plus underscoreOK.

extern crate alloc;
use alloc::vec::Vec;

use crate::convert::{
    byte as tobyte, int as toint, int64 as toint64, uint as touint, uint64 as touint64,
};
use crate::errors::{self, error, nil, ErrorTrait};
use crate::gostring::string;
use crate::types::{byte, int, uint};

use super::*;

// ─── Constants ────────────────────────────────────────────────────────

// go: sdk 1.25.5 strconv/atoi.go:63-63 intSize
/// Go computes this as `32 << (^uint(0) >> 63)`. goish's `uint` is
/// 64-bit, so the shift is by 1.
const intSize: int = 32 << (uint::MAX >> 63);

// go: sdk 1.25.5 strconv/atoi.go:65-66 IntSize
/// `IntSize` is the size in bits of an `int` or `uint` value.
pub const IntSize: int = intSize;

// go: sdk 1.25.5 strconv/atoi.go:68-68 maxUint64
const maxUint64: uint = u64::MAX;

// go: sdk 1.25.5 strconv/atoi.go:16-18 lower
#[inline]
fn lower(c: byte) -> byte {
    return c | (b'x' - b'X'); // == 0x20: ASCII letter to lower-case;
}

// ─── Sentinels (cached, Arc-stable) ───────────────────────────────────

crate::var! {
    /// `strconv.ErrSyntax` — input did not look like a number.
    pub ErrSyntax: error = "invalid syntax";
    /// `strconv.ErrRange` — value parsed but is out of range for the target.
    pub ErrRange: error  = "value out of range";
}

// ─── NumError ─────────────────────────────────────────────────────────

/// `strconv.NumError` — Go's concrete failed-conversion type. Fields
/// public so user code can inspect `Func` / `Num` directly. Reachable
/// from a wrapped `error` via the `errors::Is`/`Unwrap` chain.
pub struct NumError {
    pub Func: string,
    pub Num: string,
    pub Err: error,
}

impl ErrorTrait for NumError {
    // go: sdk 1.25.5 strconv/atoi.go:33-35 NumError.Error
    fn Error(&self) -> string {
        let func = self.Func.as_bytes();
        let num = self.Num.as_bytes();
        let inner = self.Err.Error();
        let inner_b = inner.as_bytes();
        let total = b"strconv.".len()
            + func.len()
            + b": parsing \"".len()
            + num.len()
            + b"\": ".len()
            + inner_b.len();
        let mut buf: Vec<byte> = Vec::with_capacity(total);
        buf.extend_from_slice(b"strconv.");
        buf.extend_from_slice(func);
        buf.extend_from_slice(b": parsing \"");
        buf.extend_from_slice(num);
        buf.extend_from_slice(b"\": ");
        buf.extend_from_slice(inner_b);
        return string::__from_vec(buf);
    }
    // go: sdk 1.25.5 strconv/atoi.go:37-37 NumError.Unwrap
    fn Unwrap(&self) -> error {
        return self.Err.clone();
    }
}

// go: sdk 1.25.5 strconv/atoi.go:47-49 syntaxError
pub(crate) fn syntaxError(fn_name: &'static str, s: string) -> error {
    return errors::Wrap(NumError {
        Func: string::from_static(fn_name),
        Num: s,
        Err: ErrSyntax.into(),
    });
}

// go: sdk 1.25.5 strconv/atoi.go:51-53 rangeError
pub(crate) fn rangeError(fn_name: &'static str, s: string) -> error {
    return errors::Wrap(NumError {
        Func: string::from_static(fn_name),
        Num: s,
        Err: ErrRange.into(),
    });
}

// go: sdk 1.25.5 strconv/atoi.go:55-57 baseError
fn baseError(fn_name: &'static str, s: string, base: int) -> error {
    let mut msg: Vec<byte> = Vec::with_capacity(24);
    msg.extend_from_slice(b"invalid base ");
    msg.extend_from_slice(Itoa(base).as_bytes());
    let inner = errors::New(string::__from_vec(msg));
    return errors::Wrap(NumError {
        Func: string::from_static(fn_name),
        Num: s,
        Err: inner,
    });
}

// go: sdk 1.25.5 strconv/atoi.go:59-61 bitSizeError
fn bitSizeError(fn_name: &'static str, s: string, bit_size: int) -> error {
    let mut msg: Vec<byte> = Vec::with_capacity(24);
    msg.extend_from_slice(b"invalid bit size ");
    msg.extend_from_slice(Itoa(bit_size).as_bytes());
    let inner = errors::New(string::__from_vec(msg));
    return errors::Wrap(NumError {
        Func: string::from_static(fn_name),
        Num: s,
        Err: inner,
    });
}

// ─── ParseUint ────────────────────────────────────────────────────────

// go: sdk 1.25.5 strconv/atoi.go:73-170 ParseUint
pub fn ParseUint<S: Into<string>>(s: S, base: int, bit_size: int) -> (uint, error) {
    const FN: &str = "ParseUint";
    let s = s.into();
    if s.as_bytes().is_empty() {
        return (0, syntaxError(FN, s));
    }
    let s0 = s.clone();
    let mut s_bytes: &[u8] = s.as_bytes();
    let mut base = base;
    let base0 = base == 0;

    if base != 0 && (base < 2 || base > 36) {
        return (0, baseError(FN, s0, base));
    }
    if base == 0 {
        // Detect prefix (0b / 0o / 0x / leading 0 for octal).
        base = 10;
        if s_bytes[0] == b'0' {
            if s_bytes.len() >= 3 && lower(s_bytes[1]) == b'b' {
                base = 2;
                s_bytes = &s_bytes[2..];
            } else if s_bytes.len() >= 3 && lower(s_bytes[1]) == b'o' {
                base = 8;
                s_bytes = &s_bytes[2..];
            } else if s_bytes.len() >= 3 && lower(s_bytes[1]) == b'x' {
                base = 16;
                s_bytes = &s_bytes[2..];
            } else {
                base = 8;
                s_bytes = &s_bytes[1..];
            }
        }
    }

    let bit_size_eff = if bit_size == 0 {
        IntSize
    } else if bit_size < 0 || bit_size > 64 {
        return (0, bitSizeError(FN, s0, bit_size));
    } else {
        bit_size
    };

    // Cutoff is the smallest number such that cutoff*base > maxUint64.
    let cutoff = maxUint64 / (touint64(base)) + 1;
    let max_val = if bit_size_eff == 64 {
        maxUint64
    } else {
        (1u64 << bit_size_eff) - 1
    };

    let mut underscores = false;
    let mut n: u64 = 0;
    for &c in s_bytes {
        let d: byte;
        if c == b'_' && base0 {
            underscores = true;
            continue;
        } else if b'0' <= c && c <= b'9' {
            d = c - b'0';
        } else if b'a' <= lower(c) && lower(c) <= b'z' {
            d = lower(c) - b'a' + 10;
        } else {
            return (0, syntaxError(FN, s0));
        }
        if d >= tobyte(base) {
            return (0, syntaxError(FN, s0));
        }
        if n >= cutoff {
            return (touint(max_val), rangeError(FN, s0));
        }
        n *= touint64(base);
        let n1 = n.wrapping_add(touint64(d));
        if n1 < n || n1 > max_val {
            return (touint(max_val), rangeError(FN, s0));
        }
        n = n1;
    }

    if underscores && !underscoreOK(s0.as_bytes()) {
        return (0, syntaxError(FN, s0));
    }

    return (touint(n), nil);
}

// ─── ParseInt ─────────────────────────────────────────────────────────

// go: sdk 1.25.5 strconv/atoi.go:197-240 ParseInt
pub fn ParseInt<S: Into<string>>(s: S, base: int, bit_size: int) -> (int, error) {
    const FN: &str = "ParseInt";
    let s = s.into();
    if s.as_bytes().is_empty() {
        return (0, syntaxError(FN, s));
    }
    let s0 = s.clone();
    let bytes = s.as_bytes();
    let mut start = 0usize;
    let mut neg = false;
    match bytes[0] {
        b'+' => start = 1,
        b'-' => {
            start = 1;
            neg = true;
        }
        _ => {}
    }
    let body = string::from_bytes(&bytes[start..]);

    let (un, err) = ParseUint(body, base, bit_size);
    let bs = if bit_size == 0 { IntSize } else { bit_size };

    if err != nil {
        // Go mutates the *NumError in place — same wrapped Err, but
        // Func="ParseInt" and Num=s0 — so an invalid base or bit size
        // keeps its own message instead of being flattened into a
        // syntax error. Only a range error falls through to the
        // clamping below.
        let inner_is_range = errors::Is(err.clone(), ErrRange);
        if !inner_is_range {
            let reshaped = match errors::As::<NumError>(err.clone()) {
                Some(ne) => errors::Wrap(NumError {
                    Func: string::from_static(FN),
                    Num: s0,
                    Err: ne.Err.clone(),
                }),
                None => err,
            };
            return (0, reshaped);
        }
        // Range error: clamp to the signed bound on the appropriate side.
        let cutoff_abs: u64 = if bs == 64 {
            1u64 << 63
        } else {
            1u64 << (bs - 1)
        };
        if neg {
            return ((toint64(cutoff_abs)).wrapping_neg(), rangeError(FN, s0));
        } else {
            return (toint(cutoff_abs - 1), rangeError(FN, s0));
        }
    }

    // Range-check the magnitude against signed bounds for `bs`.
    let cutoff_abs: u64 = if bs == 64 {
        1u64 << 63
    } else {
        1u64 << (bs - 1)
    };
    let un64 = touint64(un);
    if !neg && un64 >= cutoff_abs {
        return (toint(cutoff_abs - 1), rangeError(FN, s0));
    }
    if neg && un64 > cutoff_abs {
        return ((toint64(cutoff_abs)).wrapping_neg(), rangeError(FN, s0));
    }
    let n = toint64(un64);
    let result = if neg { n.wrapping_neg() } else { n };
    return (result, nil);
}

// ─── Atoi ─────────────────────────────────────────────────────────────

// go: sdk 1.25.5 strconv/atoi.go:243-278 Atoi
pub fn Atoi<S: Into<string>>(s: S) -> (int, error) {
    const FN: &str = "Atoi";
    let s = s.into();
    let bytes = s.as_bytes();
    let s_len = bytes.len();

    // Fast path: small base-10 integers known to fit i64 without overflow.
    // i64 max is 19 decimal digits; we accept up to 18 chars including a
    // leading sign — safely within range, no overflow check needed.
    if 0 < s_len && s_len < 19 {
        let s0 = s.clone();
        let mut start = 0usize;
        let mut neg = false;
        match bytes[0] {
            b'+' => start = 1,
            b'-' => {
                start = 1;
                neg = true;
            }
            _ => {}
        }
        if start > 0 && start >= s_len {
            return (0, syntaxError(FN, s0));
        }
        let mut n: int = 0;
        for &ch in &bytes[start..] {
            let d = ch.wrapping_sub(b'0');
            if d > 9 {
                return (0, syntaxError(FN, s0));
            }
            n = n * 10 + toint(d);
        }
        if neg {
            n = -n;
        }
        return (n, nil);
    }

    // Slow path: ParseInt with NumError.Func reshaped to "Atoi".
    let s0 = s.clone();
    let (i64_val, err) = ParseInt(s, 10, 0);
    if err != nil {
        let new_err = if errors::Is(err.clone(), ErrRange) {
            rangeError(FN, s0)
        } else {
            syntaxError(FN, s0)
        };
        return (i64_val, new_err);
    }
    return (i64_val, nil);
}

// ─── underscoreOK — port of Go's helper ───────────────────────────────

// go: sdk 1.25.5 strconv/atoi.go:283-328 underscoreOK
pub(crate) fn underscoreOK(s: &[u8]) -> bool {
    let mut saw: u8 = b'^';
    let mut i = 0usize;
    let mut s = s;
    if s.len() >= 1 && (s[0] == b'-' || s[0] == b'+') {
        s = &s[1..];
    }
    let mut hex = false;
    if s.len() >= 2
        && s[0] == b'0'
        && (lower(s[1]) == b'b' || lower(s[1]) == b'o' || lower(s[1]) == b'x')
    {
        i = 2;
        saw = b'0';
        hex = lower(s[1]) == b'x';
    }
    while i < s.len() {
        if (b'0' <= s[i] && s[i] <= b'9') || (hex && b'a' <= lower(s[i]) && lower(s[i]) <= b'f') {
            saw = b'0';
            i += 1;
            continue;
        }
        if s[i] == b'_' {
            if saw != b'0' {
                return false;
            }
            saw = b'_';
            i += 1;
            continue;
        }
        if saw == b'_' {
            return false;
        }
        saw = b'!';
        i += 1;
    }
    return saw != b'_';
}
