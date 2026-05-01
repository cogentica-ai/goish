// strconv — Go's strconv package, ported. M11a + M11b-A.
//
// Includes (M11a — integers / bool):
//   Atoi, Itoa, ParseInt, ParseUint, FormatInt, FormatUint, AppendInt,
//   AppendUint, ParseBool, FormatBool, AppendBool, NumError (public
//   fields), sentinels ErrSyntax / ErrRange.
//
// Includes (M11b-A — floats, slow-path port of Go's atof.go / ftoa.go /
// decimal.go, no Eisel-Lemire / Ryu yet):
//   ParseFloat, FormatFloat, AppendFloat. Verbs: 'b', 'e', 'E', 'f',
//   'g', 'G', 'x', 'X' — same as Go.
//
// Deferred:
//   * M11b-B — Ryu fast-path for FormatFloat shortest round-trip.
//   * M11b-C — Eisel-Lemire fast-path for ParseFloat.
//   * Quote / Unquote / IsPrint / IsGraphic — M11c (unicode print tables).
//   * ParseComplex / FormatComplex — no `complex` type yet.
//
// v1 differences from Go semantics:
//
//   * goish `int` is i64 always (amd64-pinned). `IntSize = 64`. ParseInt
//     with bit_size=0 is identical to bit_size=64.
//   * `NumError.Error()` text uses plain double-quotes around `Num`
//     instead of `strconv.Quote`. Identical for ASCII inputs without
//     escape chars; upgrades when M11c lands.
//
// String inputs are generic over `S: Into<string>` so call sites stay
// tight: `strconv::Atoi("42")` works without `string("42")` wrapping.

#![allow(non_snake_case, non_upper_case_globals)]

extern crate alloc;
use alloc::vec::Vec;

use crate::errors::{self, error, nil, ErrorTrait};
use crate::goslice::slice;
use crate::gostring::string;
use crate::runtime::spin::SpinLock;
use crate::types::{byte, int, rune, uint};

mod atof;
mod decimal;
mod ftoa;

pub use atof::ParseFloat;
pub use ftoa::{AppendFloat, FormatFloat};

// ─── Constants ────────────────────────────────────────────────────────

/// `IntSize` — bit width of `int`. v1 pins this to 64 (amd64-only).
pub const IntSize: int = 64;

const digits: &[u8] = b"0123456789abcdefghijklmnopqrstuvwxyz";

#[inline]
fn lower(c: byte) -> byte {
    c | (b'x' - b'X') // == 0x20: ASCII letter to lower-case
}

// ─── Sentinels (cached, Arc-stable) ───────────────────────────────────

fn cached_error(slot: &SpinLock<Option<error>>, init: fn() -> error) -> error {
    let mut g = slot.lock();
    if g.is_none() {
        *g = Some(init());
    }
    g.as_ref().unwrap().clone()
}

/// `strconv.ErrSyntax` — input did not look like a number.
pub fn ErrSyntax() -> error {
    static SLOT: SpinLock<Option<error>> = SpinLock::new(None);
    cached_error(&SLOT, || errors::New("invalid syntax"))
}

/// `strconv.ErrRange` — value parsed but is out of range for the target.
pub fn ErrRange() -> error {
    static SLOT: SpinLock<Option<error>> = SpinLock::new(None);
    cached_error(&SLOT, || errors::New("value out of range"))
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
        string::__from_vec(buf)
    }
    fn Unwrap(&self) -> error {
        self.Err.clone()
    }
}

fn syntaxError(fn_name: &'static str, s: string) -> error {
    errors::Wrap(NumError {
        Func: string::from_static(fn_name),
        Num: s,
        Err: ErrSyntax(),
    })
}

fn rangeError(fn_name: &'static str, s: string) -> error {
    errors::Wrap(NumError {
        Func: string::from_static(fn_name),
        Num: s,
        Err: ErrRange(),
    })
}

fn baseError(fn_name: &'static str, s: string, base: int) -> error {
    let mut msg: Vec<byte> = Vec::with_capacity(24);
    msg.extend_from_slice(b"invalid base ");
    let mut tmp = [0u8; 24];
    let n = format_int_into(&mut tmp, base);
    msg.extend_from_slice(&tmp[24 - n..]);
    let inner = errors::New(string::__from_vec(msg));
    errors::Wrap(NumError {
        Func: string::from_static(fn_name),
        Num: s,
        Err: inner,
    })
}

fn bitSizeError(fn_name: &'static str, s: string, bit_size: int) -> error {
    let mut msg: Vec<byte> = Vec::with_capacity(24);
    msg.extend_from_slice(b"invalid bit size ");
    let mut tmp = [0u8; 24];
    let n = format_int_into(&mut tmp, bit_size);
    msg.extend_from_slice(&tmp[24 - n..]);
    let inner = errors::New(string::__from_vec(msg));
    errors::Wrap(NumError {
        Func: string::from_static(fn_name),
        Num: s,
        Err: inner,
    })
}

// ─── Itoa / FormatInt / FormatUint / AppendInt / AppendUint ───────────

/// `strconv.Itoa` — equivalent to `FormatInt(i, 10)`.
pub fn Itoa(i: int) -> string {
    FormatInt(i, 10)
}

pub fn FormatInt(i: int, base: int) -> string {
    if base < 2 || base > 36 {
        panic!("strconv: illegal AppendInt/FormatInt base");
    }
    let neg = i < 0;
    // wrapping_neg handles i64::MIN cleanly: -i64::MIN as u64 == 2^63.
    let u = if neg {
        i.wrapping_neg() as u64
    } else {
        i as u64
    };
    format_uint_string(u, base, neg)
}

pub fn FormatUint(i: uint, base: int) -> string {
    if base < 2 || base > 36 {
        panic!("strconv: illegal AppendInt/FormatInt base");
    }
    format_uint_string(i as u64, base, false)
}

pub fn AppendInt(dst: slice<byte>, i: int, base: int) -> slice<byte> {
    let s = FormatInt(i, base);
    let mut v = dst.__into_vec();
    v.extend_from_slice(s.as_bytes());
    slice::__from_vec(v)
}

pub fn AppendUint(dst: slice<byte>, i: uint, base: int) -> slice<byte> {
    let s = FormatUint(i, base);
    let mut v = dst.__into_vec();
    v.extend_from_slice(s.as_bytes());
    slice::__from_vec(v)
}

// Format unsigned magnitude into a 65-byte fixed buffer (LSB-first),
// then return the populated tail as a string. `neg` prepends '-'.
fn format_uint_string(mut u: u64, base: int, neg: bool) -> string {
    let b = base as u64;
    let mut buf = [0u8; 65]; // 64 bits in base-2 + 1 sign byte
    let mut i = buf.len();
    if u == 0 {
        i -= 1;
        buf[i] = b'0';
    } else {
        while u > 0 {
            i -= 1;
            buf[i] = digits[(u % b) as usize];
            u /= b;
        }
    }
    if neg {
        i -= 1;
        buf[i] = b'-';
    }
    string::from_bytes(&buf[i..])
}

// Internal: write base-10 digits of `n` to the END of `buf` (LSB-first),
// return the digit count written. Caller reads `buf[buf.len() - n..]`.
//
// Re-exposed under `format_int_into_lib` so the `ftoa` submodule can
// reuse it for `%b` exponent printing.
pub(crate) fn format_int_into_lib(buf: &mut [u8; 24], n: i64) -> usize {
    format_int_into(buf, n)
}

fn format_int_into(buf: &mut [u8; 24], n: int) -> usize {
    let neg = n < 0;
    let mut u = if neg {
        n.wrapping_neg() as u64
    } else {
        n as u64
    };
    let mut i = buf.len();
    if u == 0 {
        i -= 1;
        buf[i] = b'0';
    } else {
        while u > 0 {
            i -= 1;
            buf[i] = b'0' + (u % 10) as u8;
            u /= 10;
        }
    }
    if neg {
        i -= 1;
        buf[i] = b'-';
    }
    buf.len() - i
}

// ─── ParseUint ────────────────────────────────────────────────────────

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

    let cutoff = u64::MAX / (base as u64) + 1;
    let max_val = if bit_size_eff == 64 {
        u64::MAX
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
        if d >= base as byte {
            return (0, syntaxError(FN, s0));
        }
        if n >= cutoff {
            return (max_val as uint, rangeError(FN, s0));
        }
        n *= base as u64;
        let n1 = n.wrapping_add(d as u64);
        if n1 < n || n1 > max_val {
            return (max_val as uint, rangeError(FN, s0));
        }
        n = n1;
    }

    if underscores && !underscoreOK(s0.as_bytes()) {
        return (0, syntaxError(FN, s0));
    }

    (n as uint, nil)
}

// ─── ParseInt ─────────────────────────────────────────────────────────

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
        // Reshape: same error class, but Func="ParseInt" and Num=s0.
        let inner_is_range = errors::Is(err.clone(), ErrRange());
        if !inner_is_range {
            // Could be syntax, base, or bit-size — preserve syntax;
            // for base/bit-size errors we fall through to syntaxError
            // which is wrong-but-rare (callers already passed valid
            // base/bit_size for real Go programs).
            return (0, syntaxError(FN, s0));
        }
        // Range error: clamp to the signed bound on the appropriate side.
        let cutoff_abs: u64 = if bs == 64 { 1u64 << 63 } else { 1u64 << (bs - 1) };
        if neg {
            return ((cutoff_abs as i64).wrapping_neg(), rangeError(FN, s0));
        } else {
            return ((cutoff_abs - 1) as int, rangeError(FN, s0));
        }
    }

    // Range-check the magnitude against signed bounds for `bs`.
    let cutoff_abs: u64 = if bs == 64 { 1u64 << 63 } else { 1u64 << (bs - 1) };
    let un64 = un as u64;
    if !neg && un64 >= cutoff_abs {
        return ((cutoff_abs - 1) as int, rangeError(FN, s0));
    }
    if neg && un64 > cutoff_abs {
        return ((cutoff_abs as i64).wrapping_neg(), rangeError(FN, s0));
    }
    let n = un64 as i64;
    let result = if neg { n.wrapping_neg() } else { n };
    (result, nil)
}

// ─── Atoi ─────────────────────────────────────────────────────────────

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
            n = n * 10 + d as int;
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
        let new_err = if errors::Is(err.clone(), ErrRange()) {
            rangeError(FN, s0)
        } else {
            syntaxError(FN, s0)
        };
        return (i64_val, new_err);
    }
    (i64_val, nil)
}

// ─── underscoreOK — port of Go's helper ───────────────────────────────

fn underscoreOK(s: &[u8]) -> bool {
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
        if (b'0' <= s[i] && s[i] <= b'9')
            || (hex && b'a' <= lower(s[i]) && lower(s[i]) <= b'f')
        {
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
    saw != b'_'
}

// ─── Bool ─────────────────────────────────────────────────────────────

pub fn ParseBool<S: Into<string>>(str_: S) -> (bool, error) {
    let s = str_.into();
    let b = s.as_bytes();
    match b {
        b"1" | b"t" | b"T" | b"true" | b"TRUE" | b"True" => (true, nil),
        b"0" | b"f" | b"F" | b"false" | b"FALSE" | b"False" => (false, nil),
        _ => (false, syntaxError("ParseBool", s)),
    }
}

pub fn FormatBool(b: bool) -> string {
    if b {
        string::from_static("true")
    } else {
        string::from_static("false")
    }
}

pub fn AppendBool(dst: slice<byte>, b: bool) -> slice<byte> {
    let mut v = dst.__into_vec();
    if b {
        v.extend_from_slice(b"true");
    } else {
        v.extend_from_slice(b"false");
    }
    slice::__from_vec(v)
}

// ─── Quote / Unquote (slim ASCII port of strconv/quote.go) ───────────

/// `strconv.Quote(s)` (quote.go:125) — return a double-quoted Go
/// string literal of `s`. Slim port: ASCII-only.
///
/// - `\\`, `"` always escaped.
/// - Tab/newline/CR/etc. use the canonical `\t`/`\n`/`\r` short forms.
/// - Other bytes < 0x20 or = 0x7F render as `\xHH` (lower-hex).
/// - Bytes >= 0x80 render as `\xHH` (no full UTF-8 IsPrint check).
pub fn Quote<S: Into<string>>(s: S) -> string {
    let s = s.into();
    let bs = s.as_bytes();
    let mut out: alloc::vec::Vec<u8> = alloc::vec::Vec::with_capacity(bs.len() + 2);
    out.push(b'"');
    let lowerhex = b"0123456789abcdef";
    for &c in bs.iter() {
        match c {
            b'\\' => {
                out.push(b'\\');
                out.push(b'\\');
            }
            b'"' => {
                out.push(b'\\');
                out.push(b'"');
            }
            b'\n' => out.extend_from_slice(b"\\n"),
            b'\r' => out.extend_from_slice(b"\\r"),
            b'\t' => out.extend_from_slice(b"\\t"),
            0x07 => out.extend_from_slice(b"\\a"),
            0x08 => out.extend_from_slice(b"\\b"),
            0x0c => out.extend_from_slice(b"\\f"),
            0x0b => out.extend_from_slice(b"\\v"),
            c if c < 0x20 || c == 0x7f || c >= 0x80 => {
                out.extend_from_slice(b"\\x");
                out.push(lowerhex[(c >> 4) as usize]);
                out.push(lowerhex[(c & 0x0f) as usize]);
            }
            c => out.push(c),
        }
    }
    out.push(b'"');
    string::from_bytes(&out)
}

/// `strconv.AppendQuote(dst, s)` (quote.go:131) — append the
/// quoted-string form of `s` to `dst` and return the extended buffer.
pub fn AppendQuote<S: Into<string>>(dst: slice<byte>, s: S) -> slice<byte> {
    // Go: return appendQuotedWith(dst, s, '"', false, false)
    // Slim: just delegate to Quote() and append the bytes.
    let q = Quote(s);
    let mut v = dst.__into_vec();
    v.extend_from_slice(q.as_bytes());
    slice::__from_vec(v)
}

/// `strconv.CanBackquote(s)` (quote.go:212) — report whether `s` can
/// be rendered unchanged inside backticks (no control chars except
/// '\t', no backquote, no DEL, no BOM).
///
/// Slim: ASCII fast-path identical to Go for that subset; multi-byte
/// runes other than the BOM (U+FEFF) are assumed printable per Go's
/// comment on quote.go:220.
pub fn CanBackquote<S: Into<string>>(s: S) -> bool {
    let s = s.into();
    let bs = s.as_bytes();
    let mut i: usize = 0;
    while i < bs.len() {
        // Go: r, wid := utf8.DecodeRuneInString(s); s = s[wid:]
        let (r, wid) = crate::unicode::utf8::DecodeRune(&bs[i..]);
        if wid == 0 {
            // Defensive: can't make progress.
            break;
        }
        // Go: if wid > 1 { if r == '﻿' { return false }; continue }
        if wid > 1 {
            if r == 0xFEFF {
                return false; // BOMs are invisible.
            }
            i += wid as usize;
            continue;
        }
        // Go: if r == utf8.RuneError { return false }
        if r == crate::unicode::utf8::RuneError {
            return false;
        }
        // Go: if (r < ' ' && r != '\t') || r == '`' || r == '' { return false }
        if (r < b' ' as rune && r != b'\t' as rune) || r == b'`' as rune || r == 0x7F {
            return false;
        }
        i += 1;
    }
    true
}

/// `strconv.Unquote(s)` (quote.go:383) — slim ASCII port. Decodes a
/// `"..."` literal containing the Quote-emitted escapes (`\\`, `\"`,
/// `\n`, `\r`, `\t`, `\a`, `\b`, `\f`, `\v`, `\xHH`). Returns
/// `(decoded, err)`.
pub fn Unquote<S: Into<string>>(s: S) -> (string, error) {
    let s = s.into();
    let bs = s.as_bytes();
    if bs.len() < 2 || bs[0] != b'"' || bs[bs.len() - 1] != b'"' {
        return (string::new(), errors::New("invalid syntax"));
    }
    let inner = &bs[1..bs.len() - 1];
    let mut out: alloc::vec::Vec<u8> = alloc::vec::Vec::with_capacity(inner.len());
    let mut i: usize = 0;
    while i < inner.len() {
        let c = inner[i];
        if c == b'"' {
            // Bare " inside the quoted region is invalid.
            return (string::new(), errors::New("invalid syntax"));
        }
        if c != b'\\' {
            out.push(c);
            i += 1;
            continue;
        }
        // Escape sequence; need at least one more byte.
        if i + 1 >= inner.len() {
            return (string::new(), errors::New("invalid syntax"));
        }
        let next = inner[i + 1];
        match next {
            b'\\' => {
                out.push(b'\\');
                i += 2;
            }
            b'"' => {
                out.push(b'"');
                i += 2;
            }
            b'n' => {
                out.push(b'\n');
                i += 2;
            }
            b'r' => {
                out.push(b'\r');
                i += 2;
            }
            b't' => {
                out.push(b'\t');
                i += 2;
            }
            b'a' => {
                out.push(0x07);
                i += 2;
            }
            b'b' => {
                out.push(0x08);
                i += 2;
            }
            b'f' => {
                out.push(0x0c);
                i += 2;
            }
            b'v' => {
                out.push(0x0b);
                i += 2;
            }
            b'x' => {
                if i + 3 >= inner.len() {
                    return (string::new(), errors::New("invalid syntax"));
                }
                let h1 = unhex_byte(inner[i + 2]);
                let h2 = unhex_byte(inner[i + 3]);
                if h1 == 0xff || h2 == 0xff {
                    return (string::new(), errors::New("invalid syntax"));
                }
                out.push((h1 << 4) | h2);
                i += 4;
            }
            _ => return (string::new(), errors::New("invalid syntax")),
        }
    }
    let _ = nil; // silence unused
    (string::from_bytes(&out), errors::nil)
}

fn unhex_byte(c: u8) -> u8 {
    match c {
        b'0'..=b'9' => c - b'0',
        b'a'..=b'f' => c - b'a' + 10,
        b'A'..=b'F' => c - b'A' + 10,
        _ => 0xff,
    }
}
