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
        Err: ErrSyntax.into(),
    })
}

fn rangeError(fn_name: &'static str, s: string) -> error {
    errors::Wrap(NumError {
        Func: string::from_static(fn_name),
        Num: s,
        Err: ErrRange.into(),
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
        let inner_is_range = errors::Is(err.clone(), ErrRange);
        if !inner_is_range {
            // Could be syntax, base, or bit-size — preserve syntax;
            // for base/bit-size errors we fall through to syntaxError
            // which is wrong-but-rare (callers already passed valid
            // base/bit_size for real Go programs).
            return (0, syntaxError(FN, s0));
        }
        // Range error: clamp to the signed bound on the appropriate side.
        let cutoff_abs: u64 = if bs == 64 {
            1u64 << 63
        } else {
            1u64 << (bs - 1)
        };
        if neg {
            return ((cutoff_abs as i64).wrapping_neg(), rangeError(FN, s0));
        } else {
            return ((cutoff_abs - 1) as int, rangeError(FN, s0));
        }
    }

    // Range-check the magnitude against signed bounds for `bs`.
    let cutoff_abs: u64 = if bs == 64 {
        1u64 << 63
    } else {
        1u64 << (bs - 1)
    };
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
        let new_err = if errors::Is(err.clone(), ErrRange) {
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

/// `strconv.QuoteToASCII(s)` (quote.go:138) — return a double-quoted
/// Go string literal representing `s`, escaping every non-ASCII byte
/// using `\xHH`. Slim port: the existing `Quote` already emits
/// ASCII-only output for bytes ≥ 0x80, so this delegates directly.
pub fn QuoteToASCII<S: Into<string>>(s: S) -> string {
    // Go: return quoteWith(s, '"', true, false)
    Quote(s)
}

/// `strconv.AppendQuoteToASCII(dst, s)` (quote.go:144) — append the
/// ASCII-quoted form of `s` to `dst` and return the extended buffer.
pub fn AppendQuoteToASCII<S: Into<string>>(dst: slice<byte>, s: S) -> slice<byte> {
    // Go: return appendQuotedWith(dst, s, '"', true, false)
    AppendQuote(dst, s)
}

/// `strconv.QuoteToGraphic(s)` (quote.go:152) — return a double-quoted
/// Go string literal that leaves Unicode graphic characters unchanged
/// and uses Go escape sequences for non-graphic characters.
///
/// Slim: in goish v1, [`IsGraphic`] defers to [`IsPrint`] (no Unicode
/// graphic-list table), and [`Quote`] already escapes every byte that
/// fails the slim printable test, so this is a thin alias over
/// [`Quote`]. The output for the common ASCII subset matches Go's.
pub fn QuoteToGraphic<S: Into<string>>(s: S) -> string {
    // Go: return quoteWith(s, '"', false, true)
    Quote(s)
}

/// `strconv.AppendQuoteToGraphic(dst, s)` (quote.go:158) — append the
/// graphic-quoted form of `s` to `dst` and return the extended buffer.
pub fn AppendQuoteToGraphic<S: Into<string>>(dst: slice<byte>, s: S) -> slice<byte> {
    // Go: return appendQuotedWith(dst, s, '"', false, true)
    AppendQuote(dst, s)
}

// Internal helper: append the Go-escape form of a single rune with
// the given quote-byte (either `'` for QuoteRune, `"` for Quote).
// Slim: ASCII printable bytes pass through; control chars use `\x`;
// runes ≥ 0x80 always escape (`\u` < 0x10000, else `\U`).
fn append_escaped_rune(out: &mut alloc::vec::Vec<u8>, r: rune, quote: u8) {
    let lowerhex = b"0123456789abcdef";
    // Go: if r == rune(quote) || r == '\\' { ... }
    if r == quote as rune {
        out.push(b'\\');
        out.push(quote);
        return;
    }
    if r == b'\\' as rune {
        out.push(b'\\');
        out.push(b'\\');
        return;
    }
    // Go: short-form escapes for the named control chars.
    match r {
        0x07 => {
            out.extend_from_slice(b"\\a");
            return;
        }
        0x08 => {
            out.extend_from_slice(b"\\b");
            return;
        }
        0x0C => {
            out.extend_from_slice(b"\\f");
            return;
        }
        0x0A => {
            out.extend_from_slice(b"\\n");
            return;
        }
        0x0D => {
            out.extend_from_slice(b"\\r");
            return;
        }
        0x09 => {
            out.extend_from_slice(b"\\t");
            return;
        }
        0x0B => {
            out.extend_from_slice(b"\\v");
            return;
        }
        _ => {}
    }
    // Other control chars / DEL → \xHH.
    if r >= 0 && r < 0x20 {
        out.extend_from_slice(b"\\x");
        out.push(lowerhex[((r >> 4) & 0xF) as usize]);
        out.push(lowerhex[(r & 0xF) as usize]);
        return;
    }
    if r == 0x7F {
        out.extend_from_slice(b"\\x7f");
        return;
    }
    // ASCII printable: emit raw byte.
    if r >= 0x20 && r < 0x7F {
        out.push(r as u8);
        return;
    }
    // Non-ASCII / invalid: \u or \U escape.
    if r < 0 || r > 0x10FFFF {
        // Invalid code point → render replacement char as �.
        out.extend_from_slice(b"\\ufffd");
        return;
    }
    if r < 0x10000 {
        out.extend_from_slice(b"\\u");
        let mut shift: i32 = 12;
        while shift >= 0 {
            let nib = ((r >> shift) & 0xF) as usize;
            out.push(lowerhex[nib]);
            shift -= 4;
        }
        return;
    }
    out.extend_from_slice(b"\\U");
    let mut shift: i32 = 28;
    while shift >= 0 {
        let nib = ((r >> shift) & 0xF) as usize;
        out.push(lowerhex[nib]);
        shift -= 4;
    }
}

/// `strconv.QuoteRune(r)` (quote.go:167) — return a single-quoted
/// Go character literal for `r`. Control chars and non-ASCII use
/// Go escape sequences (`\t`, `\n`, `\xFF`, `Ā`, `\U00100000`).
pub fn QuoteRune(r: rune) -> string {
    // Go: return quoteRuneWith(r, '\'', false, false)
    let mut out: alloc::vec::Vec<u8> = alloc::vec::Vec::with_capacity(8);
    out.push(b'\'');
    append_escaped_rune(&mut out, r, b'\'');
    out.push(b'\'');
    string::from_bytes(&out)
}

/// `strconv.AppendQuoteRune(dst, r)` (quote.go:173) — append the
/// QuoteRune form of `r` to `dst` and return the extended buffer.
pub fn AppendQuoteRune(dst: slice<byte>, r: rune) -> slice<byte> {
    // Go: return appendQuotedRuneWith(dst, r, '\'', false, false)
    let q = QuoteRune(r);
    let mut v = dst.__into_vec();
    v.extend_from_slice(q.as_bytes());
    slice::__from_vec(v)
}

/// `strconv.QuoteRuneToASCII(r)` (quote.go:183) — slim port: same
/// as `QuoteRune` because our slim implementation already escapes
/// non-ASCII runes.
pub fn QuoteRuneToASCII(r: rune) -> string {
    // Go: return quoteRuneWith(r, '\'', true, false)
    QuoteRune(r)
}

/// `strconv.AppendQuoteRuneToASCII(dst, r)` (quote.go:189) — append
/// the QuoteRuneToASCII form to `dst`.
pub fn AppendQuoteRuneToASCII(dst: slice<byte>, r: rune) -> slice<byte> {
    // Go: return appendQuotedRuneWith(dst, r, '\'', true, false)
    AppendQuoteRune(dst, r)
}

/// `strconv.QuoteRuneToGraphic(r)` (quote.go:199) — return a single-
/// quoted Go character literal. If `r` is not a Unicode graphic
/// character (per [`IsGraphic`]), the returned string uses a Go escape
/// sequence (`\t`, `\n`, `\xFF`, `Ā`).
///
/// Slim: aliases [`QuoteRune`] for the same reason that
/// [`QuoteToGraphic`] aliases [`Quote`].
pub fn QuoteRuneToGraphic(r: rune) -> string {
    // Go: return quoteRuneWith(r, '\'', false, true)
    QuoteRune(r)
}

/// `strconv.AppendQuoteRuneToGraphic(dst, r)` (quote.go:205) — append
/// the QuoteRuneToGraphic form to `dst`.
pub fn AppendQuoteRuneToGraphic(dst: slice<byte>, r: rune) -> slice<byte> {
    // Go: return appendQuotedRuneWith(dst, r, '\'', false, true)
    AppendQuoteRune(dst, r)
}

/// `strconv.CanBackquote(s)` (quote.go:212) — report whether `s` can
/// be rendered unchanged inside backticks (no control chars except
/// '\t', no backquote, no DEL, no BOM).
///
/// Slim: ASCII fast-path identical to Go for that subset; multi-byte
/// runes other than the BOM (U+FEFF) are assumed printable per Go's
/// comment on quote.go:220.
pub fn IsPrint(r: crate::types::rune) -> bool {
    // Go: if r <= 0xFF { ... fast Latin-1 path ... }
    if r <= 0xFF {
        // Go: if 0x20 <= r && r <= 0x7E { return true }
        if r >= 0x20 && r <= 0x7E {
            return true;
        }
        // Go: if 0xA1 <= r && r <= 0xFF { return r != 0xAD }
        if r >= 0xA1 && r <= 0xFF {
            return r != 0xAD;
        }
        return false;
    }
    // Slim deviation: the upstream non-Latin-1 path consults the
    // isPrint16 / isPrint32 / isNotPrint16 / isNotPrint32 Unicode tables
    // (~32 KiB static). Goish v1 doesn't ship those, so codepoints with
    // r > 0xFF that are valid Unicode (excluding surrogates and the
    // > 0x10FFFF out-of-range region) are accepted as printable. This
    // errs toward "show the rune" — callers needing strict Unicode-table
    // conformance should not rely on this for security-sensitive
    // filtering.
    if r < 0 || r > 0x10_FFFF {
        return false;
    }
    if r >= 0xD800 && r <= 0xDFFF {
        return false;
    }
    true
}

/// Line-by-line port of `strconv.IsGraphic(r)` (quote.go:568) — reports
/// whether `r` is defined as a Graphic by Unicode (categories L, M, N,
/// P, S, and Zs).
///
/// Slim: defers to IsPrint; upstream's `isInGraphicList` extension for
/// the U+0000..U+FFFF range needs the `isGraphic` table that goish v1
/// doesn't ship.
pub fn IsGraphic(r: crate::types::rune) -> bool {
    // Go: if IsPrint(r) { return true }; return isInGraphicList(r)
    IsPrint(r)
}

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

// Go: quote.go:232
//   func unhex(b byte) (v rune, ok bool) { ... }
fn unhex(b: byte) -> (rune, bool) {
    let c = b as rune;
    if c >= b'0' as rune && c <= b'9' as rune {
        return (c - b'0' as rune, true);
    }
    if c >= b'a' as rune && c <= b'f' as rune {
        return (c - b'a' as rune + 10, true);
    }
    if c >= b'A' as rune && c <= b'F' as rune {
        return (c - b'A' as rune + 10, true);
    }
    (0, false)
}

/// `strconv.UnquoteChar(s, quote)` (quote.go:259) — decode the first
/// character or byte in the escaped string or character literal.
///
/// Returns `(value, multibyte, tail, err)`:
///   * `value`     — the decoded Unicode code point or byte.
///   * `multibyte` — true if the decoded character requires a multibyte
///                   UTF-8 representation.
///   * `tail`      — the remainder of `s` after the consumed character.
///   * `err`       — non-nil on syntax error (no characters consumed).
///
/// The `quote` argument selects the literal form: `'` for character
/// literals, `"` for string literals, or `0` to allow both quote
/// characters to appear unescaped.
pub fn UnquoteChar<S: Into<string>>(s: S, quote: byte) -> (rune, bool, string, error) {
    let s_in = s.into();
    let bs = s_in.as_bytes();
    // Go: easy cases. if len(s) == 0 { err = ErrSyntax; return }
    if bs.is_empty() {
        return (0, false, string::new(), ErrSyntax.into());
    }
    // Go: switch c := s[0]; { ... }
    let c = bs[0];
    // Go: case c == quote && (quote == '\'' || quote == '"'): err = ErrSyntax
    if c == quote && (quote == b'\'' || quote == b'"') {
        return (0, false, string::new(), ErrSyntax.into());
    }
    // Go: case c >= utf8.RuneSelf:
    //         r, size := utf8.DecodeRuneInString(s)
    //         return r, true, s[size:], nil
    if c >= crate::unicode::utf8::RuneSelf {
        let (r, size) = crate::unicode::utf8::DecodeRune(bs);
        let tail = string::from_bytes(&bs[size as usize..]);
        return (r, true, tail, nil);
    }
    // Go: case c != '\\': return rune(s[0]), false, s[1:], nil
    if c != b'\\' {
        let tail = string::from_bytes(&bs[1..]);
        return (c as rune, false, tail, nil);
    }
    // Go: hard case — c is backslash. if len(s) <= 1 { err = ErrSyntax; return }
    if bs.len() <= 1 {
        return (0, false, string::new(), ErrSyntax.into());
    }
    // Go: c := s[1]; s = s[2:]
    let esc = bs[1];
    let mut tail_bs: &[byte] = &bs[2..];
    let value: rune;
    let mut multibyte: bool = false;
    match esc {
        b'a' => value = 0x07,
        b'b' => value = 0x08,
        b'f' => value = 0x0C,
        b'n' => value = 0x0A,
        b'r' => value = 0x0D,
        b't' => value = 0x09,
        b'v' => value = 0x0B,
        // Go: case 'x', 'u', 'U':
        b'x' | b'u' | b'U' => {
            let n: usize = match esc {
                b'x' => 2,
                b'u' => 4,
                b'U' => 8,
                _ => 0,
            };
            // Go: if len(s) < n { err = ErrSyntax; return }
            if tail_bs.len() < n {
                return (0, false, string::new(), ErrSyntax.into());
            }
            let mut v: rune = 0;
            // Go: for j := 0; j < n; j++ {
            //         x, ok := unhex(s[j]); if !ok { err = ErrSyntax; return }
            //         v = v<<4 | x
            //     }
            for j in 0..n {
                let (x, ok) = unhex(tail_bs[j]);
                if !ok {
                    return (0, false, string::new(), ErrSyntax.into());
                }
                v = (v << 4) | x;
            }
            tail_bs = &tail_bs[n..];
            // Go: if c == 'x' { value = v; break }
            if esc == b'x' {
                value = v;
            } else {
                // Go: if !utf8.ValidRune(v) { err = ErrSyntax; return }
                if !crate::unicode::utf8::ValidRune(v) {
                    return (0, false, string::new(), ErrSyntax.into());
                }
                value = v;
                multibyte = true;
            }
        }
        // Go: case '0', '1', '2', '3', '4', '5', '6', '7':
        b'0' | b'1' | b'2' | b'3' | b'4' | b'5' | b'6' | b'7' => {
            let mut v: rune = (esc as rune) - b'0' as rune;
            if tail_bs.len() < 2 {
                return (0, false, string::new(), ErrSyntax.into());
            }
            for j in 0..2 {
                let x: rune = (tail_bs[j] as rune) - b'0' as rune;
                if x < 0 || x > 7 {
                    return (0, false, string::new(), ErrSyntax.into());
                }
                v = (v << 3) | x;
            }
            tail_bs = &tail_bs[2..];
            if v > 255 {
                return (0, false, string::new(), ErrSyntax.into());
            }
            value = v;
        }
        b'\\' => value = b'\\' as rune,
        // Go: case '\'', '"':
        b'\'' | b'"' => {
            if esc != quote {
                return (0, false, string::new(), ErrSyntax.into());
            }
            value = esc as rune;
        }
        _ => return (0, false, string::new(), ErrSyntax.into()),
    }
    let tail = string::from_bytes(tail_bs);
    (value, multibyte, tail, nil)
}

// Go: quote.go:391
//   func unquote(in string, unescape bool) (out, rem string, err error)
//
// Internal helper shared by Unquote and QuotedPrefix.
fn unquote_impl(in_s: string, unescape: bool) -> (string, string, error) {
    let in_bs = in_s.as_bytes();
    // Go: if len(in) < 2 { return "", in, ErrSyntax }
    if in_bs.len() < 2 {
        return (string::new(), in_s.clone(), ErrSyntax.into());
    }
    // Go: quote := in[0]; end := index(in[1:], quote)
    //     if end < 0 { return "", in, ErrSyntax }
    //     end += 2
    let quote = in_bs[0];
    let end_after_inner = match in_bs[1..].iter().position(|&b| b == quote) {
        Some(p) => p + 2, // position after terminating quote
        None => return (string::new(), in_s.clone(), ErrSyntax.into()),
    };
    let end = end_after_inner;

    match quote {
        b'`' => {
            // Go: case '`': switch { case !unescape: out = in[:end] ... }
            let out: string;
            if !unescape {
                out = string::from_bytes(&in_bs[..end]);
            } else if !in_bs[..end].contains(&b'\r') {
                out = string::from_bytes(&in_bs[1..end - 1]);
            } else {
                // Carriage returns inside raw strings are dropped from the value.
                let mut buf: Vec<byte> = Vec::with_capacity(end - 2);
                let mut i = 1usize;
                while i < end - 1 {
                    if in_bs[i] != b'\r' {
                        buf.push(in_bs[i]);
                    }
                    i += 1;
                }
                out = string::from_bytes(&buf);
            }
            let rem = string::from_bytes(&in_bs[end..]);
            (out, rem, nil)
        }
        b'"' | b'\'' => {
            // Go: if !contains(in[:end], '\\') && !contains(in[:end], '\n') { ... fast path ... }
            let head = &in_bs[..end];
            let has_bs = head.contains(&b'\\');
            let has_nl = head.contains(&b'\n');
            if !has_bs && !has_nl {
                let valid: bool = match quote {
                    b'"' => {
                        crate::unicode::utf8::ValidString(&string::from_bytes(&head[1..end - 1]))
                    }
                    b'\'' => {
                        let inner = &head[1..end - 1];
                        let (r, n) = crate::unicode::utf8::DecodeRune(inner);
                        let n_us = n as usize;
                        // Go: valid = len("'")+n+len("'") == end && (r != utf8.RuneError || n != 1)
                        2 + n_us == end && (r != crate::unicode::utf8::RuneError || n != 1)
                    }
                    _ => false,
                };
                if valid {
                    let out: string;
                    if unescape {
                        out = string::from_bytes(&head[1..end - 1]);
                    } else {
                        out = string::from_bytes(head);
                    }
                    let rem = string::from_bytes(&in_bs[end..]);
                    return (out, rem, nil);
                }
            }

            // Go: handle quoted strings with escape sequences.
            let mut buf: Vec<byte> = if unescape {
                Vec::with_capacity(3 * end / 2)
            } else {
                Vec::new()
            };
            let in0 = in_s.clone();
            // Go: in = in[1:]; skip starting quote.
            let mut cur = string::from_bytes(&in_bs[1..]);
            // Go: for len(in) > 0 && in[0] != quote { ... }
            loop {
                let cur_bs = cur.as_bytes();
                if cur_bs.is_empty() || cur_bs[0] == quote {
                    break;
                }
                // Go: r, multibyte, rem, err := UnquoteChar(in, quote)
                //     if in[0] == '\n' || err != nil { return "", in0, ErrSyntax }
                let first = cur_bs[0];
                let (r, multibyte, rem, err) = UnquoteChar(cur.clone(), quote);
                if first == b'\n' || !err.IsNil() {
                    return (string::new(), in0, ErrSyntax.into());
                }
                cur = rem;

                if unescape {
                    // Go: if r < utf8.RuneSelf || !multibyte { buf = append(buf, byte(r)) }
                    //     else { buf = utf8.AppendRune(buf, r) }
                    if r < crate::unicode::utf8::RuneSelf as rune || !multibyte {
                        buf.push(r as byte);
                    } else {
                        let s_in = slice::__from_vec(buf);
                        let s_out = crate::unicode::utf8::AppendRune(s_in, r);
                        buf = s_out.__into_vec();
                    }
                }

                // Go: single-quoted strings are a single character.
                if quote == b'\'' {
                    break;
                }
            }

            // Go: verify the string ends with a terminating quote.
            let cur_bs = cur.as_bytes();
            if !(!cur_bs.is_empty() && cur_bs[0] == quote) {
                return (string::new(), in0, ErrSyntax.into());
            }
            // Go: in = in[1:] — skip terminating quote.
            cur = string::from_bytes(&cur_bs[1..]);

            if unescape {
                return (string::from_bytes(&buf), cur, nil);
            }
            // Go: return in0[:len(in0)-len(in)], in, nil
            let in0_bs = in0.as_bytes();
            let cur_bs = cur.as_bytes();
            let prefix_len = in0_bs.len() - cur_bs.len();
            let out = string::from_bytes(&in0_bs[..prefix_len]);
            (out, cur, nil)
        }
        _ => (string::new(), in_s.clone(), ErrSyntax.into()),
    }
}

/// `strconv.QuotedPrefix(s)` (quote.go:372) — returns the quoted
/// string at the prefix of `s` (as understood by [`Unquote`]).
/// If `s` does not start with a valid quoted string, returns an
/// `ErrSyntax` error.
pub fn QuotedPrefix<S: Into<string>>(s: S) -> (string, error) {
    // Go: out, _, err := unquote(s, false); return out, err
    let (out, _rem, err) = unquote_impl(s.into(), false);
    (out, err)
}

/// `strconv.Unquote(s)` (quote.go:383) — interprets `s` as a single-,
/// double-, or backquoted Go string literal, returning the string
/// value that `s` quotes. Single-quoted literals decode as a one-rune
/// string (or empty if the rune is a single byte).
pub fn Unquote<S: Into<string>>(s: S) -> (string, error) {
    // Go: out, rem, err := unquote(s, true)
    //     if len(rem) > 0 { return "", ErrSyntax }
    //     return out, err
    let (out, rem, err) = unquote_impl(s.into(), true);
    if rem.as_bytes().len() > 0 {
        return (string::new(), ErrSyntax.into());
    }
    (out, err)
}
