// go: file fmt/format.go decls: fmt.truncateString
//
// format.go — the per-verb formatters the printer dispatches to.

extern crate alloc;
#[allow(unused_imports)]
use alloc::vec::Vec;

#[allow(unused_imports)]
use crate::convert::{
    byte as tobyte, int as toint, int32 as toint32, int64 as toint64, rune as torune,
    uint as touint, uint32 as touint32, uint64 as touint64,
};
#[allow(unused_imports)]
use crate::errors::nil;
#[allow(unused_imports)]
use crate::errors::{self, error, ErrorTrait};
#[allow(unused_imports)]
use crate::goslice::slice;
#[allow(unused_imports)]
use crate::gostring::string;
#[allow(unused_imports)]
use crate::io;
#[allow(unused_imports)]
use crate::os;
#[allow(unused_imports)]
use crate::types::{byte, int, rune};
#[allow(unused_imports)]
use crate::unicode::utf8;

#[allow(unused_imports)]
use super::*;

// ─── Verb formatters ──────────────────────────────────────────────────

// go: none — goish idiom: Go keeps the per-verb formatters as methods on a
//     `fmt` struct that also carries the parsed flags; goish passes the
//     verb and the buffer as arguments instead, so none of these match a
//     Go signature. See the file header for which Go method each stands
//     in for.
pub(crate) fn write_string_with_verb(bytes: &[byte], verb: byte, f: &mut FmtBuf) {
    match verb {
        b'q' => write_quoted(bytes, false, f),
        // `%+q` arrives as the synthetic verb 'Q'; see the scanner.
        b'Q' => write_quoted(bytes, true, f),
        b'x' => write_hex(bytes, false, f),
        b'X' => write_hex(bytes, true, f),
        _ => f.extend(bytes), // %s, %v, default
    }
}

// go: none — goish idiom: Go keeps the per-verb formatters as methods on a
//     `fmt` struct that also carries the parsed flags; goish passes the
//     verb and the buffer as arguments instead, so none of these match a
//     Go signature. See the file header for which Go method each stands
//     in for.
// Go's fmt does not quote for itself: format.go's `fmtQ` hands the
// value to `strconv.AppendQuote`, and `%+q` to
// `strconv.AppendQuoteToASCII`. Doing it here instead meant a second
// quoter with its own idea of what is printable — one that escaped
// every byte >= 0x80 as `\xHH`, so `%q` of any non-ASCII string came
// out as hex.
pub(crate) fn write_quoted(bytes: &[byte], ascii_only: bool, f: &mut FmtBuf) {
    let s = string::from_bytes(bytes);
    let q = if ascii_only {
        crate::strconv::QuoteToASCII(s)
    } else {
        crate::strconv::Quote(s)
    };
    f.extend(q.as_bytes());
}

// go: none — goish idiom: Go keeps the per-verb formatters as methods on a
//     `fmt` struct that also carries the parsed flags; goish passes the
//     verb and the buffer as arguments instead, so none of these match a
//     Go signature. See the file header for which Go method each stands
//     in for.
pub(crate) fn write_hex(bytes: &[byte], upper: bool, f: &mut FmtBuf) {
    for &b in bytes {
        f.push(hex_digit(b >> 4, upper));
        f.push(hex_digit(b & 0xF, upper));
    }
}

// go: none — goish idiom: Go keeps the per-verb formatters as methods on a
//     `fmt` struct that also carries the parsed flags; goish passes the
//     verb and the buffer as arguments instead, so none of these match a
//     Go signature. See the file header for which Go method each stands
//     in for.
pub(crate) fn hex_digit(n: byte, upper: bool) -> byte {
    return if n < 10 {
        b'0' + n
    } else if upper {
        b'A' + n - 10
    } else {
        b'a' + n - 10
    };
}

// go: none — goish idiom: Go keeps the per-verb formatters as methods on a
//     `fmt` struct that also carries the parsed flags; goish passes the
//     verb and the buffer as arguments instead, so none of these match a
//     Go signature. See the file header for which Go method each stands
//     in for.
pub(crate) fn format_signed(n: i64, verb: byte, f: &mut FmtBuf) {
    // Go prints a NEGATIVE integer in any base as a sign followed by
    // the magnitude — `%x` of -255 is "-ff". goish handed the value
    // straight to the unsigned path, so -255 came out as the two's
    // complement, "ffffffffffffff01".
    let base: u64 = match verb {
        b'x' | b'X' => 16,
        b'b' => 2,
        b'o' => 8,
        _ => 0,
    };
    if base != 0 {
        let mut u = touint64(n);
        if n < 0 {
            f.push(b'-');
            u = touint64(n).wrapping_neg();
        }
        format_uint(u, base, verb == b'X', f);
        return;
    }
    match verb {
        b'd' | b'v' => format_decimal_signed(n, f),
        b'c' | b'q' | b'Q' => format_rune_or_int(torune(n), verb, f),
        _ => format_decimal_signed(n, f),
    }
}

// go: none — goish idiom: Go keeps the per-verb formatters as methods on a
//     `fmt` struct that also carries the parsed flags; goish passes the
//     verb and the buffer as arguments instead, so none of these match a
//     Go signature. See the file header for which Go method each stands
//     in for.
pub(crate) fn format_unsigned(n: u64, verb: byte, f: &mut FmtBuf) {
    match verb {
        b'd' | b'v' => format_uint(n, 10, false, f),
        b'x' => format_uint(n, 16, false, f),
        b'X' => format_uint(n, 16, true, f),
        b'b' => format_uint(n, 2, false, f),
        b'o' => format_uint(n, 8, false, f),
        b'c' | b'q' | b'Q' => format_rune_or_int(torune(n), verb, f),
        _ => format_uint(n, 10, false, f),
    }
}

// go: none — goish idiom: Go keeps the per-verb formatters as methods on a
//     `fmt` struct that also carries the parsed flags; goish passes the
//     verb and the buffer as arguments instead, so none of these match a
//     Go signature. See the file header for which Go method each stands
//     in for.
pub(crate) fn format_decimal_signed(n: i64, f: &mut FmtBuf) {
    if n < 0 {
        f.push(b'-');
        // Handle i64::MIN safely via wrapping_neg + cast.
        let abs = touint64(n).wrapping_neg();
        format_uint(abs, 10, false, f);
    } else {
        format_uint(touint64(n), 10, false, f);
    }
}

// go: none — goish idiom: Go keeps the per-verb formatters as methods on a
//     `fmt` struct that also carries the parsed flags; goish passes the
//     verb and the buffer as arguments instead, so none of these match a
//     Go signature. See the file header for which Go method each stands
//     in for.
pub(crate) fn format_uint(mut n: u64, base: u64, upper: bool, f: &mut FmtBuf) {
    if n == 0 {
        f.push(b'0');
        return;
    }
    // 64 bits in base 2 needs 64 chars; safe upper bound.
    let mut buf = [0u8; 64];
    let mut i = 0;
    while n > 0 {
        let d = tobyte(n % base);
        buf[i] = hex_digit(d, upper);
        i += 1;
        n /= base;
    }
    while i > 0 {
        i -= 1;
        f.push(buf[i]);
    }
}

// go: none — goish idiom: Go keeps the per-verb formatters as methods on a
//     `fmt` struct that also carries the parsed flags; goish passes the
//     verb and the buffer as arguments instead, so none of these match a
//     Go signature. See the file header for which Go method each stands
//     in for.
pub(crate) fn format_rune_or_int(r: rune, verb: byte, f: &mut FmtBuf) {
    match verb {
        b'c' => {
            let mut buf = [0u8; 4];
            let n = utf8::EncodeRune(&mut buf, r);
            f.extend(&buf[..n as usize]);
        }
        // Go's `fmtQc` hands the rune to `strconv.AppendQuoteRune`,
        // which escapes it. goish emitted the raw rune between two
        // quotes instead, so `%q` of '\n' was a literal newline inside
        // single quotes and every control character printed itself.
        b'q' => {
            let q = crate::strconv::QuoteRune(r);
            f.extend(q.as_bytes());
        }
        b'Q' => {
            let q = crate::strconv::QuoteRuneToASCII(r);
            f.extend(q.as_bytes());
        }
        _ => format_decimal_signed(toint64(r), f),
    }
}

// go: sdk 1.25.5 fmt/format.go:325-338 fmt.truncateString
/// Trim `s` to at most `prec` RUNES. `prec < 0` means no truncation.
pub(crate) fn truncate_string(s: &[byte], prec: i64) -> &[byte] {
    if prec < 0 {
        return s;
    }
    let mut n = prec;
    let mut i = 0usize;
    while i < s.len() {
        n -= 1;
        if n < 0 {
            return &s[..i];
        }
        let (_, w) = utf8::DecodeRune(&s[i..]);
        i += w as usize;
    }
    return s;
}
