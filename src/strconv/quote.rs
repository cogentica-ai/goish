// go: file strconv/quote.go decls: contains, quoteWith, quoteRuneWith, appendQuotedWith, appendQuotedRuneWith, appendEscapedRune, Quote, AppendQuote, QuoteToASCII, AppendQuoteToASCII, QuoteToGraphic, AppendQuoteToGraphic, QuoteRune, AppendQuoteRune, QuoteRuneToASCII, AppendQuoteRuneToASCII, QuoteRuneToGraphic, AppendQuoteRuneToGraphic, CanBackquote, unhex, UnquoteChar, QuotedPrefix, Unquote, unquote, bsearch, IsPrint, IsGraphic, isInGraphicList
//
// quote.go — Quote and its family, and Unquote.

extern crate alloc;
use alloc::vec::Vec;

use crate::convert::{byte as tobyte, rune as torune, uint16 as touint16, uint32 as touint32};
use crate::errors::{error, nil};
use crate::goslice::slice;
use crate::gostring::string;
use crate::types::{byte, rune};

use super::*;

// ─── Quote / Unquote (slim ASCII port of strconv/quote.go) ───────────

// go: sdk 1.25.5 strconv/quote.go:13-16 lowerhex
pub(crate) const lowerhex: &[byte] = b"0123456789abcdef";

// go: sdk 1.25.5 strconv/quote.go:13-16 upperhex
pub(crate) const upperhex: &[byte] = b"0123456789ABCDEF";

// go: sdk 1.25.5 strconv/quote.go:18-21 contains
/// Reports whether the string contains the byte `c`.
fn contains(s: &[byte], c: byte) -> bool {
    return s.contains(&c);
}

// go: sdk 1.25.5 strconv/quote.go:23-25 quoteWith
fn quoteWith(s: &[byte], quote: byte, ASCIIonly: bool, graphicOnly: bool) -> string {
    let mut buf: Vec<byte> = Vec::with_capacity(3 * s.len() / 2);
    appendQuotedWith(&mut buf, s, quote, ASCIIonly, graphicOnly);
    return string::from_bytes(&buf);
}

// go: sdk 1.25.5 strconv/quote.go:27-29 quoteRuneWith
fn quoteRuneWith(r: rune, quote: byte, ASCIIonly: bool, graphicOnly: bool) -> string {
    let mut buf: Vec<byte> = Vec::new();
    appendQuotedRuneWith(&mut buf, r, quote, ASCIIonly, graphicOnly);
    return string::from_bytes(&buf);
}

// go: sdk 1.25.5 strconv/quote.go:31-55 appendQuotedWith
/// Go grows `buf` up front and returns it; goish appends in place, so
/// the preallocation Go does by hand is `reserve`.
fn appendQuotedWith(
    buf: &mut Vec<byte>,
    s: &[byte],
    quote: byte,
    ASCIIonly: bool,
    graphicOnly: bool,
) {
    // Often called with big strings, so preallocate. If there's quoting,
    // this is conservative but still helps a lot.
    buf.reserve(1 + s.len() + 1);
    buf.push(quote);
    let mut i: usize = 0;
    while i < s.len() {
        let mut r: rune = torune(s[i]);
        let mut width: usize = 1;
        if s[i] >= crate::unicode::utf8::RuneSelf {
            let (dr, dw) = crate::unicode::utf8::DecodeRune(&s[i..]);
            r = dr;
            width = dw as usize;
        }
        if width == 1 && r == crate::unicode::utf8::RuneError {
            buf.extend_from_slice(b"\\x");
            buf.push(lowerhex[(s[i] >> 4) as usize]);
            buf.push(lowerhex[(s[i] & 0xF) as usize]);
            i += width;
            continue;
        }
        appendEscapedRune(buf, r, quote, ASCIIonly, graphicOnly);
        i += width;
    }
    buf.push(quote);
}

// go: sdk 1.25.5 strconv/quote.go:58-66 appendQuotedRuneWith
fn appendQuotedRuneWith(
    buf: &mut Vec<byte>,
    r: rune,
    quote: byte,
    ASCIIonly: bool,
    graphicOnly: bool,
) {
    buf.push(quote);
    let mut r = r;
    if !crate::unicode::utf8::ValidRune(r) {
        r = crate::unicode::utf8::RuneError;
    }
    appendEscapedRune(buf, r, quote, ASCIIonly, graphicOnly);
    buf.push(quote);
}

// go: sdk 1.25.5 strconv/quote.go:68-119 appendEscapedRune
fn appendEscapedRune(
    buf: &mut Vec<byte>,
    r: rune,
    quote: byte,
    ASCIIonly: bool,
    graphicOnly: bool,
) {
    if r == torune(quote) || r == torune(b'\\') {
        // always backslashed
        buf.push(b'\\');
        buf.push(tobyte(r));
        return;
    }
    let mut r = r;
    if ASCIIonly {
        if r < torune(crate::unicode::utf8::RuneSelf) && IsPrint(r) {
            buf.push(tobyte(r));
            return;
        }
    } else if IsPrint(r) || (graphicOnly && isInGraphicList(r)) {
        let mut tmp = [0u8; 4];
        let n = crate::unicode::utf8::EncodeRune(&mut tmp, r) as usize;
        buf.extend_from_slice(&tmp[..n]);
        return;
    }
    match r {
        0x07 => buf.extend_from_slice(b"\\a"),
        0x08 => buf.extend_from_slice(b"\\b"),
        0x0C => buf.extend_from_slice(b"\\f"),
        0x0A => buf.extend_from_slice(b"\\n"),
        0x0D => buf.extend_from_slice(b"\\r"),
        0x09 => buf.extend_from_slice(b"\\t"),
        0x0B => buf.extend_from_slice(b"\\v"),
        _ => {
            if r < torune(b' ') || r == 0x7F {
                buf.extend_from_slice(b"\\x");
                buf.push(lowerhex[(tobyte(r) >> 4) as usize]);
                buf.push(lowerhex[(tobyte(r) & 0xF) as usize]);
            } else {
                // Go writes this as a `case !utf8.ValidRune(r)` that
                // falls through into the `r < 0x10000` case.
                if !crate::unicode::utf8::ValidRune(r) {
                    r = 0xFFFD;
                }
                if r < 0x10000 {
                    buf.extend_from_slice(b"\\u");
                    let mut sh: i32 = 12;
                    while sh >= 0 {
                        buf.push(lowerhex[((r >> sh) & 0xF) as usize]);
                        sh -= 4;
                    }
                } else {
                    buf.extend_from_slice(b"\\U");
                    let mut sh: i32 = 28;
                    while sh >= 0 {
                        buf.push(lowerhex[((r >> sh) & 0xF) as usize]);
                        sh -= 4;
                    }
                }
            }
        }
    }
}

// ─── Quote and its family ─────────────────────────────────────────────

// go: sdk 1.25.5 strconv/quote.go:125-127 Quote
/// `strconv.Quote(s)` — a double-quoted Go string literal representing
/// `s`, using Go escape sequences (`\t`, `\n`, `\xFF`, `Ā`) for
/// control and non-printable characters as defined by [`IsPrint`].
pub fn Quote<S: Into<string>>(s: S) -> string {
    let s = s.into();
    return quoteWith(s.as_bytes(), b'"', false, false);
}

// go: sdk 1.25.5 strconv/quote.go:131-133 AppendQuote
/// `strconv.AppendQuote(dst, s)` — append the quoted-string form of
/// `s` to `dst` and return the extended buffer.
pub fn AppendQuote<S: Into<string>>(dst: slice<byte>, s: S) -> slice<byte> {
    let s = s.into();
    let mut v = dst.__into_vec();
    appendQuotedWith(&mut v, s.as_bytes(), b'"', false, false);
    return slice::__from_vec(v);
}

// go: sdk 1.25.5 strconv/quote.go:138-140 QuoteToASCII
/// `strconv.QuoteToASCII(s)` — like [`Quote`], but escaping every
/// non-ASCII character.
pub fn QuoteToASCII<S: Into<string>>(s: S) -> string {
    let s = s.into();
    return quoteWith(s.as_bytes(), b'"', true, false);
}

// go: sdk 1.25.5 strconv/quote.go:144-146 AppendQuoteToASCII
/// `strconv.AppendQuoteToASCII(dst, s)` — append the ASCII-quoted form
/// of `s` to `dst` and return the extended buffer.
pub fn AppendQuoteToASCII<S: Into<string>>(dst: slice<byte>, s: S) -> slice<byte> {
    let s = s.into();
    let mut v = dst.__into_vec();
    appendQuotedWith(&mut v, s.as_bytes(), b'"', true, false);
    return slice::__from_vec(v);
}

// go: sdk 1.25.5 strconv/quote.go:152-154 QuoteToGraphic
/// `strconv.QuoteToGraphic(s)` — like [`Quote`], but leaving Unicode
/// graphic characters (as defined by [`IsGraphic`]) unescaped.
pub fn QuoteToGraphic<S: Into<string>>(s: S) -> string {
    let s = s.into();
    return quoteWith(s.as_bytes(), b'"', false, true);
}

// go: sdk 1.25.5 strconv/quote.go:158-160 AppendQuoteToGraphic
/// `strconv.AppendQuoteToGraphic(dst, s)` — append the graphic-quoted
/// form of `s` to `dst` and return the extended buffer.
pub fn AppendQuoteToGraphic<S: Into<string>>(dst: slice<byte>, s: S) -> slice<byte> {
    let s = s.into();
    let mut v = dst.__into_vec();
    appendQuotedWith(&mut v, s.as_bytes(), b'"', false, true);
    return slice::__from_vec(v);
}

// go: sdk 1.25.5 strconv/quote.go:167-169 QuoteRune
/// `strconv.QuoteRune(r)` — a single-quoted Go character literal
/// representing `r`.
pub fn QuoteRune(r: rune) -> string {
    return quoteRuneWith(r, b'\'', false, false);
}

// go: sdk 1.25.5 strconv/quote.go:173-175 AppendQuoteRune
/// `strconv.AppendQuoteRune(dst, r)` — append the QuoteRune form of
/// `r` to `dst` and return the extended buffer.
pub fn AppendQuoteRune(dst: slice<byte>, r: rune) -> slice<byte> {
    let mut v = dst.__into_vec();
    appendQuotedRuneWith(&mut v, r, b'\'', false, false);
    return slice::__from_vec(v);
}

// go: sdk 1.25.5 strconv/quote.go:183-185 QuoteRuneToASCII
/// `strconv.QuoteRuneToASCII(r)` — like [`QuoteRune`], but escaping
/// every non-ASCII character.
pub fn QuoteRuneToASCII(r: rune) -> string {
    return quoteRuneWith(r, b'\'', true, false);
}

// go: sdk 1.25.5 strconv/quote.go:189-191 AppendQuoteRuneToASCII
/// `strconv.AppendQuoteRuneToASCII(dst, r)` — append the
/// QuoteRuneToASCII form of `r` to `dst`.
pub fn AppendQuoteRuneToASCII(dst: slice<byte>, r: rune) -> slice<byte> {
    let mut v = dst.__into_vec();
    appendQuotedRuneWith(&mut v, r, b'\'', true, false);
    return slice::__from_vec(v);
}

// go: sdk 1.25.5 strconv/quote.go:199-201 QuoteRuneToGraphic
/// `strconv.QuoteRuneToGraphic(r)` — like [`QuoteRune`], but leaving
/// Unicode graphic characters (as defined by [`IsGraphic`]) unescaped.
pub fn QuoteRuneToGraphic(r: rune) -> string {
    return quoteRuneWith(r, b'\'', false, true);
}

// go: sdk 1.25.5 strconv/quote.go:205-207 AppendQuoteRuneToGraphic
/// `strconv.AppendQuoteRuneToGraphic(dst, r)` — append the
/// QuoteRuneToGraphic form of `r` to `dst`.
pub fn AppendQuoteRuneToGraphic(dst: slice<byte>, r: rune) -> slice<byte> {
    let mut v = dst.__into_vec();
    appendQuotedRuneWith(&mut v, r, b'\'', false, true);
    return slice::__from_vec(v);
}

// go: sdk 1.25.5 strconv/quote.go:499-511 bsearch
/// Go's is generic over `~[]E` with `E` a `~uint16 | ~uint32`; goish
/// takes the two element types through one `PartialOrd` bound.
fn bsearch<E: PartialOrd + Copy>(s: &[E], v: E) -> (usize, bool) {
    let n = s.len();
    let mut i: usize = 0;
    let mut j: usize = n;
    while i < j {
        let h = i + (j - i) / 2;
        if s[h] < v {
            i = h + 1;
        } else {
            j = h;
        }
    }
    return (i, i < n && s[i] == v);
}

// go: sdk 1.25.5 strconv/quote.go:522-563 IsPrint
/// `strconv.IsPrint(r)` — reports whether the rune is defined as
/// printable by Go, with the same definition as `unicode.IsPrint`:
/// letters, numbers, punctuation, symbols and ASCII space.
///
/// The four range tables this binary-searches live in `isprint.rs`,
/// transcribed from Go's generated `isprint.go`.
pub fn IsPrint(r: rune) -> bool {
    // Fast check for Latin-1
    if r <= 0xFF {
        if 0x20 <= r && r <= 0x7E {
            // All the ASCII is printable from space through DEL-1.
            return true;
        }
        if 0xA1 <= r && r <= 0xFF {
            // Similarly for ¡ through ÿ...
            return r != 0xAD; // ...except for the bizarre soft hyphen.
        }
        return false;
    }

    // Same algorithm, either on uint16 or uint32 value.
    // First, find first i such that isPrint[i] >= x.
    // This is the index of either the start or end of a pair that might span x.
    // The start is even (isPrint[i&^1]) and the end is odd (isPrint[i|1]).
    // If we find x in a range, make sure x is not in isNotPrint list.

    if 0 <= r && r < 1 << 16 {
        let rr = touint16(r);
        let isPrint = super::isprint::isPrint16;
        let isNotPrint = super::isprint::isNotPrint16;
        let (i, _) = bsearch(isPrint, rr);
        if i >= isPrint.len() || rr < isPrint[i & !1] || isPrint[i | 1] < rr {
            return false;
        }
        let (_, found) = bsearch(isNotPrint, rr);
        return !found;
    }

    let rr = touint32(r);
    let isPrint = super::isprint::isPrint32;
    let isNotPrint = super::isprint::isNotPrint32;
    let (i, _) = bsearch(isPrint, rr);
    if i >= isPrint.len() || rr < isPrint[i & !1] || isPrint[i | 1] < rr {
        return false;
    }
    if r >= 0x20000 {
        return true;
    }
    let r = r - 0x10000;
    let (_, found) = bsearch(isNotPrint, touint16(r));
    return !found;
}

// go: sdk 1.25.5 strconv/quote.go:568-573 IsGraphic
/// `strconv.IsGraphic(r)` — reports whether the rune is defined as a
/// Graphic by Unicode: letters, marks, numbers, punctuation, symbols
/// and spaces, from categories L, M, N, P, S and Zs.
pub fn IsGraphic(r: rune) -> bool {
    if IsPrint(r) {
        return true;
    }
    return isInGraphicList(r);
}

// go: sdk 1.25.5 strconv/quote.go:578-585 isInGraphicList
/// Reports whether the rune is in the `isGraphic` list. This separation
/// from `IsGraphic` lets `quoteWith` avoid two calls to `IsPrint`.
/// Should be called only if `IsPrint` fails.
fn isInGraphicList(r: rune) -> bool {
    // We know r must fit in 16 bits - see makeisprint.go.
    if r > 0xFFFF {
        return false;
    }
    let (_, found) = bsearch(super::isprint::isGraphic, touint16(r));
    return found;
}

// go: sdk 1.25.5 strconv/quote.go:212-230 CanBackquote
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
        if (r < torune(b' ') && r != torune(b'\t')) || r == torune(b'`') || r == 0x7F {
            return false;
        }
        i += 1;
    }
    return true;
}

// go: sdk 1.25.5 strconv/quote.go:232-243 unhex
// Go: quote.go:232
//   func unhex(b byte) (v rune, ok bool) { ... }
fn unhex(b: byte) -> (rune, bool) {
    let c = torune(b);
    if c >= torune(b'0') && c <= torune(b'9') {
        return (c - torune(b'0'), true);
    }
    if c >= torune(b'a') && c <= torune(b'f') {
        return (c - torune(b'a') + 10, true);
    }
    if c >= torune(b'A') && c <= torune(b'F') {
        return (c - torune(b'A') + 10, true);
    }
    return (0, false);
}

// go: sdk 1.25.5 strconv/quote.go:259-368 UnquoteChar
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
        return (torune(c), false, tail, nil);
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
            let mut v: rune = (torune(esc)) - torune(b'0');
            if tail_bs.len() < 2 {
                return (0, false, string::new(), ErrSyntax.into());
            }
            for j in 0..2 {
                let x: rune = (torune(tail_bs[j])) - torune(b'0');
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
        b'\\' => value = torune(b'\\'),
        // Go: case '\'', '"':
        b'\'' | b'"' => {
            if esc != quote {
                return (0, false, string::new(), ErrSyntax.into());
            }
            value = torune(esc);
        }
        _ => return (0, false, string::new(), ErrSyntax.into()),
    }
    let tail = string::from_bytes(tail_bs);
    return (value, multibyte, tail, nil);
}

// go: sdk 1.25.5 strconv/quote.go:390-494 unquote
/// `unquote` decodes the quoted string or character literal prefixed
/// at the start of `in`, returning the decoded value, the remainder of
/// `in` after the literal, and any error. `unescape` selects whether
/// the returned value is the decoded text or the literal itself.
fn unquote(in_s: string, unescape: bool) -> (string, string, error) {
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

    return match quote {
        b'`' => {
            // Go: case '`': switch { case !unescape: out = in[:end] ... }
            let out: string;
            if !unescape {
                out = string::from_bytes(&in_bs[..end]);
            } else if !contains(&in_bs[..end], b'\r') {
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
            let has_bs = contains(head, b'\\');
            let has_nl = contains(head, b'\n');
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
                    if r < torune(crate::unicode::utf8::RuneSelf) || !multibyte {
                        buf.push(tobyte(r));
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
    };
}

// go: sdk 1.25.5 strconv/quote.go:372-375 QuotedPrefix
/// `strconv.QuotedPrefix(s)` (quote.go:372) — returns the quoted
/// string at the prefix of `s` (as understood by [`Unquote`]).
/// If `s` does not start with a valid quoted string, returns an
/// `ErrSyntax` error.
pub fn QuotedPrefix<S: Into<string>>(s: S) -> (string, error) {
    // Go: out, _, err := unquote(s, false); return out, err
    let (out, _rem, err) = unquote(s.into(), false);
    return (out, err);
}

// go: sdk 1.25.5 strconv/quote.go:383-389 Unquote
/// `strconv.Unquote(s)` (quote.go:383) — interprets `s` as a single-,
/// double-, or backquoted Go string literal, returning the string
/// value that `s` quotes. Single-quoted literals decode as a one-rune
/// string (or empty if the rune is a single byte).
pub fn Unquote<S: Into<string>>(s: S) -> (string, error) {
    // Go: out, rem, err := unquote(s, true)
    //     if len(rem) > 0 { return "", ErrSyntax }
    //     return out, err
    let (out, rem, err) = unquote(s.into(), true);
    if rem.as_bytes().len() > 0 {
        return (string::new(), ErrSyntax.into());
    }
    return (out, err);
}
