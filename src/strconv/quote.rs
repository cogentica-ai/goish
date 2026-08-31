// go: file strconv/quote.go decls: Quote, AppendQuote, QuoteToASCII, AppendQuoteToASCII, QuoteToGraphic, AppendQuoteToGraphic, QuoteRune, AppendQuoteRune, QuoteRuneToASCII, AppendQuoteRuneToASCII, QuoteRuneToGraphic, AppendQuoteRuneToGraphic, IsPrint, IsGraphic, CanBackquote, unhex, UnquoteChar, QuotedPrefix, Unquote
//
// quote.go — Quote and its family, and Unquote.

extern crate alloc;
use alloc::vec::Vec;

use crate::convert::{byte as tobyte, rune as torune, uint8 as touint8};
use crate::errors::{error, nil};
use crate::goslice::slice;
use crate::gostring::string;
use crate::types::{byte, rune};

use super::*;

// ─── Quote / Unquote (slim ASCII port of strconv/quote.go) ───────────

// go: sdk 1.25.5 strconv/quote.go:125-127 Quote
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
    return string::from_bytes(&out);
}

// go: sdk 1.25.5 strconv/quote.go:131-133 AppendQuote
/// `strconv.AppendQuote(dst, s)` (quote.go:131) — append the
/// quoted-string form of `s` to `dst` and return the extended buffer.
pub fn AppendQuote<S: Into<string>>(dst: slice<byte>, s: S) -> slice<byte> {
    // Go: return appendQuotedWith(dst, s, '"', false, false)
    // Slim: just delegate to Quote() and append the bytes.
    let q = Quote(s);
    let mut v = dst.__into_vec();
    v.extend_from_slice(q.as_bytes());
    return slice::__from_vec(v);
}

// go: sdk 1.25.5 strconv/quote.go:138-140 QuoteToASCII
/// `strconv.QuoteToASCII(s)` (quote.go:138) — return a double-quoted
/// Go string literal representing `s`, escaping every non-ASCII byte
/// using `\xHH`. Slim port: the existing `Quote` already emits
/// ASCII-only output for bytes ≥ 0x80, so this delegates directly.
pub fn QuoteToASCII<S: Into<string>>(s: S) -> string {
    // Go: return quoteWith(s, '"', true, false)
    return Quote(s);
}

// go: sdk 1.25.5 strconv/quote.go:144-146 AppendQuoteToASCII
/// `strconv.AppendQuoteToASCII(dst, s)` (quote.go:144) — append the
/// ASCII-quoted form of `s` to `dst` and return the extended buffer.
pub fn AppendQuoteToASCII<S: Into<string>>(dst: slice<byte>, s: S) -> slice<byte> {
    // Go: return appendQuotedWith(dst, s, '"', true, false)
    return AppendQuote(dst, s);
}

// go: sdk 1.25.5 strconv/quote.go:152-154 QuoteToGraphic
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
    return Quote(s);
}

// go: sdk 1.25.5 strconv/quote.go:158-160 AppendQuoteToGraphic
/// `strconv.AppendQuoteToGraphic(dst, s)` (quote.go:158) — append the
/// graphic-quoted form of `s` to `dst` and return the extended buffer.
pub fn AppendQuoteToGraphic<S: Into<string>>(dst: slice<byte>, s: S) -> slice<byte> {
    // Go: return appendQuotedWith(dst, s, '"', false, true)
    return AppendQuote(dst, s);
}

// Internal helper: append the Go-escape form of a single rune with
// the given quote-byte (either `'` for QuoteRune, `"` for Quote).
// Slim: ASCII printable bytes pass through; control chars use `\x`;
// runes ≥ 0x80 always escape (`\u` < 0x10000, else `\U`).
fn append_escaped_rune(out: &mut alloc::vec::Vec<u8>, r: rune, quote: u8) {
    let lowerhex = b"0123456789abcdef";
    // Go: if r == rune(quote) || r == '\\' { ... }
    if r == torune(quote) {
        out.push(b'\\');
        out.push(quote);
        return;
    }
    if r == torune(b'\\') {
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
        out.push(touint8(r));
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

// go: sdk 1.25.5 strconv/quote.go:167-169 QuoteRune
/// `strconv.QuoteRune(r)` (quote.go:167) — return a single-quoted
/// Go character literal for `r`. Control chars and non-ASCII use
/// Go escape sequences (`\t`, `\n`, `\xFF`, `Ā`, `\U00100000`).
pub fn QuoteRune(r: rune) -> string {
    // Go: return quoteRuneWith(r, '\'', false, false)
    let mut out: alloc::vec::Vec<u8> = alloc::vec::Vec::with_capacity(8);
    out.push(b'\'');
    append_escaped_rune(&mut out, r, b'\'');
    out.push(b'\'');
    return string::from_bytes(&out);
}

// go: sdk 1.25.5 strconv/quote.go:173-175 AppendQuoteRune
/// `strconv.AppendQuoteRune(dst, r)` (quote.go:173) — append the
/// QuoteRune form of `r` to `dst` and return the extended buffer.
pub fn AppendQuoteRune(dst: slice<byte>, r: rune) -> slice<byte> {
    // Go: return appendQuotedRuneWith(dst, r, '\'', false, false)
    let q = QuoteRune(r);
    let mut v = dst.__into_vec();
    v.extend_from_slice(q.as_bytes());
    return slice::__from_vec(v);
}

// go: sdk 1.25.5 strconv/quote.go:183-185 QuoteRuneToASCII
/// `strconv.QuoteRuneToASCII(r)` (quote.go:183) — slim port: same
/// as `QuoteRune` because our slim implementation already escapes
/// non-ASCII runes.
pub fn QuoteRuneToASCII(r: rune) -> string {
    // Go: return quoteRuneWith(r, '\'', true, false)
    return QuoteRune(r);
}

// go: sdk 1.25.5 strconv/quote.go:189-191 AppendQuoteRuneToASCII
/// `strconv.AppendQuoteRuneToASCII(dst, r)` (quote.go:189) — append
/// the QuoteRuneToASCII form to `dst`.
pub fn AppendQuoteRuneToASCII(dst: slice<byte>, r: rune) -> slice<byte> {
    // Go: return appendQuotedRuneWith(dst, r, '\'', true, false)
    return AppendQuoteRune(dst, r);
}

// go: sdk 1.25.5 strconv/quote.go:199-201 QuoteRuneToGraphic
/// `strconv.QuoteRuneToGraphic(r)` (quote.go:199) — return a single-
/// quoted Go character literal. If `r` is not a Unicode graphic
/// character (per [`IsGraphic`]), the returned string uses a Go escape
/// sequence (`\t`, `\n`, `\xFF`, `Ā`).
///
/// Slim: aliases [`QuoteRune`] for the same reason that
/// [`QuoteToGraphic`] aliases [`Quote`].
pub fn QuoteRuneToGraphic(r: rune) -> string {
    // Go: return quoteRuneWith(r, '\'', false, true)
    return QuoteRune(r);
}

// go: sdk 1.25.5 strconv/quote.go:205-207 AppendQuoteRuneToGraphic
/// `strconv.AppendQuoteRuneToGraphic(dst, r)` (quote.go:205) — append
/// the QuoteRuneToGraphic form to `dst`.
pub fn AppendQuoteRuneToGraphic(dst: slice<byte>, r: rune) -> slice<byte> {
    // Go: return appendQuotedRuneWith(dst, r, '\'', false, true)
    return AppendQuoteRune(dst, r);
}

// go: sdk 1.25.5 strconv/quote.go:522-563 IsPrint
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
    return true;
}

// go: sdk 1.25.5 strconv/quote.go:568-573 IsGraphic
/// Line-by-line port of `strconv.IsGraphic(r)` (quote.go:568) — reports
/// whether `r` is defined as a Graphic by Unicode (categories L, M, N,
/// P, S, and Zs).
///
/// Slim: defers to IsPrint; upstream's `isInGraphicList` extension for
/// the U+0000..U+FFFF range needs the `isGraphic` table that goish v1
/// doesn't ship.
pub fn IsGraphic(r: crate::types::rune) -> bool {
    // Go: if IsPrint(r) { return true }; return isInGraphicList(r)
    return IsPrint(r);
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

    return match quote {
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
    let (out, _rem, err) = unquote_impl(s.into(), false);
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
    let (out, rem, err) = unquote_impl(s.into(), true);
    if rem.as_bytes().len() > 0 {
        return (string::new(), ErrSyntax.into());
    }
    return (out, err);
}
