// go: file unicode/utf16/utf16.go decls: IsSurrogate, DecodeRune, EncodeRune, RuneLen, Encode, AppendRune, Decode, decode
//
// unicode/utf16/utf16.go — UTF-16 sequences.
//
// A code point above U+FFFF is carried as a *surrogate pair*: a high
// half in U+D800..U+DBFF and a low half in U+DC00..U+DFFF, which is why
// those 2048 code points are permanently unassigned. Every function
// here is about that split, and every one of them substitutes U+FFFD
// for a half that appears alone.

#![allow(non_snake_case, non_upper_case_globals)]

use crate::convert::{rune as torune, uint16 as touint16};

use crate::goslice::slice;
use crate::types::{int, rune};

extern crate alloc;
use alloc::vec::Vec;

// ─── Private constants (Go: utf16.go:13–26) ────────────────────────────

// go: sdk 1.25.5 unicode/utf16/utf16.go:12-15 replacementChar
// Go: replacementChar = '�'
const replacementChar: rune = 0xFFFD;
// go: sdk 1.25.5 unicode/utf16/utf16.go:12-15 maxRune
// Go: maxRune = '\U0010FFFF'
const maxRune: rune = 0x0010FFFF;

// go: sdk 1.25.5 unicode/utf16/utf16.go:17-26 surr1
// Go: surr1 = 0xd800; surr2 = 0xdc00; surr3 = 0xe000
const surr1: rune = 0xd800;
// go: sdk 1.25.5 unicode/utf16/utf16.go:17-26 surr2
const surr2: rune = 0xdc00;
// go: sdk 1.25.5 unicode/utf16/utf16.go:17-26 surr3
const surr3: rune = 0xe000;

// go: sdk 1.25.5 unicode/utf16/utf16.go:17-26 surrSelf
// Go: surrSelf = 0x10000
const surrSelf: rune = 0x10000;

// ─── Public API ────────────────────────────────────────────────────────

// go: sdk 1.25.5 unicode/utf16/utf16.go:30-32 IsSurrogate
/// `utf16.IsSurrogate(r)` (utf16.go:30) — report whether the specified
/// Unicode code point can appear in a surrogate pair.
pub fn IsSurrogate(r: rune) -> bool {
    // Go: return surr1 <= r && r < surr3
    return surr1 <= r && r < surr3;
}

// go: sdk 1.25.5 unicode/utf16/utf16.go:37-42 DecodeRune
/// `utf16.DecodeRune(r1, r2)` (utf16.go:37) — return the UTF-16
/// decoding of a surrogate pair. If the pair is not a valid UTF-16
/// surrogate pair, DecodeRune returns the Unicode replacement code
/// point U+FFFD.
pub fn DecodeRune(r1: rune, r2: rune) -> rune {
    // Go: if surr1 <= r1 && r1 < surr2 && surr2 <= r2 && r2 < surr3
    if surr1 <= r1 && r1 < surr2 && surr2 <= r2 && r2 < surr3 {
        // Go: return (r1-surr1)<<10 | (r2 - surr2) + surrSelf
        //
        // The parens are not decoration. In Go, `|` and `+` share the
        // additive precedence level and associate left to right, so the
        // expression is `(((r1-surr1)<<10) | (r2-surr2)) + surrSelf`.
        // Rust binds `+` tighter than `|`, so the same characters mean
        // `x | (y + surrSelf)` — which ORs the 0x10000 bit into a
        // position the shifted high half already occupies and loses it
        // for every code point from U+20000 up.
        return (((r1 - surr1) << 10) | (r2 - surr2)) + surrSelf;
    }
    // Go: return replacementChar
    return replacementChar;
}

// go: sdk 1.25.5 unicode/utf16/utf16.go:47-53 EncodeRune
/// `utf16.EncodeRune(r) -> (r1, r2)` (utf16.go:47) — return the UTF-16
/// surrogate pair r1, r2 for the given rune. If the rune is not a valid
/// Unicode code point or does not need encoding, EncodeRune returns
/// U+FFFD, U+FFFD.
pub fn EncodeRune(r: rune) -> (rune, rune) {
    // Go: if r < surrSelf || r > maxRune
    if r < surrSelf || r > maxRune {
        return (replacementChar, replacementChar);
    }
    // Go: r -= surrSelf
    let r = r - surrSelf;
    // Go: return surr1 + (r>>10)&0x3ff, surr2 + r&0x3ff
    return (surr1 + ((r >> 10) & 0x3ff), surr2 + (r & 0x3ff));
}

// go: sdk 1.25.5 unicode/utf16/utf16.go:57-66 RuneLen
/// `utf16.RuneLen(r)` (utf16.go:57) — return the number of 16-bit
/// words in the UTF-16 encoding of the rune. It returns -1 if the rune
/// is not a valid value to encode in UTF-16.
pub fn RuneLen(r: rune) -> int {
    // Go: case 0 <= r && r < surr1, surr3 <= r && r < surrSelf: return 1
    if (0 <= r && r < surr1) || (surr3 <= r && r < surrSelf) {
        return 1;
    }
    // Go: case surrSelf <= r && r <= maxRune: return 2
    if surrSelf <= r && r <= maxRune {
        return 2;
    }
    // Go: default: return -1
    return -1;
}

// go: sdk 1.25.5 unicode/utf16/utf16.go:69-95 Encode
/// `utf16.Encode(s)` (utf16.go:69) — return the UTF-16 encoding of the
/// Unicode code point sequence s.
pub fn Encode(s: slice<rune>) -> slice<u16> {
    // Go: n := len(s)
    let raw: &[rune] = &s;
    let mut n: usize = raw.len();
    // Go: for _, v := range s { if v >= surrSelf { n++ } }
    for v in raw.iter() {
        if *v >= surrSelf {
            n += 1;
        }
    }

    // Go: a := make([]uint16, n)
    let mut a: Vec<u16> = alloc::vec![0u16; n];
    // Go: n = 0
    let mut i: usize = 0;
    // Go: for _, v := range s { switch RuneLen(v) ... }
    for v in raw.iter() {
        match RuneLen(*v) {
            // Go: case 1: a[n] = uint16(v); n++
            1 => {
                a[i] = touint16(*v);
                i += 1;
            }
            // Go: case 2: r1, r2 := EncodeRune(v); a[n] = uint16(r1); a[n+1] = uint16(r2); n += 2
            2 => {
                let (r1, r2) = EncodeRune(*v);
                a[i] = touint16(r1);
                a[i + 1] = touint16(r2);
                i += 2;
            }
            // Go: default: a[n] = uint16(replacementChar); n++
            _ => {
                a[i] = touint16(replacementChar);
                i += 1;
            }
        }
    }
    // Go: return a[:n]
    a.truncate(i);
    return slice::__from_vec(a);
}

// go: sdk 1.25.5 unicode/utf16/utf16.go:100-112 AppendRune
/// `utf16.AppendRune(a, r)` (utf16.go:100) — append the UTF-16
/// encoding of the Unicode code point r to the end of `a` and return
/// the extended buffer. If the rune is not a valid Unicode code point,
/// it appends the encoding of U+FFFD.
pub fn AppendRune(a: slice<u16>, r: rune) -> slice<u16> {
    // Go: switch { case 0 <= r && r < surr1, surr3 <= r && r < surrSelf:
    //     return append(a, uint16(r))
    if (0 <= r && r < surr1) || (surr3 <= r && r < surrSelf) {
        let mut v: Vec<u16> = a.__into_vec();
        v.push(touint16(r));
        return slice::__from_vec(v);
    }
    // Go: case surrSelf <= r && r <= maxRune:
    //     r1, r2 := EncodeRune(r); return append(a, uint16(r1), uint16(r2))
    if surrSelf <= r && r <= maxRune {
        let (r1, r2) = EncodeRune(r);
        let mut v: Vec<u16> = a.__into_vec();
        v.push(touint16(r1));
        v.push(touint16(r2));
        return slice::__from_vec(v);
    }
    // Go: return append(a, replacementChar)
    let mut v: Vec<u16> = a.__into_vec();
    v.push(touint16(replacementChar));
    return slice::__from_vec(v);
}

// go: sdk 1.25.5 unicode/utf16/utf16.go:116-121 Decode
/// `utf16.Decode(s)` (utf16.go:116) — return the Unicode code point
/// sequence represented by the UTF-16 encoding s.
pub fn Decode(s: slice<u16>) -> slice<rune> {
    // Go: buf := make([]rune, 0, 64)
    let buf: Vec<rune> = Vec::with_capacity(64);
    // Go: return decode(s, buf)
    return decode(s, buf);
}

// go: sdk 1.25.5 unicode/utf16/utf16.go:125-144 decode
// Go: utf16.go:125 — append to buf the Unicode code point sequence.
fn decode(s: slice<u16>, mut buf: Vec<rune>) -> slice<rune> {
    let raw: &[u16] = &s;
    // Go: for i := 0; i < len(s); i++
    let mut i: usize = 0;
    while i < raw.len() {
        let r: rune = torune(raw[i]);
        let ar: rune;
        // Go: case r < surr1, surr3 <= r:
        if r < surr1 || surr3 <= r {
            // Go: ar = rune(r)
            ar = r;
        }
        // Go: case surr1 <= r && r < surr2 && i+1 < len(s) &&
        //          surr2 <= s[i+1] && s[i+1] < surr3:
        else if surr1 <= r
            && r < surr2
            && i + 1 < raw.len()
            && surr2 <= torune(raw[i + 1])
            && torune(raw[i + 1]) < surr3
        {
            // Go: ar = DecodeRune(rune(r), rune(s[i+1])); i++
            ar = DecodeRune(r, torune(raw[i + 1]));
            i += 1;
        } else {
            // Go: ar = replacementChar
            ar = replacementChar;
        }
        // Go: buf = append(buf, ar)
        buf.push(ar);
        i += 1;
    }
    // Go: return buf
    return slice::__from_vec(buf);
}
