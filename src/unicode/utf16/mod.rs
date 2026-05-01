// unicode/utf16 — Go's `unicode/utf16`, ported.
//
// Translates between UTF-16 16-bit-word sequences and Unicode code
// points (`rune` = i32). Follows Go's API surface line-for-line:
//
//   Go                                     goish
//   ────────────────────────────────────   ────────────────────────────────────
//   utf16.IsSurrogate(r)                   utf16::IsSurrogate(r)
//   utf16.DecodeRune(r1, r2)               utf16::DecodeRune(r1, r2)
//   r1, r2 := utf16.EncodeRune(r)          let (r1, r2) = utf16::EncodeRune(r);
//   utf16.RuneLen(r)                       utf16::RuneLen(r)
//   a := utf16.Encode(s)                   let a = utf16::Encode(s);
//   r := utf16.Decode(a)                   let r = utf16::Decode(a);
//   a = utf16.AppendRune(a, r)             let a = utf16::AppendRune(a, r);
//
// `[]uint16` is exposed as `slice<u16>`. Single-rune scalars use the
// existing `rune` (i32) alias — same as Go's `rune` = `int32`.

#![allow(non_snake_case, non_upper_case_globals)]

use crate::goslice::slice;
use crate::types::{int, rune};

extern crate alloc;
use alloc::vec::Vec;

// ─── Private constants (Go: utf16.go:13–26) ────────────────────────────

// Go: replacementChar = '�'
const replacementChar: rune = 0xFFFD;
// Go: maxRune = '\U0010FFFF'
const maxRune: rune = 0x0010FFFF;

// Go: surr1 = 0xd800; surr2 = 0xdc00; surr3 = 0xe000
const surr1: rune = 0xd800;
const surr2: rune = 0xdc00;
const surr3: rune = 0xe000;

// Go: surrSelf = 0x10000
const surrSelf: rune = 0x10000;

// ─── Public API ────────────────────────────────────────────────────────

/// `utf16.IsSurrogate(r)` (utf16.go:30) — report whether the specified
/// Unicode code point can appear in a surrogate pair.
pub fn IsSurrogate(r: rune) -> bool {
    // Go: return surr1 <= r && r < surr3
    surr1 <= r && r < surr3
}

/// `utf16.DecodeRune(r1, r2)` (utf16.go:37) — return the UTF-16
/// decoding of a surrogate pair. If the pair is not a valid UTF-16
/// surrogate pair, DecodeRune returns the Unicode replacement code
/// point U+FFFD.
pub fn DecodeRune(r1: rune, r2: rune) -> rune {
    // Go: if surr1 <= r1 && r1 < surr2 && surr2 <= r2 && r2 < surr3
    if surr1 <= r1 && r1 < surr2 && surr2 <= r2 && r2 < surr3 {
        // Go: return (r1-surr1)<<10 | (r2 - surr2) + surrSelf
        return ((r1 - surr1) << 10) | (r2 - surr2) + surrSelf;
    }
    // Go: return replacementChar
    replacementChar
}

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
    (surr1 + ((r >> 10) & 0x3ff), surr2 + (r & 0x3ff))
}

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
    -1
}

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
                a[i] = *v as u16;
                i += 1;
            }
            // Go: case 2: r1, r2 := EncodeRune(v); a[n] = uint16(r1); a[n+1] = uint16(r2); n += 2
            2 => {
                let (r1, r2) = EncodeRune(*v);
                a[i] = r1 as u16;
                a[i + 1] = r2 as u16;
                i += 2;
            }
            // Go: default: a[n] = uint16(replacementChar); n++
            _ => {
                a[i] = replacementChar as u16;
                i += 1;
            }
        }
    }
    // Go: return a[:n]
    a.truncate(i);
    slice::__from_vec(a)
}

/// `utf16.AppendRune(a, r)` (utf16.go:100) — append the UTF-16
/// encoding of the Unicode code point r to the end of `a` and return
/// the extended buffer. If the rune is not a valid Unicode code point,
/// it appends the encoding of U+FFFD.
pub fn AppendRune(a: slice<u16>, r: rune) -> slice<u16> {
    // Go: switch { case 0 <= r && r < surr1, surr3 <= r && r < surrSelf:
    //     return append(a, uint16(r))
    if (0 <= r && r < surr1) || (surr3 <= r && r < surrSelf) {
        let mut v: Vec<u16> = a.__into_vec();
        v.push(r as u16);
        return slice::__from_vec(v);
    }
    // Go: case surrSelf <= r && r <= maxRune:
    //     r1, r2 := EncodeRune(r); return append(a, uint16(r1), uint16(r2))
    if surrSelf <= r && r <= maxRune {
        let (r1, r2) = EncodeRune(r);
        let mut v: Vec<u16> = a.__into_vec();
        v.push(r1 as u16);
        v.push(r2 as u16);
        return slice::__from_vec(v);
    }
    // Go: return append(a, replacementChar)
    let mut v: Vec<u16> = a.__into_vec();
    v.push(replacementChar as u16);
    slice::__from_vec(v)
}

/// `utf16.Decode(s)` (utf16.go:116) — return the Unicode code point
/// sequence represented by the UTF-16 encoding s.
pub fn Decode(s: slice<u16>) -> slice<rune> {
    // Go: buf := make([]rune, 0, 64)
    let buf: Vec<rune> = Vec::with_capacity(64);
    // Go: return decode(s, buf)
    decode(s, buf)
}

// Go: utf16.go:125 — append to buf the Unicode code point sequence.
fn decode(s: slice<u16>, mut buf: Vec<rune>) -> slice<rune> {
    let raw: &[u16] = &s;
    // Go: for i := 0; i < len(s); i++
    let mut i: usize = 0;
    while i < raw.len() {
        let r: rune = raw[i] as rune;
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
            && surr2 <= raw[i + 1] as rune
            && (raw[i + 1] as rune) < surr3
        {
            // Go: ar = DecodeRune(rune(r), rune(s[i+1])); i++
            ar = DecodeRune(r, raw[i + 1] as rune);
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
    slice::__from_vec(buf)
}
