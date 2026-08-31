// go: file bytes/bytes.go decls: ToUpper, ToLower, ToTitle, makeASCIISet, asciiSet.contains, Trim, TrimLeft, trimLeftByte, trimLeftASCII, trimLeftUnicode, TrimRight, trimRightByte, trimRightASCII, trimRightUnicode, TrimSpace, TrimPrefix, TrimSuffix, containsRune, ToUpperSpecial, ToLowerSpecial, ToTitleSpecial
//
// goishlint:ignore GOISH018 — bytes.go is 1450 lines and this file
//     carries the part of it that has been anchored so far: the cutset
//     trim family, its `asciiSet`, and the three SpecialCase mappings.
//     The rest of bytes.go's surface is ported and exported from the
//     module root, unanchored, and moves here a piece at a time.
//
// goishlint:ignore GOISH021 asciiSpace, errBufferFull, maxInt — the byte array
//     `is_ascii_space` spells as a match, and two sentinels belonging
//     to the part of bytes.go that has not moved here yet.
//
// bytes/bytes.go — the cutset trim family and the special-case
// mappings.
//
// Go's cutset is a `string`, and it is decoded as RUNES: `Trim(s,
// "é")` strips the two-byte é, not the bytes 0xC3 and 0xA9 wherever
// they turn up. `Trim`, `TrimLeft` and `TrimRight` all dispatch the
// same three ways on its shape — a one-byte ASCII cutset is a byte
// comparison, an all-ASCII cutset becomes a 128-bit bitmap tested with
// a shift and an and, and only a cutset holding a non-ASCII rune pays
// for decoding.
//
// Go returns nil rather than an empty slice whenever the result is
// empty, with the comment "This is what we've historically done." A
// goish `slice<byte>` is never literally nil — `s == nil` reports
// `len == 0` — so that distinction has nothing to attach to here and
// the empty slice is the whole of it.

#![allow(non_snake_case, non_camel_case_types, non_upper_case_globals)]

extern crate alloc;
use alloc::vec::Vec;

use crate::goslice::slice;
use crate::types::{byte, rune};
use crate::unicode::utf8;

use super::{is_ascii_space, Map};

// go: sdk 1.25.5 bytes/bytes.go:946-958 asciiSet
/// A 32-byte value used as a set for ASCII characters.
///
/// The 128 bits of the lower 16 bytes map to the 128 ASCII characters;
/// the upper 16 are zeroed, so any non-ASCII byte reports as not in the
/// set. Go keeps all 32 to avoid a bounds check in `contains`.
#[derive(Copy, Clone, Default)]
struct asciiSet([u32; 8]);

// go: sdk 1.25.5 bytes/bytes.go:960-970 makeASCIISet
/// A set of ASCII characters, and whether every character in `chars`
/// was ASCII.
fn makeASCIISet(chars: &[byte]) -> (asciiSet, bool) {
    let mut as_ = asciiSet([0; 8]);
    let mut i = 0usize;
    while i < chars.len() {
        let c = chars[i];
        if c >= utf8::RuneSelf {
            return (as_, false);
        }
        as_.0[(c / 32) as usize] |= 1 << (c % 32);
        i += 1;
    }
    return (as_, true);
}

impl asciiSet {
    // go: sdk 1.25.5 bytes/bytes.go:974-976 asciiSet.contains
    /// Whether `c` is inside the set.
    fn contains(&self, c: byte) -> bool {
        return (self.0[(c / 32) as usize] & (1 << (c % 32))) != 0;
    }
}

// go: none — goish idiom: Go's trim helpers call `containsRune(cutset
//     string, r rune)`, declared in bytes.go over a string. goish's
//     cutset arrives as borrowed bytes, so the same scan is spelled
//     over `&[u8]`.
fn containsRune(cutset: &[byte], r: rune) -> bool {
    let mut i = 0usize;
    while i < cutset.len() {
        let (cr, n) = utf8::DecodeRune(&cutset[i..]);
        if cr == r {
            return true;
        }
        i += n as usize;
    }
    return false;
}

// go: sdk 1.25.5 bytes/bytes.go:1119-1155 TrimSpace
/// A subslice of `s` with all leading and trailing white space removed,
/// as defined by Unicode.
pub fn TrimSpace<S: Into<slice<byte>>>(s: S) -> slice<byte> {
    let s: slice<byte> = s.into();
    let raw: &[byte] = &s;
    let mut start = 0usize;
    while start < raw.len() && raw[start] < utf8::RuneSelf && is_ascii_space(raw[start]) {
        start += 1;
    }
    let mut stop = raw.len();
    while stop > start && raw[stop - 1] < utf8::RuneSelf && is_ascii_space(raw[stop - 1]) {
        stop -= 1;
    }
    if start == 0 && stop == raw.len() {
        return s;
    }
    return slice::__from_vec(raw[start..stop].to_vec());
}

// go: sdk 1.25.5 bytes/bytes.go:990-1006 Trim
/// A subslice of `s` with all leading and trailing UTF-8-encoded code
/// points contained in `cutset` removed.
pub fn Trim<S1: Into<slice<byte>>, S2: Into<slice<byte>>>(s: S1, cutset: S2) -> slice<byte> {
    let s: slice<byte> = s.into();
    let cutset: slice<byte> = cutset.into();
    let sb: &[byte] = &s;
    let cb: &[byte] = &cutset;
    if sb.is_empty() || cb.is_empty() {
        return s;
    }
    if cb.len() == 1 && cb[0] < utf8::RuneSelf {
        return slice::__from_vec(trimLeftByte(trimRightByte(sb, cb[0]), cb[0]).to_vec());
    }
    let (as_, ok) = makeASCIISet(cb);
    if ok {
        return slice::__from_vec(trimLeftASCII(trimRightASCII(sb, &as_), &as_).to_vec());
    }
    return slice::__from_vec(trimLeftUnicode(trimRightUnicode(sb, cb), cb).to_vec());
}

// go: sdk 1.25.5 bytes/bytes.go:1008-1026 TrimLeft
/// A subslice of `s` with all leading UTF-8-encoded code points
/// contained in `cutset` removed.
pub fn TrimLeft<S1: Into<slice<byte>>, S2: Into<slice<byte>>>(s: S1, cutset: S2) -> slice<byte> {
    let s: slice<byte> = s.into();
    let cutset: slice<byte> = cutset.into();
    let sb: &[byte] = &s;
    let cb: &[byte] = &cutset;
    if sb.is_empty() || cb.is_empty() {
        return s;
    }
    if cb.len() == 1 && cb[0] < utf8::RuneSelf {
        return slice::__from_vec(trimLeftByte(sb, cb[0]).to_vec());
    }
    let (as_, ok) = makeASCIISet(cb);
    if ok {
        return slice::__from_vec(trimLeftASCII(sb, &as_).to_vec());
    }
    return slice::__from_vec(trimLeftUnicode(sb, cb).to_vec());
}

// go: sdk 1.25.5 bytes/bytes.go:1028-1037 trimLeftByte
// goishlint:ignore GOISH014 — the anchor names Go's `trimLeftByte`.
//     Go's takes and returns a `[]byte`, which is a view; the six trim
//     helpers here take and return `&[u8]` so the whole dispatch runs
//     without allocating, and only the public entry point builds a
//     `slice<byte>`.
fn trimLeftByte(s: &[byte], c: byte) -> &[byte] {
    let mut s = s;
    while !s.is_empty() && s[0] == c {
        s = &s[1..];
    }
    return s;
}

// go: sdk 1.25.5 bytes/bytes.go:1039-1051 trimLeftASCII
// goishlint:ignore GOISH014 — see `trimLeftByte`.
fn trimLeftASCII<'a>(s: &'a [byte], as_: &asciiSet) -> &'a [byte] {
    let mut s = s;
    while !s.is_empty() {
        if !as_.contains(s[0]) {
            break;
        }
        s = &s[1..];
    }
    return s;
}

// go: sdk 1.25.5 bytes/bytes.go:1053-1071 trimLeftUnicode
// goishlint:ignore GOISH014 — see `trimLeftByte`.
fn trimLeftUnicode<'a>(s: &'a [byte], cutset: &[byte]) -> &'a [byte] {
    let mut s = s;
    while !s.is_empty() {
        let (mut r, mut n) = (crate::convert::rune(s[0]), 1usize);
        if r >= crate::convert::rune(utf8::RuneSelf) {
            let (r2, n2) = utf8::DecodeRune(s);
            r = r2;
            n = n2 as usize;
        }
        if !containsRune(cutset, r) {
            break;
        }
        s = &s[n..];
    }
    return s;
}

// go: sdk 1.25.5 bytes/bytes.go:1073-1084 TrimRight
/// A subslice of `s` with all trailing UTF-8-encoded code points
/// contained in `cutset` removed.
pub fn TrimRight<S1: Into<slice<byte>>, S2: Into<slice<byte>>>(s: S1, cutset: S2) -> slice<byte> {
    let s: slice<byte> = s.into();
    let cutset: slice<byte> = cutset.into();
    let sb: &[byte] = &s;
    let cb: &[byte] = &cutset;
    if sb.is_empty() || cb.is_empty() {
        return s;
    }
    if cb.len() == 1 && cb[0] < utf8::RuneSelf {
        return slice::__from_vec(trimRightByte(sb, cb[0]).to_vec());
    }
    let (as_, ok) = makeASCIISet(cb);
    if ok {
        return slice::__from_vec(trimRightASCII(sb, &as_).to_vec());
    }
    return slice::__from_vec(trimRightUnicode(sb, cb).to_vec());
}

// go: sdk 1.25.5 bytes/bytes.go:1086-1091 trimRightByte
// goishlint:ignore GOISH014 — see `trimLeftByte`.
fn trimRightByte(s: &[byte], c: byte) -> &[byte] {
    let mut s = s;
    while !s.is_empty() && s[s.len() - 1] == c {
        s = &s[..s.len() - 1];
    }
    return s;
}

// go: sdk 1.25.5 bytes/bytes.go:1093-1101 trimRightASCII
// goishlint:ignore GOISH014 — see `trimLeftByte`.
fn trimRightASCII<'a>(s: &'a [byte], as_: &asciiSet) -> &'a [byte] {
    let mut s = s;
    while !s.is_empty() {
        if !as_.contains(s[s.len() - 1]) {
            break;
        }
        s = &s[..s.len() - 1];
    }
    return s;
}

// go: sdk 1.25.5 bytes/bytes.go:1103-1115 trimRightUnicode
// goishlint:ignore GOISH014 — see `trimLeftByte`.
fn trimRightUnicode<'a>(s: &'a [byte], cutset: &[byte]) -> &'a [byte] {
    let mut s = s;
    while !s.is_empty() {
        let (mut r, mut n) = (crate::convert::rune(s[s.len() - 1]), 1usize);
        if r >= crate::convert::rune(utf8::RuneSelf) {
            let (r2, n2) = utf8::DecodeLastRune(s);
            r = r2;
            n = n2 as usize;
        }
        if !containsRune(cutset, r) {
            break;
        }
        s = &s[..s.len() - n];
    }
    return s;
}

// go: sdk 1.25.5 bytes/bytes.go:884-889 TrimPrefix
/// `s` without the provided leading `prefix`, or `s` unchanged if it
/// does not start with it.
pub fn TrimPrefix<S1: Into<slice<byte>>, S2: Into<slice<byte>>>(s: S1, prefix: S2) -> slice<byte> {
    let s: slice<byte> = s.into();
    let prefix: slice<byte> = prefix.into();
    let sb: &[byte] = &s;
    let pb: &[byte] = &prefix;
    if super::HasPrefix(s.clone(), prefix.clone()) {
        return slice::__from_vec(sb[pb.len()..].to_vec());
    }
    return s;
}

// go: sdk 1.25.5 bytes/bytes.go:893-898 TrimSuffix
/// `s` without the provided trailing `suffix`, or `s` unchanged if it
/// does not end with it.
pub fn TrimSuffix<S1: Into<slice<byte>>, S2: Into<slice<byte>>>(s: S1, suffix: S2) -> slice<byte> {
    let s: slice<byte> = s.into();
    let suffix: slice<byte> = suffix.into();
    let sb: &[byte] = &s;
    let fb: &[byte] = &suffix;
    if super::HasSuffix(s.clone(), suffix.clone()) {
        return slice::__from_vec(sb[..sb.len() - fb.len()].to_vec());
    }
    return s;
}

// go: sdk 1.25.5 bytes/bytes.go:761-763 ToUpperSpecial
/// A copy of `s` with every Unicode letter mapped to its upper case
/// using the case mapping specified by `c`.
pub fn ToUpperSpecial<S: Into<slice<byte>>>(c: crate::unicode::SpecialCase, s: S) -> slice<byte> {
    return Map(move |r| c.ToUpper(r), s);
}

// go: sdk 1.25.5 bytes/bytes.go:765-771 ToLowerSpecial
/// A copy of `s` with every Unicode letter mapped to its lower case
/// using the case mapping specified by `c`.
pub fn ToLowerSpecial<S: Into<slice<byte>>>(c: crate::unicode::SpecialCase, s: S) -> slice<byte> {
    return Map(move |r| c.ToLower(r), s);
}

// go: sdk 1.25.5 bytes/bytes.go:773-775 ToTitleSpecial
/// A copy of `s` with every Unicode letter mapped to its title case,
/// giving priority to the special casing rules in `c`.
pub fn ToTitleSpecial<S: Into<slice<byte>>>(c: crate::unicode::SpecialCase, s: S) -> slice<byte> {
    return Map(move |r| c.ToTitle(r), s);
}

// go: sdk 1.25.5 bytes/bytes.go:697-724 ToUpper
/// A copy of `s` with all Unicode letters mapped to their upper case.
///
/// This had been ASCII-only: the loop upper-cased 'a'..'z' and passed
/// every byte at or above 0x80 through untouched, so `ToUpper("café")`
/// came back "CAFé". Go takes the ASCII fast path only when the WHOLE
/// slice is ASCII, and otherwise maps rune-wise through
/// `unicode.ToUpper`.
pub fn ToUpper<S: Into<slice<byte>>>(s: S) -> slice<byte> {
    let s: slice<byte> = s.into();
    let raw: &[byte] = &s;
    let mut isASCII = true;
    let mut hasLower = false;
    let mut i = 0usize;
    while i < raw.len() {
        let c = raw[i];
        if c >= utf8::RuneSelf {
            isASCII = false;
            break;
        }
        hasLower = hasLower || (b'a' <= c && c <= b'z');
        i += 1;
    }
    if isASCII {
        // Go optimizes for ASCII-only byte slices, and returns a COPY
        // even when nothing changes — the caller may write into it.
        if !hasLower {
            return slice::__from_vec(raw.to_vec());
        }
        let mut v: Vec<byte> = Vec::with_capacity(raw.len());
        for &c in raw {
            if b'a' <= c && c <= b'z' {
                v.push(c - (b'a' - b'A'));
            } else {
                v.push(c);
            }
        }
        return slice::__from_vec(v);
    }
    return Map(crate::unicode::ToUpper, s);
}

// go: sdk 1.25.5 bytes/bytes.go:728-754 ToLower
/// A copy of `s` with all Unicode letters mapped to their lower case.
/// Same ASCII-only defect as [`ToUpper`], same fix.
pub fn ToLower<S: Into<slice<byte>>>(s: S) -> slice<byte> {
    let s: slice<byte> = s.into();
    let raw: &[byte] = &s;
    let mut isASCII = true;
    let mut hasUpper = false;
    let mut i = 0usize;
    while i < raw.len() {
        let c = raw[i];
        if c >= utf8::RuneSelf {
            isASCII = false;
            break;
        }
        hasUpper = hasUpper || (b'A' <= c && c <= b'Z');
        i += 1;
    }
    if isASCII {
        if !hasUpper {
            return slice::__from_vec(raw.to_vec());
        }
        let mut v: Vec<byte> = Vec::with_capacity(raw.len());
        for &c in raw {
            if b'A' <= c && c <= b'Z' {
                v.push(c + (b'a' - b'A'));
            } else {
                v.push(c);
            }
        }
        return slice::__from_vec(v);
    }
    return Map(crate::unicode::ToLower, s);
}

// go: sdk 1.25.5 bytes/bytes.go:757-757 ToTitle
/// `s` treated as UTF-8, with all Unicode letters mapped to their
/// title case.
///
/// The note that used to sit here said non-ASCII bytes "pass through
/// unchanged". They do not any more: `unicode::ToTitle` runs on Go's
/// `CaseRanges`, so U+01C4 maps to U+01C5.
pub fn ToTitle<S: Into<slice<byte>>>(s: S) -> slice<byte> {
    // Go: return Map(unicode.ToTitle, s)
    return Map(crate::unicode::ToTitle, s);
}
