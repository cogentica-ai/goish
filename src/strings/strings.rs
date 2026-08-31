// go: file strings/strings.go decls: Trim, TrimLeft, trimLeftByte, trimLeftASCII, trimLeftUnicode, TrimRight, trimRightByte, trimRightASCII, trimRightUnicode, TrimSpace, TrimPrefix, TrimSuffix, makeASCIISet, asciiSet.contains, ToUpperSpecial, ToLowerSpecial, ToTitleSpecial
//
// goishlint:ignore GOISH021 maxInt, asciiSpace, repeatedSpaces, repeatedDashes, repeatedZeroes, repeatedEquals, repeatedTabs — these belong
//     to the part of strings.go that has not moved here yet: `maxInt`
//     and `asciiSpace` are read by `Repeat` and `Fields`, and the four
//     `repeated*` constants are `Repeat`'s fast-path literals. They
//     move with the functions that use them.
//
// goishlint:ignore GOISH018 — strings.go is 1300 lines and this file
//     carries the part of it that has been anchored: the cutset trim
//     family, its `asciiSet`, and the three SpecialCase mappings. The
//     rest of strings.go's surface is ported and exported from the
//     module root, unanchored, and moves here a file at a time.
//
// strings/strings.go — the cutset trim family and the special-case
// mappings.
//
// `Trim`, `TrimLeft` and `TrimRight` all dispatch the same three ways
// on the shape of the cutset, and the dispatch is the whole point:
// a one-byte ASCII cutset is a byte comparison, an all-ASCII cutset
// becomes a 128-bit bitmap tested with a shift and an and, and only a
// cutset with a non-ASCII rune in it pays for decoding.

#![allow(non_snake_case, non_camel_case_types, non_upper_case_globals)]

extern crate alloc;

use crate::gostring::string;
use crate::types::{byte, rune};
use crate::unicode::utf8;

use super::{has_prefix_bytes, has_suffix_bytes, is_ascii_space, Map};

// ─── asciiSet, and the Trim family ────────────────────────────────────

// go: sdk 1.25.5 strings/strings.go:948-960 asciiSet
/// A 32-byte value used as a set for ASCII characters.
///
/// Go's comment: the 128-bits of the lower 16 bytes, starting with the
/// least-significant bit of the lowest word to the most-significant bit
/// of the highest word, map to the full range of all 128 ASCII
/// characters. The upper 16 bytes are zeroed, so any non-ASCII
/// character reports as not in the set — 32 bytes even though half is
/// unused, to avoid a bounds check in `contains`.
#[derive(Copy, Clone, Default)]
struct asciiSet([u32; 8]);

// go: sdk 1.25.5 strings/strings.go:962-972 makeASCIISet
/// A set of ASCII characters, and whether every character in `chars`
/// was ASCII.
fn makeASCIISet(chars: &[byte]) -> (asciiSet, bool) {
    let mut as_ = asciiSet([0; 8]);
    let mut i = 0usize;
    while i < chars.len() {
        let c = chars[i];
        if c >= crate::unicode::utf8::RuneSelf {
            return (as_, false);
        }
        as_.0[(c / 32) as usize] |= 1 << (c % 32);
        i += 1;
    }
    return (as_, true);
}

impl asciiSet {
    // go: sdk 1.25.5 strings/strings.go:976-978 asciiSet.contains
    /// Whether `c` is inside the set.
    fn contains(&self, c: byte) -> bool {
        return (self.0[(c / 32) as usize] & (1 << (c % 32))) != 0;
    }
}

// go: sdk 1.25.5 strings/strings.go:1091-1127 TrimSpace
/// `s` with all leading and trailing white space removed, as
/// defined by Unicode.
pub fn TrimSpace<S: Into<string>>(s: S) -> string {
    let s = s.into();
    let bytes = s.as_bytes();
    let mut start = 0usize;
    while start < bytes.len() && bytes[start] < utf8::RuneSelf && is_ascii_space(bytes[start]) {
        start += 1;
    }
    let mut stop = bytes.len();
    while stop > start && bytes[stop - 1] < utf8::RuneSelf && is_ascii_space(bytes[stop - 1]) {
        stop -= 1;
    }
    if start == 0 && stop == bytes.len() {
        return s;
    }
    return string::from_bytes(&bytes[start..stop]);
}

// go: sdk 1.25.5 strings/strings.go:982-993 Trim
/// `s` with all leading and trailing code points contained in `cutset`
/// removed.
pub fn Trim<S1: Into<string>, S2: Into<string>>(s: S1, cutset: S2) -> string {
    let s: string = s.into();
    let cutset: string = cutset.into();
    let sb = s.as_bytes();
    let cb = cutset.as_bytes();
    if sb.is_empty() || cb.is_empty() {
        return s;
    }
    if cb.len() == 1 && cb[0] < crate::unicode::utf8::RuneSelf {
        return string::from_bytes(trimLeftByte(trimRightByte(sb, cb[0]), cb[0]));
    }
    let (as_, ok) = makeASCIISet(cb);
    if ok {
        return string::from_bytes(trimLeftASCII(trimRightASCII(sb, &as_), &as_));
    }
    return string::from_bytes(trimLeftUnicode(trimRightUnicode(sb, cb), cb));
}

// go: sdk 1.25.5 strings/strings.go:993-1010 TrimLeft
/// `s` with all leading code points contained in `cutset` removed. To
/// remove a prefix, use [`TrimPrefix`].
pub fn TrimLeft<S1: Into<string>, S2: Into<string>>(s: S1, cutset: S2) -> string {
    let s: string = s.into();
    let cutset: string = cutset.into();
    let sb = s.as_bytes();
    let cb = cutset.as_bytes();
    if sb.is_empty() || cb.is_empty() {
        return s;
    }
    if cb.len() == 1 && cb[0] < crate::unicode::utf8::RuneSelf {
        return string::from_bytes(trimLeftByte(sb, cb[0]));
    }
    let (as_, ok) = makeASCIISet(cb);
    if ok {
        return string::from_bytes(trimLeftASCII(sb, &as_));
    }
    return string::from_bytes(trimLeftUnicode(sb, cb));
}

// go: sdk 1.25.5 strings/strings.go:1012-1017 trimLeftByte
// goishlint:ignore GOISH014 — the anchor names Go's `trimLeftByte`.
//     Go's takes and returns a `string`, which in Go is a view; the
//     six trim helpers here take and return `&[u8]` so the whole
//     dispatch runs without allocating, and only the public entry
//     point builds a `string`.
fn trimLeftByte(s: &[byte], c: byte) -> &[byte] {
    let mut s = s;
    while !s.is_empty() && s[0] == c {
        s = &s[1..];
    }
    return s;
}

// go: sdk 1.25.5 strings/strings.go:1019-1027 trimLeftASCII
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

// go: sdk 1.25.5 strings/strings.go:1029-1041 trimLeftUnicode
// goishlint:ignore GOISH014 — see `trimLeftByte`.
fn trimLeftUnicode<'a>(s: &'a [byte], cutset: &[byte]) -> &'a [byte] {
    let mut s = s;
    while !s.is_empty() {
        let (mut r, mut n) = (crate::convert::rune(s[0]), 1usize);
        if r >= crate::convert::rune(crate::unicode::utf8::RuneSelf) {
            let (r2, n2) = crate::unicode::utf8::DecodeRune(s);
            r = r2;
            n = n2 as usize;
        }
        if !containsRuneBytes(cutset, r) {
            break;
        }
        s = &s[n..];
    }
    return s;
}

// go: sdk 1.25.5 strings/strings.go:1043-1058 TrimRight
/// `s` with all trailing code points contained in `cutset` removed. To
/// remove a suffix, use [`TrimSuffix`].
pub fn TrimRight<S1: Into<string>, S2: Into<string>>(s: S1, cutset: S2) -> string {
    let s: string = s.into();
    let cutset: string = cutset.into();
    let sb = s.as_bytes();
    let cb = cutset.as_bytes();
    if sb.is_empty() || cb.is_empty() {
        return s;
    }
    if cb.len() == 1 && cb[0] < crate::unicode::utf8::RuneSelf {
        return string::from_bytes(trimRightByte(sb, cb[0]));
    }
    let (as_, ok) = makeASCIISet(cb);
    if ok {
        return string::from_bytes(trimRightASCII(sb, &as_));
    }
    return string::from_bytes(trimRightUnicode(sb, cb));
}

// go: sdk 1.25.5 strings/strings.go:1060-1065 trimRightByte
// goishlint:ignore GOISH014 — see `trimLeftByte`.
fn trimRightByte(s: &[byte], c: byte) -> &[byte] {
    let mut s = s;
    while !s.is_empty() && s[s.len() - 1] == c {
        s = &s[..s.len() - 1];
    }
    return s;
}

// go: sdk 1.25.5 strings/strings.go:1067-1075 trimRightASCII
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

// go: sdk 1.25.5 strings/strings.go:1077-1089 trimRightUnicode
// goishlint:ignore GOISH014 — see `trimLeftByte`.
fn trimRightUnicode<'a>(s: &'a [byte], cutset: &[byte]) -> &'a [byte] {
    let mut s = s;
    while !s.is_empty() {
        let (mut r, mut n) = (crate::convert::rune(s[s.len() - 1]), 1usize);
        if r >= crate::convert::rune(crate::unicode::utf8::RuneSelf) {
            let (r2, n2) = crate::unicode::utf8::DecodeLastRune(s);
            r = r2;
            n = n2 as usize;
        }
        if !containsRuneBytes(cutset, r) {
            break;
        }
        s = &s[..s.len() - n];
    }
    return s;
}

// go: none — goish idiom: Go's trim helpers call the package's own
//     `ContainsRune(cutset, r)`, which takes a `string`. These run on
//     the borrowed bytes, so the same scan is spelled over `&[u8]`.
fn containsRuneBytes(cutset: &[byte], r: rune) -> bool {
    let mut i = 0usize;
    while i < cutset.len() {
        let (cr, n) = crate::unicode::utf8::DecodeRune(&cutset[i..]);
        if cr == r {
            return true;
        }
        i += n as usize;
    }
    return false;
}

// go: sdk 1.25.5 strings/strings.go:1127-1133 TrimPrefix
/// `s` without the provided leading `prefix`, or `s` unchanged if
/// it does not start with it.
pub fn TrimPrefix<S1: Into<string>, S2: Into<string>>(s: S1, prefix: S2) -> string {
    let s = s.into();
    let prefix = prefix.into();
    let bytes = s.as_bytes();
    let pb = prefix.as_bytes();
    if has_prefix_bytes(bytes, pb) {
        return string::from_bytes(&bytes[pb.len()..]);
    }
    return s;
}

// go: sdk 1.25.5 strings/strings.go:1133-1139 TrimSuffix
/// `s` without the provided trailing `suffix`, or `s` unchanged if
/// it does not end with it.
pub fn TrimSuffix<S1: Into<string>, S2: Into<string>>(s: S1, suffix: S2) -> string {
    let s = s.into();
    let suffix = suffix.into();
    let bytes = s.as_bytes();
    let sb = suffix.as_bytes();
    if has_suffix_bytes(bytes, sb) {
        return string::from_bytes(&bytes[..bytes.len() - sb.len()]);
    }
    return s;
}

// go: sdk 1.25.5 strings/strings.go:770-774 ToUpperSpecial
/// A copy of `s` with every Unicode letter mapped to its upper case
/// using the case mapping specified by `c`.
pub fn ToUpperSpecial<S: Into<string>>(c: crate::unicode::SpecialCase, s: S) -> string {
    return Map(move |r| c.ToUpper(r), s);
}

// go: sdk 1.25.5 strings/strings.go:776-780 ToLowerSpecial
/// A copy of `s` with every Unicode letter mapped to its lower case
/// using the case mapping specified by `c`.
pub fn ToLowerSpecial<S: Into<string>>(c: crate::unicode::SpecialCase, s: S) -> string {
    return Map(move |r| c.ToLower(r), s);
}

// go: sdk 1.25.5 strings/strings.go:782-786 ToTitleSpecial
/// A copy of `s` with every Unicode letter mapped to its Unicode title
/// case, giving priority to the special casing rules in `c`.
pub fn ToTitleSpecial<S: Into<string>>(c: crate::unicode::SpecialCase, s: S) -> string {
    return Map(move |r| c.ToTitle(r), s);
}
