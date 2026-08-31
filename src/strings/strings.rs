// go: file strings/strings.go decls: ContainsAny, ContainsFunc, ContainsRune, Count, Cut, CutPrefix, CutSuffix, EqualFold, Fields, FieldsFunc, genSplit, HasPrefix, HasSuffix, Index, IndexAny, IndexByte, IndexFunc, IndexRune, isSeparator, Join, LastIndex, LastIndexAny, LastIndexByte, LastIndexFunc, Map, Repeat, Replace, ReplaceAll, Split, SplitAfter, SplitAfterN, SplitN, Title, ToLower, ToTitle, ToUpper, ToValidUTF8, TrimFunc, TrimLeftFunc, TrimRightFunc, index_byte, index_bytes, last_index_bytes, count_bytes, has_prefix_bytes, has_suffix_bytes, is_ascii_space, map_runes, sub, explode, Trim, TrimLeft, trimLeftByte, trimLeftASCII, trimLeftUnicode, TrimRight, trimRightByte, trimRightASCII, trimRightUnicode, TrimSpace, TrimPrefix, TrimSuffix, makeASCIISet, asciiSet.contains, ToUpperSpecial, ToLowerSpecial, ToTitleSpecial
//
// goishlint:ignore GOISH021 maxInt, asciiSpace, repeatedSpaces, repeatedDashes, repeatedZeroes, repeatedEquals, repeatedTabs — `maxInt` bounds
//     `Repeat`'s overflow check, `asciiSpace` is the byte array
//     `is_ascii_space` spells as a match, and the four `repeated*`
//     constants are `Repeat`'s fast-path literals. goish's `Repeat`
//     grows a Vec instead of copying from a shared literal, so none of
//     them has a value to hold.
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
use alloc::vec::Vec;

use crate::convert::{byte as tobyte, int as toint, rune as torune, uint32 as touint32};
use crate::goslice::slice;
use crate::gostring::string;
use crate::types::{byte, int, rune};
use crate::unicode::utf8;

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

// ─── private byte helpers (no allocation) ─────────────────────────────

// go: none — goish idiom: Go's `IndexByte` calls
//     `bytealg.IndexByteString`, an assembly routine in
//     internal/bytealg. goish has no bytealg, so the scan is spelled
//     here and the four public entry points share it.
fn index_byte(s: &[u8], c: byte) -> int {
    let mut i = 0usize;
    while i < s.len() {
        if s[i] == c {
            return toint(i);
        }
        i += 1;
    }
    return -1;
}

// go: none — goish idiom: the borrowed-bytes body of `Index`. Go's
//     `Index` is a five-branch dispatch over bytealg's assembly and a
//     Rabin-Karp fallback; goish scans, which gives the same answer
//     for every input and is what the smoke checks.
fn index_bytes(s: &[u8], substr: &[u8]) -> int {
    let n = substr.len();
    if n == 0 {
        return 0;
    }
    if n == 1 {
        return index_byte(s, substr[0]);
    }
    if n > s.len() {
        return -1;
    }
    let last = s.len() - n;
    let mut i = 0usize;
    while i <= last {
        if &s[i..i + n] == substr {
            return toint(i);
        }
        i += 1;
    }
    return -1;
}

// go: none — goish idiom: the borrowed-bytes body of `LastIndex`,
//     for the same reason as `index_bytes`.
fn last_index_bytes(s: &[u8], substr: &[u8]) -> int {
    let n = substr.len();
    if n == 0 {
        return toint(s.len());
    }
    if n > s.len() {
        return -1;
    }
    let mut i = (s.len() - n) as isize;
    while i >= 0 {
        let u = i as usize;
        if &s[u..u + n] == substr {
            return toint(i);
        }
        i -= 1;
    }
    return -1;
}

// go: none — goish idiom: the borrowed-bytes body of `Count`, for
//     the same reason as `index_bytes`.
fn count_bytes(s: &[u8], substr: &[u8]) -> int {
    if substr.is_empty() {
        return utf8::RuneCount(s) + 1;
    }
    let mut n: int = 0;
    let mut i = 0usize;
    let m = substr.len();
    while i + m <= s.len() {
        if &s[i..i + m] == substr {
            n += 1;
            i += m;
        } else {
            i += 1;
        }
    }
    return n;
}

// go: none — goish idiom: `HasPrefix` over borrowed bytes, so the
//     trim helpers and the search finder can use it without building
//     two `string` handles per comparison.
pub(super) fn has_prefix_bytes(s: &[u8], prefix: &[u8]) -> bool {
    return s.len() >= prefix.len() && &s[..prefix.len()] == prefix;
}

// go: none — goish idiom: `HasSuffix` over borrowed bytes; see
//     `has_prefix_bytes`.
pub(super) fn has_suffix_bytes(s: &[u8], suffix: &[u8]) -> bool {
    return s.len() >= suffix.len() && &s[s.len() - suffix.len()..] == suffix;
}

#[inline]
// go: none — goish idiom: Go indexes the `asciiSpace` byte array
//     that strings.go declares as a package var. goish spells the
//     same six bytes as a match; `iter.rs`'s `FieldsSeq` reads it too.
pub(super) fn is_ascii_space(c: byte) -> bool {
    return matches!(c, b' ' | b'\t' | b'\n' | b'\r' | 0x0B | 0x0C);
}

// ─── Split / Join ─────────────────────────────────────────────────────

// go: sdk 1.25.5 strings/strings.go:361-361 Split
/// `strings.Split(s, sep)` — splits s into substrings separated by sep.
///
/// If sep is empty, splits after each UTF-8 sequence (Go-faithful).
pub fn Split<S1: Into<string>, S2: Into<string>>(s: S1, sep: S2) -> slice<string> {
    return genSplit(s.into(), sep.into(), 0, -1);
}

// go: sdk 1.25.5 strings/strings.go:333-333 SplitN
/// `strings.SplitN(s, sep, n)` — at most n substrings.
///
///   n > 0  → at most n substrings; last is the unsplit remainder.
///   n == 0 → empty result.
///   n < 0  → no limit (same as Split).
pub fn SplitN<S1: Into<string>, S2: Into<string>>(s: S1, sep: S2, n: int) -> slice<string> {
    return genSplit(s.into(), sep.into(), 0, n);
}

// go: sdk 1.25.5 strings/strings.go:291-319 genSplit
fn genSplit(s: string, sep: string, sep_save: int, mut n: int) -> slice<string> {
    if n == 0 {
        return slice::new();
    }
    let s_bytes = s.as_bytes();
    let sep_bytes = sep.as_bytes();

    if sep_bytes.is_empty() {
        return explode(s, n);
    }
    if n < 0 {
        n = count_bytes(s_bytes, sep_bytes) + 1;
    }
    let max_n = toint(s_bytes.len()) + 1;
    if n > max_n {
        n = max_n;
    }

    let mut a: Vec<string> = Vec::with_capacity(n as usize);
    let mut start = 0usize;
    let mut i = 0;
    while i < n - 1 {
        let m = index_bytes(&s_bytes[start..], sep_bytes);
        if m < 0 {
            break;
        }
        let end = start + m as usize + sep_save as usize;
        a.push(string::from_bytes(&s_bytes[start..end]));
        start = start + m as usize + sep_bytes.len();
        i += 1;
    }
    a.push(string::from_bytes(&s_bytes[start..]));
    return slice::__from_vec(a);
}

// go: sdk 1.25.5 strings/strings.go:23-38 explode
fn explode(s: string, mut n: int) -> slice<string> {
    let bytes = s.as_bytes();
    let l = utf8::RuneCount(bytes);
    if n < 0 || n > l {
        n = l;
    }
    if n == 0 {
        return slice::new();
    }
    let mut a: Vec<string> = Vec::with_capacity(n as usize);
    let mut i = 0usize;
    let mut k: int = 0;
    while k < n - 1 {
        let (_, sz) = utf8::DecodeRune(&bytes[i..]);
        a.push(string::from_bytes(&bytes[i..i + sz as usize]));
        i += sz as usize;
        k += 1;
    }
    a.push(string::from_bytes(&bytes[i..]));
    return slice::__from_vec(a);
}

// go: sdk 1.25.5 strings/strings.go:487-517 Join
/// `strings.Join(elems, sep)` — concatenates elems with sep between each.
pub fn Join<S: Into<string>>(elems: slice<string>, sep: S) -> string {
    let elems_v = elems.__into_vec();
    if elems_v.is_empty() {
        return string::new();
    }
    if elems_v.len() == 1 {
        return elems_v.into_iter().next().unwrap();
    }
    let sep = sep.into();
    let sep_bytes = sep.as_bytes();
    let mut total = sep_bytes.len() * (elems_v.len() - 1);
    for e in &elems_v {
        total += e.as_bytes().len();
    }
    let mut v: Vec<byte> = Vec::with_capacity(total);
    let mut first = true;
    for e in elems_v {
        if !first {
            v.extend_from_slice(sep_bytes);
        }
        first = false;
        v.extend_from_slice(e.as_bytes());
    }
    return string::__from_vec(v);
}

// ─── Contains / HasPrefix / HasSuffix ─────────────────────────────────

// go: sdk 1.25.5 strings/strings.go:62-64 Contains
pub fn Contains<S1: Into<string>, S2: Into<string>>(s: S1, substr: S2) -> bool {
    return Index(s, substr) >= 0;
}

// go: sdk 1.25.5 strings/strings.go:72-74 ContainsRune
pub fn ContainsRune<S: Into<string>>(s: S, r: rune) -> bool {
    return IndexRune(s, r) >= 0;
}

// go: sdk 1.25.5 strings/strings.go:520-522 HasPrefix
pub fn HasPrefix<S1: Into<string>, S2: Into<string>>(s: S1, prefix: S2) -> bool {
    let s = s.into();
    let prefix = prefix.into();
    return has_prefix_bytes(s.as_bytes(), prefix.as_bytes());
}

// go: sdk 1.25.5 strings/strings.go:525-527 HasSuffix
pub fn HasSuffix<S1: Into<string>, S2: Into<string>>(s: S1, suffix: S2) -> bool {
    let s = s.into();
    let suffix = suffix.into();
    return has_suffix_bytes(s.as_bytes(), suffix.as_bytes());
}

// ─── Index / IndexByte / IndexRune / LastIndex ────────────────────────

// go: sdk 1.25.5 strings/strings.go:1277-1279 Index
pub fn Index<S1: Into<string>, S2: Into<string>>(s: S1, substr: S2) -> int {
    let s = s.into();
    let substr = substr.into();
    return index_bytes(s.as_bytes(), substr.as_bytes());
}

// go: sdk 1.25.5 strings/strings.go:119-121 IndexByte
pub fn IndexByte<S: Into<string>>(s: S, c: byte) -> int {
    let s = s.into();
    return index_byte(s.as_bytes(), c);
}

// go: sdk 1.25.5 strings/strings.go:127-197 IndexRune
pub fn IndexRune<S: Into<string>>(s: S, r: rune) -> int {
    let s = s.into();
    if r >= 0 && touint32(r) < touint32(utf8::RuneSelf) {
        return index_byte(s.as_bytes(), tobyte(r));
    }
    if !utf8::ValidRune(r) {
        return -1;
    }
    let mut buf = [0u8; 4];
    let n = utf8::EncodeRune(&mut buf, r);
    return index_bytes(s.as_bytes(), &buf[..n as usize]);
}

// go: sdk 1.25.5 strings/strings.go:82-116 LastIndex
pub fn LastIndex<S1: Into<string>, S2: Into<string>>(s: S1, substr: S2) -> int {
    let s = s.into();
    let substr = substr.into();
    return last_index_bytes(s.as_bytes(), substr.as_bytes());
}

// go: sdk 1.25.5 strings/strings.go:42-59 Count
pub fn Count<S1: Into<string>, S2: Into<string>>(s: S1, substr: S2) -> int {
    let s = s.into();
    let substr = substr.into();
    return count_bytes(s.as_bytes(), substr.as_bytes());
}

// ─── ToUpper / ToLower / ToTitle ──────────────────────────────────────

// go: sdk 1.25.5 strings/strings.go:687-724 ToUpper
pub fn ToUpper<S: Into<string>>(s: S) -> string {
    let s = s.into();
    let bytes = s.as_bytes();
    // ASCII fast path (Go strings.go ToUpper does the same scan).
    let mut has_lower = false;
    let mut ascii = true;
    for &c in bytes {
        if c >= 0x80 {
            ascii = false;
            break;
        }
        if c.is_ascii_lowercase() {
            has_lower = true;
        }
    }
    if ascii {
        if !has_lower {
            return s;
        }
        let mut v: Vec<byte> = Vec::with_capacity(bytes.len());
        for &c in bytes {
            v.push(c.to_ascii_uppercase());
        }
        return string::__from_vec(v);
    }
    return map_runes(bytes, crate::unicode::ToUpper);
}

// go: none — goish idiom: the non-ASCII tail of `ToUpper`/`ToLower`.
//     Go reaches it by falling through to `Map`, which takes a
//     closure; this takes a fn pointer, because both callers pass one
//     of `unicode::ToUpper` / `unicode::ToLower` and nothing else.
fn map_runes(bytes: &[byte], f: fn(rune) -> rune) -> string {
    let mut v: Vec<byte> = Vec::with_capacity(bytes.len());
    let mut i = 0usize;
    while i < bytes.len() {
        let (r, size) = crate::unicode::utf8::DecodeRune(&bytes[i..]);
        let m = f(r);
        match char::from_u32(touint32(m)) {
            Some(c) => {
                let mut buf = [0u8; 4];
                v.extend_from_slice(c.encode_utf8(&mut buf).as_bytes());
            }
            None => v.extend_from_slice(&bytes[i..i + size as usize]),
        }
        i += size as usize;
    }
    return string::__from_vec(v);
}

// go: sdk 1.25.5 strings/strings.go:727-764 ToLower
pub fn ToLower<S: Into<string>>(s: S) -> string {
    let s = s.into();
    let bytes = s.as_bytes();
    let mut has_upper = false;
    let mut ascii = true;
    for &c in bytes {
        if c >= 0x80 {
            ascii = false;
            break;
        }
        if c.is_ascii_uppercase() {
            has_upper = true;
        }
    }
    if ascii {
        if !has_upper {
            return s;
        }
        let mut v: Vec<byte> = Vec::with_capacity(bytes.len());
        for &c in bytes {
            v.push(c.to_ascii_lowercase());
        }
        return string::__from_vec(v);
    }
    return map_runes(bytes, crate::unicode::ToLower);
}

// go: sdk 1.25.5 strings/strings.go:768-768 ToTitle
/// `strings.ToTitle(s)` — every rune mapped to its Unicode title case.
///
/// The note that used to sit here said non-ASCII runes passed through
/// unchanged "until the SpecialCasing tables ship". They have:
/// `unicode::ToTitle` runs on Go's `CaseRanges` now, so U+01C4 maps to
/// U+01C5 rather than to itself.
pub fn ToTitle<S: Into<string>>(s: S) -> string {
    // Go: return Map(unicode.ToTitle, s)
    return Map(crate::unicode::ToTitle, s);
}

// ─── Replace / ReplaceAll / Repeat ────────────────────────────────────

// go: sdk 1.25.5 strings/strings.go:1145-1180 Replace
pub fn Replace<S1, S2, S3>(s: S1, old: S2, new_: S3, mut n: int) -> string
where
    S1: Into<string>,
    S2: Into<string>,
    S3: Into<string>,
{
    let s = s.into();
    let old = old.into();
    let new_ = new_.into();
    if old == new_ || n == 0 {
        return s;
    }
    let s_bytes = s.as_bytes();
    let old_bytes = old.as_bytes();
    let new_bytes = new_.as_bytes();

    let m = count_bytes(s_bytes, old_bytes);
    if m == 0 {
        return s;
    }
    if n < 0 || m < n {
        n = m;
    }

    // Compute final size: len(s) + n*(len(new) - len(old)).
    let delta = toint(new_bytes.len()) - toint(old_bytes.len());
    let cap_signed = toint(s_bytes.len()) + n * delta;
    let cap_usize = if cap_signed > 0 {
        cap_signed as usize
    } else {
        0
    };
    let mut v: Vec<byte> = Vec::with_capacity(cap_usize);

    let mut start = 0usize;
    if !old_bytes.is_empty() {
        for _ in 0..n {
            let j_rel = index_bytes(&s_bytes[start..], old_bytes);
            let j = start + j_rel as usize;
            v.extend_from_slice(&s_bytes[start..j]);
            v.extend_from_slice(new_bytes);
            start = j + old_bytes.len();
        }
    } else {
        // Empty `old`: insert `new_` between each rune.
        v.extend_from_slice(new_bytes);
        for _ in 0..(n - 1) {
            let (_, sz) = utf8::DecodeRune(&s_bytes[start..]);
            let j = start + sz as usize;
            v.extend_from_slice(&s_bytes[start..j]);
            v.extend_from_slice(new_bytes);
            start = j;
        }
    }
    v.extend_from_slice(&s_bytes[start..]);
    return string::__from_vec(v);
}

// go: sdk 1.25.5 strings/strings.go:1187-1189 ReplaceAll
pub fn ReplaceAll<S1, S2, S3>(s: S1, old: S2, new_: S3) -> string
where
    S1: Into<string>,
    S2: Into<string>,
    S3: Into<string>,
{
    return Replace(s, old, new_, -1);
}

// go: sdk 1.25.5 strings/strings.go:616-684 Repeat
pub fn Repeat<S: Into<string>>(s: S, count: int) -> string {
    if count == 0 {
        return string::new();
    }
    if count < 0 {
        panic!("strings: negative Repeat count");
    }
    let s = s.into();
    if count == 1 {
        return s;
    }
    let src = s.as_bytes();
    if src.is_empty() {
        return string::new();
    }
    let total = toint(src.len())
        .checked_mul(count)
        .expect("strings: Repeat output length overflow");
    let mut v: Vec<byte> = Vec::with_capacity(total as usize);
    for _ in 0..count {
        v.extend_from_slice(src);
    }
    return string::__from_vec(v);
}

// ─── EqualFold ────────────────────────────────────────────────────────

// go: sdk 1.25.5 strings/strings.go:1194-1274 EqualFold
pub fn EqualFold<S1: Into<string>, S2: Into<string>>(s: S1, t: S2) -> bool {
    let s = s.into();
    let t = t.into();
    let mut sb = s.as_bytes();
    let mut tb = t.as_bytes();
    // Go strings.go EqualFold: ASCII fast path byte-by-byte, general
    // path rune-by-rune with the SimpleFold orbit walk.
    while !sb.is_empty() && !tb.is_empty() {
        let (sr, ssize) = if sb[0] < 0x80 {
            (torune(sb[0]), 1usize)
        } else {
            let (r, n) = crate::unicode::utf8::DecodeRune(sb);
            (r, n as usize)
        };
        let (tr, tsize) = if tb[0] < 0x80 {
            (torune(tb[0]), 1usize)
        } else {
            let (r, n) = crate::unicode::utf8::DecodeRune(tb);
            (r, n as usize)
        };
        sb = &sb[ssize..];
        tb = &tb[tsize..];
        if sr == tr {
            continue;
        }
        // Order so sr <= tr (Go does the same swap).
        let (sr, tr) = if tr < sr { (tr, sr) } else { (sr, tr) };
        if tr < 0x80 {
            // ASCII only: fold to lower and compare.
            if (torune(b'A')..=torune(b'Z')).contains(&sr)
                && tr == sr + (torune(b'a') - torune(b'A'))
            {
                continue;
            }
            return false;
        }
        // General case: walk sr's fold orbit looking for tr.
        let mut r = crate::unicode::SimpleFold(sr);
        while r != sr && r < tr {
            r = crate::unicode::SimpleFold(r);
        }
        if r == tr {
            continue;
        }
        return false;
    }
    return sb.is_empty() && tb.is_empty();
}

// go: waived copyCheck — Go's Builder holds a `addr *Builder` self
//     pointer and copyCheck panics when it finds the Builder has been
//     copied, using `noescape` to keep that pointer off the heap. A
//     goish Builder owns its Vec and a copy is a deep copy, so there
//     is no aliasing bug to detect and no self pointer to compare.
//
// ─── M15: completeness pass ───────────────────────────────────────────

// go: sdk 1.25.5 strings/strings.go:1285-1287 Cut
/// `strings.Cut(s, sep)` — split on first `sep`. Returns
/// `(before, after, found)`. Mirrors Go 1.18+.
pub fn Cut<S1: Into<string>, S2: Into<string>>(s: S1, sep: S2) -> (string, string, bool) {
    let s = s.into();
    let sep = sep.into();
    let i = Index(s.clone(), sep.clone());
    if i < 0 {
        return (s, string::new(), false);
    }
    let before = sub(&s, 0, i);
    let after = sub(&s, i + sep.Len(), s.Len());
    return (before, after, true);
}

// go: sdk 1.25.5 strings/strings.go:1293-1295 CutPrefix
/// `strings.CutPrefix(s, prefix)` — strip `prefix`, report whether it
/// was present. Returns `(after, found)`.
pub fn CutPrefix<S1: Into<string>, S2: Into<string>>(s: S1, prefix: S2) -> (string, bool) {
    let s = s.into();
    let prefix = prefix.into();
    if HasPrefix(s.clone(), prefix.clone()) {
        return (sub(&s, prefix.Len(), s.Len()), true);
    }
    return (s, false);
}

// go: sdk 1.25.5 strings/strings.go:1301-1303 CutSuffix
/// `strings.CutSuffix(s, suffix)` — strip `suffix`. Returns `(before, found)`.
pub fn CutSuffix<S1: Into<string>, S2: Into<string>>(s: S1, suffix: S2) -> (string, bool) {
    let s = s.into();
    let suffix = suffix.into();
    if HasSuffix(s.clone(), suffix.clone()) {
        return (sub(&s, 0, s.Len() - suffix.Len()), true);
    }
    return (s, false);
}

// go: sdk 1.25.5 strings/strings.go:67-69 ContainsAny
/// `strings.ContainsAny(s, chars)` — true if any byte of `chars`
/// appears in `s`. ASCII byte-wise scan in v1.
pub fn ContainsAny<S1: Into<string>, S2: Into<string>>(s: S1, chars: S2) -> bool {
    return IndexAny(s, chars) >= 0;
}

// go: sdk 1.25.5 strings/strings.go:77-79 ContainsFunc
/// `strings.ContainsFunc(s, f)` — true if any rune in `s` satisfies `f`.
pub fn ContainsFunc<S: Into<string>, F: Fn(rune) -> bool>(s: S, f: F) -> bool {
    return IndexFunc(s, f) >= 0;
}

// go: sdk 1.25.5 strings/strings.go:201-230 IndexAny
/// `strings.IndexAny(s, chars)` — index of first byte in `s` that
/// matches any byte in `chars`, or `-1`.
pub fn IndexAny<S1: Into<string>, S2: Into<string>>(s: S1, chars: S2) -> int {
    let s = s.into();
    let chars = chars.into();
    let cb = chars.as_bytes();
    if cb.is_empty() {
        return -1;
    }
    for (i, &b) in s.as_bytes().iter().enumerate() {
        for &c in cb {
            if b == c {
                return toint(i);
            }
        }
    }
    return -1;
}

// go: sdk 1.25.5 strings/strings.go:235-282 LastIndexAny
/// `strings.LastIndexAny(s, chars)` — last-occurrence variant.
pub fn LastIndexAny<S1: Into<string>, S2: Into<string>>(s: S1, chars: S2) -> int {
    let s = s.into();
    let chars = chars.into();
    let cb = chars.as_bytes();
    if cb.is_empty() {
        return -1;
    }
    let sb = s.as_bytes();
    let mut i = sb.len();
    while i > 0 {
        i -= 1;
        for &c in cb {
            if sb[i] == c {
                return toint(i);
            }
        }
    }
    return -1;
}

// go: sdk 1.25.5 strings/strings.go:285-287 LastIndexByte
/// `strings.LastIndexByte(s, c)` — last index of byte `c`, or `-1`.
pub fn LastIndexByte<S: Into<string>>(s: S, c: byte) -> int {
    let s = s.into();
    let sb = s.as_bytes();
    let mut i = sb.len();
    while i > 0 {
        i -= 1;
        if sb[i] == c {
            return toint(i);
        }
    }
    return -1;
}

// go: sdk 1.25.5 strings/strings.go:916-918 IndexFunc
/// `strings.IndexFunc(s, f)` — index (in bytes) of first rune in `s`
/// satisfying `f`, or `-1`.
pub fn IndexFunc<S: Into<string>, F: Fn(rune) -> bool>(s: S, f: F) -> int {
    let s = s.into();
    let mut i = 0;
    let bytes = s.as_bytes();
    while i < bytes.len() {
        let (r, w) = utf8::DecodeRune(&bytes[i..]);
        if f(r) {
            return toint(i);
        }
        if w == 0 {
            break;
        }
        i += w as usize;
    }
    return -1;
}

// go: sdk 1.25.5 strings/strings.go:922-924 LastIndexFunc
/// `strings.LastIndexFunc(s, f)` — index of last rune satisfying `f`.
pub fn LastIndexFunc<S: Into<string>, F: Fn(rune) -> bool>(s: S, f: F) -> int {
    let s = s.into();
    let bytes = s.as_bytes();
    let mut i = bytes.len();
    while i > 0 {
        let (r, w) = utf8::DecodeLastRune(&bytes[..i]);
        if w == 0 {
            return -1;
        }
        i -= w as usize;
        if f(r) {
            return toint(i);
        }
    }
    return -1;
}

// go: sdk 1.25.5 strings/strings.go:384-431 Fields
/// `strings.Fields(s)` — split on runs of `unicode.IsSpace`. Empty
/// elements between consecutive whitespace are dropped.
pub fn Fields<S: Into<string>>(s: S) -> slice<string> {
    return FieldsFunc(s, crate::unicode::IsSpace);
}

// go: sdk 1.25.5 strings/strings.go:441-483 FieldsFunc
/// `strings.FieldsFunc(s, f)` — split at every run of code points
/// satisfying `f`. Empty fields are dropped.
pub fn FieldsFunc<S: Into<string>, F: Fn(rune) -> bool>(s: S, f: F) -> slice<string> {
    let s = s.into();
    let bytes = s.as_bytes();
    let mut out: alloc::vec::Vec<string> = alloc::vec::Vec::new();
    let mut start: Option<usize> = None;
    let mut i = 0;
    while i < bytes.len() {
        let (r, w) = utf8::DecodeRune(&bytes[i..]);
        let w = w as usize;
        if f(r) {
            if let Some(s_idx) = start {
                out.push(string::from_bytes(&bytes[s_idx..i]));
                start = None;
            }
        } else if start.is_none() {
            start = Some(i);
        }
        if w == 0 {
            break;
        }
        i += w;
    }
    if let Some(s_idx) = start {
        out.push(string::from_bytes(&bytes[s_idx..]));
    }
    return slice::__from_vec(out);
}

// go: sdk 1.25.5 strings/strings.go:910-912 TrimFunc
/// `strings.TrimFunc(s, f)` — strip leading + trailing runes satisfying `f`.
pub fn TrimFunc<S: Into<string>, F: Fn(rune) -> bool + Copy>(s: S, f: F) -> string {
    return TrimRightFunc(TrimLeftFunc(s, f), f);
}

// go: sdk 1.25.5 strings/strings.go:887-893 TrimLeftFunc
/// `strings.TrimLeftFunc(s, f)` — strip leading runes satisfying `f`.
pub fn TrimLeftFunc<S: Into<string>, F: Fn(rune) -> bool>(s: S, f: F) -> string {
    let s = s.into();
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        let (r, w) = utf8::DecodeRune(&bytes[i..]);
        if !f(r) {
            break;
        }
        if w == 0 {
            break;
        }
        i += w as usize;
    }
    return string::from_bytes(&bytes[i..]);
}

// go: sdk 1.25.5 strings/strings.go:897-906 TrimRightFunc
/// `strings.TrimRightFunc(s, f)` — strip trailing runes satisfying `f`.
pub fn TrimRightFunc<S: Into<string>, F: Fn(rune) -> bool>(s: S, f: F) -> string {
    let s = s.into();
    let bytes = s.as_bytes();
    let mut end = bytes.len();
    while end > 0 {
        let (r, w) = utf8::DecodeLastRune(&bytes[..end]);
        if w == 0 || !f(r) {
            break;
        }
        end -= w as usize;
    }
    return string::from_bytes(&bytes[..end]);
}

// go: sdk 1.25.5 strings/strings.go:532-589 Map
/// `strings.Map(mapping, s)` — per-rune transform. Negative-rune
/// outputs drop the character (matches Go).
pub fn Map<S: Into<string>, F: Fn(rune) -> rune>(mapping: F, s: S) -> string {
    let s = s.into();
    let bytes = s.as_bytes();
    let mut out: alloc::vec::Vec<u8> = alloc::vec::Vec::with_capacity(bytes.len());
    let mut i = 0;
    let mut tmp = [0u8; 4];
    while i < bytes.len() {
        let (r, w) = utf8::DecodeRune(&bytes[i..]);
        let nr = mapping(r);
        if nr >= 0 {
            let n = utf8::EncodeRune(&mut tmp, nr) as usize;
            out.extend_from_slice(&tmp[..n]);
        }
        if w == 0 {
            break;
        }
        i += w as usize;
    }
    return string::__from_vec(out);
}

// go: sdk 1.25.5 strings/strings.go:840-861 isSeparator
/// Line-by-line port of `strings.isSeparator` (strings/strings.go:840).
fn isSeparator(r: rune) -> bool {
    // Go: if r <= 0x7F { ... } else { …unicode.IsLetter / IsDigit / IsSpace }
    if r <= 0x7F {
        if r >= torune(b'0') && r <= torune(b'9') {
            return false;
        }
        if r >= torune(b'a') && r <= torune(b'z') {
            return false;
        }
        if r >= torune(b'A') && r <= torune(b'Z') {
            return false;
        }
        if r == torune(b'_') {
            return false;
        }
        return true;
    }
    // Slim: goish lacks the unicode tables; treat non-ASCII as non-separator.
    return false;
}

// go: sdk 1.25.5 strings/strings.go:868-883 Title
/// Line-by-line port of `strings.Title` (strings/strings.go:868) — return a
/// copy of `s` with the first letter of each word title-cased. Slim port:
/// only ASCII letters are title-cased (rune ≥ 0x80 left as-is).
///
/// Deprecated in Go upstream; ported for compatibility.
#[deprecated = "see Go upstream — Title's word-boundary rule is unsafe for general Unicode"]
pub fn Title<S: Into<string>>(s: S) -> string {
    let s = s.into();
    let bytes = s.as_bytes();
    let mut out: alloc::vec::Vec<u8> = alloc::vec::Vec::with_capacity(bytes.len());
    // Go: prev := ' '
    let mut prev: rune = torune(b' ');
    let mut tmp = [0u8; 4];
    let mut i: usize = 0;
    while i < bytes.len() {
        let (r, w) = utf8::DecodeRune(&bytes[i..]);
        let nr = if isSeparator(prev) {
            // Slim ToTitle: ASCII a..z → A..Z; everything else unchanged.
            if r >= torune(b'a') && r <= torune(b'z') {
                r - 32
            } else {
                r
            }
        } else {
            r
        };
        prev = r;
        let n = utf8::EncodeRune(&mut tmp, nr) as usize;
        out.extend_from_slice(&tmp[..n]);
        if w == 0 {
            break;
        }
        i += w as usize;
    }
    return string::__from_vec(out);
}

// go: sdk 1.25.5 strings/strings.go:790-836 ToValidUTF8
/// Line-by-line port of `strings.ToValidUTF8` (strings/strings.go:790).
///
/// Returns a copy of `s` with each run of invalid UTF-8 byte sequences
/// replaced by `replacement` (which may be empty).
pub fn ToValidUTF8<S1: Into<string>, S2: Into<string>>(s: S1, replacement: S2) -> string {
    // Go: var b Builder
    // Goish: use Vec<u8> for the scratch buffer — strings.Builder.Cap()
    // isn't part of the goish surface, so we track the "did we grow yet"
    // flag explicitly (b_grown) to mirror Go's `b.Cap() == 0` fast path.
    let s_in = s.into();
    let replacement = replacement.into();
    let bytes = s_in.as_bytes();
    let mut b: alloc::vec::Vec<u8> = alloc::vec::Vec::new();
    let mut b_grown: bool = false;

    // Go: for i, c := range s { if c != utf8.RuneError { continue }
    //         _, wid := utf8.DecodeRuneInString(s[i:])
    //         if wid == 1 { b.Grow(...); b.WriteString(s[:i]); s = s[i:]; break } }
    // Goish: walk runes manually until we hit an invalid one (RuneError
    // with width 1). Track the byte offset `start` so we can retain the
    // good prefix.
    let mut i: usize = 0;
    let mut start: usize = bytes.len(); // sentinel: no invalid byte found yet
    while i < bytes.len() {
        let (c, w) = utf8::DecodeRune(&bytes[i..]);
        if c == utf8::RuneError && w == 1 {
            // Go: b.Grow(len(s) + len(replacement))
            b.reserve(bytes.len() + replacement.as_bytes().len());
            b_grown = true;
            // Go: b.WriteString(s[:i])
            b.extend_from_slice(&bytes[..i]);
            // Go: s = s[i:]; break
            start = i;
            break;
        }
        if w == 0 {
            break;
        }
        i += w as usize;
    }

    // Go: if b.Cap() == 0 { return s }   — fast path: nothing invalid.
    if !b_grown {
        return s_in;
    }

    // Go: invalid := false
    // Go: for i := 0; i < len(s); { c := s[i]; if c < utf8.RuneSelf { ... }; ... }
    let tail = &bytes[start..];
    let mut invalid: bool = false;
    let mut j: usize = 0;
    while j < tail.len() {
        let c = tail[j];
        // Go: if c < utf8.RuneSelf { i++; invalid=false; b.WriteByte(c); continue }
        if c < utf8::RuneSelf {
            j += 1;
            invalid = false;
            b.push(c);
            continue;
        }
        // Go: _, wid := utf8.DecodeRuneInString(s[i:])
        let (_, wid) = utf8::DecodeRune(&tail[j..]);
        // Go: if wid == 1 { i++; if !invalid { invalid=true; b.WriteString(replacement) }; continue }
        if wid == 1 {
            j += 1;
            if !invalid {
                invalid = true;
                b.extend_from_slice(replacement.as_bytes());
            }
            continue;
        }
        // Go: invalid = false; b.WriteString(s[i:i+wid]); i += wid
        invalid = false;
        b.extend_from_slice(&tail[j..j + wid as usize]);
        j += wid as usize;
    }

    // Go: return b.String()
    return string::__from_vec(b);
}

// go: sdk 1.25.5 strings/strings.go:373-375 SplitAfter
/// `strings.SplitAfter(s, sep)` — split *retaining* the separator at
/// the end of each segment.
pub fn SplitAfter<S1: Into<string>, S2: Into<string>>(s: S1, sep: S2) -> slice<string> {
    return SplitAfterN(s, sep, -1);
}

// go: sdk 1.25.5 strings/strings.go:345-347 SplitAfterN
/// `strings.SplitAfterN(s, sep, n)` — count-bounded `SplitAfter`.
pub fn SplitAfterN<S1: Into<string>, S2: Into<string>>(s: S1, sep: S2, n: int) -> slice<string> {
    let s = s.into();
    let sep = sep.into();
    let mut out: alloc::vec::Vec<string> = alloc::vec::Vec::new();
    if sep.Len() == 0 {
        let bytes = s.as_bytes();
        let mut i = 0;
        while i < bytes.len() {
            let (_, w) = utf8::DecodeRune(&bytes[i..]);
            if w == 0 {
                break;
            }
            let w = w as usize;
            out.push(string::from_bytes(&bytes[i..i + w]));
            i += w;
            if n > 0 && toint(out.len()) == n - 1 {
                if i < bytes.len() {
                    out.push(string::from_bytes(&bytes[i..]));
                }
                return slice::__from_vec(out);
            }
        }
        return slice::__from_vec(out);
    }
    let mut start: int = 0;
    loop {
        if n > 0 && toint(out.len()) == n - 1 {
            break;
        }
        let rest = sub(&s, start, s.Len());
        let i = Index(rest.clone(), sep.clone());
        if i < 0 {
            break;
        }
        let end = start + i + sep.Len();
        out.push(sub(&s, start, end));
        start = end;
    }
    if start <= s.Len() {
        out.push(sub(&s, start, s.Len()));
    }
    return slice::__from_vec(out);
}

// go: none — goish idiom: `s[low:high]`. A Go string slice is a
//     view; a goish `string` owns its bytes, so the subslice is built
//     rather than pointed at.
fn sub(s: &string, low: int, high: int) -> string {
    let bytes = s.as_bytes();
    return string::from_bytes(&bytes[low as usize..high as usize]);
}
