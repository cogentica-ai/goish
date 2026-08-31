// go: file bytes/bytes.go decls: makeASCIISet, TrimSpace, Trim, TrimLeft, trimLeftByte, trimLeftASCII, trimLeftUnicode, TrimRight, trimRightByte, trimRightASCII, trimRightUnicode, TrimPrefix, TrimSuffix, ToUpperSpecial, ToLowerSpecial, ToTitleSpecial, ToUpper, ToLower, ToTitle, indexBytePortable, Equal, Compare, Contains, ContainsRune, HasPrefix, HasSuffix, Index, IndexByte, IndexRune, LastIndex, LastIndexByte, Count, EqualFold, Replace, ReplaceAll, Repeat, Split, SplitN, genSplit, explode, Join, Clone, Cut, CutPrefix, CutSuffix, ContainsAny, ContainsFunc, IndexAny, LastIndexAny, IndexFunc, LastIndexFunc, Fields, FieldsFunc, TrimFunc, TrimLeftFunc, TrimRightFunc, Map, ToValidUTF8, Runes, isSeparator, Title, SplitAfter, SplitAfterN
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

use crate::convert::{byte as tobyte, int as toint, rune as torune};
use crate::goslice::slice;
use crate::types::{byte, int, rune};
use crate::unicode::utf8;

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
    if HasPrefix(s.clone(), prefix.clone()) {
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
    if HasSuffix(s.clone(), suffix.clone()) {
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

// ─── Private byte helpers (no allocation) ─────────────────────────────

// go: sdk 1.25.5 bytes/bytes.go:101-108 indexBytePortable
pub(super) fn indexBytePortable(s: &[u8], c: byte) -> int {
    let mut i = 0usize;
    while i < s.len() {
        if s[i] == c {
            return toint(i);
        }
        i += 1;
    }
    return -1;
}

// go: none — goish idiom: the `&[u8]`-level twin of `Index`. Go's
//     `Index` takes the slice itself and can hand it straight to the
//     assembly `bytealg.Index`; goish's takes `S: Into<slice<byte>>`,
//     so every caller inside the package would have to build an owned
//     `slice<byte>` just to search. This is the shared body they call
//     instead. Naive O(n*m) — Go's threshold-switching Rabin-Karp is
//     `internal/bytealg`, not `bytes`.
pub(super) fn index_bytes(s: &[u8], substr: &[u8]) -> int {
    let n = substr.len();
    if n == 0 {
        return 0;
    }
    if n == 1 {
        return indexBytePortable(s, substr[0]);
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

// go: none — goish idiom: the `&[u8]`-level twin of `LastIndex`, for
//     the same reason as `index_bytes`.
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

// go: none — goish idiom: the `&[u8]`-level twin of `LastIndexByte`,
//     for the same reason as `index_bytes`.
fn last_index_byte(s: &[u8], c: byte) -> int {
    let mut i = s.len() as isize - 1;
    while i >= 0 {
        if s[i as usize] == c {
            return toint(i);
        }
        i -= 1;
    }
    return -1;
}

// go: none — goish idiom: the `&[u8]`-level twin of `Count`, for the
//     same reason as `index_bytes`. The empty-`substr` arm is Go's:
//     the count is the rune count plus one, not the byte count.
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

// go: none — goish idiom: the `&[u8]`-level twin of `HasPrefix`, for
//     the same reason as `index_bytes`.
fn has_prefix(s: &[u8], prefix: &[u8]) -> bool {
    return s.len() >= prefix.len() && &s[..prefix.len()] == prefix;
}

// go: none — goish idiom: the `&[u8]`-level twin of `HasSuffix`, for
//     the same reason as `index_bytes`.
fn has_suffix(s: &[u8], suffix: &[u8]) -> bool {
    return s.len() >= suffix.len() && &s[s.len() - suffix.len()..] == suffix;
}

#[inline]
// go: none — goish idiom: Go's `asciiSpace [256]uint8` lookup table
//     (bytes.go:449), spelled as the match it is. Every caller already
//     guards it with `< utf8.RuneSelf` and falls through to
//     `unicode.IsSpace` above that, exactly as Go's do, so the table's
//     zeros for 0x80-0xFF are never the thing being consulted.
pub(super) fn is_ascii_space(c: byte) -> bool {
    return matches!(c, b' ' | b'\t' | b'\n' | b'\r' | 0x0B | 0x0C);
}

// ─── Search / equality / compare ──────────────────────────────────────

// go: sdk 1.25.5 bytes/bytes.go:20-23 Equal
pub fn Equal<S1: Into<slice<byte>>, S2: Into<slice<byte>>>(a: S1, b: S2) -> bool {
    let a = a.into();
    let b = b.into();
    let av: &[byte] = &a;
    let bv: &[byte] = &b;
    return av == bv;
}

// go: sdk 1.25.5 bytes/bytes.go:28-30 Compare
pub fn Compare<S1: Into<slice<byte>>, S2: Into<slice<byte>>>(a: S1, b: S2) -> int {
    use core::cmp::Ordering::*;
    let a = a.into();
    let b = b.into();
    let av: &[byte] = &a;
    let bv: &[byte] = &b;
    return match av.cmp(bv) {
        Less => -1,
        Equal => 0,
        Greater => 1,
    };
}

// go: sdk 1.25.5 bytes/bytes.go:77-79 Contains
pub fn Contains<S1: Into<slice<byte>>, S2: Into<slice<byte>>>(s: S1, sub: S2) -> bool {
    return Index(s, sub) >= 0;
}

// go: sdk 1.25.5 bytes/bytes.go:87-89 ContainsRune
pub fn ContainsRune<S: Into<slice<byte>>>(s: S, r: rune) -> bool {
    return IndexRune(s, r) >= 0;
}

// go: sdk 1.25.5 bytes/bytes.go:598-600 HasPrefix
pub fn HasPrefix<S1: Into<slice<byte>>, S2: Into<slice<byte>>>(s: S1, prefix: S2) -> bool {
    let s = s.into();
    let prefix = prefix.into();
    return has_prefix(&s, &prefix);
}

// go: sdk 1.25.5 bytes/bytes.go:603-605 HasSuffix
pub fn HasSuffix<S1: Into<slice<byte>>, S2: Into<slice<byte>>>(s: S1, suffix: S2) -> bool {
    let s = s.into();
    let suffix = suffix.into();
    return has_suffix(&s, &suffix);
}

// go: sdk 1.25.5 bytes/bytes.go:1312-1397 Index
pub fn Index<S1: Into<slice<byte>>, S2: Into<slice<byte>>>(s: S1, sub: S2) -> int {
    let s = s.into();
    let sub = sub.into();
    return index_bytes(&s, &sub);
}

// go: sdk 1.25.5 bytes/bytes.go:97-99 IndexByte
pub fn IndexByte<S: Into<slice<byte>>>(s: S, c: byte) -> int {
    let s = s.into();
    return indexBytePortable(&s, c);
}

// go: sdk 1.25.5 bytes/bytes.go:139-215 IndexRune
pub fn IndexRune<S: Into<slice<byte>>>(s: S, r: rune) -> int {
    let s = s.into();
    let sb: &[byte] = &s;
    if r >= 0 && r < torune(utf8::RuneSelf) {
        return indexBytePortable(sb, tobyte(r));
    }
    // RuneError is not a rune you search for literally. `DecodeRune`
    // returns it for every invalid encoding, so Go's `IndexRune(s,
    // RuneError)` answers "where does this slice stop being UTF-8" —
    // and a lone 0xFF matches even though its bytes are nothing like
    // U+FFFD's. Encoding U+FFFD and searching for those three bytes,
    // as this used to, found only a literal replacement character.
    if r == utf8::RuneError {
        let mut i = 0usize;
        while i < sb.len() {
            let (r1, n) = utf8::DecodeRune(&sb[i..]);
            if r1 == utf8::RuneError {
                return toint(i);
            }
            i += n as usize;
        }
        return -1;
    }
    if !utf8::ValidRune(r) {
        return -1;
    }
    // Go searches from the last byte of the encoding, whose
    // distribution is flatter than the first's, and falls back to
    // `bytealg.Index` once the naive scan collects too many false
    // positives. Both are performance, not semantics; goish's
    // `index_bytes` is the brute-force search the fallback describes.
    let mut buf = [0u8; 4];
    let n = utf8::EncodeRune(&mut buf, r);
    return index_bytes(sb, &buf[..n as usize]);
}

// go: sdk 1.25.5 bytes/bytes.go:111-127 LastIndex
pub fn LastIndex<S1: Into<slice<byte>>, S2: Into<slice<byte>>>(s: S1, sub: S2) -> int {
    let s = s.into();
    let sub = sub.into();
    return last_index_bytes(&s, &sub);
}

// go: sdk 1.25.5 bytes/bytes.go:130-132 LastIndexByte
pub fn LastIndexByte<S: Into<slice<byte>>>(s: S, c: byte) -> int {
    let s = s.into();
    return last_index_byte(&s, c);
}

// go: sdk 1.25.5 bytes/bytes.go:57-74 Count
pub fn Count<S1: Into<slice<byte>>, S2: Into<slice<byte>>>(s: S1, sep: S2) -> int {
    let s = s.into();
    let sep = sep.into();
    return count_bytes(&s, &sep);
}

// ─── Trim family ──────────────────────────────────────────────────────

// ─── Case (ASCII-only) / EqualFold ────────────────────────────────────

// go: sdk 1.25.5 bytes/bytes.go:1228-1309 EqualFold
/// Reports whether `s` and `t`, interpreted as UTF-8 strings, are equal
/// under simple Unicode case-folding, a more general form of
/// case-insensitivity.
///
/// This used to be the ASCII fast path alone, guarded by a length
/// check. Both halves of that were wrong. Folding is not an ASCII
/// tolower — U+212A KELVIN SIGN folds to `k`, and σ, ς and Σ all fold
/// together — and equal-folding inputs need not be the same length,
/// since U+212A is three bytes and `k` is one. Go's shape is an ASCII
/// loop that bails to a rune loop the moment either side goes high, so
/// the common case still never decodes.
pub fn EqualFold<S1: Into<slice<byte>>, S2: Into<slice<byte>>>(s: S1, t: S2) -> bool {
    let s = s.into();
    let t = t.into();
    let mut sb: &[byte] = &s;
    let mut tb: &[byte] = &t;
    // Go's `goto hasUnicode` out of the ASCII loop; goish spells the
    // jump as a flag, since the two loops share nothing but `i`.
    let mut i = 0usize;
    let n = if sb.len() < tb.len() {
        sb.len()
    } else {
        tb.len()
    };
    let mut hasUnicode = false;
    while i < n {
        let mut sr = sb[i];
        let mut tr = tb[i];
        if sr | tr >= utf8::RuneSelf {
            hasUnicode = true;
            break;
        }
        if tr == sr {
            i += 1;
            continue;
        }
        if tr < sr {
            core::mem::swap(&mut tr, &mut sr);
        }
        if b'A' <= sr && sr <= b'Z' && tr == sr + b'a' - b'A' {
            i += 1;
            continue;
        }
        return false;
    }
    if !hasUnicode {
        return sb.len() == tb.len();
    }

    sb = &sb[i..];
    tb = &tb[i..];
    while !sb.is_empty() && !tb.is_empty() {
        let mut sr: rune;
        let mut tr: rune;
        if sb[0] < utf8::RuneSelf {
            sr = torune(sb[0]);
            sb = &sb[1..];
        } else {
            let (r, size) = utf8::DecodeRune(sb);
            sr = r;
            sb = &sb[size as usize..];
        }
        if tb[0] < utf8::RuneSelf {
            tr = torune(tb[0]);
            tb = &tb[1..];
        } else {
            let (r, size) = utf8::DecodeRune(tb);
            tr = r;
            tb = &tb[size as usize..];
        }

        if tr == sr {
            continue;
        }
        if tr < sr {
            core::mem::swap(&mut tr, &mut sr);
        }
        if tr < torune(utf8::RuneSelf) {
            if torune(b'A') <= sr && sr <= torune(b'Z') && tr == sr + torune(b'a') - torune(b'A') {
                continue;
            }
            return false;
        }

        // SimpleFold(x) returns the next equivalent rune > x, or wraps
        // around to the smallest in the class, so walking it from `sr`
        // enumerates the whole orbit exactly once.
        let mut r = crate::unicode::SimpleFold(sr);
        while r != sr && r < tr {
            r = crate::unicode::SimpleFold(r);
        }
        if r == tr {
            continue;
        }
        return false;
    }

    return sb.len() == tb.len();
}

// ─── Replace / Repeat ─────────────────────────────────────────────────

// go: sdk 1.25.5 bytes/bytes.go:1177-1214 Replace
pub fn Replace<S1, S2, S3>(s: S1, old: S2, new_: S3, mut n: int) -> slice<byte>
where
    S1: Into<slice<byte>>,
    S2: Into<slice<byte>>,
    S3: Into<slice<byte>>,
{
    let s = s.into();
    let old = old.into();
    let new_ = new_.into();
    let s_b: &[byte] = &s;
    let o_b: &[byte] = &old;
    let n_b: &[byte] = &new_;

    if o_b == n_b || n == 0 {
        return s;
    }
    let m = count_bytes(s_b, o_b);
    if m == 0 {
        return s;
    }
    if n < 0 || m < n {
        n = m;
    }

    let delta = toint(n_b.len()) - toint(o_b.len());
    let cap_signed = toint(s_b.len()) + n * delta;
    let cap_usize = if cap_signed > 0 {
        cap_signed as usize
    } else {
        0
    };
    let mut v: Vec<byte> = Vec::with_capacity(cap_usize);

    let mut start = 0usize;
    if !o_b.is_empty() {
        for _ in 0..n {
            let j_rel = index_bytes(&s_b[start..], o_b);
            let j = start + j_rel as usize;
            v.extend_from_slice(&s_b[start..j]);
            v.extend_from_slice(n_b);
            start = j + o_b.len();
        }
    } else {
        v.extend_from_slice(n_b);
        for _ in 0..(n - 1) {
            let (_, sz) = utf8::DecodeRune(&s_b[start..]);
            let j = start + sz as usize;
            v.extend_from_slice(&s_b[start..j]);
            v.extend_from_slice(n_b);
            start = j;
        }
    }
    v.extend_from_slice(&s_b[start..]);
    return slice::__from_vec(v);
}

// go: sdk 1.25.5 bytes/bytes.go:1221-1223 ReplaceAll
pub fn ReplaceAll<S1, S2, S3>(s: S1, old: S2, new_: S3) -> slice<byte>
where
    S1: Into<slice<byte>>,
    S2: Into<slice<byte>>,
    S3: Into<slice<byte>>,
{
    return Replace(s, old, new_, -1);
}

// go: sdk 1.25.5 bytes/bytes.go:647-693 Repeat
pub fn Repeat<S: Into<slice<byte>>>(b: S, count: int) -> slice<byte> {
    if count == 0 {
        return slice::new();
    }
    if count < 0 {
        panic!("bytes: negative Repeat count");
    }
    let s = b.into();
    if count == 1 {
        return s;
    }
    let src: &[byte] = &s;
    if src.is_empty() {
        return slice::new();
    }
    let total = toint(src.len())
        .checked_mul(count)
        .expect("bytes: Repeat output length overflow");
    let mut v: Vec<byte> = Vec::with_capacity(total as usize);
    for _ in 0..count {
        v.extend_from_slice(src);
    }
    return slice::__from_vec(v);
}

// ─── Split / Join ─────────────────────────────────────────────────────

// go: sdk 1.25.5 bytes/bytes.go:439-439 Split
pub fn Split<S1: Into<slice<byte>>, S2: Into<slice<byte>>>(s: S1, sep: S2) -> slice<slice<byte>> {
    return genSplit(s.into(), sep.into(), 0, -1);
}

// go: sdk 1.25.5 bytes/bytes.go:420-420 SplitN
pub fn SplitN<S1: Into<slice<byte>>, S2: Into<slice<byte>>>(
    s: S1,
    sep: S2,
    n: int,
) -> slice<slice<byte>> {
    return genSplit(s.into(), sep.into(), 0, n);
}

// go: sdk 1.25.5 bytes/bytes.go:381-409 genSplit
fn genSplit(s: slice<byte>, sep: slice<byte>, sep_save: int, mut n: int) -> slice<slice<byte>> {
    if n == 0 {
        return slice::new();
    }
    let s_b: &[byte] = &s;
    let sep_b: &[byte] = &sep;

    if sep_b.is_empty() {
        return explode(&s, n);
    }
    if n < 0 {
        n = count_bytes(s_b, sep_b) + 1;
    }
    let max_n = toint(s_b.len()) + 1;
    if n > max_n {
        n = max_n;
    }

    let mut a: Vec<slice<byte>> = Vec::with_capacity(n as usize);
    let mut start = 0usize;
    let mut i = 0;
    while i < n - 1 {
        let m = index_bytes(&s_b[start..], sep_b);
        if m < 0 {
            break;
        }
        let end = start + m as usize + sep_save as usize;
        a.push(slice::__from_vec(s_b[start..end].to_vec()));
        start = start + m as usize + sep_b.len();
        i += 1;
    }
    a.push(slice::__from_vec(s_b[start..].to_vec()));
    return slice::__from_vec(a);
}

// go: sdk 1.25.5 bytes/bytes.go:34-53 explode
fn explode(s: &slice<byte>, mut n: int) -> slice<slice<byte>> {
    let bytes_b: &[byte] = s;
    let l = utf8::RuneCount(bytes_b);
    if n < 0 || n > l {
        n = l;
    }
    if n == 0 {
        return slice::new();
    }
    let mut a: Vec<slice<byte>> = Vec::with_capacity(n as usize);
    let mut i = 0usize;
    let mut k: int = 0;
    while k < n - 1 {
        let (_, sz) = utf8::DecodeRune(&bytes_b[i..]);
        a.push(slice::__from_vec(bytes_b[i..i + sz as usize].to_vec()));
        i += sz as usize;
        k += 1;
    }
    a.push(slice::__from_vec(bytes_b[i..].to_vec()));
    return slice::__from_vec(a);
}

// go: sdk 1.25.5 bytes/bytes.go:565-595 Join
pub fn Join<S: Into<slice<byte>>>(elems: slice<slice<byte>>, sep: S) -> slice<byte> {
    let elems_v = elems.__into_vec();
    if elems_v.is_empty() {
        return slice::new();
    }
    if elems_v.len() == 1 {
        return elems_v.into_iter().next().unwrap();
    }
    let sep = sep.into();
    let sep_b: &[byte] = &sep;
    let mut total = sep_b.len() * (elems_v.len() - 1);
    for e in &elems_v {
        let raw: &[byte] = e;
        total += raw.len();
    }
    let mut v: Vec<byte> = Vec::with_capacity(total);
    let mut first = true;
    for e in elems_v {
        if !first {
            v.extend_from_slice(sep_b);
        }
        first = false;
        let raw: &[byte] = &e;
        v.extend_from_slice(raw);
    }
    return slice::__from_vec(v);
}

// ─── Clone ────────────────────────────────────────────────────────────

// go: sdk 1.25.5 bytes/bytes.go:1415-1420 Clone
pub fn Clone<S: Into<slice<byte>>>(b: S) -> slice<byte> {
    // Go's bytes.Clone returns a fresh allocation. We do the same:
    // .into() yields a slice<byte> (which may be an existing one or a
    // fresh copy from a literal). Either way, .clone() of a slice<byte>
    // is independent storage.
    return b.into().clone();
}

// ─── M15: completeness pass ───────────────────────────────────────────

// go: sdk 1.25.5 bytes/bytes.go:1405-1410 Cut
/// `bytes.Cut(s, sep)` — split on first `sep`. `(before, after, found)`.
pub fn Cut<S1: Into<slice<byte>>, S2: Into<slice<byte>>>(
    s: S1,
    sep: S2,
) -> (slice<byte>, slice<byte>, bool) {
    let s = s.into();
    let sep = sep.into();
    let i = Index(s.clone(), sep.clone());
    if i < 0 {
        return (s, slice::__from_vec(alloc::vec::Vec::new()), false);
    }
    let i = i as usize;
    let sl = sep.Len() as usize;
    let sb = s.__into_vec();
    let before = slice::__from_vec(sb[..i].to_vec());
    let after = slice::__from_vec(sb[i + sl..].to_vec());
    return (before, after, true);
}

// go: sdk 1.25.5 bytes/bytes.go:1428-1433 CutPrefix
/// `bytes.CutPrefix(s, prefix)` — `(after, found)`.
pub fn CutPrefix<S1: Into<slice<byte>>, S2: Into<slice<byte>>>(
    s: S1,
    prefix: S2,
) -> (slice<byte>, bool) {
    let s = s.into();
    let prefix = prefix.into();
    if HasPrefix(s.clone(), prefix.clone()) {
        let pl = prefix.Len() as usize;
        let sb = s.__into_vec();
        return (slice::__from_vec(sb[pl..].to_vec()), true);
    }
    return (s, false);
}

// go: sdk 1.25.5 bytes/bytes.go:1441-1446 CutSuffix
/// `bytes.CutSuffix(s, suffix)` — `(before, found)`.
pub fn CutSuffix<S1: Into<slice<byte>>, S2: Into<slice<byte>>>(
    s: S1,
    suffix: S2,
) -> (slice<byte>, bool) {
    let s = s.into();
    let suffix = suffix.into();
    if HasSuffix(s.clone(), suffix.clone()) {
        let sl = s.Len() as usize - suffix.Len() as usize;
        let sb = s.__into_vec();
        return (slice::__from_vec(sb[..sl].to_vec()), true);
    }
    return (s, false);
}

// go: sdk 1.25.5 bytes/bytes.go:82-84 ContainsAny
/// `bytes.ContainsAny(s, chars)` — true if any byte of `chars` is in `s`.
pub fn ContainsAny<S1: Into<slice<byte>>, S2: Into<slice<byte>>>(s: S1, chars: S2) -> bool {
    return IndexAny(s, chars) >= 0;
}

// go: sdk 1.25.5 bytes/bytes.go:92-94 ContainsFunc
/// `bytes.ContainsFunc(s, f)` — true if any rune in `s` satisfies `f`.
pub fn ContainsFunc<S: Into<slice<byte>>, F: Fn(rune) -> bool>(s: S, f: F) -> bool {
    return IndexFunc(s, f) >= 0;
}

// go: sdk 1.25.5 bytes/bytes.go:221-293 IndexAny
/// `s` interpreted as a sequence of UTF-8-encoded code points: the byte
/// index of the first occurrence in `s` of any of the code points in
/// `chars`, or -1 if `chars` is empty or nothing is in common.
///
/// `chars` is a RUNE set, not a byte set. The byte-wise scan this
/// replaced reported a hit at the 0xC3 of a `héllo` under cutset "é"
/// even when the input held no é at all, and missed the U+FFFD that
/// stands in for an invalid byte. Same rule as the trim family.
pub fn IndexAny<S1: Into<slice<byte>>, S2: Into<slice<byte>>>(s: S1, chars: S2) -> int {
    let s = s.into();
    let chars = chars.into();
    let sb: &[byte] = &s;
    let cb: &[byte] = &chars;
    if cb.is_empty() {
        // Avoid scanning all of s.
        return -1;
    }
    if sb.len() == 1 {
        let r = torune(sb[0]);
        if r >= torune(utf8::RuneSelf) {
            // A lone high byte is an invalid encoding, so it decodes to
            // U+FFFD — found only by a cutset that holds U+FFFD.
            if containsRune(cb, utf8::RuneError) {
                return 0;
            }
            return -1;
        }
        if indexBytePortable(cb, sb[0]) >= 0 {
            return 0;
        }
        return -1;
    }
    if cb.len() == 1 {
        let mut r = torune(cb[0]);
        if r >= torune(utf8::RuneSelf) {
            r = utf8::RuneError;
        }
        return IndexRune(s.clone(), r);
    }
    if sb.len() > 8 {
        let (as_, isASCII) = makeASCIISet(cb);
        if isASCII {
            let mut i = 0usize;
            while i < sb.len() {
                if as_.contains(sb[i]) {
                    return toint(i);
                }
                i += 1;
            }
            return -1;
        }
    }
    let mut i = 0usize;
    while i < sb.len() {
        let r0 = torune(sb[i]);
        if r0 < torune(utf8::RuneSelf) {
            if indexBytePortable(cb, sb[i]) >= 0 {
                return toint(i);
            }
            i += 1;
            continue;
        }
        let (r, w) = utf8::DecodeRune(&sb[i..]);
        let width = w as usize;
        if r != utf8::RuneError {
            // r is 2 to 4 bytes. Go compares encodings here rather than
            // decoding the whole cutset again — the cutset is a string,
            // so `chars == string(r)` is a byte compare.
            let mut buf = [0u8; 4];
            let n = utf8::EncodeRune(&mut buf, r) as usize;
            if cb.len() == width {
                if cb == &buf[..n] {
                    return toint(i);
                }
                i += width;
                continue;
            }
            if index_bytes(cb, &buf[..n]) >= 0 {
                return toint(i);
            }
            i += width;
            continue;
        }
        if containsRune(cb, r) {
            return toint(i);
        }
        i += width;
    }
    return -1;
}

// go: sdk 1.25.5 bytes/bytes.go:299-377 LastIndexAny
/// The byte index of the last occurrence in `s` of any of the code
/// points in `chars`, or -1 if `chars` is empty or nothing is in
/// common. `chars` is a rune set — see [`IndexAny`].
pub fn LastIndexAny<S1: Into<slice<byte>>, S2: Into<slice<byte>>>(s: S1, chars: S2) -> int {
    let s = s.into();
    let chars = chars.into();
    let sb: &[byte] = &s;
    let cb: &[byte] = &chars;
    if cb.is_empty() {
        // Avoid scanning all of s.
        return -1;
    }
    if sb.len() > 8 {
        let (as_, isASCII) = makeASCIISet(cb);
        if isASCII {
            let mut i = sb.len();
            while i > 0 {
                i -= 1;
                if as_.contains(sb[i]) {
                    return toint(i);
                }
            }
            return -1;
        }
    }
    if sb.len() == 1 {
        let r = torune(sb[0]);
        if r >= torune(utf8::RuneSelf) {
            if containsRune(cb, utf8::RuneError) {
                return 0;
            }
            return -1;
        }
        if indexBytePortable(cb, sb[0]) >= 0 {
            return 0;
        }
        return -1;
    }
    if cb.len() == 1 {
        let mut cr = torune(cb[0]);
        if cr >= torune(utf8::RuneSelf) {
            cr = utf8::RuneError;
        }
        let mut i = sb.len();
        while i > 0 {
            let (r, size) = utf8::DecodeLastRune(&sb[..i]);
            i -= size as usize;
            if r == cr {
                return toint(i);
            }
        }
        return -1;
    }
    let mut i = sb.len();
    while i > 0 {
        let r0 = torune(sb[i - 1]);
        if r0 < torune(utf8::RuneSelf) {
            if indexBytePortable(cb, sb[i - 1]) >= 0 {
                return toint(i - 1);
            }
            i -= 1;
            continue;
        }
        let (r, size) = utf8::DecodeLastRune(&sb[..i]);
        i -= size as usize;
        if r != utf8::RuneError {
            let mut buf = [0u8; 4];
            let n = utf8::EncodeRune(&mut buf, r) as usize;
            if cb.len() == size as usize {
                if cb == &buf[..n] {
                    return toint(i);
                }
                continue;
            }
            if index_bytes(cb, &buf[..n]) >= 0 {
                return toint(i);
            }
            continue;
        }
        if containsRune(cb, r) {
            return toint(i);
        }
    }
    return -1;
}

// go: sdk 1.25.5 bytes/bytes.go:903-905 IndexFunc
/// `bytes.IndexFunc(s, f)` — index of first rune in `s` satisfying `f`.
pub fn IndexFunc<S: Into<slice<byte>>, F: Fn(rune) -> bool>(s: S, f: F) -> int {
    let s = s.into();
    let bytes: alloc::vec::Vec<byte> = s.__into_vec();
    let mut i = 0;
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

// go: sdk 1.25.5 bytes/bytes.go:910-912 LastIndexFunc
/// `bytes.LastIndexFunc(s, f)` — index of last rune satisfying `f`.
pub fn LastIndexFunc<S: Into<slice<byte>>, F: Fn(rune) -> bool>(s: S, f: F) -> int {
    let s = s.into();
    let bytes: alloc::vec::Vec<byte> = s.__into_vec();
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

// go: sdk 1.25.5 bytes/bytes.go:457-505 Fields
/// `bytes.Fields(s)` — split on runs of `unicode.IsSpace`.
pub fn Fields<S: Into<slice<byte>>>(s: S) -> slice<slice<byte>> {
    return FieldsFunc(s, crate::unicode::IsSpace);
}

// go: sdk 1.25.5 bytes/bytes.go:516-561 FieldsFunc
/// `bytes.FieldsFunc(s, f)` — split at every run of code points satisfying `f`.
pub fn FieldsFunc<S: Into<slice<byte>>, F: Fn(rune) -> bool>(s: S, f: F) -> slice<slice<byte>> {
    let s = s.into();
    let bytes: alloc::vec::Vec<byte> = s.__into_vec();
    let mut out: alloc::vec::Vec<slice<byte>> = alloc::vec::Vec::new();
    let mut start: Option<usize> = None;
    let mut i = 0;
    while i < bytes.len() {
        let (r, w) = utf8::DecodeRune(&bytes[i..]);
        let w = w as usize;
        if f(r) {
            if let Some(s_idx) = start {
                out.push(slice::__from_vec(bytes[s_idx..i].to_vec()));
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
        out.push(slice::__from_vec(bytes[s_idx..].to_vec()));
    }
    return slice::__from_vec(out);
}

// go: sdk 1.25.5 bytes/bytes.go:878-880 TrimFunc
/// `bytes.TrimFunc(s, f)` — strip leading + trailing runes satisfying `f`.
pub fn TrimFunc<S: Into<slice<byte>>, F: Fn(rune) -> bool + Copy>(s: S, f: F) -> slice<byte> {
    return TrimRightFunc(TrimLeftFunc(s, f), f);
}

// go: sdk 1.25.5 bytes/bytes.go:855-861 TrimLeftFunc
/// `bytes.TrimLeftFunc(s, f)` — strip leading runes satisfying `f`.
pub fn TrimLeftFunc<S: Into<slice<byte>>, F: Fn(rune) -> bool>(s: S, f: F) -> slice<byte> {
    let s = s.into();
    let bytes: alloc::vec::Vec<byte> = s.__into_vec();
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
    return slice::__from_vec(bytes[i..].to_vec());
}

// go: sdk 1.25.5 bytes/bytes.go:865-874 TrimRightFunc
/// `bytes.TrimRightFunc(s, f)` — strip trailing runes satisfying `f`.
pub fn TrimRightFunc<S: Into<slice<byte>>, F: Fn(rune) -> bool>(s: S, f: F) -> slice<byte> {
    let s = s.into();
    let bytes: alloc::vec::Vec<byte> = s.__into_vec();
    let mut end = bytes.len();
    while end > 0 {
        let (r, w) = utf8::DecodeLastRune(&bytes[..end]);
        if w == 0 || !f(r) {
            break;
        }
        end -= w as usize;
    }
    return slice::__from_vec(bytes[..end].to_vec());
}

// go: sdk 1.25.5 bytes/bytes.go:611-629 Map
/// `bytes.Map(mapping, s)` — per-rune transform; negative-rune drops.
pub fn Map<S: Into<slice<byte>>, F: Fn(rune) -> rune>(mapping: F, s: S) -> slice<byte> {
    let s = s.into();
    let bytes: alloc::vec::Vec<byte> = s.__into_vec();
    let mut out: alloc::vec::Vec<byte> = alloc::vec::Vec::with_capacity(bytes.len());
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
    return slice::__from_vec(out);
}

// go: sdk 1.25.5 bytes/bytes.go:779-804 ToValidUTF8
/// Line-by-line port of `bytes.ToValidUTF8` (bytes/bytes.go:779).
///
/// Returns a copy of `s` with each run of invalid UTF-8 byte sequences
/// replaced by `replacement` (which may be empty).
pub fn ToValidUTF8<S1: Into<slice<byte>>, S2: Into<slice<byte>>>(
    s: S1,
    replacement: S2,
) -> slice<byte> {
    let s = s.into();
    let replacement = replacement.into();
    let s_bytes: alloc::vec::Vec<byte> = s.__into_vec();
    let repl_bytes: alloc::vec::Vec<byte> = replacement.__into_vec();
    // Go: b := make([]byte, 0, len(s)+len(replacement))
    let mut b: alloc::vec::Vec<byte> =
        alloc::vec::Vec::with_capacity(s_bytes.len() + repl_bytes.len());
    // Go: invalid := false
    let mut invalid: bool = false;
    // Go: for i := 0; i < len(s); { c := s[i]; ... }
    let mut i: usize = 0;
    while i < s_bytes.len() {
        let c = s_bytes[i];
        // Go: if c < utf8.RuneSelf { i++; invalid=false; b = append(b, c); continue }
        if c < utf8::RuneSelf {
            i += 1;
            invalid = false;
            b.push(c);
            continue;
        }
        // Go: _, wid := utf8.DecodeRune(s[i:])
        let (_, wid) = utf8::DecodeRune(&s_bytes[i..]);
        // Go: if wid == 1 { i++; if !invalid { invalid=true; b = append(b, replacement...) }; continue }
        if wid == 1 {
            i += 1;
            if !invalid {
                invalid = true;
                b.extend_from_slice(&repl_bytes);
            }
            continue;
        }
        // Go: invalid = false; b = append(b, s[i:i+wid]...); i += wid
        invalid = false;
        b.extend_from_slice(&s_bytes[i..i + wid as usize]);
        i += wid as usize;
    }
    return slice::__from_vec(b);
}

// go: sdk 1.25.5 bytes/bytes.go:1159-1169 Runes
/// Line-by-line port of `bytes.Runes` (bytes/bytes.go:1159) — interpret
/// `s` as UTF-8 and return a slice of decoded runes. Invalid UTF-8
/// bytes are decoded as `utf8.RuneError` (matching `DecodeRune`'s
/// contract — Go does the same via `RuneCount` + `DecodeRune`).
pub fn Runes<S: Into<slice<byte>>>(s: S) -> slice<rune> {
    let s = s.into();
    let bytes: alloc::vec::Vec<byte> = s.__into_vec();
    // Go: t := make([]rune, utf8.RuneCount(s))
    let cap = utf8::RuneCount(&bytes) as usize;
    let mut t: alloc::vec::Vec<rune> = alloc::vec::Vec::with_capacity(cap);
    // Go: i := 0; for len(s) > 0 { r, l := utf8.DecodeRune(s); t[i] = r; i++; s = s[l:] }
    let mut i: usize = 0;
    while i < bytes.len() {
        let (r, l) = utf8::DecodeRune(&bytes[i..]);
        t.push(r);
        if l == 0 {
            break;
        }
        i += l as usize;
    }
    return slice::__from_vec(t);
}

// go: sdk 1.25.5 bytes/bytes.go:808-829 isSeparator
/// Line-by-line port of `bytes.isSeparator` (bytes/bytes.go:808) — used
/// by `Title` to detect word boundaries.
fn isSeparator(r: rune) -> bool {
    // Go: if r <= 0x7F { ... }
    if r <= 0x7F {
        // Go: 0..9 / a..z / A..Z / '_' are not separators.
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
    // Slim: goish lacks unicode.IsLetter / IsDigit / IsSpace tables.
    // Treat any non-ASCII rune as a non-separator (Go's IsLetter/IsDigit
    // would cover most non-ASCII alphanumerics anyway).
    return false;
}

// go: sdk 1.25.5 bytes/bytes.go:836-851 Title
/// Line-by-line port of `bytes.Title` (bytes/bytes.go:836) — return a
/// copy of `s` with the first letter of each word title-cased. Slim
/// port: only ASCII letters are title-cased (rune ≥ 0x80 left as-is)
/// since goish lacks the full unicode.ToTitle table.
///
/// Deprecated in Go upstream; ported for compatibility.
#[deprecated = "see Go upstream — Title's word-boundary rule is unsafe for general Unicode"]
pub fn Title<S: Into<slice<byte>>>(s: S) -> slice<byte> {
    let s = s.into();
    let bytes: alloc::vec::Vec<byte> = s.__into_vec();
    let mut out: alloc::vec::Vec<byte> = alloc::vec::Vec::with_capacity(bytes.len());
    // Go: prev := ' '
    let mut prev: rune = torune(b' ');
    let mut tmp = [0u8; 4];
    let mut i: usize = 0;
    // Go: return Map(func(r rune) rune { … }, s) — inlined for ASCII title-case.
    while i < bytes.len() {
        let (r, w) = utf8::DecodeRune(&bytes[i..]);
        // Go: if isSeparator(prev) { return unicode.ToTitle(r) }
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
    return slice::__from_vec(out);
}

// go: sdk 1.25.5 bytes/bytes.go:445-447 SplitAfter
/// `bytes.SplitAfter(s, sep)` — split keeping `sep` at end of each segment.
pub fn SplitAfter<S1: Into<slice<byte>>, S2: Into<slice<byte>>>(
    s: S1,
    sep: S2,
) -> slice<slice<byte>> {
    return SplitAfterN(s, sep, -1);
}

// go: sdk 1.25.5 bytes/bytes.go:429-431 SplitAfterN
/// `bytes.SplitAfterN(s, sep, n)` — count-bounded `SplitAfter`.
pub fn SplitAfterN<S1: Into<slice<byte>>, S2: Into<slice<byte>>>(
    s: S1,
    sep: S2,
    n: int,
) -> slice<slice<byte>> {
    let s = s.into();
    let sep = sep.into();
    // Go is one line: `genSplit(s, sep, len(sep), n)`. It used to be a
    // second, hand-rolled walk here, and it disagreed with the shared
    // one at n == 0 — where Go returns nil and this returned the whole
    // input. Every other n arm agreed, which is why a name-match
    // "covered" it for as long as it did.
    let save = toint(sep.Len());
    return genSplit(s, sep, save, n);
}
