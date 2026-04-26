// strings — Go's `strings` package, ported.
//
// Subset for M10 launch — the most-used operations:
//
//   Split, Join, Contains, HasPrefix, HasSuffix,
//   Index, IndexByte, IndexRune, LastIndex,
//   TrimSpace, Trim, TrimLeft, TrimRight, TrimPrefix, TrimSuffix,
//   ToUpper, ToLower, Replace, ReplaceAll, Repeat, Count, EqualFold,
//   Builder { new, Len, Cap, Grow, Reset, WriteString, WriteByte,
//             WriteRune, String, Write }.
//
// Deferred (need closures or full unicode tables, M14+):
//   Map, IndexFunc, FieldsFunc, TrimFunc,
//   ToTitle, ToUpperSpecial, ToLowerSpecial,
//   Cut/CutPrefix/CutSuffix (small — easy add later).
//
// v1 deviations from Go semantics:
//
//   * `Builder.String(self)` consumes the builder. Go's String() returns
//     a non-copying view of the internal buffer; goish hands ownership of
//     the buffer to the result `string`. Build-then-call-once is the idiom.
//   * `ToUpper` / `ToLower` are ASCII-only. Bytes >= 0x80 pass through
//     unchanged. Full unicode case folding lands with the unicode tables
//     milestone.
//   * `EqualFold` is ASCII-only — strings of differing byte length always
//     compare unequal.
//   * Each `Split` segment is a fresh `string` (copy), not a window into
//     the source — see ROADMAP.md (slice copy-semantics).
//   * `Index` / `LastIndex` use naive O(n*m) byte search (no Rabin-Karp /
//     Boyer-Moore). Fine for short separators; revisit when profiling shows
//     allocator pressure.
//   * `Trim` / `TrimLeft` / `TrimRight` use byte-set semantics on the
//     cutset, not Unicode code-point semantics. Same outcome whenever the
//     cutset is ASCII (the overwhelming case).
//
// String literals as separator/prefix arguments flow in via `Into<string>`
// (because `From<&'static str> for string` exists). Call sites stay tight:
//
//     strings::Split(input, ",")          // &'static str → string
//     strings::TrimPrefix(p, "#")
//     strings::HasSuffix(name, ".rs")

#![allow(non_snake_case)]

extern crate alloc;
use alloc::vec::Vec;

use crate::errors::error;
use crate::goslice::slice;
use crate::gostring::string;
use crate::io;
use crate::nil;
use crate::types::{byte, int, rune};
use crate::unicode::utf8;

// ─── private byte helpers (no allocation) ─────────────────────────────

fn index_byte(s: &[u8], c: byte) -> int {
    let mut i = 0usize;
    while i < s.len() {
        if s[i] == c {
            return i as int;
        }
        i += 1;
    }
    -1
}

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
            return i as int;
        }
        i += 1;
    }
    -1
}

fn last_index_bytes(s: &[u8], substr: &[u8]) -> int {
    let n = substr.len();
    if n == 0 {
        return s.len() as int;
    }
    if n > s.len() {
        return -1;
    }
    let mut i = (s.len() - n) as isize;
    while i >= 0 {
        let u = i as usize;
        if &s[u..u + n] == substr {
            return i as int;
        }
        i -= 1;
    }
    -1
}

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
    n
}

fn has_prefix_bytes(s: &[u8], prefix: &[u8]) -> bool {
    s.len() >= prefix.len() && &s[..prefix.len()] == prefix
}

fn has_suffix_bytes(s: &[u8], suffix: &[u8]) -> bool {
    s.len() >= suffix.len() && &s[s.len() - suffix.len()..] == suffix
}

#[inline]
fn is_ascii_space(c: byte) -> bool {
    matches!(c, b' ' | b'\t' | b'\n' | b'\r' | 0x0B | 0x0C)
}

// ─── Split / Join ─────────────────────────────────────────────────────

/// `strings.Split(s, sep)` — splits s into substrings separated by sep.
///
/// If sep is empty, splits after each UTF-8 sequence (Go-faithful).
pub fn Split<S1: Into<string>, S2: Into<string>>(s: S1, sep: S2) -> slice<string> {
    gen_split(s.into(), sep.into(), 0, -1)
}

/// `strings.SplitN(s, sep, n)` — at most n substrings.
///
///   n > 0  → at most n substrings; last is the unsplit remainder.
///   n == 0 → empty result.
///   n < 0  → no limit (same as Split).
pub fn SplitN<S1: Into<string>, S2: Into<string>>(s: S1, sep: S2, n: int) -> slice<string> {
    gen_split(s.into(), sep.into(), 0, n)
}

fn gen_split(s: string, sep: string, sep_save: int, mut n: int) -> slice<string> {
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
    let max_n = s_bytes.len() as int + 1;
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
    slice::__from_vec(a)
}

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
    slice::__from_vec(a)
}

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
    string::__from_vec(v)
}

// ─── Contains / HasPrefix / HasSuffix ─────────────────────────────────

pub fn Contains<S1: Into<string>, S2: Into<string>>(s: S1, substr: S2) -> bool {
    Index(s, substr) >= 0
}

pub fn ContainsRune<S: Into<string>>(s: S, r: rune) -> bool {
    IndexRune(s, r) >= 0
}

pub fn HasPrefix<S1: Into<string>, S2: Into<string>>(s: S1, prefix: S2) -> bool {
    let s = s.into();
    let prefix = prefix.into();
    has_prefix_bytes(s.as_bytes(), prefix.as_bytes())
}

pub fn HasSuffix<S1: Into<string>, S2: Into<string>>(s: S1, suffix: S2) -> bool {
    let s = s.into();
    let suffix = suffix.into();
    has_suffix_bytes(s.as_bytes(), suffix.as_bytes())
}

// ─── Index / IndexByte / IndexRune / LastIndex ────────────────────────

pub fn Index<S1: Into<string>, S2: Into<string>>(s: S1, substr: S2) -> int {
    let s = s.into();
    let substr = substr.into();
    index_bytes(s.as_bytes(), substr.as_bytes())
}

pub fn IndexByte<S: Into<string>>(s: S, c: byte) -> int {
    let s = s.into();
    index_byte(s.as_bytes(), c)
}

pub fn IndexRune<S: Into<string>>(s: S, r: rune) -> int {
    let s = s.into();
    if r >= 0 && (r as u32) < utf8::RuneSelf as u32 {
        return index_byte(s.as_bytes(), r as byte);
    }
    if !utf8::ValidRune(r) {
        return -1;
    }
    let mut buf = [0u8; 4];
    let n = utf8::EncodeRune(&mut buf, r);
    index_bytes(s.as_bytes(), &buf[..n as usize])
}

pub fn LastIndex<S1: Into<string>, S2: Into<string>>(s: S1, substr: S2) -> int {
    let s = s.into();
    let substr = substr.into();
    last_index_bytes(s.as_bytes(), substr.as_bytes())
}

pub fn Count<S1: Into<string>, S2: Into<string>>(s: S1, substr: S2) -> int {
    let s = s.into();
    let substr = substr.into();
    count_bytes(s.as_bytes(), substr.as_bytes())
}

// ─── Trim family ──────────────────────────────────────────────────────

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
    string::from_bytes(&bytes[start..stop])
}

pub fn Trim<S1: Into<string>, S2: Into<string>>(s: S1, cutset: S2) -> string {
    let s = s.into();
    let cutset = cutset.into();
    let bytes = s.as_bytes();
    let cs = cutset.as_bytes();
    if bytes.is_empty() || cs.is_empty() {
        return s;
    }
    let mut start = 0usize;
    while start < bytes.len() && cs.contains(&bytes[start]) {
        start += 1;
    }
    let mut stop = bytes.len();
    while stop > start && cs.contains(&bytes[stop - 1]) {
        stop -= 1;
    }
    if start == 0 && stop == bytes.len() {
        return s;
    }
    string::from_bytes(&bytes[start..stop])
}

pub fn TrimLeft<S1: Into<string>, S2: Into<string>>(s: S1, cutset: S2) -> string {
    let s = s.into();
    let cutset = cutset.into();
    let bytes = s.as_bytes();
    let cs = cutset.as_bytes();
    if bytes.is_empty() || cs.is_empty() {
        return s;
    }
    let mut start = 0usize;
    while start < bytes.len() && cs.contains(&bytes[start]) {
        start += 1;
    }
    if start == 0 {
        return s;
    }
    string::from_bytes(&bytes[start..])
}

pub fn TrimRight<S1: Into<string>, S2: Into<string>>(s: S1, cutset: S2) -> string {
    let s = s.into();
    let cutset = cutset.into();
    let bytes = s.as_bytes();
    let cs = cutset.as_bytes();
    if bytes.is_empty() || cs.is_empty() {
        return s;
    }
    let mut stop = bytes.len();
    while stop > 0 && cs.contains(&bytes[stop - 1]) {
        stop -= 1;
    }
    if stop == bytes.len() {
        return s;
    }
    string::from_bytes(&bytes[..stop])
}

pub fn TrimPrefix<S1: Into<string>, S2: Into<string>>(s: S1, prefix: S2) -> string {
    let s = s.into();
    let prefix = prefix.into();
    let bytes = s.as_bytes();
    let pb = prefix.as_bytes();
    if has_prefix_bytes(bytes, pb) {
        return string::from_bytes(&bytes[pb.len()..]);
    }
    s
}

pub fn TrimSuffix<S1: Into<string>, S2: Into<string>>(s: S1, suffix: S2) -> string {
    let s = s.into();
    let suffix = suffix.into();
    let bytes = s.as_bytes();
    let sb = suffix.as_bytes();
    if has_suffix_bytes(bytes, sb) {
        return string::from_bytes(&bytes[..bytes.len() - sb.len()]);
    }
    s
}

// ─── ToUpper / ToLower (ASCII-only for v1) ────────────────────────────

pub fn ToUpper<S: Into<string>>(s: S) -> string {
    let s = s.into();
    let bytes = s.as_bytes();
    let mut has_lower = false;
    for &c in bytes {
        if c >= b'a' && c <= b'z' {
            has_lower = true;
            break;
        }
    }
    if !has_lower {
        return s;
    }
    let mut v: Vec<byte> = Vec::with_capacity(bytes.len());
    for &c in bytes {
        if c >= b'a' && c <= b'z' {
            v.push(c - (b'a' - b'A'));
        } else {
            v.push(c);
        }
    }
    string::__from_vec(v)
}

pub fn ToLower<S: Into<string>>(s: S) -> string {
    let s = s.into();
    let bytes = s.as_bytes();
    let mut has_upper = false;
    for &c in bytes {
        if c >= b'A' && c <= b'Z' {
            has_upper = true;
            break;
        }
    }
    if !has_upper {
        return s;
    }
    let mut v: Vec<byte> = Vec::with_capacity(bytes.len());
    for &c in bytes {
        if c >= b'A' && c <= b'Z' {
            v.push(c + (b'a' - b'A'));
        } else {
            v.push(c);
        }
    }
    string::__from_vec(v)
}

// ─── Replace / ReplaceAll / Repeat ────────────────────────────────────

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
    let delta = new_bytes.len() as int - old_bytes.len() as int;
    let cap_signed = s_bytes.len() as int + n * delta;
    let cap_usize = if cap_signed > 0 { cap_signed as usize } else { 0 };
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
    string::__from_vec(v)
}

pub fn ReplaceAll<S1, S2, S3>(s: S1, old: S2, new_: S3) -> string
where
    S1: Into<string>,
    S2: Into<string>,
    S3: Into<string>,
{
    Replace(s, old, new_, -1)
}

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
    let total = (src.len() as int)
        .checked_mul(count)
        .expect("strings: Repeat output length overflow");
    let mut v: Vec<byte> = Vec::with_capacity(total as usize);
    for _ in 0..count {
        v.extend_from_slice(src);
    }
    string::__from_vec(v)
}

// ─── EqualFold (ASCII-only for v1) ────────────────────────────────────

pub fn EqualFold<S1: Into<string>, S2: Into<string>>(s: S1, t: S2) -> bool {
    let s = s.into();
    let t = t.into();
    let sb = s.as_bytes();
    let tb = t.as_bytes();
    if sb.len() != tb.len() {
        // ASCII-only path: equal-fold cannot change byte length. When
        // unicode case folding lands, this fast reject goes away.
        return false;
    }
    let mut i = 0usize;
    while i < sb.len() {
        let mut sr = sb[i];
        let mut tr = tb[i];
        if sr == tr {
            i += 1;
            continue;
        }
        if sr > tr {
            core::mem::swap(&mut sr, &mut tr);
        }
        // sr <= tr; check if they differ by ASCII-case bit only.
        if sr >= b'A' && sr <= b'Z' && tr == sr + (b'a' - b'A') {
            i += 1;
            continue;
        }
        return false;
    }
    true
}

// ─── Builder ──────────────────────────────────────────────────────────
//
// Append-only buffer. Single-shot `String(self)` consumes the builder
// and yields a `string` backed by the same bytes (zero-copy internally).
//
// Differences from Go's strings.Builder:
//
//   * `String` consumes (Q1 = A in wip_strings.md). Calling String twice
//     is a compile error rather than a runtime alias hazard.
//   * No `addr` self-pointer / copyCheck — Rust's ownership rules already
//     prevent accidental copy-then-mutate via the same code paths.

pub struct Builder {
    buf: Vec<byte>,
}

impl Builder {
    pub fn new() -> Self {
        Self { buf: Vec::new() }
    }

    pub fn Len(&self) -> int {
        self.buf.len() as int
    }

    pub fn Cap(&self) -> int {
        self.buf.capacity() as int
    }

    pub fn Reset(&mut self) {
        self.buf.clear();
    }

    pub fn Grow(&mut self, n: int) {
        if n < 0 {
            panic!("strings.Builder.Grow: negative count");
        }
        let extra = n as usize;
        let avail = self.buf.capacity() - self.buf.len();
        if extra > avail {
            self.buf.reserve(extra - avail);
        }
    }

    /// Consume the builder and return the accumulated bytes as a `string`.
    /// **v1**: this consumes — see module-level docs.
    pub fn String(self) -> string {
        string::__from_vec(self.buf)
    }

    pub fn WriteString<S: Into<string>>(&mut self, s: S) -> (int, error) {
        let s = s.into();
        let bytes = s.as_bytes();
        self.buf.extend_from_slice(bytes);
        (bytes.len() as int, nil)
    }

    pub fn WriteByte(&mut self, c: byte) -> error {
        self.buf.push(c);
        nil
    }

    pub fn WriteRune(&mut self, r: rune) -> (int, error) {
        let mut tmp = [0u8; 4];
        let n = utf8::EncodeRune(&mut tmp, r);
        self.buf.extend_from_slice(&tmp[..n as usize]);
        (n, nil)
    }
}

impl Default for Builder {
    fn default() -> Self {
        Self::new()
    }
}

// `io.Writer` impl — consumes the slice, writes its bytes, returns
// `(len(p), nil)`. Lets `Fprintf!(b, ...)` target a Builder.
impl io::Writer for Builder {
    fn Write(&mut self, p: slice<byte>) -> (int, error) {
        let n = p.Len();
        self.buf.extend_from_slice(&p);
        (n, nil)
    }
}
