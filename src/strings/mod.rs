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

#[path = "search.rs"]
mod search;

#[path = "iter.rs"]
mod iter_go;
pub use iter_go::{FieldsFuncSeq, FieldsSeq, Lines, SplitAfterSeq, SplitSeq};

#[path = "strings.rs"]
mod strings;
pub use strings::{
    ToLowerSpecial, ToTitleSpecial, ToUpperSpecial, Trim, TrimLeft, TrimPrefix, TrimRight,
    TrimSpace, TrimSuffix,
};

#[path = "replace.rs"]
mod replace;
pub use replace::{NewReplacer, Replacer};

use alloc::vec::Vec;

use crate::error;
use crate::errors::nil;
use crate::goslice::slice;
use crate::gostring::string;
use crate::io;
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

pub(super) fn has_prefix_bytes(s: &[u8], prefix: &[u8]) -> bool {
    s.len() >= prefix.len() && &s[..prefix.len()] == prefix
}

pub(super) fn has_suffix_bytes(s: &[u8], suffix: &[u8]) -> bool {
    s.len() >= suffix.len() && &s[s.len() - suffix.len()..] == suffix
}

#[inline]
pub(super) fn is_ascii_space(c: byte) -> bool {
    matches!(c, b' ' | b'\t' | b'\n' | b'\r' | 0x0B | 0x0C)
}

// ─── Split / Join ─────────────────────────────────────────────────────

/// `strings.Split(s, sep)` — splits s into substrings separated by sep.
///
/// If sep is empty, splits after each UTF-8 sequence (Go-faithful).
pub fn Split<S1: Into<string>, S2: Into<string>>(s: S1, sep: S2) -> slice<string> {
    genSplit(s.into(), sep.into(), 0, -1)
}

/// `strings.SplitN(s, sep, n)` — at most n substrings.
///
///   n > 0  → at most n substrings; last is the unsplit remainder.
///   n == 0 → empty result.
///   n < 0  → no limit (same as Split).
pub fn SplitN<S1: Into<string>, S2: Into<string>>(s: S1, sep: S2, n: int) -> slice<string> {
    genSplit(s.into(), sep.into(), 0, n)
}

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

// ─── ToUpper / ToLower / ToTitle ──────────────────────────────────────

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
    map_runes(bytes, crate::unicode::ToUpper)
}

// Rune-wise case map for the non-ASCII path of ToUpper/ToLower.
fn map_runes(bytes: &[byte], f: fn(rune) -> rune) -> string {
    let mut v: Vec<byte> = Vec::with_capacity(bytes.len());
    let mut i = 0usize;
    while i < bytes.len() {
        let (r, size) = crate::unicode::utf8::DecodeRune(&bytes[i..]);
        let m = f(r);
        match char::from_u32(m as u32) {
            Some(c) => {
                let mut buf = [0u8; 4];
                v.extend_from_slice(c.encode_utf8(&mut buf).as_bytes());
            }
            None => v.extend_from_slice(&bytes[i..i + size as usize]),
        }
        i += size as usize;
    }
    string::__from_vec(v)
}

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
    map_runes(bytes, crate::unicode::ToLower)
}

/// `strings.ToTitle(s)` — every rune mapped to its Unicode title case.
///
/// The note that used to sit here said non-ASCII runes passed through
/// unchanged "until the SpecialCasing tables ship". They have:
/// `unicode::ToTitle` runs on Go's `CaseRanges` now, so U+01C4 maps to
/// U+01C5 rather than to itself.
pub fn ToTitle<S: Into<string>>(s: S) -> string {
    // Go: return Map(unicode.ToTitle, s)
    Map(crate::unicode::ToTitle, s)
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

// ─── EqualFold ────────────────────────────────────────────────────────

pub fn EqualFold<S1: Into<string>, S2: Into<string>>(s: S1, t: S2) -> bool {
    let s = s.into();
    let t = t.into();
    let mut sb = s.as_bytes();
    let mut tb = t.as_bytes();
    // Go strings.go EqualFold: ASCII fast path byte-by-byte, general
    // path rune-by-rune with the SimpleFold orbit walk.
    while !sb.is_empty() && !tb.is_empty() {
        let (sr, ssize) = if sb[0] < 0x80 {
            (sb[0] as rune, 1usize)
        } else {
            let (r, n) = crate::unicode::utf8::DecodeRune(sb);
            (r, n as usize)
        };
        let (tr, tsize) = if tb[0] < 0x80 {
            (tb[0] as rune, 1usize)
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
            if (b'A' as rune..=b'Z' as rune).contains(&sr)
                && tr == sr + (b'a' as rune - b'A' as rune)
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
    sb.is_empty() && tb.is_empty()
}

// go: waived copyCheck — Go's Builder holds a `addr *Builder` self
//     pointer and copyCheck panics when it finds the Builder has been
//     copied, using `noescape` to keep that pointer off the heap. A
//     goish Builder owns its Vec and a copy is a deep copy, so there
//     is no aliasing bug to detect and no self pointer to compare.
//
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

// ─── M15: completeness pass ───────────────────────────────────────────

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
    (before, after, true)
}

/// `strings.CutPrefix(s, prefix)` — strip `prefix`, report whether it
/// was present. Returns `(after, found)`.
pub fn CutPrefix<S1: Into<string>, S2: Into<string>>(s: S1, prefix: S2) -> (string, bool) {
    let s = s.into();
    let prefix = prefix.into();
    if HasPrefix(s.clone(), prefix.clone()) {
        return (sub(&s, prefix.Len(), s.Len()), true);
    }
    (s, false)
}

/// `strings.CutSuffix(s, suffix)` — strip `suffix`. Returns `(before, found)`.
pub fn CutSuffix<S1: Into<string>, S2: Into<string>>(s: S1, suffix: S2) -> (string, bool) {
    let s = s.into();
    let suffix = suffix.into();
    if HasSuffix(s.clone(), suffix.clone()) {
        return (sub(&s, 0, s.Len() - suffix.Len()), true);
    }
    (s, false)
}

/// `strings.Compare(a, b)` — `-1`/`0`/`+1`. Goish provides `==` and
/// `<`/`>` on `string` directly; this exists for API parity with Go.
pub fn Compare<S1: Into<string>, S2: Into<string>>(a: S1, b: S2) -> int {
    let a = a.into();
    let b = b.into();
    let ab = a.as_bytes();
    let bb = b.as_bytes();
    if ab < bb {
        -1
    } else if ab > bb {
        1
    } else {
        0
    }
}

/// `strings.Clone(s)` — fresh, independent copy. For our `Arc<[u8]>`
/// backing this forces a non-shared allocation.
pub fn Clone<S: Into<string>>(s: S) -> string {
    let s = s.into();
    string::from_bytes(s.as_bytes())
}

/// `strings.ContainsAny(s, chars)` — true if any byte of `chars`
/// appears in `s`. ASCII byte-wise scan in v1.
pub fn ContainsAny<S1: Into<string>, S2: Into<string>>(s: S1, chars: S2) -> bool {
    IndexAny(s, chars) >= 0
}

/// `strings.ContainsFunc(s, f)` — true if any rune in `s` satisfies `f`.
pub fn ContainsFunc<S: Into<string>, F: Fn(rune) -> bool>(s: S, f: F) -> bool {
    IndexFunc(s, f) >= 0
}

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
                return i as int;
            }
        }
    }
    -1
}

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
                return i as int;
            }
        }
    }
    -1
}

/// `strings.LastIndexByte(s, c)` — last index of byte `c`, or `-1`.
pub fn LastIndexByte<S: Into<string>>(s: S, c: byte) -> int {
    let s = s.into();
    let sb = s.as_bytes();
    let mut i = sb.len();
    while i > 0 {
        i -= 1;
        if sb[i] == c {
            return i as int;
        }
    }
    -1
}

/// `strings.IndexFunc(s, f)` — index (in bytes) of first rune in `s`
/// satisfying `f`, or `-1`.
pub fn IndexFunc<S: Into<string>, F: Fn(rune) -> bool>(s: S, f: F) -> int {
    let s = s.into();
    let mut i = 0;
    let bytes = s.as_bytes();
    while i < bytes.len() {
        let (r, w) = utf8::DecodeRune(&bytes[i..]);
        if f(r) {
            return i as int;
        }
        if w == 0 {
            break;
        }
        i += w as usize;
    }
    -1
}

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
            return i as int;
        }
    }
    -1
}

/// `strings.Fields(s)` — split on runs of `unicode.IsSpace`. Empty
/// elements between consecutive whitespace are dropped.
pub fn Fields<S: Into<string>>(s: S) -> slice<string> {
    FieldsFunc(s, crate::unicode::IsSpace)
}

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
    slice::__from_vec(out)
}

/// `strings.TrimFunc(s, f)` — strip leading + trailing runes satisfying `f`.
pub fn TrimFunc<S: Into<string>, F: Fn(rune) -> bool + Copy>(s: S, f: F) -> string {
    TrimRightFunc(TrimLeftFunc(s, f), f)
}

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
    string::from_bytes(&bytes[i..])
}

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
    string::from_bytes(&bytes[..end])
}

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
    string::__from_vec(out)
}

/// Line-by-line port of `strings.isSeparator` (strings/strings.go:840).
fn isSeparator(r: rune) -> bool {
    // Go: if r <= 0x7F { ... } else { …unicode.IsLetter / IsDigit / IsSpace }
    if r <= 0x7F {
        if r >= b'0' as rune && r <= b'9' as rune {
            return false;
        }
        if r >= b'a' as rune && r <= b'z' as rune {
            return false;
        }
        if r >= b'A' as rune && r <= b'Z' as rune {
            return false;
        }
        if r == b'_' as rune {
            return false;
        }
        return true;
    }
    // Slim: goish lacks the unicode tables; treat non-ASCII as non-separator.
    false
}

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
    let mut prev: rune = b' ' as rune;
    let mut tmp = [0u8; 4];
    let mut i: usize = 0;
    while i < bytes.len() {
        let (r, w) = utf8::DecodeRune(&bytes[i..]);
        let nr = if isSeparator(prev) {
            // Slim ToTitle: ASCII a..z → A..Z; everything else unchanged.
            if r >= b'a' as rune && r <= b'z' as rune {
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
    string::__from_vec(out)
}

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
    string::__from_vec(b)
}

/// `strings.SplitAfter(s, sep)` — split *retaining* the separator at
/// the end of each segment.
pub fn SplitAfter<S1: Into<string>, S2: Into<string>>(s: S1, sep: S2) -> slice<string> {
    SplitAfterN(s, sep, -1)
}

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
            if n > 0 && out.len() as int == n - 1 {
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
        if n > 0 && out.len() as int == n - 1 {
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
    slice::__from_vec(out)
}

// Internal helper: substring by [low, high).
fn sub(s: &string, low: int, high: int) -> string {
    let bytes = s.as_bytes();
    string::from_bytes(&bytes[low as usize..high as usize])
}

// ─── strings.Reader ───────────────────────────────────────────────────

/// `strings.Reader` — `io.Reader` over an immutable string. Mirrors
/// Go's `strings.Reader` (read-only).
pub struct Reader {
    s: string,
    i: int,
    /// Mirrors Go's `prevRune`: index of previous rune, or `-1` if
    /// the most recent op was not a successful ReadRune. Used only
    /// by UnreadRune.
    prev_rune: int,
}

impl Reader {
    pub fn Len(&self) -> int {
        if self.i >= self.s.Len() {
            return 0;
        }
        self.s.Len() - self.i
    }

    pub fn Size(&self) -> int {
        self.s.Len()
    }

    pub fn Read(&mut self, p: &mut slice<byte>) -> (int, error) {
        if self.i >= self.s.Len() {
            return (0, io::EOF.into());
        }
        // Go: r.prevRune = -1
        self.prev_rune = -1;
        let want = (p.Len() as usize).min((self.s.Len() - self.i) as usize);
        let bytes = self.s.as_bytes();
        for k in 0..want {
            p[k as int] = bytes[self.i as usize + k];
        }
        self.i += want as int;
        (want as int, nil)
    }

    pub fn Reset<S: Into<string>>(&mut self, s: S) {
        // Go: *r = Reader{s, 0, -1}
        self.s = s.into();
        self.i = 0;
        self.prev_rune = -1;
    }

    /// `(r *Reader).ReadByte()` (strings/reader.go:66) — implements
    /// io.ByteReader.
    pub fn ReadByte(&mut self) -> (byte, error) {
        // Go: r.prevRune = -1
        self.prev_rune = -1;
        // Go: if r.i >= int64(len(r.s)) { return 0, io.EOF }
        if self.i >= self.s.Len() {
            return (0, io::EOF.into());
        }
        // Go: b := r.s[r.i]; r.i++; return b, nil
        let b = self.s.as_bytes()[self.i as usize];
        self.i += 1;
        (b, nil)
    }

    /// `(r *Reader).UnreadByte()` (strings/reader.go:77) — implements
    /// io.ByteScanner.
    pub fn UnreadByte(&mut self) -> error {
        // Go: if r.i <= 0 { return errors.New("...: at beginning of string") }
        if self.i == 0 {
            return crate::errors::New("strings.Reader.UnreadByte: at beginning of string");
        }
        // Go: r.prevRune = -1; r.i--; return nil
        self.prev_rune = -1;
        self.i -= 1;
        nil
    }

    /// `(r *Reader).ReadRune()` (strings/reader.go:87) — implements
    /// io.RuneReader. ASCII fast-path; non-ASCII via DecodeRuneInString.
    pub fn ReadRune(&mut self) -> (rune, int, error) {
        // Go: if r.i >= int64(len(r.s)) { r.prevRune = -1; return 0, 0, io.EOF }
        if self.i >= self.s.Len() {
            self.prev_rune = -1;
            return (0, 0, io::EOF.into());
        }
        // Go: r.prevRune = int(r.i)
        self.prev_rune = self.i;
        // Go: if c := r.s[r.i]; c < utf8.RuneSelf { r.i++; return rune(c), 1, nil }
        let c = self.s.as_bytes()[self.i as usize];
        if c < utf8::RuneSelf {
            self.i += 1;
            return (c as rune, 1, nil);
        }
        // Go: ch, size = utf8.DecodeRuneInString(r.s[r.i:])
        let tail = string::from_bytes(&self.s.as_bytes()[self.i as usize..]);
        let (ch, size) = utf8::DecodeRuneInString(&tail);
        // Go: r.i += int64(size)
        self.i += size;
        (ch, size, nil)
    }

    /// `(r *Reader).UnreadRune()` (strings/reader.go:103) — implements
    /// io.RuneScanner. Restores cursor to the start of the most-recent
    /// ReadRune.
    pub fn UnreadRune(&mut self) -> error {
        // Go: if r.i <= 0 { return errors.New("...: at beginning of string") }
        if self.i == 0 {
            return crate::errors::New("strings.Reader.UnreadRune: at beginning of string");
        }
        // Go: if r.prevRune < 0 { return errors.New("...: previous operation was not ReadRune") }
        if self.prev_rune < 0 {
            return crate::errors::New(
                "strings.Reader.UnreadRune: previous operation was not ReadRune",
            );
        }
        // Go: r.i = int64(r.prevRune); r.prevRune = -1; return nil
        self.i = self.prev_rune;
        self.prev_rune = -1;
        nil
    }

    /// `(r *Reader).Seek(offset, whence)` (strings/reader.go:99) — slim port.
    pub fn Seek(&mut self, offset: i64, whence: int) -> (i64, error) {
        // Go: r.prevRune = -1
        self.prev_rune = -1;
        let abs: i64 = if whence == io::SeekStart {
            offset
        } else if whence == io::SeekCurrent {
            (self.i as i64).wrapping_add(offset)
        } else if whence == io::SeekEnd {
            (self.s.Len() as i64).wrapping_add(offset)
        } else {
            return (0, crate::errors::New("strings.Reader.Seek: invalid whence"));
        };
        if abs < 0 {
            return (
                0,
                crate::errors::New("strings.Reader.Seek: negative position"),
            );
        }
        self.i = abs as int;
        (abs, nil)
    }

    /// `(r *Reader).ReadAt(p, off)` (strings/reader.go:62) — slim port.
    pub fn ReadAt(&mut self, p: &mut slice<byte>, off: i64) -> (int, error) {
        if off < 0 {
            return (
                0,
                crate::errors::New("strings.Reader.ReadAt: negative offset"),
            );
        }
        if off >= self.s.Len() as i64 {
            return (0, io::EOF.into());
        }
        let bytes = self.s.as_bytes();
        let start = off as usize;
        let want = (p.Len() as usize).min(bytes.len() - start);
        for k in 0..want {
            p[k as int] = bytes[start + k];
        }
        if want < p.Len() as usize {
            return (want as int, io::EOF.into());
        }
        (want as int, nil)
    }
}

impl io::Reader for Reader {
    fn Read(&mut self, p: &mut slice<byte>) -> (int, error) {
        Reader::Read(self, p)
    }
}

impl io::Seeker for Reader {
    fn Seek(&mut self, offset: i64, whence: int) -> (i64, error) {
        Reader::Seek(self, offset, whence)
    }
}

impl io::ReaderAt for Reader {
    fn ReadAt(&mut self, p: &mut slice<byte>, off: i64) -> (int, error) {
        Reader::ReadAt(self, p, off)
    }
}

impl Reader {
    /// `(r *Reader).WriteTo(w)` (strings/reader.go:137) — drain the
    /// unread tail to `w` via WriteString. Returns bytes written.
    pub fn WriteTo(&mut self, w: &mut dyn io::Writer) -> (i64, error) {
        // Go: r.prevRune = -1
        self.prev_rune = -1;
        // Go: if r.i >= int64(len(r.s)) { return 0, nil }
        if self.i as usize >= self.s.as_bytes().len() {
            return (0, nil);
        }
        // s := r.s[r.i:]
        let tail = &self.s.as_bytes()[self.i as usize..];
        let s_tail = string::from_bytes(tail);
        // m, err := io.WriteString(w, s)
        let (m, err) = io::WriteString(w, s_tail);
        if (m as usize) > tail.len() {
            panic!("strings.Reader.WriteTo: invalid WriteString count");
        }
        // r.i += int64(m); n = int64(m)
        self.i += m as i64;
        let n = m as i64;
        // if m != len(s) && err == nil { err = io.ErrShortWrite }
        if (m as usize) != tail.len() && err.IsNil() {
            return (n, io::ErrShortWrite.into());
        }
        (n, err)
    }
}

impl io::WriterTo for Reader {
    fn WriteTo(&mut self, w: &mut dyn io::Writer) -> (i64, error) {
        Reader::WriteTo(self, w)
    }
}

/// `strings.NewReader(s)` — `Reader` over `s`.
pub fn NewReader<S: Into<string>>(s: S) -> Reader {
    Reader {
        s: s.into(),
        i: 0,
        prev_rune: -1,
    }
}

// ─── Replacer (slim port of strings/replace.go) ──────────────────────

// go: none — goish idiom: fill the `#[goish::interface]` downcast
// registries for the types this package declares. See AGENTS.md §9b.
/// Register `strings`'s concrete types into the `io` interface
/// registries. Idempotent; called from `goish::init()`.
pub fn register_strings_impls() {
    use crate::io::{
        __goish_register_ReaderAt_impl, __goish_register_Reader_impl, __goish_register_Seeker_impl,
        __goish_register_WriterTo_impl, __goish_register_Writer_impl,
    };
    __goish_register_Writer_impl::<Builder>();
    __goish_register_Reader_impl::<Reader>();
    __goish_register_ReaderAt_impl::<Reader>();
    __goish_register_Seeker_impl::<Reader>();
    __goish_register_WriterTo_impl::<Reader>();
}
