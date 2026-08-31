// bytes — Go's `bytes` package, ported. M13.
//
// Mirror of M10 `strings` over `slice<byte>`. Same surface, same call
// shape. Plus `Buffer` (read-write byte buffer, `io.Reader`+`io.Writer`)
// and `Reader` (in-memory `io.Reader`).
//
// Functions:
//   Equal, Compare, Count, Contains, ContainsRune,
//   Index, IndexByte, IndexRune, LastIndex, LastIndexByte,
//   HasPrefix, HasSuffix,
//   TrimSpace, Trim, TrimLeft, TrimRight, TrimPrefix, TrimSuffix,
//   ToUpper, ToLower (ASCII), EqualFold (ASCII),
//   Replace, ReplaceAll, Repeat,
//   Split, SplitN, Join, Clone.
//
// Types:
//   Buffer — variable-size byte buffer with Write* + Read methods,
//            implements io::Reader and io::Writer.
//   Reader — in-memory io::Reader over a slice<byte>.
//
// All `slice<byte>` inputs take `S: Into<slice<byte>>` so byte literals
// (`b","`) flow without wrapping (relies on the `From<&[u8]>` and
// `From<&[u8; N]>` impls on `slice<T>`).
//
// v1 deviations from Go:
//
//   * `Buffer::Bytes()` and `Buffer::String()` clone. Go returns a view
//     into the unread portion of the internal buffer; goish slices/
//     strings are owning, so we clone. Slightly more allocation, never
//     invalidated by next Write/Read/Reset.
//   * `ToUpper`/`ToLower`/`EqualFold` are ASCII-only — bytes ≥ 0x80 pass
//     through unchanged. Same trade as `strings`.
//   * `Index`/`LastIndex` use naive O(n*m) byte search.
//   * `Trim`/`TrimLeft`/`TrimRight` use byte-set semantics on cutset.
//   * Each `Split` segment is a fresh `slice<byte>` (copy).
//   * `Reader` only implements `io.Reader` — `Seek`/`ReadAt`/`ReadByte`/
//     `ReadRune`/`UnreadByte` deferred (need `io.Seeker` etc.).

#![allow(non_snake_case)]

extern crate alloc;
use alloc::vec::Vec;

use crate::goslice::slice;
use crate::types::{byte, int, rune};
use crate::unicode::utf8;

// ─── Private byte helpers (no allocation) ─────────────────────────────

pub(super) fn indexBytePortable(s: &[u8], c: byte) -> int {
    let mut i = 0usize;
    while i < s.len() {
        if s[i] == c {
            return i as int;
        }
        i += 1;
    }
    -1
}

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

fn last_index_byte(s: &[u8], c: byte) -> int {
    let mut i = s.len() as isize - 1;
    while i >= 0 {
        if s[i as usize] == c {
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

fn has_prefix(s: &[u8], prefix: &[u8]) -> bool {
    s.len() >= prefix.len() && &s[..prefix.len()] == prefix
}

fn has_suffix(s: &[u8], suffix: &[u8]) -> bool {
    s.len() >= suffix.len() && &s[s.len() - suffix.len()..] == suffix
}

#[inline]
pub(super) fn is_ascii_space(c: byte) -> bool {
    matches!(c, b' ' | b'\t' | b'\n' | b'\r' | 0x0B | 0x0C)
}

#[path = "reader.rs"]
mod reader;
pub use reader::{NewReader, Reader};

#[path = "buffer.rs"]
mod buffer;
pub use buffer::{Buffer, MinRead, NewBuffer, NewBufferString};

#[path = "bytes.rs"]
mod bytes_go;
pub use bytes_go::{
    ToLower, ToLowerSpecial, ToTitle, ToTitleSpecial, ToUpper, ToUpperSpecial, Trim, TrimLeft,
    TrimPrefix, TrimRight, TrimSpace, TrimSuffix,
};

#[path = "iter.rs"]
mod iter_go;
pub use iter_go::{FieldsFuncSeq, FieldsSeq, Lines, SplitAfterSeq, SplitSeq};

// ─── Search / equality / compare ──────────────────────────────────────

pub fn Equal<S1: Into<slice<byte>>, S2: Into<slice<byte>>>(a: S1, b: S2) -> bool {
    let a = a.into();
    let b = b.into();
    let av: &[byte] = &a;
    let bv: &[byte] = &b;
    av == bv
}

pub fn Compare<S1: Into<slice<byte>>, S2: Into<slice<byte>>>(a: S1, b: S2) -> int {
    use core::cmp::Ordering::*;
    let a = a.into();
    let b = b.into();
    let av: &[byte] = &a;
    let bv: &[byte] = &b;
    match av.cmp(bv) {
        Less => -1,
        Equal => 0,
        Greater => 1,
    }
}

pub fn Contains<S1: Into<slice<byte>>, S2: Into<slice<byte>>>(s: S1, sub: S2) -> bool {
    Index(s, sub) >= 0
}

pub fn ContainsRune<S: Into<slice<byte>>>(s: S, r: rune) -> bool {
    IndexRune(s, r) >= 0
}

pub fn HasPrefix<S1: Into<slice<byte>>, S2: Into<slice<byte>>>(s: S1, prefix: S2) -> bool {
    let s = s.into();
    let prefix = prefix.into();
    has_prefix(&s, &prefix)
}

pub fn HasSuffix<S1: Into<slice<byte>>, S2: Into<slice<byte>>>(s: S1, suffix: S2) -> bool {
    let s = s.into();
    let suffix = suffix.into();
    has_suffix(&s, &suffix)
}

pub fn Index<S1: Into<slice<byte>>, S2: Into<slice<byte>>>(s: S1, sub: S2) -> int {
    let s = s.into();
    let sub = sub.into();
    index_bytes(&s, &sub)
}

pub fn IndexByte<S: Into<slice<byte>>>(s: S, c: byte) -> int {
    let s = s.into();
    indexBytePortable(&s, c)
}

pub fn IndexRune<S: Into<slice<byte>>>(s: S, r: rune) -> int {
    let s = s.into();
    if r >= 0 && (r as u32) < utf8::RuneSelf as u32 {
        return indexBytePortable(&s, r as byte);
    }
    if !utf8::ValidRune(r) {
        return -1;
    }
    let mut buf = [0u8; 4];
    let n = utf8::EncodeRune(&mut buf, r);
    index_bytes(&s, &buf[..n as usize])
}

pub fn LastIndex<S1: Into<slice<byte>>, S2: Into<slice<byte>>>(s: S1, sub: S2) -> int {
    let s = s.into();
    let sub = sub.into();
    last_index_bytes(&s, &sub)
}

pub fn LastIndexByte<S: Into<slice<byte>>>(s: S, c: byte) -> int {
    let s = s.into();
    last_index_byte(&s, c)
}

pub fn Count<S1: Into<slice<byte>>, S2: Into<slice<byte>>>(s: S1, sep: S2) -> int {
    let s = s.into();
    let sep = sep.into();
    count_bytes(&s, &sep)
}

// ─── Trim family ──────────────────────────────────────────────────────

// ─── Case (ASCII-only) / EqualFold ────────────────────────────────────

pub fn EqualFold<S1: Into<slice<byte>>, S2: Into<slice<byte>>>(s: S1, t: S2) -> bool {
    let s = s.into();
    let t = t.into();
    let sb: &[byte] = &s;
    let tb: &[byte] = &t;
    if sb.len() != tb.len() {
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
        if sr >= b'A' && sr <= b'Z' && tr == sr + (b'a' - b'A') {
            i += 1;
            continue;
        }
        return false;
    }
    true
}

// ─── Replace / Repeat ─────────────────────────────────────────────────

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

    let delta = n_b.len() as int - o_b.len() as int;
    let cap_signed = s_b.len() as int + n * delta;
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
    slice::__from_vec(v)
}

pub fn ReplaceAll<S1, S2, S3>(s: S1, old: S2, new_: S3) -> slice<byte>
where
    S1: Into<slice<byte>>,
    S2: Into<slice<byte>>,
    S3: Into<slice<byte>>,
{
    Replace(s, old, new_, -1)
}

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
    let total = (src.len() as int)
        .checked_mul(count)
        .expect("bytes: Repeat output length overflow");
    let mut v: Vec<byte> = Vec::with_capacity(total as usize);
    for _ in 0..count {
        v.extend_from_slice(src);
    }
    slice::__from_vec(v)
}

// ─── Split / Join ─────────────────────────────────────────────────────

pub fn Split<S1: Into<slice<byte>>, S2: Into<slice<byte>>>(s: S1, sep: S2) -> slice<slice<byte>> {
    genSplit(s.into(), sep.into(), 0, -1)
}

pub fn SplitN<S1: Into<slice<byte>>, S2: Into<slice<byte>>>(
    s: S1,
    sep: S2,
    n: int,
) -> slice<slice<byte>> {
    genSplit(s.into(), sep.into(), 0, n)
}

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
    let max_n = s_b.len() as int + 1;
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
    slice::__from_vec(a)
}

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
    slice::__from_vec(a)
}

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
    slice::__from_vec(v)
}

// ─── Clone ────────────────────────────────────────────────────────────

pub fn Clone<S: Into<slice<byte>>>(b: S) -> slice<byte> {
    // Go's bytes.Clone returns a fresh allocation. We do the same:
    // .into() yields a slice<byte> (which may be an existing one or a
    // fresh copy from a literal). Either way, .clone() of a slice<byte>
    // is independent storage.
    b.into().clone()
}

// ─── M15: completeness pass ───────────────────────────────────────────

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
    (before, after, true)
}

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
    (s, false)
}

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
    (s, false)
}

/// `bytes.ContainsAny(s, chars)` — true if any byte of `chars` is in `s`.
pub fn ContainsAny<S1: Into<slice<byte>>, S2: Into<slice<byte>>>(s: S1, chars: S2) -> bool {
    IndexAny(s, chars) >= 0
}

/// `bytes.ContainsFunc(s, f)` — true if any rune in `s` satisfies `f`.
pub fn ContainsFunc<S: Into<slice<byte>>, F: Fn(rune) -> bool>(s: S, f: F) -> bool {
    IndexFunc(s, f) >= 0
}

/// `bytes.IndexAny(s, chars)` — first byte in `s` matching any of `chars`.
pub fn IndexAny<S1: Into<slice<byte>>, S2: Into<slice<byte>>>(s: S1, chars: S2) -> int {
    let s = s.into();
    let chars = chars.into();
    if chars.Len() == 0 {
        return -1;
    }
    let sb: &[byte] = &s;
    let cb: &[byte] = &chars;
    for (i, b) in sb.iter().enumerate() {
        for c in cb {
            if *b == *c {
                return i as int;
            }
        }
    }
    -1
}

/// `bytes.LastIndexAny(s, chars)` — last byte in `s` matching any of `chars`.
pub fn LastIndexAny<S1: Into<slice<byte>>, S2: Into<slice<byte>>>(s: S1, chars: S2) -> int {
    let s = s.into();
    let chars = chars.into();
    if chars.Len() == 0 {
        return -1;
    }
    let sb: &[byte] = &s;
    let cb: &[byte] = &chars;
    let mut i = sb.len();
    while i > 0 {
        i -= 1;
        for c in cb {
            if sb[i] == *c {
                return i as int;
            }
        }
    }
    -1
}

/// `bytes.IndexFunc(s, f)` — index of first rune in `s` satisfying `f`.
pub fn IndexFunc<S: Into<slice<byte>>, F: Fn(rune) -> bool>(s: S, f: F) -> int {
    let s = s.into();
    let bytes: alloc::vec::Vec<byte> = s.__into_vec();
    let mut i = 0;
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
            return i as int;
        }
    }
    -1
}

/// `bytes.Fields(s)` — split on runs of `unicode.IsSpace`.
pub fn Fields<S: Into<slice<byte>>>(s: S) -> slice<slice<byte>> {
    FieldsFunc(s, crate::unicode::IsSpace)
}

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
    slice::__from_vec(out)
}

/// `bytes.TrimFunc(s, f)` — strip leading + trailing runes satisfying `f`.
pub fn TrimFunc<S: Into<slice<byte>>, F: Fn(rune) -> bool + Copy>(s: S, f: F) -> slice<byte> {
    TrimRightFunc(TrimLeftFunc(s, f), f)
}

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
    slice::__from_vec(bytes[i..].to_vec())
}

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
    slice::__from_vec(bytes[..end].to_vec())
}

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
    slice::__from_vec(out)
}

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
    slice::__from_vec(b)
}

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
    slice::__from_vec(t)
}

/// Line-by-line port of `bytes.isSeparator` (bytes/bytes.go:808) — used
/// by `Title` to detect word boundaries.
fn isSeparator(r: rune) -> bool {
    // Go: if r <= 0x7F { ... }
    if r <= 0x7F {
        // Go: 0..9 / a..z / A..Z / '_' are not separators.
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
    // Slim: goish lacks unicode.IsLetter / IsDigit / IsSpace tables.
    // Treat any non-ASCII rune as a non-separator (Go's IsLetter/IsDigit
    // would cover most non-ASCII alphanumerics anyway).
    false
}

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
    let mut prev: rune = b' ' as rune;
    let mut tmp = [0u8; 4];
    let mut i: usize = 0;
    // Go: return Map(func(r rune) rune { … }, s) — inlined for ASCII title-case.
    while i < bytes.len() {
        let (r, w) = utf8::DecodeRune(&bytes[i..]);
        // Go: if isSeparator(prev) { return unicode.ToTitle(r) }
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
    slice::__from_vec(out)
}

/// `bytes.SplitAfter(s, sep)` — split keeping `sep` at end of each segment.
pub fn SplitAfter<S1: Into<slice<byte>>, S2: Into<slice<byte>>>(
    s: S1,
    sep: S2,
) -> slice<slice<byte>> {
    SplitAfterN(s, sep, -1)
}

/// `bytes.SplitAfterN(s, sep, n)` — count-bounded `SplitAfter`.
pub fn SplitAfterN<S1: Into<slice<byte>>, S2: Into<slice<byte>>>(
    s: S1,
    sep: S2,
    n: int,
) -> slice<slice<byte>> {
    let s = s.into();
    let sep = sep.into();
    let mut out: alloc::vec::Vec<slice<byte>> = alloc::vec::Vec::new();
    let bytes: alloc::vec::Vec<byte> = s.__into_vec();
    let sep_bytes: alloc::vec::Vec<byte> = sep.__into_vec();
    if sep_bytes.is_empty() {
        let mut i = 0;
        while i < bytes.len() {
            let (_, w) = utf8::DecodeRune(&bytes[i..]);
            if w == 0 {
                break;
            }
            let w = w as usize;
            out.push(slice::__from_vec(bytes[i..i + w].to_vec()));
            i += w;
            if n > 0 && out.len() as int == n - 1 {
                if i < bytes.len() {
                    out.push(slice::__from_vec(bytes[i..].to_vec()));
                }
                return slice::__from_vec(out);
            }
        }
        return slice::__from_vec(out);
    }
    let mut start: usize = 0;
    loop {
        if n > 0 && out.len() as int == n - 1 {
            break;
        }
        let i = bytes_index(&bytes[start..], &sep_bytes);
        if i < 0 {
            break;
        }
        let end = start + i as usize + sep_bytes.len();
        out.push(slice::__from_vec(bytes[start..end].to_vec()));
        start = end;
    }
    if start <= bytes.len() {
        out.push(slice::__from_vec(bytes[start..].to_vec()));
    }
    slice::__from_vec(out)
}

fn bytes_index(haystack: &[byte], needle: &[byte]) -> int {
    if needle.is_empty() {
        return 0;
    }
    if needle.len() > haystack.len() {
        return -1;
    }
    let mut i = 0;
    while i + needle.len() <= haystack.len() {
        if &haystack[i..i + needle.len()] == needle {
            return i as int;
        }
        i += 1;
    }
    -1
}

// go: none — goish idiom: fill the `#[goish::interface]` downcast
// registries for the types this package declares. See AGENTS.md §9b and
// the banner on `io::register_io_impls`.
/// Register `bytes`'s concrete types into the `io` interface
/// registries. Idempotent; called from `goish::init()`.
pub fn register_bytes_impls() {
    use crate::io::{
        __goish_register_ByteReader_impl, __goish_register_ByteWriter_impl,
        __goish_register_ReaderAt_impl, __goish_register_ReaderFrom_impl,
        __goish_register_Reader_impl, __goish_register_Seeker_impl,
        __goish_register_StringWriter_impl, __goish_register_WriterTo_impl,
        __goish_register_Writer_impl,
    };
    __goish_register_Reader_impl::<Buffer>();
    __goish_register_Writer_impl::<Buffer>();
    __goish_register_ByteReader_impl::<Buffer>();
    __goish_register_ByteWriter_impl::<Buffer>();
    __goish_register_StringWriter_impl::<Buffer>();
    __goish_register_ReaderFrom_impl::<Buffer>();
    __goish_register_WriterTo_impl::<Buffer>();

    __goish_register_Reader_impl::<Reader>();
    __goish_register_ReaderAt_impl::<Reader>();
    __goish_register_ByteReader_impl::<Reader>();
    __goish_register_Seeker_impl::<Reader>();
    __goish_register_WriterTo_impl::<Reader>();
}
