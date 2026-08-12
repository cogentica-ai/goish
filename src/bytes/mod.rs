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

use crate::errors::{error, nil};
use crate::goslice::slice;
use crate::gostring::string;
use crate::io;
use crate::types::{byte, int, rune};
use crate::unicode::utf8;

// ─── Private byte helpers (no allocation) ─────────────────────────────

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
fn is_ascii_space(c: byte) -> bool {
    matches!(c, b' ' | b'\t' | b'\n' | b'\r' | 0x0B | 0x0C)
}

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
    index_byte(&s, c)
}

pub fn IndexRune<S: Into<slice<byte>>>(s: S, r: rune) -> int {
    let s = s.into();
    if r >= 0 && (r as u32) < utf8::RuneSelf as u32 {
        return index_byte(&s, r as byte);
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

pub fn TrimSpace<S: Into<slice<byte>>>(s: S) -> slice<byte> {
    let s = s.into();
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
    slice::__from_vec(raw[start..stop].to_vec())
}

pub fn Trim<S1: Into<slice<byte>>, S2: Into<slice<byte>>>(s: S1, cutset: S2) -> slice<byte> {
    let s = s.into();
    let cutset = cutset.into();
    let raw: &[byte] = &s;
    let cs: &[byte] = &cutset;
    if raw.is_empty() || cs.is_empty() {
        return s;
    }
    let mut start = 0usize;
    while start < raw.len() && cs.contains(&raw[start]) {
        start += 1;
    }
    let mut stop = raw.len();
    while stop > start && cs.contains(&raw[stop - 1]) {
        stop -= 1;
    }
    if start == 0 && stop == raw.len() {
        return s;
    }
    slice::__from_vec(raw[start..stop].to_vec())
}

pub fn TrimLeft<S1: Into<slice<byte>>, S2: Into<slice<byte>>>(s: S1, cutset: S2) -> slice<byte> {
    let s = s.into();
    let cutset = cutset.into();
    let raw: &[byte] = &s;
    let cs: &[byte] = &cutset;
    if raw.is_empty() || cs.is_empty() {
        return s;
    }
    let mut start = 0usize;
    while start < raw.len() && cs.contains(&raw[start]) {
        start += 1;
    }
    if start == 0 {
        return s;
    }
    slice::__from_vec(raw[start..].to_vec())
}

pub fn TrimRight<S1: Into<slice<byte>>, S2: Into<slice<byte>>>(s: S1, cutset: S2) -> slice<byte> {
    let s = s.into();
    let cutset = cutset.into();
    let raw: &[byte] = &s;
    let cs: &[byte] = &cutset;
    if raw.is_empty() || cs.is_empty() {
        return s;
    }
    let mut stop = raw.len();
    while stop > 0 && cs.contains(&raw[stop - 1]) {
        stop -= 1;
    }
    if stop == raw.len() {
        return s;
    }
    slice::__from_vec(raw[..stop].to_vec())
}

pub fn TrimPrefix<S1: Into<slice<byte>>, S2: Into<slice<byte>>>(s: S1, prefix: S2) -> slice<byte> {
    let s = s.into();
    let prefix = prefix.into();
    let raw: &[byte] = &s;
    let pb: &[byte] = &prefix;
    if has_prefix(raw, pb) {
        return slice::__from_vec(raw[pb.len()..].to_vec());
    }
    s
}

pub fn TrimSuffix<S1: Into<slice<byte>>, S2: Into<slice<byte>>>(s: S1, suffix: S2) -> slice<byte> {
    let s = s.into();
    let suffix = suffix.into();
    let raw: &[byte] = &s;
    let sb: &[byte] = &suffix;
    if has_suffix(raw, sb) {
        return slice::__from_vec(raw[..raw.len() - sb.len()].to_vec());
    }
    s
}

// ─── Case (ASCII-only) / EqualFold ────────────────────────────────────

pub fn ToUpper<S: Into<slice<byte>>>(s: S) -> slice<byte> {
    let s = s.into();
    let raw: &[byte] = &s;
    let mut has_lower = false;
    for &c in raw {
        if c >= b'a' && c <= b'z' {
            has_lower = true;
            break;
        }
    }
    if !has_lower {
        return s;
    }
    let mut v: Vec<byte> = Vec::with_capacity(raw.len());
    for &c in raw {
        if c >= b'a' && c <= b'z' {
            v.push(c - (b'a' - b'A'));
        } else {
            v.push(c);
        }
    }
    slice::__from_vec(v)
}

pub fn ToLower<S: Into<slice<byte>>>(s: S) -> slice<byte> {
    let s = s.into();
    let raw: &[byte] = &s;
    let mut has_upper = false;
    for &c in raw {
        if c >= b'A' && c <= b'Z' {
            has_upper = true;
            break;
        }
    }
    if !has_upper {
        return s;
    }
    let mut v: Vec<byte> = Vec::with_capacity(raw.len());
    for &c in raw {
        if c >= b'A' && c <= b'Z' {
            v.push(c + (b'a' - b'A'));
        } else {
            v.push(c);
        }
    }
    slice::__from_vec(v)
}

/// `bytes.ToTitle(s)` (bytes.go:757) — title-case mapping over `s`.
/// Go: `func ToTitle(s []byte) []byte { return Map(unicode.ToTitle, s) }`.
///
/// Slim: ASCII title-case is identical to upper-case (mirrors
/// `strings.ToTitle`); non-ASCII bytes pass through unchanged.
pub fn ToTitle<S: Into<slice<byte>>>(s: S) -> slice<byte> {
    // Go: return Map(unicode.ToTitle, s)
    Map(crate::unicode::ToTitle, s)
}

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
    let cap_usize = if cap_signed > 0 { cap_signed as usize } else { 0 };
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
    gen_split(s.into(), sep.into(), 0, -1)
}

pub fn SplitN<S1: Into<slice<byte>>, S2: Into<slice<byte>>>(
    s: S1,
    sep: S2,
    n: int,
) -> slice<slice<byte>> {
    gen_split(s.into(), sep.into(), 0, n)
}

fn gen_split(s: slice<byte>, sep: slice<byte>, sep_save: int, mut n: int) -> slice<slice<byte>> {
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

// ─── Buffer ───────────────────────────────────────────────────────────

const SMALL_BUFFER_SIZE: usize = 64;

/// `bytes.Buffer` — variable-size byte buffer with `Read`+`Write` methods.
/// Implements `io::Reader` and `io::Writer`.
///
/// `Clone` matches Go's by-value copy semantics for `bytes.Buffer{}`
/// composite-literals — the underlying `Vec<byte>` is duplicated. This
/// makes `pool.Get().clone()` shapes (transpiled from Go's by-pointer
/// pool patterns) compile cleanly; in steady-state code that wants to
/// avoid the copy, prefer `&mut buf` to share the buffer in place.
#[derive(Clone)]
pub struct Buffer {
    buf: Vec<byte>,
    off: usize,
    /// Slim equivalent of Go's `lastRead`: encodes the size in bytes
    /// of the most-recent successful ReadRune (1..=4). 0 means the
    /// last operation was something other than ReadRune. Used only by
    /// UnreadRune; UnreadByte continues to use the simpler off>0 rule.
    last_rune_size: u8,
}

impl Buffer {
    pub fn new() -> Self {
        Self {
            buf: Vec::new(),
            off: 0,
            last_rune_size: 0,
        }
    }

    /// Unread portion of the buffer, cloned (Go returns a view; we own).
    pub fn Bytes(&self) -> slice<byte> {
        slice::__from_vec(self.buf[self.off..].to_vec())
    }

    /// Unread portion as a `string` (cloned).
    pub fn String(&self) -> string {
        string::from_bytes(&self.buf[self.off..])
    }

    pub fn Len(&self) -> int {
        (self.buf.len() - self.off) as int
    }

    pub fn Cap(&self) -> int {
        self.buf.capacity() as int
    }

    /// `(b *Buffer).Available()` (buffer.go:92) — bytes that can be
    /// written without reallocating: cap(b.buf) - len(b.buf).
    pub fn Available(&self) -> int {
        (self.buf.capacity() - self.buf.len()) as int
    }

    /// `(b *Buffer).AvailableBuffer()` (buffer.go:66) — Go returns an
    /// empty slice with capacity Available(); intended for `append +
    /// Write` patterns. In slim goish slices don't expose Vec's
    /// capacity, so we return an empty slice<byte>; the appender just
    /// needs to call b.Write on the resulting bytes.
    pub fn AvailableBuffer(&self) -> slice<byte> {
        slice::__from_vec(Vec::new())
    }

    /// Reset to empty, retaining underlying storage.
    pub fn Reset(&mut self) {
        self.buf.clear();
        self.off = 0;
        self.last_rune_size = 0;
    }

    /// Ensure space for at least `n` more bytes without reallocation.
    pub fn Grow(&mut self, n: int) {
        if n < 0 {
            panic!("bytes.Buffer.Grow: negative count");
        }
        let needed = n as usize;
        let avail = self.buf.capacity() - self.buf.len();
        if needed > avail {
            self.buf.reserve(needed - avail);
        }
    }

    /// Append bytes. Always returns `(len(p), nil)`.
    pub fn Write(&mut self, p: slice<byte>) -> (int, error) {
        self.last_rune_size = 0;
        let n = p.Len();
        let raw: &[byte] = &p;
        self.buf.extend_from_slice(raw);
        (n, nil)
    }

    pub fn WriteString<S: Into<string>>(&mut self, s: S) -> (int, error) {
        self.last_rune_size = 0;
        let s = s.into();
        let bs = s.as_bytes();
        self.buf.extend_from_slice(bs);
        (bs.len() as int, nil)
    }

    pub fn WriteByte(&mut self, c: byte) -> error {
        self.last_rune_size = 0;
        self.buf.push(c);
        nil
    }

    pub fn WriteRune(&mut self, r: rune) -> (int, error) {
        self.last_rune_size = 0;
        let mut tmp = [0u8; 4];
        let n = utf8::EncodeRune(&mut tmp, r);
        self.buf.extend_from_slice(&tmp[..n as usize]);
        (n, nil)
    }

    /// Read up to `len(p)` bytes from the buffer into `p`. Returns
    /// `(0, io::EOF)` when exhausted, matching Go.
    pub fn Read(&mut self, p: &mut slice<byte>) -> (int, error) {
        self.last_rune_size = 0;
        if self.off >= self.buf.len() {
            return (0, io::EOF.into());
        }
        let want = (p.Len() as usize).min(self.buf.len() - self.off);
        for i in 0..want {
            p[i as int] = self.buf[self.off + i];
        }
        self.off += want;
        (want as int, nil)
    }

    /// `(b *Buffer).Next(n)` (buffer.go:346) — return the next n
    /// unread bytes as an owned slice and advance the read cursor.
    /// If n exceeds Len(), returns the entire remaining buffer.
    pub fn Next(&mut self, mut n: int) -> slice<byte> {
        // Go: b.lastRead = opInvalid
        self.last_rune_size = 0;
        // Go: m := b.Len(); if n > m { n = m }
        let m = self.Len();
        if n > m {
            n = m;
        }
        if n < 0 {
            n = 0;
        }
        // Go: data := b.buf[b.off : b.off+n]
        let end = self.off + n as usize;
        let data = slice::__from_vec(self.buf[self.off..end].to_vec());
        // Go: b.off += n
        self.off = end;
        // Go: if n > 0 { b.lastRead = opRead }  — slim Read, no UnreadRune.
        data
    }

    /// `(b *Buffer).ReadRune()` (buffer.go:379) — read one UTF-8
    /// rune. Returns `(0, 0, io.EOF)` on empty buffer; on invalid
    /// UTF-8, returns `(U+FFFD, 1, nil)` after consuming one byte.
    pub fn ReadRune(&mut self) -> (rune, int, error) {
        // Go: if b.empty() { b.Reset(); return 0, 0, io.EOF }
        if self.off >= self.buf.len() {
            self.Reset();
            return (0, 0, io::EOF.into());
        }
        // Go: c := b.buf[b.off]
        let c = self.buf[self.off];
        // Go: if c < utf8.RuneSelf { b.off++; b.lastRead = opReadRune1; return rune(c), 1, nil }
        if c < utf8::RuneSelf {
            self.off += 1;
            self.last_rune_size = 1;
            return (c as rune, 1, nil);
        }
        // Go: r, n := utf8.DecodeRune(b.buf[b.off:])
        let (r, n) = utf8::DecodeRune(&self.buf[self.off..]);
        // Go: b.off += n; b.lastRead = readOp(n)
        self.off += n as usize;
        self.last_rune_size = n as u8;
        (r, n, nil)
    }

    /// `(b *Buffer).UnreadRune()` (buffer.go:402) — push back the
    /// rune read by the most recent ReadRune. Returns an error if the
    /// most recent op was not a successful ReadRune.
    pub fn UnreadRune(&mut self) -> error {
        // Go: if b.lastRead <= opInvalid { return error }
        if self.last_rune_size == 0 {
            return crate::errors::New(
                "bytes.Buffer: UnreadRune: previous operation was not a successful ReadRune",
            );
        }
        // Go: if b.off >= int(b.lastRead) { b.off -= int(b.lastRead) }
        let n = self.last_rune_size as usize;
        if self.off >= n {
            self.off -= n;
        }
        // Go: b.lastRead = opInvalid
        self.last_rune_size = 0;
        nil
    }

    /// `(b *Buffer).Truncate(n)` (buffer.go:97) — discard all but the
    /// first n unread bytes. Panics if n is out of range.
    pub fn Truncate(&mut self, n: int) {
        self.last_rune_size = 0;
        // Go: if n == 0 { b.Reset(); return }
        if n == 0 {
            self.Reset();
            return;
        }
        // Go: if n < 0 || n > b.Len() { panic(...) }
        if n < 0 || n > self.Len() {
            panic!("bytes.Buffer: truncation out of range");
        }
        // Keep the first n unread bytes, drop the rest.
        self.buf.truncate(self.off + n as usize);
    }

    /// `(b *Buffer).ReadByte()` (buffer.go:362) — pop one byte.
    /// Returns `(0, io.EOF)` when empty.
    pub fn ReadByte(&mut self) -> (byte, error) {
        self.last_rune_size = 0;
        // Go: if b.empty() { b.Reset(); return 0, io.EOF }
        if self.off >= self.buf.len() {
            self.Reset();
            return (0, io::EOF.into());
        }
        // Go: c := b.buf[b.off]; b.off++
        let c = self.buf[self.off];
        self.off += 1;
        (c, nil)
    }

    /// `(b *Buffer).UnreadByte()` (buffer.go:419) — push back one byte.
    /// Slim port: doesn't track last-op state — succeeds whenever off>0.
    pub fn UnreadByte(&mut self) -> error {
        self.last_rune_size = 0;
        // Go strictly tracks lastRead; slim port simply rewinds if able.
        if self.off > 0 {
            self.off -= 1;
            nil
        } else {
            crate::errors::New("bytes.Buffer: UnreadByte: previous operation was not a successful read")
        }
    }

    /// `(b *Buffer).ReadBytes(delim)` (buffer.go:436) — read up to and
    /// including `delim`. On EOF before delim, returns the partial data
    /// plus io.EOF.
    pub fn ReadBytes(&mut self, delim: byte) -> (slice<byte>, error) {
        self.last_rune_size = 0;
        // Go's readSlice: i := IndexByte(b.buf[b.off:], delim)
        let mut i: int = -1;
        for (k, b) in self.buf[self.off..].iter().enumerate() {
            if *b == delim {
                i = k as int;
                break;
            }
        }
        let (end, err) = if i < 0 {
            (self.buf.len(), io::EOF.into())
        } else {
            (self.off + i as usize + 1, nil)
        };
        // Go: line = b.buf[b.off:end]; b.off = end; copy out.
        let line = slice::__from_vec(self.buf[self.off..end].to_vec());
        self.off = end;
        (line, err)
    }

    /// `(b *Buffer).ReadString(delim)` (buffer.go:464) — same as
    /// ReadBytes but returns a `string`.
    pub fn ReadString(&mut self, delim: byte) -> (string, error) {
        let (line, err) = self.ReadBytes(delim);
        (string::from_bytes(&line), err)
    }

    /// `(b *Buffer).ReadFrom(r)` (buffer.go:212) — read from `r`
    /// until EOF and append to the buffer. Returns the number of
    /// bytes read.
    pub fn ReadFrom(&mut self, r: &mut dyn io::Reader) -> (i64, error) {
        self.last_rune_size = 0;
        let mut n: i64 = 0;
        loop {
            // Go: i := b.grow(MinRead); b.buf = b.buf[:i]
            //     m, e := r.Read(b.buf[i:cap(b.buf)])
            // We use a fixed scratch buffer of MinRead bytes; this loses
            // Go's "read directly into buffer's spare capacity" trick
            // but matches the visible behavior.
            let mut scratch = crate::make!([]byte, MinRead);
            let (m, e) = r.Read(&mut scratch);
            if m < 0 {
                panic!("bytes.Buffer.ReadFrom: negative Read count");
            }
            // append m bytes
            let raw: &[byte] = &scratch;
            self.buf.extend_from_slice(&raw[..m as usize]);
            n += m as i64;
            if crate::errors::Is(e.clone(), io::EOF) {
                return (n, nil);
            }
            if !e.IsNil() {
                return (n, e);
            }
        }
    }

    /// `(b *Buffer).WriteTo(w)` (buffer.go:264) — drain buffer to
    /// `w` until exhausted or an error occurs. Returns bytes
    /// written.
    pub fn WriteTo(&mut self, w: &mut dyn io::Writer) -> (i64, error) {
        self.last_rune_size = 0;
        let mut n: i64 = 0;
        let nbytes = self.Len();
        if nbytes > 0 {
            let chunk = slice::__from_vec(self.buf[self.off..].to_vec());
            let (m, e) = w.Write(chunk);
            if m as int > nbytes {
                panic!("bytes.Buffer.WriteTo: invalid Write count");
            }
            self.off += m as usize;
            n = m as i64;
            if !e.IsNil() {
                return (n, e);
            }
            // all bytes should have been written, by definition of
            // Write method in io.Writer
            if m as int != nbytes {
                return (n, io::ErrShortWrite.into());
            }
        }
        // Buffer is now empty; reset.
        self.Reset();
        (n, nil)
    }
}

/// `bytes.MinRead` (buffer.go:206) — minimum slice size used by
/// `Buffer.ReadFrom`.
pub const MinRead: int = 512;

impl Default for Buffer {
    fn default() -> Self {
        Self::new()
    }
}

impl io::Writer for Buffer {
    fn Write(&mut self, p: slice<byte>) -> (int, error) {
        Buffer::Write(self, p)
    }
}

impl io::ByteReader for Buffer {
    fn ReadByte(&mut self) -> (byte, error) {
        Buffer::ReadByte(self)
    }
}

impl io::ByteScanner for Buffer {
    fn UnreadByte(&mut self) -> error {
        Buffer::UnreadByte(self)
    }
}

impl io::ByteWriter for Buffer {
    fn WriteByte(&mut self, c: byte) -> error {
        Buffer::WriteByte(self, c)
    }
}

impl io::StringWriter for Buffer {
    fn WriteString(&mut self, s: string) -> (int, error) {
        Buffer::WriteString(self, s)
    }
}

impl io::ReaderFrom for Buffer {
    fn ReadFrom(&mut self, r: &mut dyn io::Reader) -> (i64, error) {
        Buffer::ReadFrom(self, r)
    }
}

impl io::WriterTo for Buffer {
    fn WriteTo(&mut self, w: &mut dyn io::Writer) -> (i64, error) {
        Buffer::WriteTo(self, w)
    }
}

impl io::Reader for Buffer {
    fn Read(&mut self, p: &mut slice<byte>) -> (int, error) {
        Buffer::Read(self, p)
    }
}

/// `NewBuffer(buf)` — Buffer using `buf` as initial contents (read-
/// from-front). Go's `bytes.NewBuffer` returns `*Buffer`; the Goish
/// runtime returns owned `Buffer` to keep trait-impl dispatch (io::
/// Writer, io::Reader, …) working without forwarding boilerplate.
/// The transpiler wraps the call as `nilable::new(bytes::NewBuffer(…))`
/// when feeding a `*Buffer` slot — see `PointerReturnSlots` in
/// stdlib_registry.go.
pub fn NewBuffer(buf: slice<byte>) -> Buffer {
    Buffer {
        buf: buf.__into_vec(),
        off: 0,
        last_rune_size: 0,
    }
}

/// `NewBufferString(s)` — Buffer initialized with the bytes of `s`.
/// Same return-shape rationale as `NewBuffer`.
pub fn NewBufferString<S: Into<string>>(s: S) -> Buffer {
    let s = s.into();
    Buffer {
        buf: s.as_bytes().to_vec(),
        off: 0,
        last_rune_size: 0,
    }
}

// Unused but here to keep Buffer's small-buffer hint visible.
const _: usize = SMALL_BUFFER_SIZE;

// ─── Reader (in-memory io::Reader) ────────────────────────────────────

/// `bytes.Reader` — read-only `io.Reader` over a byte slice.
pub struct Reader {
    s: Vec<byte>,
    i: usize,
    /// Mirrors Go's `prevRune`: index of previous rune, or `-1` if
    /// the most recent op was not a successful ReadRune. Used only
    /// by UnreadRune.
    prev_rune: i64,
}

impl Reader {
    pub fn Len(&self) -> int {
        if self.i >= self.s.len() {
            return 0;
        }
        (self.s.len() - self.i) as int
    }

    pub fn Size(&self) -> int {
        self.s.len() as int
    }

    pub fn Read(&mut self, p: &mut slice<byte>) -> (int, error) {
        self.prev_rune = -1;
        if self.i >= self.s.len() {
            return (0, io::EOF.into());
        }
        let want = (p.Len() as usize).min(self.s.len() - self.i);
        for k in 0..want {
            p[k as int] = self.s[self.i + k];
        }
        self.i += want;
        (want as int, nil)
    }

    pub fn Reset(&mut self, b: slice<byte>) {
        self.s = b.__into_vec();
        self.i = 0;
        self.prev_rune = -1;
    }

    /// `(r *Reader).ReadByte()` (bytes/reader.go:66) — implements
    /// io.ByteReader. Invalidates prevRune.
    pub fn ReadByte(&mut self) -> (byte, error) {
        // Go: r.prevRune = -1
        self.prev_rune = -1;
        // Go: if r.i >= int64(len(r.s)) { return 0, io.EOF }
        if self.i >= self.s.len() {
            return (0, io::EOF.into());
        }
        // Go: b := r.s[r.i]; r.i++; return b, nil
        let b = self.s[self.i];
        self.i += 1;
        (b, nil)
    }

    /// `(r *Reader).UnreadByte()` (bytes/reader.go:77) — implements
    /// io.ByteScanner. Returns error if at the start.
    pub fn UnreadByte(&mut self) -> error {
        // Go: if r.i <= 0 { return errors.New("...: at beginning of slice") }
        if self.i == 0 {
            return crate::errors::New("bytes.Reader.UnreadByte: at beginning of slice");
        }
        // Go: r.prevRune = -1; r.i--; return nil
        self.prev_rune = -1;
        self.i -= 1;
        nil
    }

    /// `(r *Reader).ReadRune()` (bytes/reader.go:87) — implements
    /// io.RuneReader. ASCII fast-path; non-ASCII via DecodeRune.
    pub fn ReadRune(&mut self) -> (rune, int, error) {
        // Go: if r.i >= int64(len(r.s)) { r.prevRune = -1; return 0, 0, io.EOF }
        if self.i >= self.s.len() {
            self.prev_rune = -1;
            return (0, 0, io::EOF.into());
        }
        // Go: r.prevRune = int(r.i)
        self.prev_rune = self.i as i64;
        // Go: if c := r.s[r.i]; c < utf8.RuneSelf { r.i++; return rune(c), 1, nil }
        let c = self.s[self.i];
        if c < utf8::RuneSelf {
            self.i += 1;
            return (c as rune, 1, nil);
        }
        // Go: ch, size = utf8.DecodeRune(r.s[r.i:])
        let (ch, size) = utf8::DecodeRune(&self.s[self.i..]);
        // Go: r.i += int64(size)
        self.i += size as usize;
        (ch, size, nil)
    }

    /// `(r *Reader).UnreadRune()` (bytes/reader.go:103) — implements
    /// io.RuneScanner. Restores cursor to the start of the most-recent
    /// ReadRune.
    pub fn UnreadRune(&mut self) -> error {
        // Go: if r.i <= 0 { return errors.New("...: at beginning of slice") }
        if self.i == 0 {
            return crate::errors::New("bytes.Reader.UnreadRune: at beginning of slice");
        }
        // Go: if r.prevRune < 0 { return errors.New("...: previous operation was not ReadRune") }
        if self.prev_rune < 0 {
            return crate::errors::New(
                "bytes.Reader.UnreadRune: previous operation was not ReadRune",
            );
        }
        // Go: r.i = int64(r.prevRune); r.prevRune = -1; return nil
        self.i = self.prev_rune as usize;
        self.prev_rune = -1;
        nil
    }

    /// `(r *Reader).Seek(offset, whence)` (bytes/reader.go:127) — slim port.
    pub fn Seek(&mut self, offset: i64, whence: int) -> (i64, error) {
        // Go: r.prevRune = -1
        self.prev_rune = -1;
        // Go: switch whence { case SeekStart: ... }
        let abs: i64 = match whence {
            x if x == io::SeekStart => offset,
            x if x == io::SeekCurrent => (self.i as i64).wrapping_add(offset),
            x if x == io::SeekEnd => (self.s.len() as i64).wrapping_add(offset),
            _ => {
                return (0, crate::errors::New("bytes.Reader.Seek: invalid whence"));
            }
        };
        // Go: if abs < 0 { return 0, error }
        if abs < 0 {
            return (0, crate::errors::New("bytes.Reader.Seek: negative position"));
        }
        self.i = abs as usize;
        (abs, nil)
    }

    /// `(r *Reader).WriteTo(w)` (bytes/reader.go:137) — drain unread
    /// tail to `w` via Write. Returns bytes written.
    pub fn WriteTo(&mut self, w: &mut dyn io::Writer) -> (i64, error) {
        // Go: r.prevRune = -1
        self.prev_rune = -1;
        // Go: if r.i >= int64(len(r.s)) { return 0, nil }
        if self.i >= self.s.len() {
            return (0, nil);
        }
        // b := r.s[r.i:]
        let b = slice::__from_vec(self.s[self.i..].to_vec());
        let blen = b.Len();
        // m, err := w.Write(b)
        let (m, err) = w.Write(b);
        if m > blen {
            panic!("bytes.Reader.WriteTo: invalid Write count");
        }
        // r.i += int64(m); n = int64(m)
        self.i += m as usize;
        let n = m as i64;
        // if m != len(b) && err == nil { err = io.ErrShortWrite }
        if m != blen && err.IsNil() {
            return (n, io::ErrShortWrite.into());
        }
        (n, err)
    }

    /// `(r *Reader).ReadAt(p, off)` (bytes/reader.go:88) — slim port.
    pub fn ReadAt(&mut self, p: &mut slice<byte>, off: i64) -> (int, error) {
        // Go: if off < 0 { return 0, errors.New("bytes.Reader.ReadAt: negative offset") }
        if off < 0 {
            return (0, crate::errors::New("bytes.Reader.ReadAt: negative offset"));
        }
        if off >= self.s.len() as i64 {
            return (0, io::EOF.into());
        }
        let start = off as usize;
        let want = (p.Len() as usize).min(self.s.len() - start);
        for k in 0..want {
            p[k as int] = self.s[start + k];
        }
        // Go: if n < len(p) { err = io.EOF }
        if want < p.Len() as usize {
            return (want as int, io::EOF.into());
        }
        (want as int, nil)
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

impl io::Reader for Reader {
    fn Read(&mut self, p: &mut slice<byte>) -> (int, error) {
        Reader::Read(self, p)
    }
}

impl io::ByteReader for Reader {
    fn ReadByte(&mut self) -> (byte, error) {
        Reader::ReadByte(self)
    }
}

impl io::WriterTo for Reader {
    fn WriteTo(&mut self, w: &mut dyn io::Writer) -> (i64, error) {
        Reader::WriteTo(self, w)
    }
}

/// `NewReader(b)` — `Reader` over `b`. Go: `*Reader`; Goish runtime
/// returns owned `Reader` (see `NewBuffer` for the rationale).
pub fn NewReader<B: Into<slice<byte>>>(b: B) -> Reader {
    let b = b.into();
    Reader {
        s: b.__into_vec(),
        i: 0,
        prev_rune: -1,
    }
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
pub fn FieldsFunc<S: Into<slice<byte>>, F: Fn(rune) -> bool>(
    s: S,
    f: F,
) -> slice<slice<byte>> {
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
fn is_separator(r: rune) -> bool {
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
        let nr = if is_separator(prev) {
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
