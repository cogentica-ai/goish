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
pub struct Buffer {
    buf: Vec<byte>,
    off: usize,
}

impl Buffer {
    pub fn new() -> Self {
        Self {
            buf: Vec::new(),
            off: 0,
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

    /// Reset to empty, retaining underlying storage.
    pub fn Reset(&mut self) {
        self.buf.clear();
        self.off = 0;
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
        let n = p.Len();
        let raw: &[byte] = &p;
        self.buf.extend_from_slice(raw);
        (n, nil)
    }

    pub fn WriteString<S: Into<string>>(&mut self, s: S) -> (int, error) {
        let s = s.into();
        let bs = s.as_bytes();
        self.buf.extend_from_slice(bs);
        (bs.len() as int, nil)
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

    /// Read up to `len(p)` bytes from the buffer into `p`. Returns
    /// `(0, io::EOF())` when exhausted, matching Go.
    pub fn Read(&mut self, p: &mut slice<byte>) -> (int, error) {
        if self.off >= self.buf.len() {
            return (0, io::EOF());
        }
        let want = (p.Len() as usize).min(self.buf.len() - self.off);
        for i in 0..want {
            p[i as int] = self.buf[self.off + i];
        }
        self.off += want;
        (want as int, nil)
    }
}

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

impl io::Reader for Buffer {
    fn Read(&mut self, p: &mut slice<byte>) -> (int, error) {
        Buffer::Read(self, p)
    }
}

/// `NewBuffer(buf)` — Buffer using `buf` as initial contents (read-from-front).
pub fn NewBuffer(buf: slice<byte>) -> Buffer {
    Buffer {
        buf: buf.__into_vec(),
        off: 0,
    }
}

/// `NewBufferString(s)` — Buffer initialized with the bytes of `s`.
pub fn NewBufferString<S: Into<string>>(s: S) -> Buffer {
    let s = s.into();
    Buffer {
        buf: s.as_bytes().to_vec(),
        off: 0,
    }
}

// Unused but here to keep Buffer's small-buffer hint visible.
const _: usize = SMALL_BUFFER_SIZE;

// ─── Reader (in-memory io::Reader) ────────────────────────────────────

/// `bytes.Reader` — read-only `io.Reader` over a byte slice.
pub struct Reader {
    s: Vec<byte>,
    i: usize,
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
        if self.i >= self.s.len() {
            return (0, io::EOF());
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
    }
}

impl io::Reader for Reader {
    fn Read(&mut self, p: &mut slice<byte>) -> (int, error) {
        Reader::Read(self, p)
    }
}

/// `NewReader(b)` — `Reader` over `b`.
pub fn NewReader(b: slice<byte>) -> Reader {
    Reader {
        s: b.__into_vec(),
        i: 0,
    }
}
