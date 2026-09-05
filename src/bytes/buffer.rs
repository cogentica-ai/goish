// go: file bytes/buffer.go decls: new, default, Buffer.Bytes, Buffer.AvailableBuffer, Buffer.String, Buffer.empty, Buffer.Len, Buffer.Cap, Buffer.Available, Buffer.Truncate, Buffer.Reset, Buffer.tryGrowByReslice, Buffer.grow, Buffer.Grow, Buffer.Write, Buffer.WriteString, Buffer.ReadFrom, growSlice, Buffer.WriteTo, Buffer.WriteByte, Buffer.WriteRune, Buffer.Read, Buffer.Next, Buffer.ReadByte, Buffer.ReadRune, Buffer.UnreadRune, Buffer.UnreadByte, Buffer.ReadBytes, Buffer.readSlice, Buffer.ReadString, NewBuffer, NewBufferString, new
//
// goishlint:ignore GOISH021 readOp, opRead, opInvalid, opReadRune1, opReadRune2, opReadRune3, opReadRune4, ErrTooLarge, errNegativeRead, maxInt, errUnreadByte — Go's `lastRead readOp`
//     records which of eight operations ran last, so `UnreadByte` and
//     `UnreadRune` can each refuse when the previous call was not the
//     matching read. goish stores `last_rune_size` instead: the width
//     of the last successful `ReadRune` in bytes, 0 for anything else.
//     That answers `UnreadRune` exactly, and `UnreadByte` uses the
//     simpler `off > 0` rule. The three sentinels and `maxInt` belong
//     to the overflow and negative-read paths, which goish reaches
//     through a panic and a Vec's own bounds instead.
//
// bytes/buffer.go — a variable-sized buffer of bytes with Read and
// Write methods.
//
// The growth policy is the interesting part and it is three steps, not
// one. `grow(n)` first resets when the buffer is logically empty but
// `off` has walked forward, then tries `tryGrowByReslice` — free, when
// the capacity is already there — then either slides the live bytes
// down over the consumed prefix (when that alone buys enough room) or
// calls `growSlice`, which doubles. Only the last of those allocates,
// and a Buffer that is written and drained repeatedly should reach a
// steady state that never does.

#![allow(non_snake_case, non_upper_case_globals)]

extern crate alloc;
use alloc::vec::Vec;

use crate::convert::{int as toint, int64 as toint64, rune as torune, uint8 as touint8};
use crate::errors::{error, nil};
use crate::goslice::slice;
use crate::gostring::string;
use crate::io;
use crate::types::{byte, int, rune};
use crate::unicode::utf8;

// ─── Buffer ───────────────────────────────────────────────────────────

// go: sdk 1.25.5 bytes/buffer.go:14-16 smallBufferSize
/// Go: "an initial allocation minimal capacity." A Buffer that is
/// grown from empty takes this rather than exactly what was asked for,
/// so a run of small writes does not reallocate on every one.
const smallBufferSize: usize = 64;

// go: sdk 1.25.5 bytes/buffer.go:233-258 growSlice
/// Grows `b` by `n`, preserving its content.
///
/// The growth rate has historically always been 2x, and Go's comment
/// keeps it that way: the new capacity is `len(b) + n`, or double the
/// old capacity, whichever is larger.
fn growSlice(b: &[byte], n: usize) -> Vec<byte> {
    let mut c = b.len() + n;
    if c < 2 * b.len() {
        c = 2 * b.len();
    }
    let mut v: Vec<byte> = Vec::with_capacity(c);
    v.extend_from_slice(b);
    return v;
}

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
    // go: none — goish idiom: Go's zero `Buffer` is ready to use, so
    //     `var b bytes.Buffer` needs no constructor. A goish `Buffer`
    //     owns a `Vec`, so the zero value is spelled here and by the
    //     `Default` impl below.
    pub fn new() -> Self {
        return Self {
            buf: Vec::new(),
            off: 0,
            last_rune_size: 0,
        };
    }

    // go: sdk 1.25.5 bytes/buffer.go:60-60 Buffer.Bytes
    /// Unread portion of the buffer, cloned (Go returns a view; we own).
    pub fn Bytes(&self) -> slice<byte> {
        return slice::__from_vec(self.buf[self.off..].to_vec());
    }

    // go: sdk 1.25.5 bytes/buffer.go:72-78 Buffer.String
    /// Unread portion as a `string` (cloned).
    pub fn String(&self) -> string {
        return string::from_bytes(&self.buf[self.off..]);
    }

    // go: sdk 1.25.5 bytes/buffer.go:79-81 Buffer.empty
    /// Go: "empty reports whether the unread portion of the buffer is
    /// empty." Read, Next and ReadByte all branch on it.
    fn empty(&self) -> bool {
        return self.buf.len() <= self.off;
    }

    // go: sdk 1.25.5 bytes/buffer.go:85-85 Buffer.Len
    pub fn Len(&self) -> int {
        return toint(self.buf.len() - self.off);
    }

    // go: sdk 1.25.5 bytes/buffer.go:89-89 Buffer.Cap
    pub fn Cap(&self) -> int {
        return toint(self.buf.capacity());
    }

    // go: sdk 1.25.5 bytes/buffer.go:92-92 Buffer.Available
    /// `(b *Buffer).Available()` (buffer.go:92) — bytes that can be
    /// written without reallocating: cap(b.buf) - len(b.buf).
    pub fn Available(&self) -> int {
        return toint(self.buf.capacity() - self.buf.len());
    }

    // go: sdk 1.25.5 bytes/buffer.go:66-66 Buffer.AvailableBuffer
    /// `(b *Buffer).AvailableBuffer()` (buffer.go:66) — Go returns an
    /// empty slice with capacity Available(); intended for `append +
    /// Write` patterns. In slim goish slices don't expose Vec's
    /// capacity, so we return an empty slice<byte>; the appender just
    /// needs to call b.Write on the resulting bytes.
    pub fn AvailableBuffer(&self) -> slice<byte> {
        return slice::__from_vec(Vec::new());
    }

    // go: sdk 1.25.5 bytes/buffer.go:112-116 Buffer.Reset
    /// Reset to empty, retaining underlying storage.
    pub fn Reset(&mut self) {
        self.buf.clear();
        self.off = 0;
        self.last_rune_size = 0;
    }

    // go: sdk 1.25.5 bytes/buffer.go:119-127 Buffer.tryGrowByReslice
    /// Go: "an inlineable version of grow for the fast-case where the
    /// internal buffer only needs to be resliced." Returns the index
    /// where bytes should be written, and whether it succeeded.
    ///
    /// Go reslices within the existing capacity; the Rust equivalent is
    /// to extend the Vec's length into capacity it already owns, which
    /// `resize` does without reallocating precisely when the capacity
    /// is there.
    fn tryGrowByReslice(&mut self, n: usize) -> (usize, bool) {
        let l = self.buf.len();
        if n <= self.buf.capacity() - l {
            self.buf.resize(l + n, 0);
            return (l, true);
        }
        return (0, false);
    }

    // go: sdk 1.25.5 bytes/buffer.go:129-163 Buffer.grow
    /// Grows the buffer to guarantee space for `n` more bytes, and
    /// returns the index where they should be written.
    ///
    /// Three steps, and only the last allocates: reset when the buffer
    /// is logically empty but `off` has walked forward, try a reslice
    /// into capacity already owned, then either slide the live bytes
    /// down over the consumed prefix — which is worth it only when it
    /// alone buys enough room — or double through `growSlice`.
    fn grow(&mut self, n: usize) -> usize {
        let m = self.Len() as usize;
        // If the buffer is empty, reset to recover space.
        if m == 0 && self.off != 0 {
            self.Reset();
        }
        let (i, ok) = self.tryGrowByReslice(n);
        if ok {
            return i;
        }
        if self.buf.is_empty() && self.buf.capacity() == 0 && n <= smallBufferSize {
            self.buf = Vec::with_capacity(smallBufferSize);
            self.buf.resize(n, 0);
            return 0;
        }
        let c = self.buf.capacity();
        if n <= c / 2 - m {
            // Slide down instead of allocating. Go only needs m+n <= c
            // to slide, but lets the capacity get twice as large so it
            // does not spend all its time copying.
            self.buf.copy_within(self.off.., 0);
        } else {
            // Go adds b.off to account for b.buf[:b.off] being sliced
            // off the front.
            self.buf = growSlice(&self.buf[self.off..], self.off + n);
        }
        self.off = 0;
        self.buf.resize(m + n, 0);
        return m;
    }

    // go: sdk 1.25.5 bytes/buffer.go:165-179 Buffer.Grow
    /// Grows the buffer's capacity, if necessary, to guarantee space
    /// for another `n` bytes. After `Grow(n)`, at least `n` bytes can
    /// be written without another allocation. Panics if `n` is
    /// negative.
    pub fn Grow(&mut self, n: int) {
        if n < 0 {
            panic!("bytes.Buffer.Grow: negative count");
        }
        let m = self.grow(n as usize);
        self.buf.truncate(m);
    }

    // go: sdk 1.25.5 bytes/buffer.go:181-188 Buffer.Write
    /// Append bytes. Always returns `(len(p), nil)`.
    pub fn Write(&mut self, p: slice<byte>) -> (int, error) {
        self.last_rune_size = 0;
        let n = p.Len();
        let raw: &[byte] = &p;
        self.buf.extend_from_slice(raw);
        return (n, nil);
    }

    // go: sdk 1.25.5 bytes/buffer.go:193-200 Buffer.WriteString
    pub fn WriteString<S: Into<string>>(&mut self, s: S) -> (int, error) {
        self.last_rune_size = 0;
        let s = s.into();
        let bs = s.as_bytes();
        self.buf.extend_from_slice(bs);
        return (toint(bs.len()), nil);
    }

    // go: sdk 1.25.5 bytes/buffer.go:291-299 Buffer.WriteByte
    pub fn WriteByte(&mut self, c: byte) -> error {
        self.last_rune_size = 0;
        self.buf.push(c);
        return nil;
    }

    // go: sdk 1.25.5 bytes/buffer.go:305-318 Buffer.WriteRune
    pub fn WriteRune(&mut self, r: rune) -> (int, error) {
        self.last_rune_size = 0;
        let mut tmp = [0u8; 4];
        let n = utf8::EncodeRune(&mut tmp, r);
        self.buf.extend_from_slice(&tmp[..n as usize]);
        return (n, nil);
    }

    // go: sdk 1.25.5 bytes/buffer.go:324-340 Buffer.Read
    /// Read up to `len(p)` bytes from the buffer into `p`. Returns
    /// `(0, io::EOF)` when exhausted, matching Go.
    pub fn Read(&mut self, p: &mut slice<byte>) -> (int, error) {
        self.last_rune_size = 0;
        if self.empty() {
            // Go: "Buffer is empty, reset to recover space."
            self.Reset();
            // Go: if len(p) == 0 { return 0, nil }
            //
            // An empty p is not the end of the stream, it is a caller
            // asking for nothing — and io.Reader's contract singles the
            // case out: "Implementations of Read are discouraged from
            // returning a zero byte count with a nil error, except when
            // len(p) == 0." Answering io.EOF instead tells a copier the
            // source is finished when it has only been handed a
            // zero-length buffer.
            if p.Len() == 0 {
                return (0, nil);
            }
            return (0, io::EOF.into());
        }
        let want = (p.Len() as usize).min(self.buf.len() - self.off);
        for i in 0..want {
            p[toint(i)] = self.buf[self.off + i];
        }
        self.off += want;
        return (toint(want), nil);
    }

    // go: sdk 1.25.5 bytes/buffer.go:346-358 Buffer.Next
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
        return data;
    }

    // go: sdk 1.25.5 bytes/buffer.go:379-395 Buffer.ReadRune
    /// `(b *Buffer).ReadRune()` (buffer.go:379) — read one UTF-8
    /// rune. Returns `(0, 0, io.EOF)` on empty buffer; on invalid
    /// UTF-8, returns `(U+FFFD, 1, nil)` after consuming one byte.
    pub fn ReadRune(&mut self) -> (rune, int, error) {
        // Go: if b.empty() { b.Reset(); return 0, 0, io.EOF }
        if self.empty() {
            self.Reset();
            return (0, 0, io::EOF.into());
        }
        // Go: c := b.buf[b.off]
        let c = self.buf[self.off];
        // Go: if c < utf8.RuneSelf { b.off++; b.lastRead = opReadRune1; return rune(c), 1, nil }
        if c < utf8::RuneSelf {
            self.off += 1;
            self.last_rune_size = 1;
            return (torune(c), 1, nil);
        }
        // Go: r, n := utf8.DecodeRune(b.buf[b.off:])
        let (r, n) = utf8::DecodeRune(&self.buf[self.off..]);
        // Go: b.off += n; b.lastRead = readOp(n)
        self.off += n as usize;
        self.last_rune_size = touint8(n);
        return (r, n, nil);
    }

    // go: sdk 1.25.5 bytes/buffer.go:402-411 Buffer.UnreadRune
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
        return nil;
    }

    // go: sdk 1.25.5 bytes/buffer.go:97-107 Buffer.Truncate
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

    // go: sdk 1.25.5 bytes/buffer.go:362-372 Buffer.ReadByte
    /// `(b *Buffer).ReadByte()` (buffer.go:362) — pop one byte.
    /// Returns `(0, io.EOF)` when empty.
    pub fn ReadByte(&mut self) -> (byte, error) {
        self.last_rune_size = 0;
        // Go: if b.empty() { b.Reset(); return 0, io.EOF }
        if self.empty() {
            self.Reset();
            return (0, io::EOF.into());
        }
        // Go: c := b.buf[b.off]; b.off++
        let c = self.buf[self.off];
        self.off += 1;
        return (c, nil);
    }

    // go: sdk 1.25.5 bytes/buffer.go:419-428 Buffer.UnreadByte
    /// `(b *Buffer).UnreadByte()` (buffer.go:419) — push back one byte.
    /// Slim port: doesn't track last-op state — succeeds whenever off>0.
    pub fn UnreadByte(&mut self) -> error {
        self.last_rune_size = 0;
        // Go strictly tracks lastRead; slim port simply rewinds if able.
        return if self.off > 0 {
            self.off -= 1;
            nil
        } else {
            crate::errors::New(
                "bytes.Buffer: UnreadByte: previous operation was not a successful read",
            )
        };
    }

    // go: sdk 1.25.5 bytes/buffer.go:443-461 Buffer.readSlice
    /// Go: "like ReadBytes but returns a reference to internal buffer
    /// data." goish's `slice<byte>` owns its bytes, so the reference
    /// half does not survive the port and both callers get a copy —
    /// which is what `ReadBytes` documents Go's own copy as doing.
    fn readSlice(&mut self, delim: byte) -> (slice<byte>, error) {
        let mut i: int = -1;
        for (k, b) in self.buf[self.off..].iter().enumerate() {
            if *b == delim {
                i = toint(k);
                break;
            }
        }
        let (end, err) = if i < 0 {
            (self.buf.len(), io::EOF.into())
        } else {
            (self.off + i as usize + 1, nil)
        };
        let line = slice::__from_vec(self.buf[self.off..end].to_vec());
        self.off = end;
        return (line, err);
    }

    // go: sdk 1.25.5 bytes/buffer.go:430-441 Buffer.ReadBytes
    /// Reads until the first occurrence of `delim`, returning the data
    /// up to and including it. Returns the data read before an error
    /// and the error itself — often `io.EOF` — so it errors iff the
    /// data does not end in `delim`.
    pub fn ReadBytes(&mut self, delim: byte) -> (slice<byte>, error) {
        self.last_rune_size = 0;
        return self.readSlice(delim);
    }

    // go: sdk 1.25.5 bytes/buffer.go:464-467 Buffer.ReadString
    /// `(b *Buffer).ReadString(delim)` (buffer.go:464) — same as
    /// ReadBytes but returns a `string`.
    pub fn ReadString(&mut self, delim: byte) -> (string, error) {
        let (line, err) = self.ReadBytes(delim);
        return (string::from_bytes(&line), err);
    }

    // go: sdk 1.25.5 bytes/buffer.go:212-231 Buffer.ReadFrom
    // goishlint:ignore GOISH023 — the body ends in an infinite
    //     `loop` whose every exit is a `return` from inside it, so
    //     there is no tail expression to make explicit. Go writes the
    //     same shape: `for { … }` with returns in the body.
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
            n += toint64(m);
            if crate::errors::Is(e.clone(), io::EOF) {
                return (n, nil);
            }
            if !e.IsNil() {
                return (n, e);
            }
        }
    }

    // go: sdk 1.25.5 bytes/buffer.go:264-285 Buffer.WriteTo
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
            if toint(m) > nbytes {
                panic!("bytes.Buffer.WriteTo: invalid Write count");
            }
            self.off += m as usize;
            n = toint64(m);
            if !e.IsNil() {
                return (n, e);
            }
            // all bytes should have been written, by definition of
            // Write method in io.Writer
            if toint(m) != nbytes {
                return (n, io::ErrShortWrite.into());
            }
        }
        // Buffer is now empty; reset.
        self.Reset();
        return (n, nil);
    }
}

/// `bytes.MinRead` (buffer.go:206) — minimum slice size used by
/// `Buffer.ReadFrom`.
pub const MinRead: int = 512;

impl Default for Buffer {
    // go: none — goish idiom: the same zero value as `new`, reachable
    //     through `Default`. Go gets this from its zero-value rule.
    fn default() -> Self {
        return Self::new();
    }
}

impl io::Writer for Buffer {
    // go: none — goish idiom: the hidden Any-view hooks every
    // `#[goish::interface]` concrete impl overrides so an assertion on
    // a `dyn io::Reader` / `dyn io::Writer` can reach this type. Go's
    // itabs make them unnecessary. Without the MUTABLE one, `io::Copy`
    // misses `src.(WriterTo)` / `dst.(ReaderFrom)` and the fast-path
    // impl on this type is unreachable through the interface.
    fn __goish_as_dyn_any(&self) -> Option<&(dyn core::any::Any + Send + Sync)> {
        return Some(self);
    }
    // go: none — goish idiom: see `__goish_as_dyn_any`.
    fn __goish_as_dyn_any_mut(&mut self) -> Option<&mut (dyn core::any::Any + Send + Sync)> {
        return Some(self);
    }

    // go: sdk 1.25.5 bytes/buffer.go:181-188 Buffer.Write
    fn Write(&mut self, p: slice<byte>) -> (int, error) {
        return Buffer::Write(self, p);
    }
}

impl io::ByteReader for Buffer {
    // go: sdk 1.25.5 bytes/buffer.go:362-372 Buffer.ReadByte
    fn ReadByte(&mut self) -> (byte, error) {
        return Buffer::ReadByte(self);
    }
}

impl io::ByteScanner for Buffer {
    // go: sdk 1.25.5 bytes/buffer.go:419-428 Buffer.UnreadByte
    fn UnreadByte(&mut self) -> error {
        return Buffer::UnreadByte(self);
    }
}

impl io::ByteWriter for Buffer {
    // go: sdk 1.25.5 bytes/buffer.go:291-299 Buffer.WriteByte
    fn WriteByte(&mut self, c: byte) -> error {
        return Buffer::WriteByte(self, c);
    }
}

impl io::StringWriter for Buffer {
    // go: sdk 1.25.5 bytes/buffer.go:193-200 Buffer.WriteString
    fn WriteString(&mut self, s: string) -> (int, error) {
        return Buffer::WriteString(self, s);
    }
}

impl io::ReaderFrom for Buffer {
    // go: sdk 1.25.5 bytes/buffer.go:212-231 Buffer.ReadFrom
    fn ReadFrom(&mut self, r: &mut dyn io::Reader) -> (i64, error) {
        return Buffer::ReadFrom(self, r);
    }
}

impl io::WriterTo for Buffer {
    // go: sdk 1.25.5 bytes/buffer.go:264-285 Buffer.WriteTo
    fn WriteTo(&mut self, w: &mut dyn io::Writer) -> (i64, error) {
        return Buffer::WriteTo(self, w);
    }
}

impl io::Reader for Buffer {
    // go: none — goish idiom: the hidden Any-view hooks every
    // `#[goish::interface]` concrete impl overrides so an assertion on
    // a `dyn io::Reader` / `dyn io::Writer` can reach this type. Go's
    // itabs make them unnecessary. Without the MUTABLE one, `io::Copy`
    // misses `src.(WriterTo)` / `dst.(ReaderFrom)` and the fast-path
    // impl on this type is unreachable through the interface.
    fn __goish_as_dyn_any(&self) -> Option<&(dyn core::any::Any + Send + Sync)> {
        return Some(self);
    }
    // go: none — goish idiom: see `__goish_as_dyn_any`.
    fn __goish_as_dyn_any_mut(&mut self) -> Option<&mut (dyn core::any::Any + Send + Sync)> {
        return Some(self);
    }

    // go: sdk 1.25.5 bytes/buffer.go:324-340 Buffer.Read
    fn Read(&mut self, p: &mut slice<byte>) -> (int, error) {
        return Buffer::Read(self, p);
    }
}

// go: sdk 1.25.5 bytes/buffer.go:478-478 NewBuffer
/// `NewBuffer(buf)` — Buffer using `buf` as initial contents (read-
/// from-front). Go's `bytes.NewBuffer` returns `*Buffer`; the Goish
/// runtime returns owned `Buffer` to keep trait-impl dispatch (io::
/// Writer, io::Reader, …) working without forwarding boilerplate.
/// The transpiler wraps the call as `nilable::new(bytes::NewBuffer(…))`
/// when feeding a `*Buffer` slot — see `PointerReturnSlots` in
/// stdlib_registry.go.
pub fn NewBuffer(buf: slice<byte>) -> Buffer {
    return Buffer {
        buf: buf.__into_vec(),
        off: 0,
        last_rune_size: 0,
    };
}

// go: sdk 1.25.5 bytes/buffer.go:486-488 NewBufferString
/// `NewBufferString(s)` — Buffer initialized with the bytes of `s`.
/// Same return-shape rationale as `NewBuffer`.
pub fn NewBufferString<S: Into<string>>(s: S) -> Buffer {
    let s = s.into();
    return Buffer {
        buf: s.as_bytes().to_vec(),
        off: 0,
        last_rune_size: 0,
    };
}
