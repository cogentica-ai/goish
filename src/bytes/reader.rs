// go: file bytes/reader.go decls: NewReader, Reader.Len, Reader.Size, Reader.Read, Reader.ReadAt, Reader.ReadByte, Reader.UnreadByte, Reader.ReadRune, Reader.UnreadRune, Reader.Seek, Reader.WriteTo, Reader.Reset
//
// bytes/reader.go — a `Reader` over a byte slice, implementing
// io.Reader, io.ReaderAt, io.WriterTo, io.Seeker, io.ByteScanner and
// io.RuneScanner.
//
// The `prevRune` field is what makes `UnreadRune` possible, and is why
// it is -1 everywhere but immediately after a `ReadRune`: every other
// read invalidates it, so an `UnreadRune` that does not directly follow
// a `ReadRune` is an error rather than a silent rewind.
//
// Unlike `bytes.Buffer`, a `Reader` is read-only and never grows, so it
// has no `off`-recovery machinery — `i` only ever moves forward, except
// through `Seek` and `UnreadByte`/`UnreadRune`.

#![allow(non_snake_case, non_upper_case_globals)]

extern crate alloc;
use alloc::vec::Vec;

use crate::convert::{int as toint, int64 as toint64, rune as torune};

use crate::errors::{error, nil};
use crate::goslice::slice;
use crate::io;
use crate::types::{byte, int, rune};
use crate::unicode::utf8;

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
    // go: sdk 1.25.5 bytes/reader.go:26-31 Reader.Len
    pub fn Len(&self) -> int {
        if self.i >= self.s.len() {
            return 0;
        }
        return toint(self.s.len() - self.i);
    }

    // go: sdk 1.25.5 bytes/reader.go:36-36 Reader.Size
    pub fn Size(&self) -> int {
        return toint(self.s.len());
    }

    // go: sdk 1.25.5 bytes/reader.go:39-47 Reader.Read
    pub fn Read(&mut self, p: &mut slice<byte>) -> (int, error) {
        self.prev_rune = -1;
        if self.i >= self.s.len() {
            return (0, io::EOF.into());
        }
        let want = (p.Len() as usize).min(self.s.len() - self.i);
        for k in 0..want {
            p[toint(k)] = self.s[self.i + k];
        }
        self.i += want;
        return (toint(want), nil);
    }

    // go: sdk 1.25.5 bytes/reader.go:156-156 Reader.Reset
    pub fn Reset(&mut self, b: slice<byte>) {
        self.s = b.__into_vec();
        self.i = 0;
        self.prev_rune = -1;
    }

    // go: sdk 1.25.5 bytes/reader.go:66-74 Reader.ReadByte
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
        return (b, nil);
    }

    // go: sdk 1.25.5 bytes/reader.go:77-84 Reader.UnreadByte
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
        return nil;
    }

    // go: sdk 1.25.5 bytes/reader.go:87-100 Reader.ReadRune
    /// `(r *Reader).ReadRune()` (bytes/reader.go:87) — implements
    /// io.RuneReader. ASCII fast-path; non-ASCII via DecodeRune.
    pub fn ReadRune(&mut self) -> (rune, int, error) {
        // Go: if r.i >= int64(len(r.s)) { r.prevRune = -1; return 0, 0, io.EOF }
        if self.i >= self.s.len() {
            self.prev_rune = -1;
            return (0, 0, io::EOF.into());
        }
        // Go: r.prevRune = int(r.i)
        self.prev_rune = toint64(self.i);
        // Go: if c := r.s[r.i]; c < utf8.RuneSelf { r.i++; return rune(c), 1, nil }
        let c = self.s[self.i];
        if c < utf8::RuneSelf {
            self.i += 1;
            return (torune(c), 1, nil);
        }
        // Go: ch, size = utf8.DecodeRune(r.s[r.i:])
        let (ch, size) = utf8::DecodeRune(&self.s[self.i..]);
        // Go: r.i += int64(size)
        self.i += size as usize;
        return (ch, size, nil);
    }

    // go: sdk 1.25.5 bytes/reader.go:103-113 Reader.UnreadRune
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
        return nil;
    }

    // go: sdk 1.25.5 bytes/reader.go:116-134 Reader.Seek
    /// `(r *Reader).Seek(offset, whence)` (bytes/reader.go:127) — slim port.
    pub fn Seek(&mut self, offset: i64, whence: int) -> (i64, error) {
        // Go: r.prevRune = -1
        self.prev_rune = -1;
        // Go: switch whence { case SeekStart: ... }
        let abs: i64 = match whence {
            x if x == io::SeekStart => offset,
            x if x == io::SeekCurrent => toint64(self.i).wrapping_add(offset),
            x if x == io::SeekEnd => toint64(self.s.len()).wrapping_add(offset),
            _ => {
                return (0, crate::errors::New("bytes.Reader.Seek: invalid whence"));
            }
        };
        // Go: if abs < 0 { return 0, error }
        if abs < 0 {
            return (
                0,
                crate::errors::New("bytes.Reader.Seek: negative position"),
            );
        }
        self.i = abs as usize;
        return (abs, nil);
    }

    // go: sdk 1.25.5 bytes/reader.go:137-153 Reader.WriteTo
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
        let n = toint64(m);
        // if m != len(b) && err == nil { err = io.ErrShortWrite }
        if m != blen && err.IsNil() {
            return (n, io::ErrShortWrite.into());
        }
        return (n, err);
    }

    // go: sdk 1.25.5 bytes/reader.go:50-63 Reader.ReadAt
    /// `(r *Reader).ReadAt(p, off)` (bytes/reader.go:88) — slim port.
    pub fn ReadAt(&mut self, p: &mut slice<byte>, off: i64) -> (int, error) {
        // Go: if off < 0 { return 0, errors.New("bytes.Reader.ReadAt: negative offset") }
        if off < 0 {
            return (
                0,
                crate::errors::New("bytes.Reader.ReadAt: negative offset"),
            );
        }
        if off >= toint64(self.s.len()) {
            return (0, io::EOF.into());
        }
        let start = off as usize;
        let want = (p.Len() as usize).min(self.s.len() - start);
        for k in 0..want {
            p[toint(k)] = self.s[start + k];
        }
        // Go: if n < len(p) { err = io.EOF }
        if want < p.Len() as usize {
            return (toint(want), io::EOF.into());
        }
        return (toint(want), nil);
    }
}

impl io::Seeker for Reader {
    // go: sdk 1.25.5 bytes/reader.go:116-134 Reader.Seek
    fn Seek(&mut self, offset: i64, whence: int) -> (i64, error) {
        return Reader::Seek(self, offset, whence);
    }
}

impl io::ReaderAt for Reader {
    // go: sdk 1.25.5 bytes/reader.go:50-63 Reader.ReadAt
    fn ReadAt(&mut self, p: &mut slice<byte>, off: i64) -> (int, error) {
        return Reader::ReadAt(self, p, off);
    }
}

impl io::Reader for Reader {
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

    // go: sdk 1.25.5 bytes/reader.go:39-47 Reader.Read
    fn Read(&mut self, p: &mut slice<byte>) -> (int, error) {
        return Reader::Read(self, p);
    }
}

impl io::ByteReader for Reader {
    // go: sdk 1.25.5 bytes/reader.go:66-74 Reader.ReadByte
    fn ReadByte(&mut self) -> (byte, error) {
        return Reader::ReadByte(self);
    }
}

impl io::WriterTo for Reader {
    // go: sdk 1.25.5 bytes/reader.go:137-153 Reader.WriteTo
    fn WriteTo(&mut self, w: &mut dyn io::Writer) -> (i64, error) {
        return Reader::WriteTo(self, w);
    }
}

// go: sdk 1.25.5 bytes/reader.go:159-159 NewReader
/// `NewReader(b)` — `Reader` over `b`. Go: `*Reader`; Goish runtime
/// returns owned `Reader` (see `NewBuffer` for the rationale).
pub fn NewReader<B: Into<slice<byte>>>(b: B) -> Reader {
    let b = b.into();
    return Reader {
        s: b.__into_vec(),
        i: 0,
        prev_rune: -1,
    };
}
