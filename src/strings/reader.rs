// go: file strings/reader.go decls: NewReader, Reader.Len, Reader.Size, Reader.Read, Reader.ReadAt, Reader.ReadByte, Reader.UnreadByte, Reader.ReadRune, Reader.UnreadRune, Reader.Seek, Reader.WriteTo, Reader.Reset
//
// strings/reader.go — a `Reader` over a string, implementing io.Reader,
// io.ReaderAt, io.ByteReader, io.RuneReader, io.Seeker, io.WriterTo,
// io.ByteScanner and io.RuneScanner.
//
// The `prevRune` field is what makes `UnreadRune` possible and is why
// it is -1 everywhere but immediately after a `ReadRune`: every other
// read invalidates it, so an `UnreadRune` that does not directly follow
// a `ReadRune` is an error rather than a silent rewind.

#![allow(non_snake_case, non_upper_case_globals)]

extern crate alloc;

use crate::convert::{int as toint, int64 as toint64, rune as torune};
use crate::errors::{error, nil};
use crate::goslice::slice;
use crate::gostring::string;
use crate::io;
use crate::types::{byte, int, rune};
use crate::unicode::utf8;

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
    // go: sdk 1.25.5 strings/reader.go:25-30 Reader.Len
    pub fn Len(&self) -> int {
        if self.i >= self.s.Len() {
            return 0;
        }
        return self.s.Len() - self.i;
    }

    // go: sdk 1.25.5 strings/reader.go:36-36 Reader.Size
    pub fn Size(&self) -> int {
        return self.s.Len();
    }

    // go: sdk 1.25.5 strings/reader.go:39-47 Reader.Read
    pub fn Read(&mut self, p: &mut slice<byte>) -> (int, error) {
        if self.i >= self.s.Len() {
            return (0, io::EOF.into());
        }
        // Go: r.prevRune = -1
        self.prev_rune = -1;
        let want = (p.Len() as usize).min((self.s.Len() - self.i) as usize);
        let bytes = self.s.as_bytes();
        for k in 0..want {
            p[toint(k)] = bytes[self.i as usize + k];
        }
        self.i += toint(want);
        return (toint(want), nil);
    }

    // go: sdk 1.25.5 strings/reader.go:156-156 Reader.Reset
    pub fn Reset<S: Into<string>>(&mut self, s: S) {
        // Go: *r = Reader{s, 0, -1}
        self.s = s.into();
        self.i = 0;
        self.prev_rune = -1;
    }

    // go: sdk 1.25.5 strings/reader.go:66-74 Reader.ReadByte
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
        return (b, nil);
    }

    // go: sdk 1.25.5 strings/reader.go:77-84 Reader.UnreadByte
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
        return nil;
    }

    // go: sdk 1.25.5 strings/reader.go:87-100 Reader.ReadRune
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
            return (torune(c), 1, nil);
        }
        // Go: ch, size = utf8.DecodeRuneInString(r.s[r.i:])
        let tail = string::from_bytes(&self.s.as_bytes()[self.i as usize..]);
        let (ch, size) = utf8::DecodeRuneInString(&tail);
        // Go: r.i += int64(size)
        self.i += size;
        return (ch, size, nil);
    }

    // go: sdk 1.25.5 strings/reader.go:103-113 Reader.UnreadRune
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
        return nil;
    }

    // go: sdk 1.25.5 strings/reader.go:116-134 Reader.Seek
    /// `(r *Reader).Seek(offset, whence)` (strings/reader.go:99) — slim port.
    pub fn Seek(&mut self, offset: i64, whence: int) -> (i64, error) {
        // Go: r.prevRune = -1
        self.prev_rune = -1;
        let abs: i64 = if whence == io::SeekStart {
            offset
        } else if whence == io::SeekCurrent {
            toint64(self.i).wrapping_add(offset)
        } else if whence == io::SeekEnd {
            toint64(self.s.Len()).wrapping_add(offset)
        } else {
            return (0, crate::errors::New("strings.Reader.Seek: invalid whence"));
        };
        if abs < 0 {
            return (
                0,
                crate::errors::New("strings.Reader.Seek: negative position"),
            );
        }
        self.i = toint(abs);
        return (abs, nil);
    }

    // go: sdk 1.25.5 strings/reader.go:50-63 Reader.ReadAt
    /// `(r *Reader).ReadAt(p, off)` (strings/reader.go:62) — slim port.
    pub fn ReadAt(&mut self, p: &mut slice<byte>, off: i64) -> (int, error) {
        if off < 0 {
            return (
                0,
                crate::errors::New("strings.Reader.ReadAt: negative offset"),
            );
        }
        if off >= toint64(self.s.Len()) {
            return (0, io::EOF.into());
        }
        let bytes = self.s.as_bytes();
        let start = off as usize;
        let want = (p.Len() as usize).min(bytes.len() - start);
        for k in 0..want {
            p[toint(k)] = bytes[start + k];
        }
        if want < p.Len() as usize {
            return (toint(want), io::EOF.into());
        }
        return (toint(want), nil);
    }
}

impl io::Reader for Reader {
    // go: none — goish idiom: the hidden Any-view hooks every
    // `#[goish::interface]` concrete impl overrides so an assertion on
    // a `dyn io::Reader` can reach this type. Go's itabs make them
    // unnecessary. Without the MUTABLE one, `io::Copy` misses
    // `src.(WriterTo)` and the WriteTo impl below is unreachable
    // through the interface.
    fn __goish_as_dyn_any(&self) -> Option<&(dyn core::any::Any + Send + Sync)> {
        return Some(self);
    }
    // go: none — goish idiom: see `__goish_as_dyn_any`.
    fn __goish_as_dyn_any_mut(&mut self) -> Option<&mut (dyn core::any::Any + Send + Sync)> {
        return Some(self);
    }

    // go: sdk 1.25.5 strings/reader.go:39-47 Reader.Read
    fn Read(&mut self, p: &mut slice<byte>) -> (int, error) {
        return Reader::Read(self, p);
    }
}

impl io::Seeker for Reader {
    // go: sdk 1.25.5 strings/reader.go:116-134 Reader.Seek
    fn Seek(&mut self, offset: i64, whence: int) -> (i64, error) {
        return Reader::Seek(self, offset, whence);
    }
}

impl io::ReaderAt for Reader {
    // go: sdk 1.25.5 strings/reader.go:50-63 Reader.ReadAt
    fn ReadAt(&mut self, p: &mut slice<byte>, off: i64) -> (int, error) {
        return Reader::ReadAt(self, p, off);
    }
}

impl Reader {
    // go: sdk 1.25.5 strings/reader.go:137-153 Reader.WriteTo
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
        self.i += toint64(m);
        let n = toint64(m);
        // if m != len(s) && err == nil { err = io.ErrShortWrite }
        if (m as usize) != tail.len() && err.IsNil() {
            return (n, io::ErrShortWrite.into());
        }
        return (n, err);
    }
}

impl io::WriterTo for Reader {
    // go: sdk 1.25.5 strings/reader.go:137-153 Reader.WriteTo
    fn WriteTo(&mut self, w: &mut dyn io::Writer) -> (i64, error) {
        return Reader::WriteTo(self, w);
    }
}

// go: sdk 1.25.5 strings/reader.go:160-160 NewReader
/// `strings.NewReader(s)` — `Reader` over `s`.
pub fn NewReader<S: Into<string>>(s: S) -> Reader {
    return Reader {
        s: s.into(),
        i: 0,
        prev_rune: -1,
    };
}
