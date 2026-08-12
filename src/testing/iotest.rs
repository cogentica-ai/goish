// testing/iotest — Readers and Writers useful for testing.
//
// Reference: /share/go/src/testing/iotest/reader.go
//
// Slim deviations:
//   * `TestReader` is ported except for its ReadSeeker and ReaderAt
//     blocks, which begin with runtime downcasts goish cannot express
//     on a `&mut dyn Reader`. Those behaviours are pinned directly
//     instead — see examples/testing_fstest_smoke.rs for MapFS's Seek
//     and ReadAt against goref output.
//   * `OneByteReader` / `HalfReader` / `DataErrReader` / `TimeoutReader`
//     / `ErrReader` are returned as concrete generic structs rather
//     than `io.Reader`. Callers chain them positionally.

#![allow(non_snake_case)]

extern crate alloc;

use alloc::vec::Vec;

use crate::errors::{self, error, ErrorTrait};
use crate::goslice::slice;
use crate::gostring::string;
use crate::io;
use crate::types::{byte, int};

// ─── ErrTimeout ─────────────────────────────────────────────────────────────

struct ErrTimeoutImpl;
impl ErrorTrait for ErrTimeoutImpl {
    fn Error(&self) -> string {
        string::from_static("timeout")
    }
}

crate::var! {
    /// `iotest.ErrTimeout` (reader.go:74) — fake timeout error.
    pub ErrTimeout: error = { ErrTimeoutImpl };
}

// ─── OneByteReader (reader.go:17) ────────────────────────────────────────────

// go: sdk 1.25.5 testing/iotest/reader.go:17-17 OneByteReader
/// `iotest.OneByteReader(r)` — Reader that reads at most one byte per Read.
pub fn OneByteReader<R: io::Reader>(r: R) -> OneByteReaderImpl<R> {
    OneByteReaderImpl { r }
}

pub struct OneByteReaderImpl<R: io::Reader> {
    r: R,
}

impl<R: io::Reader> io::Reader for OneByteReaderImpl<R> {
    fn Read(&mut self, p: &mut slice<byte>) -> (int, error) {
        // Go: reader.go:24 — if len(p) == 0 { return 0, nil }
        if p.len() == 0 {
            return (0, errors::nil);
        }
        // Go: reader.go:27 — return r.r.Read(p[0:1])
        let mut one: slice<byte> = slice::__from_vec(alloc::vec![0u8; 1]);
        let (n, e) = self.r.Read(&mut one);
        if n == 1 {
            p[0] = one[0];
        }
        (n, e)
    }
}

// ─── HalfReader (reader.go:32) ───────────────────────────────────────────────

// go: sdk 1.25.5 testing/iotest/reader.go:32-32 HalfReader
/// `iotest.HalfReader(r)` — reads half the requested bytes per Read.
pub fn HalfReader<R: io::Reader>(r: R) -> HalfReaderImpl<R> {
    HalfReaderImpl { r }
}

pub struct HalfReaderImpl<R: io::Reader> {
    r: R,
}

impl<R: io::Reader> io::Reader for HalfReaderImpl<R> {
    fn Read(&mut self, p: &mut slice<byte>) -> (int, error) {
        // Go: reader.go:39 — return r.r.Read(p[0 : (len(p)+1)/2])
        let want = (p.len() + 1) / 2;
        let mut tmp: slice<byte> = slice::__from_vec(alloc::vec![0u8; want]);
        let (n, e) = self.r.Read(&mut tmp);
        for i in 0..n as usize {
            p[i as int] = tmp[i as int];
        }
        (n, e)
    }
}

// ─── DataErrReader (reader.go:47) ────────────────────────────────────────────

// go: sdk 1.25.5 testing/iotest/reader.go:47-47 DataErrReader
/// `iotest.DataErrReader(r)` — wrap `r` so the final error is returned
/// alongside the final data, instead of in the next call.
pub fn DataErrReader<R: io::Reader>(r: R) -> DataErrReaderImpl<R> {
    DataErrReaderImpl {
        r,
        unread: alloc::vec![],
        data: alloc::vec![0u8; 1024],
        err: errors::nil,
    }
}

pub struct DataErrReaderImpl<R: io::Reader> {
    r: R,
    unread: Vec<byte>,
    data: Vec<byte>,
    err: error,
}

impl<R: io::Reader> io::Reader for DataErrReaderImpl<R> {
    fn Read(&mut self, p: &mut slice<byte>) -> (int, error) {
        // Go: reader.go:55-71 — first call needs two reads.
        let mut n: int = 0;
        loop {
            if self.unread.is_empty() && self.err.IsNil() {
                let mut tmp: slice<byte> = slice::__from_vec(self.data.clone());
                let (n1, err1) = self.r.Read(&mut tmp);
                let raw: &[byte] = &tmp;
                self.unread = raw[..n1 as usize].to_vec();
                self.err = err1;
            }
            if n > 0 || !self.err.IsNil() {
                break;
            }
            let take = (p.len() as usize).min(self.unread.len());
            for i in 0..take {
                p[i as int] = self.unread[i];
            }
            n = take as int;
            self.unread.drain(..take);
        }
        (n, self.err.clone())
    }
}

// ─── TimeoutReader (reader.go:78) ────────────────────────────────────────────

// go: sdk 1.25.5 testing/iotest/reader.go:78-78 TimeoutReader
/// `iotest.TimeoutReader(r)` — return ErrTimeout on the second read with
/// no data; subsequent reads succeed.
pub fn TimeoutReader<R: io::Reader>(r: R) -> TimeoutReaderImpl<R> {
    TimeoutReaderImpl { r, count: 0 }
}

pub struct TimeoutReaderImpl<R: io::Reader> {
    r: R,
    count: int,
}

impl<R: io::Reader> io::Reader for TimeoutReaderImpl<R> {
    fn Read(&mut self, p: &mut slice<byte>) -> (int, error) {
        // Go: reader.go:85-91
        self.count += 1;
        if self.count == 2 {
            return (0, ErrTimeout.into());
        }
        self.r.Read(p)
    }
}

// ─── ErrReader (reader.go:94) ────────────────────────────────────────────────

// go: sdk 1.25.5 testing/iotest/reader.go:94-96 ErrReader
/// `iotest.ErrReader(err)` — Reader that returns `(0, err)` on every Read.
pub fn ErrReader(err: error) -> ErrReaderImpl {
    ErrReaderImpl { err }
}

pub struct ErrReaderImpl {
    err: error,
}

impl io::Reader for ErrReaderImpl {
    fn Read(&mut self, _p: &mut slice<byte>) -> (int, error) {
        // Go: reader.go:102-104
        (0, self.err.clone())
    }
}

// ─── writeLogger / readLogger (logger.go) ────────────────────────────────────

// go: sdk 1.25.5 testing/iotest/logger.go:11-14 writeLogger
/// Go: `type writeLogger struct { prefix string; w io.Writer }`
pub struct writeLogger<W: io::Writer> {
    prefix: string,
    w: W,
}

impl<W: io::Writer> io::Writer for writeLogger<W> {
    // go: sdk 1.25.5 testing/iotest/logger.go:16-24 writeLogger.Write
    /// Go: write through, then log the prefix and the hex of what was
    /// actually written — `p[0:n]`, not `p`, so a short write logs only
    /// the bytes that landed.
    fn Write(&mut self, p: slice<byte>) -> (int, error) {
        let (n, err) = self.w.Write(p.clone());
        // Go: log.Printf("%s %x: %v", l.prefix, p[0:n], err)  on error
        //     log.Printf("%s %x",     l.prefix, p[0:n])       otherwise
        let written = hex_of(&p, n);
        if err != errors::nil {
            crate::log::Printf!("%s %x: %v", self.prefix.clone(), written, err.Error());
        } else {
            crate::log::Printf!("%s %x", self.prefix.clone(), written);
        }
        return (n, err);
    }
}

// go: sdk 1.25.5 testing/iotest/logger.go:30-32 NewWriteLogger
/// Go: "NewWriteLogger returns a writer that behaves like w except that
/// it logs (using log.Printf) each write to standard error, printing
/// the prefix and the hexadecimal data written."
pub fn NewWriteLogger<W: io::Writer>(prefix: string, w: W) -> writeLogger<W> {
    return writeLogger { prefix: prefix, w: w };
}

// go: sdk 1.25.5 testing/iotest/logger.go:34-37 readLogger
/// Go: `type readLogger struct { prefix string; r io.Reader }`
pub struct readLogger<R: io::Reader> {
    prefix: string,
    r: R,
}

impl<R: io::Reader> io::Reader for readLogger<R> {
    // go: sdk 1.25.5 testing/iotest/logger.go:39-47 readLogger.Read
    /// Go: read through, then log the prefix and the hex of `p[0:n]`.
    fn Read(&mut self, p: &mut slice<byte>) -> (int, error) {
        let (n, err) = self.r.Read(p);
        let read = hex_of(p, n);
        if err != errors::nil {
            crate::log::Printf!("%s %x: %v", self.prefix.clone(), read, err.Error());
        } else {
            crate::log::Printf!("%s %x", self.prefix.clone(), read);
        }
        return (n, err);
    }
}

// go: sdk 1.25.5 testing/iotest/logger.go:52-54 NewReadLogger
/// Go: "NewReadLogger returns a reader that behaves like r except that
/// it logs (using log.Printf) each read to standard error, printing the
/// prefix and the hexadecimal data read."
pub fn NewReadLogger<R: io::Reader>(prefix: string, r: R) -> readLogger<R> {
    return readLogger { prefix: prefix, r: r };
}

// go: none — goish idiom: Go passes the sub-slice `p[0:n]` straight to
// `%x`, which fmt renders as hex. goish's `%x` on a slice<byte> takes
// the same path, so this only performs the re-slice.
fn hex_of(p: &slice<byte>, n: int) -> slice<byte> {
    let mut out: Vec<byte> = Vec::new();
    let mut i: int = 0;
    while i < n && i < p.Len() {
        out.push(p[i]);
        i += 1;
    }
    return slice::__from_vec(out);
}

// ─── truncateWriter (writer.go) ──────────────────────────────────────────────

// go: sdk 1.25.5 testing/iotest/writer.go:15-18 truncateWriter
/// Go: `type truncateWriter struct { w io.Writer; n int64 }`
pub struct truncateWriter<W: io::Writer> {
    w: W,
    n: crate::types::int64,
}

impl<W: io::Writer> io::Writer for truncateWriter<W> {
    // go: sdk 1.25.5 testing/iotest/writer.go:20-34 truncateWriter.Write
    /// Go: pass writes through until the budget runs out, then report
    /// success without writing. Note the two places Go reports
    /// `len(p)` rather than the bytes actually written — a truncating
    /// writer must look like a complete write to its caller, or every
    /// io helper above it would return ErrShortWrite.
    fn Write(&mut self, p: slice<byte>) -> (int, error) {
        // Go: if t.n <= 0 { return len(p), nil }
        if self.n <= 0 {
            return (p.Len(), errors::nil);
        }
        // Go: n = len(p); if int64(n) > t.n { n = int(t.n) }
        let mut n: int = p.Len();
        if crate::int64(n) > self.n {
            n = crate::int(self.n);
        }
        // Go: n, err = t.w.Write(p[0:n])
        let (mut n, err) = self.w.Write(p.slice(0, n));
        self.n -= crate::int64(n);
        // Go: if err == nil { n = len(p) }
        if err == errors::nil {
            n = p.Len();
        }
        return (n, err);
    }
}

// go: sdk 1.25.5 testing/iotest/writer.go:11-13 TruncateWriter
/// Go: "TruncateWriter returns a Writer that writes to w but stops
/// silently after n bytes."
pub fn TruncateWriter<W: io::Writer>(w: W, n: crate::types::int64) -> truncateWriter<W> {
    return truncateWriter { w: w, n: n };
}

// ─── TestReader ──────────────────────────────────────────────────────

// go: sdk 1.25.5 testing/iotest/reader.go:106-110 smallByteReader
/// Go: a Reader that forwards reads in deliberately awkward 1-, 2- and
/// 3-byte chunks, cycling.
///
/// The point is that a caller must not assume `Read` fills the buffer
/// it was given. Anything that treats a short read as EOF, or that
/// indexes past `n`, breaks here and passes against a well-behaved
/// reader.
pub struct smallByteReader<R: io::Reader> {
    r: R,
    off: int,
    n: int,
}

impl<R: io::Reader> io::Reader for smallByteReader<R> {
    // go: sdk 1.25.5 testing/iotest/reader.go:112-127 smallByteReader.Read
    fn Read(&mut self, p: &mut slice<byte>) -> (int, error) {
        // Go: if len(p) == 0 { return 0, nil }
        if p.Len() == 0 {
            return (0, errors::nil);
        }
        // Go: r.n = r.n%3 + 1 — cycles 1, 2, 3, 1, 2, 3, …
        self.n = self.n % 3 + 1;
        let mut n = self.n;
        if n > p.Len() {
            n = p.Len();
        }
        let mut sub = p.slice(0, n);
        let (got, err) = self.r.Read(&mut sub);
        // Copy back: goish's re-slice is a fresh handle rather than a
        // view sharing backing storage, so the bytes have to be moved
        // into the caller's buffer explicitly. Go's `p[0:n]` aliases.
        for i in 0..got {
            p[i] = sub[i];
        }
        let eof: error = crate::io::EOF.clone().into();
        let err = if err != errors::nil && err != eof {
            errors::New(crate::fmt::Sprintf!(
                "Read(%d bytes at offset %d): %v",
                got,
                self.off,
                err.Error()
            ))
        } else {
            err
        };
        self.off += got;
        return (got, err);
    }
}

// go: sdk 1.25.5 testing/iotest/reader.go:136-268 TestReader
/// Go: "TestReader tests that reading from r returns the expected file
/// content. It does reads of different sizes, until EOF. If r implements
/// io.ReaderAt or io.Seeker, TestReader also checks that those work.
/// It checks that if TestReader reads the same content twice, it gets
/// the same bytes both times."
///
/// **Partial port.** The `io.ReadSeeker` and `io.ReaderAt` blocks —
/// roughly two thirds of Go's body — are absent. They begin
/// `if r, ok := r.(io.ReadSeeker); ok`, and goish models Seeker and
/// ReaderAt as concrete impl bounds rather than dyn-dispatched
/// interfaces, so there is no runtime assertion to make on a
/// `&mut dyn Reader`. Those behaviours are not untested: MapFS's Seek
/// and ReadAt are pinned directly in
/// examples/testing_fstest_smoke.rs, against goref output.
///
/// What remains is the part that applies to every Reader, and it is the
/// part most implementations get wrong:
///
///   * `Read` with a zero-length buffer must return `(0, nil)` — NOT
///     EOF. A reader that reports EOF for an empty buffer breaks every
///     caller that probes before allocating.
///   * Reading through `smallByteReader`'s 1/2/3-byte chunks must
///     reassemble to exactly `content`, so a short read cannot be
///     treated as the end.
///   * At EOF, a further read returns `(0, io.EOF)`.
pub fn TestReader<R: io::Reader>(mut r: R, content: slice<byte>) -> error {
    // Go: if len(content) > 0 { n, err := r.Read(nil); ... }
    if content.Len() > 0 {
        let mut empty: slice<byte> = slice::new();
        let (n, err) = r.Read(&mut empty);
        if n != 0 || err != errors::nil {
            return errors::New(crate::fmt::Sprintf!(
                "Read(0) = %d, %v, want 0, nil",
                n,
                err.Error()
            ));
        }
    }

    let mut small = smallByteReader { r: r, off: 0, n: 0 };
    let (data, err) = read_to_end(&mut small);
    if err != errors::nil {
        return err;
    }
    if string::from_bytes(data.as_ref()) != string::from_bytes(content.as_ref()) {
        return errors::New(crate::fmt::Sprintf!(
            "ReadAll(small amounts) = %q\n\twant %q",
            string::from_bytes(data.as_ref()),
            string::from_bytes(content.as_ref())
        ));
    }

    // Go: n, err := r.Read(make([]byte, 10)); want 0, EOF
    let mut buf: slice<byte> = crate::make!([]byte, 10);
    let (n, err) = small.r.Read(&mut buf);
    let eof: error = crate::io::EOF.clone().into();
    if n != 0 || err != eof {
        return errors::New(crate::fmt::Sprintf!(
            "Read(10) at EOF = %v, %v, want 0, EOF",
            n,
            err.Error()
        ));
    }

    return errors::nil;
}

// go: none — goish idiom: Go calls `io.ReadAll(&smallByteReader{r: r})`.
// goish's io::ReadAll takes `&mut dyn Reader`, and threading the
// generic reader through a trait object here would force an allocation
// per call, so the loop is spelled out.
fn read_to_end<R: io::Reader>(r: &mut R) -> (slice<byte>, error) {
    let mut out: Vec<byte> = Vec::new();
    let eof: error = crate::io::EOF.clone().into();
    return 'read: loop {
        let mut buf: slice<byte> = crate::make!([]byte, 64);
        let (n, err) = r.Read(&mut buf);
        for i in 0..n {
            out.push(buf[i]);
        }
        if err == eof {
            break 'read (slice::__from_vec(out), errors::nil);
        }
        if err != errors::nil {
            break 'read (slice::__from_vec(out), err);
        }
        if n == 0 {
            break 'read (slice::__from_vec(out), errors::nil);
        }
    };
}
