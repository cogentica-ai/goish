// testing/iotest — Readers and Writers useful for testing.
//
// Reference: /share/go/src/testing/iotest/reader.go
//
// Slim deviations:
//   * `TestReader` not ported. It does runtime downcasts to ReadSeeker
//     and ReaderAt to exercise those interfaces; goish models those
//     traits as concrete impl bounds rather than dyn-Trait so a
//     downcast-style test helper is awkward without trait objects.
//     Easy to add per-trait test helpers later if needed.
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
