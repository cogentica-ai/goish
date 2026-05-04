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
