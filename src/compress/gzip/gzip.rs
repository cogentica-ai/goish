// go: file compress/gzip/gzip.go decls: NewWriter, NewWriterLevel, Writer.Reset, Writer.writeBytes, Writer.writeString, Writer.Write, Writer.Flush, Writer.Close
//
// goishlint:ignore GOISH018 init — Go's `(z *Writer).init(w, level)`
//     resets a `Writer` that already exists, because `NewWriterLevel`
//     validates the level *after* allocating. goish builds the struct
//     in one literal inside `NewWriterLevel` and validates after, so
//     there is no separate init step to call.
//
// The `decls:` manifest above lists gzip.go's funcs and methods only.
// GOISH017 matches a manifest entry against Rust `fn` items, so naming
// the `Writer` type or the level constants there would report them as
// dropped ports. They are not dropped - each carries its own
// `// go: sdk` anchor below.
//
// compress/gzip/gzip.go - the gzip (RFC 1952) writer.
//
// The header is written lazily on the first `Write`, `Flush` or
// `Close`, which is what lets a caller set `Name`, `Comment`, `Extra`
// and `ModTime` on the embedded `Header` after construction. The
// string fields are Latin-1 on the wire, not UTF-8, and must not
// contain a NUL, since they are NUL-terminated - `writeString`
// enforces both.

#![allow(non_snake_case, non_camel_case_types, non_upper_case_globals)]

extern crate alloc;
use alloc::vec::Vec;

use crate::compress::flate;
use crate::convert::{byte as tobyte, uint16 as touint16, uint32 as touint32};
use crate::errors::{self, error, nil};
use crate::goslice::slice;
use crate::hash::crc32;
use crate::io;
use crate::time;
use crate::types::{byte, int};

use super::gunzip::{
    flagComment, flagExtra, flagName, from_bytes, gzipDeflate, gzipID1, gzipID2, lePutUint16,
    lePutUint32, Header,
};

// ─── Writer (gzip.go:28) ───────────────────────────────────────────────

/// A `Writer` takes data written to it and writes the gzip-compressed
/// form of that data to an underlying writer. Created by [`NewWriter`] /
/// [`NewWriterLevel`]; implements `io::Writer` + `io::Closer`.
///
/// Go's `Writer` *embeds* `Header`; goish names the embedded field
/// `Header` literally, so `w.Header.Name = ...` mirrors Go's
/// `w.Name = ...`. Callers that wish to set header fields must do so
/// before the first call to [`Write`](Writer::Write) /
/// [`Flush`](Writer::Flush) / [`Close`](Writer::Close).
pub struct Writer<W: io::Writer> {
    /// The gzip header — written at the first call to `Write` / `Flush`
    /// / `Close`.
    pub Header: Header,
    // The destination, parked here until the header + flate writer take
    // over. `compressor` is `None` until the header is written.
    w: Option<W>,
    level: int,
    wroteHeader: bool,
    closed: bool,
    compressor: Option<flate::Writer<W>>,
    digest: u32, // CRC-32, IEEE polynomial (section 8)
    size: u32,   // uncompressed size (section 2.3.1)
    err: error,
}

// go: sdk 1.25.5 compress/gzip/gzip.go:18-25 NoCompression
/// `gzip.NoCompression` — only DEFLATE+gzip framing. Re-exported from
/// `flate` so callers need not also import `compress/flate`.
pub const NoCompression: int = flate::NoCompression;
// go: sdk 1.25.5 compress/gzip/gzip.go:18-25 BestSpeed
/// `gzip.BestSpeed` — fastest compression.
pub const BestSpeed: int = flate::BestSpeed;
// go: sdk 1.25.5 compress/gzip/gzip.go:18-25 BestCompression
/// `gzip.BestCompression` — best compression ratio.
pub const BestCompression: int = flate::BestCompression;
// go: sdk 1.25.5 compress/gzip/gzip.go:18-25 DefaultCompression
/// `gzip.DefaultCompression` — the default level.
pub const DefaultCompression: int = flate::DefaultCompression;
// go: sdk 1.25.5 compress/gzip/gzip.go:18-25 HuffmanOnly
/// `gzip.HuffmanOnly` — Huffman entropy coding only.
pub const HuffmanOnly: int = flate::HuffmanOnly;

// go: sdk 1.25.5 compress/gzip/gzip.go:49-52 NewWriter
/// `gzip.NewWriter(w)` (gzip.go:49) — a new [`Writer`] at
/// [`DefaultCompression`]. Writes are compressed and written to `w`.
///
/// It is the caller's responsibility to call [`Close`](Writer::Close)
/// when done; writes may be buffered until then.
pub fn NewWriter<W: io::Writer>(w: W) -> Writer<W> {
    let (z, _) = NewWriterLevel(w, DefaultCompression);
    return z;
}

// go: sdk 1.25.5 compress/gzip/gzip.go:60-67 NewWriterLevel
/// `gzip.NewWriterLevel(w, level)` (gzip.go:60) — like [`NewWriter`] but
/// with an explicit compression level. The level may be
/// [`DefaultCompression`], [`NoCompression`], [`HuffmanOnly`], or any
/// integer in `[BestSpeed, BestCompression]`. The error is `nil` iff the
/// level is valid.
pub fn NewWriterLevel<W: io::Writer>(w: W, level: int) -> (Writer<W>, error) {
    let z = Writer {
        Header: Header {
            Comment: crate::string::new(),
            Extra: slice::new(),
            ModTime: time::Time::default(),
            Name: crate::string::new(),
            OS: 255, // unknown
        },
        w: Some(w),
        level,
        wroteHeader: false,
        closed: false,
        compressor: None,
        digest: 0,
        size: 0,
        err: nil,
    };
    if level < HuffmanOnly || level > BestCompression {
        return (
            z,
            crate::fmt::Errorf!("gzip: invalid compression level: %d", level),
        );
    }
    return (z, nil);
}

impl<W: io::Writer> Writer<W> {
    // go: sdk 1.25.5 compress/gzip/gzip.go:88-90 Writer.Reset
    /// `(z *Writer).Reset(w)` (gzip.go:88) — discards the `Writer`'s
    /// state and makes it equivalent to a fresh [`NewWriter`] /
    /// [`NewWriterLevel`] writing to `w`, keeping the level unchanged.
    /// The header fields are reset to their `NewWriterLevel` defaults.
    pub fn Reset(&mut self, w: W) {
        self.Header = Header {
            Comment: crate::string::new(),
            Extra: slice::new(),
            ModTime: time::Time::default(),
            Name: crate::string::new(),
            OS: 255,
        };
        self.w = Some(w);
        self.wroteHeader = false;
        self.closed = false;
        self.compressor = None;
        self.digest = 0;
        self.size = 0;
        self.err = nil;
    }

    // go: sdk 1.25.5 compress/gzip/gzip.go:93-104 Writer.writeBytes
    /// `(z *Writer).writeBytes(b)` (gzip.go:93) — writes a
    /// length-prefixed byte slice (used for the FEXTRA field).
    fn writeBytes(&mut self, b: &slice<byte>) -> error {
        if b.Len() > 0xffff {
            return errors::New("gzip.Write: Extra data is too large");
        }
        let mut lenbuf: [byte; 2] = [0; 2];
        lePutUint16(&mut lenbuf, touint16(b.Len()));
        let w = match self.w.as_mut() {
            Some(w) => w,
            None => return errors::New("gzip: writer not initialized"),
        };
        let (_, e) = w.Write(from_bytes(&lenbuf));
        if !e.IsNil() {
            return e;
        }
        let (_, e) = w.Write(b.clone());
        return e;
    }

    // go: sdk 1.25.5 compress/gzip/gzip.go:108-135 Writer.writeString
    /// `(z *Writer).writeString(s)` (gzip.go:108) — writes a UTF-8
    /// string in gzip's format: NUL-terminated ISO 8859-1 (Latin-1).
    /// Errors on non-Latin-1 code points.
    fn writeString(&mut self, s: &crate::string) -> error {
        // gzip stores Latin-1 strings; error on non-Latin-1, convert if
        // non-ASCII.
        let mut needconv = false;
        for (_, v) in crate::range!(*s) {
            if v == 0 || v > 0xff {
                return errors::New("gzip.Write: non-Latin-1 header string");
            }
            if v > 0x7f {
                needconv = true;
            }
        }
        let w = match self.w.as_mut() {
            Some(w) => w,
            None => return errors::New("gzip: writer not initialized"),
        };
        if needconv {
            let mut b: Vec<byte> = Vec::new();
            for (_, v) in crate::range!(*s) {
                b.push(tobyte(v));
            }
            let (_, e) = w.Write(slice::__from_vec(b));
            if !e.IsNil() {
                return e;
            }
        } else {
            let (_, e) = w.Write(from_bytes(s.as_bytes()));
            if !e.IsNil() {
                return e;
            }
        }
        // gzip strings are NUL-terminated.
        let (_, e) = w.Write(from_bytes(&[0]));
        return e;
    }

    // go: sdk 1.25.5 compress/gzip/gzip.go:139-198 Writer.Write
    /// `(z *Writer).Write(p)` (gzip.go:139) — writes a compressed form
    /// of `p` to the underlying writer. The compressed bytes are not
    /// necessarily flushed until the `Writer` is closed.
    pub fn Write(&mut self, p: slice<byte>) -> (int, error) {
        if !self.err.IsNil() {
            return (0, self.err.clone());
        }
        // Write the gzip header lazily.
        if !self.wroteHeader {
            self.wroteHeader = true;
            let mut head: [byte; 10] = [0; 10];
            head[0] = gzipID1;
            head[1] = gzipID2;
            head[2] = gzipDeflate;
            if self.Header.Extra.Len() > 0 {
                head[3] |= flagExtra;
            }
            if self.Header.Name.Len() > 0 {
                head[3] |= flagName;
            }
            if self.Header.Comment.Len() > 0 {
                head[3] |= flagComment;
            }
            if self.Header.ModTime.After(time::Unix(0, 0)) {
                // §2.3.1: a zero MTIME means the modified time is unset.
                lePutUint32(&mut head[4..8], touint32(self.Header.ModTime.Unix()));
            }
            if self.level == BestCompression {
                head[8] = 2;
            } else if self.level == BestSpeed {
                head[8] = 4;
            }
            head[9] = self.Header.OS;
            {
                let w = match self.w.as_mut() {
                    Some(w) => w,
                    None => {
                        self.err = errors::New("gzip: writer not initialized");
                        return (0, self.err.clone());
                    }
                };
                let (_, e) = w.Write(from_bytes(&head));
                self.err = e;
            }
            if !self.err.IsNil() {
                return (0, self.err.clone());
            }
            if self.Header.Extra.Len() > 0 {
                let extra = self.Header.Extra.clone();
                self.err = self.writeBytes(&extra);
                if !self.err.IsNil() {
                    return (0, self.err.clone());
                }
            }
            if self.Header.Name.Len() > 0 {
                let name = self.Header.Name.clone();
                self.err = self.writeString(&name);
                if !self.err.IsNil() {
                    return (0, self.err.clone());
                }
            }
            if self.Header.Comment.Len() > 0 {
                let comment = self.Header.Comment.clone();
                self.err = self.writeString(&comment);
                if !self.err.IsNil() {
                    return (0, self.err.clone());
                }
            }
            // Build the flate compressor over the destination writer.
            if self.compressor.is_none() {
                let w = match self.w.take() {
                    Some(w) => w,
                    None => {
                        self.err = errors::New("gzip: writer not initialized");
                        return (0, self.err.clone());
                    }
                };
                let (cw, _) = flate::NewWriter(w, self.level);
                self.compressor = Some(cw);
            }
        }
        self.size = self.size.wrapping_add(touint32(p.Len()));
        let tab = crc32::IEEETable();
        self.digest = crc32::Update(self.digest, &tab, p.clone());
        let (n, e) = match self.compressor.as_mut() {
            Some(cw) => cw.Write(p),
            None => (0, errors::New("gzip: writer not initialized")),
        };
        self.err = e;
        return (n, self.err.clone());
    }

    // go: sdk 1.25.5 compress/gzip/gzip.go:208-223 Writer.Flush
    /// `(z *Writer).Flush()` (gzip.go:208) — flushes any pending
    /// compressed data to the underlying writer. Equivalent to zlib's
    /// `Z_SYNC_FLUSH`.
    pub fn Flush(&mut self) -> error {
        if !self.err.IsNil() {
            return self.err.clone();
        }
        if self.closed {
            return nil;
        }
        if !self.wroteHeader {
            self.Write(slice::new());
            if !self.err.IsNil() {
                return self.err.clone();
            }
        }
        self.err = match self.compressor.as_mut() {
            Some(cw) => cw.Flush(),
            None => errors::New("gzip: writer not initialized"),
        };
        return self.err.clone();
    }

    // go: sdk 1.25.5 compress/gzip/gzip.go:228-250 Writer.Close
    /// `(z *Writer).Close()` (gzip.go:228) — flushes any unwritten data
    /// and writes the 8-byte little-endian gzip footer (CRC-32 + ISIZE).
    /// Does not close the underlying writer.
    pub fn Close(&mut self) -> error {
        if !self.err.IsNil() {
            return self.err.clone();
        }
        if self.closed {
            return nil;
        }
        self.closed = true;
        if !self.wroteHeader {
            self.Write(slice::new());
            if !self.err.IsNil() {
                return self.err.clone();
            }
        }
        // Close the flate compressor (flushes the DEFLATE payload), then
        // recover the destination writer so the trailer can be written
        // directly — Go's `z.w.Write` bypasses the compressor.
        let comp = self.compressor.take();
        let (cerr, dst) = match comp {
            Some(mut cw) => {
                let e = cw.Close();
                (e, Some(cw.into_writer()))
            }
            None => (errors::New("gzip: writer not initialized"), None),
        };
        if !cerr.IsNil() {
            self.err = cerr.clone();
            self.w = dst;
            return cerr;
        }
        let mut tbuf: [byte; 8] = [0; 8];
        lePutUint32(&mut tbuf[0..4], self.digest);
        lePutUint32(&mut tbuf[4..8], self.size);
        let mut dst = dst;
        if let Some(w) = dst.as_mut() {
            let (_, e) = w.Write(from_bytes(&tbuf));
            self.err = e;
        } else {
            self.err = errors::New("gzip: writer not initialized");
        }
        // Park the destination back on the Writer for `into_writer`.
        self.w = dst;
        return self.err.clone();
    }

    // go: none — goish idiom: a goish `Writer` owns `W` by value, so it
    //     hands it back after `Close`. Go callers keep their own
    //     reference to the destination `io.Writer`.
    /// Consume the `Writer` and return the underlying writer.
    pub fn into_writer(self) -> W {
        return match self.compressor {
            Some(cw) => cw.into_writer(),
            None => match self.w {
                Some(w) => w,
                None => panic!("gzip: Writer has no underlying writer"),
            },
        };
    }
}

impl<W: io::Writer> io::Writer for Writer<W> {
    // go: sdk 1.25.5 compress/gzip/gzip.go:139-198 Writer.Write
    fn Write(&mut self, p: slice<byte>) -> (int, error) {
        return Writer::Write(self, p);
    }
}

impl<W: io::Writer> io::Closer for Writer<W> {
    // go: sdk 1.25.5 compress/gzip/gzip.go:228-250 Writer.Close
    fn Close(&mut self) -> error {
        return Writer::Close(self);
    }
}
