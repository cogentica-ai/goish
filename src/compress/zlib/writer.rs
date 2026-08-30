// go: file compress/zlib/writer.go decls: NewWriter, NewWriterLevel, NewWriterLevelDict, Writer.Reset, Writer.writeHeader, Writer.Write, Writer.Flush, Writer.Close
//
// The `decls:` manifest above lists writer.go's funcs and methods only.
// GOISH017 matches a manifest entry against Rust `fn` items, so naming
// the `Writer` type there would report it as a dropped port. It is not
// dropped - it carries its own `// go: sdk` anchor below.
//
// compress/zlib/writer.go - the zlib (RFC 1950) writer.
//
// The header is written lazily, on the first `Write` or `Flush`. That
// is what lets `Reset` change the destination after construction and
// still emit a correct header, and it is why `wroteHeader` exists.
// `writeHeader` also derives the two "compression level" bits from the
// flate level and, when a preset dictionary is in use, appends its
// Adler-32 and seeds the flate writer with it.

#![allow(non_snake_case, non_camel_case_types, non_upper_case_globals)]

extern crate alloc;
use alloc::vec::Vec;

use crate::compress::flate;
use crate::convert::{byte as tobyte, uint16 as touint16};
use crate::errors::{self, error, nil};
use crate::goslice::slice;
use crate::hash::adler32;
use crate::hash::Hash32;
use crate::io;
use crate::types::{byte, int};

use super::reader::bePutUint32;

// ─── Writer (writer.go:28) ─────────────────────────────────────────────

// The inner compressor differs depending on whether a preset dictionary
// is used: `flate::NewWriter` yields `flate::Writer<W>`, but
// `flate::NewWriterDict` yields `flate::Writer<flate::dictWriter<W>>`.
// This enum lets the public `Writer<W>` carry either.
enum inner<W: io::Writer> {
    plain(flate::Writer<W>),
    dict(flate::Writer<flate::dictWriter<W>>),
}

/// A `Writer` takes data written to it and writes the zlib-compressed
/// form of that data to an underlying writer. Created by [`NewWriter`] /
/// [`NewWriterLevel`] / [`NewWriterLevelDict`]; implements `io::Writer` +
/// `io::Closer`.
pub struct Writer<W: io::Writer> {
    // `compressor` is None until the header is written (first Write /
    // Flush / Close), then holds the flate writer.
    compressor: Option<inner<W>>,
    // The destination, parked here until `writeHeader` builds the flate
    // writer and moves it in.
    w: Option<W>,
    level: int,
    dict: Vec<byte>,
    digest: adler32::digest,
    err: error,
    wroteHeader: bool,
}

// go: sdk 1.25.5 compress/zlib/writer.go:18-25 NoCompression
/// `zlib.NoCompression` — only DEFLATE+zlib framing. Re-exported from
/// `flate` so callers need not also import `compress/flate`.
pub const NoCompression: int = flate::NoCompression;
// go: sdk 1.25.5 compress/zlib/writer.go:18-25 BestSpeed
/// `zlib.BestSpeed` — fastest compression.
pub const BestSpeed: int = flate::BestSpeed;
// go: sdk 1.25.5 compress/zlib/writer.go:18-25 BestCompression
/// `zlib.BestCompression` — best compression ratio.
pub const BestCompression: int = flate::BestCompression;
// go: sdk 1.25.5 compress/zlib/writer.go:18-25 DefaultCompression
/// `zlib.DefaultCompression` — the default level.
pub const DefaultCompression: int = flate::DefaultCompression;
// go: sdk 1.25.5 compress/zlib/writer.go:18-25 HuffmanOnly
/// `zlib.HuffmanOnly` — Huffman entropy coding only, no Lempel-Ziv
/// match search.
pub const HuffmanOnly: int = flate::HuffmanOnly;

// go: sdk 1.25.5 compress/zlib/writer.go:44-47 NewWriter
/// `zlib.NewWriter(w)` (writer.go:44) — a new [`Writer`] at
/// [`DefaultCompression`]. Writes are compressed and written to `w`.
///
/// It is the caller's responsibility to call [`Close`](Writer::Close).
pub fn NewWriter<W: io::Writer>(w: W) -> Writer<W> {
    let (z, _) = NewWriterLevelDict(w, DefaultCompression, slice::new());
    return z;
}

// go: sdk 1.25.5 compress/zlib/writer.go:55-57 NewWriterLevel
/// `zlib.NewWriterLevel(w, level)` (writer.go:55) — like [`NewWriter`]
/// but with an explicit compression level. The level may be
/// [`DefaultCompression`], [`NoCompression`], [`HuffmanOnly`], or any
/// integer in `[BestSpeed, BestCompression]`. The error is `nil` iff the
/// level is valid.
pub fn NewWriterLevel<W: io::Writer>(w: W, level: int) -> (Writer<W>, error) {
    return NewWriterLevelDict(w, level, slice::new());
}

// go: sdk 1.25.5 compress/zlib/writer.go:64-73 NewWriterLevelDict
/// `zlib.NewWriterLevelDict(w, level, dict)` (writer.go:64) — like
/// [`NewWriterLevel`] but with a preset dictionary. `dict` may be empty.
pub fn NewWriterLevelDict<W: io::Writer>(
    w: W,
    level: int,
    dict: slice<byte>,
) -> (Writer<W>, error) {
    let mut dictv: Vec<byte> = Vec::new();
    {
        let raw: &[byte] = &dict;
        dictv.extend_from_slice(raw);
    }
    let z = Writer {
        compressor: None,
        w: Some(w),
        level,
        dict: dictv,
        digest: adler32::New(),
        err: nil,
        wroteHeader: false,
    };
    if level < HuffmanOnly || level > BestCompression {
        return (
            z,
            crate::fmt::Errorf!("zlib: invalid compression level: %d", level),
        );
    }
    return (z, nil);
}

impl<W: io::Writer> Writer<W> {
    // go: sdk 1.25.5 compress/zlib/writer.go:93-139 Writer.writeHeader
    /// `(z *Writer).writeHeader()` (writer.go:93) — writes the 2-byte
    /// zlib header (CMF/FLG) plus the optional 4-byte dictionary id, then
    /// builds the inner flate writer.
    fn writeHeader(&mut self) -> error {
        self.wroteHeader = true;
        let mut scratch: [byte; 4] = [0; 4];
        // CMF: CINFO=7 (32 KiB window) in the high nibble, CM=8 (deflate)
        // in the low nibble — 0x78.
        scratch[0] = 0x78;
        // FLG: top two bits are FLEVEL (0=fastest .. 3=best).
        match self.level {
            -2 | 0 | 1 => scratch[1] = 0 << 6,
            2 | 3 | 4 | 5 => scratch[1] = 1 << 6,
            6 | -1 => scratch[1] = 2 << 6,
            7 | 8 | 9 => scratch[1] = 3 << 6,
            _ => panic!("unreachable"),
        }
        let haveDict = !self.dict.is_empty();
        if haveDict {
            scratch[1] |= 1 << 5; // FDICT
        }
        // FCHECK: low five bits make the 16-bit header a multiple of 31.
        let pre = (touint16(scratch[0]) << 8) | touint16(scratch[1]);
        scratch[1] = scratch[1].wrapping_add(tobyte(31 - pre % 31));

        // Take the destination writer back so we can write the header
        // directly, then move it into the flate writer.
        let mut w = match self.w.take() {
            Some(w) => w,
            None => return errors::New("zlib: writer already initialized"),
        };
        let hdr = from_bytes(&scratch[0..2]);
        let (_, e) = w.Write(hdr);
        if !e.IsNil() {
            self.w = Some(w);
            return e;
        }
        if haveDict {
            // The dictionary id: 4-byte big-endian Adler-32 of the dict.
            let mut idbuf: [byte; 4] = [0; 4];
            bePutUint32(&mut idbuf, adler32::Checksum(from_bytes(&self.dict)));
            let (_, e) = w.Write(from_bytes(&idbuf));
            if !e.IsNil() {
                self.w = Some(w);
                return e;
            }
        }

        // Build the flate compressor.
        if haveDict {
            let dict = from_bytes(&self.dict);
            let (cw, ce) = flate::NewWriterDict(w, self.level, dict);
            if !ce.IsNil() {
                return ce;
            }
            self.compressor = Some(inner::dict(cw));
        } else {
            let (cw, ce) = flate::NewWriter(w, self.level);
            if !ce.IsNil() {
                return ce;
            }
            self.compressor = Some(inner::plain(cw));
        }
        return nil;
    }

    // go: sdk 1.25.5 compress/zlib/writer.go:144-161 Writer.Write
    /// `(z *Writer).Write(p)` (writer.go:144) — writes a compressed form
    /// of `p` to the underlying writer. Output is not necessarily flushed
    /// until the `Writer` is closed or explicitly flushed.
    pub fn Write(&mut self, p: slice<byte>) -> (int, error) {
        if !self.wroteHeader {
            self.err = self.writeHeader();
        }
        if !self.err.IsNil() {
            return (0, self.err.clone());
        }
        if p.Len() == 0 {
            return (0, nil);
        }
        let (n, e) = match self.compressor.as_mut() {
            Some(inner::plain(cw)) => cw.Write(p.clone()),
            Some(inner::dict(cw)) => cw.Write(p.clone()),
            None => (0, errors::New("zlib: writer not initialized")),
        };
        if !e.IsNil() {
            self.err = e.clone();
            return (n, e);
        }
        io::Writer::Write(&mut self.digest, p);
        return (n, nil);
    }

    // go: sdk 1.25.5 compress/zlib/writer.go:164-173 Writer.Flush
    /// `(z *Writer).Flush()` (writer.go:164) — flushes the `Writer` to
    /// its underlying writer.
    pub fn Flush(&mut self) -> error {
        if !self.wroteHeader {
            self.err = self.writeHeader();
        }
        if !self.err.IsNil() {
            return self.err.clone();
        }
        self.err = match self.compressor.as_mut() {
            Some(inner::plain(cw)) => cw.Flush(),
            Some(inner::dict(cw)) => cw.Flush(),
            None => errors::New("zlib: writer not initialized"),
        };
        return self.err.clone();
    }

    // go: sdk 1.25.5 compress/zlib/writer.go:177-193 Writer.Close
    /// `(z *Writer).Close()` (writer.go:177) — flushes any unwritten data
    /// and writes the 4-byte big-endian Adler-32 trailer. Does not close
    /// the underlying writer.
    pub fn Close(&mut self) -> error {
        if !self.wroteHeader {
            self.err = self.writeHeader();
        }
        if !self.err.IsNil() {
            return self.err.clone();
        }
        // Close the flate compressor (flushes the DEFLATE payload), then
        // recover the destination writer so the trailer can be written
        // directly — Go's `z.w.Write` bypasses the compressor.
        let comp = self.compressor.take();
        let close_res: (error, Option<W>) = match comp {
            Some(inner::plain(mut cw)) => {
                let e = cw.Close();
                (e, Some(cw.into_writer()))
            }
            Some(inner::dict(mut cw)) => {
                let e = cw.Close();
                (e, Some(cw.into_writer().into_writer()))
            }
            None => (errors::New("zlib: writer not initialized"), None),
        };
        let (cerr, mut dst) = close_res;
        if !cerr.IsNil() {
            self.err = cerr.clone();
            self.w = dst;
            return cerr;
        }
        // Write the Adler-32 checksum, big-endian (RFC 1950).
        let checksum = self.digest.Sum32();
        let mut scratch: [byte; 4] = [0; 4];
        bePutUint32(&mut scratch, checksum);
        if let Some(w) = dst.as_mut() {
            let (_, e) = w.Write(from_bytes(&scratch));
            self.err = e;
        } else {
            self.err = errors::New("zlib: writer not initialized");
        }
        // Park the destination back on the Writer for `into_writer`.
        self.w = dst;
        return self.err.clone();
    }

    // go: sdk 1.25.5 compress/zlib/writer.go:78-90 Writer.Reset
    /// `(z *Writer).Reset(w)` (writer.go:78) — clears the `Writer`'s
    /// state so it is equivalent to a fresh [`NewWriterLevel`] /
    /// [`NewWriterLevelDict`] targeting `w`, keeping the level and
    /// dictionary unchanged.
    pub fn Reset(&mut self, w: W) {
        self.compressor = None;
        self.w = Some(w);
        self.digest = adler32::New();
        self.err = nil;
        self.wroteHeader = false;
    }

    // go: none — goish idiom: a goish `Writer` owns `W` by value, so it
    //     has to hand it back after `Close`. Go callers keep their own
    //     reference to the destination `io.Writer`.
    /// Consume the `Writer` and return the underlying writer.
    pub fn into_writer(self) -> W {
        return match self.compressor {
            Some(inner::plain(cw)) => cw.into_writer(),
            Some(inner::dict(cw)) => cw.into_writer().into_writer(),
            None => match self.w {
                Some(w) => w,
                None => panic!("zlib: Writer has no underlying writer"),
            },
        };
    }
}

impl<W: io::Writer> io::Writer for Writer<W> {
    // go: sdk 1.25.5 compress/zlib/writer.go:144-161 Writer.Write
    fn Write(&mut self, p: slice<byte>) -> (int, error) {
        return Writer::Write(self, p);
    }
}

impl<W: io::Writer> io::Closer for Writer<W> {
    // go: sdk 1.25.5 compress/zlib/writer.go:177-193 Writer.Close
    fn Close(&mut self) -> error {
        return Writer::Close(self);
    }
}

// ─── helpers ───────────────────────────────────────────────────────────

// go: none — goish idiom: a goish `slice<byte>` owns its buffer, so a
//     borrowed `&[byte]` has to be copied into one at the boundary.
/// Build a goish `slice<byte>` from a borrowed Rust byte slice.
fn from_bytes(b: &[byte]) -> slice<byte> {
    let mut v: Vec<byte> = Vec::with_capacity(b.len());
    v.extend_from_slice(b);
    return slice::__from_vec(v);
}
