// compress/zlib — zlib compressed data format (RFC 1950).
//
// Line-by-line port of Go 1.25 `/share/go/src/compress/zlib/`
// (`reader.go` + `writer.go`). zlib is a thin framing around
// `compress/flate`: a 2-byte header (CMF/FLG), an optional 4-byte
// preset-dictionary id, the raw DEFLATE payload, and a 4-byte
// big-endian Adler-32 checksum of the *uncompressed* data.
//
// Slim deviations from Go:
//   * Go's `NewReader`/`NewReaderDict` return `io.ReadCloser`; goish
//     has no trait-object ReadCloser, so they return the concrete
//     `Reader<R>` which implements `io::Reader` + `io::Closer` (and
//     carries `Reset`, mirroring Go's `Resetter` interface). The
//     `flate` port does the same.
//   * Go's `zlib.reader` keeps a `flate.Reader` handle (`z.r`) and
//     reads the Adler-32 trailer from it after the decompressor hits
//     EOF. goish's `flate::Decompressor<R>` owns its source, so the
//     zlib `Reader<R>` parses the header from a `bufio::Reader<R>`,
//     hands that to `flate::NewReader`, and reads the trailer back
//     through the decompressor's `reader_mut()` accessor — which is
//     positioned exactly at the first trailing byte once `Read` has
//     returned `io.EOF`.
//   * Go's `NewWriter` returns `*Writer` (level always valid);
//     `NewWriterLevel`/`NewWriterLevelDict` return `(*Writer, error)`.
//     goish returns `(Writer<W>, error)` by value throughout (the
//     `flate` precedent) and provides `into_writer` so callers can
//     recover the underlying writer after `Close`.
//   * Go's `Writer` is generic over an `io.Writer` interface field;
//     goish's `Writer<W>` is generic over `W: io::Writer` and wraps a
//     `flate::Writer<W>`. The optional preset dictionary makes the
//     compressed writer `flate::Writer<flate::dictWriter<W>>`, so a
//     dictless `Writer<W>` and a dict `Writer<W>` differ in their
//     inner compressor type; the public `Writer<W>` carries the
//     branch in an enum (`inner`).

#![allow(non_snake_case, non_upper_case_globals, non_camel_case_types)]

extern crate alloc;

use alloc::vec::Vec;

use crate::bufio;
use crate::compress::flate;
use crate::errors::{self, error, nil};
use crate::goslice::slice;
use crate::hash::adler32;
use crate::hash::Hash32;
use crate::io;
use crate::types::{byte, int};

// ─── header constants (reader.go:36) ───────────────────────────────────

const zlibDeflate: byte = 8;
const zlibMaxWindow: byte = 7;

// ─── error sentinels (reader.go:41, AGENTS.md §8) ──────────────────────

crate::var! {
    /// `zlib.ErrChecksum` — the data has an invalid Adler-32 checksum.
    pub ErrChecksum: error = "zlib: invalid checksum";
    /// `zlib.ErrDictionary` — the data refers to an unknown dictionary.
    pub ErrDictionary: error = "zlib: invalid dictionary";
    /// `zlib.ErrHeader` — the 2-byte zlib header is invalid.
    pub ErrHeader: error = "zlib: invalid header";
}

// ─── compression-level constants (writer.go:18) ────────────────────────
//
// Copied from `flate` so callers of `compress/zlib` need not also
// import `compress/flate`.

/// No compression — only DEFLATE+zlib framing.
pub const NoCompression: int = flate::NoCompression;
/// Fastest compression.
pub const BestSpeed: int = flate::BestSpeed;
/// Best compression ratio.
pub const BestCompression: int = flate::BestCompression;
/// The default compression level.
pub const DefaultCompression: int = flate::DefaultCompression;
/// Huffman entropy coding only — no Lempel-Ziv match search.
pub const HuffmanOnly: int = flate::HuffmanOnly;

// ─── big-endian helpers ────────────────────────────────────────────────
//
// zlib (RFC 1950) is big-endian, unlike gzip (RFC 1952).

fn beUint32(b: &[byte]) -> u32 {
    ((b[0] as u32) << 24) | ((b[1] as u32) << 16) | ((b[2] as u32) << 8) | (b[3] as u32)
}

fn bePutUint32(b: &mut [byte], v: u32) {
    b[0] = (v >> 24) as byte;
    b[1] = (v >> 16) as byte;
    b[2] = (v >> 8) as byte;
    b[3] = v as byte;
}

// ─── Reader (reader.go:50) ─────────────────────────────────────────────

/// A `Reader` decompresses zlib-format data read from an underlying
/// reader. Created by [`NewReader`] / [`NewReaderDict`]; implements
/// `io::Reader` + `io::Closer`.
pub struct Reader<FR: io::Reader + io::ByteReader> {
    // Go's `reader` keeps a separate `flate.Reader` (`z.r`); goish's
    // `flate::Decompressor` owns its source, so the trailer is read back
    // through `decompressor.reader_mut()`. `FR` is Go's `flate.Reader`
    // (io.Reader + io.ByteReader): for `NewReader` it is `bufio::Reader<R>`
    // (wrapped); for `NewReaderByte` it is the caller's source directly.
    decompressor: flate::Decompressor<FR>,
    digest: adler32::Digest,
    err: error,
    scratch: [byte; 4],
}

/// `zlib.NewReader(r)` (reader.go:74) — a new [`Reader`]. Reads from the
/// returned `Reader` read and decompress data from `r`.
///
/// Mirrors Go's `makeReader` ELSE-branch: a plain `io::Reader` is wrapped
/// in a SINGLE `bufio::Reader` (which supplies `io::ByteReader` to flate).
/// For a source that already implements `io::ByteReader`, use
/// [`NewReaderByte`] — that path uses the source directly and leaves it
/// positioned exactly at the byte past the zlib trailer.
///
/// It is the caller's responsibility to call [`Close`](Reader::Close)
/// when done. For the Adler-32 checksum to be verified the reader must
/// be fully consumed until `io.EOF`.
pub fn NewReader<R: io::Reader>(r: R) -> (Reader<bufio::Reader<R>>, error) {
    NewReaderDict(r, slice::new())
}

/// `zlib.NewReaderDict(r, dict)` (reader.go:83) — like [`NewReader`] but
/// uses a preset dictionary. The dictionary is ignored if the compressed
/// data does not refer to it; if the data refers to a *different*
/// dictionary, [`ErrDictionary`] is returned.
pub fn NewReaderDict<R: io::Reader>(r: R, dict: slice<byte>) -> (Reader<bufio::Reader<R>>, error) {
    // Wrap the source in ONE bufio reader (supplies io::ByteReader), parse
    // the zlib header from it, then hand the SAME reader to flate via the
    // ByteReader-direct path — so flate adds NO further buffering.
    let br = bufio::NewReader(r);
    new_reader_from(br, dict)
}

/// `zlib.NewReader` for a source that already implements `io::ByteReader`
/// (Go's `r.(flate.Reader)` branch). The source is used directly with no
/// `bufio` wrapping, so after the `Reader` is fully consumed the source is
/// positioned exactly at the first byte past the 4-byte Adler-32 trailer.
/// Offset-tracking consumers (e.g. git packfile scanners reading back-to-
/// back zlib streams from an in-memory `bytes::Reader`) require this.
pub fn NewReaderByte<R: io::Reader + io::ByteReader>(r: R) -> (Reader<R>, error) {
    new_reader_from(r, slice::new())
}

/// [`NewReaderByte`] with a preset dictionary.
pub fn NewReaderByteDict<R: io::Reader + io::ByteReader>(
    r: R,
    dict: slice<byte>,
) -> (Reader<R>, error) {
    new_reader_from(r, dict)
}

/// Core constructor: `fr` already implements `io::Reader + io::ByteReader`
/// (Go's `flate.Reader`). Parses the zlib header from it, then builds the
/// flate decompressor directly on it (no extra buffering).
fn new_reader_from<FR: io::Reader + io::ByteReader>(
    mut fr: FR,
    dict: slice<byte>,
) -> (Reader<FR>, error) {
    let (haveDict, herr) = readHeader(&mut fr, &dict);
    if !herr.IsNil() {
        // Build a placeholder decompressor so the struct is well-formed;
        // `err` short-circuits every Read.
        let decompressor = flate::NewReaderByte(fr);
        return (
            Reader {
                decompressor,
                digest: adler32::New(),
                err: herr.clone(),
                scratch: [0; 4],
            },
            herr,
        );
    }
    let decompressor = if haveDict {
        flate::NewReaderByteDict(fr, dict)
    } else {
        flate::NewReaderByte(fr)
    };
    (
        Reader {
            decompressor,
            digest: adler32::New(),
            err: nil,
            scratch: [0; 4],
        },
        nil,
    )
}

/// Parse the RFC 1950 §2.2 header from `r`: 2-byte CMF/FLG, plus the
/// optional 4-byte preset-dictionary Adler-32 id. Returns whether a
/// preset dictionary is in use. Faithful port of `reader.Reset`'s
/// header section (reader.go:141).
fn readHeader<R: io::Reader>(r: &mut R, dict: &slice<byte>) -> (bool, error) {
    let mut scratch: [byte; 4] = [0; 4];
    // Read the 2-byte header.
    let mut hdr = crate::make!([]byte, 2);
    let (_, e) = io::ReadFull(r, &mut hdr);
    if !e.IsNil() {
        if e == io::EOF {
            return (false, io::ErrUnexpectedEOF.into());
        }
        return (false, e);
    }
    scratch[0] = hdr[0];
    scratch[1] = hdr[1];
    let h = ((scratch[0] as u16) << 8) | (scratch[1] as u16);
    // CM must be deflate, CINFO must not exceed the max window, and the
    // 16-bit header must be a multiple of 31 (FCHECK).
    if (scratch[0] & 0x0f != zlibDeflate) || (scratch[0] >> 4 > zlibMaxWindow) || (h % 31 != 0) {
        return (false, ErrHeader.into());
    }
    let haveDict = scratch[1] & 0x20 != 0;
    if haveDict {
        let mut idbuf = crate::make!([]byte, 4);
        let (_, e) = io::ReadFull(r, &mut idbuf);
        if !e.IsNil() {
            if e == io::EOF {
                return (false, io::ErrUnexpectedEOF.into());
            }
            return (false, e);
        }
        let raw: &[byte] = &idbuf;
        let checksum = beUint32(raw);
        if checksum != adler32::Checksum(dict.clone()) {
            return (false, ErrDictionary.into());
        }
    }
    (haveDict, nil)
}

impl<FR: io::Reader + io::ByteReader> Reader<FR> {
    /// `(z *reader).Read(p)` (reader.go:92) — decompress into `p`. On the
    /// final read it consumes and verifies the 4-byte big-endian
    /// Adler-32 trailer; a mismatch yields [`ErrChecksum`].
    pub fn Read(&mut self, p: &mut slice<byte>) -> (int, error) {
        if !self.err.IsNil() {
            return (0, self.err.clone());
        }

        let (n, e) = self.decompressor.Read(p);
        self.err = e;
        // Feed the freshly decompressed bytes to the running digest.
        if n > 0 {
            let mut chunk = crate::make!([]byte, n);
            let mut i: int = 0;
            while i < n {
                chunk[i] = p[i];
                i += 1;
            }
            io::Writer::Write(&mut self.digest, chunk);
        }
        if self.err != io::EOF {
            // Normal case.
            return (n, self.err.clone());
        }

        // Finished payload; read and check the Adler-32 trailer from the
        // decompressor's buffered source.
        let mut tbuf = crate::make!([]byte, 4);
        let (_, terr) = io::ReadFull(self.decompressor.reader_mut(), &mut tbuf);
        if !terr.IsNil() {
            self.err = if terr == io::EOF {
                io::ErrUnexpectedEOF.into()
            } else {
                terr
            };
            return (n, self.err.clone());
        }
        self.scratch[0] = tbuf[0];
        self.scratch[1] = tbuf[1];
        self.scratch[2] = tbuf[2];
        self.scratch[3] = tbuf[3];
        let checksum = beUint32(&self.scratch);
        if checksum != self.digest.Sum32() {
            self.err = ErrChecksum.into();
            return (n, self.err.clone());
        }
        (n, io::EOF.into())
    }

    /// `(z *reader).Close()` (reader.go:125) — closes the `Reader`. Does
    /// not close the underlying reader passed to [`NewReader`].
    pub fn Close(&mut self) -> error {
        if !self.err.IsNil() && self.err != io::EOF {
            return self.err.clone();
        }
        self.err = self.decompressor.Close();
        self.err.clone()
    }

    /// `(z *reader).Reset(r, dict)` (reader.go:133) — Go's `Resetter`.
    /// Discards buffered state and reinitializes the `Reader` for a new
    /// source `r`, re-parsing the zlib header.
    pub fn Reset(&mut self, mut r: FR, dict: slice<byte>) -> error {
        // `FR` is already Go's `flate.Reader`; parse the header from it and
        // hand it straight to the flate decompressor (no re-wrapping).
        let (_, herr) = readHeader(&mut r, &dict);
        if !herr.IsNil() {
            self.err = herr.clone();
            // Keep the decompressor consistent with the new source.
            self.decompressor.Reset(r, slice::new());
            self.digest = adler32::New();
            return herr;
        }
        self.err = self.decompressor.Reset(r, dict);
        self.digest = adler32::New();
        self.scratch = [0; 4];
        self.err.clone()
    }
}

impl<FR: io::Reader + io::ByteReader> io::Reader for Reader<FR> {
    fn Read(&mut self, p: &mut slice<byte>) -> (int, error) {
        Reader::Read(self, p)
    }
}

impl<FR: io::Reader + io::ByteReader> io::Closer for Reader<FR> {
    fn Close(&mut self) -> error {
        Reader::Close(self)
    }
}

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
    digest: adler32::Digest,
    err: error,
    wroteHeader: bool,
}

/// `zlib.NewWriter(w)` (writer.go:44) — a new [`Writer`] at
/// [`DefaultCompression`]. Writes are compressed and written to `w`.
///
/// It is the caller's responsibility to call [`Close`](Writer::Close).
pub fn NewWriter<W: io::Writer>(w: W) -> Writer<W> {
    let (z, _) = NewWriterLevelDict(w, DefaultCompression, slice::new());
    z
}

/// `zlib.NewWriterLevel(w, level)` (writer.go:55) — like [`NewWriter`]
/// but with an explicit compression level. The level may be
/// [`DefaultCompression`], [`NoCompression`], [`HuffmanOnly`], or any
/// integer in `[BestSpeed, BestCompression]`. The error is `nil` iff the
/// level is valid.
pub fn NewWriterLevel<W: io::Writer>(w: W, level: int) -> (Writer<W>, error) {
    NewWriterLevelDict(w, level, slice::new())
}

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
    (z, nil)
}

impl<W: io::Writer> Writer<W> {
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
        let pre = ((scratch[0] as u16) << 8) | (scratch[1] as u16);
        scratch[1] = scratch[1].wrapping_add((31 - pre % 31) as byte);

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
        nil
    }

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
        (n, nil)
    }

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
        self.err.clone()
    }

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
        self.err.clone()
    }

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

    /// Consume the `Writer` and return the underlying writer.
    ///
    /// goish-specific: a goish `Writer` *owns* `W` by value, so this
    /// hands it back after [`Close`](Self::Close). Mirrors
    /// `flate::Writer::into_writer`.
    pub fn into_writer(self) -> W {
        match self.compressor {
            Some(inner::plain(cw)) => cw.into_writer(),
            Some(inner::dict(cw)) => cw.into_writer().into_writer(),
            None => match self.w {
                Some(w) => w,
                None => panic!("zlib: Writer has no underlying writer"),
            },
        }
    }
}

impl<W: io::Writer> io::Writer for Writer<W> {
    fn Write(&mut self, p: slice<byte>) -> (int, error) {
        Writer::Write(self, p)
    }
}

impl<W: io::Writer> io::Closer for Writer<W> {
    fn Close(&mut self) -> error {
        Writer::Close(self)
    }
}

// ─── helpers ───────────────────────────────────────────────────────────

/// Build a goish `slice<byte>` from a borrowed Rust byte slice.
fn from_bytes(b: &[byte]) -> slice<byte> {
    let mut v: Vec<byte> = Vec::with_capacity(b.len());
    v.extend_from_slice(b);
    slice::__from_vec(v)
}
