// go: file compress/zlib/reader.go decls: NewReader, NewReaderDict, reader.Read, reader.Close, reader.Reset
//
// goishlint:ignore GOISH021 Resetter — Go's `zlib.Resetter` is a
//     one-method interface used only to type-assert the value
//     `NewReader` returns as an `io.ReadCloser`. goish returns the
//     concrete `Reader<FR>`, which carries `Reset` inherently, so there
//     is nothing nominal left to declare.
//
// The `decls:` manifest above lists reader.go's funcs and methods only.
// GOISH017 matches a manifest entry against Rust `fn` items, so naming
// the file's consts, types and error vars there would report them as
// dropped ports. They are not dropped — each carries its own
// `// go: sdk` anchor below.
//
// compress/zlib/reader.go - the zlib (RFC 1950) reader.
//
// zlib is a two-byte header and a four-byte Adler-32 trailer around a
// raw DEFLATE stream, and almost all of this file is those six bytes.
// The header check is stricter than it looks: the low nibble of the
// first byte must be 8 (deflate), the window size must not exceed
// 32 KiB, the two bytes together must be a multiple of 31, and if the
// dictionary bit is set the caller's dictionary must match the
// Adler-32 the header names. Each of those has its own sentinel error,
// and `Read` cannot report the trailer's checksum error until the
// DEFLATE stream itself has reported EOF.
//
// Deviations from Go:
//
//   * Go's `NewReader` returns `io.ReadCloser`; goish returns the
//     concrete `Reader<FR>`, since there is no trait-object ReadCloser.
//   * `Reader` is generic over its source so it can pass the exact
//     `flate.Reader` bound down to `compress/flate`, which is how
//     `NewReaderByte` leaves the source positioned at the byte after
//     the stream (see zlib_offset_smoke).

#![allow(non_snake_case, non_camel_case_types, non_upper_case_globals)]

extern crate alloc;

use crate::bufio;
use crate::compress::flate;
use crate::convert::{byte as tobyte, uint16 as touint16, uint32 as touint32};
use crate::errors::{error, nil};
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

// ─── big-endian helpers ────────────────────────────────────────────────
//
// zlib (RFC 1950) is big-endian, unlike gzip (RFC 1952).

// go: none — goish idiom: Go reads the trailer with
//     `binary.BigEndian.Uint32`; goish's encoding/binary takes a
//     `slice<byte>`, and this is a borrowed scratch array.
pub(super) fn beUint32(b: &[byte]) -> u32 {
    return (touint32(b[0]) << 24)
        | (touint32(b[1]) << 16)
        | (touint32(b[2]) << 8)
        | touint32(b[3]);
}

// go: none — goish idiom: the write half of `beUint32`.
pub(super) fn bePutUint32(b: &mut [byte], v: u32) {
    b[0] = tobyte(v >> 24);
    b[1] = tobyte(v >> 16);
    b[2] = tobyte(v >> 8);
    b[3] = tobyte(v);
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
    digest: adler32::digest,
    err: error,
    scratch: [byte; 4],
}

// go: sdk 1.25.5 compress/zlib/reader.go:74-76 NewReader
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
    return NewReaderDict(r, slice::new());
}

// go: sdk 1.25.5 compress/zlib/reader.go:83-90 NewReaderDict
/// `zlib.NewReaderDict(r, dict)` (reader.go:83) — like [`NewReader`] but
/// uses a preset dictionary. The dictionary is ignored if the compressed
/// data does not refer to it; if the data refers to a *different*
/// dictionary, [`ErrDictionary`] is returned.
pub fn NewReaderDict<R: io::Reader>(r: R, dict: slice<byte>) -> (Reader<bufio::Reader<R>>, error) {
    // Wrap the source in ONE bufio reader (supplies io::ByteReader), parse
    // the zlib header from it, then hand the SAME reader to flate via the
    // ByteReader-direct path — so flate adds NO further buffering.
    let br = bufio::NewReader(r);
    return new_reader_from(br, dict);
}

// go: none — goish idiom: the `r.(flate.Reader)` branch of Go's
//     `NewReader`, chosen at compile time by calling this constructor.
//     Go decides it at run time inside `flate.makeReader`.
/// `zlib.NewReader` for a source that already implements `io::ByteReader`
/// (Go's `r.(flate.Reader)` branch). The source is used directly with no
/// `bufio` wrapping, so after the `Reader` is fully consumed the source is
/// positioned exactly at the first byte past the 4-byte Adler-32 trailer.
/// Offset-tracking consumers (e.g. git packfile scanners reading back-to-
/// back zlib streams from an in-memory `bytes::Reader`) require this.
pub fn NewReaderByte<R: io::Reader + io::ByteReader>(r: R) -> (Reader<R>, error) {
    return new_reader_from(r, slice::new());
}

// go: none — goish idiom: the dictionary form of `NewReaderByte`.
/// [`NewReaderByte`] with a preset dictionary.
pub fn NewReaderByteDict<R: io::Reader + io::ByteReader>(
    r: R,
    dict: slice<byte>,
) -> (Reader<R>, error) {
    return new_reader_from(r, dict);
}

// go: none — goish idiom: the shared body of the four `NewReader*`
//     constructors, over a source that already satisfies
//     `flate.Reader`.
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
    return (
        Reader {
            decompressor,
            digest: adler32::New(),
            err: nil,
            scratch: [0; 4],
        },
        nil,
    );
}

// go: none — goish idiom: the header half of Go's `reader.Reset`,
//     split out because goish parses it before building the
//     `Reader`, where Go mutates a `reader` that already exists.
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
    let h = (touint16(scratch[0]) << 8) | touint16(scratch[1]);
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
    return (haveDict, nil);
}

impl<FR: io::Reader + io::ByteReader> Reader<FR> {
    // go: sdk 1.25.5 compress/zlib/reader.go:92-120 Read
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
        return (n, io::EOF.into());
    }

    // go: sdk 1.25.5 compress/zlib/reader.go:125-131 Close
    /// `(z *reader).Close()` (reader.go:125) — closes the `Reader`. Does
    /// not close the underlying reader passed to [`NewReader`].
    pub fn Close(&mut self) -> error {
        if !self.err.IsNil() && self.err != io::EOF {
            return self.err.clone();
        }
        self.err = self.decompressor.Close();
        return self.err.clone();
    }

    // go: sdk 1.25.5 compress/zlib/reader.go:133-181 Reset
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
        return self.err.clone();
    }
}

impl<FR: io::Reader + io::ByteReader> io::Reader for Reader<FR> {
    // go: sdk 1.25.5 compress/zlib/reader.go:92-120 Read
    fn Read(&mut self, p: &mut slice<byte>) -> (int, error) {
        return Reader::Read(self, p);
    }
}

impl<FR: io::Reader + io::ByteReader> io::Closer for Reader<FR> {
    // go: sdk 1.25.5 compress/zlib/reader.go:125-131 Close
    fn Close(&mut self) -> error {
        return Reader::Close(self);
    }
}
