// go: file compress/gzip/gunzip.go decls: noEOF, NewReader, Reader.Reset, Reader.Multistream, Reader.readString, Reader.readHeader, Reader.Read, Reader.Close
//
// goishlint:ignore GOISH021 le — Go keeps a package-level
//     `le = binary.LittleEndian` and calls methods on it. goish's
//     encoding/binary takes a `slice<byte>`, and the framing here is
//     read out of borrowed scratch arrays, so the four `le*` helpers
//     below stand in for it.
//
// The `decls:` manifest above lists gunzip.go's funcs and methods only.
// GOISH017 matches a manifest entry against Rust `fn` items, so naming
// the file's consts, types and error vars there would report them as
// dropped ports. They are not dropped - each carries its own
// `// go: sdk` anchor below.
//
// compress/gzip/gunzip.go - the gzip (RFC 1952) reader.
//
// gzip is a ten-byte header, optional extra/name/comment fields, a raw
// DEFLATE stream, and an eight-byte trailer of CRC-32 and length mod
// 2^32. Almost all of this file is those framing bytes.
//
// Two details are load-bearing and easy to lose. `Multistream` decides
// whether the reader continues into a second concatenated member after
// the first one's trailer, which is why `Read` loops back to
// `readHeader` instead of returning EOF. And the length in the trailer
// is only the low 32 bits, so it is compared modulo 2^32 rather than
// against the true byte count.

#![allow(non_snake_case, non_camel_case_types, non_upper_case_globals)]

extern crate alloc;
use alloc::vec::Vec;

use crate::bufio;
use crate::compress::flate;
use crate::convert::{
    byte as tobyte, int as toint, rune as torune, uint16 as touint16, uint32 as touint32,
};
use crate::errors::{self, error, nil};
use crate::goslice::slice;
use crate::hash::crc32;
use crate::io;
use crate::time;
use crate::types::{byte, int, rune};

// ─── header constants (gzip.go:19) ─────────────────────────────────────

pub(super) const gzipID1: byte = 0x1f;
pub(super) const gzipID2: byte = 0x8b;
pub(super) const gzipDeflate: byte = 8;
/// `flagText` (gzip.go:23) — RFC 1952 FTEXT bit. Defined for fidelity
/// to Go's flag-constant block; not consulted by the reader or writer.
#[allow(dead_code)]
pub(super) const flagText: byte = 1 << 0;
pub(super) const flagHdrCrc: byte = 1 << 1;
pub(super) const flagExtra: byte = 1 << 2;
pub(super) const flagName: byte = 1 << 3;
pub(super) const flagComment: byte = 1 << 4;

// ─── error sentinels (gunzip.go:30-35, AGENTS.md §8) ───────────────────

crate::var! {
    /// `gzip.ErrChecksum` — the gzip data has an invalid checksum.
    pub ErrChecksum: error = "gzip: invalid checksum";
    /// `gzip.ErrHeader` — the gzip data has an invalid header.
    pub ErrHeader: error = "gzip: invalid header";
}

// ─── little-endian helpers ─────────────────────────────────────────────
//
// gzip (RFC 1952) is little-endian, unlike zlib (RFC 1950). Go uses
// `binary.LittleEndian`; a tiny local helper keeps the byte layout
// explicit and avoids `AsRef`/`AsMut` ceremony around fixed buffers.

// go: none — goish idiom: Go reads the framing with a package-level
//     `le = binary.LittleEndian`; goish's encoding/binary takes a
//     `slice<byte>`, and these are borrowed scratch arrays.
pub(super) fn leUint16(b: &[byte]) -> u16 {
    return touint16(b[0]) | (touint16(b[1]) << 8);
}

// go: none — goish idiom: see `leUint16`.
pub(super) fn leUint32(b: &[byte]) -> u32 {
    return touint32(b[0])
        | (touint32(b[1]) << 8)
        | (touint32(b[2]) << 16)
        | (touint32(b[3]) << 24);
}

// go: none — goish idiom: see `leUint16`.
pub(super) fn lePutUint16(b: &mut [byte], v: u16) {
    b[0] = tobyte(v);
    b[1] = tobyte(v >> 8);
}

// go: none — goish idiom: see `leUint16`.
pub(super) fn lePutUint32(b: &mut [byte], v: u32) {
    b[0] = tobyte(v);
    b[1] = tobyte(v >> 8);
    b[2] = tobyte(v >> 16);
    b[3] = tobyte(v >> 24);
}

// go: none — goish idiom: a goish `slice<byte>` owns its buffer, so
//     a borrowed `&[byte]` is copied into one at the boundary.
/// Build a goish `slice<byte>` from a borrowed Rust byte slice.
pub(super) fn from_bytes(b: &[byte]) -> slice<byte> {
    let mut v: Vec<byte> = Vec::with_capacity(b.len());
    v.extend_from_slice(b);
    return slice::__from_vec(v);
}

// go: sdk 1.25.5 compress/gzip/gunzip.go:40-45 noEOF
/// `noEOF` (gunzip.go:40) — converts `io.EOF` to `io.ErrUnexpectedEOF`.
pub(super) fn noEOF(err: error) -> error {
    if err == io::EOF {
        return io::ErrUnexpectedEOF.into();
    }
    return err;
}

// ─── Header (gunzip.go:52) ─────────────────────────────────────────────

/// The gzip file stores a header giving metadata about the compressed
/// file. That header is exposed as the [`Header`] field of the
/// [`Writer`] and [`Reader`] structs.
///
/// Strings must be UTF-8 encoded and may only contain Unicode code
/// points U+0001 through U+00FF, due to limitations of the gzip file
/// format.
#[derive(Clone, Default)]
pub struct Header {
    /// Comment.
    pub Comment: crate::string,
    /// "Extra data".
    pub Extra: slice<byte>,
    /// Modification time.
    pub ModTime: time::Time,
    /// File name.
    pub Name: crate::string,
    /// Operating-system type.
    pub OS: byte,
}

// ─── Reader (gunzip.go:74) ─────────────────────────────────────────────

/// A `Reader` is an `io::Reader` that can be read to retrieve
/// uncompressed data from a gzip-format compressed file.
///
/// In general, a gzip file can be a concatenation of gzip files, each
/// with its own header. Reads from the `Reader` return the
/// concatenation of the uncompressed data of each. Only the first
/// header is recorded in the [`Header`] field.
///
/// gzip files store a length and checksum of the uncompressed data.
/// The `Reader` returns [`ErrChecksum`] when [`Read`](Reader::Read)
/// reaches the end of the uncompressed data if it does not have the
/// expected length or checksum.
pub struct Reader<R: io::Reader> {
    /// The first gzip member's header — valid after [`NewReader`] /
    /// [`Reset`](Reader::Reset).
    pub Header: Header,
    // Go keeps `r flate.Reader` separate from `decompressor`; goish's
    // `flate::Decompressor` owns its buffered source, so the
    // decompressor lives in an `Option` and is taken out (via
    // `into_reader`) when a multistream re-init needs the bare source.
    decompressor: Option<flate::Decompressor<bufio::Reader<R>>>,
    digest: u32, // CRC-32, IEEE polynomial (section 8)
    size: u32,   // uncompressed size (section 2.3.1)
    buf: [byte; 512],
    err: error,
    multistream: bool,
}

// go: sdk 1.25.5 compress/gzip/gunzip.go:92-98 NewReader
/// `gzip.NewReader(r)` (gunzip.go:92) — a new [`Reader`] reading the
/// given reader.
///
/// It is the caller's responsibility to call [`Close`](Reader::Close)
/// when done. The [`Header`] fields are valid in the returned `Reader`.
pub fn NewReader<R: io::Reader>(r: R) -> (Reader<R>, error) {
    let mut z = Reader {
        Header: Header::default(),
        decompressor: None,
        digest: 0,
        size: 0,
        buf: [0; 512],
        err: nil,
        multistream: true,
    };
    let e = z.Reset(r);
    if !e.IsNil() {
        return (z, e);
    }
    return (z, nil);
}

impl<R: io::Reader> Reader<R> {
    // go: sdk 1.25.5 compress/gzip/gunzip.go:103-115 Reader.Reset
    /// `(z *Reader).Reset(r)` (gunzip.go:103) — discards the `Reader`'s
    /// state and makes it equivalent to a fresh [`NewReader`] reading
    /// from `r` instead. Permits reusing a `Reader`.
    pub fn Reset(&mut self, r: R) -> error {
        self.Header = Header::default();
        self.digest = 0;
        self.size = 0;
        self.buf = [0; 512];
        self.err = nil;
        self.multistream = true;
        // Park the source in a fresh decompressor so the struct is
        // well-formed; `readHeader` re-builds it onto the parsed source.
        self.decompressor = Some(flate::NewReader(r));
        let (hdr, e) = self.readHeader();
        self.Header = hdr;
        self.err = e;
        return self.err.clone();
    }

    // go: sdk 1.25.5 compress/gzip/gunzip.go:133-135 Reader.Multistream
    /// `(z *Reader).Multistream(ok)` (gunzip.go:133) — controls whether
    /// the reader supports multistream files.
    ///
    /// If enabled (the default), the `Reader` expects the input to be a
    /// sequence of individually gzipped streams, each with its own
    /// header and trailer, ending at EOF; the concatenation of gzipped
    /// files reads as the gzip of the concatenation. Disabling makes
    /// [`Read`](Reader::Read) return `io.EOF` at the first member's end.
    pub fn Multistream(&mut self, ok: bool) {
        self.multistream = ok;
    }

    // go: sdk 1.25.5 compress/gzip/gunzip.go:141-170 Reader.readString
    // goishlint:ignore GOISH023 - Go's `for { … return … }`; the Rust
    //     `loop` below never breaks, so every exit is already an
    //     explicit `return`.
    /// `(z *Reader).readString()` (gunzip.go:141) — reads a
    /// NUL-terminated string from the source. The bytes are treated as
    /// ISO 8859-1 (Latin-1) and the result is UTF-8. Always updates
    /// `digest` with the data read (including the NUL terminator).
    fn readString(&mut self) -> (crate::string, error) {
        let mut needConv = false;
        let mut i: usize = 0;
        loop {
            if i >= self.buf.len() {
                return (crate::string::new(), ErrHeader.into());
            }
            let (b, err) = self.source_mut().ReadByte();
            if !err.IsNil() {
                return (crate::string::new(), err);
            }
            self.buf[i] = b;
            if self.buf[i] > 0x7f {
                needConv = true;
            }
            if self.buf[i] == 0 {
                // Digest covers the NUL terminator.
                let tab = crc32::IEEETable();
                self.digest = crc32::Update(self.digest, &tab, from_bytes(&self.buf[..i + 1]));
                // Strings are ISO 8859-1, Latin-1 (RFC 1952, §2.3.1).
                if needConv {
                    let mut s = crate::string::new();
                    for j in 0..i {
                        let r: rune = torune(self.buf[j]);
                        s = s + crate::string::from_rune(r);
                    }
                    return (s, nil);
                }
                return (crate::string::from_bytes(&self.buf[..i]), nil);
            }
            i += 1;
        }
    }

    // go: sdk 1.25.5 compress/gzip/gunzip.go:174-243 Reader.readHeader
    /// `(z *Reader).readHeader()` (gunzip.go:174) — reads the gzip
    /// header (RFC 1952 §2.3.1). Does not set `self.err`.
    fn readHeader(&mut self) -> (Header, error) {
        let mut hdr = Header::default();
        let mut head: [byte; 10] = [0; 10];
        {
            let mut tmp = from_bytes(&head);
            let (_, e) = io::ReadFull(self.source_mut(), &mut tmp);
            if !e.IsNil() {
                // RFC 1952 §2.2: a "series" of members may be empty, so
                // returning io.EOF here is acceptable.
                return (hdr, e);
            }
            let raw: &[byte] = &tmp;
            head.copy_from_slice(raw);
        }
        self.buf[..10].copy_from_slice(&head);
        if head[0] != gzipID1 || head[1] != gzipID2 || head[2] != gzipDeflate {
            return (hdr, ErrHeader.into());
        }
        let flg = head[3];
        let t = toint(leUint32(&head[4..8]));
        if t > 0 {
            // §2.3.1: a zero MTIME means the modified time is not set.
            hdr.ModTime = time::Unix(t, 0);
        }
        // head[8] is XFL and is currently ignored.
        hdr.OS = head[9];
        self.digest = crc32::ChecksumIEEE(from_bytes(&head));

        if flg & flagExtra != 0 {
            let mut lenbuf: [byte; 2] = [0; 2];
            {
                let mut tmp = from_bytes(&lenbuf);
                let (_, e) = io::ReadFull(self.source_mut(), &mut tmp);
                if !e.IsNil() {
                    return (hdr, noEOF(e));
                }
                let raw: &[byte] = &tmp;
                lenbuf.copy_from_slice(raw);
            }
            let tab = crc32::IEEETable();
            self.digest = crc32::Update(self.digest, &tab, from_bytes(&lenbuf));
            let extralen = toint(leUint16(&lenbuf));
            let mut data = crate::make!([]byte, extralen);
            let (_, e) = io::ReadFull(self.source_mut(), &mut data);
            if !e.IsNil() {
                return (hdr, noEOF(e));
            }
            self.digest = crc32::Update(self.digest, &tab, data.clone());
            hdr.Extra = data;
        }

        if flg & flagName != 0 {
            let (s, e) = self.readString();
            if !e.IsNil() {
                return (hdr, noEOF(e));
            }
            hdr.Name = s;
        }

        if flg & flagComment != 0 {
            let (s, e) = self.readString();
            if !e.IsNil() {
                return (hdr, noEOF(e));
            }
            hdr.Comment = s;
        }

        if flg & flagHdrCrc != 0 {
            let mut crcbuf: [byte; 2] = [0; 2];
            {
                let mut tmp = from_bytes(&crcbuf);
                let (_, e) = io::ReadFull(self.source_mut(), &mut tmp);
                if !e.IsNil() {
                    return (hdr, noEOF(e));
                }
                let raw: &[byte] = &tmp;
                crcbuf.copy_from_slice(raw);
            }
            let digest = leUint16(&crcbuf);
            if digest != touint16(self.digest) {
                return (hdr, ErrHeader.into());
            }
        }

        self.digest = 0;
        // Reset the flate decompressor onto the (header-consumed) source,
        // reusing the buffered reader without an extra wrapping layer.
        let dc = self.decompressor.take();
        let br = match dc {
            Some(d) => d.into_reader(),
            None => return (hdr, errors::New("gzip: reader not initialized")),
        };
        self.decompressor = Some(flate::new_decompressor_buffered(br, &[]));
        return (hdr, nil);
    }

    // go: sdk 1.25.5 compress/gzip/gunzip.go:246-285 Reader.Read
    /// `(z *Reader).Read(p)` (gunzip.go:246) — implements `io::Reader`,
    /// reading uncompressed bytes. On the final read of each member it
    /// consumes and verifies the 8-byte little-endian CRC-32 + ISIZE
    /// trailer; a mismatch yields [`ErrChecksum`]. With multistream
    /// enabled, members are concatenated transparently.
    pub fn Read(&mut self, p: &mut slice<byte>) -> (int, error) {
        if !self.err.IsNil() {
            return (0, self.err.clone());
        }

        let mut n: int = 0;
        while n == 0 {
            let (rn, re) = match self.decompressor.as_mut() {
                Some(d) => d.Read(p),
                None => (0, errors::New("gzip: reader not initialized")),
            };
            n = rn;
            self.err = re;
            // Feed the freshly decompressed bytes to the running digest.
            let tab = crc32::IEEETable();
            if n > 0 {
                let mut chunk = crate::make!([]byte, n);
                let mut i: int = 0;
                while i < n {
                    chunk[i] = p[i];
                    i += 1;
                }
                self.digest = crc32::Update(self.digest, &tab, chunk);
            }
            self.size = self.size.wrapping_add(touint32(n));
            if self.err != io::EOF {
                // In the normal case we return here.
                return (n, self.err.clone());
            }

            // Finished member; check checksum and size from the trailer.
            let mut tbuf: [byte; 8] = [0; 8];
            {
                let src = match self.decompressor.as_mut() {
                    Some(d) => d.reader_mut(),
                    None => return (n, errors::New("gzip: reader not initialized")),
                };
                let mut tmp = from_bytes(&tbuf);
                let (_, e) = io::ReadFull(src, &mut tmp);
                if !e.IsNil() {
                    self.err = noEOF(e);
                    return (n, self.err.clone());
                }
                let raw: &[byte] = &tmp;
                tbuf.copy_from_slice(raw);
            }
            let digest = leUint32(&tbuf[0..4]);
            let size = leUint32(&tbuf[4..8]);
            if digest != self.digest || size != self.size {
                self.err = ErrChecksum.into();
                return (n, self.err.clone());
            }
            self.digest = 0;
            self.size = 0;

            // Member is ok; check if there is another.
            if !self.multistream {
                return (n, io::EOF.into());
            }
            self.err = nil; // remove io.EOF

            let (_, he) = self.readHeader();
            if !he.IsNil() {
                self.err = he;
                return (n, self.err.clone());
            }
        }

        return (n, nil);
    }

    // go: sdk 1.25.5 compress/gzip/gunzip.go:290-290 Reader.Close
    /// `(z *Reader).Close()` (gunzip.go:290) — closes the `Reader`. Does
    /// not close the underlying reader. For the gzip checksum to be
    /// verified the reader must be fully consumed until `io.EOF`.
    pub fn Close(&mut self) -> error {
        return match self.decompressor.as_mut() {
            Some(d) => d.Close(),
            None => nil,
        };
    }

    // go: none — goish idiom: Go's `gzip.Reader` keeps its own
    //     `z.r flate.Reader` alongside the decompressor and reads the
    //     header from it. goish's decompressor owns the buffered
    //     source, so header parsing borrows it back through here.
    /// Borrow the buffered source held inside the flate decompressor.
    fn source_mut(&mut self) -> &mut bufio::Reader<R> {
        return match self.decompressor.as_mut() {
            Some(d) => d.reader_mut(),
            None => panic!("gzip: reader not initialized"),
        };
    }
}

impl<R: io::Reader> io::Reader for Reader<R> {
    // go: sdk 1.25.5 compress/gzip/gunzip.go:246-285 Reader.Read
    fn Read(&mut self, p: &mut slice<byte>) -> (int, error) {
        return Reader::Read(self, p);
    }
}

impl<R: io::Reader> io::Closer for Reader<R> {
    // go: sdk 1.25.5 compress/gzip/gunzip.go:290-290 Reader.Close
    fn Close(&mut self) -> error {
        return Reader::Close(self);
    }
}
