// compress/gzip — gzip file format (RFC 1952).
//
// Line-by-line port of Go 1.25 `/share/go/src/compress/gzip/`
// (`gunzip.go` + `gzip.go`). gzip is a thin framing around
// `compress/flate`: a variable-length header (magic `1f 8b`, method,
// flags, mtime, XFL, OS, optional FEXTRA / FNAME / FCOMMENT / FHCRC
// fields), the raw DEFLATE payload, and an 8-byte little-endian
// trailer of CRC-32/IEEE + ISIZE (uncompressed length mod 2^32).
//
// Slim deviations from Go:
//   * Go's `NewReader` returns `*Reader`; goish has no trait-object
//     ReadCloser, so it returns the concrete `Reader<R>` which
//     implements `io::Reader` + `io::Closer` and carries `Reset`. The
//     `flate`/`zlib` ports do the same.
//   * Go's `gzip.Reader` keeps a `flate.Reader` handle (`z.r`) separate
//     from the `decompressor`, reading the header and the 8-byte
//     trailer directly from it. goish's `flate::Decompressor<R>` owns
//     its buffered source, so the gzip `Reader<R>` wraps the source in
//     a `bufio::Reader<R>`, hands it to `flate::NewReader`, and reaches
//     the trailer (and, for multistream, the next member's header)
//     through `reader_mut()` / `into_reader()` — the decompressor stops
//     on a byte boundary, so the source is positioned exactly at the
//     first trailing byte once `Read` has returned `io.EOF`.
//   * Go's `Writer` embeds `Header` and is generic over an `io.Writer`
//     interface field; goish's `Writer<W>` is generic over `W` and
//     names the embedded header field `Header` literally (AGENTS.md
//     §5), so `w.Header.Name = ...` mirrors Go's `w.Name = ...`.
//   * `into_writer` lets callers recover `W` after `Close`, matching
//     the `flate`/`zlib` ports.

#![allow(non_snake_case, non_upper_case_globals, non_camel_case_types)]

extern crate alloc;

use alloc::vec::Vec;

use crate::bufio;
use crate::compress::flate;
use crate::errors::{self, error, nil};
use crate::goslice::slice;
use crate::hash::crc32;
use crate::io;
use crate::time;
use crate::types::{byte, int, rune};

// ─── header constants (gzip.go:19) ─────────────────────────────────────

const gzipID1: byte = 0x1f;
const gzipID2: byte = 0x8b;
const gzipDeflate: byte = 8;
/// `flagText` (gzip.go:23) — RFC 1952 FTEXT bit. Defined for fidelity
/// to Go's flag-constant block; not consulted by the reader or writer.
#[allow(dead_code)]
const flagText: byte = 1 << 0;
const flagHdrCrc: byte = 1 << 1;
const flagExtra: byte = 1 << 2;
const flagName: byte = 1 << 3;
const flagComment: byte = 1 << 4;

// ─── error sentinels (gzip.go:30, AGENTS.md §8) ────────────────────────

crate::var! {
    /// `gzip.ErrChecksum` — the gzip data has an invalid checksum.
    pub ErrChecksum: error = "gzip: invalid checksum";
    /// `gzip.ErrHeader` — the gzip data has an invalid header.
    pub ErrHeader: error = "gzip: invalid header";
}

// ─── compression-level constants (gzip.go:18) ──────────────────────────
//
// Copied from `flate` so callers of `compress/gzip` need not also
// import `compress/flate`.

/// No compression — only DEFLATE+gzip framing.
pub const NoCompression: int = flate::NoCompression;
/// Fastest compression.
pub const BestSpeed: int = flate::BestSpeed;
/// Best compression ratio.
pub const BestCompression: int = flate::BestCompression;
/// The default compression level.
pub const DefaultCompression: int = flate::DefaultCompression;
/// Huffman entropy coding only — no Lempel-Ziv match search.
pub const HuffmanOnly: int = flate::HuffmanOnly;

// ─── little-endian helpers ─────────────────────────────────────────────
//
// gzip (RFC 1952) is little-endian, unlike zlib (RFC 1950). Go uses
// `binary.LittleEndian`; a tiny local helper keeps the byte layout
// explicit and avoids `AsRef`/`AsMut` ceremony around fixed buffers.

fn leUint16(b: &[byte]) -> u16 {
    (b[0] as u16) | ((b[1] as u16) << 8)
}

fn leUint32(b: &[byte]) -> u32 {
    (b[0] as u32) | ((b[1] as u32) << 8) | ((b[2] as u32) << 16) | ((b[3] as u32) << 24)
}

fn lePutUint16(b: &mut [byte], v: u16) {
    b[0] = v as byte;
    b[1] = (v >> 8) as byte;
}

fn lePutUint32(b: &mut [byte], v: u32) {
    b[0] = v as byte;
    b[1] = (v >> 8) as byte;
    b[2] = (v >> 16) as byte;
    b[3] = (v >> 24) as byte;
}

/// Build a goish `slice<byte>` from a borrowed Rust byte slice.
fn from_bytes(b: &[byte]) -> slice<byte> {
    let mut v: Vec<byte> = Vec::with_capacity(b.len());
    v.extend_from_slice(b);
    slice::__from_vec(v)
}

/// `noEOF` (gunzip.go:40) — converts `io.EOF` to `io.ErrUnexpectedEOF`.
fn noEOF(err: error) -> error {
    if err == io::EOF {
        return io::ErrUnexpectedEOF.into();
    }
    err
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
    (z, nil)
}

impl<R: io::Reader> Reader<R> {
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
        self.err.clone()
    }

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
                self.digest =
                    crc32::Update(self.digest, &tab, from_bytes(&self.buf[..i + 1]));
                // Strings are ISO 8859-1, Latin-1 (RFC 1952, §2.3.1).
                if needConv {
                    let mut s = crate::string::new();
                    for j in 0..i {
                        let r: rune = self.buf[j] as rune;
                        s = s + crate::string::from_rune(r);
                    }
                    return (s, nil);
                }
                return (crate::string::from_bytes(&self.buf[..i]), nil);
            }
            i += 1;
        }
    }

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
        let t = leUint32(&head[4..8]) as int;
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
            let extralen = leUint16(&lenbuf) as int;
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
            if digest != (self.digest as u16) {
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
        (hdr, nil)
    }

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
            self.size = self.size.wrapping_add(n as u32);
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

        (n, nil)
    }

    /// `(z *Reader).Close()` (gunzip.go:290) — closes the `Reader`. Does
    /// not close the underlying reader. For the gzip checksum to be
    /// verified the reader must be fully consumed until `io.EOF`.
    pub fn Close(&mut self) -> error {
        match self.decompressor.as_mut() {
            Some(d) => d.Close(),
            None => nil,
        }
    }

    /// Borrow the buffered source held inside the flate decompressor.
    /// Internal: header parsing reads directly from it the way Go's
    /// `gzip.Reader` reads from its separate `z.r flate.Reader`.
    fn source_mut(&mut self) -> &mut bufio::Reader<R> {
        match self.decompressor.as_mut() {
            Some(d) => d.reader_mut(),
            None => panic!("gzip: reader not initialized"),
        }
    }
}

impl<R: io::Reader> io::Reader for Reader<R> {
    fn Read(&mut self, p: &mut slice<byte>) -> (int, error) {
        Reader::Read(self, p)
    }
}

impl<R: io::Reader> io::Closer for Reader<R> {
    fn Close(&mut self) -> error {
        Reader::Close(self)
    }
}

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

/// `gzip.NewWriter(w)` (gzip.go:49) — a new [`Writer`] at
/// [`DefaultCompression`]. Writes are compressed and written to `w`.
///
/// It is the caller's responsibility to call [`Close`](Writer::Close)
/// when done; writes may be buffered until then.
pub fn NewWriter<W: io::Writer>(w: W) -> Writer<W> {
    let (z, _) = NewWriterLevel(w, DefaultCompression);
    z
}

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
    (z, nil)
}

impl<W: io::Writer> Writer<W> {
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

    /// `(z *Writer).writeBytes(b)` (gzip.go:93) — writes a
    /// length-prefixed byte slice (used for the FEXTRA field).
    fn writeBytes(&mut self, b: &slice<byte>) -> error {
        if b.Len() > 0xffff {
            return errors::New("gzip.Write: Extra data is too large");
        }
        let mut lenbuf: [byte; 2] = [0; 2];
        lePutUint16(&mut lenbuf, b.Len() as u16);
        let w = match self.w.as_mut() {
            Some(w) => w,
            None => return errors::New("gzip: writer not initialized"),
        };
        let (_, e) = w.Write(from_bytes(&lenbuf));
        if !e.IsNil() {
            return e;
        }
        let (_, e) = w.Write(b.clone());
        e
    }

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
                b.push(v as byte);
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
        e
    }

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
                lePutUint32(&mut head[4..8], self.Header.ModTime.Unix() as u32);
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
        self.size = self.size.wrapping_add(p.Len() as u32);
        let tab = crc32::IEEETable();
        self.digest = crc32::Update(self.digest, &tab, p.clone());
        let (n, e) = match self.compressor.as_mut() {
            Some(cw) => cw.Write(p),
            None => (0, errors::New("gzip: writer not initialized")),
        };
        self.err = e;
        (n, self.err.clone())
    }

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
        self.err.clone()
    }

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
        self.err.clone()
    }

    /// Consume the `Writer` and return the underlying writer.
    ///
    /// goish-specific: a goish `Writer` *owns* `W` by value, so this
    /// hands it back after [`Close`](Self::Close). Mirrors
    /// `flate::Writer::into_writer` / `zlib::Writer::into_writer`.
    pub fn into_writer(self) -> W {
        match self.compressor {
            Some(cw) => cw.into_writer(),
            None => match self.w {
                Some(w) => w,
                None => panic!("gzip: Writer has no underlying writer"),
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
