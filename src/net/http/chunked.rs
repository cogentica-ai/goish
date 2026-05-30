// net/http/chunked — HTTP/1.1 "chunked" Transfer-Encoding wire format.
//
// Faithful port of Go 1.25 src/net/http/internal/chunked.go (300 LOC).
//
//   Wire format:                       chunk            chunk             trailer
//     <hex-size> CRLF <data> CRLF  ...  0 CRLF  ...  CRLF
//
// Public API:
//   NewChunkedReader(r) -> ChunkedReader<R>   — io::Reader; EOF at "0\r\n"
//   NewChunkedWriter(w) -> ChunkedWriter<W>   — io::Writer + Closer
//
// Used internally by:
//   * `request.rs::ReadRequest` to decode `Transfer-Encoding: chunked`
//     request bodies (bodies without Content-Length).
//   * `response.rs::ResponseWriter::Flush()` to switch the response
//     writer into streaming mode when no Content-Length is known.
//
// Deviations from Go (faithful at the wire level):
//   * No `FlushAfterChunkWriter` Bufio plumbing — goish's Conn writes
//     are synchronous (no userspace buffering layer between the chunked
//     writer and the TCP send), so per-chunk flush is automatic.
//   * Errors are returned as goish `error` values rather than typed
//     `io.ErrUnexpectedEOF` etc.; `errors::Is(err, io::EOF)` keeps
//     working through `cached_error` Arc-pointer identity.

#![allow(non_snake_case)]
#![allow(dead_code)]

extern crate alloc;

use alloc::vec::Vec;

use crate::bufio;
use crate::errors::{self, error};
use crate::goslice::slice;
use crate::io::{self, Closer, Reader, Writer};
use crate::types::{byte, int};

const MAX_LINE_LENGTH: usize = 4096;

crate::var! {
    /// `httputil.ErrLineTooLong` (httputil.go:43) — sentinel returned when
    /// a chunked-encoding line exceeds `maxLineLength` (4 KiB).
    pub ErrLineTooLong: error = "http: chunked header line too long";
}

fn err_line_too_long() -> error {
    ErrLineTooLong.into()
}
fn err_malformed() -> error {
    errors::New(crate::string("http: malformed chunked encoding"))
}
fn err_bare_lf() -> error {
    errors::New(crate::string("http: chunked line ends with bare LF"))
}
fn err_invalid_cr() -> error {
    errors::New(crate::string("http: invalid CR in chunked line"))
}
fn err_too_much_overhead() -> error {
    errors::New(crate::string("http: chunked encoding contains too much non-data"))
}
fn err_empty_hex() -> error {
    errors::New(crate::string("http: empty hex number for chunk length"))
}
fn err_bad_hex() -> error {
    errors::New(crate::string("http: invalid byte in chunk length"))
}
fn err_chunk_too_large() -> error {
    errors::New(crate::string("http: chunk length too large"))
}

// ─── ChunkedReader ───────────────────────────────────────────────────

/// Decoder for HTTP/1.1 chunked Transfer-Encoding. Wraps a buffered
/// reader; emits `io::EOF` after consuming the terminating `"0\r\n"`.
///
/// Mirrors `chunkedReader` (chunked.go:37). `R` is the underlying
/// reader type — typically the `Conn` type.
pub struct ChunkedReader<R: Reader> {
    r: bufio::Reader<R>,
    /// Bytes remaining in the current chunk. 0 = at chunk boundary.
    n: u64,
    /// Sticky terminal error. Once set, `Read` short-circuits to it.
    err: error,
    /// True between consuming a chunk's payload and consuming the
    /// trailing CRLF. Allows a partial Read to return early.
    check_end: bool,
    /// Cumulative non-data overhead (chunk-size lines + CRLFs, minus
    /// 16 bytes per chunk + 2× data). Caps at 16 KiB to bound abuse.
    excess: i64,
}

/// `internal.NewChunkedReader(r)` — wrap `r` in a chunked decoder.
pub fn NewChunkedReader<R: Reader>(r: R) -> ChunkedReader<R> {
    ChunkedReader {
        r: bufio::NewReader(r),
        n: 0,
        err: errors::nil,
        check_end: false,
        excess: 0,
    }
}

impl<R: Reader> ChunkedReader<R> {
    /// Line-by-line port of `(*chunkedReader).beginChunk`
    /// (chunked.go:46).
    fn begin_chunk(&mut self) {
        // Go: var line []byte
        // Go: line, cr.err = readChunkLine(cr.r)
        let (line, err) = read_chunk_line(&mut self.r);
        if !err.IsNil() {
            self.err = err;
            return;
        }
        // Go: cr.excess += int64(len(line)) + 2
        self.excess = self.excess.saturating_add(line.Len() + 2);
        // Go: line = trimTrailingWhitespace(line)
        let line = trim_trailing_ows(line);
        // Go: line, cr.err = removeChunkExtension(line)
        let line = remove_chunk_extension(line);
        // Go: cr.n, cr.err = parseHexUint(line)
        match parse_hex_uint(line) {
            Ok(n) => self.n = n,
            Err(e) => {
                self.err = e;
                return;
            }
        }
        // Reduce overhead budget by 16 + 2*data, clamp to >=0, error if
        // it grew over 16 KiB without proportional data.
        self.excess -= 16 + 2 * (self.n as i64);
        if self.excess < 0 {
            self.excess = 0;
        }
        if self.excess > 16 * 1024 {
            self.err = err_too_much_overhead();
            return;
        }
        if self.n == 0 {
            self.err = io::EOF.into();
        }
    }

    /// Line-by-line port of `(*chunkedReader).chunkHeaderAvailable`
    /// (chunked.go:88).
    fn chunk_header_available(&mut self) -> bool {
        // Go: n := cr.r.Buffered()
        let n = self.r.Buffered();
        // Go: if n > 0 { peek, _ := cr.r.Peek(n); return bytes.IndexByte(peek, '\n') >= 0 }
        if n > 0 {
            let (peek, _) = self.r.Peek(n);
            return crate::bytes::IndexByte(peek, b'\n') >= 0;
        }
        // Go: return false
        false
    }
}

impl<R: Reader> Reader for ChunkedReader<R> {
    fn Read(&mut self, b: &mut slice<byte>) -> (int, error) {
        let mut n: int = 0;
        loop {
            if !self.err.IsNil() {
                break;
            }
            if self.check_end {
                if n > 0 && self.r.Buffered() < 2 {
                    // Have payload — return early instead of blocking
                    // on the CRLF.
                    break;
                }
                let mut buf = slice::<byte>::__from_vec(alloc::vec![0u8; 2]);
                let (rn, rerr) = io_read_full(&mut self.r, &mut buf);
                if !rerr.IsNil() || rn != 2 {
                    self.err = if errors::Is(rerr.clone(), io::EOF) {
                        io::ErrUnexpectedEOF.into()
                    } else {
                        rerr
                    };
                    break;
                }
                if buf[0] != b'\r' || buf[1] != b'\n' {
                    self.err = err_malformed();
                    break;
                }
                self.check_end = false;
            }
            if self.n == 0 {
                if n > 0 && !self.chunk_header_available() {
                    // Have payload — don't block reading next header.
                    break;
                }
                self.begin_chunk();
                continue;
            }
            // Go: if len(b) == 0 { break }
            // In Go, b is a sub-slice that shrinks (b = b[n0:]) after each
            // read; Goish uses a fixed slice + offset n. Check remaining space.
            if b.Len() - n <= 0 {
                break;
            }
            // Go: rbuf := b; if uint64(len(rbuf)) > cr.n { rbuf = rbuf[:cr.n] }
            let want = core::cmp::min((b.Len() - n) as u64, self.n) as int;
            let mut rbuf = crate::make!([]byte, want);
            // Go: var n0 int; n0, cr.err = cr.r.Read(rbuf); n += n0; b = b[n0:]
            let (rn, rerr) = self.r.Read(&mut rbuf);
            for i in 0..rn {
                b[n + i] = rbuf[i];
            }
            n += rn;
            self.n -= rn as u64;
            if !rerr.IsNil() {
                if errors::Is(rerr.clone(), io::EOF) {
                    self.err = io::ErrUnexpectedEOF.into();
                } else {
                    self.err = rerr;
                }
                break;
            }
            if self.n == 0 {
                self.check_end = true;
            }
        }
        (n, self.err.clone())
    }
}

/// Line-by-line port of `io.ReadFull` (Go's io/io.go:331).
/// Reads exactly `len(buf)` bytes from `r` into `buf`, or returns the
/// short count with the underlying error.
fn io_read_full<R: Reader>(r: &mut R, buf: &mut slice<byte>) -> (int, error) {
    // Go: min := len(buf); for n < min && err == nil { … }
    let min = buf.Len();
    let mut n: int = 0;
    while n < min {
        let mut tail = crate::make!([]byte, min - n);
        let (rn, err) = r.Read(&mut tail);
        for i in 0..rn {
            buf[n + i] = tail[i];
        }
        n += rn;
        if !err.IsNil() {
            return (n, err);
        }
        if rn == 0 {
            return (n, io::EOF.into());
        }
    }
    (n, errors::nil)
}

/// Line-by-line port of `readChunkLine` (chunked.go:155). Returns
/// the line without trailing CRLF as a `slice<byte>`.
fn read_chunk_line<R: Reader>(b: &mut bufio::Reader<R>) -> (slice<byte>, error) {
    // Go: p, err := b.ReadSlice('\n')
    let (p, err) = b.ReadSlice(b'\n');
    if !err.IsNil() {
        // Go: if err == io.EOF { err = io.ErrUnexpectedEOF }
        // Go: else if err == bufio.ErrBufferFull { err = ErrLineTooLong }
        let mapped = if errors::Is(err.clone(), io::EOF) {
            io::ErrUnexpectedEOF.into()
        } else if errors::Is(err.clone(), bufio::ErrBufferFull) {
            err_line_too_long()
        } else {
            err
        };
        return (slice::<byte>::__from_vec(Vec::new()), mapped);
    }
    // Go: if idx := bytes.IndexByte(p, '\r'); idx == -1 { return nil, errors.New("…bare LF") }
    let idx = crate::bytes::IndexByte(p.clone(), b'\r');
    if idx == -1 {
        return (slice::<byte>::__from_vec(Vec::new()), err_bare_lf());
    }
    // Go: else if idx != len(p)-2 { return nil, errors.New("invalid CR…") }
    if idx != p.Len() - 2 {
        return (slice::<byte>::__from_vec(Vec::new()), err_invalid_cr());
    }
    // Go: p = p[:len(p)-2]
    let p = p.slice(0, p.Len() - 2);
    // Go: if len(p) >= maxLineLength { return nil, ErrLineTooLong }
    if p.Len() >= MAX_LINE_LENGTH as int {
        return (slice::<byte>::__from_vec(Vec::new()), err_line_too_long());
    }
    (p, errors::nil)
}

/// Line-by-line port of `trimTrailingWhitespace` (chunked.go:186).
fn trim_trailing_ows(b: slice<byte>) -> slice<byte> {
    crate::bytes::TrimRight(b, crate::convert::bytes(" \t"))
}

/// Line-by-line port of `removeChunkExtension` (chunked.go:206).
/// Strips everything from the first `;` onward.
fn remove_chunk_extension(p: slice<byte>) -> slice<byte> {
    // Go: p, _, _ = bytes.Cut(p, semi)
    let (before, _after, _found) = crate::bytes::Cut(p, crate::convert::bytes(";"));
    before
}

/// Line-by-line port of `parseHexUint` (chunked.go:278).
fn parse_hex_uint(v: slice<byte>) -> Result<u64, error> {
    // Go: if len(v) == 0 { return 0, errors.New("empty hex…") }
    if v.Len() == 0 {
        return Err(err_empty_hex());
    }
    // Go: for i, b := range v { … n <<= 4; n |= uint64(b) }
    let mut n: u64 = 0;
    for (i, b) in crate::range!(v) {
        // Go: if i == 16 { return 0, errors.New("…too large") }
        if i == 16 {
            return Err(err_chunk_too_large());
        }
        // Go: switch { case '0' <= b && b <= '9': b = b - '0'; … }
        let d: byte = if *b >= b'0' && *b <= b'9' {
            *b - b'0'
        } else if *b >= b'a' && *b <= b'f' {
            *b - b'a' + 10
        } else if *b >= b'A' && *b <= b'F' {
            *b - b'A' + 10
        } else {
            return Err(err_bad_hex());
        };
        n = (n << 4) | (d as u64);
    }
    Ok(n)
}

// ─── ChunkedWriter ───────────────────────────────────────────────────

/// Encoder for HTTP/1.1 chunked Transfer-Encoding. Each `Write` call
/// emits one chunk; `Close` writes the terminating `"0\r\n"`. Mirrors
/// `chunkedWriter` (chunked.go:231).
///
/// **Note.** Like Go, `Close` sends only `"0\r\n"`, not the final
/// `\r\n` after trailers. Callers that don't emit trailers must still
/// write that terminating `\r\n` themselves (the response writer does
/// this in its final `flush()`).
pub struct ChunkedWriter<W: Writer> {
    pub Wire: W,
}

pub fn NewChunkedWriter<W: Writer>(w: W) -> ChunkedWriter<W> {
    ChunkedWriter { Wire: w }
}

impl<W: Writer> Writer for ChunkedWriter<W> {
    /// Line-by-line port of `(*chunkedWriter).Write` (chunked.go:238).
    fn Write(&mut self, data: slice<byte>) -> (int, error) {
        // Go: if len(data) == 0 { return 0, nil }
        if data.Len() == 0 {
            return (0, errors::nil);
        }
        // Go: if _, err = fmt.Fprintf(cw.Wire, "%x\r\n", len(data)); err != nil { return 0, err }
        let (_, err) = crate::Fprintf!(self.Wire, "%x\r\n", data.Len());
        if !err.IsNil() {
            return (0, err);
        }
        let want = data.Len();
        // Go: if n, err = cw.Wire.Write(data); err != nil { return }
        let (n, werr) = self.Wire.Write(data);
        if !werr.IsNil() {
            return (n, werr);
        }
        // Go: if n != len(data) { err = io.ErrShortWrite; return }
        if n != want {
            return (n, io::ErrShortWrite.into());
        }
        // Go: if _, err = io.WriteString(cw.Wire, "\r\n"); err != nil { return }
        let (_, terr) = self.Wire.Write(crate::convert::bytes("\r\n"));
        (n, terr)
    }
}

impl<W: Writer> Closer for ChunkedWriter<W> {
    /// Line-by-line port of `(*chunkedWriter).Close` (chunked.go:264).
    fn Close(&mut self) -> error {
        // Go: _, err := io.WriteString(cw.Wire, "0\r\n")
        let (_, err) = self.Wire.Write(crate::convert::bytes("0\r\n"));
        err
    }
}
