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
//     `io.ErrUnexpectedEOF` etc.; `errors::Is(err, io::EOF())` keeps
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

fn err_line_too_long() -> error {
    errors::New(crate::string("http: chunked header line too long"))
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
    /// Read the chunk-size line and parse it. Sets `self.err` on
    /// failure (or to `io::EOF` when size is 0).
    fn begin_chunk(&mut self) {
        let (line, err) = read_chunk_line(&mut self.r);
        if !err.IsNil() {
            self.err = err;
            return;
        }
        // line excludes the trailing CRLF.
        self.excess = self.excess.saturating_add(line.len() as i64 + 2);
        let trimmed = trim_trailing_ows(&line);
        let stripped = remove_chunk_extension(&trimmed);
        match parse_hex_uint(&stripped) {
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
            self.err = io::EOF();
        }
    }

    fn chunk_header_available(&mut self) -> bool {
        let nbuf = self.r.Buffered();
        if nbuf <= 0 {
            return false;
        }
        let (peek, _) = self.r.Peek(nbuf);
        for i in 0..peek.len() {
            if peek[i as int] == b'\n' {
                return true;
            }
        }
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
                    self.err = if errors::Is(rerr.clone(), io::EOF()) {
                        io::ErrUnexpectedEOF()
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
            if b.len() == 0 {
                break;
            }
            // Read up to min(remaining_in_chunk, b.len() - n).
            let want = core::cmp::min(b.len() as u64 - n as u64, self.n) as usize;
            // Slice over &mut b[n..n+want].
            let mut tmp: Vec<u8> = alloc::vec![0u8; want];
            let mut tmp_slice = slice::<byte>::__from_vec(tmp.clone());
            let (rn, rerr) = self.r.Read(&mut tmp_slice);
            // Copy bytes out.
            for i in 0..rn {
                b[(n + i) as int] = tmp_slice[i as int];
            }
            let _ = tmp;
            n += rn;
            self.n -= rn as u64;
            if !rerr.IsNil() {
                if errors::Is(rerr.clone(), io::EOF()) {
                    self.err = io::ErrUnexpectedEOF();
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

/// Implement `io::ReadFull` inline: read exactly `b.len()` bytes or
/// return whatever short count was achieved with the underlying error.
fn io_read_full<R: Reader>(r: &mut R, b: &mut slice<byte>) -> (int, error) {
    let need: int = b.Len();
    let mut got: int = 0;
    while got < need {
        let mut tail = slice::<byte>::__from_vec(alloc::vec![0u8; (need - got) as usize]);
        let (rn, rerr) = r.Read(&mut tail);
        for i in 0..rn {
            b[got + i] = tail[i as int];
        }
        got += rn;
        if !rerr.IsNil() {
            return (got, rerr);
        }
        if rn == 0 {
            return (got, io::EOF());
        }
    }
    (got, errors::nil)
}

fn read_chunk_line<R: Reader>(b: &mut bufio::Reader<R>) -> (Vec<u8>, error) {
    let (raw, err) = b.ReadSlice(b'\n');
    if !err.IsNil() {
        let mapped = if errors::Is(err.clone(), io::EOF()) {
            io::ErrUnexpectedEOF()
        } else if errors::Is(err.clone(), bufio::ErrBufferFull()) {
            err_line_too_long()
        } else {
            err
        };
        return (Vec::new(), mapped);
    }
    let bytes: Vec<u8> = (0..raw.Len()).map(|i| raw[i]).collect();
    // Verify the line ends in CRLF and contains no other CR.
    let mut cr_idx: Option<usize> = None;
    for (i, &c) in bytes.iter().enumerate() {
        if c == b'\r' {
            cr_idx = Some(i);
            break;
        }
    }
    match cr_idx {
        None => (Vec::new(), err_bare_lf()),
        Some(i) if i != bytes.len() - 2 => (Vec::new(), err_invalid_cr()),
        Some(i) => {
            let p: Vec<u8> = bytes[..i].to_vec();
            if p.len() >= MAX_LINE_LENGTH {
                return (Vec::new(), err_line_too_long());
            }
            (p, errors::nil)
        }
    }
}

fn trim_trailing_ows(b: &[u8]) -> Vec<u8> {
    let mut end = b.len();
    while end > 0 && (b[end - 1] == b' ' || b[end - 1] == b'\t') {
        end -= 1;
    }
    b[..end].to_vec()
}

/// Strip any chunk-extension (everything from the first `;` onward).
/// Mirrors `removeChunkExtension` (chunked.go:206) — we ignore the
/// extension contents entirely.
fn remove_chunk_extension(p: &[u8]) -> Vec<u8> {
    for (i, &b) in p.iter().enumerate() {
        if b == b';' {
            return p[..i].to_vec();
        }
    }
    p.to_vec()
}

fn parse_hex_uint(v: &[u8]) -> Result<u64, error> {
    if v.is_empty() {
        return Err(err_empty_hex());
    }
    let mut n: u64 = 0;
    for (i, &b) in v.iter().enumerate() {
        if i == 16 {
            return Err(err_chunk_too_large());
        }
        let d = match b {
            b'0'..=b'9' => b - b'0',
            b'a'..=b'f' => b - b'a' + 10,
            b'A'..=b'F' => b - b'A' + 10,
            _ => return Err(err_bad_hex()),
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
    fn Write(&mut self, data: slice<byte>) -> (int, error) {
        let n: int = data.Len();
        if n == 0 {
            // Don't send zero-length data — that's the EOF terminator
            // shape on the wire.
            return (0, errors::nil);
        }
        // Hex size + CRLF.
        let mut header: Vec<u8> = Vec::with_capacity(20);
        push_hex(&mut header, n as u64);
        header.extend_from_slice(b"\r\n");
        let (_, err) = self.Wire.Write(slice::<byte>::__from_vec(header));
        if !err.IsNil() {
            return (0, err);
        }
        let (wrote, werr) = self.Wire.Write(data);
        if !werr.IsNil() {
            return (wrote, werr);
        }
        if wrote != n {
            return (wrote, io::ErrShortWrite());
        }
        let (_, terr) = self
            .Wire
            .Write(slice::<byte>::__from_vec(alloc::vec![b'\r', b'\n']));
        (n, terr)
    }
}

impl<W: Writer> Closer for ChunkedWriter<W> {
    fn Close(&mut self) -> error {
        let (_, err) = self
            .Wire
            .Write(slice::<byte>::__from_vec(alloc::vec![b'0', b'\r', b'\n']));
        err
    }
}

fn push_hex(buf: &mut Vec<u8>, mut n: u64) {
    if n == 0 {
        buf.push(b'0');
        return;
    }
    let mut tmp = [0u8; 16];
    let mut i = 0;
    while n > 0 {
        let nibble = (n & 0xf) as u8;
        tmp[i] = if nibble < 10 {
            b'0' + nibble
        } else {
            b'a' + (nibble - 10)
        };
        n >>= 4;
        i += 1;
    }
    while i > 0 {
        i -= 1;
        buf.push(tmp[i]);
    }
}
