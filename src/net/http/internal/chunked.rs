// go: package net/http/internal
//
// go: file net/http/internal/chunked.go decls: NewChunkedReader, chunkedReader.beginChunk, chunkedReader.chunkHeaderAvailable, chunkedReader.Read, readChunkLine, trimTrailingWhitespace, isOWS, removeChunkExtension, NewChunkedWriter, chunkedWriter.Write, chunkedWriter.Close, parseHexUint
//
// Go: "The wire protocol for HTTP's 'chunked' Transfer-Encoding."
//
// This lived at src/net/http/chunked.rs until now, which is not where
// Go puts it — so port_deps reported net/http/internal as a SQUATTER at
// 0/12 while a faithful port of all twelve sat one directory up.
//
// goishlint:ignore GOISH021 chunkedReader, chunkedWriter, semi, maxLineLength — chunkedReader/chunkedWriter are exposed as ChunkedReader/ChunkedWriter because Go returns them behind io.Reader/io.WriteCloser and goish's generic wrappers cannot be erased that way; `semi` is a one-byte separator inlined at its single use.

#![allow(non_snake_case)]
#![allow(dead_code)]

extern crate alloc;

use alloc::vec::Vec;

use crate::bufio;
use crate::errors::{self, error};
use crate::goslice::slice;
use crate::io::{self, Closer, Reader, Writer};
use crate::types::{byte, int};

const maxLineLength: usize = 4096;

crate::var! {
    /// `httputil.ErrLineTooLong` (httputil.go:43) — sentinel returned when
    /// a chunked-encoding line exceeds `maxLineLength` (4 KiB).
    pub ErrLineTooLong: error = "header line too long";
}

// go: none — goish idiom: Go builds these inline with errors.New at the
// point of failure; ErrLineTooLong as an owned error. Named here because
// goish's `error` is an owned Arc, so an inline construction inside a
// method that also borrows `self` does not type-check.
fn err_line_too_long() -> error {
    return ErrLineTooLong.into();
}
// go: none — goish idiom: Go builds these inline with errors.New at the
// point of failure; chunked.go:107 `errors.New("malformed chunked encoding")`. Named here because
// goish's `error` is an owned Arc, so an inline construction inside a
// method that also borrows `self` does not type-check.
fn err_malformed() -> error {
    return errors::New(crate::string("malformed chunked encoding"));
}
// go: none — goish idiom: Go builds these inline with errors.New at the
// point of failure; chunked.go:173 `errors.New("chunked line ends with bare LF")`. Named here because
// goish's `error` is an owned Arc, so an inline construction inside a
// method that also borrows `self` does not type-check.
fn err_bare_lf() -> error {
    return errors::New(crate::string("chunked line ends with bare LF"));
}
// go: none — goish idiom: Go builds these inline with errors.New at the
// point of failure; chunked.go:175 `errors.New("invalid CR in chunked line")`. Named here because
// goish's `error` is an owned Arc, so an inline construction inside a
// method that also borrows `self` does not type-check.
fn err_invalid_cr() -> error {
    return errors::New(crate::string("invalid CR in chunked line"));
}
// go: none — goish idiom: Go builds these inline with errors.New at the
// point of failure; chunked.go:79 `errors.New("chunked encoding contains too much non-data")`. Named here because
// goish's `error` is an owned Arc, so an inline construction inside a
// method that also borrows `self` does not type-check.
fn err_too_much_overhead() -> error {
    return errors::New(crate::string("chunked encoding contains too much non-data"));
}
// go: none — goish idiom: Go builds these inline with errors.New at the
// point of failure; chunked.go:273 `errors.New("empty hex number for chunk length")`. Named here because
// goish's `error` is an owned Arc, so an inline construction inside a
// method that also borrows `self` does not type-check.
fn err_empty_hex() -> error {
    return errors::New(crate::string("empty hex number for chunk length"));
}
// go: none — goish idiom: Go builds these inline with errors.New at the
// point of failure; chunked.go:283 `errors.New("invalid byte in chunk length")`. Named here because
// goish's `error` is an owned Arc, so an inline construction inside a
// method that also borrows `self` does not type-check.
fn err_bad_hex() -> error {
    return errors::New(crate::string("invalid byte in chunk length"));
}
// go: none — goish idiom: Go builds these inline with errors.New at the
// point of failure; chunked.go:286 `errors.New("http chunk length too large")`. Named here because
// goish's `error` is an owned Arc, so an inline construction inside a
// method that also borrows `self` does not type-check.
fn err_chunk_too_large() -> error {
    return errors::New(crate::string("http chunk length too large"));
}

// ─── ChunkedReader ───────────────────────────────────────────────────

// goishlint:ignore GOISH019 chunkedReader — Go's `buf [2]byte` is a
// scratch array for reading the CRLF that follows a chunk; goish's
// io_read_full takes the buffer as a parameter, so the two bytes live
// on the stack at the one call site instead of on the struct.
// go: sdk 1.25.5 net/http/internal/chunked.go:36-43 chunkedReader
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
    checkEnd: bool,
    /// Cumulative non-data overhead (chunk-size lines + CRLFs, minus
    /// 16 bytes per chunk + 2× data). Caps at 16 KiB to bound abuse.
    excess: i64,
}

// go: sdk 1.25.5 net/http/internal/chunked.go:29-34 NewChunkedReader
/// `internal.NewChunkedReader(r)` — wrap `r` in a chunked decoder.
pub fn NewChunkedReader<R: Reader>(r: R) -> ChunkedReader<R> {
    return ChunkedReader {
        r: bufio::NewReader(r),
        n: 0,
        err: errors::nil,
        checkEnd: false,
        excess: 0,
    };
}

impl<R: Reader> ChunkedReader<R> {
    // go: none — goish-only: Go's chunkedReader holds a *bufio.Reader
    // the http.Body reaches through by type assertion. goish's is a
    // generic field, so the accessor is written out.
    /// Crate-internal: mutable access to the internal buffered reader,
    /// and through it the wrapped source. The streaming `http::Body`
    /// closes its connection down this path.
    pub(crate) fn __bufio_mut(&mut self) -> &mut bufio::Reader<R> {
        return &mut self.r;
    }

    // go: sdk 1.25.5 net/http/internal/chunked.go:46-86 chunkedReader.beginChunk
    /// Line-by-line port of `(*chunkedReader).beginChunk`
    /// (chunked.go:46).
    fn beginChunk(&mut self) {
        // Go: var line []byte
        // Go: line, cr.err = readChunkLine(cr.r)
        let (line, err) = readChunkLine(&mut self.r);
        if !err.IsNil() {
            self.err = err;
            return;
        }
        // Go: cr.excess += int64(len(line)) + 2
        self.excess = self.excess.saturating_add(line.Len() + 2);
        // Go: line = trimTrailingWhitespace(line)
        let line = trimTrailingWhitespace(line);
        // Go: line, cr.err = removeChunkExtension(line)
        let line = removeChunkExtension(line);
        // Go: cr.n, cr.err = parseHexUint(line)
        match parseHexUint(line) {
            Ok(n) => self.n = n,
            Err(e) => {
                self.err = e;
                return;
            }
        }
        // Reduce overhead budget by 16 + 2*data, clamp to >=0, error if
        // it grew over 16 KiB without proportional data.
        self.excess -= 16 + 2 * crate::int64(self.n);
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

    // go: sdk 1.25.5 net/http/internal/chunked.go:88-95 chunkedReader.chunkHeaderAvailable
    /// Line-by-line port of `(*chunkedReader).chunkHeaderAvailable`
    /// (chunked.go:88).
    fn chunkHeaderAvailable(&mut self) -> bool {
        // Go: n := cr.r.Buffered()
        let n = self.r.Buffered();
        // Go: if n > 0 { peek, _ := cr.r.Peek(n); return bytes.IndexByte(peek, '\n') >= 0 }
        if n > 0 {
            let (peek, _) = self.r.Peek(n);
            return crate::bytes::IndexByte(peek, b'\n') >= 0;
        }
        // Go: return false
        return false;
    }
}

impl<R: Reader> Reader for ChunkedReader<R> {
    // go: sdk 1.25.5 net/http/internal/chunked.go:94-148 chunkedReader.Read
    fn Read(&mut self, b: &mut slice<byte>) -> (int, error) {
        let mut n: int = 0;
        loop {
            if !self.err.IsNil() {
                break;
            }
            if self.checkEnd {
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
                self.checkEnd = false;
            }
            if self.n == 0 {
                if n > 0 && !self.chunkHeaderAvailable() {
                    // Have payload — don't block reading next header.
                    break;
                }
                self.beginChunk();
                continue;
            }
            // Go: if len(b) == 0 { break }
            // In Go, b is a sub-slice that shrinks (b = b[n0:]) after each
            // read; Goish uses a fixed slice + offset n. Check remaining space.
            if b.Len() - n <= 0 {
                break;
            }
            // Go: rbuf := b; if uint64(len(rbuf)) > cr.n { rbuf = rbuf[:cr.n] }
            let want = crate::int(core::cmp::min(crate::uint64(b.Len() - n), self.n));
            let mut rbuf = crate::make!([]byte, want);
            // Go: var n0 int; n0, cr.err = cr.r.Read(rbuf); n += n0; b = b[n0:]
            let (rn, rerr) = self.r.Read(&mut rbuf);
            for i in 0..rn {
                b[n + i] = rbuf[i];
            }
            n += rn;
            self.n -= crate::uint64(rn);
            if !rerr.IsNil() {
                if errors::Is(rerr.clone(), io::EOF) {
                    self.err = io::ErrUnexpectedEOF.into();
                } else {
                    self.err = rerr;
                }
                break;
            }
            if self.n == 0 {
                self.checkEnd = true;
            }
        }
        return (n, self.err.clone());
    }
}

// go: none — goish idiom: Go calls io.ReadFull(cr.r, cr.buf[:2]).
// goish's io::ReadFull does not accept a &mut bufio::Reader by generic
// bound, so the two-byte fill is written out here.
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
    return (n, errors::nil);
}

// go: sdk 1.25.5 net/http/internal/chunked.go:155-184 readChunkLine
/// Line-by-line port of `readChunkLine` (chunked.go:155). Returns
/// the line without trailing CRLF as a `slice<byte>`.
fn readChunkLine<R: Reader>(b: &mut bufio::Reader<R>) -> (slice<byte>, error) {
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
    if p.Len() >= crate::int(maxLineLength) {
        return (slice::<byte>::__from_vec(Vec::new()), err_line_too_long());
    }
    return (p, errors::nil);
}

// go: sdk 1.25.5 net/http/internal/chunked.go:186-191 trimTrailingWhitespace
/// Line-by-line port of `trimTrailingWhitespace` (chunked.go:186).
fn trimTrailingWhitespace(b: slice<byte>) -> slice<byte> {
    // Go walks the tail one byte at a time against isOWS rather than
    // calling bytes.TrimRight with a cutset. Kept that way: the cutset
    // form hides isOWS, which is the decl that says WHICH bytes count
    // as optional whitespace here (SP and HTAB only — not CR, LF or
    // any other space character bytes.TrimRight might be handed).
    let mut b = b;
    while b.Len() > 0 && isOWS(b[b.Len() - 1]) {
        b = b.slice(0, b.Len() - 1);
    }
    return b;
}

// go: sdk 1.25.5 net/http/internal/chunked.go:193-195 isOWS
/// Go: optional whitespace, per RFC 9110 — space and horizontal tab,
/// and nothing else.
fn isOWS(b: byte) -> bool {
    return b == b' ' || b == b'\t';
}

// go: sdk 1.25.5 net/http/internal/chunked.go:206-212 removeChunkExtension
/// Line-by-line port of `removeChunkExtension` (chunked.go:206).
/// Strips everything from the first `;` onward.
fn removeChunkExtension(p: slice<byte>) -> slice<byte> {
    // Go: p, _, _ = bytes.Cut(p, semi)
    let (before, _after, _found) = crate::bytes::Cut(p, crate::convert::bytes(";"));
    return before;
}

// go: sdk 1.25.5 net/http/internal/chunked.go:278-300 parseHexUint
/// Line-by-line port of `parseHexUint` (chunked.go:278).
fn parseHexUint(v: slice<byte>) -> Result<u64, error> {
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
        n = (n << 4) | crate::uint64(d);
    }
    return Ok(n);
}

// ─── ChunkedWriter ───────────────────────────────────────────────────

// go: sdk 1.25.5 net/http/internal/chunked.go:231-233 chunkedWriter
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

// go: sdk 1.25.5 net/http/internal/chunked.go:225-227 NewChunkedWriter
pub fn NewChunkedWriter<W: Writer>(w: W) -> ChunkedWriter<W> {
    return ChunkedWriter { Wire: w };
}

impl<W: Writer> Writer for ChunkedWriter<W> {
    // go: sdk 1.25.5 net/http/internal/chunked.go:238-262 chunkedWriter.Write
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
        return (n, terr);
    }
}

impl<W: Writer> Closer for ChunkedWriter<W> {
    // go: sdk 1.25.5 net/http/internal/chunked.go:264-267 chunkedWriter.Close
    /// Line-by-line port of `(*chunkedWriter).Close` (chunked.go:264).
    fn Close(&mut self) -> error {
        // Go: _, err := io.WriteString(cw.Wire, "0\r\n")
        let (_, err) = self.Wire.Write(crate::convert::bytes("0\r\n"));
        return err;
    }
}

// goishlint:ignore GOISH019 FlushAfterChunkWriter — Go EMBEDS
// *bufio.Writer so the wrapper forwards Write/Flush by promotion. Rust
// has no embedding, so the writer is a named field and the two methods
// are written out.
// go: sdk 1.25.5 net/http/internal/chunked.go:274-276 FlushAfterChunkWriter
/// Go: "FlushAfterChunkWriter signals from the caller of
/// [NewChunkedWriter] that each chunk should be followed by a flush. It
/// is used by the [net/http.Transport] code to keep the buffering
/// behavior for headers and trailers, but flush out chunks aggressively
/// in the middle for request bodies which may be generated slowly."
///
/// The type carries no behaviour of its own — it exists purely so
/// chunkedWriter.Write can recognise it and flush. That is why Go makes
/// it a distinct type rather than a bool field.
pub struct FlushAfterChunkWriter<W: Writer> {
    pub Writer: bufio::Writer<W>,
}

impl<W: Writer> FlushAfterChunkWriter<W> {
    // go: none — goish idiom: Go promotes Flush from the embedded
    // *bufio.Writer; Rust forwards it explicitly.
    pub fn Flush(&mut self) -> error {
        return self.Writer.Flush();
    }
}

impl<W: Writer> Writer for FlushAfterChunkWriter<W> {
    // go: none — goish idiom: Go promotes Write from the embedded
    // *bufio.Writer.
    fn Write(&mut self, p: slice<byte>) -> (int, error) {
        return self.Writer.Write(p);
    }
}
