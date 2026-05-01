// net/http/response — ResponseWriter.
//
// Buffered v1: handler `Write` calls accumulate into an internal
// body buffer. `flush` (or its convenience wrapper `close_conn`)
// emits status line + headers + body in one go, with a
// Content-Length derived from the buffer length so HTTP/1.1
// keep-alive can frame successive responses without chunked
// transfer-encoding (deferred).
//
// Trade vs. Go's `chunkWriter`: simpler — one Vec per response, no
// auto-detect-length state machine, no streaming. Cost: total
// response body must fit in memory. For the REST/JSON-shaped
// payloads net/http typically hosts, this is the right v1 trade.

#![allow(non_snake_case)]

extern crate alloc;

use alloc::vec::Vec;

use crate::errors::{self, error};
use crate::goslice::slice;
use crate::io::{self, Closer, Writer};
use crate::net::Conn;
use crate::string;
use crate::types::{byte, int};

use super::header::Header;

/// `http.ResponseWriter`. Owns the connection until `take_conn` /
/// `close_conn` ends its lifecycle.
///
/// Two modes:
///   * **Buffered (default):** `Write` calls accumulate into `body`;
///     `flush` emits status + headers (with derived `Content-Length`)
///     + body in one send. Right for typical sub-MB responses.
///   * **Streaming (after `Flush`):** the response head is emitted
///     with `Transfer-Encoding: chunked` and any subsequent `Write`
///     emits one chunk per call. The closing `0\r\n\r\n` terminator is
///     sent by the final `flush()`. Mirrors Go's `http.Flusher`
///     interface (`(*response).Flush()` in server.go:1657).
pub struct ResponseWriter {
    conn: Conn,
    header: Header,
    /// Captured at `WriteHeader` time. Zero before that; `Write`
    /// implicitly calls WriteHeader(200) on first body byte.
    status: int,
    /// `true` once `WriteHeader` was called explicitly or implicitly.
    wrote_header: bool,
    /// `true` once `flush` has emitted bytes onto the wire. Idempotent
    /// guard.
    flushed: bool,
    /// Buffered body. Used in buffered mode; in streaming mode, it
    /// only holds bytes written before the first `Flush()` call (those
    /// are emitted as the first chunk).
    body: Vec<u8>,
    /// Streaming mode flag — once true, `Write` emits each call as a
    /// chunk on the wire and the head has already been sent.
    chunked: bool,
    /// Set by the server before invoking the handler, based on the
    /// request's HTTP version + `Connection` header. Controls whether
    /// `flush` emits `Connection: close`.
    keep_alive: bool,
}

impl ResponseWriter {
    /// Build a fresh `ResponseWriter` over `conn`. Connection is
    /// closed after the response unless the caller flips
    /// `set_keep_alive(true)` before invoking the handler.
    pub fn new(conn: Conn) -> Self {
        let mut h = Header::new();
        h.Set(string("Content-Type"), string("text/plain; charset=utf-8"));
        ResponseWriter {
            conn,
            header: h,
            status: 200,
            wrote_header: false,
            flushed: false,
            body: Vec::new(),
            chunked: false,
            keep_alive: false,
        }
    }

    /// Server hook: enable/disable HTTP keep-alive on this response.
    /// The default is `false` (HTTP/1.0 close-style); ListenAndServe
    /// flips this to `true` for HTTP/1.1 requests without an
    /// explicit `Connection: close`.
    pub fn __set_keep_alive(&mut self, keep_alive: bool) {
        self.keep_alive = keep_alive;
    }

    /// `Header()` returns the response header map.
    pub fn Header(&mut self) -> &mut Header {
        &mut self.header
    }

    /// `WriteHeader(status)` — set the status code. Buffered until
    /// `flush`; subsequent calls are no-ops (matching Go's "second
    /// WriteHeader" warning behavior).
    pub fn WriteHeader(&mut self, status: int) {
        if self.wrote_header {
            return;
        }
        self.wrote_header = true;
        self.status = status;
    }

    /// `Write(p)` — buffered or streaming depending on mode.
    /// In buffered mode (no `Flush()` yet), appends to the body
    /// buffer. In streaming mode (after `Flush()`), emits one chunk
    /// directly on the wire. Implicitly calls `WriteHeader(200)` on
    /// first call. Returns `(p.len(), nil)` for the buffered path;
    /// the streaming path returns `(written, err)` from the wire.
    pub fn Write(&mut self, p: slice<byte>) -> (int, error) {
        if !self.wrote_header {
            self.WriteHeader(200);
        }
        if self.chunked {
            return write_chunk(&mut self.conn, &p);
        }
        self.body.extend_from_slice(&*p);
        (p.len() as int, errors::nil)
    }

    /// `Flush()` — switch the response into streaming (chunked) mode.
    /// Mirrors Go's `http.Flusher` interface
    /// (`(*response).Flush()`, server.go:1657).
    ///
    /// First call: emit the response head with
    /// `Transfer-Encoding: chunked` (no Content-Length), followed by
    /// any already-buffered body bytes as the first chunk. From this
    /// point on, every `Write` emits a chunk directly on the wire and
    /// the closing `0\r\n\r\n` terminator is appended by the final
    /// `flush()`.
    ///
    /// Subsequent `Flush()` calls in streaming mode are no-ops at the
    /// wire level (the `Conn` writes are already unbuffered) but kept
    /// for API compatibility with handlers that loop
    /// `w.Write(...); w.Flush();`.
    pub fn Flush(&mut self) -> error {
        if !self.wrote_header {
            self.WriteHeader(200);
        }
        if self.chunked {
            // Already streaming — nothing to flush at the writer level.
            return errors::nil;
        }
        // Promote to chunked mode: emit head + any buffered body as
        // the first chunk.
        self.chunked = true;
        // Set Transfer-Encoding; clear any user-set Content-Length
        // (mutually exclusive per RFC 7230 §3.3.2).
        self.header.Del(string("Content-Length"));
        self.header
            .Set(string("Transfer-Encoding"), string("chunked"));
        if !self.keep_alive && self.header.Get(string("Connection")).Len() == 0 {
            self.header.Set(string("Connection"), string("close"));
        }
        // Emit head.
        let head = build_head(self.status, &self.header);
        let (_, err) = self.conn.Write(slice::<byte>::__from_vec(head));
        if !err.IsNil() {
            return err;
        }
        // Emit any buffered body as the initial chunk.
        if !self.body.is_empty() {
            let body = core::mem::take(&mut self.body);
            let (_, werr) = write_chunk(
                &mut self.conn,
                &slice::<byte>::__from_vec(body),
            );
            if !werr.IsNil() {
                return werr;
            }
        }
        errors::nil
    }

    /// Render the response onto the wire. Idempotent — calling twice
    /// is a no-op. After `flush`, the underlying connection holds
    /// only the kept-alive read buffer (if any) and may be reused.
    pub fn flush(&mut self) -> error {
        if self.flushed {
            return errors::nil;
        }
        self.flushed = true;
        if !self.wrote_header {
            self.WriteHeader(200);
        }
        if self.chunked {
            // Streaming mode: emit "0\r\n\r\n" terminator (the chunked
            // writer's Close() emits "0\r\n"; the trailing CRLF
            // closes the trailer block).
            let (_, err) = self
                .conn
                .Write(slice::<byte>::__from_vec(alloc::vec![
                    b'0', b'\r', b'\n', b'\r', b'\n'
                ]));
            return err;
        }

        // Buffered mode: emit Content-Length derived from buffered body.
        if self.header.Get(string("Content-Length")).Len() == 0 {
            self.header
                .Set(string("Content-Length"), int_to_string(self.body.len() as i64));
        }
        if !self.keep_alive && self.header.Get(string("Connection")).Len() == 0 {
            self.header.Set(string("Connection"), string("close"));
        }
        let mut buf = build_head(self.status, &self.header);
        buf.reserve(self.body.len());
        buf.extend_from_slice(&self.body);
        let (_, err) = self.conn.Write(slice::<byte>::__from_vec(buf));
        err
    }

    /// Server hook: flush the response and return the underlying
    /// connection. Used by the keep-alive loop in ListenAndServe to
    /// hand the connection back for the next request on the same fd.
    pub fn __take_conn(mut self) -> Conn {
        let _ = self.flush();
        self.conn
    }

    /// Server hook: raw fd of the underlying connection. Used by
    /// `serve_conn` to register a panic-time close cleanup so a
    /// handler-panic doesn't leak the fd / hang the client.
    pub fn __conn_fd(&self) -> i32 {
        self.conn.__fd()
    }

    /// Convenience for examples that drive their own accept loop:
    /// flush headers (if not yet) and close the underlying conn.
    pub fn close_conn(mut self) -> error {
        let _ = self.flush();
        self.conn.Close()
    }
}

/// Build the response head (status line + headers + final CRLF).
/// Shared between buffered and streaming modes. Returns the bytes
/// ready to write to the wire.
fn build_head(status: int, header: &Header) -> Vec<u8> {
    let mut buf: Vec<u8> = Vec::with_capacity(256);
    buf.extend_from_slice(b"HTTP/1.1 ");
    push_dec(&mut buf, status as u32);
    buf.push(b' ');
    buf.extend_from_slice(status_text(status as u32).as_bytes());
    buf.extend_from_slice(b"\r\n");
    let inner = header.__inner();
    for (key, values) in inner.__iter() {
        let n = values.Len();
        for i in 0..n {
            buf.extend_from_slice(key.as_bytes());
            buf.extend_from_slice(b": ");
            buf.extend_from_slice(values[i].as_bytes());
            buf.extend_from_slice(b"\r\n");
        }
    }
    buf.extend_from_slice(b"\r\n");
    buf
}

/// Emit one chunk on the wire: `<hex>\r\n<data>\r\n`. Returns
/// `(data.len(), err)` so a `Write` proxy can forward it.
fn write_chunk(conn: &mut Conn, data: &slice<byte>) -> (int, error) {
    let n = data.Len();
    if n == 0 {
        return (0, errors::nil);
    }
    let mut head: Vec<u8> = Vec::with_capacity(20);
    push_hex(&mut head, n as u64);
    head.extend_from_slice(b"\r\n");
    let (_, err) = conn.Write(slice::<byte>::__from_vec(head));
    if !err.IsNil() {
        return (0, err);
    }
    let (_, werr) = conn.Write(data.clone());
    if !werr.IsNil() {
        return (0, werr);
    }
    let (_, terr) = conn.Write(slice::<byte>::__from_vec(alloc::vec![b'\r', b'\n']));
    (n, terr)
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

/// Standard reason phrases for the status codes a handler is most
/// likely to use. Falls back to "Status NNN" for unknown codes —
/// HTTP allows arbitrary phrases as long as the numeric code is
/// recognized by the client.
fn status_text(code: u32) -> &'static str {
    match code {
        100 => "Continue",
        200 => "OK",
        201 => "Created",
        202 => "Accepted",
        204 => "No Content",
        301 => "Moved Permanently",
        302 => "Found",
        304 => "Not Modified",
        400 => "Bad Request",
        401 => "Unauthorized",
        403 => "Forbidden",
        404 => "Not Found",
        405 => "Method Not Allowed",
        408 => "Request Timeout",
        409 => "Conflict",
        413 => "Payload Too Large",
        414 => "URI Too Long",
        429 => "Too Many Requests",
        500 => "Internal Server Error",
        501 => "Not Implemented",
        502 => "Bad Gateway",
        503 => "Service Unavailable",
        504 => "Gateway Timeout",
        _ => "Status",
    }
}

fn push_dec(buf: &mut Vec<u8>, mut n: u32) {
    if n == 0 {
        buf.push(b'0');
        return;
    }
    let mut tmp = [0u8; 10];
    let mut i = 0;
    while n > 0 {
        tmp[i] = b'0' + (n % 10) as u8;
        n /= 10;
        i += 1;
    }
    while i > 0 {
        i -= 1;
        buf.push(tmp[i]);
    }
}

fn int_to_string(n: i64) -> string {
    let mut buf: Vec<u8> = Vec::with_capacity(20);
    if n < 0 {
        buf.push(b'-');
        push_dec_64(&mut buf, (-n) as u64);
    } else {
        push_dec_64(&mut buf, n as u64);
    }
    string::from_bytes(&buf)
}

fn push_dec_64(buf: &mut Vec<u8>, mut n: u64) {
    if n == 0 {
        buf.push(b'0');
        return;
    }
    let mut tmp = [0u8; 20];
    let mut i = 0;
    while n > 0 {
        tmp[i] = b'0' + (n % 10) as u8;
        n /= 10;
        i += 1;
    }
    while i > 0 {
        i -= 1;
        buf.push(tmp[i]);
    }
}

// io::Writer impl for handlers that pass `w` to fmt/io::Copy/etc.
impl io::Writer for ResponseWriter {
    fn Write(&mut self, p: slice<byte>) -> (int, error) {
        ResponseWriter::Write(self, p)
    }
}
