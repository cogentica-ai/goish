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
/// `close_conn` ends its lifecycle. v1 buffers the body internally;
/// `flush` writes status + headers (including a derived
/// `Content-Length`) + body in one wire send.
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
    /// Buffered body. v1 requires the full body in memory so
    /// `flush` can compute Content-Length.
    body: Vec<u8>,
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

    /// `Write(p)` — append `p` to the body buffer. Implicitly calls
    /// `WriteHeader(200)` on first call. Returns `(p.len(), nil)` —
    /// buffered writes never report short writes.
    pub fn Write(&mut self, p: slice<byte>) -> (int, error) {
        if !self.wrote_header {
            self.WriteHeader(200);
        }
        self.body.extend_from_slice(&*p);
        (p.len() as int, errors::nil)
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

        // Emit Content-Length derived from buffered body. Required
        // for HTTP/1.1 keep-alive framing without chunked encoding.
        if self.header.Get(string("Content-Length")).Len() == 0 {
            self.header
                .Set(string("Content-Length"), int_to_string(self.body.len() as i64));
        }
        // Connection header policy:
        //   keep_alive  → don't emit Connection (HTTP/1.1 default).
        //   !keep_alive → emit Connection: close.
        if !self.keep_alive && self.header.Get(string("Connection")).Len() == 0 {
            self.header.Set(string("Connection"), string("close"));
        }

        let mut buf: Vec<u8> = Vec::with_capacity(256 + self.body.len());
        buf.extend_from_slice(b"HTTP/1.1 ");
        push_dec(&mut buf, self.status as u32);
        buf.push(b' ');
        buf.extend_from_slice(status_text(self.status as u32).as_bytes());
        buf.extend_from_slice(b"\r\n");

        let inner = self.header.__inner();
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

    /// Convenience for examples that drive their own accept loop:
    /// flush headers (if not yet) and close the underlying conn.
    pub fn close_conn(mut self) -> error {
        let _ = self.flush();
        self.conn.Close()
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
