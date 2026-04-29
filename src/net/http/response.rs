// net/http/response — ResponseWriter.
//
// Slim port of Go's `http.ResponseWriter` interface and the default
// implementation that writes onto the bufio.Writer<Conn> bound to a
// connection. We materialize ResponseWriter as a concrete struct
// (not a trait) for v1 — handlers receive `&mut ResponseWriter`.
// Promotion to a trait is a future refactor.

#![allow(non_snake_case)]

extern crate alloc;

use alloc::vec::Vec;

use crate::errors::{self, error};
use crate::goslice::slice;
use crate::io::{self, Writer};
use crate::net::Conn;
use crate::string;
use crate::types::{byte, int};

use super::header::Header;

/// `http.ResponseWriter`. Owns a buffered handle to the connection.
/// Handler code calls `Header()` / `WriteHeader(status)` / `Write(p)`.
///
/// **Lifecycle**: built by `serve_conn` per request, dropped after
/// the handler returns. The drop path flushes the headers if the
/// handler never wrote a body.
pub struct ResponseWriter {
    /// The connection. Internal — body bytes go to it via Write.
    /// We don't wrap in `bufio::Writer` for v1 because that would
    /// force ownership of the conn into the writer; the server
    /// keeps it for keep-alive read-back. Direct writes are fine
    /// for the volumes a one-handler response generates.
    conn: Conn,
    header: Header,
    /// `true` after `WriteHeader` (or the first `Write`) sent the
    /// status line + headers onto the wire. From this point on
    /// `Header()` mutations are silently ignored (Go panics in
    /// debug; we silently drop).
    wrote_header: bool,
    /// Status code captured at WriteHeader time.
    status: int,
}

impl ResponseWriter {
    /// Build a fresh `ResponseWriter` over `conn`. Public so callers
    /// running their own accept loop (e.g. examples that need to
    /// print the port before serving) can reuse the same response
    /// path the server's internal `serve_conn` does.
    pub fn new(conn: Conn) -> Self {
        let mut h = Header::new();
        h.Set(string("Content-Type"), string("text/plain; charset=utf-8"));
        ResponseWriter {
            conn,
            header: h,
            wrote_header: false,
            status: 200,
        }
    }

    /// `Header()` returns the response header map. Mutations made
    /// before the first `Write` / `WriteHeader` flush onto the wire.
    pub fn Header(&mut self) -> &mut Header {
        &mut self.header
    }

    /// `WriteHeader(status)` — emit the status line + headers.
    /// Idempotent: subsequent calls are no-ops (matching Go's
    /// "second WriteHeader" warning behavior).
    pub fn WriteHeader(&mut self, status: int) {
        if self.wrote_header {
            return;
        }
        self.wrote_header = true;
        self.status = status;
        self.flush_headers();
    }

    /// `Write(p)` — emit body bytes. Implicitly calls
    /// `WriteHeader(200)` on first call if the handler hasn't yet.
    pub fn Write(&mut self, p: slice<byte>) -> (int, error) {
        if !self.wrote_header {
            self.WriteHeader(200);
        }
        self.conn.Write(p)
    }

    /// Internal: render `HTTP/1.1 <status> <reason>\r\n` + each
    /// header line + the empty separator. Direct write — buffer
    /// once, single syscall on the wire.
    fn flush_headers(&mut self) {
        let mut buf: Vec<u8> = Vec::with_capacity(256);
        buf.extend_from_slice(b"HTTP/1.1 ");
        push_dec(&mut buf, self.status as u32);
        buf.push(b' ');
        buf.extend_from_slice(status_text(self.status as u32).as_bytes());
        buf.extend_from_slice(b"\r\n");

        // Default to Connection: close in v1 (no keep-alive).
        if self.header.Get(string("Connection")).Len() == 0 {
            self.header
                .Set(string("Connection"), string("close"));
        }

        // Walk the header map.
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
        let _ = self.conn.Write(slice::<byte>::__from_vec(buf));
    }

    /// Flush headers (if not yet) and close the underlying conn.
    /// Public for the same reason as `new` — examples that drive
    /// their own accept loop call this after the handler returns.
    pub fn close_conn(mut self) -> error {
        if !self.wrote_header {
            // Empty body but still need to flush a 200.
            self.WriteHeader(200);
        }
        use crate::io::Closer;
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

// io::Writer impl for handlers that pass `w` to fmt/io::Copy/etc.
impl io::Writer for ResponseWriter {
    fn Write(&mut self, p: slice<byte>) -> (int, error) {
        ResponseWriter::Write(self, p)
    }
}
