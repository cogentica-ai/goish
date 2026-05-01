// net/http/httputil — slim port of Go's net/http/httputil package.
//
// Currently provides DumpRequest, DumpResponse, NewChunkedReader,
// NewChunkedWriter, ErrLineTooLong. Future iterations will add
// ReverseProxy.

#![allow(non_snake_case)]
#![allow(dead_code)]

use crate::errors::{self, error};
use crate::gomap::map;
use crate::goslice::slice;
use crate::io::{Reader, Writer};
use crate::string;
use crate::strings;
use crate::types::byte;

use super::chunked::{ChunkedReader, ChunkedWriter};
use super::client::Response;
use super::request::Request;

// ─── Chunked Reader / Writer wrappers ────────────────────────────────

/// `httputil.NewChunkedReader(r)` (httputil.go:21) — translate from
/// HTTP "chunked" format. Returns an `io.Reader` that yields the
/// dechunked body and signals EOF on the terminator. Thin wrapper
/// over the internal `chunked.NewChunkedReader`.
pub fn NewChunkedReader<R: Reader>(r: R) -> ChunkedReader<R> {
    super::chunked::NewChunkedReader(r)
}

/// `httputil.NewChunkedWriter(w)` (httputil.go:36) — wrap `w` so
/// writes are emitted as HTTP "chunked" frames. Closing the writer
/// sends the terminating zero-length chunk but not the trailing CRLF
/// — callers writing trailers (or a final empty trailer) must emit
/// the closing CRLF themselves.
pub fn NewChunkedWriter<W: Writer>(w: W) -> ChunkedWriter<W> {
    super::chunked::NewChunkedWriter(w)
}

/// `httputil.ErrLineTooLong` (httputil.go:43) — sentinel returned by
/// `NewChunkedReader` when a chunk-extension line exceeds the 4 KiB
/// limit.
pub fn ErrLineTooLong() -> error {
    super::chunked::ErrLineTooLong()
}

/// `httputil.DumpRequest(req, body) -> ([]byte, error)` — render a
/// Request in HTTP/1.x wire format. Line-by-line port of Go 1.25
/// src/net/http/httputil/dump.go:218.
///
/// If `body` is true, the request body is included verbatim. Goish's
/// `req.Body` is already a buffered slice<byte>, so no `drainBody`
/// dance is needed (Go has to read+restore from io.ReadCloser).
pub fn DumpRequest(req: &Request, body: bool) -> (slice<byte>, error) {
    // Go: var b bytes.Buffer
    let mut b = strings::Builder::new();
    b.Grow(256 + req.Body.Len());

    // Go: reqURI := req.RequestURI; if reqURI == "" { reqURI = req.URL.RequestURI() }
    // Goish doesn't store RequestURI separately; build from URL.Path + RawQuery.
    let mut req_uri = strings::Builder::new();
    if req.URL.Path.Len() == 0 {
        let _ = req_uri.WriteByte(b'/');
    } else {
        let _ = req_uri.WriteString(req.URL.Path.clone());
    }
    if req.URL.RawQuery.Len() > 0 {
        let _ = req_uri.WriteByte(b'?');
        let _ = req_uri.WriteString(req.URL.RawQuery.clone());
    }
    let req_uri = req_uri.String();

    // Go: fmt.Fprintf(&b, "%s %s HTTP/%d.%d\r\n", method, reqURI, major, minor)
    let method = if req.Method.Len() == 0 {
        string("GET")
    } else {
        req.Method.clone()
    };
    let _ = b.WriteString(method);
    let _ = b.WriteByte(b' ');
    let _ = b.WriteString(req_uri.clone());
    let _ = b.WriteByte(b' ');
    let _ = b.WriteString(string("HTTP/1.1\r\n"));

    // Go: absRequestURI := strings.HasPrefix(req.RequestURI, "http://") ...
    let abs_req_uri = strings::HasPrefix(req_uri.clone(), string("http://"))
        || strings::HasPrefix(req_uri.clone(), string("https://"));
    if !abs_req_uri {
        // Go: host := req.Host; if host == "" && req.URL != nil { host = req.URL.Host }
        let host = if req.Host.Len() > 0 {
            req.Host.clone()
        } else {
            req.URL.Host.clone()
        };
        if host.Len() > 0 {
            // Go: fmt.Fprintf(&b, "Host: %s\r\n", host)
            let _ = b.WriteString(string("Host: "));
            let _ = b.WriteString(host);
            let _ = b.WriteString(string("\r\n"));
        }
    }

    // Go: chunked := req.TransferEncoding[0] == "chunked" — read from header.
    let te = req.Header.Get(string("Transfer-Encoding"));
    if te.Len() > 0 {
        let _ = b.WriteString(string("Transfer-Encoding: "));
        let _ = b.WriteString(te.clone());
        let _ = b.WriteString(string("\r\n"));
    }

    // Go: req.Header.WriteSubset(&b, reqWriteExcludeHeaderDump)
    // The dump-exclude set: Host, Content-Length, Transfer-Encoding,
    // Trailer (we synthesize them or already wrote them).
    let mut excl: map<string, bool> = map::<string, bool>::new();
    excl.Set(string("Host"), true);
    excl.Set(string("Content-Length"), true);
    excl.Set(string("Transfer-Encoding"), true);
    excl.Set(string("Trailer"), true);
    let mut head_buf = crate::bytes::NewBuffer(slice::<byte>::__from_vec(alloc::vec::Vec::new()));
    let werr = req.Header.WriteSubset(&mut head_buf, &excl);
    if !werr.IsNil() {
        return (slice::<byte>::__from_vec(alloc::vec::Vec::new()), werr);
    }
    // Concatenate the WriteSubset output via slice<byte> indexing.
    let head_bytes = head_buf.Bytes();
    for i in 0..head_bytes.Len() {
        let _ = b.WriteByte(head_bytes[i]);
    }

    // Go: io.WriteString(&b, "\r\n")
    let _ = b.WriteString(string("\r\n"));

    // Go: if req.Body != nil { … }
    let mut out = crate::convert::bytes(b.String());
    if body && req.Body.Len() > 0 {
        for i in 0..req.Body.Len() {
            out = crate::append!(out, req.Body[i]);
        }
    }

    (out, errors::nil)
}

/// `httputil.DumpResponse(resp, body) -> ([]byte, error)` — render a
/// Response in HTTP/1.x wire format. Line-by-line port of dump.go:305.
///
/// In Go, this delegates to `Response.Write`. Goish doesn't have a
/// Response.Write yet; we inline the wire serialization (status line +
/// headers + optional body) which is the dominant path anyway.
pub fn DumpResponse(resp: &Response, body: bool) -> (slice<byte>, error) {
    let mut b = strings::Builder::new();
    b.Grow(256 + resp.Body.Len());

    // Status line: "HTTP/X.Y CODE STATUS_TEXT\r\n"
    let _ = b.WriteString(string("HTTP/"));
    let _ = b.WriteString(crate::strconv::Itoa(resp.ProtoMajor));
    let _ = b.WriteByte(b'.');
    let _ = b.WriteString(crate::strconv::Itoa(resp.ProtoMinor));
    let _ = b.WriteByte(b' ');
    let _ = b.WriteString(crate::strconv::Itoa(resp.StatusCode));
    let _ = b.WriteByte(b' ');
    // Go: include the `Status` text or fall back to StatusText(StatusCode).
    let st = if resp.Status.Len() > 0 {
        // Status is "200 OK" — strip the leading code if present.
        let space = strings::IndexByte(resp.Status.clone(), b' ');
        if space >= 0 {
            // Drop the "200 " prefix; keep "OK"
            let raw = resp.Status.clone();
            let rest_bytes = &raw.as_bytes()[(space + 1) as usize..];
            string::from_bytes(rest_bytes)
        } else {
            resp.Status.clone()
        }
    } else {
        super::status::StatusText(resp.StatusCode)
    };
    let _ = b.WriteString(st);
    let _ = b.WriteString(string("\r\n"));

    // Content-Length / Transfer-Encoding from the canonical fields.
    if resp.ContentLength >= 0 {
        let _ = b.WriteString(string("Content-Length: "));
        let _ = b.WriteString(crate::strconv::Itoa(resp.ContentLength));
        let _ = b.WriteString(string("\r\n"));
    } else {
        // Go: TransferEncoding may be set; we approximate by checking
        // for a chunked Transfer-Encoding header.
        let te = resp.Header.Get(string("Transfer-Encoding"));
        if te.Len() > 0 {
            let _ = b.WriteString(string("Transfer-Encoding: "));
            let _ = b.WriteString(te);
            let _ = b.WriteString(string("\r\n"));
        }
    }

    // User-set headers, sorted, excluding ones we synthesize.
    let mut excl: map<string, bool> = map::<string, bool>::new();
    excl.Set(string("Content-Length"), true);
    excl.Set(string("Transfer-Encoding"), true);
    let mut head_buf = crate::bytes::NewBuffer(slice::<byte>::__from_vec(alloc::vec::Vec::new()));
    let werr = resp.Header.WriteSubset(&mut head_buf, &excl);
    if !werr.IsNil() {
        return (slice::<byte>::__from_vec(alloc::vec::Vec::new()), werr);
    }
    let head_bytes = head_buf.Bytes();
    for i in 0..head_bytes.Len() {
        let _ = b.WriteByte(head_bytes[i]);
    }

    // Header/body separator.
    let _ = b.WriteString(string("\r\n"));

    // Optional body.
    let mut out = crate::convert::bytes(b.String());
    if body && resp.Body.Len() > 0 {
        for i in 0..resp.Body.Len() {
            out = crate::append!(out, resp.Body[i]);
        }
    }
    (out, errors::nil)
}
