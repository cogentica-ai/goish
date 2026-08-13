// net/http/httputil/dump.go — DumpRequest and DumpResponse.

#![allow(non_snake_case)]
#![allow(dead_code)]

use crate::errors::{self, error};
use crate::gomap::map;
use crate::goslice::slice;
use crate::string;
use crate::strings;
use crate::types::byte;

use super::super::client::Response;
use super::super::request::Request;

// go: sdk 1.25.5 net/http/httputil/dump.go:218-286 DumpRequest
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

    return (out, errors::nil);
}

// go: sdk 1.25.5 net/http/httputil/dump.go:305-337 DumpResponse
/// `httputil.DumpResponse(resp, body) -> ([]byte, error)` — render a
/// Response in HTTP/1.x wire format. Line-by-line port of dump.go:305.
///
/// In Go, this delegates to `Response.Write`. Goish doesn't have a
/// Response.Write yet; we inline the wire serialization (status line +
/// headers + optional body) which is the dominant path anyway.
pub fn DumpResponse(resp: &Response, body: bool) -> (slice<byte>, error) {
    // Go: drainBody — read the body fully, then leave the Response
    // holding an equivalent re-readable copy. Streaming bodies get
    // drained off the conn here (and the conn released).
    let mut body_bytes = slice::<byte>::__from_vec(alloc::vec::Vec::new());
    if body {
        let (bb, derr) = resp.Body.__drain_remainder();
        if !derr.IsNil() {
            return (slice::<byte>::__from_vec(alloc::vec::Vec::new()), derr);
        }
        body_bytes = bb;
    }

    let mut b = strings::Builder::new();
    b.Grow(256 + body_bytes.Len());

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
        super::super::status::StatusText(resp.StatusCode)
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
    if body && body_bytes.Len() > 0 {
        for i in 0..body_bytes.Len() {
            out = crate::append!(out, body_bytes[i]);
        }
    }
    return (out, errors::nil);
}

// ─── ReverseProxy (slim port of reverseproxy.go) ─────────────────────

