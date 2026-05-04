// net/http/httputil — slim port of Go's net/http/httputil package.
//
// Currently provides DumpRequest, DumpResponse, NewChunkedReader,
// NewChunkedWriter, ErrLineTooLong, NewSingleHostReverseProxy.

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

/// `httputil.ErrLineTooLong` (httputil.go:43) — re-export of
/// `chunked::ErrLineTooLong`. Same Arc identity.
pub use super::chunked::ErrLineTooLong;

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

// ─── ReverseProxy (slim port of reverseproxy.go) ─────────────────────

/// `httputil.NewSingleHostReverseProxy(target)` (reverseproxy.go:275).
/// Returns a Handler that forwards every incoming request to `target`,
/// rewriting the URL's Scheme/Host/Path and stripping hop-by-hop
/// headers in both directions.
///
/// Slim deviations from Go:
///   - No Director, ModifyResponse, ErrorHandler, or Transport hooks
///     (the proxy uses a default `http::Client`).
///   - No streaming Body — request body is `slice<byte>` already.
///   - No X-Forwarded-For / X-Forwarded-Host injection (slim).
///   - No connection upgrade (websocket) handling.
///
/// Sufficient for in-process reverse-proxy demos and basic load
/// balancers; not a drop-in for Go's hardened `httputil.ReverseProxy`.
pub fn NewSingleHostReverseProxy(
    target: super::url::URL,
) -> alloc::sync::Arc<dyn super::server::Handler> {
    alloc::sync::Arc::new(reverseProxyHandler {
        target,
        client: alloc::sync::Arc::new(super::client::Client::default()),
    })
}

#[allow(non_camel_case_types)]
struct reverseProxyHandler {
    target: super::url::URL,
    client: alloc::sync::Arc<super::client::Client>,
}

/// Hop-by-hop headers (RFC 7230). Stripped before forwarding the
/// request and before relaying the response back to the original
/// client. Mirrors Go's `hopHeaders` (reverseproxy.go:307).
const HOP_HEADERS: &[&str] = &[
    "Connection",
    "Proxy-Connection",
    "Keep-Alive",
    "Proxy-Authenticate",
    "Proxy-Authorization",
    "Te",
    "Trailer",
    "Transfer-Encoding",
    "Upgrade",
];

fn is_hop_header(name: &string) -> bool {
    for h in HOP_HEADERS.iter() {
        if crate::strings::EqualFold(name.clone(), string(*h)) {
            return true;
        }
    }
    false
}

/// `joinURLPath` (reverseproxy.go: ~the unexported helper). Appends
/// req's path to target's, gluing with a single '/'.
fn join_url_path(target_path: &string, req_path: &string) -> string {
    let a = target_path.clone();
    let b = req_path.clone();
    let a_slash = crate::strings::HasSuffix(a.clone(), string("/"));
    let b_slash = crate::strings::HasPrefix(b.clone(), string("/"));
    let mut out = strings::Builder::new();
    if a_slash && b_slash {
        let _ = out.WriteString(a.clone());
        let trimmed = crate::strings::TrimPrefix(b, string("/"));
        let _ = out.WriteString(trimmed);
    } else if !a_slash && !b_slash {
        let _ = out.WriteString(a.clone());
        if a.Len() > 0 && b.Len() > 0 {
            let _ = out.WriteByte(b'/');
        }
        let _ = out.WriteString(b);
    } else {
        let _ = out.WriteString(a);
        let _ = out.WriteString(b);
    }
    out.String()
}

impl super::server::Handler for reverseProxyHandler {
    fn ServeHTTP(
        &self,
        w: &mut super::response::ResponseWriter,
        r: &super::request::Request,
    ) {
        // Go: outreq := req.Clone(req.Context())
        let mut outreq = r.clone();

        // Go: rewriteRequestURL(req, target)
        outreq.URL.Scheme = self.target.Scheme.clone();
        outreq.URL.Host = self.target.Host.clone();
        outreq.URL.Path = join_url_path(&self.target.Path, &r.URL.Path);
        outreq.URL.RawPath = outreq.URL.Path.clone();
        // Combine target query with request query, preferring incoming.
        if self.target.RawQuery.Len() > 0 || r.URL.RawQuery.Len() > 0 {
            if self.target.RawQuery.Len() == 0 || r.URL.RawQuery.Len() == 0 {
                let mut q = strings::Builder::new();
                let _ = q.WriteString(self.target.RawQuery.clone());
                let _ = q.WriteString(r.URL.RawQuery.clone());
                outreq.URL.RawQuery = q.String();
            } else {
                let mut q = strings::Builder::new();
                let _ = q.WriteString(self.target.RawQuery.clone());
                let _ = q.WriteByte(b'&');
                let _ = q.WriteString(r.URL.RawQuery.clone());
                outreq.URL.RawQuery = q.String();
            }
        }
        // Drop the original Host so URL.Host wins on serialization.
        outreq.Host = string::new();

        // Go: removeHopByHopHeaders(outreq.Header)
        let inner = outreq.Header.__inner().clone();
        for (k, _) in inner.__iter() {
            if is_hop_header(k) {
                outreq.Header.Del(k.clone());
            }
        }

        // Go: roundTrip via Transport / our Client.
        let (resp, err) = self.client.Do(&outreq);
        if !err.IsNil() {
            super::server::Error(
                w,
                string("Bad Gateway"),
                super::status::StatusBadGateway,
            );
            return;
        }

        // Go: copyHeader(rw.Header(), res.Header) minus hop-by-hop.
        let r_inner = resp.Header.__inner();
        for (k, vs) in r_inner.__iter() {
            if is_hop_header(k) {
                continue;
            }
            for i in 0..vs.Len() {
                w.Header().Add(k.clone(), vs[i].clone());
            }
        }

        // Go: rw.WriteHeader(res.StatusCode)
        w.WriteHeader(resp.StatusCode);

        // Go: io.Copy(rw, res.Body)
        let _ = w.Write(resp.Body);
    }
}
