// net/http/request — Request type + ReadRequest parser.
//
// Slim port of Go's net/http.Request and ReadRequest
// (Go 1.25 src/net/http/request.go:1058).
//
// Subset implemented:
//   - HTTP/1.0 and HTTP/1.1 origin-form / absolute-form request-target.
//   - Header parsing per RFC 7230, with continuation-line folding NOT
//     supported (deprecated in HTTP/1.1).
//   - Body: read fully into a slice<byte> before the handler runs.
//     Bounded by Content-Length; zero bytes if absent.
//
// Out of scope (v1):
//   - Chunked transfer-encoding on incoming bodies.
//   - Trailers.
//   - Multipart parsing (handled at higher layers in user code).

#![allow(non_snake_case)]

extern crate alloc;

use alloc::vec::Vec;

use crate::bufio;
use crate::bytes;
use crate::errors::{self, error};
use crate::goslice::slice;
use crate::io::{self, Reader};
use crate::string;
use crate::types::{byte, int};

use super::header::{canonical_key, Header};
use super::url::{parse_request_uri, URL};

/// `net/http.Request`. Slim — only fields a handler typically reads.
#[derive(Clone)]
pub struct Request {
    pub Method: string,
    pub URL: URL,
    pub Proto: string,    // "HTTP/1.1"
    pub ProtoMajor: int,
    pub ProtoMinor: int,
    pub Header: Header,
    pub Host: string,
    pub ContentLength: int, // -1 if unknown
    /// Fully-buffered request body. Bounded by `Content-Length`.
    /// Empty for GET/HEAD/no-body methods.
    ///
    /// **Deviation from Go**: Go exposes `Body io.ReadCloser` for
    /// streaming. Goish v1 reads the body upfront — callers wrap it
    /// in `bytes::NewReader` if they want a `Reader`. For the
    /// sub-MB requests typical of REST APIs this is the same
    /// observable behavior with simpler lifetimes.
    pub Body: slice<byte>,
    pub RemoteAddr: string,
}

impl Request {
    /// Convenience: `bytes::Reader` over `Body` so handler code that
    /// expects an `io::Reader` (`json::NewDecoder(req.body_reader())`)
    /// keeps working. Mirrors what `Request.Body io.Reader` would
    /// return in Go.
    pub fn body_reader(&self) -> bytes::Reader {
        bytes::NewReader(self.Body.clone())
    }

    /// `r.Cookies()` — parse all `Cookie:` request headers. Mirrors
    /// `(*Request).Cookies()` (request.go:404).
    pub fn Cookies(&self) -> slice<super::cookie::Cookie> {
        super::cookie::read_cookies(&self.Header, &string::new())
    }

    /// `r.Cookie(name)` — return the named cookie, or
    /// `(Cookie::default(), ErrNoCookie)` if absent. Mirrors
    /// `(*Request).Cookie(name)` (request.go:418).
    pub fn Cookie(&self, name: string) -> (super::cookie::Cookie, error) {
        let matches = super::cookie::read_cookies(&self.Header, &name);
        if matches.Len() > 0 {
            return (matches[0].clone(), errors::nil);
        }
        (
            super::cookie::Cookie::default(),
            errors::New(string("http: named cookie not present")),
        )
    }

    /// `r.AddCookie(c)` — append a cookie to the `Cookie:` request
    /// header. Mirrors `(*Request).AddCookie(c)` (request.go:434);
    /// per RFC 6265 the request only has a single `Cookie:` line, so
    /// repeat calls fold into one space+`; `-separated value.
    pub fn AddCookie(&mut self, c: &super::cookie::Cookie) {
        let s = c.String();
        if s.Len() == 0 {
            return;
        }
        let existing = self.Header.Get(string("Cookie"));
        if existing.Len() == 0 {
            self.Header.Set(string("Cookie"), s);
        } else {
            let mut buf: Vec<u8> = Vec::with_capacity((existing.Len() + s.Len()) as usize + 2);
            buf.extend_from_slice(existing.as_bytes());
            buf.extend_from_slice(b"; ");
            buf.extend_from_slice(s.as_bytes());
            self.Header.Set(string("Cookie"), string::from_bytes(&buf));
        }
    }
}

// ─── ReadRequest ─────────────────────────────────────────────────────

const MAX_LINE: usize = 8 * 1024;
const MAX_HEADERS: usize = 100;
const MAX_BODY: usize = 16 * 1024 * 1024; // 16 MiB safety cap

/// `http.ReadRequest(b *bufio.Reader)` — parse an HTTP/1.x request
/// from the given buffered reader. Mirrors Go's
/// `func ReadRequest(b *bufio.Reader) (*Request, error)`
/// (request.go:1058).
///
/// On success the reader is positioned at the first byte after the
/// final CRLF of the request body (or after the headers if no body).
pub fn ReadRequest<R: io::Reader>(
    br: &mut bufio::Reader<R>,
) -> (Request, error) {
    let mut req = Request {
        Method: string::new(),
        URL: URL::empty(),
        Proto: string::new(),
        ProtoMajor: 0,
        ProtoMinor: 0,
        Header: Header::new(),
        Host: string::new(),
        ContentLength: 0,
        Body: slice::<byte>::__from_vec(Vec::new()),
        RemoteAddr: string::new(),
    };

    // Request-line: METHOD SP request-target SP HTTP-version CRLF
    let line = match read_line(br, MAX_LINE) {
        Ok(l) => l,
        Err(e) => return (req, e),
    };
    let (method, target, proto) = match parse_request_line(&line) {
        Some(t) => t,
        None => return (req, errors::New(string("net/http: malformed request line"))),
    };

    if !valid_method(method.as_bytes()) {
        return (req, errors::New(string("net/http: invalid method")));
    }
    let (major, minor) = match parse_http_version(proto.as_bytes()) {
        Some(v) => v,
        None => return (req, errors::New(string("net/http: malformed HTTP version"))),
    };

    let url = match parse_request_uri(&target) {
        Ok(u) => u,
        Err(msg) => return (req, errors::New(msg)),
    };

    req.Method = method;
    req.URL = url;
    req.Proto = proto;
    req.ProtoMajor = major;
    req.ProtoMinor = minor;

    // Headers: lines of `Name: value` ending with an empty line.
    let mut count = 0;
    loop {
        let line = match read_line(br, MAX_LINE) {
            Ok(l) => l,
            Err(e) => return (req, e),
        };
        if line.as_bytes().is_empty() {
            break; // end of headers
        }
        count += 1;
        if count > MAX_HEADERS {
            return (req, errors::New(string("net/http: too many headers")));
        }
        let (name, value) = match parse_header_line(&line) {
            Some(t) => t,
            None => return (req, errors::New(string("net/http: malformed header"))),
        };
        // Special-case Host: into req.Host, not into Header.
        let canon = canonical_key(&name);
        if canon.as_bytes() == b"Host" {
            req.Host = value;
        } else {
            req.Header.Add(name, value);
        }
    }

    // Body framing — Transfer-Encoding: chunked takes precedence over
    // Content-Length per RFC 7230 §3.3.3.
    let te = req.Header.Get(string("Transfer-Encoding"));
    let chunked = is_chunked(te.as_bytes());
    if chunked {
        // Decode chunked body into a Vec, then drop into req.Body.
        // ContentLength = -1 ("unknown") matches Go's convention.
        req.ContentLength = -1;
        let mut buf: Vec<u8> = Vec::new();
        // ChunkedReader sits over `br` directly via a small adapter:
        // we hand it ownership of a &mut bufio::Reader-like surface.
        // Simplest: drain the bufio::Reader's Buffered() bytes plus
        // any future reads through the chunked decoder. Since
        // `ChunkedReader<R>` wraps its own bufio::Reader, we feed it
        // a thin `BufioPassthrough` that delegates to the existing
        // `br`.
        let mut cr = super::chunked::NewChunkedReader(BufioPassthrough { inner: br });
        loop {
            let mut tmp = slice::<byte>::__from_vec(alloc::vec![0u8; 4096]);
            let (n_read, err) = cr.Read(&mut tmp);
            if n_read > 0 {
                let n_us = n_read as usize;
                if buf.len() + n_us > MAX_BODY {
                    return (req, errors::New(string("net/http: chunked body too large")));
                }
                for i in 0..n_us {
                    buf.push(tmp[i as int]);
                }
            }
            if !err.IsNil() {
                if errors::Is(err.clone(), io::EOF()) {
                    break;
                }
                return (req, err);
            }
            if n_read == 0 {
                break;
            }
        }
        req.Body = slice::<byte>::__from_vec(buf);
        return (req, errors::nil);
    }

    // Content-Length → bounded body.
    let cl_str = req.Header.Get(string("Content-Length"));
    let n: int = if cl_str.as_bytes().is_empty() {
        0
    } else {
        match parse_dec(cl_str.as_bytes()) {
            Some(n) if n >= 0 && (n as usize) <= MAX_BODY => n,
            _ => return (req, errors::New(string("net/http: invalid Content-Length"))),
        }
    };
    req.ContentLength = n;

    if n > 0 {
        let want = n as usize;
        let mut buf: Vec<u8> = Vec::with_capacity(want);
        let mut got: usize = 0;
        while got < want {
            let chunk = (want - got).min(4096);
            let scratch_vec: Vec<u8> = alloc::vec![0u8; chunk];
            let mut scratch = slice::<byte>::__from_vec(scratch_vec);
            let (n_read, err) = br.Read(&mut scratch);
            if n_read > 0 {
                let n_us = n_read as usize;
                let v: Vec<u8> = scratch.__into_vec();
                buf.extend_from_slice(&v[..n_us]);
                got += n_us;
            } else if !err.IsNil() {
                return (req, err);
            } else {
                return (req, errors::New(string("net/http: read returned 0 bytes")));
            }
        }
        req.Body = slice::<byte>::__from_vec(buf);
    }

    (req, errors::nil)
}

/// Adapter so ChunkedReader (which builds its *own* bufio::Reader)
/// can pull bytes from the request parser's existing bufio::Reader
/// without double-buffering. ChunkedReader wraps this in a fresh
/// bufio of its own — that's a small extra buffer, but the alternative
/// would require ChunkedReader to take a borrowed bufio which clashes
/// with its current `R: Reader` API shape.
struct BufioPassthrough<'a, R: io::Reader> {
    inner: &'a mut bufio::Reader<R>,
}
impl<'a, R: io::Reader> io::Reader for BufioPassthrough<'a, R> {
    fn Read(&mut self, b: &mut slice<byte>) -> (int, error) {
        self.inner.Read(b)
    }
}

/// Match RFC 7230 `Transfer-Encoding: chunked` (case-insensitive,
/// possibly part of a comma-separated list — we accept any list whose
/// last item is `chunked`).
fn is_chunked(value: &[u8]) -> bool {
    // Trim and lowercase walk; check trailing token == "chunked".
    let mut end = value.len();
    while end > 0 && (value[end - 1] == b' ' || value[end - 1] == b'\t') {
        end -= 1;
    }
    let mut start = end;
    while start > 0 {
        let prev = value[start - 1];
        if prev == b',' || prev == b' ' || prev == b'\t' {
            break;
        }
        start -= 1;
    }
    let last = &value[start..end];
    last.len() == 7
        && (last[0] | 0x20) == b'c'
        && (last[1] | 0x20) == b'h'
        && (last[2] | 0x20) == b'u'
        && (last[3] | 0x20) == b'n'
        && (last[4] | 0x20) == b'k'
        && (last[5] | 0x20) == b'e'
        && (last[6] | 0x20) == b'd'
}

// ─── parsers ─────────────────────────────────────────────────────────

/// Read a CRLF-terminated line via `bufio.Reader`. Returns the line
/// **without** the trailing CRLF, or an error on EOF / oversize.
fn read_line<R: io::Reader>(
    br: &mut bufio::Reader<R>,
    max: usize,
) -> Result<string, error> {
    let (line_bytes, err) = br.ReadBytes(b'\n');
    if !err.IsNil() {
        return Err(err);
    }
    // Deref slice<byte> → &[u8] for bounds + indexing.
    let bs: &[u8] = &*line_bytes;
    if bs.len() > max {
        return Err(errors::New(string("net/http: header line too long")));
    }
    // Strip trailing \n and optional \r.
    let mut end = bs.len();
    if end > 0 && bs[end - 1] == b'\n' {
        end -= 1;
    }
    if end > 0 && bs[end - 1] == b'\r' {
        end -= 1;
    }
    Ok(string::from_bytes(&bs[..end]))
}

/// `parseRequestLine` (request.go:961) — split "METHOD SP target SP
/// proto" on the two spaces.
fn parse_request_line(line: &string) -> Option<(string, string, string)> {
    let bytes = line.as_bytes();
    let s1 = bytes.iter().position(|&b| b == b' ')?;
    let s2 = bytes[s1 + 1..].iter().position(|&b| b == b' ')? + s1 + 1;
    Some((
        string::from_bytes(&bytes[..s1]),
        string::from_bytes(&bytes[s1 + 1..s2]),
        string::from_bytes(&bytes[s2 + 1..]),
    ))
}

/// `parseHeaderLine` — split "Name: value" on the first colon.
/// Trims optional whitespace around `value`.
fn parse_header_line(line: &string) -> Option<(string, string)> {
    let bytes = line.as_bytes();
    let colon = bytes.iter().position(|&b| b == b':')?;
    let name = &bytes[..colon];
    if name.is_empty() {
        return None;
    }
    let mut start = colon + 1;
    while start < bytes.len() && (bytes[start] == b' ' || bytes[start] == b'\t') {
        start += 1;
    }
    let mut end = bytes.len();
    while end > start && (bytes[end - 1] == b' ' || bytes[end - 1] == b'\t') {
        end -= 1;
    }
    Some((
        string::from_bytes(name),
        string::from_bytes(&bytes[start..end]),
    ))
}

/// `ParseHTTPVersion` (request.go:929) — parse "HTTP/1.1" → (1, 1).
fn parse_http_version(b: &[u8]) -> Option<(int, int)> {
    if !b.starts_with(b"HTTP/") {
        return None;
    }
    let rest = &b[5..];
    let dot = rest.iter().position(|&c| c == b'.')?;
    let major = parse_dec(&rest[..dot])?;
    let minor = parse_dec(&rest[dot + 1..])?;
    if !(0..1000).contains(&major) || !(0..1000).contains(&minor) {
        return None;
    }
    Some((major, minor))
}

fn parse_dec(b: &[u8]) -> Option<int> {
    if b.is_empty() {
        return None;
    }
    let mut acc: i64 = 0;
    for &c in b {
        if !c.is_ascii_digit() {
            return None;
        }
        acc = acc.checked_mul(10)?.checked_add((c - b'0') as i64)?;
    }
    Some(acc)
}

/// RFC 7230 §3.2.6 token chars — what's legal in a method name.
fn valid_method(m: &[u8]) -> bool {
    if m.is_empty() {
        return false;
    }
    for &b in m {
        let ok = matches!(b,
            b'!' | b'#' | b'$' | b'%' | b'&' | b'\'' | b'*' | b'+' |
            b'-' | b'.' | b'^' | b'_' | b'`' | b'|' | b'~' |
            b'0'..=b'9' | b'A'..=b'Z' | b'a'..=b'z'
        );
        if !ok {
            return false;
        }
    }
    true
}

