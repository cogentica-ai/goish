// net/http/client — slim port of Go's HTTP client.
//
//   Go                                      goish
//   ─────────────────────────────────────   ──────────────────────────────────
//   resp, err := http.Get(url)               let (resp, err) = http::Get(url);
//   resp, err := http.Post(url, ct, body)    let (resp, err) = http::Post(url, ct, body);
//   resp, err := client.Do(req)              let (resp, err) = client.Do(&req);
//
// Slim port consolidating Go 1.25 src/net/http/client.go (1040 LOC),
// transport.go (3142 LOC, only the dial-and-read portion), and
// response.go (371 LOC). Total goish-side: this single file.
//
// **Deviations from Go (v1):**
//
//   * No connection pool / idle reuse — each RoundTrip dials a fresh
//     conn and closes it after the response. Ports for keepalive
//     reuse defer to a future iteration; the wire-level state machine
//     here is the right base.
//   * No TLS (`https://`). Calls return an error if Scheme == "https".
//   * No CookieJar. Cookies must be set via `req.AddCookie` and read
//     via `resp.Cookies()` explicitly.
//   * No `context.Context` / per-request cancellation. `Client.Timeout`
//     bounds the whole request via deadline-set on the dialed Conn.
//   * `Request.Body` and `Response.Body` are pre-buffered `slice<byte>`
//     (matches the existing Request type in goish v1).
//   * No automatic decompression (no `Accept-Encoding: gzip`).

#![allow(non_snake_case)]
#![allow(dead_code)]

extern crate alloc;

use alloc::sync::Arc;
use alloc::vec::Vec;

use crate::bufio;
use crate::errors::{self, error};
use crate::goslice::slice;
use crate::io::{self, Closer, Reader, Writer};
use crate::net;
use crate::string;
use crate::time;
use crate::types::{byte, int};

use super::cookie::{read_set_cookies, Cookie};
use super::header::Header;
use super::request::Request;
use super::url::URL;

// ─── Response ────────────────────────────────────────────────────────

/// `http.Response` (response.go:35). v1 buffers Body fully (matches
/// our Request convention).
#[derive(Clone)]
pub struct Response {
    pub Status: string,    // "200 OK"
    pub StatusCode: int,
    pub Proto: string,
    pub ProtoMajor: int,
    pub ProtoMinor: int,
    pub Header: Header,
    pub Body: slice<byte>,
    /// `-1` if unknown (chunked / no Content-Length on a non-empty body).
    pub ContentLength: int,
    /// Whether the connection should be closed after reading Body.
    pub Close: bool,
    /// The Request that produced this Response. Populated by Client::Do.
    pub Request: Option<Request>,
}

impl Default for Response {
    fn default() -> Self {
        Response {
            Status: string::new(),
            StatusCode: 0,
            Proto: string::new(),
            ProtoMajor: 0,
            ProtoMinor: 0,
            Header: Header::new(),
            Body: slice::<byte>::__from_vec(Vec::new()),
            ContentLength: 0,
            Close: false,
            Request: None,
        }
    }
}

impl Response {
    /// `(*Response).Cookies()` — parse Set-Cookie headers.
    /// Mirrors response.go:125.
    pub fn Cookies(&self) -> slice<Cookie> {
        read_set_cookies(&self.Header)
    }

    /// `(*Response).Location()` — Resolve the `Location` header.
    /// Returns absolute URLs as-is; relative URLs are best-effort
    /// resolved against the request's URL.
    pub fn Location(&self) -> (URL, error) {
        let lv = self.Header.Get(string("Location"));
        if lv.Len() == 0 {
            return (URL::empty(), errors::New(string("http: no Location header in response")));
        }
        // Absolute URL → parse via parse_request_uri (accepts http://...).
        match super::url::parse_request_uri(&lv) {
            Ok(u) => {
                if u.Scheme.Len() != 0 {
                    return (u, errors::nil);
                }
                // Relative — fall through to merge with self.Request.URL below.
            }
            Err(_) => {}
        }
        // Relative resolution: replace path/query of req.URL with lv.
        if let Some(ref req) = self.Request {
            let mut merged = req.URL.clone();
            // If Location starts with "/", replace path; else append to dirname.
            let lvb = lv.as_bytes();
            if !lvb.is_empty() && lvb[0] == b'/' {
                // Split at "?".
                let q = lvb.iter().position(|&c| c == b'?');
                let (path_b, query_b) = match q {
                    Some(i) => (&lvb[..i], &lvb[i + 1..]),
                    None => (lvb, &lvb[..0]),
                };
                merged.Path = string::from_bytes(path_b);
                merged.RawPath = merged.Path.clone();
                merged.RawQuery = string::from_bytes(query_b);
                return (merged, errors::nil);
            }
        }
        (URL::empty(), errors::New(string("http: cannot resolve relative Location")))
    }
}

// ─── ReadResponse ────────────────────────────────────────────────────

/// `http.ReadResponse(b, req)` — parse an HTTP/1.x response from the
/// buffered reader. Mirrors response.go:154.
///
/// On success the reader has consumed up through the response body.
/// The `req` argument is recorded into `Response.Request` so callers
/// can chain `Location()` etc.
pub fn ReadResponse<R: Reader>(
    br: &mut bufio::Reader<R>,
    req: Option<Request>,
) -> (Response, error) {
    let mut resp = Response::default();
    resp.Request = req;

    // Status line: "HTTP/1.1 200 OK\r\n"
    let line = match read_crlf_line(br) {
        Ok(l) => l,
        Err(e) => return (resp, e),
    };
    let lb = line.as_bytes();
    let sp1 = match lb.iter().position(|&b| b == b' ') {
        Some(i) => i,
        None => return (resp, errors::New(string("http: malformed response status line"))),
    };
    resp.Proto = string::from_bytes(&lb[..sp1]);
    let rest = &lb[sp1 + 1..];
    let sp2 = rest.iter().position(|&b| b == b' ').unwrap_or(rest.len());
    let code_b = &rest[..sp2];
    if code_b.len() != 3 {
        return (resp, errors::New(string("http: malformed HTTP status code")));
    }
    let mut code: int = 0;
    for &b in code_b {
        if !b.is_ascii_digit() {
            return (resp, errors::New(string("http: malformed HTTP status code")));
        }
        code = code * 10 + (b - b'0') as int;
    }
    resp.StatusCode = code;
    resp.Status = string::from_bytes(rest);
    let (major, minor) = parse_http_version(&resp.Proto);
    if major == 0 {
        return (resp, errors::New(string("http: malformed HTTP version")));
    }
    resp.ProtoMajor = major;
    resp.ProtoMinor = minor;

    // Headers.
    loop {
        let h = match read_crlf_line(br) {
            Ok(l) => l,
            Err(e) => return (resp, e),
        };
        if h.Len() == 0 {
            break;
        }
        let hb = h.as_bytes();
        let colon = match hb.iter().position(|&b| b == b':') {
            Some(i) => i,
            None => return (resp, errors::New(string("http: malformed response header"))),
        };
        let name = string::from_bytes(&hb[..colon]);
        let mut value_start = colon + 1;
        while value_start < hb.len() && (hb[value_start] == b' ' || hb[value_start] == b'\t') {
            value_start += 1;
        }
        let value = string::from_bytes(&hb[value_start..]);
        resp.Header.Add(name, value);
    }

    // Determine Close.
    let conn_hdr = resp.Header.Get(string("Connection"));
    if ascii_eq_ci(conn_hdr.as_bytes(), b"close") {
        resp.Close = true;
    } else if resp.ProtoMajor == 1 && resp.ProtoMinor == 0 {
        resp.Close = !ascii_eq_ci(conn_hdr.as_bytes(), b"keep-alive");
    }

    // Body framing.
    let te = resp.Header.Get(string("Transfer-Encoding"));
    let chunked = is_chunked_te(te.as_bytes());
    let cl_str = resp.Header.Get(string("Content-Length"));

    // HEAD / 1xx / 204 / 304 → empty body, regardless of CL/TE.
    let head_only = match resp.Request {
        Some(ref r) => r.Method.as_bytes() == b"HEAD",
        None => false,
    };
    let no_body = head_only
        || (resp.StatusCode >= 100 && resp.StatusCode < 200)
        || resp.StatusCode == 204
        || resp.StatusCode == 304;

    if no_body {
        resp.ContentLength = 0;
        resp.Body = slice::<byte>::__from_vec(Vec::new());
    } else if chunked {
        resp.ContentLength = -1;
        let mut buf: Vec<u8> = Vec::new();
        let mut cr = super::chunked::NewChunkedReader(BufioPassthrough { inner: br });
        let mut tmp = slice::<byte>::__from_vec(alloc::vec![0u8; 4096]);
        loop {
            let (n, err) = cr.Read(&mut tmp);
            for i in 0..n {
                buf.push(tmp[i]);
            }
            if !err.IsNil() {
                if errors::Is(err.clone(), io::EOF()) {
                    break;
                }
                return (resp, err);
            }
            if n == 0 {
                break;
            }
        }
        resp.Body = slice::<byte>::__from_vec(buf);
    } else if cl_str.Len() > 0 {
        let n = match parse_decimal(cl_str.as_bytes()) {
            Some(n) => n,
            None => return (resp, errors::New(string("http: invalid Content-Length"))),
        };
        resp.ContentLength = n;
        let want = n as usize;
        let mut buf: Vec<u8> = Vec::with_capacity(want);
        while buf.len() < want {
            let mut tmp = slice::<byte>::__from_vec(alloc::vec![0u8; (want - buf.len()).min(4096)]);
            let (rn, rerr) = br.Read(&mut tmp);
            for i in 0..rn {
                buf.push(tmp[i]);
            }
            if !rerr.IsNil() {
                if errors::Is(rerr.clone(), io::EOF()) {
                    break;
                }
                return (resp, rerr);
            }
            if rn == 0 {
                break;
            }
        }
        resp.Body = slice::<byte>::__from_vec(buf);
    } else if resp.Close {
        // No CL, no TE, Connection: close → read until EOF.
        resp.ContentLength = -1;
        let mut buf: Vec<u8> = Vec::new();
        let mut tmp = slice::<byte>::__from_vec(alloc::vec![0u8; 4096]);
        loop {
            let (rn, rerr) = br.Read(&mut tmp);
            for i in 0..rn {
                buf.push(tmp[i]);
            }
            if !rerr.IsNil() {
                if errors::Is(rerr.clone(), io::EOF()) {
                    break;
                }
                return (resp, rerr);
            }
            if rn == 0 {
                break;
            }
        }
        resp.Body = slice::<byte>::__from_vec(buf);
    } else {
        // No CL, no TE, no close — body is empty.
        resp.ContentLength = 0;
        resp.Body = slice::<byte>::__from_vec(Vec::new());
    }

    (resp, errors::nil)
}

// ─── RoundTripper / Transport ────────────────────────────────────────

/// `http.RoundTripper` — single-method interface that executes a
/// request and returns the response. Mirrors transport.go:103.
pub trait RoundTripper: Send + Sync {
    fn RoundTrip(&self, req: &Request) -> (Response, error);
}

/// `http.Transport` (transport.go:163). v1: dial-per-request, no idle
/// pool. Configurable timeouts only.
pub struct Transport {
    /// Maximum time `RoundTrip` will spend on the entire request
    /// (dial + write + read). Zero ≡ no timeout.
    pub Timeout: time::Duration,
}

impl Default for Transport {
    fn default() -> Self {
        Transport {
            Timeout: time::Duration(0),
        }
    }
}

impl RoundTripper for Transport {
    fn RoundTrip(&self, req: &Request) -> (Response, error) {
        // Resolve scheme.
        let scheme = req.URL.Scheme.clone();
        if scheme.Len() != 0
            && scheme.as_bytes() != b"http"
        {
            return (
                Response::default(),
                errors::New(string("http: only scheme=http is supported (TLS not yet ported)")),
            );
        }
        // Resolve host:port. URL.Host may already include :port.
        let host = if req.URL.Host.Len() > 0 {
            req.URL.Host.clone()
        } else {
            req.Host.clone()
        };
        if host.Len() == 0 {
            return (
                Response::default(),
                errors::New(string("http: no Host in request")),
            );
        }
        let dial_addr = ensure_default_port(&host, 80);

        // Dial.
        let (mut conn, derr) = net::Dial(string("tcp"), dial_addr);
        if !derr.IsNil() {
            return (Response::default(), derr);
        }

        // Apply deadline if Timeout > 0.
        if self.Timeout.0 > 0 {
            let dl = time::Now().Add(self.Timeout);
            let _ = conn.SetDeadline(dl);
        }

        // Write the request.
        let req_bytes = serialize_request(req, &host);
        let (_, werr) = conn.Write(slice::<byte>::__from_vec(req_bytes));
        if !werr.IsNil() {
            let _ = conn.Close();
            return (Response::default(), werr);
        }

        // Read the response.
        let (resp, rerr) = {
            let mut br = bufio::NewReader(&mut conn);
            ReadResponse(&mut br, Some(req.clone()))
        };
        let _ = conn.Close();
        (resp, rerr)
    }
}

// ─── Client ──────────────────────────────────────────────────────────

/// `http.Client` (client.go:57). v1 subset: Transport + Timeout. No
/// CheckRedirect override (always uses default of 10 max), no Jar.
pub struct Client {
    pub Transport: Arc<dyn RoundTripper>,
    /// Whole-request deadline. Zero ≡ no timeout.
    pub Timeout: time::Duration,
}

impl Default for Client {
    fn default() -> Self {
        Client {
            Transport: Arc::new(Transport::default()) as Arc<dyn RoundTripper>,
            Timeout: time::Duration(0),
        }
    }
}

const MAX_REDIRECTS: usize = 10;

impl Client {
    /// `(*Client).Do(req)` — execute the request, following up to 10
    /// redirects on 301/302/303/307/308. Mirrors client.go:565.
    pub fn Do(&self, req: &Request) -> (Response, error) {
        let mut current = req.clone();
        for _step in 0..=MAX_REDIRECTS {
            let (resp, err) = self.Transport.RoundTrip(&current);
            if !err.IsNil() {
                return (resp, err);
            }
            // Decide whether to follow.
            match resp.StatusCode {
                301 | 302 | 303 | 307 | 308 => {
                    let (loc, lerr) = resp.Location();
                    if !lerr.IsNil() {
                        return (resp, errors::nil); // no Location → return as-is
                    }
                    let next_method = if resp.StatusCode == 303 {
                        // 303 → GET
                        string("GET")
                    } else if resp.StatusCode == 301 || resp.StatusCode == 302 {
                        // 301/302 → POST becomes GET (matching Go)
                        if current.Method.as_bytes() == b"POST"
                            || current.Method.as_bytes() == b"PUT"
                        {
                            string("GET")
                        } else {
                            current.Method.clone()
                        }
                    } else {
                        current.Method.clone()
                    };
                    let mut next = Request {
                        Method: next_method.clone(),
                        URL: loc.clone(),
                        Proto: string("HTTP/1.1"),
                        ProtoMajor: 1,
                        ProtoMinor: 1,
                        Header: current.Header.clone(),
                        Host: loc.Host.clone(),
                        ContentLength: 0,
                        Body: slice::<byte>::__from_vec(Vec::new()),
                        RemoteAddr: string::new(),
                    };
                    // Preserve body only on 307/308 (per RFC).
                    if resp.StatusCode == 307 || resp.StatusCode == 308 {
                        next.Body = current.Body.clone();
                        next.ContentLength = current.ContentLength;
                    }
                    current = next;
                    continue;
                }
                _ => return (resp, errors::nil),
            }
        }
        (
            Response::default(),
            errors::New(string("http: stopped after 10 redirects")),
        )
    }

    /// `(*Client).Get(url)` — issue a GET. Mirrors client.go:481.
    pub fn Get(&self, url: string) -> (Response, error) {
        let (req, err) = NewRequest(string("GET"), url, slice::<byte>::__from_vec(Vec::new()));
        if !err.IsNil() {
            return (Response::default(), err);
        }
        self.Do(&req)
    }

    /// `(*Client).Head(url)`.
    pub fn Head(&self, url: string) -> (Response, error) {
        let (req, err) = NewRequest(string("HEAD"), url, slice::<byte>::__from_vec(Vec::new()));
        if !err.IsNil() {
            return (Response::default(), err);
        }
        self.Do(&req)
    }

    /// `(*Client).Post(url, contentType, body)`.
    pub fn Post(
        &self,
        url: string,
        content_type: string,
        body: slice<byte>,
    ) -> (Response, error) {
        let (mut req, err) = NewRequest(string("POST"), url, body);
        if !err.IsNil() {
            return (Response::default(), err);
        }
        req.Header.Set(string("Content-Type"), content_type);
        self.Do(&req)
    }

    /// `(*Client).PostForm(url, vals)` — POST `application/x-www-form-urlencoded`
    /// body built from key=value pairs.
    pub fn PostForm(&self, url: string, vals: &[(string, string)]) -> (Response, error) {
        let body = encode_form(vals);
        self.Post(
            url,
            string("application/x-www-form-urlencoded"),
            body,
        )
    }
}

// ─── DefaultClient + free fns ────────────────────────────────────────

/// A default-configured Client used by the free `Get` / `Post` /
/// `PostForm` / `Head` functions. Created lazily on first use.
fn default_client() -> Arc<Client> {
    use crate::runtime::spin::SpinLock;
    static SLOT: SpinLock<Option<Arc<Client>>> = SpinLock::new(None);
    let mut g = SLOT.lock();
    if g.is_none() {
        *g = Some(Arc::new(Client::default()));
    }
    g.as_ref().unwrap().clone()
}

/// `http.Get(url)`.
pub fn Get(url: string) -> (Response, error) {
    default_client().Get(url)
}

/// `http.Head(url)`.
pub fn Head(url: string) -> (Response, error) {
    default_client().Head(url)
}

/// `http.Post(url, contentType, body)`.
pub fn Post(url: string, content_type: string, body: slice<byte>) -> (Response, error) {
    default_client().Post(url, content_type, body)
}

/// `http.PostForm(url, vals)`.
pub fn PostForm(url: string, vals: &[(string, string)]) -> (Response, error) {
    default_client().PostForm(url, vals)
}

// ─── NewRequest ──────────────────────────────────────────────────────

/// `http.NewRequest(method, url, body)` — slim. Body is a pre-buffered
/// slice<byte> rather than an `io.Reader` (matches v1 Request shape).
pub fn NewRequest(method: string, url: string, body: slice<byte>) -> (Request, error) {
    let m = if method.Len() == 0 {
        string("GET")
    } else {
        method
    };
    let u = match super::url::parse_request_uri(&url) {
        Ok(u) => u,
        Err(msg) => return (default_request(), errors::New(msg)),
    };
    let body_len = body.Len();
    let host = u.Host.clone();
    let req = Request {
        Method: m,
        URL: u,
        Proto: string("HTTP/1.1"),
        ProtoMajor: 1,
        ProtoMinor: 1,
        Header: Header::new(),
        Host: host,
        ContentLength: body_len,
        Body: body,
        RemoteAddr: string::new(),
    };
    (req, errors::nil)
}

fn default_request() -> Request {
    Request {
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
    }
}

// ─── helpers ─────────────────────────────────────────────────────────

/// Adapter so ChunkedReader can pull from a borrowed bufio::Reader
/// without taking ownership.
struct BufioPassthrough<'a, R: Reader> {
    inner: &'a mut bufio::Reader<R>,
}
impl<'a, R: Reader> Reader for BufioPassthrough<'a, R> {
    fn Read(&mut self, b: &mut slice<byte>) -> (int, error) {
        self.inner.Read(b)
    }
}

/// Read a CRLF-terminated line, returning the line without CRLF.
fn read_crlf_line<R: Reader>(br: &mut bufio::Reader<R>) -> Result<string, error> {
    let (line, err) = br.ReadSlice(b'\n');
    if !err.IsNil() {
        return Err(err);
    }
    let n = line.Len();
    if n == 0 {
        return Ok(string::new());
    }
    let mut end = n as usize;
    if end > 0 && line[(end - 1) as int] == b'\n' {
        end -= 1;
    }
    if end > 0 && line[(end - 1) as int] == b'\r' {
        end -= 1;
    }
    let mut buf: Vec<u8> = Vec::with_capacity(end);
    for i in 0..end {
        buf.push(line[i as int]);
    }
    Ok(string::from_bytes(&buf))
}

fn parse_http_version(s: &string) -> (int, int) {
    let b = s.as_bytes();
    if b.len() < 8 || &b[..5] != b"HTTP/" {
        return (0, 0);
    }
    let dot = match b[5..].iter().position(|&c| c == b'.') {
        Some(i) => 5 + i,
        None => return (0, 0),
    };
    let mut major: int = 0;
    for &c in &b[5..dot] {
        if !c.is_ascii_digit() {
            return (0, 0);
        }
        major = major * 10 + (c - b'0') as int;
    }
    let mut minor: int = 0;
    for &c in &b[dot + 1..] {
        if !c.is_ascii_digit() {
            return (0, 0);
        }
        minor = minor * 10 + (c - b'0') as int;
    }
    (major, minor)
}

fn parse_decimal(b: &[u8]) -> Option<int> {
    if b.is_empty() {
        return None;
    }
    let mut n: int = 0;
    for &c in b {
        if !c.is_ascii_digit() {
            return None;
        }
        n = n.checked_mul(10)?.checked_add((c - b'0') as int)?;
    }
    Some(n)
}

fn ascii_eq_ci(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    for i in 0..a.len() {
        if (a[i] | 0x20) != (b[i] | 0x20) {
            return false;
        }
    }
    true
}

fn is_chunked_te(value: &[u8]) -> bool {
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
    ascii_eq_ci(last, b"chunked")
}

/// Add `:port` if Host has none.
fn ensure_default_port(host: &string, port: u16) -> string {
    let hb = host.as_bytes();
    let mut has_port = false;
    // Walk from end; ":" before any "]" → has port.
    for &b in hb.iter().rev() {
        if b == b':' {
            has_port = true;
            break;
        }
        if b == b']' {
            break;
        }
    }
    if has_port {
        host.clone()
    } else {
        let mut buf: Vec<u8> = Vec::with_capacity(hb.len() + 6);
        buf.extend_from_slice(hb);
        buf.push(b':');
        let mut p = port;
        let mut tmp = [0u8; 5];
        let mut i = 0;
        if p == 0 {
            tmp[0] = b'0';
            i = 1;
        } else {
            while p > 0 {
                tmp[i] = b'0' + (p % 10) as u8;
                p /= 10;
                i += 1;
            }
        }
        while i > 0 {
            i -= 1;
            buf.push(tmp[i]);
        }
        string::from_bytes(&buf)
    }
}

/// Serialize a Request onto the wire as HTTP/1.1.
fn serialize_request(req: &Request, host: &string) -> Vec<u8> {
    let mut out: Vec<u8> = Vec::with_capacity(256 + req.Body.Len() as usize);
    // Request line: METHOD SP request-target SP HTTP-version CRLF
    out.extend_from_slice(req.Method.as_bytes());
    out.push(b' ');
    // request-target = origin form when scheme is set; else just URL.String().
    // We always emit origin form for HTTP/1.1 (path[?query]).
    let path = req.URL.Path.as_bytes();
    if path.is_empty() {
        out.push(b'/');
    } else {
        out.extend_from_slice(path);
    }
    if req.URL.RawQuery.Len() > 0 {
        out.push(b'?');
        out.extend_from_slice(req.URL.RawQuery.as_bytes());
    }
    out.extend_from_slice(b" HTTP/1.1\r\n");

    // Host header (mandatory in HTTP/1.1).
    out.extend_from_slice(b"Host: ");
    out.extend_from_slice(host.as_bytes());
    out.extend_from_slice(b"\r\n");

    // User-Agent default if not set.
    if req.Header.Get(string("User-Agent")).Len() == 0 {
        out.extend_from_slice(b"User-Agent: goish/0.1\r\n");
    }

    // Content-Length for body-bearing methods. For GET/HEAD with empty
    // body, skip it.
    let body_len = req.Body.Len();
    let has_body_method = !matches!(req.Method.as_bytes(), b"GET" | b"HEAD" | b"DELETE" | b"OPTIONS");
    if body_len > 0 || has_body_method {
        out.extend_from_slice(b"Content-Length: ");
        let mut cl = body_len;
        let mut tmp = [0u8; 20];
        let mut i = 0;
        if cl == 0 {
            tmp[0] = b'0';
            i = 1;
        } else {
            while cl > 0 {
                tmp[i] = b'0' + (cl % 10) as u8;
                cl /= 10;
                i += 1;
            }
        }
        while i > 0 {
            i -= 1;
            out.push(tmp[i]);
        }
        out.extend_from_slice(b"\r\n");
    }

    // User-set headers.
    let inner = req.Header.__inner();
    for (key, values) in inner.__iter() {
        // Skip headers we synthesize.
        let kb = key.as_bytes();
        if ascii_eq_ci(kb, b"Host") || ascii_eq_ci(kb, b"Content-Length") {
            continue;
        }
        let n = values.Len();
        for i in 0..n {
            out.extend_from_slice(kb);
            out.extend_from_slice(b": ");
            out.extend_from_slice(values[i].as_bytes());
            out.extend_from_slice(b"\r\n");
        }
    }
    out.extend_from_slice(b"\r\n");

    // Body.
    if body_len > 0 {
        for i in 0..body_len {
            out.push(req.Body[i]);
        }
    }
    out
}

/// `application/x-www-form-urlencoded` encode a list of (key, value) pairs.
fn encode_form(vals: &[(string, string)]) -> slice<byte> {
    let mut out: Vec<u8> = Vec::new();
    for (i, (k, v)) in vals.iter().enumerate() {
        if i > 0 {
            out.push(b'&');
        }
        percent_encode_into(&mut out, k.as_bytes());
        out.push(b'=');
        percent_encode_into(&mut out, v.as_bytes());
    }
    slice::<byte>::__from_vec(out)
}

fn percent_encode_into(out: &mut Vec<u8>, src: &[u8]) {
    for &b in src {
        let unreserved = b.is_ascii_alphanumeric() || b == b'-' || b == b'_' || b == b'.' || b == b'~';
        if unreserved {
            out.push(b);
        } else if b == b' ' {
            out.push(b'+');
        } else {
            out.push(b'%');
            const HEX: &[u8; 16] = b"0123456789ABCDEF";
            out.push(HEX[(b >> 4) as usize]);
            out.push(HEX[(b & 0xf) as usize]);
        }
    }
}

