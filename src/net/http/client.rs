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
use crate::strings;
use crate::time;
use crate::types::{byte, int};
use crate::{append, make};

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

    /// `(*Response).ProtoAtLeast(major, minor)` (response.go:224) —
    /// reports whether the response's HTTP protocol is at least
    /// major.minor.
    pub fn ProtoAtLeast(&self, major: int, minor: int) -> bool {
        // Go: return r.ProtoMajor > major ||
        //         r.ProtoMajor == major && r.ProtoMinor >= minor
        self.ProtoMajor > major || self.ProtoMajor == major && self.ProtoMinor >= minor
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

    // Go: if connHdr := resp.Header.Get("Connection"); … { resp.Close = … }
    let conn_hdr = resp.Header.Get(string("Connection"));
    if strings::EqualFold(conn_hdr.clone(), string("close")) {
        resp.Close = true;
    } else if resp.ProtoMajor == 1 && resp.ProtoMinor == 0 {
        resp.Close = !strings::EqualFold(conn_hdr, string("keep-alive"));
    }

    // Go: body framing — Transfer-Encoding takes precedence over Content-Length.
    let te = resp.Header.Get(string("Transfer-Encoding"));
    let chunked = is_chunked_te(&te);
    let cl_str = resp.Header.Get(string("Content-Length"));

    // Go: HEAD / 1xx / 204 / 304 → empty body, regardless of CL/TE.
    let head_only = match resp.Request {
        Some(ref r) => r.Method == "HEAD",
        None => false,
    };
    let no_body = head_only
        || (resp.StatusCode >= 100 && resp.StatusCode < 200)
        || resp.StatusCode == 204
        || resp.StatusCode == 304;

    if no_body {
        resp.ContentLength = 0;
        resp.Body = make!([]byte, 0);
    } else if chunked {
        // Go: resp.TransferEncoding = []string{"chunked"}; resp.ContentLength = -1
        // Go: resp.Body = http.internal.NewChunkedReader(r) — drained into Body.
        resp.ContentLength = -1;
        let body = make!([]byte, 0);
        let mut cr = super::chunked::NewChunkedReader(BufioPassthrough { inner: br });
        let (b, err) = drain_to_eof(&mut cr, body);
        if !err.IsNil() && !errors::Is(err.clone(), io::EOF()) {
            return (resp, err);
        }
        resp.Body = b;
    } else if cl_str.Len() > 0 {
        // Go: cl, err := strconv.ParseInt(cls, 10, 64)
        let (n, perr) = crate::strconv::Atoi(cl_str);
        if !perr.IsNil() || n < 0 {
            return (resp, errors::New(string("http: invalid Content-Length")));
        }
        resp.ContentLength = n;
        let want = n as int;
        let mut body = make!([]byte, want);
        // Go: io.ReadFull(r, body)
        let (got, ferr) = read_full_into(br, &mut body);
        if !ferr.IsNil() && !errors::Is(ferr.clone(), io::EOF()) {
            return (resp, ferr);
        }
        if got < want {
            body = body.slice(0, got);
        }
        resp.Body = body;
    } else if resp.Close {
        // Go: no CL, no TE, Connection: close → io.ReadAll(r)
        resp.ContentLength = -1;
        let body = make!([]byte, 0);
        let (b, err) = drain_to_eof(br, body);
        if !err.IsNil() && !errors::Is(err.clone(), io::EOF()) {
            return (resp, err);
        }
        resp.Body = b;
    } else {
        // Go: no CL, no TE, no close — body is empty.
        resp.ContentLength = 0;
        resp.Body = make!([]byte, 0);
    }

    (resp, errors::nil)
}

/// Read until EOF into `body`, returning the appended slice and any
/// non-EOF error. Replaces ad-hoc Vec<u8> drain loops.
fn drain_to_eof<R: Reader>(r: &mut R, mut body: slice<byte>) -> (slice<byte>, error) {
    let mut tmp = make!([]byte, 4096);
    loop {
        let (n, err) = r.Read(&mut tmp);
        for i in 0..n {
            body = append!(body, tmp[i]);
        }
        if !err.IsNil() {
            return (body, err);
        }
        if n == 0 {
            return (body, errors::nil);
        }
    }
}

/// Read exactly `len(buf)` bytes from `r` into `buf`. Returns the
/// short count + error on EOF mid-read. Mirrors `io.ReadFull` over a
/// goish buffered reader.
fn read_full_into<R: Reader>(r: &mut bufio::Reader<R>, buf: &mut slice<byte>) -> (int, error) {
    let want = buf.Len();
    let mut got: int = 0;
    while got < want {
        let chunk: int = (want - got).min(4096);
        let mut tmp = make!([]byte, chunk);
        let (rn, rerr) = r.Read(&mut tmp);
        for i in 0..rn {
            buf[got + i] = tmp[i];
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
        let (_, werr) = conn.Write(req_bytes);
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
                        path_values: crate::gomap::map::<string, string>::new(),
                        form_state: alloc::sync::Arc::new(crate::sync::Mutex::new(super::request::FormCell::default())),
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

/// `http.NewRequestWithContext(ctx, method, url, body)` (request.go:898).
/// Slim port: ctx is accepted but currently ignored (goish doesn't yet
/// thread context through Request). Behaves identically to NewRequest
/// in v1; switching to a context-aware Client/Transport later won't
/// break call sites that already pass the ctx through.
pub fn NewRequestWithContext(
    _ctx: alloc::sync::Arc<dyn crate::context::Context>,
    method: string,
    url: string,
    body: slice<byte>,
) -> (Request, error) {
    NewRequest(method, url, body)
}

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
        path_values: crate::gomap::map::<string, string>::new(),
        form_state: alloc::sync::Arc::new(crate::sync::Mutex::new(super::request::FormCell::default())),
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
        path_values: crate::gomap::map::<string, string>::new(),
        form_state: alloc::sync::Arc::new(crate::sync::Mutex::new(super::request::FormCell::default())),
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
    // Go: line, err := br.ReadSlice('\n')
    let (line, err) = br.ReadSlice(b'\n');
    if !err.IsNil() {
        return Err(err);
    }
    // Go: trim trailing CRLF
    let mut end = line.Len();
    if end > 0 && line[end - 1] == b'\n' {
        end -= 1;
    }
    if end > 0 && line[end - 1] == b'\r' {
        end -= 1;
    }
    Ok(crate::convert::string(line.slice(0, end)))
}

/// Line-by-line port of `ParseHTTPVersion` (request.go:1390 in Go's source).
fn parse_http_version(s: &string) -> (int, int) {
    // Go: if len(s) < 8 || !strings.HasPrefix(s, "HTTP/") { return 0,0,false }
    if s.Len() < 8 || !strings::HasPrefix(s.clone(), string("HTTP/")) {
        return (0, 0);
    }
    // Go: rest := s[5:]; major, minor, ok := strings.Cut(rest, ".")
    let rest = strings::TrimPrefix(s.clone(), string("HTTP/"));
    let (major_s, minor_s, ok) = strings::Cut(rest, string("."));
    if !ok {
        return (0, 0);
    }
    // Go: major, err := strconv.Atoi(majorStr); minor, err := strconv.Atoi(minorStr)
    let (major, e1) = crate::strconv::Atoi(major_s);
    let (minor, e2) = crate::strconv::Atoi(minor_s);
    if !e1.IsNil() || !e2.IsNil() {
        return (0, 0);
    }
    (major, minor)
}

/// Line-by-line port of `isChunked` (transfer.go:617 paraphrased).
/// Returns true if `value` ends in `chunked` (case-insensitive),
/// optionally preceded by a comma-separated list.
fn is_chunked_te(value: &string) -> bool {
    // Go (paraphrased): trim OWS, then check the last comma-separated
    // token equals "chunked" (case-insensitive). The simplest goish
    // line-by-line: split, trim, check last.
    let trimmed = strings::TrimSpace(value.clone());
    if trimmed.Len() == 0 {
        return false;
    }
    let parts = strings::Split(trimmed, string(","));
    let last = strings::TrimSpace(parts[parts.Len() - 1].clone());
    strings::EqualFold(last, string("chunked"))
}

/// Add `:port` if Host has none.
fn ensure_default_port(host: &string, port: int) -> string {
    // Go: if hasPort(host) { return host }; return host + ":" + strconv.Itoa(port)
    if has_port(host) {
        return host.clone();
    }
    let mut b = strings::Builder::new();
    b.Grow(host.Len() + 6);
    let _ = b.WriteString(host.clone());
    let _ = b.WriteByte(b':');
    let _ = b.WriteString(crate::strconv::Itoa(port));
    b.String()
}

/// Detect a `:port` suffix in `host`. Walk from end; `:` before `]`
/// counts. Mirrors Go's `hasPort` shape (net/url/url.go).
fn has_port(host: &string) -> bool {
    // Go: for i := len(host) - 1; i >= 0; i-- { switch host[i] { case ':': return true; case ']': return false } }
    let mut i = host.Len() - 1;
    while i >= 0 {
        let c = host[i];
        if c == b':' {
            return true;
        }
        if c == b']' {
            return false;
        }
        i -= 1;
    }
    false
}

/// Serialize a Request onto the wire as HTTP/1.1. Returns the bytes
/// ready to write to the underlying conn.
///
/// Loose port of `(*Request).write` (request.go:603) — we don't have
/// `bufio.Writer` plumbing yet, so we accumulate into a `strings::Builder`
/// for the head and concatenate the body slice<byte> at the end.
pub(crate) fn serialize_request(req: &Request, host: &string) -> slice<byte> {
    serialize_request_proxy(req, host, false)
}

/// Same as `serialize_request` but emits an absolute Request-URI in
/// the request line when `using_proxy` is true. Mirrors Go's
/// `(*Request).write` (request.go:582) call shape.
pub(crate) fn serialize_request_proxy(
    req: &Request,
    host: &string,
    using_proxy: bool,
) -> slice<byte> {
    // Go: var b strings.Builder
    let mut b = strings::Builder::new();
    b.Grow(256);

    // Go: fmt.Fprintf(&b, "%s %s HTTP/1.1\r\n", req.Method, ruri)
    let _ = b.WriteString(req.Method.clone());
    let _ = b.WriteByte(b' ');
    // Go: when usingProxy, ruri = req.URL.Scheme + "://" + host + path
    if using_proxy && req.URL.Scheme.Len() != 0 {
        let _ = b.WriteString(req.URL.Scheme.clone());
        let _ = b.WriteString("://");
        let _ = b.WriteString(host.clone());
    }
    if req.URL.Path.Len() == 0 {
        let _ = b.WriteByte(b'/');
    } else {
        let _ = b.WriteString(req.URL.Path.clone());
    }
    if req.URL.RawQuery.Len() > 0 {
        let _ = b.WriteByte(b'?');
        let _ = b.WriteString(req.URL.RawQuery.clone());
    }
    let _ = b.WriteString(" HTTP/1.1\r\n");

    // Go: fmt.Fprintf(&b, "Host: %s\r\n", host)
    let _ = b.WriteString("Host: ");
    let _ = b.WriteString(host.clone());
    let _ = b.WriteString("\r\n");

    // Go: default User-Agent if not set
    if req.Header.Get(string("User-Agent")).Len() == 0 {
        let _ = b.WriteString("User-Agent: goish/0.1\r\n");
    }

    // Go: fmt.Fprintf(&b, "Content-Length: %d\r\n", contentLength) — for body-bearing
    let body_len = req.Body.Len();
    let has_body_method = !(req.Method == "GET"
        || req.Method == "HEAD"
        || req.Method == "DELETE"
        || req.Method == "OPTIONS");
    if body_len > 0 || has_body_method {
        let _ = b.WriteString("Content-Length: ");
        let _ = b.WriteString(crate::strconv::Itoa(body_len));
        let _ = b.WriteString("\r\n");
    }

    // Go: write user-set headers via Header.WriteSubset
    let inner = req.Header.__inner();
    for (key, values) in inner.__iter() {
        // Go: skip Host / Content-Length (we synthesize)
        if strings::EqualFold(key.clone(), string("Host"))
            || strings::EqualFold(key.clone(), string("Content-Length"))
        {
            continue;
        }
        let n = values.Len();
        for i in 0..n {
            let _ = b.WriteString(key.clone());
            let _ = b.WriteString(": ");
            let _ = b.WriteString(values[i].clone());
            let _ = b.WriteString("\r\n");
        }
    }
    // Go: b.WriteString("\r\n")
    let _ = b.WriteString("\r\n");

    // Concat head + body. Convert head to bytes, then append body.
    let head = crate::convert::bytes(b.String());
    if body_len == 0 {
        return head;
    }
    let mut out = head;
    for i in 0..body_len {
        out = append!(out, req.Body[i]);
    }
    out
}

/// `application/x-www-form-urlencoded` encode a list of (key, value) pairs.
/// Line-by-line port of `url.Values.Encode` (net/url/url.go:993).
fn encode_form(vals: &[(string, string)]) -> slice<byte> {
    let mut buf = strings::Builder::new();
    for (i, kv) in vals.iter().enumerate() {
        // Go: if buf.Len() > 0 { buf.WriteByte('&') }
        if i > 0 {
            let _ = buf.WriteByte(b'&');
        }
        // Go: buf.WriteString(url.QueryEscape(k))
        let _ = buf.WriteString(query_escape(kv.0.clone()));
        let _ = buf.WriteByte(b'=');
        let _ = buf.WriteString(query_escape(kv.1.clone()));
    }
    crate::convert::bytes(buf.String())
}

/// Line-by-line port of `url.QueryEscape` (net/url/url.go:887, slim).
fn query_escape(s: string) -> string {
    let mut b = strings::Builder::new();
    b.Grow(s.Len());
    for i in 0..s.Len() {
        let c: byte = s[i];
        // Go: if shouldEscape(c, encodeQueryComponent) { … } else { write c }
        let unreserved = (c >= b'a' && c <= b'z')
            || (c >= b'A' && c <= b'Z')
            || (c >= b'0' && c <= b'9')
            || c == b'-'
            || c == b'_'
            || c == b'.'
            || c == b'~';
        if unreserved {
            let _ = b.WriteByte(c);
        } else if c == b' ' {
            // Go: special case — space → '+'
            let _ = b.WriteByte(b'+');
        } else {
            let _ = b.WriteByte(b'%');
            const HEX: &[byte; 16] = b"0123456789ABCDEF";
            let _ = b.WriteByte(HEX[(c >> 4) as usize]);
            let _ = b.WriteByte(HEX[(c & 0xf) as usize]);
        }
    }
    b.String()
}

