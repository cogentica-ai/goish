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
    /// Wildcard pattern bindings (Go 1.22). Populated by `ServeMux`
    /// when a `/users/{id}`-style pattern matches; queried via
    /// `r.PathValue(name)`. Empty otherwise.
    pub(crate) path_values: crate::gomap::map<string, string>,
    /// Parsed form (URL query + POST body if any). Populated lazily by
    /// `ParseForm()`; mirrors `Request.Form` (request.go:281). The
    /// pair `(form_parsed, form)` represents Go's `r.Form == nil` test.
    pub(crate) form_parsed: bool,
    pub(crate) form: crate::gomap::map<string, slice<string>>,
    /// Parsed POST body form. Populated lazily by `ParseForm()` when
    /// the method is POST/PUT/PATCH. Mirrors `Request.PostForm`.
    pub(crate) post_form_parsed: bool,
    pub(crate) post_form: crate::gomap::map<string, slice<string>>,
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

    /// `r.PathValue(name)` — look up a wildcard binding from a Go 1.22
    /// pattern match (e.g. `/users/{id}` → `r.PathValue("id")`).
    /// Returns the empty string if no such binding exists. Mirrors
    /// `(*Request).PathValue(name)` (request.go:472 in Go's source).
    pub fn PathValue(&self, name: string) -> string {
        let (v, ok) = self.path_values.Get(name);
        if ok {
            v
        } else {
            string::new()
        }
    }

    /// `r.SetPathValue(name, value)` — set a wildcard binding for
    /// testing or middleware use. Mirrors `(*Request).SetPathValue`.
    pub fn SetPathValue(&mut self, name: string, value: string) {
        self.path_values.Set(name, value);
    }

    /// Internal: bulk-install path bindings from a successful pattern
    /// match. Used by `ServeMux::ServeHTTP`; not part of the public
    /// API since users would set bindings via `SetPathValue` instead.
    #[doc(hidden)]
    pub fn __set_path_values(&mut self, m: crate::gomap::map<string, string>) {
        self.path_values = m;
    }

    /// `r.ParseForm()` — populate `r.Form` and `r.PostForm`.
    ///
    /// Line-by-line port of `(*Request).ParseForm()` (request.go:1327).
    /// For all requests, parses the URL's RawQuery into `r.Form`. For
    /// POST/PUT/PATCH with `Content-Type: application/x-www-form-urlencoded`,
    /// also parses the body and merges into both `r.PostForm` and
    /// `r.Form`. Idempotent.
    pub fn ParseForm(&mut self) -> error {
        // Go: var err error
        let mut err: error = errors::nil;
        // Go: if r.PostForm == nil { … }
        if !self.post_form_parsed {
            self.post_form_parsed = true;
            // Go: if r.Method == "POST" || "PUT" || "PATCH" { r.PostForm, err = parsePostForm(r) }
            if self.Method == "POST" || self.Method == "PUT" || self.Method == "PATCH" {
                let (pf, e) = parse_post_form(self);
                self.post_form = pf;
                err = e;
            }
            // Go: if r.PostForm == nil { r.PostForm = make(url.Values) }
            // (already initialized to empty map by default; nothing to do)
        }
        // Go: if r.Form == nil { … }
        if !self.form_parsed {
            self.form_parsed = true;
            // Go: if len(r.PostForm) > 0 { copyValues(r.Form, r.PostForm) }
            if self.post_form.Len() > 0 {
                copy_values(&mut self.form, &self.post_form);
            }
            // Go: newValues, e := url.ParseQuery(r.URL.RawQuery)
            let (new_values, e) = super::url::ParseQuery(self.URL.RawQuery.clone());
            if err.IsNil() {
                err = e;
            }
            // Go: copyValues(r.Form, newValues)
            copy_values(&mut self.form, &new_values);
        }
        err
    }

    /// `r.FormValue(key)` — first form value for `key`, or empty.
    /// Mirrors `(*Request).FormValue(key)` (request.go:1419).
    pub fn FormValue(&mut self, key: string) -> string {
        // Go: if r.Form == nil { r.ParseMultipartForm(defaultMaxMemory) }
        if !self.form_parsed {
            let _ = self.ParseForm();
        }
        // Go: if vs := r.Form[key]; len(vs) > 0 { return vs[0] }
        let (vs, ok) = self.form.Get(key);
        if ok && vs.Len() > 0 {
            return vs[0].clone();
        }
        string::new()
    }

    /// `r.PostFormValue(key)` — first POST form value for `key`, or
    /// empty. Mirrors request.go:1434.
    pub fn PostFormValue(&mut self, key: string) -> string {
        if !self.post_form_parsed {
            let _ = self.ParseForm();
        }
        let (vs, ok) = self.post_form.Get(key);
        if ok && vs.Len() > 0 {
            return vs[0].clone();
        }
        string::new()
    }

    /// `r.UserAgent()` (request.go:423) — convenience for the
    /// `User-Agent` request header.
    pub fn UserAgent(&self) -> string {
        self.Header.Get(string("User-Agent"))
    }

    /// `r.Referer()` (request.go:481) — convenience for the
    /// `Referer` request header. Note the historical misspelling.
    pub fn Referer(&self) -> string {
        self.Header.Get(string("Referer"))
    }

    /// `r.BasicAuth()` (request.go:973) — return `(user, pass, ok)`
    /// from a HTTP Basic `Authorization` header.
    pub fn BasicAuth(&self) -> (string, string, bool) {
        let auth = self.Header.Get(string("Authorization"));
        if auth.Len() == 0 {
            return (string::new(), string::new(), false);
        }
        parse_basic_auth(auth)
    }

    /// `r.SetBasicAuth(user, pass)` (request.go:1022) — set the
    /// `Authorization` header to "Basic " + base64(user:pass).
    pub fn SetBasicAuth(&mut self, username: string, password: string) {
        let mut creds = crate::strings::Builder::new();
        let _ = creds.WriteString(username);
        let _ = creds.WriteByte(b':');
        let _ = creds.WriteString(password);
        let combined = creds.String();
        let encoded = crate::encoding::base64::StdEncoding
            .EncodeToString(crate::convert::bytes(combined).as_ref());
        let mut hv = crate::strings::Builder::new();
        let _ = hv.WriteString("Basic ");
        let _ = hv.WriteString(encoded);
        self.Header.Set(string("Authorization"), hv.String());
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

const DEFAULT_MAX_LINE: usize = 8 * 1024;
const MAX_HEADERS: usize = 100;
const MAX_BODY: usize = 16 * 1024 * 1024; // 16 MiB safety cap

/// `http.ReadRequest(b *bufio.Reader)` — parse an HTTP/1.x request
/// using the default 8 KiB max-header-line. Mirrors
/// `func ReadRequest(b *bufio.Reader) (*Request, error)`
/// (request.go:1058).
///
/// For server use with a configurable limit, prefer
/// `ReadRequestWithLimit` (called by `http::Server` with
/// `srv.MaxHeaderBytes`).
pub fn ReadRequest<R: io::Reader>(
    br: &mut bufio::Reader<R>,
) -> (Request, error) {
    ReadRequestWithLimit(br, DEFAULT_MAX_LINE as int)
}

/// Variant of `ReadRequest` that honors the caller-provided
/// `max_header_bytes` — the maximum length of the request line and of
/// each individual header line. `<= 0` means "use the default".
///
/// On success the reader is positioned at the first byte after the
/// final CRLF of the request body (or after the headers if no body).
pub fn ReadRequestWithLimit<R: io::Reader>(
    br: &mut bufio::Reader<R>,
    max_header_bytes: int,
) -> (Request, error) {
    let max_line = if max_header_bytes > 0 {
        max_header_bytes as usize
    } else {
        DEFAULT_MAX_LINE
    };
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
        path_values: crate::gomap::map::<string, string>::new(),
        form_parsed: false,
        form: crate::gomap::map::<string, slice<string>>::new(),
        post_form_parsed: false,
        post_form: crate::gomap::map::<string, slice<string>>::new(),
    };

    // Request-line: METHOD SP request-target SP HTTP-version CRLF
    let line = match read_line(br, max_line) {
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
        let line = match read_line(br, max_line) {
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
/// `http.ParseHTTPVersion(vers)` (request.go:817) — parse an HTTP
/// version string per RFC 7230 §2.6. `"HTTP/1.0"` → `(1, 0, true)`.
/// Note: strings without a minor version (e.g. `"HTTP/2"`) are
/// rejected.
pub fn ParseHTTPVersion(vers: string) -> (int, int, bool) {
    // Go: switch vers { case "HTTP/1.1": return 1, 1, true; case "HTTP/1.0": return 1, 0, true }
    if vers == "HTTP/1.1" {
        return (1, 1, true);
    }
    if vers == "HTTP/1.0" {
        return (1, 0, true);
    }
    // Go: if !strings.HasPrefix(vers, "HTTP/") || len(vers) != len("HTTP/X.Y") { return 0,0,false }
    if !crate::strings::HasPrefix(vers.clone(), string("HTTP/")) || vers.Len() != 8 {
        return (0, 0, false);
    }
    // Go: if vers[6] != '.' { return 0,0,false }
    if vers[6] != b'.' {
        return (0, 0, false);
    }
    // Go: maj, err := strconv.ParseUint(vers[5:6], 10, 0)
    let mb: byte = vers[5];
    let nb: byte = vers[7];
    if !mb.is_ascii_digit() || !nb.is_ascii_digit() {
        return (0, 0, false);
    }
    ((mb - b'0') as int, (nb - b'0') as int, true)
}

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

/// Line-by-line port of `parseBasicAuth` (request.go:993).
fn parse_basic_auth(auth: string) -> (string, string, bool) {
    // Go: const prefix = "Basic "
    // Go: if len(auth) < len(prefix) || !ascii.EqualFold(auth[:len(prefix)], prefix) { return "","",false }
    if auth.Len() < 6 {
        return (string::new(), string::new(), false);
    }
    let head_bytes = &auth.as_bytes()[..6];
    let head = string::from_bytes(head_bytes);
    if !crate::strings::EqualFold(head, string("Basic ")) {
        return (string::new(), string::new(), false);
    }
    // Go: c, err := base64.StdEncoding.DecodeString(auth[len(prefix):])
    let payload_bytes = &auth.as_bytes()[6..];
    let payload_str = match core::str::from_utf8(payload_bytes) {
        Ok(s) => s,
        Err(_) => return (string::new(), string::new(), false),
    };
    let (decoded, derr) = crate::encoding::base64::StdEncoding.DecodeString(payload_str);
    if !derr.IsNil() {
        return (string::new(), string::new(), false);
    }
    // Go: cs := string(c); username, password, ok := strings.Cut(cs, ":")
    let cs = crate::convert::string(decoded);
    let (user, pass, ok) = crate::strings::Cut(cs, string(":"));
    if !ok {
        return (string::new(), string::new(), false);
    }
    (user, pass, true)
}

// ─── MaxBytesReader (line-by-line port of request.go:1186) ───────────

/// `http.MaxBytesReader(w, r, n)` — returns a `Reader` that stops
/// reading from `r` after `n` bytes, returning `MaxBytesError` once
/// the limit is exceeded. Slim port: drops Go's `requestTooLarge`
/// connection-close hook (goish ResponseWriter doesn't expose one
/// yet) and the `io.ReadCloser` aspect (Reader-only).
pub struct MaxBytesReader<R: io::Reader> {
    inner: R,
    initial: int,
    remaining: int,
    err: error,
}

/// `http.MaxBytesReader` returned-error sentinel (request.go:1193).
pub fn ErrMaxBytes() -> error {
    use crate::runtime::spin::SpinLock;
    static SLOT: SpinLock<Option<error>> = SpinLock::new(None);
    let mut g = SLOT.lock();
    if g.is_none() {
        *g = Some(errors::New(string("http: request body too large")));
    }
    g.as_ref().unwrap().clone()
}

pub fn NewMaxBytesReader<R: io::Reader>(r: R, n: int) -> MaxBytesReader<R> {
    // Go: if n < 0 { n = 0 }
    let n = if n < 0 { 0 } else { n };
    MaxBytesReader {
        inner: r,
        initial: n,
        remaining: n,
        err: errors::nil,
    }
}

impl<R: io::Reader> io::Reader for MaxBytesReader<R> {
    fn Read(&mut self, p: &mut slice<byte>) -> (int, error) {
        // Go: if l.err != nil { return 0, l.err }
        if !self.err.IsNil() {
            return (0, self.err.clone());
        }
        // Go: if len(p) == 0 { return 0, nil }
        if p.Len() == 0 {
            return (0, errors::nil);
        }
        // Go: if int64(len(p))-1 > l.n { p = p[:l.n+1] }
        // We can't shrink the caller's slice; instead read into a tmp.
        let cap = if p.Len() - 1 > self.remaining {
            self.remaining + 1
        } else {
            p.Len()
        };
        let mut tmp = crate::make!([]byte, cap);
        let (n, err) = self.inner.Read(&mut tmp);
        // Copy what we read into p.
        for i in 0..n {
            p[i] = tmp[i];
        }
        // Go: if int64(n) <= l.n { l.n -= int64(n); l.err = err; return n, err }
        if n <= self.remaining {
            self.remaining -= n;
            self.err = err.clone();
            return (n, err);
        }
        // Go: n = int(l.n); l.n = 0; … return n, MaxBytesError
        let limited_n = self.remaining;
        self.remaining = 0;
        let _ = self.initial; // tagged but unused (slim version)
        self.err = ErrMaxBytes();
        (limited_n, self.err.clone())
    }
}

// ─── Form helpers (line-by-line port of request.go:1245-1306) ────────

/// `parsePostForm(r)` (request.go:1245). Reads body when content type
/// is application/x-www-form-urlencoded; otherwise returns empty.
fn parse_post_form(r: &Request) -> (crate::gomap::map<string, slice<string>>, error) {
    use crate::gomap::map;
    // Go: if r.Body == nil { return … }
    if r.Body.Len() == 0 && r.ContentLength <= 0 {
        return (map::<string, slice<string>>::new(), errors::nil);
    }
    // Go: ct := r.Header.Get("Content-Type")
    let ct = r.Header.Get(string("Content-Type"));
    // Strip parameters: "application/x-www-form-urlencoded; charset=utf-8" → base
    let (base, _, _) = crate::strings::Cut(ct, string(";"));
    let base = crate::strings::TrimSpace(base);
    // Go: switch ct { case "application/x-www-form-urlencoded": … }
    if !crate::strings::EqualFold(base, string("application/x-www-form-urlencoded")) {
        return (map::<string, slice<string>>::new(), errors::nil);
    }
    // Go: b, e := io.ReadAll(reader)
    // We already have r.Body fully buffered; just decode it as a string.
    let body_bytes = r.Body.clone();
    let body_str = crate::convert::string(body_bytes);
    super::url::ParseQuery(body_str)
}

/// Merge `src` into `dst` (append values). Mirrors `copyValues`
/// (request.go:1238).
fn copy_values(
    dst: &mut crate::gomap::map<string, slice<string>>,
    src: &crate::gomap::map<string, slice<string>>,
) {
    for (k, v) in src.__iter() {
        let (existing, _) = dst.Get(k.clone());
        let mut merged = existing;
        for i in 0..v.Len() {
            merged = crate::append!(merged, v[i].clone());
        }
        dst.Set(k.clone(), merged);
    }
}

