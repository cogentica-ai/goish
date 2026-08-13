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
//   * Request contexts are honored: `RoundTrip` fast-fails a done
//     ctx, folds `ctx.Deadline()` into conn deadlines, and a cancel
//     watcher interrupts blocked I/O (HTTP path; TLS gets deadline
//     folding only). `Client.Timeout` re-parents the request under
//     `context.WithTimeout` — one deadline across all redirect hops.
//   * `Request.Body` is a pre-buffered `slice<byte>` (matches the
//     existing Request type in goish v1).
//   * `Response.Body` is a streaming `Body` (Go's `io.ReadCloser`
//     shape): `RoundTrip` returns after parsing the response head,
//     and the conn lives inside the Body until `Close`. Read sees
//     flushed chunks as they arrive — the substrate for SSE/LLM
//     token streaming. Callers `io::ReadAll(&mut resp.Body)` +
//     `resp.Body.Close()` exactly like Go. (The public
//     `ReadResponse` helper still returns a pre-drained Body — its
//     borrowed-reader signature can't carry ownership.)
//   * No automatic decompression (no `Accept-Encoding: gzip`).

#![allow(non_snake_case)]
#![allow(dead_code)]

extern crate alloc;

use alloc::sync::Arc;
use alloc::vec::Vec;

use crate::bufio;
use crate::errors::{self, error};
use crate::gonilable::nilable;
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

/// `http.Response` (response.go:35). `Body` streams from the wire
/// (Go's `io.ReadCloser` shape) — see the `Body` type below.
#[derive(Clone)]
pub struct Response {
    pub Status: string,    // "200 OK"
    pub StatusCode: int,
    pub Proto: string,
    pub ProtoMajor: int,
    pub ProtoMinor: int,
    pub Header: Header,
    pub Body: Body,
    /// `-1` if unknown (chunked / no Content-Length on a non-empty body).
    pub ContentLength: int,
    /// Whether the connection should be closed after reading Body.
    pub Close: bool,
    /// The Request that produced this Response. Populated by Client::Do.
    /// Modelled as `nilable<Request>` (Go's `*http.Request` shape) so
    /// Goish-side `resp.Request.URL` access can narrow via `.Must()`.
    pub Request: nilable<Request>,
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
            Body: Body::default(),
            ContentLength: 0,
            Close: false,
            Request: nilable::nil(),
        }
    }
}

// ─── Body — Go's `Response.Body io.ReadCloser`, streaming ────────────
//
// The conn (TCP or TLS), wrapped in the head-parse's bufio reader
// (which may hold read-ahead body bytes), moves INTO the Body when
// `RoundTrip` returns. `Read` pulls framed bytes off the wire on
// demand; `Close` stops the ctx-cancel watcher and closes the conn.
// Interior `Arc<sync::Mutex<…>>` keeps `Response: Clone` working —
// clones share one read cursor, exactly like Go sharing one
// `io.ReadCloser` value.

/// Which conn a streaming body reads from. The bufio layer is the one
/// `read_response_head` parsed the head through — its buffer may
/// already hold the first body bytes.
enum ConnSrc {
    Tcp(bufio::Reader<crate::net::TCPConn>),
    Tls(bufio::Reader<crate::crypto::tls::Conn>),
}

impl Reader for ConnSrc {
    fn Read(&mut self, p: &mut slice<byte>) -> (int, error) {
        match self {
            ConnSrc::Tcp(br) => br.Read(p),
            ConnSrc::Tls(br) => br.Read(p),
        }
    }
}

impl ConnSrc {
    fn close_conn(&mut self) -> error {
        match self {
            ConnSrc::Tcp(br) => br.__rd_mut().Close(),
            ConnSrc::Tls(br) => br.__rd_mut().Close(),
        }
    }
}

/// Wire framing of a body-in-progress. Mirrors Go's transfer.go body
/// readers: `body` over a LimitedReader (Content-Length), over a
/// chunkedReader (TE: chunked), or straight to EOF (Connection:
/// close). `Eager` is a fully-materialized body (ReadResponse,
/// DumpResponse replacement, `Body::from`).
enum FramedBody {
    Eager { data: slice<byte>, off: int },
    Cl { src: ConnSrc, remaining: int },
    Chunked { cr: super::internal::chunked::ChunkedReader<ConnSrc> },
    UntilEof { src: ConnSrc },
    Closed,
}

struct BodyState {
    framing: FramedBody,
    /// Request ctx — a Read kicked out by the cancel watcher maps its
    /// wire error to ctx.Err(), like `ctx_err_or` on the head path.
    ctx: Option<Arc<dyn crate::context::Context>>,
    /// The ctx-cancel watcher (see `arm_cancel_watch`). MUST be
    /// stopped before the conn closes — it dereferences the conn's
    /// PollDesc.
    watch: Option<(crate::gochan::chan<()>, crate::gochan::chan<()>)>,
    /// `Client.Timeout`'s WithTimeout release — Go's setRequestCancel
    /// stops the timer when the body is closed, not when Do returns
    /// (the deadline covers body reads).
    cancel: Option<crate::context::CancelFunc>,
}

fn read_locked(st: &mut BodyState, p: &mut slice<byte>) -> (int, error) {
    let (n, err) = match &mut st.framing {
        FramedBody::Eager { data, off } => {
            let total = data.Len();
            if *off >= total {
                (0, io::EOF.into())
            } else {
                let want = (total - *off).min(p.Len());
                for i in 0..want {
                    p[i] = data[*off + i];
                }
                *off += want;
                (want, errors::nil)
            }
        }
        FramedBody::Cl { src, remaining } => {
            if *remaining <= 0 {
                (0, io::EOF.into())
            } else {
                // Never read past the framing boundary off the conn.
                let want = (*remaining).min(p.Len());
                let (n, e) = if p.Len() > want {
                    let mut tmp = make!([]byte, want);
                    let (n, e) = src.Read(&mut tmp);
                    for i in 0..n {
                        p[i] = tmp[i];
                    }
                    (n, e)
                } else {
                    src.Read(p)
                };
                *remaining -= n;
                if !e.IsNil() && errors::Is(e.clone(), io::EOF) && *remaining > 0 {
                    // Conn died mid-body — Go surfaces ErrUnexpectedEOF.
                    (n, io::ErrUnexpectedEOF.into())
                } else {
                    (n, e)
                }
            }
        }
        FramedBody::Chunked { cr } => cr.Read(p),
        FramedBody::UntilEof { src } => src.Read(p),
        FramedBody::Closed => (
            0,
            errors::New(string("http: read on closed response body")),
        ),
    };
    // A read interrupted by the cancel watcher surfaces as a timeout
    // off the netpoller; prefer ctx.Err() (context canceled /
    // deadline exceeded), matching Go's url.Error unwrapping.
    if !err.IsNil() && !errors::Is(err.clone(), io::EOF) {
        if let Some(c) = &st.ctx {
            let ce = c.Err();
            if !ce.IsNil() {
                return (n, ce);
            }
        }
    }
    (n, err)
}

fn close_locked(st: &mut BodyState) -> error {
    // Watcher first — it holds a raw PollDesc pointer into the conn.
    if let Some(w) = st.watch.take() {
        stop_cancel_watch(Some(w));
    }
    let err = match &mut st.framing {
        FramedBody::Cl { src, .. } | FramedBody::UntilEof { src } => src.close_conn(),
        FramedBody::Chunked { cr } => cr.__bufio_mut().__rd_mut().close_conn(),
        _ => errors::nil,
    };
    st.framing = FramedBody::Closed;
    // Release the Client.Timeout timer, if we carry one.
    if let Some(c) = st.cancel.take() {
        c();
    }
    err
}

impl Drop for BodyState {
    fn drop(&mut self) {
        // Un-Closed stream dropped (body leaked without Close, or a
        // redirect hop discarded) — release the conn + watcher.
        let _ = close_locked(self);
    }
}

/// `http.Response.Body` — a streaming `io.ReadCloser`.
///
///   let (body, err) = io::ReadAll(&mut resp.Body);   // io.ReadAll(resp.Body)
///   let _ = resp.Body.Close();                       // resp.Body.Close()
///
/// Incremental reads see flushed chunks the moment they arrive.
#[derive(Clone)]
pub struct Body {
    inner: Arc<crate::sync::Mutex<BodyState>>,
}

impl Body {
    fn from_parts(
        framing: FramedBody,
        ctx: Option<Arc<dyn crate::context::Context>>,
        watch: Option<(crate::gochan::chan<()>, crate::gochan::chan<()>)>,
    ) -> Body {
        Body {
            inner: Arc::new(crate::sync::Mutex::new(BodyState {
                framing,
                ctx,
                watch,
                cancel: None,
            })),
        }
    }

    /// Fully-materialized body over `data` — the shape `ReadResponse`
    /// returns and `httputil` reconstructs. Reads walk the bytes,
    /// then EOF; Close is a no-op state flip.
    pub fn from_bytes(data: slice<byte>) -> Body {
        Body::from_parts(FramedBody::Eager { data, off: 0 }, None, None)
    }

    /// Crate-internal: hand the `Client.Timeout` WithTimeout release
    /// to the body — invoked on Close/Drop (Go client.go:394 shape).
    pub(crate) fn __set_cancel(&self, cancel: crate::context::CancelFunc) {
        let mut g = self.inner.Lock();
        g.cancel = Some(cancel);
    }

    /// Crate-internal (DumpResponse): drain the unread remainder,
    /// close any underlying conn, and leave the body re-readable as
    /// an Eager copy of that remainder — Go's `drainBody` shape.
    pub(crate) fn __drain_remainder(&self) -> (slice<byte>, error) {
        let mut g = self.inner.Lock();
        let mut out = make!([]byte, 0);
        let mut chunk = make!([]byte, 4096);
        loop {
            let (n, err) = read_locked(&mut g, &mut chunk);
            for i in 0..n {
                out = append!(out, chunk[i]);
            }
            if !err.IsNil() {
                if errors::Is(err.clone(), io::EOF) {
                    break;
                }
                return (out, err);
            }
        }
        // Release conn + watcher, then become the remainder.
        let _ = close_locked(&mut g);
        g.framing = FramedBody::Eager {
            data: out.clone(),
            off: 0,
        };
        (out, errors::nil)
    }

    /// Crate-internal: Close through a shared handle (`&self`) — the
    /// redirect loop discards hop responses without a `mut` binding.
    pub(crate) fn __close_shared(&self) -> error {
        let mut g = self.inner.Lock();
        close_locked(&mut g)
    }
}

impl Default for Body {
    fn default() -> Self {
        Body::from_bytes(slice::<byte>::__from_vec(Vec::new()))
    }
}

impl From<slice<byte>> for Body {
    fn from(data: slice<byte>) -> Body {
        Body::from_bytes(data)
    }
}

impl Reader for Body {
    fn Read(&mut self, p: &mut slice<byte>) -> (int, error) {
        let mut g = self.inner.Lock();
        read_locked(&mut g, p)
    }
}

impl Closer for Body {
    fn Close(&mut self) -> error {
        self.__close_shared()
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
        if let Some(req) = self.Request.Try() {
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

/// Body framing of a parsed response head — which wire discipline the
/// body bytes follow. Mirrors the transfer.go decision tree.
pub(crate) enum BodyKind {
    /// HEAD / 1xx / 204 / 304, or no CL + no TE + no close.
    Empty,
    /// `Transfer-Encoding: chunked`.
    Chunked,
    /// `Content-Length: n` with n > 0.
    Cl(int),
    /// No CL, no TE, `Connection: close` — body runs to conn EOF.
    UntilEof,
}

/// `http.ReadResponse(b, req)` — parse an HTTP/1.x response from the
/// buffered reader. Mirrors response.go:154.
///
/// On success the reader has consumed up through the response body,
/// which is returned pre-drained (an `Eager` Body) — the borrowed
/// reader can't move into a streaming Body. The client's `RoundTrip`
/// uses `read_response_head` + an owned reader to stream instead.
/// The `req` argument is recorded into `Response.Request` so callers
/// can chain `Location()` etc.
pub fn ReadResponse<R: Reader>(
    br: &mut bufio::Reader<R>,
    req: Option<Request>,
) -> (Response, error) {
    let (mut resp, kind, err) = read_response_head(br, req);
    if !err.IsNil() {
        return (resp, err);
    }
    match kind {
        BodyKind::Empty => {
            resp.Body = Body::default();
        }
        BodyKind::Chunked => {
            let body = make!([]byte, 0);
            let mut cr = super::internal::chunked::NewChunkedReader(BufioPassthrough { inner: br });
            let (b, err) = drain_to_eof(&mut cr, body);
            if !err.IsNil() && !errors::Is(err.clone(), io::EOF) {
                return (resp, err);
            }
            resp.Body = Body::from_bytes(b);
        }
        BodyKind::Cl(n) => {
            let want = n;
            let mut body = make!([]byte, want);
            // Go: io.ReadFull(r, body)
            let (got, ferr) = read_full_into(br, &mut body);
            if !ferr.IsNil() && !errors::Is(ferr.clone(), io::EOF) {
                return (resp, ferr);
            }
            if got < want {
                body = body.slice(0, got);
            }
            resp.Body = Body::from_bytes(body);
        }
        BodyKind::UntilEof => {
            let body = make!([]byte, 0);
            let (b, err) = drain_to_eof(br, body);
            if !err.IsNil() && !errors::Is(err.clone(), io::EOF) {
                return (resp, err);
            }
            resp.Body = Body::from_bytes(b);
        }
    }
    (resp, errors::nil)
}

/// Parse status line + headers + framing decision, WITHOUT touching
/// body bytes. `resp.ContentLength` / `resp.Close` are set; the
/// returned `BodyKind` says how the bytes that follow are framed.
pub(crate) fn read_response_head<R: Reader>(
    br: &mut bufio::Reader<R>,
    req: Option<Request>,
) -> (Response, BodyKind, error) {
    let mut resp = Response::default();
    resp.Request = match req {
        Some(r) => nilable::new(r),
        None => nilable::nil(),
    };

    // Status line: "HTTP/1.1 200 OK\r\n"
    let line = match read_crlf_line(br) {
        Ok(l) => l,
        Err(e) => return (resp, BodyKind::Empty, e),
    };
    let lb = line.as_bytes();
    let sp1 = match lb.iter().position(|&b| b == b' ') {
        Some(i) => i,
        None => {
            return (
                resp,
                BodyKind::Empty,
                errors::New(string("http: malformed response status line")),
            )
        }
    };
    resp.Proto = string::from_bytes(&lb[..sp1]);
    let rest = &lb[sp1 + 1..];
    let sp2 = rest.iter().position(|&b| b == b' ').unwrap_or(rest.len());
    let code_b = &rest[..sp2];
    if code_b.len() != 3 {
        return (
            resp,
            BodyKind::Empty,
            errors::New(string("http: malformed HTTP status code")),
        );
    }
    let mut code: int = 0;
    for &b in code_b {
        if !b.is_ascii_digit() {
            return (
                resp,
                BodyKind::Empty,
                errors::New(string("http: malformed HTTP status code")),
            );
        }
        code = code * 10 + (b - b'0') as int;
    }
    resp.StatusCode = code;
    resp.Status = string::from_bytes(rest);
    let (major, minor) = parse_http_version(&resp.Proto);
    if major == 0 {
        return (
            resp,
            BodyKind::Empty,
            errors::New(string("http: malformed HTTP version")),
        );
    }
    resp.ProtoMajor = major;
    resp.ProtoMinor = minor;

    // Headers.
    loop {
        let h = match read_crlf_line(br) {
            Ok(l) => l,
            Err(e) => return (resp, BodyKind::Empty, e),
        };
        if h.Len() == 0 {
            break;
        }
        let hb = h.as_bytes();
        let colon = match hb.iter().position(|&b| b == b':') {
            Some(i) => i,
            None => {
                return (
                    resp,
                    BodyKind::Empty,
                    errors::New(string("http: malformed response header")),
                )
            }
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
    let head_only = match resp.Request.Try() {
        Some(r) => r.Method == "HEAD",
        None => false,
    };
    let no_body = head_only
        || (resp.StatusCode >= 100 && resp.StatusCode < 200)
        || resp.StatusCode == 204
        || resp.StatusCode == 304;

    if no_body {
        resp.ContentLength = 0;
        return (resp, BodyKind::Empty, errors::nil);
    }
    if chunked {
        // Go: resp.TransferEncoding = []string{"chunked"}; resp.ContentLength = -1
        resp.ContentLength = -1;
        return (resp, BodyKind::Chunked, errors::nil);
    }
    if cl_str.Len() > 0 {
        // Go: cl, err := strconv.ParseInt(cls, 10, 64)
        let (n, perr) = crate::strconv::Atoi(cl_str);
        if !perr.IsNil() || n < 0 {
            return (
                resp,
                BodyKind::Empty,
                errors::New(string("http: invalid Content-Length")),
            );
        }
        resp.ContentLength = n;
        if n == 0 {
            return (resp, BodyKind::Empty, errors::nil);
        }
        return (resp, BodyKind::Cl(n), errors::nil);
    }
    if resp.Close {
        // Go: no CL, no TE, Connection: close → body runs to conn EOF.
        resp.ContentLength = -1;
        return (resp, BodyKind::UntilEof, errors::nil);
    }
    // Go: no CL, no TE, no close — body is empty.
    resp.ContentLength = 0;
    (resp, BodyKind::Empty, errors::nil)
}

/// Read until EOF into `body`, returning the appended slice and any
/// non-EOF error. Mirrors Go's `io.ReadAll` loop — only exits on error
/// (including io.EOF). A (0, nil) return is treated as "keep reading",
/// matching Go's `io.Reader` contract: "0 bytes and nil error is not EOF".
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
        // Go's io.ReadAll does NOT exit on (0, nil) — it keeps looping.
        // Exiting here was wrong: a reader that temporarily returns 0 bytes
        // without error (e.g., a MockReader injecting zeros, or a TLS record
        // boundary where no data is ready yet) would cause silent body truncation.
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
            return (got, io::EOF.into());
        }
    }
    (got, errors::nil)
}

// ─── RoundTripper / Transport ────────────────────────────────────────

/// `http.RoundTripper` — single-method interface that executes a
/// request and returns the response. Mirrors transport.go:103.
#[goish::interface]
pub trait RoundTripper: Send + Sync {
    fn RoundTrip(&self, req: &Request) -> (Response, error);
}

// `__NilRoundTripper`, `From<Nil> for Box<dyn RoundTripper>`, and
// `From<Nil> for Arc<dyn RoundTripper + Send + Sync>` are all auto-
// generated by `#[goish::interface]` above (sections 6.9 and 7 of the
// macro). The hand-emitted `From<Nil> for Arc<dyn RoundTripper>` that
// used to live here was removed when the macro started emitting it
// directly — keeping it would cause an E0119 coherence conflict.

/// Type alias for the proxy-resolver closure shape. Go: `func(*Request)
/// (*url.URL, error)`. Goish carries an opaque boxed closure so the
/// package-level `ProxyFromEnvironment` (and user-supplied resolvers)
/// can be assigned in via the `Transport.Proxy` field. The function
/// shape is left as `Arc<dyn Fn>` rather than a typed closure so we
/// don't need a public URL type in the surface.
pub type ProxyResolver = alloc::sync::Arc<dyn Fn() + Send + Sync>;
/// Type alias for the dial-context closure. Same opaque shape as
/// `ProxyResolver` — the real signature would carry `(Context, network,
/// addr) -> (Conn, error)` but those are inert in v1.
pub type DialContextFn = alloc::sync::Arc<dyn Fn() + Send + Sync>;

/// `http.Transport` (transport.go:163). v1: dial-per-request, no idle
/// pool. Field surface mirrors Go's struct so user ports can configure
/// or read these slots; only `Timeout` actually drives behaviour
/// today, the rest are inert metadata until the connection-pool layer
/// lands.
pub struct Transport {
    /// Maximum time `RoundTrip` will spend on the entire request
    /// (dial + write + read). Zero ≡ no timeout.
    pub Timeout: time::Duration,
    /// Disable transparent gzip request/response. Inert in v1.
    pub DisableCompression: bool,
    /// Proxy resolver. `Option` so the zero value is None (`nil` in Go).
    pub Proxy: Option<ProxyResolver>,
    /// Idle-connection eviction timeout. Inert until the connection
    /// pool lands.
    pub IdleConnTimeout: time::Duration,
    /// Per-dial timeout/keepalive callback. `Option` so the zero value
    /// is None.
    pub DialContext: Option<DialContextFn>,
    /// Maximum time waiting for the TLS handshake. Inert in v1.
    pub TLSHandshakeTimeout: time::Duration,
    /// Maximum time waiting for an Expect: 100-continue response.
    pub ExpectContinueTimeout: time::Duration,
    /// TLS configuration applied per-connection. Inert in v1 (TLS not
    /// yet plumbed); the field exists so user ports can store and
    /// reset it for thread-safety.
    pub TLSClientConfig: crate::crypto::tls::Config,
    /// Disable HTTP keep-alive. Inert in v1 (each request dials anew).
    pub DisableKeepAlives: bool,
    /// Idle-connection-pool cap. Inert until the pool lands.
    pub MaxIdleConns: int,
    /// Per-host idle-connection cap. Inert until the pool lands.
    /// Negative values mean "no pool for this host" in Go.
    pub MaxIdleConnsPerHost: int,
    /// Max in-flight connections per host. Inert in v1.
    pub MaxConnsPerHost: int,
    /// Prefer HTTP/2 over TLS. Inert in v1 (HTTP/2 not yet plumbed).
    pub ForceAttemptHTTP2: bool,
}

impl Default for Transport {
    fn default() -> Self {
        Transport {
            Timeout: time::Duration(0),
            DisableCompression: false,
            Proxy: None,
            IdleConnTimeout: time::Duration(0),
            DialContext: None,
            TLSHandshakeTimeout: time::Duration(0),
            ExpectContinueTimeout: time::Duration(0),
            TLSClientConfig: crate::crypto::tls::Config::default(),
            DisableKeepAlives: false,
            MaxIdleConns: 0,
            MaxIdleConnsPerHost: 0,
            MaxConnsPerHost: 0,
            ForceAttemptHTTP2: false,
        }
    }
}

/// `http.ProxyFromEnvironment` — Go's default proxy resolver. v1
/// returns a no-op closure (env-var inspection deferred). Goish ports
/// reference this as `http::ProxyFromEnvironment` (a function call is
/// what produces the resolver value in goish; Go callers assigning the
/// bare identifier go through `From<>` under the hood).
pub fn ProxyFromEnvironment() -> ProxyResolver {
    alloc::sync::Arc::new(|| {})
}

// Polymorphic-nil for Transport. Go's `transport *http.Transport`
// callers do `if transport == nil { … }` — in goish the param is
// `&Transport` which is always non-nil by Rust's borrow guarantee, so
// the comparison returns false. Symmetric impl mirrors the Nil↔T
// triple from priority #5.
impl PartialEq<crate::nilval::Nil> for Transport {
    fn eq(&self, _: &crate::nilval::Nil) -> bool {
        false
    }
}
impl PartialEq<Transport> for crate::nilval::Nil {
    fn eq(&self, _: &Transport) -> bool {
        false
    }
}
impl PartialEq<crate::nilval::Nil> for &Transport {
    fn eq(&self, _: &crate::nilval::Nil) -> bool {
        false
    }
}
impl PartialEq<&Transport> for crate::nilval::Nil {
    fn eq(&self, _: &&Transport) -> bool {
        false
    }
}

impl RoundTripper for Transport {
    fn RoundTrip(&self, req: &Request) -> (Response, error) {
        // Resolve scheme.
        let scheme = req.URL.Scheme.clone();
        let is_https = scheme.as_bytes() == b"https";
        let is_http = scheme.Len() == 0 || scheme.as_bytes() == b"http";
        if !is_http && !is_https {
            return (
                Response::default(),
                errors::New(string("http: only scheme=http and scheme=https are supported")),
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

        // ── request context (Go transport.go:594 roundTrip) ──
        // Fast-fail before dialing if the request's ctx is already
        // done; fold any ctx deadline into the conn deadline below.
        let ctx = req.ctx.clone();
        if let Some(c) = &ctx {
            let cerr = c.Err();
            if !cerr.IsNil() {
                return (Response::default(), cerr);
            }
        }

        if is_https {
            // ── HTTPS path ───────────────────────────────────────────────
            // Dial the raw TCP conn ourselves (instead of tls::Dial's
            // dial-and-handshake) so the deadline and the ctx-cancel
            // watcher are armed on the socket *before* the handshake —
            // Timeout and cancellation cover the ClientHello/ServerHello
            // exchange, not just the request/response I/O after it.
            let dial_addr = ensure_default_port(&host, 443);

            let (raw_conn, derr) = net::Dial(string("tcp"), dial_addr);
            if !derr.IsNil() {
                return (Response::default(), derr);
            }

            // Deadline: Transport.Timeout tightened by the ctx deadline.
            let dl = self.effective_deadline(&ctx);
            if !dl.IsZero() {
                let _ = raw_conn.SetDeadline(dl);
            }

            // ctx-cancel watcher on the underlying socket — TLS reads
            // and writes all funnel into it, so a past netpoll
            // deadline interrupts them exactly like plain HTTP.
            let watch = arm_cancel_watch(&ctx, raw_conn.__disconnect_watch_parts());

            // tls.Client(conn, cfg) + Handshake, SNI from the config
            // or the request host (what tls::Dial would derive).
            let mut tls_cfg = self.TLSClientConfig.clone();
            if tls_cfg.ServerName.Len() == 0 {
                tls_cfg.ServerName = host_without_port(&host);
            }
            let box_conn: alloc::boxed::Box<dyn crate::net::Conn> =
                alloc::boxed::Box::new(raw_conn);
            let mut tls_conn = crate::crypto::tls::Client(box_conn, &tls_cfg);
            let herr = tls_conn.Handshake();
            if !herr.IsNil() {
                stop_cancel_watch(watch);
                let _ = tls_conn.Close();
                return (Response::default(), ctx_err_or(&ctx, herr));
            }

            // Write the request.
            let req_bytes = serialize_request(req, &host);
            let (_, werr) = <crate::crypto::tls::Conn as crate::io::Writer>::Write(
                &mut tls_conn,
                req_bytes,
            );
            if !werr.IsNil() {
                stop_cancel_watch(watch);
                let _ = tls_conn.Close();
                return (Response::default(), ctx_err_or(&ctx, werr));
            }

            // Read the response head; the conn moves into the bufio
            // reader and onward into resp.Body, which streams the
            // body bytes until the caller Closes it.
            let mut br = bufio::NewReader(tls_conn);
            let (mut resp, kind, rerr) = read_response_head(&mut br, Some(req.clone()));
            if !rerr.IsNil() {
                stop_cancel_watch(watch);
                let _ = br.__rd_mut().Close();
                return (resp, ctx_err_or(&ctx, rerr));
            }
            attach_stream_body(&mut resp, kind, ConnSrc::Tls(br), ctx, watch);
            (resp, errors::nil)
        } else {
            // ── HTTP path ────────────────────────────────────────────────
            let dial_addr = ensure_default_port(&host, 80);

            let (mut conn, derr) = net::Dial(string("tcp"), dial_addr);
            if !derr.IsNil() {
                return (Response::default(), derr);
            }

            // Deadline: Transport.Timeout tightened by the ctx deadline.
            let dl = self.effective_deadline(&ctx);
            if !dl.IsZero() {
                let _ = conn.SetDeadline(dl);
            }

            // ctx-cancel watcher (see arm_cancel_watch).
            let watch = arm_cancel_watch(&ctx, conn.__disconnect_watch_parts());

            // Write the request.
            let req_bytes = serialize_request(req, &host);
            let (_, werr) = conn.Write(req_bytes);
            if !werr.IsNil() {
                stop_cancel_watch(watch);
                let _ = conn.Close();
                return (Response::default(), ctx_err_or(&ctx, werr));
            }

            // Read the response head; the conn moves into the bufio
            // reader and onward into resp.Body, which streams the
            // body bytes until the caller Closes it.
            let mut br = bufio::NewReader(conn);
            let (mut resp, kind, rerr) = read_response_head(&mut br, Some(req.clone()));
            if !rerr.IsNil() {
                stop_cancel_watch(watch);
                let _ = br.__rd_mut().Close();
                return (resp, ctx_err_or(&ctx, rerr));
            }
            attach_stream_body(&mut resp, kind, ConnSrc::Tcp(br), ctx, watch);
            (resp, errors::nil)
        }
    }
}

/// Wire a parsed head + owned conn into a streaming `resp.Body`. For
/// `Empty` framing there is nothing left on the wire: the watcher
/// stops and the conn closes immediately (v1 has no idle pool).
fn attach_stream_body(
    resp: &mut Response,
    kind: BodyKind,
    mut src: ConnSrc,
    ctx: Option<Arc<dyn crate::context::Context>>,
    watch: Option<(crate::gochan::chan<()>, crate::gochan::chan<()>)>,
) {
    match kind {
        BodyKind::Empty => {
            stop_cancel_watch(watch);
            let _ = src.close_conn();
            resp.Body = Body::default();
        }
        BodyKind::Cl(n) => {
            resp.Body = Body::from_parts(
                FramedBody::Cl {
                    src,
                    remaining: n,
                },
                ctx,
                watch,
            );
        }
        BodyKind::Chunked => {
            resp.Body = Body::from_parts(
                FramedBody::Chunked {
                    cr: super::internal::chunked::NewChunkedReader(src),
                },
                ctx,
                watch,
            );
        }
        BodyKind::UntilEof => {
            resp.Body = Body::from_parts(FramedBody::UntilEof { src }, ctx, watch);
        }
    }
}

impl Transport {
    /// Effective conn deadline for one roundtrip: `Transport.Timeout`
    /// (if set) tightened by the request ctx's deadline (if any).
    /// Zero Time ⇒ no deadline.
    fn effective_deadline(
        &self,
        ctx: &Option<Arc<dyn crate::context::Context>>,
    ) -> time::Time {
        let mut dl = time::Time::default();
        if self.Timeout.0 > 0 {
            dl = time::Now().Add(self.Timeout);
        }
        if let Some(c) = ctx {
            if let Some(cd) = c.Deadline() {
                if dl.IsZero() || cd.Before(dl) {
                    dl = cd;
                }
            }
        }
        dl
    }
}

/// Prefer the ctx's error over the wire error once the ctx is done —
/// a read kicked out by the cancel watcher's past-deadline surfaces
/// as "context canceled" / "context deadline exceeded", matching
/// Go's url.Error unwrapping to ctx.Err().
fn ctx_err_or(ctx: &Option<Arc<dyn crate::context::Context>>, fallback: error) -> error {
    if let Some(c) = ctx {
        let e = c.Err();
        if !e.IsNil() {
            return e;
        }
    }
    fallback
}

/// Arm the ctx-cancel watcher (Go transport.go persistConn's cancel
/// plumbing, slim). For ctxs whose Done chan is real (WithCancel /
/// WithTimeout), a helper goroutine selects on Done vs a stop chan.
/// On cancellation it slams past deadlines onto the conn's PollDesc,
/// kicking any blocked read/write out with a timeout that the
/// caller's error mapping (`ctx_err_or`) converts to ctx.Err(). TLS
/// conns are covered by arming the *underlying* TCP socket — every
/// TLS record read/write funnels into it.
///
/// Returns `None` (nothing to watch) or the (stop, exited) chan pair
/// to hand to `stop_cancel_watch`, which must run before the conn is
/// closed — the watcher dereferences the conn's PollDesc.
fn arm_cancel_watch(
    ctx: &Option<Arc<dyn crate::context::Context>>,
    parts: (i32, *const crate::runtime::netpoll::PollDesc),
) -> Option<(crate::gochan::chan<()>, crate::gochan::chan<()>)> {
    let c = ctx.as_ref()?;
    let done = c.Done();
    if done.is_nil() {
        return None;
    }
    let (_fd, pd) = parts;
    if pd.is_null() {
        return None;
    }
    let stop = crate::gochan::chan::<()>::new_unbuffered();
    let exited = crate::gochan::chan::<()>::new_unbuffered();
    let stop2 = stop.clone();
    let exited2 = exited.clone();
    let pd_addr = pd as usize;
    crate::go!(move || {
        let fired: bool = crate::select! {
            let _ = done.Recv() => true,
            let _ = stop2.Recv() => false,
        };
        if fired {
            let pd = unsafe { &*(pd_addr as *const crate::runtime::netpoll::PollDesc) };
            crate::runtime::netpoll::set_deadline(pd, -1, b'r');
            crate::runtime::netpoll::set_deadline(pd, -1, b'w');
        }
        exited2.Close();
    });
    Some((stop, exited))
}

/// Stop + join the ctx-cancel watcher. Must run before the conn is
/// closed (the watcher dereferences the conn's PollDesc).
fn stop_cancel_watch(watch: Option<(crate::gochan::chan<()>, crate::gochan::chan<()>)>) {
    if let Some((stop, exited)) = watch {
        stop.Close();
        let (_, _) = exited.Recv();
    }
}

/// Strip a `:port` suffix from `host` — the SNI name for a dialed
/// address (what `tls::Dial` derives internally).
fn host_without_port(host: &string) -> string {
    if !has_port(host) {
        return host.clone();
    }
    let hb = host.as_bytes();
    if let Some(i) = hb.iter().rposition(|&b| b == b':') {
        return string::from_bytes(&hb[..i]);
    }
    host.clone()
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

/// Calls the held `context.CancelFunc` when dropped — the goish
/// rendering of Go's `defer cancel()`. Releases the WithTimeout
/// timer on every return path out of `Client::Do`.
struct __CancelOnDrop(Option<crate::context::CancelFunc>);
impl Drop for __CancelOnDrop {
    fn drop(&mut self) {
        if let Some(c) = self.0.take() {
            c();
        }
    }
}

impl Client {
    /// `(*Client).Do(req)` — execute the request, following up to 10
    /// redirects on 301/302/303/307/308. Mirrors client.go:565.
    ///
    /// `Client.Timeout` bounds the entire exchange (all redirect hops
    /// included) — implemented the way Go's `setRequestCancel`
    /// (client.go:394) does it: the request is re-parented under
    /// `context.WithTimeout`, and the transport folds the context
    /// deadline into its connection deadlines.
    pub fn Do(&self, req: &Request) -> (Response, error) {
        let mut current = req.clone();
        // Whole-exchange deadline via ctx. The drop guard covers the
        // error paths; on success the release migrates into the
        // returned Body (Go's setRequestCancel stops the timer on
        // body Close, not on Do return — the deadline covers body
        // reads).
        let mut _cancel_guard = __CancelOnDrop(None);
        if self.Timeout.0 > 0 {
            let (ctx, cancel) = crate::context::WithTimeout(current.Context(), self.Timeout);
            current = current.WithContext(ctx);
            _cancel_guard.0 = Some(cancel);
        }
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
                        // No Location → return as-is.
                        if let Some(c) = _cancel_guard.0.take() {
                            resp.Body.__set_cancel(c);
                        }
                        return (resp, errors::nil);
                    }
                    // Go: the hop's body is closed before following.
                    let _ = resp.Body.__close_shared();
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
                        // Redirect hops inherit the original request's
                        // context (Go client.go:665: ireq.Context()).
                        ctx: current.ctx.clone(),
                    };
                    // Preserve body only on 307/308 (per RFC).
                    if resp.StatusCode == 307 || resp.StatusCode == 308 {
                        next.Body = current.Body.clone();
                        next.ContentLength = current.ContentLength;
                    }
                    current = next;
                    continue;
                }
                _ => {
                    // Final response: the Timeout release rides along
                    // in the Body, invoked on Close/Drop.
                    if let Some(c) = _cancel_guard.0.take() {
                        resp.Body.__set_cancel(c);
                    }
                    return (resp, errors::nil);
                }
            }
        }
        (
            Response::default(),
            errors::New(string("http: stopped after 10 redirects")),
        )
    }

    /// `(*Client).Get(url)` — issue a GET. Mirrors client.go:481.
    pub fn Get<U: Into<string>>(&self, url: U) -> (Response, error) {
        let (req, err) = NewRequest(string("GET"), url, ());
        if !err.IsNil() {
            return (Response::default(), err);
        }
        self.Do(&req)
    }

    /// `(*Client).Head(url)`.
    pub fn Head<U: Into<string>>(&self, url: U) -> (Response, error) {
        let (req, err) = NewRequest(string("HEAD"), url, ());
        if !err.IsNil() {
            return (Response::default(), err);
        }
        self.Do(&req)
    }

    /// `(*Client).Post(url, contentType, body)`. Like Go's `body
    /// io.Reader` slot, the body is polymorphic: `nil`, `slice<byte>`,
    /// `string`, and `&str` literals all work (same `__RequestBody`
    /// dispatch as `NewRequest`).
    pub fn Post<U: Into<string>, C: Into<string>, B: __RequestBody>(
        &self,
        url: U,
        content_type: C,
        body: B,
    ) -> (Response, error) {
        let (mut req, err) = NewRequest(string("POST"), url, body);
        if !err.IsNil() {
            return (Response::default(), err);
        }
        req.Header.Set(string("Content-Type"), content_type.into());
        self.Do(&req)
    }

    /// `(*Client).PostForm(url, vals)` — POST `application/x-www-form-urlencoded`
    /// body built from key=value pairs.
    pub fn PostForm<U: Into<string>>(&self, url: U, vals: &[(string, string)]) -> (Response, error) {
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
pub fn Get<U: Into<string>>(url: U) -> (Response, error) {
    default_client().Get(url)
}

/// `http.Head(url)`.
pub fn Head<U: Into<string>>(url: U) -> (Response, error) {
    default_client().Head(url)
}

/// `http.Post(url, contentType, body)`. Body is polymorphic like
/// Go's `io.Reader` slot — `nil` / `slice<byte>` / `string` / `&str`.
pub fn Post<U: Into<string>, C: Into<string>, B: __RequestBody>(
    url: U,
    content_type: C,
    body: B,
) -> (Response, error) {
    default_client().Post(url, content_type, body)
}

/// `http.PostForm(url, vals)`.
pub fn PostForm<U: Into<string>>(url: U, vals: &[(string, string)]) -> (Response, error) {
    default_client().PostForm(url, vals)
}

// ─── NewRequest ──────────────────────────────────────────────────────

/// `http.NewRequestWithContext(ctx, method, url, body)` (request.go:898).
/// The ctx is stored on the Request and visible via `r.Context()`.
/// (v1 slim: the client transport doesn't yet observe ctx
/// cancellation mid-roundtrip — `Client.Timeout` bounds the wire.)
pub fn NewRequestWithContext<M: Into<string>, U: Into<string>, B: __RequestBody>(
    ctx: alloc::sync::Arc<dyn crate::context::Context>,
    method: M,
    url: U,
    body: B,
) -> (Request, error) {
    let (req, err) = NewRequest(method, url, body);
    if !err.IsNil() {
        return (req, err);
    }
    (req.WithContext(ctx), err)
}

/// Body-arg dispatch — lets `http::NewRequest`/`Client::Post` accept
/// any of: `nil` (no body, mirrors Go's `nil`), `slice<byte>` (raw
/// bytes), `string` (bytes-of-string), or `&'static str` (literal
/// body sugar). Mirrors Go's `body io.Reader` accepting `nil` plus
/// `*bytes.Reader` / `*strings.Reader` constructors. The future
/// `io.Reader`-streaming port will plug in here as another impl.
pub trait __RequestBody {
    #[doc(hidden)]
    fn __to_body(self) -> slice<byte>;
}

/// `http::NewRequest("GET", url, nil)` — Goish's polymorphic nil
/// sentinel as a body, exactly mirroring Go's `body == nil` slot.
impl __RequestBody for crate::nilval::Nil {
    #[inline]
    fn __to_body(self) -> slice<byte> {
        slice::<byte>::__from_vec(Vec::new())
    }
}

// `()` retained for backwards compatibility while old call sites
// migrate; new code should pass `nil`.
impl __RequestBody for () {
    #[inline]
    fn __to_body(self) -> slice<byte> {
        slice::<byte>::__from_vec(Vec::new())
    }
}

impl __RequestBody for slice<byte> {
    #[inline]
    fn __to_body(self) -> slice<byte> {
        self
    }
}

impl __RequestBody for string {
    #[inline]
    fn __to_body(self) -> slice<byte> {
        crate::convert::bytes(self)
    }
}

impl __RequestBody for &'static str {
    #[inline]
    fn __to_body(self) -> slice<byte> {
        crate::convert::bytes(self)
    }
}

/// `http.NewRequest(method, url, body)` — slim. Body accepts `()`
/// (no body, like Go's `nil`), a `slice<byte>`, a `string`, or a
/// `&'static str` via the `__RequestBody` trait. Real `io.Reader`
/// streaming is the C1 follow-up.
pub fn NewRequest<M: Into<string>, U: Into<string>, B: __RequestBody>(
    method: M,
    url: U,
    body: B,
) -> (Request, error) {
    let method: string = method.into();
    let url: string = url.into();
    let body: slice<byte> = body.__to_body();
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
        ctx: None,
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
        ctx: None,
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


// go: none — goish idiom: `ConnSrc` is unexported, so only this module
// can register it. See AGENTS.md §9b.
pub(super) fn register_client_impls() {
    crate::io::__goish_register_Reader_impl::<Body>();
    crate::io::__goish_register_Closer_impl::<Body>();
    crate::io::__goish_register_Reader_impl::<ConnSrc>();
    __goish_register_RoundTripper_impl::<Transport>();
}
