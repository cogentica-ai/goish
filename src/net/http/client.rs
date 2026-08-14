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

use super::header::Header;
use super::response::Response;
use super::request::Request;
use super::url::URL;

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
        // Go (transfer.go, fixTransferEncoding):
        //   resp.TransferEncoding = []string{"chunked"}
        //   resp.ContentLength = -1
        //
        // The comment here already said so; only the ContentLength
        // half was ever written. `Response.TransferEncoding` was added
        // earlier today when GOISH019 reported it missing from the
        // struct, and then nothing populated it — so a chunked
        // response decoded correctly but reported an empty
        // TransferEncoding, and any caller branching on it (Go's own
        // `chunked(r.TransferEncoding)` helper, for one) saw the wrong
        // framing.
        resp.TransferEncoding =
            crate::goslice::slice::<string>::__from_vec(alloc::vec![string("chunked")]);
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
pub(crate) fn drain_to_eof<R: Reader>(r: &mut R, mut body: slice<byte>) -> (slice<byte>, error) {
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
pub(crate) fn read_full_into<R: Reader>(r: &mut bufio::Reader<R>, buf: &mut slice<byte>) -> (int, error) {
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

    // go: none — goish rendering of Go's OPTIONAL `closeIdler`
    // interface. Go's Client.CloseIdleConnections probes the
    // transport for an unexported
    //
    //     interface { CloseIdleConnections() }
    //
    // and does nothing when it is not implemented. Rust cannot probe
    // a `dyn Trait` for an unrelated interface, so the method lives
    // on RoundTripper with a DEFAULT no-op body: an implementor that
    // holds connections overrides it, one that does not inherits the
    // no-op. Same observable behaviour, and no downcast.
    fn CloseIdleConnections(&self) {}
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
    /// `Client.Jar` (client.go) — the cookie jar. When set, the jar
    /// supplies the request's Cookie header and receives the
    /// response's Set-Cookie headers, INCLUDING across redirects,
    /// which is what makes a session survive a 302.
    ///
    /// goish's `cookiejar` package is fully ported and was
    /// unreachable until this field existed — a whole package ported
    /// and unwired.
    ///
    /// `None` ≡ Go's nil Jar: cookies are neither sent nor stored.
    pub Jar: Option<Arc<dyn super::CookieJar>>,
    /// `Client.CheckRedirect` (client.go) — consulted before every
    /// redirect. `via` holds the requests already made, oldest first.
    ///
    /// Returning an error stops the redirect chain and makes `Do`
    /// return that error. Returning `ErrUseLastResponse` is the
    /// special case: `Do` returns the most recent response with its
    /// body UNCLOSED and no error, which is how a caller inspects a
    /// 3xx instead of following it.
    ///
    /// `None` ≡ Go's nil, which uses `defaultCheckRedirect`: stop
    /// after 10 redirects.
    pub CheckRedirect: Option<Arc<dyn Fn(&Request, &[Request]) -> error + Send + Sync>>,
    /// Whole-request deadline. Zero ≡ no timeout.
    pub Timeout: time::Duration,
}

impl Default for Client {
    fn default() -> Self {
        Client {
            Transport: Arc::new(Transport::default()) as Arc<dyn RoundTripper>,
            Jar: None,
            CheckRedirect: None,
            Timeout: time::Duration(0),
        }
    }
}

// ─── redirect helpers (client.go) ───────────────────────────────────

// go: sdk 1.25.5 net/http/client.go:147-170 refererForURL
/// Go: "refererForURL returns a referer without any authentication
/// info or an empty string if lastReq scheme is https and newReq
/// scheme is http. If the referer was explicitly set, then it will
/// continue to be used."
///
/// The https -> http rule is RFC 7231 5.5.2: a secure page's URL must
/// not leak into a cleartext request. Query and fragment ARE kept;
/// only the userinfo is stripped.
pub fn refererForURL(lastReq: &URL, newReq: &URL, explicitRef: string) -> string {
    if lastReq.Scheme == "https" && newReq.Scheme == "http" {
        return string::new();
    }
    if explicitRef.Len() != 0 {
        return explicitRef;
    }

    // Go strips `lastReq.User.String()+"@"` from the rendered URL
    // here. goish's `url::URL` has NO `User` field — `Parse` splits the
    // authority at the last '@' and DISCARDS the userinfo (url.rs:971)
    // rather than storing it, so a goish URL can never render one and
    // there is nothing to strip. If `URL.User` is ever added (it is a
    // real GOISH019 field-parity gap, along with Opaque/OmitHost/
    // ForceQuery), this function must grow that branch back.
    return lastReq.String();
}

// go: sdk 1.25.5 net/http/client.go:539-547 urlErrorOp
/// Go: the `(*url.Error).Op` value for a method. NOT title-case: Go
/// keeps the first byte VERBATIM and lowercases the rest, so "GET"
/// becomes "Get" but "head" stays "head". A method with non-ASCII
/// bytes is returned unchanged (ascii.ToLower fails).
pub fn urlErrorOp(method: string) -> string {
    if method.Len() == 0 {
        return string("Get");
    }
    let (lowerMethod, ok) = super::internal::ascii::ToLower(method.clone());
    if ok {
        let b = method.as_bytes();
        let lb = lowerMethod.as_bytes();
        let mut out: Vec<u8> = Vec::with_capacity(b.len());
        out.push(b[0]);
        out.extend_from_slice(&lb[1..]);
        return string::from_bytes(&out);
    }
    return method;
}

// go: sdk 1.25.5 net/http/client.go:1011-1032 isDomainOrSubdomain
/// Go: "reports whether sub is a subdomain (or exact match) of the
/// parent domain. Both domains must already be in canonical form."
///
/// The `:%` guard is load-bearing: without it
/// `::1%.www.example.com` would read as a subdomain of
/// `www.example.com` because it ends in `.www.example.com`.
pub fn isDomainOrSubdomain(sub: string, parent: string) -> bool {
    if sub == parent {
        return true;
    }
    // Go: "If sub contains a :, it's probably an IPv6 address (and is
    // definitely not a hostname)."
    if crate::strings::ContainsAny(sub.clone(), string(":%")) {
        return false;
    }
    if !crate::strings::HasSuffix(sub.clone(), parent.clone()) {
        return false;
    }
    // Go: sub must end in "."+parent.
    let sb = sub.as_bytes();
    let idx = sb.len() - parent.as_bytes().len() - 1;
    return sb[idx] == b'.';
}

// go: sdk 1.25.5 net/http/client.go:992-1009 shouldCopyHeaderOnRedirect
/// Go permits sending auth/cookie headers from "foo.com" to
/// "sub.foo.com", but NOT the reverse and not to an unrelated host.
pub fn shouldCopyHeaderOnRedirect(initial: &URL, dest: &URL) -> bool {
    let (ihost, _) = super::request::idnaASCII(initial.Hostname());
    let (dhost, _) = super::request::idnaASCII(dest.Hostname());
    return isDomainOrSubdomain(dhost, ihost);
}

// go: sdk 1.25.5 net/http/client.go:1034-1040 stripPassword
/// Redacts the password in a URL for error messages. An EMPTY password
/// still counts as set: `http://u:@a.com` renders as `http://u:***@a.com`.
pub fn stripPassword(u: &URL) -> string {
    // Same `URL.User` gap as refererForURL above: goish's Parse
    // discards userinfo, so a parsed URL never carries a password to
    // redact and this reduces to String(). Kept as a named port so the
    // rule is in one place when `URL.User` lands. Go's exact behaviour,
    // for whoever adds it: an EMPTY password still counts as set —
    // `http://u:@a.com` renders `http://u:***@a.com`.
    return u.String();
}

// go: sdk 1.25.5 net/http/client.go:505-537 redirectBehavior
/// Go: "describes what should happen when the client encounters a 3xx
/// status code from the server." Returns
/// `(redirectMethod, shouldRedirect, includeBody)`.
///
/// 301/302/303 downgrade ANY non-GET/HEAD method to GET (Issue 18570);
/// 307/308 preserve both method and body. Every other status — 300 and
/// 304 included — is not a redirect at all.
pub fn redirectBehavior(
    reqMethod: string,
    resp: &Response,
    _ireq: &Request,
) -> (string, bool, bool) {
    match resp.StatusCode {
        301 | 302 | 303 => {
            let mut redirectMethod = reqMethod.clone();
            // Go: "RFC 2616 allowed automatic redirection only with GET
            // and HEAD requests. RFC 7231 lifts this restriction, but we
            // still restrict other methods to GET to maintain
            // compatibility. See Issue 18570."
            if reqMethod != "GET" && reqMethod != "HEAD" {
                redirectMethod = string("GET");
            }
            return (redirectMethod, true, false);
        }
        307 | 308 => {
            // Go additionally clears shouldRedirect when the original
            // request had a body but no GetBody to replay it. goish's
            // Request carries its body as an owned `slice<byte>`, which
            // is always replayable, so that branch cannot arise —
            // GetBody exists to rewind a streaming io.Reader.
            return (reqMethod, true, true);
        }
        _ => {
            return (string::new(), false, false);
        }
    }
}

// go: sdk 1.25.5 net/http/client.go:487 alwaysFalse
pub fn alwaysFalse() -> bool {
    return false;
}

// go: sdk 1.25.5 net/http/client.go:307-313 timeBeforeContextDeadline
/// Go: "reports whether the non-zero Time t is before ctx's deadline,
/// if any. If ctx does not have a deadline, it always reports true."
pub fn timeBeforeContextDeadline(
    t: crate::time::Time,
    ctx: &alloc::sync::Arc<dyn crate::context::Context>,
) -> bool {
    match ctx.Deadline() {
        None => {
            return true;
        }
        Some(d) => {
            return t.Before(d);
        }
    }
}

// go: none — goish-only. Go closes over `ireqhdr` in
// `makeHeadersCopier` (client.go:756); goish holds the same snapshot in
// a struct because the returned closure would otherwise need to own a
// Header across the redirect loop's borrows. Same data, same rule.
pub struct headersCopier {
    ireqhdr: Header,
}

impl Client {
    // go: sdk 1.25.5 net/http/client.go:756-818 Client.makeHeadersCopier
    /// Go: "makes a function that copies headers from the initial
    /// Request, ireq. For every redirect, this function must be called
    /// so that it can copy headers into the upcoming Request."
    ///
    /// The Jar/icookies half of Go's version (issue 17494 — rewriting
    /// the caller's own Cookie header when a hop's Set-Cookie
    /// overrides it) is handled separately in `Do`'s loop, which
    /// already restores `originalCookies` per hop.
    pub fn makeHeadersCopier(&self, ireq: &Request) -> headersCopier {
        return headersCopier {
            ireqhdr: ireq.Header.Clone(),
        };
    }
}

impl headersCopier {
    // go: none — goish-only: Go's makeHeadersCopier RETURNS a closure
    // and this is that closure's body, split out because goish holds
    // the captured header in a struct instead.
    /// Copy the initial request's headers onto `req` — "at least the
    /// safe ones". `stripSensitiveHeaders` drops the six credential
    /// headers Go names.
    pub fn copy(&self, req: &mut Request, stripSensitiveHeaders: bool) {
        for (k, vv) in crate::range!(&self.ireqhdr) {
            let ck = super::header::CanonicalHeaderKey(k.clone());
            let sensitive = ck == "Authorization"
                || ck == "Www-Authenticate"
                || ck == "Cookie"
                || ck == "Cookie2"
                || ck == "Proxy-Authorization"
                || ck == "Proxy-Authenticate";
            if !(sensitive && stripSensitiveHeaders) {
                req.Header.__set_values(k.clone(), vv.clone());
            }
        }
        return;
    }
}

const MAX_REDIRECTS: usize = 10;

// go: sdk 1.25.5 net/http/client.go:489-493 ErrUseLastResponse
//
// Go: "ErrUseLastResponse can be returned by Client.CheckRedirect
// hooks to control how redirects are processed. If returned, the next
// request is not sent and the most recent response is returned with
// its body unclosed."
crate::var! {
    pub ErrUseLastResponse: error = "net/http: use last response";
}

// go: sdk 1.25.5 net/http/client.go:820-825 defaultCheckRedirect
fn defaultCheckRedirect(_req: &Request, via: &[Request]) -> error {
    if via.len() >= MAX_REDIRECTS {
        return errors::New(string("stopped after 10 redirects"));
    }
    return errors::nil;
}

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
    // go: sdk 1.25.5 net/http/client.go:586-588 Client.Do
    //
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
        // Go's defaultCheckRedirect errors when the `via` list has
        // reached 10, i.e. BEFORE issuing an 11th request — so a
        // redirect loop causes exactly MAX_REDIRECTS requests, not
        // MAX_REDIRECTS + 1. `0..=MAX_REDIRECTS` issued eleven,
        // measured against Go's ten with a self-redirecting server.
        // Requests already made, oldest first — Go's `via`.
        let mut via: Vec<Request> = Vec::new();
        // The caller's own Cookie header, before any jar additions.
        let originalCookies = current.Header.Values(string("Cookie"));
        // Go builds this ONCE from the initial request and calls it on
        // every hop (client.go:609, :688). It is what keeps
        // Authorization / Cookie / Proxy-Authorization from following a
        // redirect to an unrelated host.
        let copyHeaders = self.makeHeadersCopier(&current);
        let initialURL = current.URL.clone();
        // Go's flag is STICKY: `if !stripSensitiveHeaders && ...`
        // (client.go:683). Once a hop leaves the initial host's domain,
        // the credentials stay stripped for the rest of the chain —
        // foo.com -> evil.com -> foo.com must NOT restore them.
        let mut stripSensitiveHeaders = false;
        for _step in 0..MAX_REDIRECTS {
            // Go (client.go, send): if c.Jar != nil { for _, cookie
            // := range c.Jar.Cookies(req.URL) { req.AddCookie(cookie) } }
            //
            // Go builds each redirected request's headers from the
            // ORIGINAL request (makeHeadersCopier closes over
            // `ireqhdr`), so the jar's additions from hop N never
            // carry into hop N+1 — the jar re-supplies them for the
            // new URL. goish copies the PREVIOUS hop's header into
            // the redirect, so without this reset the Cookie header
            // accumulated: "sid=abc; sid=abc; hop=1" against Go's
            // "sid=abc; hop=1".
            //
            // Restoring the caller's own Cookie header (captured
            // before the first hop) and letting the jar re-add keeps
            // both halves of Go's rule: a user-set Cookie survives
            // every hop, and jar cookies are recomputed per URL.
            if let Some(jar) = self.Jar.as_ref() {
                current.Header.Del(string("Cookie"));
                for i in 0..originalCookies.len() {
                    current
                        .Header
                        .Add(string("Cookie"), originalCookies[i].clone());
                }
                let cs = jar.Cookies(&current.URL);
                for i in 0..cs.len() {
                    current.AddCookie(&cs[i]);
                }
            }
            let (resp, err) = self.Transport.RoundTrip(&current);
            if !err.IsNil() {
                return (resp, err);
            }
            // Go (client.go, send): if c.Jar != nil { if rc :=
            // resp.Cookies(); len(rc) > 0 { c.Jar.SetCookies(req.URL, rc) } }
            //
            // This runs on EVERY hop, which is what carries a session
            // cookie set by a 302 into the redirected request below.
            if let Some(jar) = self.Jar.as_ref() {
                let rc = resp.Cookies();
                if rc.len() > 0 {
                    jar.SetCookies(&current.URL, rc);
                }
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
                    // Go's redirectBehavior (client.go):
                    //
                    //   301, 302, 303: redirectMethod = reqMethod, but
                    //     "if reqMethod != GET && reqMethod != HEAD
                    //      { redirectMethod = GET }" — ANY other
                    //     method becomes GET. includeBody = false.
                    //   307, 308: method and body both preserved.
                    //
                    // goish special-cased only POST and PUT, so a
                    // DELETE or PATCH followed a 302 UNCHANGED. That
                    // is the dangerous shape: whoever controls the
                    // redirect target gets a destructive method
                    // re-issued against a URL of their choosing.
                    // Converting to GET is exactly what prevents it.
                    let (next_method, _shouldRedirect, includeBody) =
                        redirectBehavior(current.Method.clone(), &resp, &current);
                    let mut next = Request {
                        Close: false,
                        Trailer: Header::new(),
                        TLS: None,
                        RequestURI: string::new(),
                        Method: next_method.clone(),
                        URL: loc.clone(),
                        Proto: string("HTTP/1.1"),
                        ProtoMajor: 1,
                        ProtoMinor: 1,
                        // Headers are NOT copied wholesale here — see
                        // copyHeaders below, which drops the credential
                        // headers when the hop leaves the domain.
                        Header: Header::new(),
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
                    // Go: `includeBody` from redirectBehavior — true
                    // for 307/308 only.
                    if includeBody {
                        next.Body = current.Body.clone();
                        next.ContentLength = current.ContentLength;
                    }

                    // Go client.go:683-688 — decide whether this hop
                    // leaves the initial host's domain, then copy the
                    // initial request's headers minus the sensitive ones.
                    if !stripSensitiveHeaders && initialURL.Host != next.URL.Host {
                        if !shouldCopyHeaderOnRedirect(&initialURL, &next.URL) {
                            stripSensitiveHeaders = true;
                        }
                    }
                    copyHeaders.copy(&mut next, stripSensitiveHeaders);

                    // Go client.go:690-694 — "Add the Referer header
                    // from the most recent request URL to the new one,
                    // if it's not https->http".
                    {
                        let ref_ = refererForURL(
                            &current.URL,
                            &next.URL,
                            next.Header.Get(string("Referer")),
                        );
                        if ref_.Len() != 0 {
                            next.Header.Set(string("Referer"), ref_);
                        }
                    }
                    // Go (client.go): if err := c.checkRedirect(req,
                    //     reqs); err != nil { … }, called BEFORE the
                    // next request is sent. ErrUseLastResponse returns
                    // the current response with its body unclosed.
                    {
                        // Go accumulates `reqs` with the request it
                        // just SENT, then calls checkRedirect(newReq,
                        // reqs) — so `via` holds one entry on the
                        // first redirect, not zero. Pushing after the
                        // call would shift every length by one and
                        // let defaultCheckRedirect run an extra hop.
                        via.push(current.clone());
                        let e = match self.CheckRedirect.as_ref() {
                            Some(fn_) => fn_(&next, &via[..]),
                            None => defaultCheckRedirect(&next, &via[..]),
                        };
                        if !e.IsNil() {
                            let sentinel: error = ErrUseLastResponse.into();
                            if errors::Is(e.clone(), sentinel) {
                                if let Some(c) = _cancel_guard.0.take() {
                                    resp.Body.__set_cancel(c);
                                }
                                return (resp, errors::nil);
                            }
                            return (resp, e);
                        }
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

    // go: sdk 1.25.5 net/http/client.go:953-959 Client.CloseIdleConnections
    //
    /// Closes any connections on the Client's Transport which were
    /// previously connected from a request but are now sitting idle.
    /// It does not interrupt any connections currently in use.
    ///
    /// Go probes the transport for an unexported `closeIdler`
    /// interface and does nothing if it is not implemented. goish's
    /// `RoundTripper` trait has no such optional method, so this
    /// downcasts to the concrete `Transport` — the only implementor
    /// that has connections to close — and is a no-op for any other,
    /// which is the same observable behaviour.
    pub fn CloseIdleConnections(&self) {
        self.Transport.CloseIdleConnections();
    }

    // go: sdk 1.25.5 net/http/client.go:479-485 Client.Get
    //
    /// `(*Client).Get(url)` — issue a GET. Mirrors client.go:481.
    pub fn Get<U: Into<string>>(&self, url: U) -> (Response, error) {
        let (req, err) = NewRequest(string("GET"), url, ());
        if !err.IsNil() {
            return (Response::default(), err);
        }
        self.Do(&req)
    }

    // go: sdk 1.25.5 net/http/client.go:938-944 Client.Head
    //
    /// `(*Client).Head(url)`.
    pub fn Head<U: Into<string>>(&self, url: U) -> (Response, error) {
        let (req, err) = NewRequest(string("HEAD"), url, ());
        if !err.IsNil() {
            return (Response::default(), err);
        }
        self.Do(&req)
    }

    // go: sdk 1.25.5 net/http/client.go:861-868 Client.Post
    //
    /// `(*Client).Post(url, contentType, body)`. Like Go's `body
    /// io.Reader` slot, the body is polymorphic: `nil`, `slice<byte>`,
    /// `string`, and `&str` literals all work (same `__RequestBody`
    /// dispatch as `NewRequest`).
    // go: sdk 1.25.5 net/http/client.go:843-845 Post
//
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

    // go: sdk 1.25.5 net/http/client.go:904-906 Client.PostForm
    //
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

// go: sdk 1.25.5 net/http/client.go:452-454 Get
//
/// `http.Get(url)`.
pub fn Get<U: Into<string>>(url: U) -> (Response, error) {
    default_client().Get(url)
}

// go: sdk 1.25.5 net/http/client.go:922-924 Head
//
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

// go: sdk 1.25.5 net/http/client.go:886-888 PostForm
//
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
    // Go: if !validMethod(method) {
    //         return nil, fmt.Errorf("net/http: invalid method %q", method) }
    //
    // This check was MISSING. `validMethod` has been ported and
    // anchored (request.rs:1200) the whole time and nothing called
    // it, so any string was accepted as a method — including one
    // containing a space or CRLF, which Request.Write then puts
    // straight into the request line. That is a request-smuggling
    // primitive, not a cosmetic gap.
    if !super::request::validMethod(m.clone()) {
        return (
            default_request(),
            errors::New(string("net/http: invalid method \"") + m + string("\"")),
        );
    }
    // Go uses urlpkg.Parse here, NOT parse_request_uri. The latter is
    // for server-side request-line URIs (RFC 9112 origin-form) and
    // differs on two forms NewRequest must handle: a scheme-relative
    // "//host/path" (Parse splits the authority; parse_request_uri
    // treats it all as a path) and userinfo (Parse puts "user:pw" in
    // URL.User, leaving Host clean; parse_request_uri leaves it in
    // Host, which then leaked the credentials into the Host header).
    let (u, perr) = super::url::Parse(url);
    if perr != errors::nil {
        return (default_request(), perr);
    }
    let body_len = body.Len();
    let host = u.Host.clone();
    let req = Request {
        Close: false,
        Trailer: Header::new(),
        TLS: None,
        RequestURI: string::new(),
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
        Close: false,
        Trailer: Header::new(),
        TLS: None,
        RequestURI: string::new(),
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
pub(crate) struct BufioPassthrough<'a, R: Reader> {
    pub(crate) inner: &'a mut bufio::Reader<R>,
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

    // Go (request.go:689-697):
    //     userAgent := defaultUserAgent
    //     if r.Header.has("User-Agent") { userAgent = r.Header.Get("User-Agent") }
    //     if userAgent != "" { …write, sanitized… }
    //
    // The test is `has`, NOT `Get(...) == ""`. Setting User-Agent to
    // the empty string explicitly SUPPRESSES the header; only an
    // ABSENT one gets the default. goish previously checked Get's
    // length, so an explicit blank produced the default anyway — the
    // one documented way to send no User-Agent did not work.
    //
    // The value is also sanitized before writing, the same
    // newline-to-space + trim the header writer applies, so a
    // caller-supplied UA cannot inject a header.
    let mut userAgent = string(super::request::defaultUserAgent);
    if req.Header.has(string("User-Agent")) {
        userAgent = req.Header.Get(string("User-Agent"));
    }
    if userAgent != "" {
        let ua = crate::net::textproto::TrimString(crate::strings::ReplaceAll(
            crate::strings::ReplaceAll(userAgent, string("\n"), string(" ")),
            string("\r"),
            string(" "),
        ));
        let _ = b.WriteString("User-Agent: ");
        let _ = b.WriteString(ua);
        let _ = b.WriteString("\r\n");
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

    // Go (request.go, write): if r.Close { _, err = io.WriteString(w,
    //     "Connection: close\r\n") }
    //
    // This was missing, so a Request with Close set asked for no such
    // thing on the wire and the peer kept the connection open.
    if req.Close {
        let _ = b.WriteString("Connection: close\r\n");
    }

    // Go (request.go:707): err = r.Header.writeSubset(w,
    //     reqWriteExcludeHeader, trace)
    //
    // This used to be a hand-rolled loop that skipped only Host and
    // Content-Length. Three things were wrong with that:
    //
    //  * User-Agent, Transfer-Encoding and Trailer are ALSO synthesized
    //    above, so they went out TWICE — visibly, for User-Agent.
    //  * writeSubset drops a header name that is not a token
    //    (httpguts.ValidHeaderFieldName). The raw loop wrote any key
    //    verbatim, so a key holding CRLF injected a header.
    //  * writeSubset folds newlines to spaces and trims each VALUE,
    //    for the same reason.
    //
    // Routing through it puts request writing on the same hardened
    // path as response writing.
    {
        let mut hb = crate::bytes::Buffer::new();
        let _ = req
            .Header
            .WriteSubset(&mut hb, &super::request::reqWriteExcludeHeader());
        let _ = b.WriteString(string::from_bytes(&hb.Bytes()));
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
