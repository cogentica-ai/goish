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
use crate::io::{self, Closer, Reader};
use crate::string;
use crate::strings;
use crate::time;
use crate::types::{byte, int};
use crate::{append, make};

use super::header::Header;
use super::request::Request;
use super::response::Response;
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
#[doc(hidden)]
pub enum ConnSrc {
    Tcp(bufio::Reader<crate::net::TCPConn>),
    Tls(bufio::Reader<crate::crypto::tls::Conn>),
    /// A caller-supplied connection (Transport.DialTLS/DialTLSContext
    /// — Go stores it as the interface-typed pc.conn). No PollDesc is
    /// reachable through the trait, so the disconnect watch stays
    /// disarmed on these.
    Dyn(bufio::Reader<DynConn>),
}

// go: none — goish-only: the io-trait bridge over a caller-supplied
// `dyn net::Conn` (the net::Conn trait spells Read/Write/Close as its
// own methods, not the io traits bufio wants).
#[doc(hidden)]
pub struct DynConn(pub(crate) alloc::boxed::Box<dyn crate::net::Conn>);

impl Reader for DynConn {
    fn Read(&mut self, p: &mut slice<byte>) -> (int, error) {
        return self.0.Read(p);
    }
}

impl crate::io::Writer for DynConn {
    fn Write(&mut self, p: slice<byte>) -> (int, error) {
        return self.0.Write(p);
    }
}

impl Closer for DynConn {
    fn Close(&mut self) -> error {
        return self.0.Close();
    }
}

impl DynConn {
    pub(crate) fn SetDeadline(&self, t: crate::time::Time) -> error {
        return self.0.SetDeadline(t);
    }
}

impl Reader for ConnSrc {
    fn Read(&mut self, p: &mut slice<byte>) -> (int, error) {
        match self {
            ConnSrc::Tcp(br) => br.Read(p),
            ConnSrc::Tls(br) => br.Read(p),
            ConnSrc::Dyn(br) => br.Read(p),
        }
    }
}

impl ConnSrc {
    pub(crate) fn close_conn(&mut self) -> error {
        match self {
            ConnSrc::Tcp(br) => br.__rd_mut().Close(),
            ConnSrc::Tls(br) => br.__rd_mut().Close(),
            ConnSrc::Dyn(br) => br.__rd_mut().Close(),
        }
    }

    // go: none — goish-only: the write half of the upgraded-body
    // carrier (see newReadWriteCloserBody). Reads drain the bufio
    // remainder first; writes go straight to the conn beneath it.
    pub(crate) fn write(&mut self, p: slice<byte>) -> (int, error) {
        let out = match self {
            ConnSrc::Tcp(br) => crate::io::Writer::Write(br.__rd_mut(), p),
            ConnSrc::Tls(br) => {
                let raw: &[u8] = &p;
                br.__rd_mut().Write(raw)
            }
            ConnSrc::Dyn(br) => crate::io::Writer::Write(br.__rd_mut(), p),
        };
        return out;
    }

    // go: none — goish-only: split the carrier for a full-duplex pump.
    // Go's two copier goroutines share one io.ReadWriteCloser
    // interface value; goish hands the READ side (bufio remainder +
    // conn) to one goroutine and a dup(2)'d WRITE handle to the other.
    // A TLS backend cannot be split this way (the record layer's
    // cipher state is one object), so it reports its unsupportedness
    // instead of corrupting a stream.
    // go: none — goish-only: the TCPConn under a plain-HTTP source
    // (request writes + deadline control). Panics on a TLS source —
    // the plain RoundTrip arm is its only caller.
    pub(crate) fn __tcp_mut(&mut self) -> &mut crate::net::TCPConn {
        match self {
            ConnSrc::Tcp(br) => br.__rd_mut(),
            ConnSrc::Tls(_) | ConnSrc::Dyn(_) => panic!("__tcp_mut on a TLS source"),
        }
    }

    // go: none — goish-only: per-request deadline control over either
    // source (Go sets it on pc.conn, which is the tls.Conn after
    // addTLS — same dispatch).
    pub(crate) fn __set_deadline(&mut self, t: crate::time::Time) -> error {
        let out = match self {
            ConnSrc::Tcp(br) => br.__rd_mut().SetDeadline(t),
            ConnSrc::Tls(br) => br.__rd_mut().SetDeadline(t),
            ConnSrc::Dyn(br) => br.__rd_mut().SetDeadline(t),
        };
        return out;
    }

    pub(crate) fn split_for_upgrade(self) -> (Option<(ConnSrc, crate::net::TCPConn)>, error) {
        let out = match self {
            ConnSrc::Tcp(mut br) => {
                let (w, e) = br.__rd_mut().__dup_handle();
                if !e.IsNil() {
                    (None, e)
                } else {
                    (Some((ConnSrc::Tcp(br), w)), errors::nil)
                }
            }
            ConnSrc::Tls(_) | ConnSrc::Dyn(_) => (
                None,
                errors::New(string(
                    "httputil: protocol switch over a TLS backend is not supported",
                )),
            ),
        };
        return out;
    }
}

// go: none — goish-only: transferWriter::writeBody wants `&mut dyn
// io::Writer`; this adapts a borrowed ConnSrc (Go's persistConnWriter
// role, minus the nwrite accounting that arrives with the loops).
pub(crate) struct ConnSrcWriter<'a>(pub(crate) &'a mut ConnSrc);

impl crate::io::Writer for ConnSrcWriter<'_> {
    fn Write(&mut self, p: slice<byte>) -> (int, error) {
        return self.0.write(p);
    }
}

/// Wire framing of a body-in-progress. Mirrors Go's transfer.go body
/// readers: `body` over a LimitedReader (Content-Length), over a
/// chunkedReader (TE: chunked), or straight to EOF (Connection:
/// close). `Eager` is a fully-materialized body (ReadResponse,
/// DumpResponse replacement, `Body::from`).
enum FramedBody {
    Eager {
        data: slice<byte>,
        off: int,
    },
    Cl {
        src: ConnSrc,
        remaining: int,
    },
    Chunked {
        cr: super::internal::chunked::ChunkedReader<ConnSrc>,
    },
    UntilEof {
        src: ConnSrc,
    },
    /// An arbitrary `io.ReadCloser` standing in for the body — Go's
    /// `Response.Body` is that interface, so anything can fill it. The
    /// other variants are conn-backed; this one exists for bodies with
    /// no connection behind them, such as `io.Pipe`'s read half in
    /// filetransport.go.
    Piped {
        r: alloc::boxed::Box<dyn crate::io::ReadCloser + Send + Sync>,
    },
    /// A 101 Switching Protocols response: the connection itself IS
    /// the body (Go: newReadWriteCloserBody, transport.go:2548).
    /// Reads drain any bytes the peer sent past the head (still in
    /// the bufio buffer), then the conn; the proxy extracts the whole
    /// carrier with `__take_upgraded` to pump both directions.
    Upgraded {
        src: ConnSrc,
    },
    Closed,
}

struct BodyState {
    framing: FramedBody,
    /// Go's bodyEOFSignal `fn`/`earlyCloseFn` pair (transport.go:
    /// 2978), goish-shaped: on Close/Drop of a CLEANLY-FINISHED
    /// conn-backed body the ConnSrc is handed back (Some) for pool
    /// reuse instead of closed; an early Close with unread framing
    /// closes the conn and signals None — a loop-mode reader must
    /// learn the conn died or it waits forever (Go's waitForBodyRead
    /// false arm).
    reuse_fn: Option<alloc::boxed::Box<dyn FnOnce(Option<ConnSrc>) + Send>>,
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
        FramedBody::Upgraded { src } => src.Read(p),
        FramedBody::Piped { r } => r.Read(p),
        FramedBody::Closed => (0, errors::New(string("http: read on closed response body"))),
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

// go: waived condfn — bodyEOFSignal's fire-once guard (fn nil-check
// + clear); goish integrates the signal into BodyState, where
// `reuse_fn` is an FnOnce TAKEN by close_locked below — the once-ness
// is the type system's, with nothing left to guard.
fn close_locked(st: &mut BodyState) -> error {
    // Watcher first — it holds a raw PollDesc pointer into the conn.
    if let Some(w) = st.watch.take() {
        stop_cancel_watch(Some(w));
    }
    // Go (bodyEOFSignal, transport.go:2978): a Content-Length body
    // read to its exact boundary leaves the conn synchronized — hand
    // it back to the pool instead of closing. Anything short of that
    // (unread remainder, chunked (phase A), streaming errors) closes
    // as before: reuse of a desynced conn is a response-smuggling
    // hazard, never an optimization.
    if let Some(bank) = st.reuse_fn.take() {
        let clean = matches!(&st.framing, FramedBody::Cl { remaining, .. } if *remaining <= 0);
        if clean {
            if let FramedBody::Cl { src, .. } =
                core::mem::replace(&mut st.framing, FramedBody::Closed)
            {
                bank(Some(src));
                if let Some(c) = st.cancel.take() {
                    c();
                }
                return errors::nil;
            }
        }
        // Dirty close: the conn is unusable — close it below and tell
        // the bank so (Go's earlyCloseFn / waitForBodyRead false).
        st.reuse_fn = Some(bank);
    }
    // An in-memory (Eager) body is Go's NopCloser shape — NewRequest
    // wraps *bytes.Reader/*strings.Reader in io.NopCloser, so Close is
    // a NO-OP and the bytes stay readable. transferWriter::writeBody
    // "always closes t.BodyCloser"; without this, that close killed
    // 307/308 redirect replay of an in-memory request body.
    if matches!(st.framing, FramedBody::Eager { .. }) {
        if let Some(c) = st.cancel.take() {
            c();
        }
        return errors::nil;
    }
    let err = match &mut st.framing {
        FramedBody::Cl { src, .. }
        | FramedBody::UntilEof { src }
        | FramedBody::Upgraded { src } => src.close_conn(),
        FramedBody::Chunked { cr } => cr.__bufio_mut().__rd_mut().close_conn(),
        FramedBody::Piped { r } => r.Close(),
        _ => errors::nil,
    };
    st.framing = FramedBody::Closed;
    if let Some(bank) = st.reuse_fn.take() {
        bank(None);
    }
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
                reuse_fn: None,
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

    /// Body backed by an arbitrary `io.ReadCloser`. Go's
    /// `Response.Body` IS that interface; goish's `Body` is a closed
    /// enum over the conn-backed framings, so this is the escape hatch
    /// for a body with no connection — `io.Pipe` in filetransport.go,
    /// and anything a future RoundTripper wants to hand back.
    pub fn from_reader(r: alloc::boxed::Box<dyn crate::io::ReadCloser + Send + Sync>) -> Body {
        return Body::from_parts(FramedBody::Piped { r }, None, None);
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

    // go: none — goish-only: Go's readTrackingBody.didRead, answered
    // by the Body's own cursor: an Eager body reports whether any
    // byte was taken; conn-backed and Closed framings count as read
    // (conservative, like a wrapper that saw a Read call).
    pub(crate) fn __was_read(&self) -> bool {
        let g = self.inner.Lock();
        let out = match &g.framing {
            FramedBody::Eager { off, .. } => *off > 0,
            _ => true,
        };
        return out;
    }

    // go: none — goish-only: install the bodyEOFSignal bank-back (see
    // BodyState.reuse_fn).
    pub(crate) fn __set_reuse(&self, f: alloc::boxed::Box<dyn FnOnce(Option<ConnSrc>) + Send>) {
        self.inner.Lock().reuse_fn = Some(f);
        return;
    }

    /// Crate-internal: Close through a shared handle (`&self`) — the
    /// redirect loop discards hop responses without a `mut` binding.
    pub(crate) fn __close_shared(&self) -> error {
        let mut g = self.inner.Lock();
        close_locked(&mut g)
    }

    // go: none — goish-only: non-consuming view of a fully-buffered
    // (Eager) body's unread remainder. None for a streaming body.
    // The cheap path for callers that Go writes as slice access on an
    // in-memory body (DumpRequest, redirect replay, serialization of
    // a NewRequest-built request).
    pub(crate) fn __bytes_eager(&self) -> Option<slice<byte>> {
        let g = self.inner.Lock();
        let out = match &g.framing {
            FramedBody::Eager { data, off } => Some(data.slice(*off, data.Len())),
            _ => None,
        };
        return out;
    }

    // go: none — goish-only: unread length of an Eager body, None if
    // streaming. `outgoingLength`'s "Body == nil" test maps here.
    pub(crate) fn __eager_len(&self) -> Option<int> {
        let g = self.inner.Lock();
        let out = match &g.framing {
            FramedBody::Eager { data, off } => Some(data.Len() - *off),
            _ => None,
        };
        return out;
    }

    // go: none — goish-only: the body's remaining bytes as a slice.
    // Eager bodies hand back a non-consuming view; a streaming body is
    // drained (and left re-readable as the Eager remainder, the
    // `__drain_remainder` shape). Callers that Go writes as
    // `io.ReadAll(r.Body)` over a body they must not lose use this.
    pub(crate) fn __materialize(&self) -> (slice<byte>, error) {
        if let Some(b) = self.__bytes_eager() {
            return (b, errors::nil);
        }
        return self.__drain_remainder();
    }
}

// go: none — goish-only body of transport.rs's newReadWriteCloserBody
// (the anchor lives there, with transport.go's other decls): a 101
// response's connection becomes the body. Go pairs (bufio remainder,
// conn); goish's `ConnSrc` is already that pair.
pub(crate) fn __new_upgraded_body(src: ConnSrc) -> Body {
    return Body::from_parts(FramedBody::Upgraded { src }, None, None);
}

impl Body {
    // go: none — goish-only: Go's caller type-asserts
    // `res.Body.(io.ReadWriteCloser)`; goish's Body is a closed enum,
    // so the comma-ok is an extraction. Leaves the body Closed.
    pub(crate) fn __take_upgraded(&self) -> Option<ConnSrc> {
        let mut g = self.inner.Lock();
        if !matches!(g.framing, FramedBody::Upgraded { .. }) {
            return None;
        }
        match core::mem::replace(&mut g.framing, FramedBody::Closed) {
            FramedBody::Upgraded { src } => {
                return Some(src);
            }
            _ => unreachable!(),
        }
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

impl Response {}

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

    // Go (ReadResponse → readTransfer, transfer.go:491): every
    // framing decision — Connection-close via shouldClose, STRICT
    // Transfer-Encoding parse (a second TE or a non-chunked coding is
    // an unsupportedTEError, not silently ignored), fixLength's
    // smuggling hardening, HEAD's Content-Length, trailer capture
    // into resp.Trailer, and RFC 7230 §3.3: a response with no CL,
    // no TE and an allowed-body status is UNBOUNDED (read to EOF,
    // Close=true) — the hand-rolled block this replaces treated that
    // as an empty body and silently dropped such responses.
    let (kind, terr) =
        super::transfer::readTransfer(super::transfer::TransferMsgMut::Resp(&mut resp));
    if !terr.IsNil() {
        return (resp, BodyKind::Empty, terr);
    }
    return (resp, kind, errors::nil);
}

// go: none — goish-only: readLoop's body attachment — like
// attach_stream_body's bank arm, but the hand-back ALWAYS fires
// (Some on a clean Content-Length boundary, None when the body
// closed the conn), which is what lets readLoop block on it safely.
// Framings with no clean end in the sequential model (chunked,
// UntilEof, 101) attach owning the conn and answer None on close.
pub(crate) fn __attach_loop_body(
    resp: &mut Response,
    kind: BodyKind,
    src: ConnSrc,
    done: alloc::boxed::Box<dyn FnOnce(Option<ConnSrc>) + Send>,
) {
    match kind {
        BodyKind::Empty => {
            resp.Body = Body::default();
            done(None);
        }
        BodyKind::Cl(n) => {
            resp.Body = Body::from_parts(FramedBody::Cl { src, remaining: n }, None, None);
            resp.Body.__set_reuse(done);
        }
        BodyKind::Chunked => {
            resp.Body = Body::from_parts(
                FramedBody::Chunked {
                    cr: super::internal::chunked::NewChunkedReader(src),
                },
                None,
                None,
            );
            resp.Body.__set_reuse(done);
        }
        BodyKind::UntilEof => {
            resp.Body = Body::from_parts(FramedBody::UntilEof { src }, None, None);
            resp.Body.__set_reuse(done);
        }
    }
    return;
}

// go: none — goish-only: the readLoop half of the 100-continue dance
// (Go reads the interim head inside readResponse's 1xx loop): consume
// the interim status line and its terminating blank line, leaving the
// real response buffered.
fn __consume_interim<R: Reader>(br: &mut bufio::Reader<R>) -> error {
    loop {
        let line = match read_crlf_line(br) {
            Ok(l) => l,
            Err(e) => return e,
        };
        if line.Len() == 0 {
            return errors::nil;
        }
    }
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
pub(crate) fn read_full_into<R: Reader>(
    r: &mut bufio::Reader<R>,
    buf: &mut slice<byte>,
) -> (int, error) {
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

    // go: none — goish rendering of Go's `switch t := rt.(type) { case
    // *Transport: … }` in knownRoundTripperImpl. Rust cannot
    // type-switch a `dyn Trait` back to a concrete type, and a
    // goish::interface method must return an OWNED type, so the whole
    // probe lives on the trait: Transport overrides it, everything
    // else inherits false.
    fn __known_round_tripper(&self, req: &Request) -> bool {
        let _ = req;
        return false;
    }

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
pub type ProxyResolver =
    alloc::sync::Arc<dyn Fn(&Request) -> (super::url::URL, error) + Send + Sync>;
/// Type alias for the dial-context closure. Same opaque shape as
/// `ProxyResolver` — the real signature would carry `(Context, network,
/// addr) -> (Conn, error)` but those are inert in v1.
pub type DialContextFn = alloc::sync::Arc<dyn Fn() + Send + Sync>;

/// `Transport.DialTLSContext`'s shape (transport.go:120): dial AND
/// handshake, returning a ready encrypted conn. Go's is
/// `func(ctx, network, addr) (net.Conn, error)`.
pub type DialTLSContextFn = alloc::sync::Arc<
    dyn Fn(
            Option<Arc<dyn crate::context::Context>>,
            string,
            string,
        ) -> (Option<alloc::boxed::Box<dyn crate::net::Conn>>, error)
        + Send
        + Sync,
>;

/// `http.Transport` (transport.go:163). v1: dial-per-request, no idle
/// pool. Field surface mirrors Go's struct so user ports can configure
/// or read these slots; only `Timeout` actually drives behaviour
/// today, the rest are inert metadata until the connection-pool layer
/// lands.
pub struct Transport {
    /// The idle-connection pool: Go's `idleMu` + `idleConn` +
    /// `idleLRU` + `closeIdle` (transport.go:270-276), which its own
    /// comments mark as guarded together. Keyed by
    /// `connectMethodKey.String()` because goish has no struct-keyed
    /// map. STAGED — nothing puts a conn in it yet.
    pub(crate) __idle: Arc<crate::sync::Mutex<super::transport::idlePool>>,
    /// Go's `connsPerHostMu` + `connsPerHost` + `connsPerHostWait`
    /// (transport.go:278-281) — the MaxConnsPerHost limiter, a
    /// separate lock from the idle pool in Go and kept separate here.
    pub(crate) __conns_per_host: crate::sync::Mutex<super::transport::connsPerHost>,
    /// Go's `MaxResponseHeaderBytes` (transport.go:288) — cap on the
    /// response head. Zero means Go's 10 MiB default; NEGATIVE passes
    /// through, like MaxIdleConnsPerHost.
    pub MaxResponseHeaderBytes: i64,
    /// Go's `WriteBufferSize` (transport.go:298) — bytes of write
    /// buffer per connection. Zero means 4 KiB.
    pub WriteBufferSize: int,
    /// Go's `ReadBufferSize` (transport.go:304). Zero means 4 KiB.
    pub ReadBufferSize: int,
    /// Go's `altProto atomic.Value` holding `map[string]RoundTripper`
    /// (transport.go:307), populated by `RegisterProtocol`. goish uses
    /// a Mutex-guarded map — the atomic.Value dance exists to make the
    /// read path lock-free, which goish's v1 does not need.
    pub(crate) __alt_proto:
        crate::sync::Mutex<crate::gomap::map<string, Option<alloc::sync::Arc<dyn RoundTripper>>>>,
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
    /// `Transport.DialTLSContext` (transport.go:117) — Go: "specifies
    /// an optional dial function for creating TLS connections for
    /// non-proxied HTTPS requests" — the conn arrives already
    /// handshaken; addTLS is skipped.
    pub DialTLSContext: Option<DialTLSContextFn>,
    /// `Transport.DialTLS` (transport.go:126) — the ctx-less
    /// deprecated form; DialTLSContext wins when both are set.
    pub DialTLS: Option<
        alloc::sync::Arc<
            dyn Fn(string, string) -> (Option<alloc::boxed::Box<dyn crate::net::Conn>>, error)
                + Send
                + Sync,
        >,
    >,
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
            __idle: Arc::new(crate::sync::Mutex::new(super::transport::idlePool::new())),
            __conns_per_host: crate::sync::Mutex::new(super::transport::connsPerHost::new()),
            MaxResponseHeaderBytes: 0,
            WriteBufferSize: 0,
            ReadBufferSize: 0,
            __alt_proto: crate::sync::Mutex::new(crate::gomap::map::new()),
            Timeout: time::Duration(0),
            DisableCompression: false,
            Proxy: None,
            IdleConnTimeout: time::Duration(0),
            DialContext: None,
            DialTLSContext: None,
            DialTLS: None,
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
    // Mirrors Go's `return envProxyFunc()(req.URL)` — transport.go
    // lines 499-501. The
    // environment is read once and cached across requests; goish's
    // "no proxy" is the empty URL (the resolver-shape's nil).
    alloc::sync::Arc::new(|r: &Request| -> (super::url::URL, error) {
        let f = super::transport::envProxyFunc();
        let (u, err) = f(&r.URL);
        let out = match u {
            Some(u) => u,
            None => super::url::URL::default(),
        };
        return (out, err);
    })
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
    fn __known_round_tripper(&self, req: &Request) -> bool {
        // Go recurses through any alternate RoundTripper registered
        // for this request's scheme: a Transport is only "known" if
        // its alternate is too.
        match self.alternateRoundTripper(req) {
            Some(alt) => {
                return alt.__known_round_tripper(req);
            }
            None => {
                return true;
            }
        }
    }

    fn RoundTrip(&self, req: &Request) -> (Response, error) {
        // Resolve scheme.
        let scheme = req.URL.Scheme.clone();
        let is_https = scheme.as_bytes() == b"https";
        let is_http = scheme.Len() == 0 || scheme.as_bytes() == b"http";
        if !is_http && !is_https {
            return (
                Response::default(),
                errors::New(string(
                    "http: only scheme=http and scheme=https are supported",
                )),
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

        // ── unified path (Go roundTrip → getConn) ──
        // One loop for both schemes: getConn tries the idle pool,
        // else dials (dialConn's TLS arm runs addTLS, so HTTPS conns
        // POOL exactly like plain ones). The deadline and the
        // ctx-cancel watch arm on the raw socket's PollDesc captured
        // at dial time — before any TLS wrap — so Timeout and
        // cancellation cover the handshake and every request on the
        // conn after it.
        {
            let dial_addr = ensure_default_port(&host, if is_https { 443 } else { 80 });
            let cm = super::transport::connectMethod {
                proxyURL: None,
                targetScheme: if is_https {
                    string("https")
                } else {
                    string("http")
                },
                targetAddr: dial_addr.clone(),
                onlyH1: false,
            };

            // Go (roundTrip, transport.go:598): req = setupRewindBody(req)
            // — the retry path below must be able to replay a consumed
            // body via GetBody (rewindBody), never resend it empty.
            let mut rt_req = super::transport::setupRewindBody(req);
            // Go (roundTrip): treq := &transportRequest{Request: req, …}
            // — the error cell mapRoundTripError consults, rebuilt per
            // rewind like Go rebuilds it per retry loop turn.
            let mut treq = super::transport::transportRequest::__new(rt_req.clone());
            // Retry loop — Go's transport.roundTrip: a request that
            // failed on a REUSED conn (the server may have closed it
            // while idle) is retried once on a fresh dial
            // (shouldRetryRequest; pc.isReused is the gate).
            loop {
                // Go (roundTrip): pconn, err := t.getConn(treq, cm) —
                // idle pool first, else dial through the
                // wantConn/connsPerHost machinery.
                let (pc, gerr) = self.getConn(&rt_req, &cm);
                if !gerr.IsNil() {
                    return (Response::default(), ctx_err_or(&ctx, gerr));
                }
                let pc = match pc {
                    Some(pc) => pc,
                    None => {
                        return (
                            Response::default(),
                            errors::New(string("http: getConn returned no connection")),
                        )
                    }
                };
                let pc_reused = pc.isReused();
                let mut src = match pc.__take_src() {
                    Some(s) => s,
                    None => {
                        return (
                            Response::default(),
                            errors::New(string("http: persistConn has no connection")),
                        )
                    }
                };
                // Arm the per-request deadline + ctx watch (fresh and
                // pooled conns alike; the bank cleared the deadline).
                // The watch target is the raw socket's PollDesc the
                // dial captured — valid under a TLS wrap too.
                let watch = {
                    let dl = self.effective_deadline(&ctx);
                    if !dl.IsZero() {
                        let _ = src.__set_deadline(dl);
                    } else {
                        let _ = src.__set_deadline(time::Time::default());
                    }
                    let (wfd, wpd) = pc.__watch_parts();
                    arm_cancel_watch(&ctx, (wfd, wpd as *const crate::runtime::netpoll::PollDesc))
                };

                // Write the request: head, then stream the body (see
                // the TLS arm above).
                let (head, mut tw, serr) = serialize_request_head(&rt_req, &host, false);
                if !serr.IsNil() {
                    stop_cancel_watch(watch);
                    let _ = src.close_conn();
                    return (Response::default(), serr);
                }
                let (_, head_werr) = src.write(head);
                // Go (writeLoop → Request.write → waitForContinue):
                // an "Expect: 100-continue" request holds its body
                // until the server answers. The sequential feeder
                // plays readLoop's half: peek for an interim response
                // under ExpectContinueTimeout — a 100 (consumed) means
                // send, a FINAL head (left buffered for the normal
                // read below) means skip, a quiet wire means send
                // after the timeout, all fed through the verbatim
                // waitForContinue closure.
                let mut skip_body = false;
                if head_werr.IsNil() && tw.Body.is_some() && rt_req.expectsContinue() {
                    let continue_ch: crate::gochan::chan<bool> = crate::make!(chan bool, 1);
                    let ect = self.ExpectContinueTimeout;
                    if ect.0 > 0 {
                        let _ = src.__set_deadline(time::Now().Add(ect));
                        let sniff = match &mut src {
                            ConnSrc::Tcp(br) => br.Peek(12).0,
                            ConnSrc::Tls(br) => br.Peek(12).0,
                            ConnSrc::Dyn(br) => br.Peek(12).0,
                        };
                        if sniff.Len() >= 12 {
                            let raw: &[u8] = &sniff;
                            if &raw[9..12] == b"100" {
                                // Interim 100: consume its lines
                                // through the blank terminator.
                                let consumed = match &mut src {
                                    ConnSrc::Tcp(br) => __consume_interim(br),
                                    ConnSrc::Tls(br) => __consume_interim(br),
                                    ConnSrc::Dyn(br) => __consume_interim(br),
                                };
                                let _ = consumed;
                                let _ = continue_ch.Send(true);
                            } else {
                                // A final response before any body
                                // byte: Go's readLoop closes the
                                // channel — skip the body.
                                let _ = continue_ch.Send(false);
                            }
                        } else {
                            // Quiet wire (deadline hit): Go's timer
                            // outcome — send the body.
                            let _ = continue_ch.Send(true);
                        }
                        // Restore the request deadline.
                        let dl = self.effective_deadline(&ctx);
                        let _ = src.__set_deadline(if dl.IsZero() {
                            time::Time::default()
                        } else {
                            dl
                        });
                    } else {
                        // Go: a zero ExpectContinueTimeout fires the
                        // closure's timer immediately — body sent.
                        let _ = continue_ch.Send(true);
                    }
                    if let Some(wait) =
                        pc.waitForContinue(self.ExpectContinueTimeout, Some(continue_ch))
                    {
                        if !wait() {
                            skip_body = true;
                        }
                    }
                }
                let (werr, head_failed) = if !head_werr.IsNil() {
                    (head_werr, true)
                } else if skip_body {
                    // The body stays unsent; its closer still runs
                    // (Go's Request.write defer).
                    tw.__abort_body();
                    (errors::nil, false)
                } else {
                    let mut cw = ConnSrcWriter(&mut src);
                    let mut cw: &mut dyn crate::io::Writer = &mut cw;
                    (tw.writeBody(&mut cw), false)
                };
                if !werr.IsNil() {
                    stop_cancel_watch(watch);
                    let _ = src.close_conn();
                    // Go (writeLoop): a request whose FIRST write got
                    // nothing onto a reused conn maps to
                    // nothingWrittenError, which shouldRetryRequest
                    // always retries. An EPIPE/ECONNRESET mid-write on
                    // a REUSED conn is the same event seen later — Go's
                    // concurrent readLoop peek reports it as
                    // errServerClosedIdle before the writer notices;
                    // sequential goish maps the write error itself
                    // (text-matched: the net package has no typed
                    // errors, same substitution isCommonNetReadError
                    // makes).
                    let mapped = if pc_reused && head_failed {
                        super::transport::errNothingWritten.into()
                    } else if pc_reused
                        && ((werr.Error().as_ref() as &str).contains("broken pipe")
                            || (werr.Error().as_ref() as &str).contains("connection reset"))
                    {
                        super::transport::errServerClosedIdle.into()
                    } else {
                        werr.clone()
                    };
                    treq.setError(werr.clone());
                    if super::transport::shouldRetryRequest(&rt_req, mapped, pc_reused) {
                        // Go (roundTrip retry): req, err = rewindBody(req)
                        let (rw, rwerr) = super::transport::rewindBody(&rt_req);
                        if !rwerr.IsNil() {
                            return (Response::default(), rwerr);
                        }
                        rt_req = rw;
                        treq = super::transport::transportRequest::__new(rt_req.clone());
                        continue;
                    }
                    let mapped_out = pc.mapRoundTripError(&treq, head_failed, werr);
                    return (Response::default(), ctx_err_or(&ctx, mapped_out));
                }

                // Read the response head; the src moves onward into
                // resp.Body, which streams until the caller Closes it.
                let (mut resp, kind, rerr) = match &mut src {
                    ConnSrc::Tcp(br) => read_response_head(br, Some(rt_req.clone())),
                    ConnSrc::Tls(br) => read_response_head(br, Some(rt_req.clone())),
                    ConnSrc::Dyn(br) => read_response_head(br, Some(rt_req.clone())),
                };
                if !rerr.IsNil() {
                    stop_cancel_watch(watch);
                    // Go (readLoop): a failed peek where the response
                    // head should be goes through
                    // readLoopPeekFailLocked — an unsolicited 408 or a
                    // bare EOF on a reused conn maps to
                    // errServerClosedIdle (retried); anything else is
                    // wrapped and terminal. The classification lands
                    // in pc.closed, read back for the retry gate.
                    let buffered = match &mut src {
                        ConnSrc::Tcp(br) => {
                            let n = br.Buffered();
                            if n > 0 {
                                br.Peek(n).0
                            } else {
                                slice::<byte>::__from_vec(Vec::new())
                            }
                        }
                        ConnSrc::Tls(br) => {
                            let n = br.Buffered();
                            if n > 0 {
                                br.Peek(n).0
                            } else {
                                slice::<byte>::__from_vec(Vec::new())
                            }
                        }
                        ConnSrc::Dyn(br) => {
                            let n = br.Buffered();
                            if n > 0 {
                                br.Peek(n).0
                            } else {
                                slice::<byte>::__from_vec(Vec::new())
                            }
                        }
                    };
                    let _ = src.close_conn();
                    let mapped = if pc_reused {
                        pc.readLoopPeekFailLocked(rerr.clone(), &buffered);
                        pc.__closed_reason()
                    } else {
                        rerr.clone()
                    };
                    if super::transport::shouldRetryRequest(&rt_req, mapped.clone(), pc_reused) {
                        let (rw, rwerr) = super::transport::rewindBody(&rt_req);
                        if !rwerr.IsNil() {
                            return (resp, rwerr);
                        }
                        rt_req = rw;
                        treq = super::transport::transportRequest::__new(rt_req.clone());
                        continue;
                    }
                    let mapped_out = pc.mapRoundTripError(&treq, false, mapped);
                    return (resp, ctx_err_or(&ctx, mapped_out));
                }

                // Go's bodyEOFSignal bank-back: reusable when the
                // server didn't ask to close and the framing has a
                // clean end (Empty now, Content-Length at body Close).
                let bank: Option<alloc::boxed::Box<dyn FnOnce(Option<ConnSrc>) + Send>> = if !self
                    .DisableKeepAlives
                    && !resp.Close
                    && matches!(kind, BodyKind::Empty | BodyKind::Cl(_))
                {
                    let idle = self.__idle.clone();
                    let cfg = self.__bank_cfg();
                    let pc2 = pc.clone();
                    let idle_timeout = self.IdleConnTimeout;
                    Some(alloc::boxed::Box::new(move |s: Option<ConnSrc>| {
                        let mut s = match s {
                            Some(s) => s,
                            // Dirty close: the conn died with the
                            // body; nothing to bank.
                            None => return,
                        };
                        // Clear the per-request deadline before the
                        // conn waits idle.
                        let _ = s.__set_deadline(time::Time::default());
                        pc2.__put_src(s);
                        let e = super::transport::__try_put_idle(&idle, &cfg, &pc2);
                        if !e.IsNil() {
                            // Pool refused (full/closed): release.
                            pc2.close(e);
                            return;
                        }
                        // Go: pc.idleTimer = time.AfterFunc(
                        // t.IdleConnTimeout, pc.closeConnIfStillIdle)
                        // — armed per idle cycle, stopped when the
                        // conn is taken (__take_src).
                        if idle_timeout.0 > 0 {
                            let pc3 = pc2.clone();
                            let idle3 = idle.clone();
                            let t = crate::time::AfterFunc(idle_timeout, move || {
                                pc3.closeConnIfStillIdle(&idle3);
                            });
                            pc2.__arm_idle_timer(t);
                        }
                    }))
                } else {
                    None
                };
                attach_stream_body(&mut resp, kind, src, ctx, watch, bank);
                return (resp, errors::nil);
            }
        }
    }
}

/// Wire a parsed head + owned conn into a streaming `resp.Body`.
/// `bank` is the pool hand-back (Go's bodyEOFSignal fn): an
/// Empty-framed response's conn goes back immediately; a
/// Content-Length body carries it and banks on clean Close. Framings
/// that end only with the conn (UntilEof, 101) and chunked (phase A)
/// drop the bank and close as before.
fn attach_stream_body(
    resp: &mut Response,
    kind: BodyKind,
    mut src: ConnSrc,
    ctx: Option<Arc<dyn crate::context::Context>>,
    watch: Option<(crate::gochan::chan<()>, crate::gochan::chan<()>)>,
    bank: Option<alloc::boxed::Box<dyn FnOnce(Option<ConnSrc>) + Send>>,
) {
    // Go (transport.go:2306): a 101 Switching Protocols response's
    // body IS the connection — attach it un-framed and detach the
    // cancel watch (the switched protocol is caller-owned; the
    // client's per-request timeout has no say over its lifetime).
    if resp.StatusCode == super::status::StatusSwitchingProtocols {
        stop_cancel_watch(watch);
        resp.Body = super::transport::newReadWriteCloserBody(src);
        return;
    }
    match kind {
        BodyKind::Empty => {
            stop_cancel_watch(watch);
            match bank {
                Some(b) => b(Some(src)),
                None => {
                    let _ = src.close_conn();
                }
            }
            resp.Body = Body::default();
        }
        BodyKind::Cl(n) => {
            resp.Body = Body::from_parts(FramedBody::Cl { src, remaining: n }, ctx, watch);
            if let Some(b) = bank {
                resp.Body.__set_reuse(b);
            }
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
    fn effective_deadline(&self, ctx: &Option<Arc<dyn crate::context::Context>>) -> time::Time {
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
pub(crate) fn arm_cancel_watch(
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
pub(crate) fn stop_cancel_watch(watch: Option<(crate::gochan::chan<()>, crate::gochan::chan<()>)>) {
    if let Some((stop, exited)) = watch {
        stop.Close();
        let (_, _) = exited.Recv();
    }
}

/// Strip a `:port` suffix from `host` — the SNI name for a dialed
/// address (what `tls::Dial` derives internally).
pub(crate) fn host_without_port(host: &string) -> string {
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

    // Go: referer := lastReq.String(); if lastReq.User != nil {
    //     auth := lastReq.User.String() + "@"
    //     referer = strings.Replace(referer, auth, "", 1) }
    let referer = lastReq.String();
    // Go: `if lastReq.User != nil` — a nil-able *Userinfo. goish's
    // net/url models the nil with the same `== nil` comparison the rest
    // of the tree uses, where net/http's own copy used an Option.
    if lastReq.User != crate::nil {
        let auth = lastReq.User.String() + "@";
        return crate::strings::Replace(referer, auth, string(""), 1);
    }
    return referer;
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
    if u.User != crate::nil {
        let ui = &u.User;
        let (_, passSet) = ui.Password();
        if passSet {
            return crate::strings::Replace(
                u.String(),
                ui.String() + "@",
                ui.Username() + ":***@",
                1,
            );
        }
    }
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
    ireq: &Request,
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
            // Go: "We had a request body, and 307/308 require
            // re-sending it, but GetBody is not defined. So just use
            // the last response." The send consumed the body; without
            // a replay hook the redirect cannot be followed.
            if ireq.GetBody.is_none() && ireq.outgoingLength() != 0 {
                return (reqMethod, false, true);
            }
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

// go: sdk 1.25.5 net/http/client.go:422-425 basicAuth
/// Go: "See 2 (end of page 4)
/// https://www.ietf.org/rfc/rfc2617.txt \"To receive authorization,
/// the client sends the userid and password, separated by a single
/// colon (\":\") character, within a base64 encoded string in the
/// credentials.\""
pub fn basicAuth(username: string, password: string) -> string {
    let mut creds = crate::strings::Builder::new();
    let _ = creds.WriteString(username);
    let _ = creds.WriteByte(b':');
    let _ = creds.WriteString(password);
    return crate::encoding::base64::StdEncoding
        .EncodeToString(crate::convert::bytes(creds.String()).as_ref());
}

// go: sdk 1.25.5 net/http/client.go:320-341 knownRoundTripperImpl
/// Go: "reports whether rt is a RoundTripper that's maintained by the
/// Go team and known to implement the latest optional semantics
/// (notably contexts)."
///
/// Go checks for *Transport (recursing through any alternate
/// RoundTripper registered for the request's scheme), then for the two
/// HTTP/2 transports, then falls back to a reflect type-name
/// comparison against "*http2.Transport" — its own comment calls that
/// last one "a good enough heuristic".
///
/// goish has neither HTTP/2 transport, and `reflect` here is a value
/// tree rather than Go's reflect, so only the *Transport arm ports.
/// The recursion through alternateRoundTripper is the part that
/// matters and is kept: a Transport with a registered protocol is
/// only "known" if the alternate is too.
pub fn knownRoundTripperImpl(rt: &Arc<dyn RoundTripper>, req: &Request) -> bool {
    return rt.__known_round_tripper(req);
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

// go: sdk 1.25.5 net/http/client.go:351-421 setRequestCancel
/// Go: "sets req.Cancel and adds a deadline context to req if
/// deadline is non-zero."
///
/// goish carries only the knownRoundTripperImpl arm — every goish
/// transport is "known", and the deprecated `Request.Cancel` channel
/// (whose legacy doCancel machinery is the rest of Go's function) has
/// no goish field. Go's WithDeadline is spelled WithTimeout(until):
/// context.WithDeadline is not ported yet.
pub(crate) fn setRequestCancel(
    req: &mut Request,
    rt: &Arc<dyn RoundTripper>,
    deadline: crate::time::Time,
) -> (
    crate::context::CancelFunc,
    Arc<dyn Fn() -> bool + Send + Sync>,
) {
    let af: Arc<dyn Fn() -> bool + Send + Sync> = Arc::new(|| alwaysFalse());
    if deadline.IsZero() {
        // Go: return nop, alwaysFalse
        return (alloc::boxed::Box::new(super::transport::nop), af);
    }
    let _ = knownRoundTripperImpl(rt, req);
    let oldCtx = req.Context();
    // Go: "If they already had a Request.Context that's expiring
    // sooner, do nothing."
    if !timeBeforeContextDeadline(deadline.clone(), &oldCtx) {
        return (alloc::boxed::Box::new(super::transport::nop), af);
    }
    let until = deadline.clone().Sub(crate::time::Now());
    let (ctx, cancelCtx) = crate::context::WithTimeout(oldCtx, until);
    req.ctx = Some(ctx);
    let dl = deadline;
    return (
        cancelCtx,
        Arc::new(move || {
            return crate::time::Now().After(dl.clone());
        }),
    );
}

// go: sdk 1.25.5 net/http/client.go:209-303 send
/// Go: "send issues an HTTP request. Caller should close resp.Body
/// when done reading from it." The request-shape guards live here —
/// a set RequestURI is refused, and URL userinfo becomes an
/// `Authorization: Basic` header unless the caller set one — plus
/// the deadline arming (setRequestCancel) whose release rides in the
/// response Body (Go's cancelTimerBody; goish's Body carries the
/// CancelFunc and fires it on Close/Drop).
///
/// The `(*Client).send` jar halves stay inline in Do, exactly where
/// Go's wrapper has them. Go's nil-URL / nil-Header / nil-Body arms
/// are values in goish (an empty URL is its nil); the RoundTripper
/// non-nil guard cannot arise (Client.Transport is a value).
pub(crate) fn send(
    ireq: &Request,
    rt: &Arc<dyn RoundTripper>,
    deadline: crate::time::Time,
) -> (Response, Arc<dyn Fn() -> bool + Send + Sync>, error) {
    let af: Arc<dyn Fn() -> bool + Send + Sync> = Arc::new(|| alwaysFalse());
    // Go: req is a lazy shallow fork of ireq; goish Requests clone
    // cheaply (Arc-backed innards), so the fork is unconditional.
    let mut req = ireq.clone();

    if req.URL.Scheme.Len() == 0 && req.URL.Host.Len() == 0 && req.URL.Path.Len() == 0 {
        let _ = req.Body.__close_shared();
        return (
            Response::default(),
            af,
            errors::New(string("http: nil Request.URL")),
        );
    }

    if req.RequestURI.Len() != 0 {
        let _ = req.Body.__close_shared();
        return (
            Response::default(),
            af,
            errors::New(string(
                "http: Request.RequestURI can't be set in client requests",
            )),
        );
    }

    // Go: if u := req.URL.User; u != nil && req.Header.Get(
    // "Authorization") == "" { … "Basic " + basicAuth(...) }
    if req.URL.User != crate::nil {
        let u = req.URL.User.clone();
        if req.Header.Get(string("Authorization")).Len() == 0 {
            let username = u.Username();
            let (password, _) = u.Password();
            req.Header = super::clone::cloneOrMakeHeader(&ireq.Header);
            req.Header.Set(
                string("Authorization"),
                string("Basic ") + basicAuth(username, password),
            );
        }
    }

    let (stop_timer, did_timeout) = setRequestCancel(&mut req, rt, deadline.clone());

    let (resp, err) = rt.RoundTrip(&req);
    if !err.IsNil() {
        stop_timer();
        return (resp, did_timeout, err);
    }
    // Go's non-nil-Body guarantee holds by construction: goish's
    // Response.Body is a value.
    if !deadline.IsZero() {
        // Go: resp.Body = &cancelTimerBody{stop, rc, reqDidTimeout}.
        resp.Body.__set_cancel(stop_timer);
    }
    return (resp, did_timeout, errors::nil);
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
    // go: sdk 1.25.5 net/http/client.go:192-197 Client.deadline
    /// Go: the absolute deadline for the whole request, or the zero
    /// Time when `Timeout` is unset.
    pub fn deadline(&self) -> time::Time {
        if self.Timeout > time::Duration(0) {
            return time::Now().Add(self.Timeout);
        }
        return time::Time::default();
    }

    // go: sdk 1.25.5 net/http/client.go:199-204 Client.transport
    /// Go: `c.Transport` when set, else `DefaultTransport`. goish's
    /// field is non-optional and already defaults to a Transport, so
    /// this is the accessor rather than a fallback.
    pub fn transport(&self) -> Arc<dyn RoundTripper> {
        return self.Transport.clone();
    }

    // go: sdk 1.25.5 net/http/client.go:497-503 Client.checkRedirect
    /// Go: "calls either the user's configured CheckRedirect function,
    /// or the default."
    pub fn checkRedirect(&self, req: &Request, via: &[Request]) -> error {
        match self.CheckRedirect.as_ref() {
            Some(f) => {
                return f(req, via);
            }
            None => {
                return defaultCheckRedirect(req, via);
            }
        }
    }

    pub fn Do(&self, req: &Request) -> (Response, error) {
        let mut current = req.clone();
        // Go: deadline := c.deadline() — one wall-clock bound for the
        // WHOLE redirect chain; `send` arms it per hop and hands the
        // release to the response Body (Go's cancelTimerBody shape).
        let deadline = self.deadline();
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
        // Go replays a 307/308 body from the INITIAL request's GetBody
        // (client.go:669-676) — never from the consumed hop body.
        let ireqGetBody = current.GetBody.clone();
        let ireqContentLength = current.ContentLength;
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
            // Go: resp, didTimeout, err = c.send(req, deadline) —
            // the jar halves of (*Client).send are the blocks above
            // and below this call.
            let (resp, _did_timeout, err) = send(&current, &self.Transport, deadline.clone());
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
                        // No Location → return as-is (the deadline
                        // release already rides in the Body).
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
                        TransferEncoding: slice::<string>::__from_vec(Vec::new()),
                        Body: Body::default(),
                        GetBody: None,
                        RemoteAddr: string::new(),
                        pat: None,
                        matches: crate::goslice::slice::<string>::__from_vec(alloc::vec::Vec::new()),
                        otherValues: crate::gomap::map::<string, string>::new(),
                        form_state: alloc::sync::Arc::new(crate::sync::Mutex::new(
                            super::request::FormCell::default(),
                        )),
                        // Redirect hops inherit the original request's
                        // context (Go client.go:665: ireq.Context()).
                        ctx: current.ctx.clone(),
                    };
                    // Go: `includeBody` from redirectBehavior — true
                    // for 307/308 only. Go: if includeBody &&
                    // ireq.GetBody != nil { next.Body, err =
                    // ireq.GetBody(); next.ContentLength =
                    // ireq.ContentLength } — a FRESH body; the hop
                    // that was just sent consumed the old one.
                    if includeBody {
                        if let Some(gb) = &ireqGetBody {
                            let (b, gerr) = gb();
                            if !gerr.IsNil() {
                                return (resp, gerr);
                            }
                            next.Body = b;
                            next.ContentLength = ireqContentLength;
                            next.GetBody = ireqGetBody.clone();
                        }
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
                    // in the Body (set by `send`), invoked on
                    // Close/Drop.
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
    pub fn PostForm<U: Into<string>>(
        &self,
        url: U,
        vals: &[(string, string)],
    ) -> (Response, error) {
        let body = encode_form(vals);
        self.Post(url, string("application/x-www-form-urlencoded"), body)
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

/// A `Body` handed straight back as another request's body — the
/// ReverseProxy shape (`outreq.Body = r.Body`). An in-memory body is
/// viewed without consuming; a streaming one is drained (phase 2 of
/// the transfer.go port threads it through unread).
impl __RequestBody for Body {
    #[inline]
    fn __to_body(self) -> slice<byte> {
        return self.__materialize().0;
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
    // Go uses urlpkg.Parse here, NOT ParseRequestURI. The latter is
    // for server-side request-line URIs (RFC 9112 origin-form) and
    // differs on two forms NewRequest must handle: a scheme-relative
    // "//host/path" (Parse splits the authority; ParseRequestURI
    // treats it all as a path) and userinfo (Parse puts "user:pw" in
    // URL.User, leaving Host clean; ParseRequestURI leaves it in
    // Host, which then leaked the credentials into the Host header).
    let (u, perr) = super::url::Parse(url);
    if perr != errors::nil {
        return (default_request(), perr);
    }
    let body_len = body.Len();
    let host = u.Host.clone();
    let gb_data = body.clone();
    let body = Body::from_bytes(body);
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
        TransferEncoding: slice::<string>::__from_vec(Vec::new()),
        Body: body,
        // Go populates GetBody for the in-memory body types
        // (request.go:924-943) so 307/308 redirects can replay the
        // body after the send consumed it. goish's eager body is
        // exactly that case: a fresh Body over the same bytes.
        GetBody: Some(alloc::sync::Arc::new(move || {
            return (Body::from_bytes(gb_data.clone()), errors::nil);
        })),
        RemoteAddr: string::new(),
        pat: None,
        matches: crate::goslice::slice::<string>::__from_vec(alloc::vec::Vec::new()),
        otherValues: crate::gomap::map::<string, string>::new(),
        form_state: alloc::sync::Arc::new(crate::sync::Mutex::new(
            super::request::FormCell::default(),
        )),
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
        URL: URL::default(),
        Proto: string::new(),
        ProtoMajor: 0,
        ProtoMinor: 0,
        Header: Header::new(),
        Host: string::new(),
        ContentLength: 0,
        TransferEncoding: slice::<string>::__from_vec(Vec::new()),
        Body: Body::default(),
        GetBody: None,
        RemoteAddr: string::new(),
        pat: None,
        matches: crate::goslice::slice::<string>::__from_vec(alloc::vec::Vec::new()),
        otherValues: crate::gomap::map::<string, string>::new(),
        form_state: alloc::sync::Arc::new(crate::sync::Mutex::new(
            super::request::FormCell::default(),
        )),
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
/// ready to write to the underlying conn — head plus fully-encoded
/// body (chunked framing included when the transferWriter chose it).
///
/// Loose port of `(*Request).write` (request.go:603). The Client's
/// send path avoids this buffered form: it writes the head, then
/// STREAMS the body with `transferWriter::writeBody` directly onto
/// the conn.
pub(crate) fn serialize_request(req: &Request, host: &string) -> (slice<byte>, error) {
    return serialize_request_proxy(req, host, false);
}

/// Same as `serialize_request` but emits an absolute Request-URI in
/// the request line when `using_proxy` is true. Mirrors Go's
/// `(*Request).write` (request.go:582) call shape.
pub(crate) fn serialize_request_proxy(
    req: &Request,
    host: &string,
    using_proxy: bool,
) -> (slice<byte>, error) {
    let (head, mut tw, err) = serialize_request_head(req, host, using_proxy);
    if !err.IsNil() {
        return (head, err);
    }
    let mut buf = crate::bytes::Buffer::new();
    let _ = crate::io::Writer::Write(&mut buf, head);
    let werr = tw.writeBody(&mut buf);
    if !werr.IsNil() {
        return (buf.Bytes(), werr);
    }
    return (buf.Bytes(), errors::nil);
}

/// The request HEAD alone — request line, Host, User-Agent, the
/// transfer-owned lines (via `transferWriter::writeHeader`: Connection:
/// close, Content-Length or Transfer-Encoding: chunked, Trailer), and
/// the user headers. Returns the transferWriter so the caller can
/// stream the body next; its decisions (probe included) are made here.
pub fn serialize_request_head(
    req: &Request,
    host: &string,
    using_proxy: bool,
) -> (slice<byte>, super::transfer::transferWriter, error) {
    let (tw, terr) = super::transfer::newTransferWriter(super::transfer::TransferMsg::Req(req));
    if !terr.IsNil() {
        return (slice::<byte>::__from_vec(Vec::new()), tw, terr);
    }
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

    // Go (request.go:699): err = tw.writeHeader(w, trace) — the
    // transfer-owned lines: Connection: close, exactly one of
    // Content-Length / Transfer-Encoding: chunked, and Trailer.
    {
        let mut hb = crate::bytes::Buffer::new();
        let herr = tw.writeHeader(&mut hb, None);
        if !herr.IsNil() {
            return (slice::<byte>::__from_vec(Vec::new()), tw, herr);
        }
        let _ = b.WriteString(string::from_bytes(&hb.Bytes()));
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

    let head = crate::convert::bytes(b.String());
    return (head, tw, errors::nil);
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
