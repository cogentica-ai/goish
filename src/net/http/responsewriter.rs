// net/http/response — the ResponseWriter interface + its v1 concrete
// implementation, `response`.
//
// Go-faithful interface layering (server.go):
//
//   type ResponseWriter interface { Header; Write; WriteHeader }
//   type Flusher        interface { Flush() }
//   type Hijacker       interface { Hijack() (...) }
//   type Pusher         interface { Push(...) error }
//
// A handler receives a `ResponseWriter` value and discovers the
// *optional* capabilities of the concrete writer behind it with a
// type assertion:
//
//   if f, ok := w.(http.Flusher); ok { f.Flush() }
//
// Goish models this exactly. `ResponseWriter` / `Flusher` / `Hijacker`
// / `Pusher` are `#[goish::interface]` traits; the concrete v1 writer
// is the (unexported, Go-named) `response` struct. Handlers take
// `&dyn ResponseWriter`, and the comma-ok assertion is spelled with
// the `goish::cast!` macro:
//
//   let (f, ok) = goish::cast!(w, http::Flusher);
//   if ok { f.Flush(); }
//
// — backed by the per-trait downcast registry the interface macro
// emits (see `goish::any`).
//
// v1 capability matrix for `response`:
//   * ResponseWriter — yes.
//   * Flusher        — yes (chunked streaming, see `promote_chunked`).
//   * Hijacker       — no. The buffered v1 writer owns its socket for
//                      its whole lifecycle; raw-socket handoff is
//                      deferred. `w.(Hijacker)` therefore yields
//                      `ok == false`.
//   * Pusher         — no. Server push is HTTP/2-only; Go's HTTP/1
//                      `*response` doesn't implement Pusher either,
//                      so `w.(Pusher)` yielding `ok == false` is
//                      Go-faithful.
//
// Buffered v1 (unchanged from the pre-interface design): handler
// `Write` calls accumulate into an internal body buffer; `flush`
// emits status line + headers + body in one go with a derived
// Content-Length. `Flush()` promotes the response into
// `Transfer-Encoding: chunked` streaming mode.

#![allow(non_snake_case, non_camel_case_types)]

extern crate alloc;

use alloc::sync::Arc;
use alloc::vec::Vec;

use crate::errors::{self, error};
use crate::goslice::slice;
use crate::io::{Closer, Writer};
use crate::net::TCPConn;
use crate::runtime::spin::SpinLock;
use crate::string;
use crate::types::{byte, int};

use super::transfer::bodyAllowedForStatus;
use super::header::Header;

// ─── The interfaces ─────────────────────────────────────────────────

/// `http.ResponseWriter` (server.go:90) — the interface a handler
/// uses to construct an HTTP response.
///
/// Every method takes `&self`: the concrete writer carries interior
/// mutability, mirroring Go's `ResponseWriter` interface value (which
/// is a pointer — all writes flow through it without an exclusive
/// borrow). This is what lets a handler hold `&dyn ResponseWriter`
/// and still downcast it to `&dyn Flusher` for streaming.
#[goish::interface]
pub trait ResponseWriter {
    /// `Header()` — a handle to the response's header map. Mutating
    /// the returned [`HeaderHandle`] (`w.Header().Set(...)`) mutates
    /// this response's headers — Go reference-map semantics. (Go
    /// returns the `Header` map directly; goish's `Header` is a value
    /// type, so the handle restores the shared-mutation behaviour.)
    fn Header(&self) -> HeaderHandle;
    /// `Write(p)` — write response body bytes. Implicitly calls
    /// `WriteHeader(StatusOK)` on first invocation.
    fn Write(&self, p: slice<byte>) -> (int, error);
    /// `WriteHeader(statusCode)` — send the response status line.
    /// Idempotent: the second and later calls are no-ops.
    fn WriteHeader(&self, statusCode: int);
}

// go: none — Go's `ResponseWriter` IS an `io.Writer`: its method set
// contains `Write([]byte) (int, error)`, so every ResponseWriter
// satisfies io.Writer implicitly and fs.go's serveContent, io.Copy and
// io.CopyN take `w` directly.
//
// goish's ResponseWriter::Write takes `&self` — a response writer is
// shared and interior-mutable — while io::Writer::Write takes
// `&mut self`. The signatures therefore do not unify, and a blanket
// `impl<T: ResponseWriter> io::Writer for T` cannot be written: it
// would overlap the existing `Box<W>` and `Arc<Mutex<W>>` impls and
// coherence rejects it.
//
// So the conversion is explicit and lives here rather than at each call
// site. `AsWriter(w)` is what a Go call passing `w` where an io.Writer
// is wanted lowers to.
pub struct writerOf<'a>(pub &'a (dyn ResponseWriter + Send + Sync + 'static));

impl<'a> crate::io::Writer for writerOf<'a> {
    // go: none — goish-only adapter; in Go a ResponseWriter IS an
    // io.Writer, so this conversion has no counterpart to cite.
    fn Write(&mut self, p: slice<byte>) -> (int, error) {
        return self.0.Write(p);
    }
}

// go: none — goish-only adapter, as above.
//
/// Borrow a [`ResponseWriter`] as an [`io::Writer`](crate::io::Writer).
/// Go needs no equivalent — there the two interfaces already unify.
pub fn AsWriter<'a>(
    w: &'a (dyn ResponseWriter + Send + Sync + 'static),
) -> writerOf<'a> {
    return writerOf(w);
}

/// `http.Flusher` (server.go:135) — implemented by ResponseWriters
/// that allow an HTTP handler to flush buffered data to the client.
#[goish::interface]
pub trait Flusher {
    /// `Flush()` — send any buffered data to the client. The first
    /// call promotes the response into chunked streaming mode.
    fn Flush(&self);
}

/// `http.Hijacker` (server.go:150) — implemented by ResponseWriters
/// that allow an HTTP handler to take over the connection.
///
/// v1 slim: Go's `Hijack() (net.Conn, *bufio.ReadWriter, error)`
/// drops the buffered-ReadWriter slot (the v1 `response` has no
/// pending buffered read state to hand off). The v1 `response` does
/// not implement this trait — see the capability matrix at the top
/// of this file.
#[goish::interface]
pub trait Hijacker {
    /// `Hijack()` — take over the connection. Returns the raw conn,
    /// or a non-nil error if hijacking is unsupported.
    fn Hijack(&self) -> (TCPConn, error);
}

// PushOptions and Pusher moved to http.rs — Go declares both in
// net/http/http.go, not in a response file.

// `requestTooLarger` — net/http/request.go line 1243, declared inside
// maxBytesReader.Read. Go's comment explains why it is an interface
// rather than a `*response` assertion: "To prevent binaries which only
// using the HTTP Client code (such as cmd/go) from also linking in the
// HTTP server, don't use a static type assertion to the server
// '*response' type."
//
// Named `requestTooLarger` in Go; goish spells it `__RequestTooLarge`
// because `cast!` needs a nameable public trait.
#[goish::interface] // goishlint:ignore GOISH022 - `goish::interface`, not `goish::int`
pub trait __RequestTooLarge {
    fn requestTooLarge(&self);
}

// ─── HeaderHandle ───────────────────────────────────────────────────

/// A cheap reference handle to a `response`'s header map — the return
/// type of `ResponseWriter::Header()`.
///
/// Why not return `Header` directly: goish's `Header` is a *value*
/// type (cloning it deep-copies the underlying map), whereas Go's
/// `http.Header` is a reference type — `w.Header().Set(k, v)` mutates
/// the response in place. `HeaderHandle` is an `Arc`-shared view that
/// restores that semantics: every mutation flows back to the
/// `response` it came from. Cloning a `HeaderHandle` is an `Arc`
/// bump, not a map copy.
#[derive(Clone)]
pub struct HeaderHandle(Arc<SpinLock<Header>>);

impl HeaderHandle {
    /// Create a new `HeaderHandle` backed by the given `Header` value.
    /// Useful for constructing mock `ResponseWriter` implementations in tests.
    pub fn new(header: Header) -> Self {
        HeaderHandle(Arc::new(SpinLock::new(header)))
    }

    /// Wrap an existing shared header cell — used by the HTTPS
    /// response writer (server_tls.rs), which owns its own
    /// `Arc<SpinLock<Header>>`.
    pub(crate) fn __from_arc(inner: Arc<SpinLock<Header>>) -> Self {
        HeaderHandle(inner)
    }

    /// Snapshot: clone the current header state. Use in tests to read back
    /// what was written into the handle.
    pub fn snapshot(&self) -> Header {
        self.0.lock().clone()
    }

    /// `h.Set(key, value)` — replace any existing values for `key`.
    pub fn Set<K: Into<string>, V: Into<string>>(&self, key: K, value: V) {
        self.0.lock().Set(key, value);
    }

    /// `h.Add(key, value)` — append `value` to the values for `key`.
    pub fn Add<K: Into<string>, V: Into<string>>(&self, key: K, value: V) {
        self.0.lock().Add(key, value);
    }

    /// `h.Del(key)` — drop all values for `key`.
    pub fn Del<K: Into<string>>(&self, key: K) {
        self.0.lock().Del(key);
    }

    // go: none — HeaderHandle is goish-only plumbing (Go's Header is a
    // map, so it needs no handle type); this forwards to Header::has,
    // which carries the header.go anchor.
    //
    /// `h.has(key)` — key presence, forwarded to [`Header::has`].
    /// Distinct from `Get` returning `""`: serveError must tell an
    /// absent header from one explicitly set empty.
    pub fn has<K: Into<string>>(&self, key: K) -> bool {
        return self.0.lock().has(key);
    }

    /// `h.Get(key)` — the first value for `key`, or `""`.
    pub fn Get<K: Into<string>>(&self, key: K) -> string {
        self.0.lock().Get(key)
    }

    /// `h.Values(key)` — all values for `key`.
    pub fn Values<K: Into<string>>(&self, key: K) -> slice<string> {
        self.0.lock().Values(key)
    }
}

// ─── Registry wiring ────────────────────────────────────────────────

/// Register `response`'s trait impls into the per-trait downcast
/// registries the `#[goish::interface]` macro emits. Must run before
/// any `goish::cast!(w, Trait)` call. Idempotent and cheap on the hot
/// path — a `Lazy` runs the registration exactly once for the process.
fn register_response_impls() {
    static REGISTER: crate::lazy::Lazy<()> = crate::lazy::Lazy::new(|| {
        __goish_register_ResponseWriter_impl::<response>();
        __goish_register_Flusher_impl::<response>();
        __goish_register___RequestTooLarge_impl::<response>();
    });
    let _ = REGISTER.get();
}

// ─── The concrete v1 writer ─────────────────────────────────────────

/// The v1 concrete `http.ResponseWriter` (Go's unexported
/// `*http.response`). Owns the connection until `__take_conn` /
/// `close_conn` ends its lifecycle.
///
/// Interior mutability via `SpinLock` so the writer is `Send + Sync`
/// (required by the interface registry) and every interface method
/// can take `&self`. There is no real lock contention: a `response`
/// is confined to its single connection-serving goroutine.
///
/// The header lives in its own `Arc<SpinLock<Header>>` so that the
/// `HeaderHandle` returned by `Header()` shares it (lock order is
/// always `inner` before `header`, so the two locks never deadlock).
///
/// Two modes:
///   * **Buffered (default):** `Write` calls accumulate into `body`;
///     `flush` emits status + headers (with derived `Content-Length`)
///     + body in one send.
///   * **Streaming (after `Flush`):** the response head is emitted
///     with `Transfer-Encoding: chunked` and every subsequent `Write`
///     emits one chunk. The closing `0\r\n\r\n` terminator is sent by
///     the final `flush()`.
pub struct response {
    inner: SpinLock<respInner>,
    /// Response headers — shared with every `HeaderHandle` handed out
    /// by `Header()`.
    header: Arc<SpinLock<Header>>,
}

/// Mutable state of a `response`, serialised behind the writer's
/// `SpinLock`. The header is *not* here — see `response::header`.
struct respInner {
    conn: TCPConn,
    /// Captured at `WriteHeader` time. 200 before that; `Write`
    /// implicitly calls WriteHeader(200) on first body byte.
    status: int,
    /// `true` once `WriteHeader` was called explicitly or implicitly.
    wrote_header: bool,
    /// `true` once `flush` has emitted bytes onto the wire.
    flushed: bool,
    /// Buffered body. In streaming mode it only holds bytes written
    /// before the first `Flush()` (emitted as the first chunk).
    body: Vec<u8>,
    /// Streaming-mode flag — once true, `Write` emits each call as a
    /// chunk and the head has already been sent.
    chunked: bool,
    /// Set by the server before invoking the handler. Controls
    /// whether `flush` emits `Connection: close`.
    keep_alive: bool,
    /// Set by the server when the request method is HEAD. Handler
    /// writes are accepted and counted (so the derived Content-Length
    /// matches what the equivalent GET would return) but the body is
    /// never emitted — Go's `chunkWriter.Write` "Eat writes."
    /// (server.go:1339).
    is_head: bool,
    /// Go's `response.closeAfterReply` (server.go:236) — set when the
    /// request or something during the handler decided this connection
    /// must not be reused.
    closeAfterReply: bool,
    /// Go's `response.requestBodyLimitHit` (server.go:248).
    requestBodyLimitHit: bool,
    /// Go's `canWriteContinue atomic.Bool` (server.go:244) — cleared
    /// by disableWriteContinue so Request.Body.Read stops emitting an
    /// automatic 100-Continue.
    canWriteContinue: bool,
    /// Go's `response.trailers []string` (server.go:214) — trailer
    /// keys declared via the `Trailer` response header before the
    /// head is written. Populated by `declareTrailer`.
    trailers: Vec<string>,
}

impl response {
    /// Build a fresh `response` over `conn`. Connection is closed
    /// after the response unless the server flips `__set_keep_alive`
    /// before invoking the handler.
    pub fn new(conn: TCPConn) -> Self {
        register_response_impls();
        let mut h = Header::new();
        h.Set(string("Content-Type"), string("text/plain; charset=utf-8"));
        response {
            inner: SpinLock::new(respInner {
                conn,
                status: 200,
                wrote_header: false,
                flushed: false,
                body: Vec::new(),
                chunked: false,
                keep_alive: false,
                is_head: false,
                closeAfterReply: false,
                requestBodyLimitHit: false,
                canWriteContinue: true,
                trailers: Vec::new(),
            }),
            header: Arc::new(SpinLock::new(h)),
        }
    }

    /// Server hook: enable/disable HTTP keep-alive on this response.
    pub fn __set_keep_alive(&self, keep_alive: bool) {
        self.inner.lock().keep_alive = keep_alive;
    }

    /// Server hook: mark this response as answering a HEAD request.
    /// Mirrors Go's `isHEAD := w.req.Method == "HEAD"`
    /// (server.go:1302): headers and derived Content-Length are
    /// produced as for GET, but no body bytes reach the wire.
    pub fn __set_head(&self, is_head: bool) {
        self.inner.lock().is_head = is_head;
    }

    /// Server hook: raw fd of the underlying connection. Used by
    /// `serve_conn` to register a panic-time close cleanup.
    pub fn __conn_fd(&self) -> i32 {
        self.inner.lock().conn.__fd()
    }

    /// Promote the response into streaming (chunked) mode. Backs the
    /// `Flusher::Flush` interface method.
    ///
    /// First call: emit the response head with
    /// `Transfer-Encoding: chunked` (no Content-Length), followed by
    /// any already-buffered body bytes as the first chunk. From this
    /// point on, every `Write` emits a chunk directly on the wire.
    /// Subsequent calls are no-ops at the wire level.
    fn promote_chunked(&self) -> error {
        let mut g = self.inner.lock();
        if !g.wrote_header {
            g.wrote_header = true;
        }
        if g.chunked {
            // Already streaming — nothing to flush at the writer level.
            return errors::nil;
        }
        g.chunked = true;
        // Go's chunkWriter.writeHeader calls declareTrailer for each
        // element of the `Trailer` response header as the head is
        // written (server.go:1470-1476). Doing it here is what makes a
        // handler's `w.Header().Set("Trailer", "X-Sum")` actually
        // produce a trailer at the end.
        {
            let decls = self.header.lock().Values(string("Trailer"));
            drop(g);
            for i in 0..decls.Len() {
                super::server::foreachHeaderElement(decls[i].clone(), |k: string| {
                    self.declareTrailer(k);
                });
            }
            g = self.inner.lock();
        }
        // A HEAD response has no body at all — no Transfer-Encoding,
        // no chunks, no terminator (Go's chunkWriter eats the writes;
        // TE is only set when a body follows, server.go:1442-1461).
        let suppress_body = g.is_head || !bodyAllowedForStatus(g.status);
        // Build the head: set Transfer-Encoding, clear any user-set
        // Content-Length (mutually exclusive per RFC 7230 §3.3.2).
        let head = {
            let mut h = self.header.lock();
            if !suppress_body {
                h.Del(string("Content-Length"));
                h.Set(string("Transfer-Encoding"), string("chunked"));
            }
            if !g.keep_alive && h.Get(string("Connection")).Len() == 0 {
                h.Set(string("Connection"), string("close"));
            }
            build_head(g.status, &h)
        };
        let (_, err) = g.conn.Write(slice::<byte>::__from_vec(head));
        if !err.IsNil() {
            return err;
        }
        // Emit any buffered body as the initial chunk.
        if !g.body.is_empty() && !suppress_body {
            let body = core::mem::take(&mut g.body);
            let (_, werr) = write_chunk(&mut g.conn, &slice::<byte>::__from_vec(body));
            if !werr.IsNil() {
                return werr;
            }
        }
        errors::nil
    }

    /// Render the response onto the wire. Idempotent — calling twice
    /// is a no-op. After `flush`, the underlying connection holds
    /// only the kept-alive read buffer (if any) and may be reused.
    // `response.requestTooLarge` moved to the __RequestTooLarge impl
    // below, so `cast!` can reach it the way Go's type assertion does.
    /// Go: "called by maxBytesReader when too much input has been read
    /// from the client."
    ///
    /// The connection MUST close: the client is still sending a body
    /// nobody will read, so the unread remainder would be parsed as
    /// the next keep-alive request. That is a request-smuggling shape,
    /// which is why goish's earlier "slim port: drops Go's
    /// requestTooLarge hook" was not a harmless simplification.
    pub fn requestTooLarge(&self) {
        let mut g = self.inner.lock();
        g.closeAfterReply = true;
        g.requestBodyLimitHit = true;
        g.keep_alive = false;
        if !g.wrote_header {
            drop(g);
            self.header.lock().Set(string("Connection"), string("close"));
        }
        return;
    }

    // `response.closeAfterReply` accessor — goish-only. The serve loop
    // consults it after the handler returns.
    pub fn __close_after_reply(&self) -> bool {
        return self.inner.lock().closeAfterReply;
    }

    // `response.disableWriteContinue` — net/http/server.go line 574.
    // Prose, not an anchor; see declareTrailer below.
    //
    /// Go: "stops Request.Body.Read from sending an automatic
    /// 100-Continue. If a 100-Continue is being written, it waits for
    /// it to complete before continuing." Go takes writeContinueMu to
    /// get that wait; goish's flag lives under the response's own
    /// lock, which serialises it against the writer the same way.
    pub fn disableWriteContinue(&self) {
        self.inner.lock().canWriteContinue = false;
        return;
    }

    // `response.canWriteContinue` reader — goish-only, so the serve
    // loop and tests can observe the flag.
    pub fn __can_write_continue(&self) -> bool {
        return self.inner.lock().canWriteContinue;
    }

    // `response.closedRequestBodyEarly` — net/http/server.go line 1751.
    //
    /// Go type-asserts `w.req.Body.(*body)` and asks it whether Close
    /// beat EOF; `shouldReuseConnection` refuses the conn when it did,
    /// because an undrained body desyncs the next keep-alive request.
    ///
    /// ALWAYS FALSE in goish today, and that is not a stub: a goish
    /// Request owns its body as a `slice<byte>`, so there is no
    /// `*body` to assert on and no early close to detect. The same
    /// desync is prevented from the other end — MaxBytesReader and
    /// MaxBytesHandler set closeAfterReply directly. This grows a real
    /// body when Request.Body becomes an io.ReadCloser.
    pub fn closedRequestBodyEarly(&self) -> bool {
        return false;
    }

    // `response.declareTrailer` — net/http/server.go line 551.
    //
    // NOT a `// go:` anchor: this file holds `response` while server.rs
    // holds the rest of server.go, and GOISH018/021 are per-FILE — one
    // anchor here made the rule demand all 153 of server.go's
    // declarations in this file (+209 false findings, measured). Same
    // split-file limitation as server_tls.rs.
    /// Go: "declareTrailer is called for each Trailer header when the
    /// response header is written. It notes that a header will need to
    /// be written in the trailers at the end of the response."
    ///
    /// The `ValidTrailerHeader` gate is a security control, not a
    /// nicety: RFC 7230 §4.1.2 forbids these in trailers precisely
    /// because a proxy that has already acted on the head must not see
    /// them changed afterwards.
    pub fn declareTrailer(&self, k: string) {
        let k = super::header::CanonicalHeaderKey(k);
        if !super::http::ValidTrailerHeader(&k) {
            // Go: "Forbidden by RFC 7230, section 4.1.2"
            return;
        }
        self.inner.lock().trailers.push(k);
        return;
    }

    // `response.finalTrailers` — net/http/server.go line 529. Prose,
    // not an anchor; see declareTrailer above.
    /// The trailer set to emit after the last chunk: keys the handler
    /// declared up front via the `Trailer` header, plus any header it
    /// set under the `Trailer:` magic prefix while writing the body.
    /// Empty Header (Go's nil) when there are none.
    pub fn finalTrailers(&self) -> Header {
        let mut t = Header::new();
        let h = self.header.lock();
        for (k, vv) in crate::range!(&*h) {
            let ks: &str = k.as_ref();
            if let Some(kk) = ks.strip_prefix(super::server::TrailerPrefix) {
                t.__set_values(
                    super::header::CanonicalHeaderKey(string::from_bytes(kk.as_bytes())),
                    vv.clone(),
                );
            }
        }
        let g = self.inner.lock();
        for k in g.trailers.iter() {
            let vals = h.Values(k.clone());
            for i in 0..vals.Len() {
                t.Add(k.clone(), vals[i].clone());
            }
        }
        return t;
    }

    // `response.bodyAllowed` — net/http/server.go line 1613. Prose,
    // not an anchor; see declareTrailer above.
    /// Go: "bodyAllowed reports whether a Write is allowed for this
    /// response type. It's illegal to call this before the header has
    /// been flushed." Go panics on that misuse; so does this.
    pub fn bodyAllowed(&self) -> bool {
        let g = self.inner.lock();
        if !g.wrote_header {
            panic!("");
        }
        return bodyAllowedForStatus(g.status);
    }

    pub fn flush(&self) -> error {
        let mut g = self.inner.lock();
        if g.flushed {
            return errors::nil;
        }
        g.flushed = true;
        if !g.wrote_header {
            g.wrote_header = true;
        }
        let suppress_body = g.is_head || !bodyAllowedForStatus(g.status);
        if g.chunked {
            if suppress_body {
                // No Transfer-Encoding was advertised and no chunks
                // were sent — a terminator would itself be a body.
                return errors::nil;
            }
            // Streaming mode: "0\r\n", then the trailer block, then
            // the final CRLF. Go writes the trailers between the
            // zero-length chunk and the blank line (chunkWriter.close,
            // server.go:1650); a bare "0\r\n\r\n" drops them silently.
            let trailers = {
                drop(g);
                let t = self.finalTrailers();
                g = self.inner.lock();
                t
            };
            let mut out: Vec<u8> = alloc::vec![b'0', b'\r', b'\n'];
            if trailers.Len() > 0 {
                // Same key-sorted, CRLF-terminated rendering the head
                // uses — build_head's second half, reused so a trailer
                // cannot bypass the header sanitiser.
                let tb = build_trailer_block(&trailers);
                out.extend_from_slice(&tb);
            }
            out.extend_from_slice(b"\r\n");
            let (_, err) = g.conn.Write(slice::<byte>::__from_vec(out));
            return err;
        }

        // Buffered mode: emit Content-Length derived from buffered body.
        let buf = {
            let mut h = self.header.lock();
            // HEAD still advertises the GET-equivalent length; 1xx/
            // 204/304 must not carry an auto Content-Length at all
            // (Go omits it for bodyless statuses, server.go:1533).
            if bodyAllowedForStatus(g.status)
                && h.Get(string("Content-Length")).Len() == 0
            {
                h.Set(string("Content-Length"), int_to_string(g.body.len() as i64));
            }
            if !g.keep_alive && h.Get(string("Connection")).Len() == 0 {
                h.Set(string("Connection"), string("close"));
            }
            let mut buf = build_head(g.status, &h);
            if !suppress_body {
                buf.reserve(g.body.len());
                buf.extend_from_slice(&g.body);
            }
            buf
        };
        let (_, err) = g.conn.Write(slice::<byte>::__from_vec(buf));
        err
    }

    /// Server hook: flush the response and return the underlying
    /// connection. Used by the keep-alive loop in ListenAndServe to
    /// hand the connection back for the next request on the same fd.
    pub fn __take_conn(self) -> TCPConn {
        let _ = self.flush();
        self.inner.into_inner().conn
    }

    /// Convenience for examples that drive their own accept loop:
    /// flush headers (if not yet) and close the underlying conn.
    pub fn close_conn(self) -> error {
        let _ = self.flush();
        let mut conn = self.inner.into_inner().conn;
        conn.Close()
    }
}

// ─── Interface impls for `response` ─────────────────────────────────

impl ResponseWriter for response {
    fn Header(&self) -> HeaderHandle {
        // The handle shares the response's header `Arc` — mutations
        // on it (`w.Header().Set(...)`) flow back to this response.
        HeaderHandle(self.header.clone())
    }

    fn Write(&self, p: slice<byte>) -> (int, error) {
        let mut g = self.inner.lock();
        if !g.wrote_header {
            g.wrote_header = true;
        }
        // `(*response).write` (server.go:1686): a status that forbids
        // a body rejects handler writes with ErrBodyNotAllowed.
        if p.len() > 0 && !bodyAllowedForStatus(g.status) {
            return (0, super::server::ErrBodyNotAllowed.into());
        }
        // HEAD: eat writes (server.go:1339) — report success so the
        // handler proceeds normally. In buffered mode the bytes are
        // kept so `flush` derives the GET-equivalent Content-Length.
        if g.chunked {
            if g.is_head {
                return (p.len() as int, errors::nil);
            }
            return write_chunk(&mut g.conn, &p);
        }
        g.body.extend_from_slice(&*p);
        (p.len() as int, errors::nil)
    }

    fn WriteHeader(&self, statusCode: int) {
        let mut g = self.inner.lock();
        if g.wrote_header {
            return;
        }
        g.wrote_header = true;
        g.status = statusCode;
    }

    fn __goish_as_dyn_any(
        &self,
    ) -> Option<&(dyn core::any::Any + Send + Sync)> {
        Some(self)
    }
}

impl __RequestTooLarge for response {
    fn requestTooLarge(&self) {
        response::requestTooLarge(self);
        return;
    }
}

impl Flusher for response {
    /// `(*response).Flush()` (server.go:1756) — promote to chunked
    /// streaming. Go's one-line body is `w.FlushError()`; the error is
    /// dropped either way, because `Flusher.Flush` has no error return.
    fn Flush(&self) {
        let _ = self.promote_chunked();
    }

    fn __goish_as_dyn_any(
        &self,
    ) -> Option<&(dyn core::any::Any + Send + Sync)> {
        Some(self)
    }
}

/// Build the response head (status line + headers + final CRLF).
/// Shared between buffered and streaming modes.
// go: none — goish-only: the trailer block after the terminating
// chunk. Routed through the SAME `WriteSubset` the head uses, so a
// trailer value carrying CRLF cannot inject a header — the exact
// defect a third hand-rolled key:value loop caused on the head path.
fn build_trailer_block(trailers: &Header) -> Vec<u8> {
    let mut hb = crate::bytes::Buffer::new();
    let _ = trailers.WriteSubset(&mut hb, &crate::gomap::map::<string, bool>::new());
    return hb.Bytes().as_ref().to_vec();
}

pub(crate) fn build_head(status: int, header: &Header) -> Vec<u8> {
    let mut buf: Vec<u8> = Vec::with_capacity(256);
    // Go's writeStatusLine (server.go:1596), ported in server.rs.
    // `is11` is true because goish's server only speaks HTTP/1.1;
    // Go passes `w.req.ProtoAtLeast(1, 1)`.
    buf.extend_from_slice(super::server::writeStatusLine(true, status).as_bytes());
    // Go's chunkWriter.writeHeader ends with
    // `cw.header.WriteSubset(w, excludeHeader)` — the SAME writer the
    // public Header.Write uses.
    //
    // This used to be a third hand-rolled `key: value\r\n` loop, and
    // it is the one that reaches a real socket. It had neither the
    // ValidHeaderFieldName guard nor the newline folding that
    // writeSubset applies, so a handler setting a header value
    // containing CRLF — a redirect target or filename echoed from user
    // input, say — wrote a real extra header onto the wire. The
    // response path was hardened in writeSubset earlier; THIS copy
    // bypassed it.
    //
    // Routing through writeSubset also sorts the keys, which Go does
    // here too.
    {
        let mut hb = crate::bytes::Buffer::new();
        let _ = header.WriteSubset(&mut hb, &crate::gomap::map::<string, bool>::new());
        buf.extend_from_slice(hb.Bytes().as_ref());
    }
    buf.extend_from_slice(b"\r\n");
    return buf;
}

/// Emit one chunk on the wire: `<hex>\r\n<data>\r\n`. Returns
/// `(data.len(), err)` so a `Write` proxy can forward it.
fn write_chunk(conn: &mut TCPConn, data: &slice<byte>) -> (int, error) {
    let n = data.Len();
    if n == 0 {
        return (0, errors::nil);
    }
    let mut head: Vec<u8> = Vec::with_capacity(20);
    push_hex(&mut head, n as u64);
    head.extend_from_slice(b"\r\n");
    let (_, err) = conn.Write(slice::<byte>::__from_vec(head));
    if !err.IsNil() {
        return (0, err);
    }
    let (_, werr) = conn.Write(data.clone());
    if !werr.IsNil() {
        return (0, werr);
    }
    let (_, terr) = conn.Write(slice::<byte>::__from_vec(alloc::vec![b'\r', b'\n']));
    (n, terr)
}

pub(crate) fn push_hex(buf: &mut Vec<u8>, mut n: u64) {
    if n == 0 {
        buf.push(b'0');
        return;
    }
    let mut tmp = [0u8; 16];
    let mut i = 0;
    while n > 0 {
        let nibble = (n & 0xf) as u8;
        tmp[i] = if nibble < 10 {
            b'0' + nibble
        } else {
            b'a' + (nibble - 10)
        };
        n >>= 4;
        i += 1;
    }
    while i > 0 {
        i -= 1;
        buf.push(tmp[i]);
    }
}

/// Reason phrase for a status code via the full IANA registry. Empty
/// string falls back to "Status" so the wire stays well-formed.


fn int_to_string(n: i64) -> string {
    let mut buf: Vec<u8> = Vec::with_capacity(20);
    if n < 0 {
        buf.push(b'-');
        push_dec_64(&mut buf, (-n) as u64);
    } else {
        push_dec_64(&mut buf, n as u64);
    }
    string::from_bytes(&buf)
}

fn push_dec_64(buf: &mut Vec<u8>, mut n: u64) {
    if n == 0 {
        buf.push(b'0');
        return;
    }
    let mut tmp = [0u8; 20];
    let mut i = 0;
    while n > 0 {
        tmp[i] = b'0' + (n % 10) as u8;
        n /= 10;
        i += 1;
    }
    while i > 0 {
        i -= 1;
        buf.push(tmp[i]);
    }
}

