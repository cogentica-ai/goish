// go: file net/http/server.go decls: response.FlushError, response.SetReadDeadline, response.SetWriteDeadline, response.EnableFullDuplex, response.ReadFrom, conn.hijacked, conn.hijackLocked, response.finishRequest, response.shouldReuseConnection, response.CloseNotify, response.closeNotify, response.Hijack, response.sendExpectationFailed, response.requestTooLarge, response.disableWriteContinue, response.closedRequestBodyEarly, response.declareTrailer, response.finalTrailers, response.bodyAllowed, response.Header, response.Write, response.WriteHeader
// goishlint:ignore GOISH015 — this file is the `response`/ResponseWriter
// half of server.go, split out for size the same way server_tls.rs holds
// its ServeTLS third; the decls manifest above carries the traceability
// the filename rule wants, and renaming to server.rs would collide.
// goishlint:ignore GOISH018 — per-file completeness cannot hold on a
// split Go file: server.go's other ~130 functions live in server.rs,
// which stays UNsuppressed and is the canonical worklist. Nothing this
// suppression hides is missing from that ledger.
// goishlint:ignore GOISH021 — same split-file reasoning as GOISH018;
// server.go's consts/types are anchored in server.rs.
// goishlint:ignore GOISH019 — one finding, on `writerOnly`: Go's field
// is an ANONYMOUS io.Writer embed, which Rust must name (`w`); the
// rule has no line-scoped form. Other structs here pass the check.
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
// Capability matrix for `response` (the PLAINTEXT writer), as
// measured against Go by examples/https_iface_ref_smoke.rs:
//   * ResponseWriter — yes.
//   * Flusher        — yes (chunked streaming, see `promote_chunked`).
//   * Hijacker       — yes (`response::Hijack`), with the slimmed
//                      return described on the trait below.
//   * CloseNotifier  — yes (`response::CloseNotify`), driven by the
//                      netpoll disconnect watcher.
//   * Pusher         — no. Server push is HTTP/2-only; Go's HTTP/1
//                      `*response` doesn't implement Pusher either,
//                      so `w.(Pusher)` yielding `ok == false` is
//                      Go-faithful.
//
// HTTPS does NOT use this writer. goish's serve loop is specialised
// on net::TCPConn, so `Server.ServeTLS` runs a second loop with a
// second writer, `server_tls::tlsResponse`, whose matrix is narrower
// (Flusher only). Go has one writer for both and cannot drift this
// way; goish can, so both are pinned side by side in that smoke.
//
// A concrete writer needs THREE things for `w.(Iface)` to hit: the
// trait impl, the `__goish_as_dyn_any` hook, and registration in the
// runtime registry. Go's assertion is structural and has none of
// these. Two writers have already shipped with the impl and hook but
// no registration (net/http/cgi's response, and tlsResponse), each
// silently disabling flushing for every handler on that transport.
// If you add a writer, register it and add a line to that smoke.
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

use super::header::Header;
use super::transfer::bodyAllowedForStatus;

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
pub fn AsWriter<'a>(w: &'a (dyn ResponseWriter + Send + Sync + 'static)) -> writerOf<'a> {
    return writerOf(w);
}

/// `http.CloseNotifier` (server.go:217) — Go: "the CloseNotifier
/// interface is implemented by ResponseWriters which allow detecting
/// when the underlying connection has gone away."
///
/// Go: "CloseNotify returns a channel that receives at most a single
/// value (true) when the client connection has gone away." Deprecated
/// there in favour of the request context — which goish cancels from
/// the same disconnect watch that fires this.
#[goish::interface] // goishlint:ignore GOISH022 - `goish::interface`, not `goish::int`
pub trait CloseNotifier {
    fn CloseNotify(&self) -> crate::gochan::chan<bool>;
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
/// v1 slim, in two ways. Go returns `(net.Conn, *bufio.ReadWriter,
/// error)`; goish drops the buffered-ReadWriter slot (the v1
/// `response` has no pending buffered read state to hand off) and
/// returns a CONCRETE `TCPConn` rather than the `net.Conn` interface.
///
/// The concrete return is what keeps `tlsResponse` from implementing
/// this trait: a hijacked HTTPS connection is a `tls::Conn`, which is
/// not a `TCPConn`, so the signature cannot express it. Go hijacks
/// TLS conns fine. Closing that gap means widening this return to an
/// interface — a breaking change to a public trait, not a wiring fix.
/// See the KNOWN GAP note in examples/https_iface_ref_smoke.rs.
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
pub struct HeaderHandle(Arc<crate::sync::Mutex<Header>>);

impl HeaderHandle {
    // go: none — goish-only constructor for mock ResponseWriters in tests.
    /// Create a new `HeaderHandle` backed by the given `Header` value.
    /// Useful for constructing mock `ResponseWriter` implementations in tests.
    pub fn new(header: Header) -> Self {
        HeaderHandle(Arc::new(crate::sync::Mutex::new(header)))
    }

    // go: none — goish-only plumbing for the TLS response writer's shared header cell.
    /// Wrap an existing shared header cell — used by the HTTPS
    /// response writer (server_tls.rs), which owns its own
    /// `Arc<crate::sync::Mutex<Header>>`.
    pub(crate) fn __from_arc(inner: Arc<crate::sync::Mutex<Header>>) -> Self {
        HeaderHandle(inner)
    }

    // go: none — goish-only test convenience over the shared header cell.
    /// Snapshot: clone the current header state. Use in tests to read back
    /// what was written into the handle.
    pub fn snapshot(&self) -> Header {
        self.0.Lock().clone()
    }

    // go: none — HeaderHandle forwarder; Header::Set carries the header.go anchor.
    /// `h.Set(key, value)` — replace any existing values for `key`.
    pub fn Set<K: Into<string>, V: Into<string>>(&self, key: K, value: V) {
        self.0.Lock().Set(key, value);
    }

    // go: none — HeaderHandle forwarder; Header::Add carries the header.go anchor.
    /// `h.Add(key, value)` — append `value` to the values for `key`.
    pub fn Add<K: Into<string>, V: Into<string>>(&self, key: K, value: V) {
        self.0.Lock().Add(key, value);
    }

    // go: none — HeaderHandle forwarder; Header::Del carries the header.go anchor.
    /// `h.Del(key)` — drop all values for `key`.
    pub fn Del<K: Into<string>>(&self, key: K) {
        self.0.Lock().Del(key);
    }

    // go: none — HeaderHandle is goish-only plumbing (Go's Header is a
    // map, so it needs no handle type); this forwards to Header::has,
    // which carries the header.go anchor.
    //
    /// `h.has(key)` — key presence, forwarded to [`Header::has`].
    /// Distinct from `Get` returning `""`: serveError must tell an
    /// absent header from one explicitly set empty.
    pub fn has<K: Into<string>>(&self, key: K) -> bool {
        return self.0.Lock().has(key);
    }

    // go: none — HeaderHandle forwarder; Header::Get carries the header.go anchor.
    /// `h.Get(key)` — the first value for `key`, or `""`.
    pub fn Get<K: Into<string>>(&self, key: K) -> string {
        self.0.Lock().Get(key)
    }

    // go: none — HeaderHandle forwarder; Header::Values carries the header.go anchor.
    /// `h.Values(key)` — all values for `key`.
    pub fn Values<K: Into<string>>(&self, key: K) -> slice<string> {
        self.0.Lock().Values(key)
    }
}

// ─── Registry wiring ────────────────────────────────────────────────

// go: none — goish-only interface-registry wiring for cast! support.
/// Register `response`'s trait impls into the per-trait downcast
/// registries the `#[goish::interface]` macro emits. Must run before
/// any `goish::cast!(w, Trait)` call. Idempotent and cheap on the hot
/// path — a `Lazy` runs the registration exactly once for the process.
fn register_response_impls() {
    static REGISTER: crate::lazy::Lazy<()> = crate::lazy::Lazy::new(|| {
        __goish_register_ResponseWriter_impl::<response>();
        __goish_register_Flusher_impl::<response>();
        __goish_register___RequestTooLarge_impl::<response>();
        __goish_register_CloseNotifier_impl::<response>();
        // The ResponseController capabilities. Without these four the
        // controller's probe misses on the server's own writer and
        // every method answers ErrNotSupported — which is what it did.
        super::responsecontroller::__goish_register_FlushErrorer_impl::<response>();
        super::responsecontroller::__goish_register_ReadDeadliner_impl::<response>();
        super::responsecontroller::__goish_register_WriteDeadliner_impl::<response>();
        super::responsecontroller::__goish_register_FullDuplexer_impl::<response>();
        __goish_register_Hijacker_impl::<response>();
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
/// The header lives in its own `Arc<crate::sync::Mutex<Header>>` so that the
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
/// `response.closeNotifyCh` / `closeNotifyTriggered` (server.go:493),
/// lifted into their own cell.
///
/// Go keeps both on the response and reaches them from the conn's
/// read side through `curReq`. goish's disconnect watch is armed with
/// a plain closure BEFORE the response exists, so the cell is what
/// the two share — the watch triggers it, `CloseNotify` reads it.
pub struct closeNotifyCell {
    st: SpinLock<closeNotifyState>,
}

struct closeNotifyState {
    ch: Option<crate::gochan::chan<bool>>,
    triggered: bool,
    handlerDone: bool,
    /// Go's `conn.hijackedv` (server.go:280). It lives in this shared
    /// cell rather than on the response because the serve loop's
    /// panic guard must read it WITHOUT holding the response — a
    /// handler that hijacks and then panics must not have its new
    /// connection closed out from under it.
    hijacked: bool,
}

impl closeNotifyCell {
    // go: none — goish-only: the cell above.
    pub fn new() -> closeNotifyCell {
        return closeNotifyCell {
            st: SpinLock::new(closeNotifyState {
                ch: None,
                triggered: false,
                handlerDone: false,
                hijacked: false,
            }),
        };
    }

    // go: none — goish-only cell mechanics behind conn.closeNotify (anchored on the response-side method).
    /// `response.closeNotify` (server.go:2275). Go: "already
    /// triggered" is a no-op, and the send only happens if someone
    /// asked for the channel — the buffered cap-1 chan is what keeps
    /// this from blocking the reader that calls it.
    pub fn closeNotify(&self) {
        let mut g = self.st.lock();
        if g.triggered {
            return;
        }
        g.triggered = true;
        if let Some(ch) = g.ch.as_ref() {
            let _ = ch.__try_send(true);
        }
        return;
    }

    // go: none — goish-only: read the handlerDone flag, for Hijack's
    // late-call panic.
    pub fn __is_handler_done(&self) -> bool {
        return self.st.lock().handlerDone;
    }

    // go: none — goish-only accessor over the hijacked flag (conn.hijacked carries the anchor).
    /// `(*conn).hijacked()` (server.go:308).
    pub fn __is_hijacked(&self) -> bool {
        return self.st.lock().hijacked;
    }

    // go: none — goish-only: set by Hijack, read by the serve loop and
    // by its panic guard.
    pub fn __set_hijacked(&self) {
        self.st.lock().hijacked = true;
        return;
    }

    // go: none — goish-only: Go sets `handlerDone` on the response;
    // the flag lives here so CloseNotify can panic on a late call
    // without the response having to outlive the handler.
    pub fn __set_handler_done(&self) {
        self.st.lock().handlerDone = true;
        return;
    }

    // go: none — goish-only cell accessor backing response.CloseNotify (anchored on the response method).
    /// `response.CloseNotify` (server.go:2260).
    pub fn CloseNotify(&self) -> crate::gochan::chan<bool> {
        let mut g = self.st.lock();
        if g.handlerDone {
            // Go panics here: a channel handed out after ServeHTTP
            // returned can never fire, so a caller waiting on it would
            // wait forever.
            panic!("net/http: CloseNotify called after ServeHTTP finished");
        }
        if g.ch.is_none() {
            let ch: crate::gochan::chan<bool> = crate::make!(chan bool, 1);
            if g.triggered {
                // Go: "action prior closeNotify call".
                let _ = ch.__try_send(true);
            }
            g.ch = Some(ch);
        }
        return g.ch.as_ref().unwrap().clone();
    }
}

pub struct response {
    inner: crate::sync::Mutex<respInner>,
    /// The close-notify cell this response shares with the conn's
    /// disconnect watch.
    cnc: Arc<closeNotifyCell>,
    /// Response headers — shared with every `HeaderHandle` handed out
    /// by `Header()`.
    header: Arc<crate::sync::Mutex<Header>>,
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
    /// The header map as it stood when the head was COMMITTED.
    ///
    /// Go clones the handler's header at that moment
    /// (`cw.header = w.handlerHeader.Clone()`, server.go:1216) and
    /// writes the head from the clone, so a `Header().Set` after the
    /// handler's first write is ignored. goish rendered the head from
    /// the LIVE map at flush time, which honoured those late sets —
    /// measured: a header set after the first Write reached the wire
    /// where Go drops it.
    ///
    /// The visible cost was trailers. A handler that announces
    /// `Trailer: X-Sum` and sets X-Sum after writing the body, without
    /// an explicit Flush, had the value emitted BOTH in the head and
    /// after the last chunk. `finalTrailers` still reads the live map,
    /// which is what Go does too, so the trailer half stays correct.
    committed: Option<Header>,
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
    /// The `Server.ErrorLog` this response should report handler
    /// misuse through, passed in by the serve loop. Go reaches it as
    /// `c.server.logf`; goish's response has no server pointer, so the
    /// logger itself is handed over. None — a response built outside a
    /// serve loop — falls back to the package logger, which is what
    /// `Server.logf` does when ErrorLog is nil.
    error_log: Option<Arc<crate::log::Logger>>,
    /// Go's `w.req.ProtoAtLeast(1, 1)`, passed in by the server the
    /// way `is_head` is. Go reads it off the request the response
    /// holds; goish's writer holds no request, and without it the
    /// Connection header cannot follow Go's rules — `close` is only
    /// ever ADDED on HTTP/1.1, and `keep-alive` only on HTTP/1.0.
    /// Defaults true so a writer built outside the serve loop behaves
    /// as the common case.
    proto11: bool,
    /// Go's `response.wants10KeepAlive` (server.go:432) — "HTTP/1.0 w/
    /// Connection \"keep-alive\"", populated in readRequest from
    /// `Request.wantsHttp10KeepAlive` and read by writeHeader.
    ///
    /// Separate from `keep_alive` on purpose, and goish conflated the
    /// two. Go decides the 1.0 `Connection: keep-alive` header off
    /// THIS alone, ungated by whether the server will actually reuse
    /// the connection, while the reuse decision is gated. So a 1.0
    /// client talking to a server with keep-alives disabled gets the
    /// header and a closed connection under it. Measured; see
    /// http_keepalives_enabled_smoke's fourth line.
    wants10: bool,
    /// Go's `response.written` (server.go:206) — bytes the handler has
    /// passed to Write, counted whether or not they reached the wire,
    /// so a declared Content-Length can be enforced against them.
    written: i64,
    /// Go's `response.closeAfterReply` (server.go:236) — set when the
    /// request or something during the handler decided this connection
    /// must not be reused.
    closeAfterReply: bool,
    /// Go's `response.requestBodyLimitHit` (server.go:248).
    requestBodyLimitHit: bool,
    /// Go's `conn.werr` (server.go:298) — "any errors writing to rwc",
    /// consulted by shouldReuseConnection. Go hangs it on the conn;
    /// goish's response owns the conn, so it lives here.
    werr: error,
    /// Go's `canWriteContinue atomic.Bool` (server.go:244) — cleared
    /// by disableWriteContinue so Request.Body.Read stops emitting an
    /// automatic 100-Continue.
    canWriteContinue: bool,
    /// Go's `response.trailers []string` (server.go:214) — trailer
    /// keys declared via the `Trailer` response header before the
    /// head is written. Populated by `declareTrailer`.
    trailers: Vec<string>,
}

// go: sdk 1.25.5 net/http/server.go:582-584 writerOnly
/// Go: "writerOnly hides an io.Writer value's optional ReadFrom
/// method from io.Copy" — here it adapts the shared-handle response
/// (`&self` writes) to the `&mut`-shaped io::Writer CopyBuffer wants.
struct writerOnly<'a> {
    w: &'a response,
}

impl crate::io::Writer for writerOnly<'_> {
    fn Write(&mut self, p: slice<byte>) -> (int, crate::errors::error) {
        return ResponseWriter::Write(self.w, p);
    }
}

impl response {
    // go: sdk 1.25.5 net/http/server.go:589-627 response.ReadFrom
    // goishlint:ignore GOISH020 ReadFrom — Go's src is io.Reader; the
    // trait-object spelling is the same arity.
    /// Go: "ReadFrom is here to optimize copying from an *os.File
    /// regular file to a *net.TCPConn with sendfile". goish's TCPConn
    /// carries no ReadFrom/sendfile yet, so this is Go's `rf, ok :=
    /// w.conn.rwc.(io.ReaderFrom); if !ok` arm, verbatim: CopyBuffer
    /// through the response writer over the pooled copy buffer (the
    /// header-sniff preamble and the sendfile handoff activate when a
    /// TCPConn ReaderFrom exists to hand off to).
    pub fn ReadFrom(&self, src: &mut dyn crate::io::Reader) -> (i64, crate::errors::error) {
        let buf = super::server::getCopyBuf();
        let mut wo = writerOnly { w: self };
        let (n, err) = crate::io::CopyBuffer(&mut wo, src, buf.clone());
        super::server::putCopyBuf(buf);
        return (n, err);
    }
}

impl response {
    // go: none — goish-only constructor; Go builds its response inline in conn.readRequest.
    /// Build a fresh `response` over `conn`. Connection is closed
    /// after the response unless the server flips `__set_keep_alive`
    /// before invoking the handler.
    pub fn new(conn: TCPConn) -> Self {
        register_response_impls();
        // Go does NOT seed a Content-Type. It sniffs the body when the
        // handler set none (see `sniffContentType`); seeding one here
        // made `haveType` permanently true, so nothing was ever
        // sniffed and every handler-generated response went out as
        // text/plain — HTML rendered as source in a browser.
        let h = Header::new();
        response {
            inner: crate::sync::Mutex::new(respInner {
                conn,
                status: 200,
                wrote_header: false,
                committed: None,
                flushed: false,
                body: Vec::new(),
                chunked: false,
                keep_alive: false,
                is_head: false,
                proto11: true,
                wants10: false,
                written: 0,
                error_log: None,
                closeAfterReply: false,
                requestBodyLimitHit: false,
                werr: errors::nil,
                canWriteContinue: true,
                trailers: Vec::new(),
            }),
            header: Arc::new(crate::sync::Mutex::new(h)),
            cnc: Arc::new(closeNotifyCell::new()),
        }
    }

    // go: none — goish-only: build a response that shares an existing
    // close-notify cell with the conn's disconnect watch, which is
    // armed before the response exists.
    pub fn __new_with_cnc(conn: TCPConn, cnc: Arc<closeNotifyCell>) -> Self {
        let mut r = response::new(conn);
        r.cnc = cnc;
        return r;
    }

    // go: sdk 1.25.5 net/http/server.go:2260-2273 response.CloseNotify
    /// See closeNotifyCell for the mechanics.
    pub fn CloseNotify(&self) -> crate::gochan::chan<bool> {
        return self.cnc.CloseNotify();
    }

    // go: sdk 1.25.5 net/http/server.go:2275-2285 response.closeNotify
    /// See closeNotifyCell for the mechanics.
    pub fn closeNotify(&self) {
        self.cnc.closeNotify();
        return;
    }

    // go: sdk 1.25.5 net/http/server.go:2237-2258 response.Hijack
    //
    /// The locked core is `hijackLocked` below, as in Go.
    ///
    /// The ownership transfer is the whole point. Go hands the caller
    /// `c.rwc` and stops using it — the server never closes a hijacked
    /// conn, and its serve loop returns immediately. goish takes the
    /// fd OUT of this response's conn (leaving that one dead, so its
    /// Close is a no-op), which gives the fd exactly one closer on
    /// either side of the handover.
    ///
    /// Deadlines are cleared, as Go does: they were the server's
    /// policy for serving a request, and the new owner never agreed to
    /// them. A websocket that inherited a 5-second read deadline would
    /// die on its first idle moment.
    ///
    /// Slim: Go also returns a `*bufio.ReadWriter` holding whatever it
    /// had already buffered off the conn. goish's `Hijacker` returns
    /// the conn alone — the serve loop reads a request at a time and
    /// hands back the buffer, so there is no pre-read remainder to
    /// pass on.
    pub fn Hijack(&self) -> (TCPConn, error) {
        if self.cnc.__is_handler_done() {
            // Go panics: "Hijack called after ServeHTTP finished".
            panic!("net/http: Hijack called after ServeHTTP finished");
        }
        if self.cnc.__is_hijacked() {
            return (TCPConn::dead(), super::server::ErrHijacked.into());
        }
        return self.hijackLocked();
    }

    // go: sdk 1.25.5 net/http/server.go:317-337 conn.hijackLocked
    //
    /// The core of Hijack, past the ErrHijacked/handler-done gates.
    /// Adaptations, stated: Go returns a `*bufio.ReadWriter` wrapping
    /// the conn's buffered reader/writer (and Peeks the background-
    /// read byte back into it); goish's request reader is returned to
    /// the pool per request and the response writes directly, so
    /// there is no buffered state to hand over and the conn alone is
    /// the handoff. `abortPendingRead` is Go's background-read
    /// cancel; goish disarms its netpoll disconnect watch in the
    /// serve loop's hijack branch instead. What ports intact: the
    /// hijacked flag, the pre-handoff flush of anything the handler
    /// already wrote, and the deadline clear (a long-lived hijacked
    /// conn never agreed to the server's per-request policy).
    fn hijackLocked(&self) -> (TCPConn, error) {
        let mut g = self.inner.Lock();
        if g.wrote_header && !g.flushed {
            drop(g);
            let _ = self.flush();
            g = self.inner.Lock();
        }
        self.cnc.__set_hijacked();
        g.canWriteContinue = false;
        let rwc = g.conn.__take_over();
        // Go: `rwc.SetDeadline(time.Time{})`.
        let _ = rwc.SetReadDeadline(crate::time::Time::default());
        let _ = rwc.SetWriteDeadline(crate::time::Time::default());
        return (rwc, crate::errors::nil);
    }

    // go: sdk 1.25.5 net/http/server.go:310-314 conn.hijacked
    //
    /// Read by the serve loop so it stops touching a connection it no
    /// longer owns. Go guards the flag with c.mu; goish's flag lives
    /// in the closeNotifyCell's lock.
    pub fn hijacked(&self) -> bool {
        return self.cnc.__is_hijacked();
    }

    // go: none — goish-only: the serve loop's panic guard needs the
    // flag without holding the response.
    pub fn __cnc(&self) -> Arc<closeNotifyCell> {
        return self.cnc.clone();
    }

    // go: none — goish-only: the serve loop marks the handler done so
    // a late CloseNotify panics as Go's does.
    pub fn __set_handler_done(&self) {
        self.cnc.__set_handler_done();
        return;
    }

    // go: sdk 1.25.5 net/http/server.go:2217-2233 response.sendExpectationFailed
    //
    /// Sends 417 and arranges the close.
    /// without a decls manifest.
    ///
    /// RFC 7231 5.1.1: "A server that receives an Expect field-value
    /// other than 100-continue MAY respond with a 417 (Expectation
    /// Failed)". The `Connection: close` is not optional in practice —
    /// the client is waiting for a 100 before it sends the body, so a
    /// kept-alive conn would then carry a body nobody asked for into
    /// the next request's parse.
    ///
    /// Both lines are belt and braces here: `response::new` starts
    /// with keep_alive false, so the writer would emit
    /// `Connection: close` anyway. They stay because they are what Go
    /// states, and because that default is not this function's to
    /// depend on.
    pub fn sendExpectationFailed(&self) {
        self.header
            .Lock()
            .Set(string("Connection"), string("close"));
        self.__set_keep_alive(false);
        self.WriteHeader(super::status::StatusExpectationFailed);
        return;
    }

    // go: none — goish-only: Go derives keep-alive from conn state; goish's serve loop injects it.
    /// Server hook: enable/disable HTTP keep-alive on this response.
    pub fn __set_keep_alive(&self, keep_alive: bool) {
        self.inner.Lock().keep_alive = keep_alive;
    }

    // go: none — goish-only: Go stores the request on the response; goish passes the protocol version in.
    /// Server hook: record `w.req.ProtoAtLeast(1, 1)`. Drives the
    /// Connection header rules in `finalizeHeaders`.
    pub fn __set_proto11(&self, proto11: bool) {
        self.inner.Lock().proto11 = proto11;
    }

    // go: none — goish-only: Go populates response.wants10KeepAlive in
    // readRequest; goish's serve loop sets it here.
    /// Server hook: record that this was an HTTP/1.0 request asking to
    /// keep the connection.
    pub fn __set_wants10(&self, v: bool) {
        self.inner.Lock().wants10 = v;
    }

    // go: none — goish-only: Go reaches the logger as `c.server.logf`;
    // goish's response has no server pointer, so the serve loop hands
    // the logger over instead.
    /// Server hook: route this response's handler-misuse messages to
    /// `Server.ErrorLog`.
    pub fn __set_error_log(&self, l: Option<Arc<crate::log::Logger>>) {
        self.inner.Lock().error_log = l;
    }

    // go: none — goish-only: Go reaches the server's logger as
    // `c.server.logf` (server.go:3459, ported on Server in server.rs);
    // goish's response has no server pointer, so this forwards to the
    // logger the serve loop handed it, with Server.logf's own
    // package-logger fallback.
    /// The `c.server.logf` every handler-misuse message in this file
    /// goes through. These used to call `log::Printf!` directly, which
    /// meant `Server.ErrorLog` was accepted and then ignored for
    /// exactly the messages a handler provokes — superfluous
    /// WriteHeader, WriteHeader after Hijack, Content-Length beside a
    /// Transfer-Encoding. They went to the process logger instead,
    /// escaping whatever pipeline the application had configured.
    fn logf(&self, msg: string) {
        let l = self.inner.Lock().error_log.clone();
        match l {
            Some(l) => {
                let _ = l.Output(2, msg);
            }
            None => {
                crate::log::println_impl(&[crate::fmt::FmtArg::Val(&msg)]);
            }
        }
    }

    // go: none — goish-only: Go stores the request on the response; goish passes the HEAD-ness in.
    /// Server hook: mark this response as answering a HEAD request.
    /// Mirrors Go's `isHEAD := w.req.Method == "HEAD"`
    /// (server.go:1302): headers and derived Content-Length are
    /// produced as for GET, but no body bytes reach the wire.
    pub fn __set_head(&self, is_head: bool) {
        self.inner.Lock().is_head = is_head;
    }

    // go: none — goish-only: the serve loop's panic guard needs the raw fd.
    /// Server hook: raw fd of the underlying connection. Used by
    /// `serve_conn` to register a panic-time close cleanup.
    pub fn __conn_fd(&self) -> i32 {
        self.inner.Lock().conn.__fd()
    }

    // go: none — goish-only: Go promotes to chunked inside chunkWriter.writeHeader; the buffered writer needs it as an explicit step (this carries response.Flush's semantics).
    /// Promote the response into streaming (chunked) mode. Backs the
    /// `Flusher::Flush` interface method.
    ///
    /// First call: emit the response head with
    /// `Transfer-Encoding: chunked` (no Content-Length), followed by
    /// any already-buffered body bytes as the first chunk. From this
    /// point on, every `Write` emits a chunk directly on the wire.
    /// Subsequent calls are no-ops at the wire level.
    fn promote_chunked(&self) -> error {
        let mut g = self.inner.Lock();
        if !g.wrote_header {
            g.wrote_header = true;
            if g.committed.is_none() {
                g.committed = Some(self.header.Lock().Clone());
            }
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
            let decls = self.header.Lock().Values(string("Trailer"));
            drop(g);
            for i in 0..decls.Len() {
                super::server::foreachHeaderElement(decls[i].clone(), |k: string| {
                    self.declareTrailer(k);
                });
            }
            g = self.inner.Lock();
        }
        // A HEAD response has no body at all — no Transfer-Encoding,
        // no chunks, no terminator (Go's chunkWriter eats the writes;
        // TE is only set when a body follows, server.go:1442-1461).
        let suppress_body = g.is_head || !bodyAllowedForStatus(g.status);
        // Build the head: set Transfer-Encoding, clear any user-set
        // Content-Length (mutually exclusive per RFC 7230 §3.3.2).
        let head = {
            // The COMMITTED header, as in the buffered path — see
            // respInner's `committed`. The chunked path needs it too:
            // a handler that announces a trailer and sets its value
            // after writing the body, with no explicit Flush, reaches
            // HERE with the value already in the live map, and emitted
            // it in the head as well as after the last chunk.
            let mut h: Header = match &g.committed {
                Some(c) => c.clone(),
                None => self.header.Lock().Clone(),
            };
            // Before the auto `chunked` below: Go's hasTE guard tests a
            // HANDLER-set Transfer-Encoding, and a flushed response is
            // still sniffed.
            finalizeHeaders(
                &mut h,
                g.status,
                &g.body,
                g.keep_alive,
                g.wants10,
                g.proto11,
                g.is_head,
            );
            if !suppress_body {
                h.Del(string("Content-Length"));
                h.Set(string("Transfer-Encoding"), string("chunked"));
            }
            build_head(g.status, &h, g.proto11)
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

    // go: none — goish-only accessor; the serve loop reads Go's field directly.
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
    // go: none — goish-only accessor: the serve loop consults Go's
    // `w.requestBodyLimitHit` field directly (server.go:2119); goish's
    // field is behind the response lock.
    pub fn __request_body_limit_hit(&self) -> bool {
        return self.inner.Lock().requestBodyLimitHit;
    }

    // go: sdk 1.25.5 net/http/server.go:564-570 response.requestTooLarge
    pub fn requestTooLarge(&self) {
        let mut g = self.inner.Lock();
        g.closeAfterReply = true;
        g.requestBodyLimitHit = true;
        g.keep_alive = false;
        if !g.wrote_header {
            drop(g);
            self.header
                .Lock()
                .Set(string("Connection"), string("close"));
        }
        return;
    }

    // go: none — goish-only accessor; the serve loop reads Go's field directly.
    // `response.closeAfterReply` accessor — goish-only. The serve loop
    // consults it after the handler returns.
    pub fn __close_after_reply(&self) -> bool {
        return self.inner.Lock().closeAfterReply;
    }

    // go: sdk 1.25.5 net/http/server.go:574-578 response.disableWriteContinue
    //
    /// Go: "stops Request.Body.Read from sending an automatic
    /// 100-Continue. If a 100-Continue is being written, it waits for
    /// it to complete before continuing." Go takes writeContinueMu to
    /// get that wait; goish's flag lives under the response's own
    /// lock, which serialises it against the writer the same way.
    pub fn disableWriteContinue(&self) {
        self.inner.Lock().canWriteContinue = false;
        return;
    }

    // go: none — goish-only accessor over the canWriteContinue flag.
    // `response.canWriteContinue` reader — goish-only, so the serve
    // loop and tests can observe the flag.
    pub fn __can_write_continue(&self) -> bool {
        return self.inner.Lock().canWriteContinue;
    }

    // go: sdk 1.25.5 net/http/server.go:1751-1754 response.closedRequestBodyEarly
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

    // go: sdk 1.25.5 net/http/server.go:553-560 response.declareTrailer
    //
    // (The old "prose, not an anchor" workaround here predated the
    // `// go: file … decls:` manifest, which now scopes the per-file
    // rules to the declared subset.)
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
        self.inner.Lock().trailers.push(k);
        return;
    }

    // go: sdk 1.25.5 net/http/server.go:529-548 response.finalTrailers
    /// The trailer set to emit after the last chunk: keys the handler
    /// declared up front via the `Trailer` header, plus any header it
    /// set under the `Trailer:` magic prefix while writing the body.
    /// Empty Header (Go's nil) when there are none.
    pub fn finalTrailers(&self) -> Header {
        let mut t = Header::new();
        let h = self.header.Lock();
        for (k, vv) in crate::range!(&*h) {
            let ks: &str = k.as_ref();
            if let Some(kk) = ks.strip_prefix(super::server::TrailerPrefix) {
                t.__set_values(
                    super::header::CanonicalHeaderKey(string::from_bytes(kk.as_bytes())),
                    vv.clone(),
                );
            }
        }
        let g = self.inner.Lock();
        for k in g.trailers.iter() {
            let vals = h.Values(k.clone());
            for i in 0..vals.Len() {
                t.Add(k.clone(), vals[i].clone());
            }
        }
        return t;
    }

    // go: sdk 1.25.5 net/http/server.go:1615-1620 response.bodyAllowed
    /// Go: "bodyAllowed reports whether a Write is allowed for this
    /// response type. It's illegal to call this before the header has
    /// been flushed." Go panics on that misuse; so does this.
    pub fn bodyAllowed(&self) -> bool {
        let g = self.inner.Lock();
        if !g.wrote_header {
            panic!("");
        }
        return bodyAllowedForStatus(g.status);
    }

    // go: none — goish-only: the buffered writer's single render-and-write; Go's equivalent work happens incrementally inside chunkWriter + finishRequest.
    pub fn flush(&self) -> error {
        let mut g = self.inner.Lock();
        if g.flushed {
            return errors::nil;
        }
        // Trailers REQUIRE chunked framing: they are sent after the
        // body, and a Content-Length response has nowhere to put them.
        // Go arranges this by declining to derive a Content-Length when
        // the handler declared trailers (chunkWriter.writeHeader's
        // `!trailers` guard), which drops the response into chunked.
        //
        // goish derived the length regardless, so a handler that set
        // `Trailer: X-Sum` and wrote a short body got a Content-Length
        // response, the announcement was dropped, and the trailer
        // itself was never sent — silently, with the body intact. The
        // case that found it was a reverse proxy relaying a backend's
        // trailer announcement to a client, which could not work
        // because there was no announcement left to relay.
        if !g.chunked && !g.is_head && bodyAllowedForStatus(g.status) {
            // Same reasoning for a handler-set `Transfer-Encoding:
            // chunked`: Go sets cw.chunking and frames the body
            // (server.go:1524-1535). goish used to leave it buffered,
            // so the response advertised chunked framing and then sent
            // raw bytes — unparseable to any client that believed the
            // header.
            let hdr = self.header.Lock();
            let declares = hdr.Values(string("Trailer")).Len() > 0
                || hdr.Get(string("Transfer-Encoding")).as_ref() as &str == "chunked";
            drop(hdr);
            if declares {
                drop(g);
                let e = self.promote_chunked();
                if !e.IsNil() {
                    return e;
                }
                g = self.inner.Lock();
            }
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
                g = self.inner.Lock();
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
            if !err.IsNil() {
                g.werr = err.clone();
            }
            return err;
        }

        // Buffered mode: emit Content-Length derived from buffered body.
        let buf = {
            // The COMMITTED header, not the live one — see respInner's
            // `committed`. Falls back to the live map for a response
            // that never wrote anything.
            let mut h: Header = match &g.committed {
                Some(c) => c.clone(),
                None => self.header.Lock().Clone(),
            };
            // HEAD still advertises the GET-equivalent length; 1xx/
            // 204/304 must not carry an auto Content-Length at all
            // (Go omits it for bodyless statuses, server.go:1533).
            // Go also declines to derive one when the handler set a
            // Transfer-Encoding, "because they're generally
            // incompatible" (server.go:1361).
            let hasTE = h.Get(string("Transfer-Encoding")).Len() != 0;
            // Go's condition carries one more clause: `(!isHEAD ||
            // len(p) > 0)` (server.go:1363). Its comment says why —
            // zero bytes on a HEAD is ambiguous between "the resource
            // really is empty" and "the handler noticed the method and
            // wrote nothing", and Go refuses to guess: "If it's
            // actually 0 bytes and the handler never looked at the
            // Request.Method, we just don't send a Content-Length
            // header."
            //
            // goish sent `Content-Length: 0`, which is not a refusal to
            // answer but a claim that the GET would be empty. The
            // common shape `if r.Method == "HEAD" { return }` therefore
            // told every client the resource had no content, and a
            // client that believes it has no reason to fetch it.
            //
            // A HEAD that DID write still advertises the GET-equivalent
            // length, which is the head-writes-body row.
            if bodyAllowedForStatus(g.status)
                && !hasTE
                && h.Values(string("Content-Length")).Len() == 0
                && (!g.is_head || g.body.len() > 0)
            {
                h.Set(string("Content-Length"), int_to_string(g.body.len() as i64));
            }
            finalizeHeaders(
                &mut h,
                g.status,
                &g.body,
                g.keep_alive,
                g.wants10,
                g.proto11,
                g.is_head,
            );
            let mut buf = build_head(g.status, &h, g.proto11);
            if !suppress_body {
                buf.reserve(g.body.len());
                buf.extend_from_slice(&g.body);
            }
            buf
        };
        let (_, err) = g.conn.Write(slice::<byte>::__from_vec(buf));
        if !err.IsNil() {
            g.werr = err.clone();
        }
        err
    }

    // go: sdk 1.25.5 net/http/server.go:1700-1723 response.finishRequest
    // goishlint:ignore GOISH020 finishRequest — Go reads w.req (a field);
    // goish's response carries no request, so the serve loop passes it.
    //
    /// End-of-request bookkeeping, run by the serve loop after the
    /// handler returns (and after the hijack check — a hijacked conn
    /// never reaches here). Adaptations, each stated:
    ///  * Go flushes w.w/w.cw/c.bufw and returns them to the bufio
    ///    pools; goish's response renders straight onto the conn, and
    ///    its pooled READER is already returned per request by the
    ///    serve loop — `flush()` here is the whole write side.
    ///  * `c.r.abortPendingRead` is Go's background-read cancel; goish
    ///    watches for disconnect via netpoll and disarms that watch in
    ///    the serve loop instead.
    ///  * `w.reqBody.Close()` — goish reads bodies eagerly; there is
    ///    no streaming reader left to close.
    /// What ports intact: handlerDone, the default 200 for a handler
    /// that never wrote, the flush, and `MultipartForm.RemoveAll` —
    /// Go's cleanup of a parsed form's temp files at request end.
    pub fn finishRequest(&self, req: &super::request::Request) {
        self.__set_handler_done();
        {
            let g = self.inner.Lock();
            if !g.wrote_header {
                drop(g);
                // Go: w.WriteHeader(StatusOK) — the default status.
                <Self as ResponseWriter>::WriteHeader(self, super::status::StatusOK);
            }
        }
        let _ = self.flush();
        // Go: if w.req.MultipartForm != nil { w.req.MultipartForm.RemoveAll() }
        if let Some(mf) = req.MultipartForm() {
            let _ = mf.RemoveAll();
        }
        return;
    }

    // go: sdk 1.25.5 net/http/server.go:1725-1749 response.shouldReuseConnection
    // goishlint:ignore GOISH020 shouldReuseConnection — Go reads w.req (a
    // field); goish's response carries no request, so the caller passes it.
    //
    /// Go: "reports whether the connection can be reused" — consulted
    /// AFTER finishRequest. The three checks that port intact:
    /// closeAfterReply, the wrote-too-little guard ("Did not write
    /// enough. Avoid getting out of sync."), and a recorded write
    /// error (`c.werr`). `closedRequestBodyEarly` reduces to false —
    /// goish's eager body is fully consumed before the handler runs,
    /// so there is never an early-closed streaming body to get out of
    /// sync with.
    ///
    /// The wrote-too-little guard is goish-shaped: Go compares the
    /// declared contentLength against bytes written through the
    /// chunkWriter; goish buffers the body, so the comparison is a
    /// handler-set Content-Length header vs the buffered body length.
    /// Same protection: a handler that promises N bytes and delivers
    /// fewer must not leave a keep-alive peer waiting on the shortfall.
    pub fn shouldReuseConnection(&self, req: &super::request::Request) -> bool {
        let g = self.inner.Lock();
        if g.closeAfterReply {
            return false;
        }
        if req.Method != "HEAD" && !g.chunked && bodyAllowedForStatus(g.status) {
            let declared = self.header.Lock().Get(string("Content-Length"));
            if declared.Len() != 0 {
                let (n, err) = crate::strconv::ParseInt(declared, 10, 64);
                if err.IsNil() && n != g.body.len() as i64 {
                    return false;
                }
            }
        }
        if !g.werr.IsNil() {
            return false;
        }
        return true;
    }

    // go: none — goish-only: the keep-alive loop reclaims the conn from the finished response; Go's conn owns the socket for the conn's whole life instead.
    /// Server hook: flush the response and return the underlying
    /// connection. Used by the keep-alive loop in ListenAndServe to
    /// hand the connection back for the next request on the same fd.
    pub fn __take_conn(self) -> TCPConn {
        let _ = self.flush();
        self.inner.into_inner().conn
    }

    // go: none — goish-only convenience for examples driving their own accept loop.
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
    // go: sdk 1.25.5 net/http/server.go:1128-1137 response.Header
    fn Header(&self) -> HeaderHandle {
        // The handle shares the response's header `Arc` — mutations
        // on it (`w.Header().Set(...)`) flow back to this response.
        HeaderHandle(self.header.clone())
    }

    // go: sdk 1.25.5 net/http/server.go:1656-1658 response.Write
    fn Write(&self, p: slice<byte>) -> (int, error) {
        let mut g = self.inner.Lock();
        if !g.wrote_header {
            g.wrote_header = true;
            if g.committed.is_none() {
                g.committed = Some(self.header.Lock().Clone());
            }
        }
        // `(*response).write` (server.go:1686): a status that forbids
        // a body rejects handler writes with ErrBodyNotAllowed.
        if p.len() > 0 && !bodyAllowedForStatus(g.status) {
            return (0, super::server::ErrBodyNotAllowed.into());
        }
        // `(*response).write` (server.go:1694-1700): count the bytes
        // BEFORE the bound is tested, then reject the write whole —
        // Go returns (0, ErrContentLength) rather than a short write,
        // and the counter stays advanced so every later write fails
        // too. Without this a handler that declared N bytes and wrote
        // more put all of them on the wire under a Content-Length that
        // did not cover them.
        {
            let declared = self.header.Lock().Get(string("Content-Length"));
            if declared.Len() != 0 {
                let (cl, perr) = crate::strconv::ParseInt(declared, 10, 64);
                if perr.IsNil() && cl >= 0 {
                    g.written += crate::int64(p.len());
                    if g.written > cl {
                        return (0, super::server::ErrContentLength.into());
                    }
                }
            }
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

    // go: sdk 1.25.5 net/http/server.go:1185-1235 response.WriteHeader
    fn WriteHeader(&self, statusCode: int) {
        // Go logs both misuse cases with the offending CALLER's frame
        // (server.go:1186-1194) — the whole point of relevantCaller is
        // that "some handler you wrote called this twice" names the
        // handler, not net/http. Go routes through c.server.logf;
        // goish's response has no server pointer, so the serve loop
        // hands it the logger — see `__set_error_log`. A response built
        // outside a serve loop still falls back to the package logger,
        // which is what Server.logf does with no ErrorLog.
        if self.hijacked() {
            let caller = super::server::relevantCaller();
            self.logf(crate::Sprintf!(
                "http: response.WriteHeader on hijacked connection from %s (%s:%d)",
                caller.Function,
                crate::path::Base(caller.File),
                caller.Line
            ));
            return;
        }
        let mut g = self.inner.Lock();
        if g.wrote_header {
            drop(g);
            let caller = super::server::relevantCaller();
            self.logf(crate::Sprintf!(
                "http: superfluous response.WriteHeader call from %s (%s:%d)",
                caller.Function,
                crate::path::Base(caller.File),
                caller.Line
            ));
            return;
        }
        g.wrote_header = true;
        g.status = statusCode;
        // Go clones the handler header at WriteHeader as well as at the
        // implicit one on first Write (server.go:1216), so a Set after
        // an explicit WriteHeader is ignored just the same.
        if g.committed.is_none() {
            g.committed = Some(self.header.Lock().Clone());
        }
    }

    // go: none — goish-only interface-registry hook emitted for cast! support.
    fn __goish_as_dyn_any(&self) -> Option<&(dyn core::any::Any + Send + Sync)> {
        Some(self)
    }
}

impl __RequestTooLarge for response {
    // go: none — trait forwarder; the response.requestTooLarge anchor is on the inherent method.
    fn requestTooLarge(&self) {
        response::requestTooLarge(self);
        return;
    }
}

impl Hijacker for response {
    // go: none — trait forwarder; the response.Hijack anchor is on the inherent method.
    /// `(*response).Hijack()` — see the inherent method.
    fn Hijack(&self) -> (TCPConn, error) {
        return response::Hijack(self);
    }
}

impl CloseNotifier for response {
    // go: none — trait forwarder; the response.CloseNotify anchor is on the inherent method.
    /// `(*response).CloseNotify()` (server.go:2260).
    fn CloseNotify(&self) -> crate::gochan::chan<bool> {
        return response::CloseNotify(self);
    }
}

// go: sdk 1.25.5 net/http/server.go:1760-1770 response.FlushError
/// Go: "FlushError is an internal Flush wrapper which differs from
/// Flush in that it returns an error." `ResponseController.Flush`
/// prefers it over `Flusher` precisely so a failed flush can be
/// reported rather than swallowed.
impl super::responsecontroller::FlushErrorer for response {
    // go: none — goish idiom: the interface VIEW of promote_chunked,
    //     which is the anchored flush machinery.
    fn FlushError(&self) -> error {
        return self.promote_chunked();
    }
    // go: none — goish idiom: the hidden Any-view hook every
    //     `#[goish::interface]` concrete impl overrides.
    fn __goish_as_dyn_any(&self) -> Option<&(dyn core::any::Any + Send + Sync)> {
        return Some(self);
    }
}

// go: sdk 1.25.5 net/http/server.go:499-501 response.SetReadDeadline
/// Go sets the deadline on the underlying connection, so a handler can
/// bound how long it will wait for the rest of a request body.
impl super::responsecontroller::ReadDeadliner for response {
    // go: none — goish idiom: the conn is the deadline's owner.
    fn SetReadDeadline(&self, deadline: crate::time::Time) -> error {
        let g = self.inner.Lock();
        return g.conn.SetReadDeadline(deadline);
    }
    // go: none — goish idiom: as above.
    fn __goish_as_dyn_any(&self) -> Option<&(dyn core::any::Any + Send + Sync)> {
        return Some(self);
    }
}

// go: sdk 1.25.5 net/http/server.go:503-505 response.SetWriteDeadline
/// The write half of the same, bounding how long a slow client may
/// take to accept the response.
impl super::responsecontroller::WriteDeadliner for response {
    // go: none — goish idiom: as ReadDeadline.
    fn SetWriteDeadline(&self, deadline: crate::time::Time) -> error {
        let g = self.inner.Lock();
        return g.conn.SetWriteDeadline(deadline);
    }
    // go: none — goish idiom: as above.
    fn __goish_as_dyn_any(&self) -> Option<&(dyn core::any::Any + Send + Sync)> {
        return Some(self);
    }
}

// go: sdk 1.25.5 net/http/server.go:507-510 response.EnableFullDuplex
/// Go: "EnableFullDuplex indicates that the request handler will
/// interleave reads from Request.Body with writes to the
/// ResponseWriter." Go must be told, because its default is to consume
/// the request body before replying.
///
/// goish reads the body EAGERLY, before the handler runs, so there is
/// never an unread body for a write to deadlock against — the
/// behaviour Go's flag buys is already unconditional here. Answering
/// nil is therefore honest: the caller asked for full duplex and full
/// duplex is what it gets. Returning ErrNotSupported would say the
/// opposite of the truth.
impl super::responsecontroller::FullDuplexer for response {
    // go: none — goish idiom: see the note above; the eager body read
    //     makes this unconditional.
    fn EnableFullDuplex(&self) -> error {
        return errors::nil;
    }
    // go: none — goish idiom: as above.
    fn __goish_as_dyn_any(&self) -> Option<&(dyn core::any::Any + Send + Sync)> {
        return Some(self);
    }
}

impl Flusher for response {
    // go: none — forwards to FlushError-shaped promote_chunked; the response.Flush anchor lives on the inherent flush machinery (see promote_chunked).
    /// `(*response).Flush()` (server.go:1756) — promote to chunked
    /// streaming. Go's one-line body is `w.FlushError()`; the error is
    /// dropped either way, because `Flusher.Flush` has no error return.
    fn Flush(&self) {
        let _ = self.promote_chunked();
    }

    // go: none — goish-only interface-registry hook emitted for cast! support.
    fn __goish_as_dyn_any(&self) -> Option<&(dyn core::any::Any + Send + Sync)> {
        Some(self)
    }
}

// go: none — goish-only: the trailer half of build_head, reused by flush.
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

// go: none — goish-only: the Content-Type sniffing branch of Go's chunkWriter.writeHeader (server.go:1482-1493), extracted so both goish response writers can share it.
/// Go's Content-Type sniffing branch, lifted out of `writeHeader` so
/// both goish response writers can call it:
///
///     if bodyAllowedForStatus(w.status) {
///         _, haveType := header["Content-Type"]
///         hasTE := header.Get("Transfer-Encoding") != ""
///         if !haveType && !hasTE && len(p) > 0 {
///             setHeader.contentType = DetectContentType(p)
///         }
///     }
///
/// Three details this mirrors exactly, each confirmed against a
/// running Go by examples/sniff_server_ref_smoke.rs:
///
///   * `haveType` tests for the KEY, not a non-empty value. A handler
///     that does `Set("Content-Type", "")` gets an empty Content-Type
///     on the wire, not a sniffed one — hence `Values(..).Len()`
///     rather than `Get(..).Len()`.
///   * `hasTE` is a HANDLER-set Transfer-Encoding. The auto
///     `chunked` that a `Flush()` adds must not suppress sniffing, so
///     this has to run BEFORE the writer sets that header.
///   * An empty body is not sniffed, and the response then carries no
///     Content-Type at all. Go does not fall back to text/plain.
pub(crate) fn sniffContentType(h: &mut Header, status: int, body: &[byte]) {
    if !bodyAllowedForStatus(status) {
        return;
    }
    if h.Values(string("Content-Type")).Len() != 0 {
        return;
    }
    if h.Get(string("Transfer-Encoding")).Len() != 0 {
        return;
    }
    // Go issue 31753: a Content-Encoding means the bytes on the wire
    // are compressed, so sniffing them reports the container's type
    // (gzip → application/x-gzip) instead of the payload's. Go
    // declines to sniff at all rather than guess wrong.
    if h.Get(string("Content-Encoding")).Len() != 0 {
        return;
    }
    if body.is_empty() {
        return;
    }
    let ct = super::sniff::DetectContentType(slice::<byte>::__from_vec(body.to_vec()));
    h.Set(string("Content-Type"), ct);
    return;
}

// go: none — goish-only: the header-finalising tail of Go's chunkWriter.writeHeader (server.go:1482-1511), extracted so both goish response writers can share it.
/// The three header adjustments Go makes after the status is known and
/// before the head is written, shared by both goish response writers:
///
///   1. Sniff the Content-Type, or — for a status that allows no body
///      — drop the headers RFC 7232 §4.1 forbids on it
///      (`suppressedHeaders`, already ported in transfer.rs but until
///      now never called from the response path, so a 304 went out
///      still carrying the handler's Content-Type and Content-Length).
///   2. Stamp `Date` unless the handler set one. Go sends Date on
///      EVERY response including 204 and 304; RFC 9110 §6.6.1 makes it
///      a MUST for an origin server with a clock. goish sent none at
///      all, which breaks any cache that dates a response by it.
///   3. Reject a Content-Length that arrives alongside a non-identity
///      Transfer-Encoding. Go logs and drops the Content-Length.
///      goish used to send BOTH, which is the response half of a
///      request-smuggling desync: a proxy honouring Transfer-Encoding
///      and one honouring Content-Length disagree about where the
///      body ends.
pub(crate) fn finalizeHeaders(
    h: &mut Header,
    status: int,
    body: &[byte],
    keep_alive: bool,
    wants10: bool,
    proto11: bool,
    is_head: bool,
) {
    if bodyAllowedForStatus(status) {
        sniffContentType(h, status, body);
    } else {
        let sup = super::transfer::suppressedHeaders(status);
        for i in 0..sup.Len() {
            h.Del(sup[i].clone());
        }
    }

    if h.Values(string("Date")).Len() == 0 {
        let mut buf = [0u8; 29];
        let now = crate::time::Now().UTC();
        let rendered = super::cookie::append_imf_fixdate_into(&mut buf, &now);
        h.Set(string("Date"), string::from_bytes(rendered));
    }

    let te = h.Get(string("Transfer-Encoding"));
    let hasCL = h.Values(string("Content-Length")).Len() != 0;
    if hasCL && te.Len() != 0 && te.as_ref() as &str != "identity" {
        crate::log::Printf!(
            "http: WriteHeader called with both Transfer-Encoding of %q and a Content-Length of %s",
            te,
            h.Get(string("Content-Length"))
        );
        h.Del(string("Content-Length"));
    }

    // Go's Connection rules (server.go:1366-1373 and :1557-1565).
    // A handler that set the header itself is left alone; otherwise:
    //
    //   * `close` is only ever ADDED on HTTP/1.1. On HTTP/1.0 the
    //     absence of `keep-alive` already means "closing", so Go sends
    //     nothing and just closes. goish sent `Connection: close` to
    //     every 1.0 client.
    //   * `keep-alive` is only ever added on HTTP/1.0, and only when
    //     the response is self-delimiting (a Content-Length, a HEAD,
    //     or a status that allows no body) — otherwise the client
    //     cannot find the end of it. goish sent nothing, so a 1.0
    //     client that asked to keep the connection had no way to learn
    //     it could, and closed after one request.
    if h.Values(string("Connection")).Len() == 0 {
        let hasCL2 = h.Values(string("Content-Length")).Len() != 0;
        // Go: `if w.wants10KeepAlive && (isHEAD || hasCL || ...)`
        // (server.go:1380) — off wants10KeepAlive ALONE. goish tested
        // its combined keep_alive flag, which also carries the
        // server's reuse decision, so a 1.0 client hitting a server
        // with keep-alives disabled lost a header Go still sends.
        if wants10 && (is_head || hasCL2 || !bodyAllowedForStatus(status)) {
            h.Set(string("Connection"), string("keep-alive"));
        } else if !keep_alive && proto11 {
            h.Set(string("Connection"), string("close"));
        }
    }
    return;
}

// go: none — goish-only: renders status line + sorted headers in one buffer; Go streams the same bytes through chunkWriter.writeHeader.
pub(crate) fn build_head(status: int, header: &Header, is11: bool) -> Vec<u8> {
    let mut buf: Vec<u8> = Vec::with_capacity(256);
    // Go's writeStatusLine (server.go:1596), ported in server.rs.
    // Go passes `w.req.ProtoAtLeast(1, 1)`, and so does goish now:
    // this used to be hard-coded true, so an HTTP/1.0 request got a
    // status line claiming HTTP/1.1 — a version the client never
    // offered and may not speak.
    buf.extend_from_slice(super::server::writeStatusLine(is11, status).as_bytes());
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

// go: none — goish-only: one chunked-encoding frame; Go's chunkWriter does this inside its Write.
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

// go: none — goish-only chunk-size renderer (Go uses fmt in chunkWriter).
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

// go: none — goish-only rendering helper (Go uses strconv.AppendInt via the chunkWriter).
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

// go: none — goish-only rendering helper for the head builder.
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

// go: none — goish-only bridge, and the reason it can exist where the
// blanket impl above cannot: this is an impl on ONE concrete (if
// unsized) type, `&dyn ResponseWriter`, not `impl<T: ResponseWriter>
// io::Writer for T`. It therefore cannot overlap io's `&mut __T` or
// `Arc<Mutex<W>>` impls, and coherence accepts it.
//
// With this, a handler writes Go's own line — `fmt::Fprintf!(w, …)` —
// instead of wrapping in AsWriter. Go needs no equivalent: there a
// ResponseWriter's method set already contains
// `Write([]byte) (int, error)`, so it satisfies io.Writer structurally.
//
// `io::Writer::Write` takes `&mut self` while `ResponseWriter::Write`
// takes `&self` (a response writer is shared and interior-mutable); the
// `&mut` on the outer reference is simply unused, which is what lets
// the two signatures meet here.
impl crate::io::Writer for &(dyn ResponseWriter + Send + Sync + 'static) {
    fn Write(&mut self, p: slice<byte>) -> (int, error) {
        return (**self).Write(p);
    }
}
