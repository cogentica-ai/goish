// net/http/server_tls — HTTPS server (ServeTLS / ListenAndServeTLS).
//
// Port of Go 1.25.5 net/http/server.go:
//   Server.ServeTLS           (server.go:3511)
//   Server.ListenAndServeTLS  (server.go:3732)
//   ListenAndServeTLS         (server.go:3712)
//
// Go's `ServeTLS` wraps the listener with `crypto/tls.NewListener`
// and runs the same `Serve` loop — because Go's `Serve`/`conn.serve`
// are written against the `net.Conn` interface, and `*tls.Conn`
// implements it. goish's `serve_conn` is specialised to the concrete
// `net::TCPConn` (it reaches for the raw fd: netpoll disconnect
// watcher, per-conn read deadlines, shutdown idle-kicks), so a TLS
// connection can't flow through it unchanged.
//
// Rather than refactor the freshly-hardened M31 TCP serve loop to be
// transport-generic, this module runs a dedicated HTTPS serve loop
// over `tls::Conn`. It reuses the parts that are already transport-
// agnostic — the request parser (`ReadRequestWithLimit`, generic over
// `io::Reader`), the `Handler`/`ServeMux` dispatch, and the response
// head/body serialisation helpers — so user handlers run over HTTPS
// unchanged.
//
// Documented deferrals vs. the TCP path (all keyed off the raw fd,
// which the TLS record layer sits above):
//   - No netpoll client-disconnect watcher mid-handler; peer close is
//     observed as EOF (close_notify) on the next request read.
//   - No `Server.Shutdown` idle-conn kicking for HTTPS conns (the
//     in_shutdown flag is still honoured between keep-alive requests).
//   - `Expect: 100-continue` is not emitted (bodies are read eagerly
//     after the full header block, as in the TCP path, but without
//     the interim 100 write).

#![allow(non_snake_case, non_camel_case_types)]

extern crate alloc;

use alloc::sync::Arc;
use alloc::vec::Vec;

use crate::bufio;
use crate::crypto::tls;
use crate::errors::{self, error};
use crate::goslice::slice;
use crate::string;
use crate::time;
use crate::go;
use crate::net;
use crate::types::{byte, int};

use super::responsewriter::{build_head, push_hex};
use super::transfer::bodyAllowedForStatus;
use super::responsewriter::{Flusher, HeaderHandle, ResponseWriter};
use super::request::{ReadRequestWithLimit, Request};
use super::server::request_keep_alive_pub;
use super::header::Header;
use super::server::{Handler, Server};

// ─── tlsResponse — ResponseWriter over a tls::Conn ──────────────────

/// A buffered `ResponseWriter` writing over a shared `tls::Conn`.
/// Mirrors the buffered/chunked behaviour of the TCP `response`
/// writer (status line + headers + Content-Length, HEAD body
/// suppression, `Connection: close` when keep-alive is off), but its
/// sink is the TLS record layer rather than a raw fd.
pub(crate) struct tlsResponse {
    conn: Arc<crate::sync::Mutex<tls::Conn>>,
    header: Arc<crate::runtime::spin::SpinLock<Header>>,
    inner: crate::runtime::spin::SpinLock<tlsRespInner>,
}

struct tlsRespInner {
    status: int,
    wrote_header: bool,
    flushed: bool,
    body: Vec<byte>,
    chunked: bool,
    keep_alive: bool,
    is_head: bool,
}

impl tlsResponse {
    // go: none — goish-only: constructor for the TLS-side `response`.
    // Go builds its `response` inline in `(*conn).readRequest`
    // (server.go:1079); the split serve loop needs a named one.
    fn new(conn: Arc<crate::sync::Mutex<tls::Conn>>) -> Self {
        let mut h = Header::new();
        h.Set(string("Content-Type"), string("text/plain; charset=utf-8"));
        tlsResponse {
            conn,
            header: Arc::new(crate::runtime::spin::SpinLock::new(h)),
            inner: crate::runtime::spin::SpinLock::new(tlsRespInner {
                status: 200,
                wrote_header: false,
                flushed: false,
                body: Vec::new(),
                chunked: false,
                keep_alive: false,
                is_head: false,
            }),
        }
    }

    fn set_keep_alive(&self, ka: bool) {
        self.inner.lock().keep_alive = ka;
    }

    /// Mirrors `response::__close_after_reply` on the plaintext path:
    /// the handler may force the conn closed after keep-alive was
    /// decided.
    fn close_after_reply(&self) -> bool {
        return !self.inner.lock().keep_alive;
    }

    fn set_head(&self, is_head: bool) {
        self.inner.lock().is_head = is_head;
    }

    /// Render the response onto the TLS record layer. Idempotent.
    fn flush(&self) -> error {
        let mut g = self.inner.lock();
        if g.flushed {
            return errors::nil;
        }
        g.flushed = true;
        g.wrote_header = true;

        let suppress_body = g.is_head || !bodyAllowedForStatus(g.status);
        if g.chunked {
            if suppress_body {
                return errors::nil;
            }
            // Streaming terminator.
            let mut c = self.conn.Lock();
            let (_, err) = c.Write(&[b'0', b'\r', b'\n', b'\r', b'\n']);
            return err;
        }

        let buf = {
            let mut h = self.header.lock();
            if bodyAllowedForStatus(g.status)
                && h.Get(string("Content-Length")).Len() == 0
            {
                h.Set(
                    string("Content-Length"),
                    int_to_string(g.body.len() as i64),
                );
            }
            if !g.keep_alive && h.Get(string("Connection")).Len() == 0 {
                h.Set(string("Connection"), string("close"));
            }
            let mut buf = build_head(g.status, &h);
            if !suppress_body {
                buf.extend_from_slice(&g.body);
            }
            buf
        };
        let mut c = self.conn.Lock();
        let (_, err) = c.Write(&buf);
        err
    }

    /// `Flush()` backing — promote to chunked streaming: emit the head
    /// (Transfer-Encoding: chunked) plus any buffered body as the
    /// first chunk. Subsequent `Write`s stream each call as a chunk.
    fn promote_chunked(&self) -> error {
        let mut g = self.inner.lock();
        g.wrote_header = true;
        if g.chunked {
            return errors::nil;
        }
        g.chunked = true;
        let suppress_body = g.is_head || !bodyAllowedForStatus(g.status);
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
        let mut c = self.conn.Lock();
        let (_, err) = c.Write(&head);
        if !err.IsNil() {
            return err;
        }
        if !g.body.is_empty() && !suppress_body {
            let body = core::mem::take(&mut g.body);
            let (_, werr) = write_chunk(&mut c, &body);
            if !werr.IsNil() {
                return werr;
            }
        }
        errors::nil
    }
}

/// Emit one HTTP chunk (`<hex>\r\n<data>\r\n`) over the TLS conn.
fn write_chunk(conn: &mut tls::Conn, data: &[byte]) -> (int, error) {
    let n = data.len();
    if n == 0 {
        return (0, errors::nil);
    }
    let mut out: Vec<u8> = Vec::with_capacity(n + 20);
    push_hex(&mut out, n as u64);
    out.extend_from_slice(b"\r\n");
    out.extend_from_slice(data);
    out.extend_from_slice(b"\r\n");
    let (_, err) = conn.Write(&out);
    if !err.IsNil() {
        return (0, err);
    }
    (n as int, errors::nil)
}

fn int_to_string(n: i64) -> crate::gostring::string {
    crate::gostring::string::from_bytes(crate::strconv::Itoa(n as int).as_bytes())
}

impl ResponseWriter for tlsResponse {
    fn Header(&self) -> HeaderHandle {
        HeaderHandle::__from_arc(self.header.clone())
    }

    fn Write(&self, p: slice<byte>) -> (int, error) {
        let mut g = self.inner.lock();
        g.wrote_header = true;
        if p.len() > 0 && !bodyAllowedForStatus(g.status) {
            return (0, super::server::ErrBodyNotAllowed.into());
        }
        if g.chunked {
            if g.is_head {
                return (p.len() as int, errors::nil);
            }
            let mut c = self.conn.Lock();
            return write_chunk(&mut c, &p);
        }
        g.body.extend_from_slice(&p);
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

    fn __goish_as_dyn_any(&self) -> Option<&(dyn core::any::Any + Send + Sync)> {
        Some(self)
    }
}

impl Flusher for tlsResponse {
    fn Flush(&self) {
        let _ = self.promote_chunked();
    }

    fn __goish_as_dyn_any(&self) -> Option<&(dyn core::any::Any + Send + Sync)> {
        Some(self)
    }
}

// ─── serve loop ─────────────────────────────────────────────────────

/// Per-connection HTTPS serve loop: drive the handshake, then run
/// HTTP/1.1 keep-alive over the established TLS conn.
fn serve_tls_conn(
    srv: Arc<Server>,
    tls_conn: tls::Conn,
    // Dispatch goes through `serverHandler` (which reads srv.Handler),
    // so this is kept only to mirror Go's `c.server.Handler` reaching
    // the conn goroutine.
    _handler: Arc<dyn Handler>,
    raw_fd: i32,
    pd_addr: usize,
) {
    let conn = Arc::new(crate::sync::Mutex::new(tls_conn));
    // Join the shutdown / idle-kick machinery. Without this an HTTPS
    // conn is invisible to `Server.Shutdown`, which then returns while
    // requests are still in flight and never kicks an idle HTTPS
    // keep-alive conn. Go gets this for free: plaintext and TLS conns
    // share `conn.serve` (server.go:2039).
    let track = { let t = srv.newConn(pd_addr); srv.trackConn(&t, true); t };
    // Releases the slot on every ordinary exit path. The panic path
    // cannot rely on it — goish recovery skips Rust drops — so the
    // deferred recover below unregisters explicitly, and
    // `trackConn(_, false)` is idempotent so the double call is safe.
    struct TrackGuard<'a> {
        srv: &'a Arc<Server>,
        track: Arc<super::server::ConnTrack>,
    }
    impl<'a> Drop for TrackGuard<'a> {
        // go: none — goish-only. Go relies on `defer` inside
        // conn.serve; goish needs an explicit guard because the
        // HTTPS loop is a separate function.
        fn drop(&mut self) {
            self.srv.trackConn(&self.track, false);
        }
    }
    let _track_guard = TrackGuard {
        srv: &srv,
        track: track.clone(),
    };
    // Drive the handshake up front so a failure closes the conn
    // without reaching the handler.
    //
    // Go stamps `c.remoteAddr` ONCE at conn.serve entry
    // (server.go:2076) and readRequest copies it onto every request
    // (:1120). Formatting it per request cost an alloc *and* a lock
    // acquisition each; hoist both out of the loop, matching the
    // plaintext serve loop.
    //
    // Go bounds the handshake with `Server.tlsHandshakeTimeout()`
    // (server.go:1961) — the smallest positive of ReadHeaderTimeout /
    // ReadTimeout / WriteTimeout — so a peer that completes the TCP
    // connect and then stalls mid-handshake cannot pin the conn.
    let (remote_addr, tls_state, local_addr) = {
        let mut c = conn.Lock();
        let hs_ns = srv.tlsHandshakeTimeout().Nanoseconds();
        if hs_ns > 0 {
            let _ = c.SetDeadline(time::Now().Add(time::Duration(hs_ns)));
        }
        if !c.Handshake().IsNil() {
            let _ = c.Close();
            return;
        }
        if hs_ns > 0 {
            let _ = c.SetDeadline(time::Time::default());
        }
        // Go snapshots the state ONCE after the handshake
        // (`c.tlsState = new(tls.ConnectionState)`, server.go:1987)
        // and readRequest copies the pointer onto every request
        // (:1123). Post-handshake it does not change, so one Arc is
        // shared by every request on this conn.
        (
            c.RemoteAddr().String(),
            Arc::new(c.ConnectionState()),
            c.LocalAddr(),
        )
    };

    // The per-conn context every request on this conn will carry.
    let conn_ctx = crate::context::WithValue(
        crate::context::WithValue(
            crate::context::Background(),
            super::server::ServerContextKey,
            srv.clone(),
        ),
        super::server::LocalAddrContextKey,
        local_addr,
    );

    let max_header_bytes = srv.MaxHeaderBytes;
    // Read/write deadlines, resolved once per conn as the plaintext
    // loop does (server.rs `serve_conn`).
    let read_header_ns = srv.read_header_timeout_ns();
    let idle_ns = srv.idle_timeout_ns();
    let write_timeout_ns = srv.write_timeout_ns();
    let mut first_request = true;
    // Recycled bufio backing buffer — the per-conn analogue of Go's
    // pooled `c.bufr` (newBufioReader, server.go:840), and the same
    // pattern the plaintext loop uses. The reader borrows the conn so
    // it is rebuilt per request, but the 4 KiB buffer survives instead
    // of being allocated and dropped on every keep-alive request.
    let mut rbuf: alloc::vec::Vec<u8> = alloc::vec::Vec::new();
    loop {
        if srv
            .__state_in_shutdown()
        {
            let mut c = conn.Lock();
            let _ = c.Close();
            return;
        }

        // Read one request. The bufio reader borrows the tls::Conn
        // through the mutex guard for the duration of the parse, then
        // hands its buffer back for the next request to reuse.
        // Arm the wait-for-request read deadline: ReadHeaderTimeout on
        // the first request, the idle bound between keep-alive
        // requests (Go arms `idleTimeout()` while waiting for the next
        // first byte, server.go:2135). Cleared once the headers parse
        // so a handler's body read is not artificially capped.
        let wait_ns = if first_request { read_header_ns } else { idle_ns };
        first_request = false;

        let (mut req, err): (Request, error) = {
            let mut c = conn.Lock();
            if wait_ns > 0 {
                let _ = c.SetReadDeadline(time::Now().Add(time::Duration(wait_ns)));
            }
            let mut br =
                bufio::__new_reader_with_buf(&mut *c, core::mem::take(&mut rbuf));
            let out = ReadRequestWithLimit(&mut br, max_header_bytes);
            rbuf = br.__into_buf();
            out
        };
        if !err.IsNil() {
            let mut c = conn.Lock();
            let _ = c.Close();
            return;
        }
        // Same HTTP/1-only gate the plaintext loop applies
        // (server.go:1113 / :2069). A TLS conn is exactly where an
        // HTTP/2 preface arrives, so leaving it out here is the half
        // that matters.
        if !super::server::http1ServerSupportsRequest(&req) {
            let mut c = conn.Lock();
            let _ = crate::io::Writer::Write(
                &mut *c,
                crate::convert::bytes(super::server::__status_error_response(
                    super::status::StatusHTTPVersionNotSupported,
                    string("unsupported protocol version"),
                )),
            );
            let _ = c.Close();
            return;
        }
        {
            let c = conn.Lock();
            let _ = c.SetReadDeadline(time::Time::default());
            // Response phase: apply WriteTimeout if configured.
            if write_timeout_ns > 0 {
                let _ =
                    c.SetWriteDeadline(time::Now().Add(time::Duration(write_timeout_ns)));
            }
        }
        // Request in flight — Go's `c.setState(StateActive)`
        // (server.go:2034): shutdown's idle-kick skips us now.
        track.setState(super::server::CONN_STATE_ACTIVE);
        // Go readRequest stamps the conn's TLS state onto every
        // request served over TLS (server.go:1079).
        req.TLS = Some(tls_state.clone());
        // Go conn.serve stamps `c.remoteAddr` at entry and readRequest
        // copies it onto every request (server.go:2076 / :1120).
        req.RemoteAddr = remote_addr.clone();
        // Go builds ONE ctx per server (ServerContextKey, server.go:3461)
        // and adds the local address per conn (:1937); every request
        // served on the conn carries it. The plaintext loop does this
        // through serve_conn's ctx argument — this loop has no ctx of
        // its own, so it builds the same two values here. Without it a
        // handler on HTTPS cannot reach its Server, and `httputil`'s
        // shouldPanicOnCopyError silently takes the pre-1.11 branch.
        req = req.WithContext(conn_ctx.clone());

        let keep_alive = request_keep_alive_pub(&mut req) && !srv.__state_in_shutdown();
        let w = tlsResponse::new(conn.clone());
        w.set_keep_alive(keep_alive);
        w.set_head(req.Method == string("HEAD"));

        // Close the conn fd if the handler panics — the same guard the
        // plaintext loop installs (server.rs, Go conn.serve's deferred
        // recover at server.go:1944). goish's recovery longjmps to the
        // goroutine entry without running Rust drops, so neither the
        // `tls::Conn` nor its fd would ever be released: the client
        // hangs on Read forever and the server leaks a descriptor per
        // panicking request.
        let panic_remote = remote_addr.clone();
        let panic_srv = srv.clone();
        let panic_track = track.clone();
        crate::defer! {
            let pv = crate::recover!();
            if pv != crate::nil {
                // Go logs "http: panic serving %v: %v\n%s" with a
                // stack (server.go:1944); goish logs addr + value.
                panic_srv.logf(crate::Sprintf!(
                    "http: panic serving %s: %v",
                    panic_remote,
                    pv
                ));
                let _ = crate::syscall::Close(raw_fd);
                // The TrackGuard above never fires on this path, so
                // release the conn accounting here or Shutdown waits
                // on a ghost conn forever.
                panic_srv.trackConn(&panic_track, false);
            }
        }
        // Through serverHandler, as the plaintext loop does — the
        // `OPTIONS *` route lives there (server.go:3331).
        super::server::serverHandler { srv: srv.clone() }.ServeHTTP(&w, &req);
        let _ = w.flush();

        // Same post-handler check as the plaintext loop: the handler
        // may have set closeAfterReply (e.g. MaxBytesReader hitting
        // its limit) after keep_alive was computed.
        if !keep_alive || w.close_after_reply() {
            let mut c = conn.Lock();
            let _ = c.Close();
            return;
        }
        // Waiting on the next keep-alive request — Go's
        // `c.setState(StateIdle)` (server.go:2124), which is what
        // makes this conn eligible for Shutdown's idle kick.
        track.setState(super::server::CONN_STATE_IDLE);
    }
}

impl Server {
    /// `(*Server).ServeTLS(l, certFile, keyFile)` (server.go:3511) —
    /// accept loop on a pre-bound listener, wrapping each accepted
    /// connection in server-side TLS. The cert/key PEM pair is loaded
    /// into a `tls::Config` (or `Server.TLSConfig` is used if set).
    pub fn ServeTLS<C, K>(
        self: Arc<Self>,
        ln: net::Listener,
        certFile: C,
        keyFile: K,
    ) -> error
    where
        C: Into<string>,
        K: Into<string>,
    {
        let cfg = match self.__resolve_tls_config(certFile.into(), keyFile.into()) {
            Ok(c) => c,
            Err(e) => return e,
        };
        return self.__serve_tls_arc(alloc::sync::Arc::new(ln), cfg);
    }

    // go: none — goish-only: the body of ServeTLS after the config is
    // resolved, taking an already-shared listener and an explicit
    // config. httptest holds `Arc<net::Listener>` and cannot mutate
    // `Config.TLSConfig` through its `Arc<Server>`, so it needs both.
    // ServeTLS itself is now the thin wrapper Go's is.
    pub(crate) fn __serve_tls_arc(
        self: Arc<Self>,
        ln: Arc<net::Listener>,
        cfg: tls::Config,
    ) -> error {
        // Track the raw listener so `Shutdown`/`Close` can wake the
        // parked Accept and close the fd — the same install `Serve`
        // performs at entry (Go routes ServeTLS through Serve, which
        // tracks the listener; server.go:3540 → :3405).
        if !self.trackListener(&ln, true) {
            return super::server::ErrServerClosed.into();
        }
        let handler = self.Handler.clone();
        loop {
            if self.__state_in_shutdown() {
                let _ = ln.Close();
                return super::server::ErrServerClosed.into();
            }
            // Accept raw TCP, then wrap server-side TLS — what
            // `tls::listener.Accept` (tls.go:77) does, inlined so the
            // accept parks on the shutdown-tracked fd.
            let (c, err) = ln.Accept();
            if !err.IsNil() {
                if self.__state_in_shutdown() {
                    return super::server::ErrServerClosed.into();
                }
                // Fatal accept error — remove this loop's listener
                // from the shutdown-tracked set (Go's deferred
                // `trackListener(&l, false)`).
                self.trackListener(&ln, false);
                return err;
            }
            // Grab the raw fd BEFORE the conn moves into the TLS
            // wrapper: the panic path in `serve_tls_conn` closes it
            // directly, because goish's recovery longjmps to the
            // goroutine entry without running Rust drops.
            let raw_fd = c.__fd();
            let (_, pd) = c.__disconnect_watch_parts();
            let pd_addr = pd as usize;
            let conn = tls::Server(alloc::boxed::Box::new(c), &cfg);
            let srv = self.clone();
            let h = handler.clone();
            // Bare `go!()` on purpose, unlike the plaintext server's
            // `stack(64 * KB)`: this goroutine runs the TLS handshake,
            // whose ported call chain (record layer -> key schedule ->
            // certificate verification) is far deeper than a 64 KiB
            // sub-page stack allows in debug builds. A bare spawn gets
            // the 1 MiB lazily-committed reservation with a guard page,
            // so depth is available while RSS still tracks only the
            // pages actually touched.
            go!(move || {
                serve_tls_conn(srv, conn, h, raw_fd, pd_addr);
            });
        }
    }

    /// `(*Server).ListenAndServeTLS(certFile, keyFile)`
    /// (server.go:3732) — bind `Addr` (default ":443") and serve
    /// HTTPS.
    pub fn ListenAndServeTLS<C, K>(self: Arc<Self>, certFile: C, keyFile: K) -> error
    where
        C: Into<string>,
        K: Into<string>,
    {
        let addr = if self.Addr.Len() == 0 {
            string(":443")
        } else {
            self.Addr.clone()
        };
        let (ln, err) = net::Listen(string("tcp"), addr);
        if !err.IsNil() {
            return err;
        }
        self.ServeTLS(ln, certFile, keyFile)
    }

    /// Build the effective server `tls::Config`: use `Server.TLSConfig`
    /// if present (its `Certificates` win), else load the cert/key
    /// PEM pair via `tls::LoadX509KeyPair`. Mirrors Go's ServeTLS
    /// cloneable-config logic (server.go:3524).
    fn __resolve_tls_config(
        &self,
        cert_file: string,
        key_file: string,
    ) -> Result<tls::Config, error> {
        let mut cfg = self.TLSConfig.clone().unwrap_or_default();
        let config_has_cert = cfg.Certificates.Len() > 0;
        if !config_has_cert || cert_file.Len() > 0 || key_file.Len() > 0 {
            if cert_file.Len() == 0 || key_file.Len() == 0 {
                if config_has_cert {
                    return Ok(cfg);
                }
                return Err(errors::New(
                    "http: ServeTLS requires certFile+keyFile or Server.TLSConfig.Certificates",
                ));
            }
            let (cert, err) = tls::LoadX509KeyPair(cert_file, key_file);
            if !err.IsNil() {
                return Err(err);
            }
            cfg.Certificates = slice::<tls::Certificate>::__from_vec(alloc::vec![cert]);
        }
        Ok(cfg)
    }
}

/// `http.ListenAndServeTLS(addr, certFile, keyFile, handler)`
/// (server.go:3712) — convenience: build a `Server` and serve HTTPS.
pub fn ListenAndServeTLS<A, C, K>(
    addr: A,
    certFile: C,
    keyFile: K,
    handler: Arc<dyn Handler>,
) -> error
where
    A: Into<string>,
    C: Into<string>,
    K: Into<string>,
{
    let mut srv = Server::new(handler);
    srv.Addr = addr.into();
    Arc::new(srv).ListenAndServeTLS(certFile, keyFile)
}
