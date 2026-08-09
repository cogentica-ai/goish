// net/http/server_tls — HTTPS server (ServeTLS / ListenAndServeTLS).
//
// Port of Go 1.25.5 net/http/server.go:
//   Server.ServeTLS           (server.go:3511)
//   Server.ListenAndServeTLS  (server.go:3639)
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
use crate::go;
use crate::net;
use crate::types::{byte, int};

use super::response::{body_allowed_for_status, build_head, push_hex};
use super::response::{Flusher, HeaderHandle, ResponseWriter};
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

        let suppress_body = g.is_head || !body_allowed_for_status(g.status);
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
            if body_allowed_for_status(g.status)
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
        let suppress_body = g.is_head || !body_allowed_for_status(g.status);
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
        if p.len() > 0 && !body_allowed_for_status(g.status) {
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
fn serve_tls_conn(srv: Arc<Server>, tls_conn: tls::Conn, handler: Arc<dyn Handler>) {
    let conn = Arc::new(crate::sync::Mutex::new(tls_conn));
    // Drive the handshake up front so a failure closes the conn
    // without reaching the handler.
    {
        let mut c = conn.Lock();
        if !c.Handshake().IsNil() {
            let _ = c.Close();
            return;
        }
    }

    let max_header_bytes = srv.MaxHeaderBytes;
    loop {
        if srv
            .__state_in_shutdown()
        {
            let mut c = conn.Lock();
            let _ = c.Close();
            return;
        }

        // Read one request. The bufio reader borrows the tls::Conn
        // through the mutex guard for the duration of the parse.
        let (mut req, err): (Request, error) = {
            let mut c = conn.Lock();
            let mut br = bufio::NewReader(&mut *c);
            ReadRequestWithLimit(&mut br, max_header_bytes)
        };
        if !err.IsNil() {
            let mut c = conn.Lock();
            let _ = c.Close();
            return;
        }
        // Go conn.serve stamps `c.remoteAddr` at entry and readRequest
        // copies it onto every request (server.go:2076 / :1120).
        req.RemoteAddr = {
            let c = conn.Lock();
            c.RemoteAddr().String()
        };

        let keep_alive = request_keep_alive_pub(&req) && !srv.__state_in_shutdown();
        let w = tlsResponse::new(conn.clone());
        w.set_keep_alive(keep_alive);
        w.set_head(req.Method == string("HEAD"));

        handler.ServeHTTP(&w, &req);
        let _ = w.flush();

        if !keep_alive {
            let mut c = conn.Lock();
            let _ = c.Close();
            return;
        }
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
        // Track the raw listener so `Shutdown`/`Close` can wake the
        // parked Accept and close the fd — the same install `Serve`
        // performs at entry (Go routes ServeTLS through Serve, which
        // tracks the listener; server.go:3540 → :3405).
        let ln = Arc::new(ln);
        if !self.__track_listener(ln.clone()) {
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
                self.__untrack_listener(&ln);
                return err;
            }
            let conn = tls::Server(alloc::boxed::Box::new(c), &cfg);
            let srv = self.clone();
            let h = handler.clone();
            go!(stack(64 * 1024), move || {
                serve_tls_conn(srv, conn, h);
            });
        }
    }

    /// `(*Server).ListenAndServeTLS(certFile, keyFile)`
    /// (server.go:3639) — bind `Addr` (default ":443") and serve
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
