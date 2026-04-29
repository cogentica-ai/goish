// net/http/server — Handler trait, ServeMux, ListenAndServe.
//
// Slim port of Go's net/http.Server (server.go:2993),
// http.ServeMux (server.go:2486), and http.ListenAndServe
// (server.go:3702). Delivers the canonical Go-shape:
//
//   let mut mux = http::ServeMux::new();
//   mux.HandleFunc(string("/"), |w, r| {
//       let _ = w.Write(bytes("hello\n"));
//   });
//   let _ = http::ListenAndServe(string(":8080"), &mux);
//
// One goroutine per connection (`go!(stack(N), …)`), blocking I/O.
// HTTP/1.x only, no keep-alive in v1 (`Connection: close` injected
// by ResponseWriter). The mux uses a flat exact-match table plus
// longest-prefix tiebreak for `"/path/"` patterns — same algorithm
// shape as Go's `ServeMux` (Go 1.22 simple form, pre-`{wildcard}`
// patterns).

#![allow(non_snake_case)]

extern crate alloc;

use alloc::sync::Arc;
use alloc::vec::Vec;

use crate::bufio;
use crate::errors::error;
use crate::go;
use crate::io::Closer;
use crate::net;
use crate::string;
use crate::sync::Mutex;

use super::request::{ReadRequest, Request};
use super::response::ResponseWriter;

/// `http.Handler` — types that can serve HTTP requests. Mirrors
/// Go's `type Handler interface { ServeHTTP(ResponseWriter, *Request) }`
/// (server.go:88).
pub trait Handler: Send + Sync {
    fn ServeHTTP(&self, w: &mut ResponseWriter, r: &Request);
}

/// `http.HandlerFunc` adapter — wrap a closure as a `Handler`.
/// Mirrors Go's `type HandlerFunc func(ResponseWriter, *Request)`.
pub struct HandlerFunc<F>(pub F)
where
    F: Fn(&mut ResponseWriter, &Request) + Send + Sync;

impl<F> Handler for HandlerFunc<F>
where
    F: Fn(&mut ResponseWriter, &Request) + Send + Sync,
{
    fn ServeHTTP(&self, w: &mut ResponseWriter, r: &Request) {
        (self.0)(w, r);
    }
}

// ─── ServeMux ────────────────────────────────────────────────────────

/// `http.ServeMux` — pattern → Handler routing table.
///
/// Two pattern shapes:
///   - Exact: `"/about"` matches only `/about`.
///   - Prefix: `"/static/"` (trailing slash) matches any path
///     starting with `/static/`.
/// Longest-pattern wins on conflict (`/static/` > `/`).
pub struct ServeMux {
    /// Inner state behind a Mutex so handlers can be added before
    /// `ListenAndServe` and `ServeMux` is `Send + Sync` for
    /// passing into the per-connection goroutine.
    state: Arc<Mutex<MuxState>>,
}

struct MuxState {
    /// Routes as a Vec so the value can be a `dyn Handler` trait
    /// object — `gomap` requires V: Default which `dyn Trait`
    /// can't satisfy. Linear scan in `match_handler` is fine
    /// for typical route counts (<100).
    routes: Vec<(string, Arc<dyn Handler>)>,
}

impl ServeMux {
    pub fn new() -> Self {
        ServeMux {
            state: Arc::new(Mutex::new(MuxState { routes: Vec::new() })),
        }
    }

    /// `mux.Handle(pattern, h)` — register a Handler. If `pattern`
    /// already exists, replaces it (Go panics; we silently replace
    /// for v1 simplicity).
    pub fn Handle(&self, pattern: string, h: Arc<dyn Handler>) {
        let mut s = self.state.Lock();
        for r in s.routes.iter_mut() {
            if r.0 == pattern {
                r.1 = h;
                return;
            }
        }
        s.routes.push((pattern, h));
    }

    /// `mux.HandleFunc(pattern, fn)` — register a closure handler.
    /// The closure must be `Send + Sync + 'static` to be safely
    /// shared across the per-connection worker goroutines.
    pub fn HandleFunc<F>(&self, pattern: string, f: F)
    where
        F: Fn(&mut ResponseWriter, &Request) + Send + Sync + 'static,
    {
        self.Handle(pattern, Arc::new(HandlerFunc(f)));
    }

    /// Internal: pick the handler for `path`. Returns the
    /// longest-matching pattern's handler, or a 404 stub.
    fn match_handler(&self, path: &string) -> Arc<dyn Handler> {
        let s = self.state.Lock();
        // Try exact match first.
        for r in s.routes.iter() {
            if r.0 == *path {
                return r.1.clone();
            }
        }
        // Then longest prefix-with-trailing-slash match.
        let path_b = path.as_bytes();
        let mut best_len: usize = 0;
        let mut best: Option<Arc<dyn Handler>> = None;
        for (pat, handler) in s.routes.iter() {
            let pb = pat.as_bytes();
            if pb.last() == Some(&b'/') && path_b.starts_with(pb) && pb.len() > best_len {
                best_len = pb.len();
                best = Some(handler.clone());
            }
        }
        best.unwrap_or_else(|| Arc::new(NotFoundHandler))
    }
}

impl Handler for ServeMux {
    fn ServeHTTP(&self, w: &mut ResponseWriter, r: &Request) {
        let h = self.match_handler(&r.URL.Path);
        h.ServeHTTP(w, r);
    }
}

/// Default 404 handler. Matches Go's `http.NotFoundHandler()`.
pub struct NotFoundHandler;
impl Handler for NotFoundHandler {
    fn ServeHTTP(&self, w: &mut ResponseWriter, _r: &Request) {
        w.WriteHeader(404);
        let _ = w.Write(crate::convert::bytes("404 page not found\n"));
    }
}

// ─── ListenAndServe ──────────────────────────────────────────────────

/// `http.ListenAndServe(addr, handler)` — bind + accept loop +
/// goroutine-per-connection dispatch. Blocks until the listener is
/// closed (which never happens in v1; returns only on Listen error).
///
/// Mirrors Go's `func ListenAndServe(addr string, handler Handler) error`
/// (server.go:3702). Always returns a non-nil error in v1 — there is
/// no graceful shutdown path yet.
pub fn ListenAndServe(addr: string, handler: Arc<dyn Handler>) -> error {
    let (ln, err) = net::Listen(string("tcp"), addr);
    if !err.IsNil() {
        return err;
    }
    Serve(ln, handler)
}

/// `http.Serve(l, handler)` — accept loop on a pre-bound Listener.
/// Mirrors Go's `func Serve(l net.Listener, handler Handler) error`
/// (server.go:3676). Useful when you need access to the bound port
/// before serving (e.g., to print it for tests / port-zero binds).
pub fn Serve(ln: net::Listener, handler: Arc<dyn Handler>) -> error {
    loop {
        let (conn, err) = ln.Accept();
        if !err.IsNil() {
            return err;
        }
        let h = handler.clone();
        // 64 KiB stack — ample for the per-handler chain in debug
        // and release. Handlers that need more can spawn their own
        // goroutines.
        go!(stack(64 * 1024), move || {
            serve_conn(conn, h);
        });
    }
}

/// Per-connection serving loop with HTTP/1.1 keep-alive (M27f-β).
///
/// Cycle: SetReadDeadline(ReadHeaderTimeout) → ReadRequest → clear
/// deadline → dispatch → flush response → if keep-alive, reuse conn
/// for next request; otherwise close.
///
/// Idle keep-alive connections are bounded by the read deadline:
/// after the configured `ReadHeaderTimeout` (default 5s) of no data
/// from the client, ReadRequest's underlying Read returns
/// "i/o timeout" and we close the conn. This prevents stuck peers
/// from leaking goroutines indefinitely.
fn serve_conn(mut conn: net::Conn, handler: Arc<dyn Handler>) {
    use crate::time;
    /// Idle keep-alive timeout. Matches Go's `Server.IdleTimeout`
    /// default behavior (when zero, falls back to ReadHeaderTimeout).
    /// 5s is a conservative compromise — long enough that browsers
    /// reuse conns within a page load, short enough that idle peers
    /// don't pin goroutines.
    const READ_HEADER_TIMEOUT: i64 = 5_000_000_000; // 5s in ns

    loop {
        // Arm the idle deadline before each request. Cleared after the
        // headers parse so the handler's body read isn't artificially
        // capped (chunked uploads etc. take their own time).
        let dl = time::Now().Add(time::Duration(READ_HEADER_TIMEOUT));
        let _ = conn.SetReadDeadline(dl);

        let (req, err) = {
            let mut br = bufio::NewReader(&mut conn);
            ReadRequest(&mut br)
        };
        if !err.IsNil() {
            // EOF, parse error, or idle timeout — all close the conn.
            let _ = conn.Close();
            return;
        }
        // Clear the deadline once headers are parsed. The handler can
        // re-arm via Conn methods if it cares about body-read timeouts.
        let _ = conn.SetReadDeadline(time::Time::default());

        let keep_alive = request_keep_alive(&req);
        let mut w = ResponseWriter::new(conn);
        w.__set_keep_alive(keep_alive);
        handler.ServeHTTP(&mut w, &req);
        conn = w.__take_conn();

        if !keep_alive {
            let _ = conn.Close();
            return;
        }
    }
}

/// Decide whether to keep the connection alive after this request.
/// Mirrors Go's `Request.shouldClose()` (request.go:1450) inverted.
///
/// HTTP/1.1: keep-alive default; `Connection: close` opts out.
/// HTTP/1.0: close default; `Connection: keep-alive` opts in.
fn request_keep_alive(req: &Request) -> bool {
    let conn_hdr = req.Header.Get(string("Connection"));
    let conn_bytes = conn_hdr.as_bytes();
    let says_close = ascii_eq_ignore_case(conn_bytes, b"close");
    let says_keep_alive = ascii_eq_ignore_case(conn_bytes, b"keep-alive");
    if req.ProtoMajor == 1 && req.ProtoMinor >= 1 {
        !says_close
    } else {
        says_keep_alive
    }
}

fn ascii_eq_ignore_case(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    for i in 0..a.len() {
        let x = a[i] | 0x20;
        let y = b[i] | 0x20;
        if x != y {
            return false;
        }
    }
    true
}
