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

/// One-shot connection handler. Reads a single request, dispatches
/// to `handler`, sends the response, closes the conn. No keep-alive
/// in v1.
fn serve_conn(mut conn: net::Conn, handler: Arc<dyn Handler>) {
    let req = {
        // Borrow the conn for the parser; releases on scope exit so
        // the same conn can be moved into ResponseWriter below.
        let mut br = bufio::NewReader(&mut conn);
        let (req, err) = ReadRequest(&mut br);
        if !err.IsNil() {
            let _ = conn.Close();
            return;
        }
        req
    };
    let mut w = ResponseWriter::new(conn);
    handler.ServeHTTP(&mut w, &req);
    let _ = w.close_conn();
}
