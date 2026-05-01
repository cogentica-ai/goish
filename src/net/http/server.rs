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
use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use crate::bufio;
use crate::errors::{self, error};
use crate::go;
use crate::io::Closer;
use crate::net;
use crate::string;
use crate::sync::Mutex;
use crate::time;

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

// ─── Server ──────────────────────────────────────────────────────────

/// `http.Server` (server.go:2993). v1 subset of fields; the rest
/// (TLSConfig, ConnState, BaseContext, etc.) is deferred.
///
/// **Construction**: start from `Server::default()` (or
/// `Server::new(handler)`), mutate the public-config fields, then
/// `Arc::new(srv)`. The `..Default::default()` struct-update syntax
/// is unavailable from external crates because internal-state
/// fields are private; the default-and-mutate pattern is
/// equivalent.
///
/// ```ignore
/// let mut srv = http::Server::default();
/// srv.Addr = string(":8080");
/// srv.Handler = mux;
/// srv.ReadHeaderTimeout = time::Second * 5;
/// let srv = alloc::sync::Arc::new(srv);
/// let srv2 = srv.clone();
/// go!(stack(64 * KB), move || { let _ = srv2.ListenAndServe(); });
/// // ...
/// let _ = srv.Shutdown(time::Second * 5);
/// ```
pub struct Server {
    /// `host:port` to listen on. Empty = ":80".
    pub Addr: string,
    /// Handler that dispatches requests. Use a `ServeMux` for routing.
    pub Handler: Arc<dyn Handler>,
    /// Maximum duration for the entire request (header + body). Zero
    /// or negative disables. Mirrors `Server.ReadTimeout` (server.go:3015).
    pub ReadTimeout: time::Duration,
    /// Maximum duration to read the request headers. Zero falls back
    /// to `ReadTimeout`. If both are zero/negative, the v1 fallback
    /// `DEFAULT_READ_HEADER_TIMEOUT` (5s) prevents idle keep-alive
    /// conns from pinning goroutines forever — Go has no such
    /// implicit fallback (zero = no timeout) but goish v1 makes it
    /// explicit because there's no signal-driven cleanup yet.
    pub ReadHeaderTimeout: time::Duration,
    /// Maximum duration before timing out writes of the response.
    /// Reset whenever a new request's headers are read. Zero or
    /// negative = no timeout.
    pub WriteTimeout: time::Duration,
    /// Idle keep-alive timeout. Zero falls back to `ReadHeaderTimeout`.
    pub IdleTimeout: time::Duration,
    /// Cap on bytes read parsing the request line + header. Currently
    /// honored at fixed 8 KiB by `ReadRequest`; this field is reserved
    /// for a v2 plumb-through. Zero = use the parser default.
    pub MaxHeaderBytes: crate::types::int,

    // ─── internal state, populated by Default ─────────────────────
    in_shutdown: AtomicBool,
    active_conns: AtomicUsize,
    /// Tracked listener for shutdown. `Mutex<Option<...>>` so the
    /// Serve goroutine can install it on entry and Shutdown can
    /// take it out (close it + wake parked Accept) from another
    /// goroutine. Held inside an `Arc<Listener>` because the Serve
    /// loop also needs read access to call Accept.
    tracked_listener: Mutex<Option<Arc<net::Listener>>>,
}

/// `http.ErrServerClosed` (server.go:36). Returned by `Serve` /
/// `ListenAndServe` after `Shutdown` is called. Cached as a stable
/// sentinel so `errors::Is(err, http::ErrServerClosed())` works the
/// same way Go's `errors.Is(err, http.ErrServerClosed)` does.
pub fn ErrServerClosed() -> error {
    use crate::runtime::spin::SpinLock;
    static SLOT: SpinLock<Option<error>> = SpinLock::new(None);
    let mut g = SLOT.lock();
    if g.is_none() {
        *g = Some(errors::New(string("http: Server closed")));
    }
    g.as_ref().unwrap().clone()
}

/// v1 fallback when both ReadHeaderTimeout and ReadTimeout are zero
/// — bounds idle keep-alive at 5 seconds.
const DEFAULT_READ_HEADER_TIMEOUT_NS: i64 = 5_000_000_000;

impl Default for Server {
    fn default() -> Self {
        Server {
            Addr: string::new(),
            Handler: Arc::new(NotFoundHandler) as Arc<dyn Handler>,
            ReadTimeout: time::Duration(0),
            ReadHeaderTimeout: time::Duration(0),
            WriteTimeout: time::Duration(0),
            IdleTimeout: time::Duration(0),
            MaxHeaderBytes: 0,
            in_shutdown: AtomicBool::new(false),
            active_conns: AtomicUsize::new(0),
            tracked_listener: Mutex::new(None),
        }
    }
}

impl Server {
    /// Convenience constructor — equivalent to `Server::default()` with
    /// `Handler` set to `handler`. Other fields stay at their defaults
    /// (zero timeouts, empty Addr → `:80`).
    pub fn new(handler: Arc<dyn Handler>) -> Self {
        let mut s = Server::default();
        s.Handler = handler;
        s
    }

    /// `(*Server).ListenAndServe` (server.go:3377) — bind to `Addr`
    /// and run the accept loop. Returns ErrServerClosed after a
    /// successful Shutdown, or the underlying network error otherwise.
    pub fn ListenAndServe(self: Arc<Self>) -> error {
        let addr = if self.Addr.Len() == 0 {
            string(":80")
        } else {
            self.Addr.clone()
        };
        let (ln, err) = net::Listen(string("tcp"), addr);
        if !err.IsNil() {
            return err;
        }
        self.Serve(ln)
    }

    /// `(*Server).Serve(l)` (server.go:3433) — accept loop on a
    /// pre-bound Listener. Tracks the listener so `Shutdown` can
    /// break the Accept loop and close the socket.
    pub fn Serve(self: Arc<Self>, ln: net::Listener) -> error {
        let ln = Arc::new(ln);
        // Install tracked_listener and check in_shutdown atomically:
        // hold the listener mutex across both. Without this, a
        // Shutdown call that wins the race against Serve's entry
        // would observe an empty tracked_listener (so __wake_accept
        // and Close run on nothing), and Serve would later install
        // its listener and enter Accept on a fd that was never
        // closed → permanent park.
        {
            let mut tracked = self.tracked_listener.Lock();
            if self.in_shutdown.load(Ordering::Acquire) {
                return ErrServerClosed();
            }
            *tracked = Some(ln.clone());
        }

        loop {
            let (conn, err) = ln.Accept();
            if !err.IsNil() {
                // Whether the error is the kernel's EBADF (we closed
                // the fd) or netpoll's "i/o timeout" (we forced the
                // pd's read deadline expired), we treat it as a
                // graceful shutdown if `in_shutdown` is set.
                if self.in_shutdown.load(Ordering::Acquire) {
                    return ErrServerClosed();
                }
                return err;
            }
            let srv = self.clone();
            // 64 KiB stack — ample for the per-handler chain.
            go!(stack(64 * 1024), move || {
                srv.serve_conn(conn);
            });
        }
    }

    /// `(*Server).Shutdown(timeout)` — graceful shutdown. Closes the
    /// tracked listener (causing Accept to return ErrServerClosed),
    /// then polls active connection count until it reaches zero or
    /// `timeout` elapses. Mirrors Go's `Server.Shutdown(ctx)`
    /// (server.go:3179) with a Duration in place of context.
    ///
    /// `timeout <= 0` waits indefinitely. On timeout, returns
    /// `"shutdown: timeout"`.
    ///
    /// **Drain semantics**: connections currently parked in
    /// ReadRequest waiting for the next keep-alive request will close
    /// once the per-conn ReadHeaderTimeout fires (default 5s). To
    /// drain faster, set `Server.ReadHeaderTimeout` to a smaller value
    /// before invoking Serve.
    pub fn Shutdown(self: Arc<Self>, timeout: time::Duration) -> error {
        // Set the shutdown flag and take the listener under one lock
        // so Serve's mirror-image install/check sees a consistent
        // state. Without this, a Serve that hadn't reached its
        // tracked_listener install yet could install AFTER Shutdown
        // observed None and proceeded — leaving a fd open with no
        // wakeup.
        let listener = {
            let mut tracked = self.tracked_listener.Lock();
            self.in_shutdown.store(true, Ordering::Release);
            tracked.take()
        };

        // Order matters: wake first (so Accept's netpoll::block
        // returns Timedout and the goroutine resumes), then close
        // the fd (so the next Accept4 retry returns EBADF).
        if let Some(ln) = listener {
            ln.__wake_accept();
            let _ = ln.Close();
        }

        // Poll active_conns down to 0. Exponential backoff capped
        // at 100ms (Go's pollIntervalBase doubles to 500ms).
        let deadline_ns = if timeout.0 > 0 {
            crate::runtime::sysmon::monotonic_ns().wrapping_add(timeout.0 as i64)
        } else {
            i64::MAX
        };
        let mut sleep_ns: i64 = 1_000_000; // 1ms
        loop {
            if self.active_conns.load(Ordering::Acquire) == 0 {
                return errors::nil;
            }
            if crate::runtime::sysmon::monotonic_ns() >= deadline_ns {
                return errors::New(string("shutdown: timeout"));
            }
            time::Sleep(time::Duration(sleep_ns));
            sleep_ns = (sleep_ns * 2).min(100_000_000); // cap 100ms
        }
    }

    /// Per-connection serving loop. See keep-alive doc (M27f-β).
    fn serve_conn(self: Arc<Self>, mut conn: net::Conn) {
        // Drop guard ensures active_conns is decremented even if a
        // handler panics or an early return path is taken.
        struct ActiveGuard<'a>(&'a AtomicUsize);
        impl Drop for ActiveGuard<'_> {
            fn drop(&mut self) {
                self.0.fetch_sub(1, Ordering::AcqRel);
            }
        }
        self.active_conns.fetch_add(1, Ordering::AcqRel);
        let _guard = ActiveGuard(&self.active_conns);

        let read_header_ns = self.read_header_timeout_ns();
        let write_timeout_ns = self.write_timeout_ns();

        loop {
            if self.in_shutdown.load(Ordering::Acquire) {
                let _ = conn.Close();
                return;
            }

            // Arm the idle/header read deadline before each request.
            // Cleared after the headers parse so handler body reads
            // aren't artificially capped (large uploads).
            let dl = time::Now().Add(time::Duration(read_header_ns));
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
            // Clear the read deadline once headers are parsed.
            let _ = conn.SetReadDeadline(time::Time::default());
            // Apply WriteTimeout for the response phase if configured.
            if write_timeout_ns > 0 {
                let wdl = time::Now().Add(time::Duration(write_timeout_ns));
                let _ = conn.SetWriteDeadline(wdl);
            }

            let keep_alive = request_keep_alive(&req)
                && !self.in_shutdown.load(Ordering::Acquire);
            let mut w = ResponseWriter::new(conn);
            w.__set_keep_alive(keep_alive);

            // Register a panic-only cleanup that closes the fd if the
            // handler panics. Without this, gogo recovery abandons the
            // ResponseWriter (whose Drop is skipped under panic=abort)
            // and the client hangs on Read forever waiting for data /
            // EOF that never comes. On the success path we unregister
            // BEFORE the cleanup fires, so the fd survives for keep-
            // alive reuse.
            let fd = w.__conn_fd();
            let mut close_node = crate::runtime::sched::cleanup::Cleanup::new(
                close_fd_on_panic,
                fd as usize as *mut (),
            );
            let cur_g = crate::runtime::sched::current_g();
            if let Some(g_ptr) = cur_g {
                unsafe {
                    crate::runtime::sched::cleanup::register(
                        &*g_ptr.as_ptr(),
                        &mut close_node,
                    );
                }
            }
            self.Handler.ServeHTTP(&mut w, &req);
            // Handler returned normally — unregister BEFORE __take_conn
            // so the cleanup is gone before we move conn out.
            if let Some(g_ptr) = cur_g {
                unsafe {
                    crate::runtime::sched::cleanup::unregister(
                        &*g_ptr.as_ptr(),
                        &mut close_node,
                    );
                }
            }
            conn = w.__take_conn();

            if write_timeout_ns > 0 {
                let _ = conn.SetWriteDeadline(time::Time::default());
            }

            if !keep_alive {
                let _ = conn.Close();
                return;
            }
        }
    }

    /// Resolve effective read-header timeout: `ReadHeaderTimeout` if
    /// set, else `ReadTimeout`, else the v1 default (5s).
    fn read_header_timeout_ns(&self) -> i64 {
        if self.ReadHeaderTimeout.0 > 0 {
            self.ReadHeaderTimeout.0 as i64
        } else if self.ReadTimeout.0 > 0 {
            self.ReadTimeout.0 as i64
        } else {
            DEFAULT_READ_HEADER_TIMEOUT_NS
        }
    }

    fn write_timeout_ns(&self) -> i64 {
        if self.WriteTimeout.0 > 0 {
            self.WriteTimeout.0 as i64
        } else {
            0
        }
    }
}

// ─── Free-function wrappers (Go-faithful one-liners) ─────────────────

/// `http.ListenAndServe(addr, handler)` — bind + accept loop +
/// goroutine-per-connection dispatch. Blocks until the server is
/// shut down (returns ErrServerClosed) or the underlying Listen
/// fails.
///
/// Mirrors Go's `func ListenAndServe(addr string, handler Handler) error`
/// (server.go:3702). For per-server config (timeouts, shutdown), use
/// `http::Server` directly.
pub fn ListenAndServe(addr: string, handler: Arc<dyn Handler>) -> error {
    let srv = Arc::new(Server {
        Addr: addr,
        Handler: handler,
        ..Default::default()
    });
    srv.ListenAndServe()
}

/// `http.Serve(l, handler)` — accept loop on a pre-bound Listener.
/// Mirrors Go's `func Serve(l net.Listener, handler Handler) error`
/// (server.go:3676). For per-server config / shutdown, use
/// `http::Server::Serve`.
pub fn Serve(ln: net::Listener, handler: Arc<dyn Handler>) -> error {
    let srv = Arc::new(Server {
        Handler: handler,
        ..Default::default()
    });
    srv.Serve(ln)
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

/// Cleanup callback invoked by `runtime::sched::cleanup::run_all`
/// when a handler panics with `close_node` registered. Closes the fd
/// so the client sees EOF instead of hanging on Read forever.
unsafe extern "C" fn close_fd_on_panic(fd_arg: *mut ()) {
    let fd = fd_arg as usize as i32;
    if fd >= 0 {
        let _ = crate::syscall::Close(fd);
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
