// go: file net/http/pprof/pprof.go decls: Cmdline, sleep, configureWriteDeadline, serveError
//
// net/http/pprof — the HTTP surface of the runtime profiler.
//
// PARTIAL, and the split is by DEPENDENCY, not by difficulty. What
// lands here is everything that needs only net/http itself:
//
//   * `Cmdline` — the process argv, NUL-separated.
//   * `serveError` — the package's error response shape.
//   * `sleep` — the profile duration wait, cancellable by the request.
//   * `configureWriteDeadline` — the reason a 30-second profile is not
//     cut off by the server's WriteTimeout. It reads the *Server back
//     out of the request context, which only became possible when
//     `ServerContextKey` was ported.
//
// NOT ported, each with the package it actually needs:
//
//   * `Index`, `Handler`, `handler.ServeHTTP`, `collectProfile`,
//     `serveDeltaProfile` — `runtime/pprof` (Lookup, WriteTo,
//     Profile), which goish does not have.
//   * `Profile` — `runtime/pprof.StartCPUProfile`.
//   * `Trace` — `runtime/trace`.
//   * `indexTmplExecute` — `html/template`; Go generates it from
//     index.html at `go generate` time.
//   * `serveDeltaProfile` also needs `internal/profile` for the
//     profile-subtraction step.
//
// An earlier note called the whole package blocked on those three.
// That was true of the package and false of four of its thirteen
// declarations, which is the same mistake this port keeps making.

#![allow(non_snake_case)]

extern crate alloc;

use crate::errors::error;
use crate::goslice::slice;
use crate::string;
use crate::types::{float64, int};

use super::super::request::Request;
use super::super::responsewriter::ResponseWriter;

// go: sdk 1.25.5 net/http/pprof/pprof.go:110-114 Cmdline
/// Go: "Cmdline responds with the running program's command line,
/// with arguments separated by NUL bytes."
///
/// `X-Content-Type-Options: nosniff` is on every handler in this
/// package and is not decoration — profile output is attacker-
/// influenced in the sense that it contains program data, and a
/// browser sniffing it as HTML would run it.
pub fn Cmdline(w: &(dyn ResponseWriter + Send + Sync + 'static), _r: &Request) {
    w.Header().Set(
        string("X-Content-Type-Options"),
        string("nosniff"),
    );
    w.Header().Set(
        string("Content-Type"),
        string("text/plain; charset=utf-8"),
    );
    let _ = w.Write(crate::convert::bytes(crate::strings::Join(
        crate::os::Args(),
        string("\x00"),
    )));
    return;
}

// go: sdk 1.25.5 net/http/pprof/pprof.go:116-121 sleep
/// Wait `d`, or until the request is cancelled — whichever comes
/// first. A profile that ignored the second half would keep running
/// after the client hung up.
pub fn sleep(r: &Request, d: crate::time::Duration) {
    let done = r.Context().Done();
    let after = crate::time::After(d);
    crate::select! {
        let _ = after.Recv() => {},
        let _ = done.Recv() => {},
    }
    return;
}

// go: sdk 1.25.5 net/http/pprof/pprof.go:123-131 configureWriteDeadline
/// Extend this response's write deadline to cover the profile.
///
/// Without it a `Server.WriteTimeout` of, say, 10 seconds truncates
/// every 30-second profile at 10 — the handler is not stuck, it is
/// working as asked, and the timeout cannot tell the difference. The
/// server is reached through `ServerContextKey`, which is why this
/// could not be ported before that key existed.
pub fn configureWriteDeadline(
    w: &(dyn ResponseWriter + Send + Sync + 'static),
    r: &Request,
    seconds: float64,
) {
    let v = match r.Context().Value(super::super::server::ServerContextKey) {
        None => {
            return;
        }
        Some(v) => v,
    };
    let srv = match v.downcast_ref::<alloc::sync::Arc<super::super::server::Server>>() {
        None => {
            return;
        }
        Some(s) => s.clone(),
    };
    if srv.WriteTimeout.0 > 0 {
        // Go: `srv.WriteTimeout + time.Duration(seconds*float64(time.Second))`
        let extra = crate::int64(seconds * crate::float64(crate::time::Second.0));
        let timeout = crate::time::Duration(srv.WriteTimeout.0 + extra);
        let rc = super::super::responsecontroller::NewResponseController(__rw_arc(w));
        let _ = rc.SetWriteDeadline(crate::time::Now().Add(timeout));
    }
    return;
}

// go: none — goish-only: `NewResponseController` takes an owned
// `Arc<dyn ResponseWriter>` because a ResponseController outlives the
// call that built it. A handler is handed a borrow, so the borrow is
// re-wrapped in a non-owning Arc whose only job is to satisfy that
// signature for the duration of this call.
fn __rw_arc(
    w: &(dyn ResponseWriter + Send + Sync + 'static),
) -> alloc::sync::Arc<dyn ResponseWriter + Send + Sync + 'static> {
    struct Borrowed(*const (dyn ResponseWriter + Send + Sync + 'static));
    // SAFETY: the Arc never escapes `configureWriteDeadline`, which
    // borrows `w` for its whole body, so the pointer cannot dangle.
    unsafe impl Send for Borrowed {}
    unsafe impl Sync for Borrowed {}
    impl ResponseWriter for Borrowed {
        // go: none — goish-only: forwarding shim, see __rw_arc.
        fn Header(&self) -> super::super::responsewriter::HeaderHandle {
            return unsafe { (*self.0).Header() };
        }
        // go: none — goish-only: forwarding shim, see __rw_arc.
        fn Write(&self, p: slice<crate::types::byte>) -> (int, error) {
            return unsafe { (*self.0).Write(p) };
        }
        // go: none — goish-only: forwarding shim, see __rw_arc.
        fn WriteHeader(&self, statusCode: int) {
            unsafe { (*self.0).WriteHeader(statusCode) }
        }
        // go: none — goish-only: forwarding shim, see __rw_arc.
        fn __goish_as_dyn_any(&self) -> Option<&(dyn core::any::Any + Send + Sync)> {
            // The controller's capability walk must see through to the
            // real writer, not to this shim.
            return unsafe { (*self.0).__goish_as_dyn_any() };
        }
    }
    return alloc::sync::Arc::new(Borrowed(w as *const _));
}

// go: sdk 1.25.5 net/http/pprof/pprof.go:133-139 serveError
/// The package's error shape. `X-Go-Pprof: 1` is how the pprof CLIENT
/// recognises an error coming from this handler rather than from a
/// proxy in between, and the `Content-Disposition` DELETE matters
/// because the success path sets one — leaving it on an error would
/// have the browser save the error text as a .pprof file.
pub fn serveError(
    w: &(dyn ResponseWriter + Send + Sync + 'static),
    status: int,
    txt: string,
) {
    w.Header().Set(
        string("Content-Type"),
        string("text/plain; charset=utf-8"),
    );
    w.Header().Set(string("X-Go-Pprof"), string("1"));
    w.Header().Del(string("Content-Disposition"));
    w.WriteHeader(status);
    // Go: fmt.Fprintln — the newline is part of the response.
    let _ = w.Write(crate::convert::bytes(txt + string("\n")));
    return;
}
