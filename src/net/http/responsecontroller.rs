// go: package net/http
//
// go: file net/http/responsecontroller.go decls: NewResponseController, ResponseController.Flush, ResponseController.Hijack, ResponseController.SetReadDeadline, ResponseController.SetWriteDeadline, ResponseController.EnableFullDuplex, errNotSupported
//
// Go: "A ResponseController is used by an HTTP handler to control the
// response. A ResponseController may not be used after the
// [Handler.ServeHTTP] method has returned."
//
// Each method walks the ResponseWriter chain: try the capability, and
// if the writer does not have it, unwrap and try again, ending in an
// error that matches ErrNotSupported. That walk is the whole point of
// the type — a handler wrapped in three middlewares can still reach the
// real connection underneath.
//
// Go writes four of the five capabilities as ANONYMOUS interfaces
// (`interface{ FlushError() error }`), which Rust has no equivalent
// for. They are declared as named traits below with exactly Go's method
// sets, so a writer opts in the same way and `cast!` finds it. The two
// Go already names — Flusher and Hijacker — are reused from
// response.rs, not redeclared.
//
// goish's own concrete writer implements only Flusher so far. Go's
// `*response` also has FlushError, SetReadDeadline, SetWriteDeadline
// and EnableFullDuplex, but all four are declared in server.go, and
// server.go is not ported yet — putting them here or in response.rs
// would mix two Go files into one Rust file, which GOISH015 exists to
// prevent. They arrive with the server.go port. Until then a handler
// gets ErrNotSupported for them, which is exactly what Go gives for a
// writer that lacks them.

#![allow(non_snake_case)]

extern crate alloc;

use alloc::sync::Arc;

use crate::errors::error;
use crate::time::Time;

use super::response::{Flusher, Hijacker, ResponseWriter};
use crate::net::TCPConn;

/// The writer chain ResponseController walks. Every method takes it by
/// shared reference, so a middleware can hand out its own wrapper and
/// still be unwrapped down to the connection.
type RW = Arc<dyn ResponseWriter + Send + Sync + 'static>;

// go: sdk 1.25.5 net/http/responsecontroller.go:17-19 ResponseController
/// Go: "A ResponseController is used by an HTTP handler to control the
/// response."
pub struct ResponseController {
    rw: RW,
}

// go: sdk 1.25.5 net/http/responsecontroller.go:42-44 rwUnwrapper
/// Go: `interface{ Unwrap() ResponseWriter }`.
///
/// A middleware that wraps a ResponseWriter implements this so the
/// controller can see through it. Without it every wrapper would make
/// Flush and Hijack unavailable to the handler beneath.
#[goish::interface] // goishlint:ignore GOISH022 - `goish::interface`, not `goish::int`
pub trait rwUnwrapper: Send + Sync {
    fn Unwrap(&self) -> RW;
}

// go: none — goish-only: Go spells this `interface{ FlushError() error }`
// inline in ResponseController.Flush. Rust has no anonymous interface,
// so the method set gets a name. Preferred over Flusher when present
// because it can report a write failure instead of swallowing it.
#[goish::interface] // goishlint:ignore GOISH022 - `goish::interface`, not `goish::int`
pub trait FlushErrorer: Send + Sync {
    fn FlushError(&self) -> error;
}

// go: none — goish-only: Go's `interface{ SetReadDeadline(time.Time) error }`.
#[goish::interface] // goishlint:ignore GOISH022 - `goish::interface`, not `goish::int`
pub trait ReadDeadliner: Send + Sync {
    fn SetReadDeadline(&self, deadline: Time) -> error;
}

// go: none — goish-only: Go's `interface{ SetWriteDeadline(time.Time) error }`.
#[goish::interface] // goishlint:ignore GOISH022 - `goish::interface`, not `goish::int`
pub trait WriteDeadliner: Send + Sync {
    fn SetWriteDeadline(&self, deadline: Time) -> error;
}

// go: none — goish-only: Go's `interface{ EnableFullDuplex() error }`.
#[goish::interface] // goishlint:ignore GOISH022 - `goish::interface`, not `goish::int`
pub trait FullDuplexer: Send + Sync {
    fn EnableFullDuplex(&self) -> error;
}

// go: sdk 1.25.5 net/http/responsecontroller.go:38-40 NewResponseController
/// Go: "NewResponseController creates a [ResponseController] for a
/// request. The ResponseWriter should be the original value passed to
/// the [Handler.ServeHTTP] method, or have an Unwrap method returning
/// the original ResponseWriter. If the ResponseWriter does not support
/// a method, ResponseController returns an error matching
/// [ErrNotSupported]."
pub fn NewResponseController(rw: RW) -> ResponseController {
    return ResponseController { rw };
}

impl ResponseController {
    // go: sdk 1.25.5 net/http/responsecontroller.go:47-62 ResponseController.Flush
    /// Go: "Flush flushes buffered data to the client."
    pub fn Flush(&self) -> error {
        let mut rw = self.rw.clone();
        // The cast borrows `rw` and the unwrap arm reassigns it, so the
        // next writer leaves the inner block as an owned value and the
        // borrow ends with that block. Every exit is a `break`, so the
        // walk has one return.
        let err = loop {
            let next = {
                let r: &(dyn ResponseWriter + Send + Sync + 'static) = &*rw;
                // Go's type switch tries FlushError FIRST, so a writer
                // that has both reports the error rather than dropping it.
                let (fe, ok) = crate::cast!(r, FlushErrorer);
                if ok {
                    break fe.FlushError();
                }
                let (fl, ok) = crate::cast!(r, Flusher);
                if ok {
                    fl.Flush();
                    break crate::errors::nil;
                }
                let (u, ok) = crate::cast!(r, rwUnwrapper);
                if !ok {
                    break errNotSupported();
                }
                u.Unwrap()
            };
            rw = next;
        };
        return err;
    }

    // go: sdk 1.25.5 net/http/responsecontroller.go:66-78 ResponseController.Hijack
    /// Go: "Hijack lets the caller take over the connection. See the
    /// [Hijacker] interface for details."
    ///
    /// Go returns `(net.Conn, *bufio.ReadWriter, error)`; goish's
    /// Hijacker drops the buffered-reader slot, so this follows it —
    /// see the note on Hijacker in response.rs.
    pub fn Hijack(&self) -> (TCPConn, error) {
        let mut rw = self.rw.clone();
        let out = loop {
            let next = {
                let r: &(dyn ResponseWriter + Send + Sync + 'static) = &*rw;
                let (h, ok) = crate::cast!(r, Hijacker);
                if ok {
                    break h.Hijack();
                }
                let (u, ok) = crate::cast!(r, rwUnwrapper);
                if !ok {
                    break (TCPConn::dead(), errNotSupported());
                }
                u.Unwrap()
            };
            rw = next;
        };
        return out;
    }

    // go: sdk 1.25.5 net/http/responsecontroller.go:85-97 ResponseController.SetReadDeadline
    /// Go: "SetReadDeadline sets the deadline for reading the entire
    /// request, including the body. A zero value means no deadline.
    /// Setting the read deadline after it has been exceeded will not
    /// extend it."
    pub fn SetReadDeadline(&self, deadline: Time) -> error {
        let mut rw = self.rw.clone();
        let err = loop {
            let next = {
                let r: &(dyn ResponseWriter + Send + Sync + 'static) = &*rw;
                let (d, ok) = crate::cast!(r, ReadDeadliner);
                if ok {
                    break d.SetReadDeadline(deadline);
                }
                let (u, ok) = crate::cast!(r, rwUnwrapper);
                if !ok {
                    break errNotSupported();
                }
                u.Unwrap()
            };
            rw = next;
        };
        return err;
    }

    // go: sdk 1.25.5 net/http/responsecontroller.go:105-117 ResponseController.SetWriteDeadline
    /// Go: "SetWriteDeadline sets the deadline for writing the
    /// response. Writes to the response body after the deadline has
    /// been exceeded will not block, but may succeed if the data has
    /// been buffered. A zero value means no deadline."
    pub fn SetWriteDeadline(&self, deadline: Time) -> error {
        let mut rw = self.rw.clone();
        let err = loop {
            let next = {
                let r: &(dyn ResponseWriter + Send + Sync + 'static) = &*rw;
                let (d, ok) = crate::cast!(r, WriteDeadliner);
                if ok {
                    break d.SetWriteDeadline(deadline);
                }
                let (u, ok) = crate::cast!(r, rwUnwrapper);
                if !ok {
                    break errNotSupported();
                }
                u.Unwrap()
            };
            rw = next;
        };
        return err;
    }

    // go: sdk 1.25.5 net/http/responsecontroller.go:129-141 ResponseController.EnableFullDuplex
    /// Go: "EnableFullDuplex indicates that the request handler will
    /// interleave reads from [Request.Body] with writes to the
    /// [ResponseWriter]. For HTTP/1 requests, the Go HTTP server by
    /// default consumes any unread portion of the request body before
    /// beginning to write the response; calling EnableFullDuplex
    /// disables this."
    pub fn EnableFullDuplex(&self) -> error {
        let mut rw = self.rw.clone();
        let err = loop {
            let next = {
                let r: &(dyn ResponseWriter + Send + Sync + 'static) = &*rw;
                let (d, ok) = crate::cast!(r, FullDuplexer);
                if ok {
                    break d.EnableFullDuplex();
                }
                let (u, ok) = crate::cast!(r, rwUnwrapper);
                if !ok {
                    break errNotSupported();
                }
                u.Unwrap()
            };
            rw = next;
        };
        return err;
    }
}

// go: sdk 1.25.5 net/http/responsecontroller.go:145-147 errNotSupported
/// Go: "errNotSupported returns an error that Is ErrNotSupported, but
/// is not == to it."
///
/// The distinction is deliberate on Go's part and is preserved here:
/// `fmt.Errorf("%w", ErrNotSupported)` wraps the sentinel so
/// errors::Is matches while `==` does not, which stops callers from
/// depending on identity.
fn errNotSupported() -> error {
    // `var!` yields a marker type, not an `error`; %w needs the value.
    let sentinel: error = super::ErrNotSupported.into();
    return crate::fmt::Errorf!("%w", sentinel);
}
