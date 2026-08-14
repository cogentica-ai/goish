// net/http/httputil/persist — the deprecated ClientConn / ServerConn
// pipelining API.
//
// PARTIAL port of Go 1.25.5 net/http/httputil/persist.go. Go's own
// header says what this is: "Deprecated: Use the Server in net/http
// instead." It exists because callers still reach for `Hijack` to take
// a connection back off a ServerConn.
//
// What lands: the two structs, their constructors, Hijack, Close and
// Pending. NOT ported — Read/Write/Do, which drive the pipeline and
// need `textproto.Pipeline` plus request/response serialisation over
// a shared conn; and `Pending`'s counters only move once those do.

#![allow(non_snake_case)]

extern crate alloc;


use crate::errors::{self, error};
use crate::net;
use crate::types::int;

crate::var! {
    // go: sdk 1.25.5 net/http/httputil/persist.go:30 errClosed
    pub errClosed: error = "i/o operation on closed connection";
}

// goishlint:ignore GOISH019 ServerConn — Go's struct carries `re`/`we`
// (read/write errors), `lastbody`, and `pipe textproto.Pipeline`, all
// of which belong to the Read/Write half this slice does not port.
// goish has no textproto.Pipeline at all.
// go: sdk 1.25.5 net/http/httputil/persist.go:37-47 ServerConn
/// Go: "ServerConn is an artifact of Go's early HTTP implementation.
/// Deprecated: Use the Server in net/http instead."
pub struct ServerConn {
    state: crate::sync::Mutex<connState>,
}

// go: none — goish-only: the payload of Go's `mu sync.Mutex`, limited
// to the fields this slice ports.
struct connState {
    c: Option<net::TCPConn>,
    nread: int,
    nwritten: int,
}

// go: sdk 1.25.5 net/http/httputil/persist.go:54-59 NewServerConn
/// Go: "NewServerConn is out of date. Use the Server in net/http
/// instead."
///
/// Go takes a `*bufio.Reader` that may be nil and builds one when it
/// is; goish's serve path owns its own buffering, so the reader is not
/// carried here — `Hijack` returns the conn alone.
pub fn NewServerConn(c: net::TCPConn, r: Option<crate::bufio::Reader<net::TCPConn>>) -> ServerConn {
    // Go builds a bufio.Reader when `r` is nil and keeps it for its
    // Read half. goish does not port that half, so the reader is
    // accepted (Go's arity, and callers pass what they have) and
    // dropped — Hijack returns the conn alone. It comes back with Read.
    let _ = r;
    return ServerConn {
        state: crate::sync::Mutex::new(connState {
            c: Some(c),
            nread: 0,
            nwritten: 0,
        }),
    };
}

impl ServerConn {
    // go: sdk 1.25.5 net/http/httputil/persist.go:65-73 ServerConn.Hijack
    /// Go: "Hijack detaches the ServerConn and returns the underlying
    /// connection as well as the read-side bufio which may have some
    /// left over data. Hijack may be called before Read has signaled
    /// the end of the keep-alive logic."
    ///
    /// The detach is the point: the ServerConn keeps NO reference
    /// afterwards, so a later Close cannot close a conn the caller now
    /// owns. Returning a clone instead would double-close it.
    pub fn Hijack(&self) -> Option<net::TCPConn> {
        return self.state.Lock().c.take();
    }

    // go: sdk 1.25.5 net/http/httputil/persist.go:76-82 ServerConn.Close
    /// Go: "Close calls Hijack and then also closes the underlying
    /// connection." Close-after-Hijack is therefore a no-op, not an
    /// error — the caller took ownership.
    pub fn Close(&self) -> error {
        if let Some(mut c) = self.Hijack() {
            return crate::io::Closer::Close(&mut c);
        }
        return errors::nil;
    }
}

// goishlint:ignore GOISH019 ClientConn — same omissions as ServerConn,
// plus Go's `writeReq func(*http.Request, io.Writer) error`, the hook
// NewProxyClientConn swaps to write absolute-form request lines.
// go: sdk 1.25.5 net/http/httputil/persist.go:228-246 ClientConn
/// Go: "ClientConn is an artifact of Go's early HTTP implementation.
/// Deprecated: Use Client or Transport in net/http instead."
pub struct ClientConn {
    state: crate::sync::Mutex<connState>,
    /// Go's `writeReq`: `(*Request).Write` normally, or
    /// `(*Request).WriteProxy` for a proxy conn — the difference is
    /// whether the request line carries an absolute URI.
    pub proxy: bool,
}

// go: sdk 1.25.5 net/http/httputil/persist.go:248-258 NewClientConn
pub fn NewClientConn(c: net::TCPConn, r: Option<crate::bufio::Reader<net::TCPConn>>) -> ClientConn {
    let _ = r;
    return ClientConn {
        state: crate::sync::Mutex::new(connState {
            c: Some(c),
            nread: 0,
            nwritten: 0,
        }),
        proxy: false,
    };
}

// go: sdk 1.25.5 net/http/httputil/persist.go:265-269 NewProxyClientConn
/// Go: identical to NewClientConn except that it writes requests in
/// PROXY form — `(*Request).WriteProxy`, i.e. an absolute URI on the
/// request line.
pub fn NewProxyClientConn(
    c: net::TCPConn,
    r: Option<crate::bufio::Reader<net::TCPConn>>,
) -> ClientConn {
    let cc = NewClientConn(c, r);
    return ClientConn { proxy: true, ..cc };
}

impl ClientConn {
    // go: sdk 1.25.5 net/http/httputil/persist.go:275-283 ClientConn.Hijack
    pub fn Hijack(&self) -> Option<net::TCPConn> {
        return self.state.Lock().c.take();
    }

    // go: sdk 1.25.5 net/http/httputil/persist.go:286-292 ClientConn.Close
    pub fn Close(&self) -> error {
        if let Some(mut c) = self.Hijack() {
            return crate::io::Closer::Close(&mut c);
        }
        return errors::nil;
    }

    // go: sdk 1.25.5 net/http/httputil/persist.go:353-357 ClientConn.Pending
    /// Go: "Pending returns the number of unanswered requests that
    /// have been sent on the connection." Always 0 until Read/Write
    /// land and move the counters.
    pub fn Pending(&self) -> int {
        let st = self.state.Lock();
        return st.nwritten - st.nread;
    }
}
