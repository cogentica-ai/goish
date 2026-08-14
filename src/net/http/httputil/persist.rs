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

    // go: sdk 1.25.5 net/http/httputil/persist.go:17-26 ErrPersistEOF
    /// Go: "a ProtocolError […] the remote requested that this be the
    /// last request serviced."
    pub ErrPersistEOF: error = "persistent connection closed";

    // go: sdk 1.25.5 net/http/httputil/persist.go:17-26 ErrPipeline
    /// Go: returned by Read when the request was never written, so
    /// there is no pipeline slot to read a response into.
    pub ErrPipeline: error = "pipeline error";
}

// go: none — goish-only: Go keys `pipereq` by the `*http.Request`
// pointer. goish has no pointer-keyed map, so the address is the key —
// same identity, and the same requirement that Read be handed the very
// same Request value Write was.
fn __req_key(req: &super::super::request::Request) -> crate::types::uint {
    return req as *const super::super::request::Request as crate::types::uint;
}

// go: sdk 1.25.5 net/http/httputil/persist.go:37-47 ServerConn
// goishlint:ignore GOISH019 ServerConn — Go's struct carries `re`/`we`
// (read/write errors), `lastbody`, and `pipe textproto.Pipeline`,
// which belong to the Read/Write half this type does not port. (An
// earlier note here said "goish has no textproto.Pipeline at all".
// It does — src/net/textproto/pipeline.rs, all five methods — and the
// ClientConn half below now uses it.)
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
    /// Go's `re error` — a sticky READ-side error. Once set, every
    /// later Read returns it rather than touching the conn.
    re: error,
    /// Go's `we error` — the same for the write side.
    we: error,
    /// Go's `pipereq map[*http.Request]uint`, which correlates a Read
    /// with the pipeline id its Write took. Go keys it by request
    /// POINTER; goish keys by the request's address, which is the same
    /// identity written differently — a caller must pass Read the very
    /// same Request value it passed Write, exactly as in Go.
    pipereq: crate::gomap::map<crate::types::uint, u64>,
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
            re: errors::nil,
            we: errors::nil,
            pipereq: crate::gomap::map::new(),
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
    /// Go's `pipe textproto.Pipeline` — the request/response
    /// sequencer that makes pipelined use safe.
    pipe: crate::net::textproto::Pipeline,
}

// go: sdk 1.25.5 net/http/httputil/persist.go:248-258 NewClientConn
pub fn NewClientConn(c: net::TCPConn, r: Option<crate::bufio::Reader<net::TCPConn>>) -> ClientConn {
    let _ = r;
    return ClientConn {
        state: crate::sync::Mutex::new(connState {
            c: Some(c),
            nread: 0,
            nwritten: 0,
            re: errors::nil,
            we: errors::nil,
            pipereq: crate::gomap::map::new(),
        }),
        proxy: false,
        pipe: crate::net::textproto::Pipeline::new(),
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

    // go: sdk 1.25.5 net/http/httputil/persist.go:299-350 ClientConn.Write
    /// Go: "Write writes a request. An [ErrPersistEOF] error is
    /// returned if the connection has been closed in an HTTP
    /// keep-alive sense."
    ///
    /// The pipeline bookkeeping is the reason this is not just
    /// `req.Write(conn)`: the id taken here is what a later Read uses
    /// to wait its turn, and on a write FAILURE the response slot is
    /// opened and closed immediately so a pipelined reader behind this
    /// one is not stranded waiting for a response that will never come.
    pub fn Write(&self, req: &super::super::request::Request) -> error {
        let id = self.pipe.Next();
        self.pipe.StartRequest(id);

        // Go's deferred half, run on every exit path below.
        let finish = |ok: bool| {
            self.pipe.EndRequest(id);
            if !ok {
                self.pipe.StartResponse(id);
                self.pipe.EndResponse(id);
            } else {
                // Go: "Remember the pipeline id of this request".
                let mut st = self.state.Lock();
                st.pipereq.Set(__req_key(req), id);
            }
        };

        let mut c = {
            let mut st = self.state.Lock();
            // Go: "no point sending if read-side closed or broken".
            if !st.re.IsNil() {
                let e = st.re.clone();
                drop(st);
                finish(false);
                return e;
            }
            if !st.we.IsNil() {
                let e = st.we.clone();
                drop(st);
                finish(false);
                return e;
            }
            if st.c.is_none() {
                // Go: "connection closed by user in the meantime".
                drop(st);
                finish(false);
                return errClosed.into();
            }
            if req.Close {
                // Go: "We write the EOF to the write-side error,
                // because there still might be some pipelined reads".
                st.we = ErrPersistEOF.into();
            }
            st.c.take().unwrap()
        };

        let err = if self.proxy {
            req.WriteProxy(&mut c)
        } else {
            req.Write(&mut c)
        };

        let mut st = self.state.Lock();
        st.c = Some(c);
        if !err.IsNil() {
            st.we = err.clone();
            drop(st);
            finish(false);
            return err;
        }
        st.nwritten += 1;
        drop(st);
        finish(true);
        return errors::nil;
    }

    // go: sdk 1.25.5 net/http/httputil/persist.go:363-422 ClientConn.Read
    /// Go: "Read reads the next response from the wire. A valid
    /// response might be returned together with an [ErrPersistEOF],
    /// which means that the remote requested that this be the last
    /// request serviced."
    ///
    /// `ErrPipeline` when the request was never written is not a
    /// technicality: without a pipeline slot there is no way to know
    /// WHICH response on the wire belongs to this caller.
    pub fn Read(
        &self,
        req: &super::super::request::Request,
    ) -> (super::super::response::Response, error) {
        // Go: retrieve and delete the pipeline id for this request.
        let id = {
            let mut st = self.state.Lock();
            let key = __req_key(req);
            let (id, ok) = st.pipereq.Get(key);
            st.pipereq.Delete(key);
            if !ok {
                return (
                    super::super::response::Response::default(),
                    ErrPipeline.into(),
                );
            }
            id
        };

        // Go: "Ensure pipeline order".
        self.pipe.StartResponse(id);

        let mut c = {
            // ONE lock for the whole check-and-take. goish's Mutex is
            // not reentrant, and taking it twice here deadlocks the
            // goroutine — which is a hang, not an error.
            let mut st = self.state.Lock();
            if !st.re.IsNil() {
                let e = st.re.clone();
                drop(st);
                self.pipe.EndResponse(id);
                return (super::super::response::Response::default(), e);
            }
            if st.c.is_none() {
                drop(st);
                self.pipe.EndResponse(id);
                return (
                    super::super::response::Response::default(),
                    errClosed.into(),
                );
            }
            st.c.take().unwrap()
        };
        // Go drains `lastbody` here so an unread body does not desync
        // the next response. goish's ReadResponse reads the body as
        // part of the response, so there is never a remainder on the
        // wire to drain.

        let mut br = crate::bufio::NewReader(&mut c);
        let (resp, err) = super::super::response::ReadResponse(&mut br, Some(req.clone()));
        drop(br);

        let mut st = self.state.Lock();
        st.c = Some(c);
        if !err.IsNil() {
            st.re = err.clone();
            drop(st);
            self.pipe.EndResponse(id);
            return (resp, err);
        }
        st.nread += 1;
        if resp.Close {
            // Go: "don't send any more requests".
            st.re = ErrPersistEOF.into();
            let e = st.re.clone();
            drop(st);
            self.pipe.EndResponse(id);
            return (resp, e);
        }
        drop(st);
        self.pipe.EndResponse(id);
        return (resp, errors::nil);
    }

    // go: sdk 1.25.5 net/http/httputil/persist.go:425-431 ClientConn.Do
    /// Go: "Do is convenience method that writes a request and reads a
    /// response."
    pub fn Do(
        &self,
        req: &super::super::request::Request,
    ) -> (super::super::response::Response, error) {
        let err = self.Write(req);
        if !err.IsNil() {
            return (super::super::response::Response::default(), err);
        }
        return self.Read(req);
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
