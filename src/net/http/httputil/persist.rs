// net/http/httputil/persist — the deprecated ClientConn / ServerConn
// pipelining API.
//
// Port of Go 1.25.5 net/http/httputil/persist.go. Go's own header
// says what this is: "Deprecated: Use the Server in net/http instead."
// It exists because callers still reach for `Hijack` to take a
// connection back off a ServerConn.
//
// Every declaration in the file lands: both structs, their
// constructors, Hijack, Close, and both pipelined halves — ClientConn
// Write/Read/Do/Pending and ServerConn Read/Pending/Write. The server
// half was the last of it, and the counters only became meaningful
// with it: before, `Pending` had nothing to count.
//
// goishlint:ignore GOISH019 ServerConn — the ten Go fields are guarded
// by its `mu` and are reached only under it, so they live in one
// `state` behind a goish Mutex rather than beside a bare `sync.Mutex`
// field, with `pipe` beside it as in ClientConn.

#![allow(non_snake_case)]

extern crate alloc;

use alloc::sync::Arc;
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

    // go: sdk 1.25.5 net/http/httputil/persist.go:17-26 ErrClosed
    /// Go: "connection closed by user" — the EXPORTED one, distinct
    /// from `errClosed` above. Go returns this from exactly one of the
    /// four closed-conn sites (ServerConn.Write, persist.go line 198)
    /// and `errClosed` from the other three. The asymmetry is Go's;
    /// reproducing it is the point of a port.
    pub ErrClosed: error = "connection closed by user";

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
// goishlint:ignore GOISH019 ServerConn — Go's `re`/`we` (sticky
// read/write errors) live in `state`, and `pipe` beside it. Go's
// `lastbody` has no counterpart: it exists to close a body the caller
// left unread, and goish's ReadRequest consumes the body before it
// returns, so there is never one outstanding. (Two earlier notes here
// were wrong in turn: that goish has no textproto.Pipeline — it has,
// all five methods — and that Read/Write are unported. Both are.)
/// Go: "ServerConn is an artifact of Go's early HTTP implementation.
/// Deprecated: Use the Server in net/http instead."
pub struct ServerConn {
    state: crate::sync::Mutex<connState>,
    /// Go's `pipe textproto.Pipeline` — the request/response
    /// sequencer that keeps a pipelined Write behind the Read that
    /// produced its request.
    pipe: crate::net::textproto::Pipeline,
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
    // Go builds a bufio.Reader when `r` is nil and keeps it across
    // calls, because its ReadRequest can leave an unread body on the
    // wire. goish's ReadRequest consumes the body before it returns
    // (request.rs: "the reader is positioned at the first byte after
    // the final CRLF of the request body"), so nothing is buffered
    // between Reads and each Read wraps the conn afresh. The argument
    // is still accepted for Go's arity, and dropped. Same reasoning
    // as ClientConn.Read below, which drains no `lastbody` either.
    let _ = r;
    return ServerConn {
        pipe: crate::net::textproto::Pipeline::new(),
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

    // go: sdk 1.25.5 net/http/httputil/persist.go:88-162 ServerConn.Read
    /// Go: "Read returns the next request on the wire. An
    /// [ErrPersistEOF] is returned if it is gracefully determined that
    /// there are no more requests (e.g. after the first request on an
    /// HTTP/1.0 connection, or after a Connection:close on a HTTP/1.1
    /// connection)."
    ///
    /// Returns `Arc<Request>` where Go returns `*http.Request`, and
    /// the pointer is the whole point: `Write` finds this request's
    /// pipeline slot by IDENTITY, and here the callee allocates it.
    /// ClientConn takes a plain `&Request` because there the caller
    /// owns the value across both calls. The asymmetry is Go's — one
    /// direction hands you a pointer, the other borrows yours.
    pub fn Read(&self) -> (Arc<super::super::request::Request>, error) {
        // Go: "Ensure ordered execution of Reads and Writes."
        let id = self.pipe.Next();
        self.pipe.StartRequest(id);

        // Go does this in a defer, which also burns the RESPONSE slot
        // when no request came back — otherwise a Write that never
        // happens leaves every later response waiting on this id.
        // goish has no defer, so both exits are spelled out.
        let end_dead = || {
            self.pipe.EndRequest(id);
            self.pipe.StartResponse(id);
            self.pipe.EndResponse(id);
        };

        let mut c = {
            // ONE lock for the whole check-and-take: goish's Mutex is
            // not reentrant, so taking it twice here hangs rather than
            // errors. Same care as ClientConn.Read below.
            let mut st = self.state.Lock();
            // Go: "no point receiving if write-side broken or closed".
            if !st.we.IsNil() {
                let e = st.we.clone();
                drop(st);
                end_dead();
                return (Arc::new(Default::default()), e);
            }
            if !st.re.IsNil() {
                let e = st.re.clone();
                drop(st);
                end_dead();
                return (Arc::new(Default::default()), e);
            }
            // Go tests `sc.r == nil` — its reader, cleared by Hijack.
            // goish keeps no reader (see NewServerConn), so the conn
            // being gone is the same "closed by user in the meantime".
            if st.c.is_none() {
                drop(st);
                end_dead();
                return (Arc::new(Default::default()), errClosed.into());
            }
            st.c.take().unwrap()
        };

        // Go closes `lastbody` here so an unread body cannot desync
        // the next request. goish's ReadRequest consumes the body, so
        // there is no remainder to drain and no lastbody to keep.
        let mut br = crate::bufio::NewReader(&mut c);
        let (req, err) = super::super::request::ReadRequest(&mut br);
        drop(br);

        let mut st = self.state.Lock();
        st.c = Some(c);
        if !err.IsNil() {
            if errors::Is(err.clone(), crate::io::ErrUnexpectedEOF) {
                // Go: "A close from the opposing client is treated as
                // a graceful close, even if there was some
                // unparse-able data before the close."
                st.re = ErrPersistEOF.into();
                let e = st.re.clone();
                drop(st);
                end_dead();
                return (Arc::new(Default::default()), e);
            }
            st.re = err.clone();
            drop(st);
            end_dead();
            return (Arc::new(Default::default()), err);
        }

        st.nread += 1;
        let close = req.Close;
        let arc = Arc::new(req);
        // Go's defer: "Remember the pipeline id of this request." The
        // key is the identity Write will present.
        st.pipereq
            .Set(Arc::as_ptr(&arc) as crate::types::uint, id);
        if close {
            st.re = ErrPersistEOF.into();
            let e = st.re.clone();
            drop(st);
            self.pipe.EndRequest(id);
            return (arc, e);
        }
        drop(st);
        self.pipe.EndRequest(id);
        return (arc, errors::nil);
    }

    // go: sdk 1.25.5 net/http/httputil/persist.go:166-170 ServerConn.Pending
    /// Go: "Pending returns the number of unanswered requests that
    /// have been received on the connection."
    pub fn Pending(&self) -> int {
        let st = self.state.Lock();
        return st.nread - st.nwritten;
    }

    // go: sdk 1.25.5 net/http/httputil/persist.go:175-223 ServerConn.Write
    /// Go: "Write writes resp in response to req. To close the
    /// connection gracefully, set the Response.Close field to true.
    /// Write should be considered operational until it returns an
    /// error, regardless of any errors returned on the
    /// [ServerConn.Read] side."
    ///
    /// Takes the `Arc<Request>` Read handed out; any other value is a
    /// request this conn never read, and Go's answer to that is
    /// ErrPipeline, not a guess at which response slot was meant.
    pub fn Write(
        &self,
        req: &Arc<super::super::request::Request>,
        resp: &super::super::response::Response,
    ) -> error {
        // Go: "Retrieve the pipeline ID of this request/response pair."
        let id = {
            let mut st = self.state.Lock();
            let key = Arc::as_ptr(req) as crate::types::uint;
            let (id, ok) = st.pipereq.Get(key);
            st.pipereq.Delete(key);
            if !ok {
                return ErrPipeline.into();
            }
            id
        };

        // Go: "Ensure pipeline order."
        self.pipe.StartResponse(id);

        let mut c = {
            let mut st = self.state.Lock();
            if !st.we.IsNil() {
                let e = st.we.clone();
                drop(st);
                self.pipe.EndResponse(id);
                return e;
            }
            if st.c.is_none() {
                drop(st);
                self.pipe.EndResponse(id);
                // The EXPORTED ErrClosed, and only here: Go returns
                // `errClosed` from the other three closed-conn sites
                // (persist.go lines 119, 329, 385) and this one alone
                // returns ErrClosed. Kept as Go has it.
                return ErrClosed.into();
            }
            if st.nread <= st.nwritten {
                drop(st);
                self.pipe.EndResponse(id);
                return errors::New("persist server pipe count");
            }
            if resp.Close {
                // Go: "After signaling a keep-alive close, any
                // pipelined unread requests will be lost. It is up to
                // the user to drain them before signaling."
                st.re = ErrPersistEOF.into();
            }
            st.c.take().unwrap()
        };

        let err = resp.Write(&mut c);

        let mut st = self.state.Lock();
        st.c = Some(c);
        if !err.IsNil() {
            st.we = err.clone();
            drop(st);
            self.pipe.EndResponse(id);
            return err;
        }
        st.nwritten += 1;
        drop(st);
        self.pipe.EndResponse(id);
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
