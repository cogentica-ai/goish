// net/http/fcgi/child.go — FastCGI from the perspective of a child
// process (the application side of the protocol).
//
// Ported here: the parameter-decoding half — `request`, `newRequest`,
// `parseParams` — plus the two pure environment predicates
// `addFastCGIEnvToContext` and `filterOutUsedEnvVars`.
//
// NOT ported, with the reason MEASURED rather than assumed:
//
//   * `child`, `newChild`, `serve`, `handleRecord`, `serveRequest`,
//     `cleanUp`, `Serve`, and `response` with its methods — the
//     connection serve loop.
//
//     Every SYMBOL it needs is present: io::Pipe (io/pipe.rs:341),
//     PipeWriter::CloseWithError (:313), io::CopyN (io/mod.rs:686),
//     io::DiscardWriter (:394), cgi::RequestFromMap, beginRequest::read,
//     roleResponder / statusUnknownRole / statusRequestComplete. An
//     earlier draft of this comment said io.Pipe was missing; it was
//     not, and one grep would have said so.
//
//     **The blocker is the conn's lock discipline, and it is real.**
//     Go's `serve()` reads the transport with `rec.read(c.conn.rwc)`
//     WITHOUT taking `c.conn.mutex` — the mutex guards writes only
//     (fcgi.go:151-153). Meanwhile `serveRequest` runs on its own
//     goroutine and calls `writeRecord`, which does take it. So Go has
//     a blocking read and a concurrent write on one transport.
//
//     goish's `rwc` lives INSIDE `Mutex<connState>`, so a read method
//     would hold that lock across a blocking read, and any handler
//     writing its response would park until the next record arrived —
//     a deadlock in the ordinary case, where the handler replies
//     before the peer sends anything more. Rust also cannot borrow one
//     `Box<dyn ReadWriteCloser>` mutably twice, so the read and write
//     halves must become separate handles: either split at
//     construction, or take a Clone/Arc transport the way net::Conn is
//     shared. That is a design decision about this package's
//     concurrency, not a transcription, and it wants a session with
//     room to test it rather than a tail-end guess.
//   * `ProcessEnv` / `envVarsContextKey` — need a context Value keyed
//     by a private type.

#![allow(non_snake_case)]

extern crate alloc;

#[allow(unused_imports)] // used by the `var!` expansion below
use crate::errors::error;
use crate::gomap::map;
use crate::goslice::slice;
use crate::string;
use crate::strings;
use crate::types::{byte, uint16, uint8};

use super::fcgi::{flagKeepConn, readSize, readString};

// goishlint:ignore GOISH019 request — Go's `pw *io.PipeWriter` is
// replaced by `body slice<byte>`: goish's http.Request carries its
// body as bytes, so the handler cannot run until the body is
// complete and there is no pipe to hold. Its `buf [1024]byte` inline
// arena is a slice here for the same reason it is elsewhere.
// go: sdk 1.25.5 net/http/fcgi/child.go:24-32 request
//
/// One in-flight FastCGI request, accumulated across records.
///
/// Go's `buf [1024]byte` with `rawParams = r.buf[:0]` is an inline
/// arena so short param blocks need no allocation; goish grows a
/// slice instead, which is the same observable behaviour. `pw
/// *io.PipeWriter` is omitted with the serve loop above.
#[derive(Clone, Default)]
pub struct request {
    pub reqId: uint16,
    pub params: map<string, string>,
    pub rawParams: slice<byte>,
    pub keepConn: bool,
    /// Go streams the body through `pw *io.PipeWriter` as records
    /// arrive; goish accumulates it here, because the `http.Request`
    /// it will build carries the body as bytes. See the serve-loop
    /// note below.
    pub body: slice<byte>,
}

// goishlint:ignore GOISH019 response — Go embeds `*bufWriter` and
// keeps three plain bools; goish's ResponseWriter methods take `&self`
// so the bools live behind a mutex, and the writer is a named field
// because Rust has no embedding.
// go: sdk 1.25.5 net/http/fcgi/child.go:73-81 response
/// The ResponseWriter a FastCGI child hands its Handler. Writes go
/// out as `typeStdout` records on the FastCGI connection.
pub struct response {
    pub reqId: crate::types::uint16,
    header: alloc::sync::Arc<crate::sync::Mutex<super::super::header::Header>>,
    state: crate::sync::Mutex<responseState>,
    w: crate::sync::Mutex<super::fcgi::bufWriter>,
}

// go: none — goish-only: the three bools Go keeps as plain fields.
// goish's ResponseWriter methods take `&self`, so they live behind a
// mutex; same grouping the plaintext `response` uses.
struct responseState {
    code: crate::types::int,
    wroteHeader: bool,
    wroteCGIHeader: bool,
}

// go: sdk 1.25.5 net/http/fcgi/child.go:83-89 newResponse
pub fn newResponse(c: &alloc::sync::Arc<super::fcgi::conn>, req: &request) -> response {
    return response {
        reqId: req.reqId,
        header: alloc::sync::Arc::new(crate::sync::Mutex::new(
            super::super::header::Header::new(),
        )),
        state: crate::sync::Mutex::new(responseState {
            code: 0,
            wroteHeader: false,
            wroteCGIHeader: false,
        }),
        w: crate::sync::Mutex::new(super::fcgi::newWriter(c, super::fcgi::typeStdout, req.reqId)),
    };
}

impl response {
    // go: sdk 1.25.5 net/http/fcgi/child.go:91-93 response.Header
    pub fn Header(&self) -> super::super::responsewriter::HeaderHandle {
        return super::super::responsewriter::HeaderHandle::__from_arc(self.header.clone());
    }

    // go: sdk 1.25.5 net/http/fcgi/child.go:104-120 response.WriteHeader
    pub fn WriteHeader(&self, code: crate::types::int) {
        let mut st = self.state.Lock();
        if st.wroteHeader {
            return;
        }
        st.wroteHeader = true;
        st.code = code;
        return;
    }

    // go: sdk 1.25.5 net/http/fcgi/child.go:126-138 response.writeCGIHeader
    /// Emit the CGI-style head: a `Status:` line, then the headers,
    /// then a blank line.
    ///
    /// Two details that are not decoration. The Content-Type is
    /// SNIFFED from the first body bytes when the handler set none —
    /// and NOT for 304, which must not carry one. And the whole head
    /// is flushed here, before any body byte, so the parent sees a
    /// complete response head even if the handler then stalls.
    pub fn writeCGIHeader(&self, p: &crate::goslice::slice<crate::types::byte>) {
        {
            let mut st = self.state.Lock();
            if st.wroteCGIHeader {
                return;
            }
            st.wroteCGIHeader = true;
        }
        let code = self.state.Lock().code;
        let mut w = self.w.Lock();
        let head = crate::fmt::Sprintf!(
            "Status: %s %s\r\n",
            crate::strconv::Itoa(code),
            super::super::status::StatusText(code)
        );
        let _ = crate::io::Writer::Write(
            &mut *w,
            crate::convert::bytes(head),
        );
        {
            let mut h = self.header.Lock();
            if code != super::super::status::StatusNotModified
                && h.Get(crate::string("Content-Type")).Len() == 0
            {
                h.Set(
                    crate::string("Content-Type"),
                    super::super::sniff::DetectContentType(p.clone()),
                );
            }
            let _ = h.Write(&mut *w);
        }
        let _ = crate::io::Writer::Write(&mut *w, crate::convert::bytes("\r\n"));
        let _ = w.Flush();
        return;
    }

    // go: sdk 1.25.5 net/http/fcgi/child.go:95-102 response.Write
    /// Every write implies a 200 and a CGI header block, in that
    /// order. The header block is written from THIS call's bytes,
    /// because writeCGIHeader sniffs the Content-Type from them.
    pub fn Write(&self, p: crate::goslice::slice<crate::types::byte>)
        -> (crate::types::int, crate::errors::error)
    {
        self.WriteHeader(super::super::status::StatusOK);
        if !self.state.Lock().wroteCGIHeader {
            self.writeCGIHeader(&p);
        }
        let mut w = self.w.Lock();
        return crate::io::Writer::Write(&mut *w, p);
    }

    // go: sdk 1.25.5 net/http/fcgi/child.go:147-150 response.Close
    pub fn Close(&self) -> crate::errors::error {
        self.Flush();
        return self.w.Lock().Close();
    }

    // go: sdk 1.25.5 net/http/fcgi/child.go:140-145 response.Flush
    pub fn Flush(&self) {
        if !self.state.Lock().wroteHeader {
            self.WriteHeader(super::super::status::StatusOK);
        }
        let _ = self.w.Lock().Flush();
        return;
    }
}

// go: sdk 1.25.5 net/http/fcgi/child.go:37-45 newRequest
pub fn newRequest(reqId: uint16, flags: uint8) -> request {
    return request {
        reqId,
        params: map::new(),
        rawParams: slice::<byte>::new(),
        keepConn: flags & flagKeepConn != 0,
        body: slice::<byte>::new(),
    };
}

impl request {
    // go: sdk 1.25.5 net/http/fcgi/child.go:48-71 request.parseParams
    //
    /// Reads an encoded `[]byte` into `params`.
    ///
    /// Every early `return` is a malformed-input bail-out that keeps
    /// whatever was parsed so far — Go does not report the error, and
    /// neither does this.
    pub fn parseParams(&mut self) {
        let mut text = self.rawParams.clone();
        self.rawParams = slice::<byte>::new();
        while crate::len(&text) > 0 {
            let (keyLen, n) = readSize(text.clone());
            if n == 0 {
                return;
            }
            text = slice::<byte>::__from_vec((&(&*text)[n as usize..]).to_vec());

            let (valLen, n) = readSize(text.clone());
            if n == 0 {
                return;
            }
            text = slice::<byte>::__from_vec((&(&*text)[n as usize..]).to_vec());

            if crate::int(keyLen) + crate::int(valLen) > crate::len(&text) {
                return;
            }
            let key = readString(text.clone(), keyLen);
            text = slice::<byte>::__from_vec((&(&*text)[keyLen as usize..]).to_vec());
            let val = readString(text.clone(), valLen);
            text = slice::<byte>::__from_vec((&(&*text)[valLen as usize..]).to_vec());
            self.params.Set(key, val);
        }
    }
}

// go: sdk 1.25.5 net/http/fcgi/child.go:373-395 addFastCGIEnvToContext
//
/// Reports whether to include the FastCGI environment variable `s` in
/// the `http.Request.Context`, accessible via `ProcessEnv`.
pub fn addFastCGIEnvToContext(s: string) -> bool {
    // Exclude things supported by net/http natively:
    if s == "CONTENT_LENGTH"
        || s == "CONTENT_TYPE"
        || s == "HTTPS"
        || s == "PATH_INFO"
        || s == "QUERY_STRING"
        || s == "REMOTE_ADDR"
        || s == "REMOTE_HOST"
        || s == "REMOTE_PORT"
        || s == "REQUEST_METHOD"
        || s == "REQUEST_URI"
        || s == "SCRIPT_NAME"
        || s == "SERVER_PROTOCOL"
    {
        return false;
    }
    if strings::HasPrefix(s.clone(), string("HTTP_")) {
        return false;
    }
    // Explicitly include FastCGI-specific things. This list is
    // redundant with the default `return true` below. Consider this
    // documentation of the sorts of things we expect to maybe see.
    if s == "REMOTE_USER" {
        return true;
    }
    // Unknown, so include it to be safe.
    return true;
}

// go: sdk 1.25.5 net/http/fcgi/child.go:280-288 filterOutUsedEnvVars
//
/// Drops the environment variables net/http already surfaces on the
/// Request, leaving only what `ProcessEnv` should expose.
pub fn filterOutUsedEnvVars(envVars: &map<string, string>) -> map<string, string> {
    let mut withoutUsedEnvVars: map<string, string> = map::new();
    let keys = envVars.Keys();
    for i in 0..keys.len() {
        let k = keys[i].clone();
        if addFastCGIEnvToContext(k.clone()) {
            let (v, _) = envVars.Get(k.clone());
            withoutUsedEnvVars.Set(k, v);
        }
    }
    return withoutUsedEnvVars;
}

// ─── the serve loop ──────────────────────────────────────────────────
//
// This is the half the file header used to say was blocked on "the
// conn's lock discipline". The blocker was real for GO's shape and
// dissolves in goish's, for a reason that has nothing to do with
// locks: `http.Request.Body` is `slice<byte>` here, not an
// `io.ReadCloser`. Go spawns `serveRequest` on the FIRST stdin record
// so the handler can stream the body through an `io.Pipe` while more
// records arrive; goish has to have the whole body before it can build
// the Request at all, so the handler runs when stdin ENDS — from the
// read loop itself, not from a second goroutine.
//
// With no handler running while the loop reads, nothing writes while
// the transport is being read, and one mutex is enough.
//
// What this costs, stated plainly: a slow handler delays other
// multiplexed requests on the same connection. Go's own code carries
// a TODO about the mirror-image problem ("This blocks until the
// handler reads from the pipe. If the handler takes a long time, it
// might be a problem."), so neither shape is free.


crate::var! {
    // go: sdk 1.25.5 net/http/fcgi/child.go:181-181 errCloseConn
    pub errCloseConn: error = "fcgi: connection should be closed";

    // go: sdk 1.25.5 net/http/fcgi/child.go:187-187 ErrRequestAborted
    /// Go: "returned by Read when a handler attempts to read the body
    /// of a request that has been aborted by the web server."
    pub ErrRequestAborted: error = "fcgi: request aborted by web server";

    // go: sdk 1.25.5 net/http/fcgi/child.go:191-191 ErrConnClosed
    /// Go: "returned by Read when a handler attempts to read the body
    /// of a request after the connection to the web server has been
    /// closed."
    pub ErrConnClosed: error = "fcgi: connection to web server closed";
}

// go: sdk 1.25.5 net/http/fcgi/child.go:183-183 emptyBody
/// Go: `io.NopCloser(strings.NewReader(""))` — the body a request
/// with no stdin content gets. goish's request carries its body as
/// bytes, so the empty body is the empty slice; this exists so the
/// declaration is present and named where Go names it.
pub fn emptyBody() -> slice<byte> {
    return slice::<byte>::new();
}

// go: none — goish-only: Go's `envVarsContextKey struct{}` is a
// private TYPE used as a context key, so no other package can forge
// it. goish's context keys are `&str`, so the guarantee is by naming
// convention; the name is namespaced to this package for that reason.
pub const envVarsContextKey: &str = "net/http/fcgi.envVars";

// go: sdk 1.25.5 net/http/fcgi/child.go:152-157 child
/// One FastCGI connection being served: the transport, the handler,
/// and the in-flight requests keyed by request ID.
pub struct child {
    conn: alloc::sync::Arc<super::fcgi::conn>,
    handler: alloc::sync::Arc<dyn super::super::server::Handler>,
    /// Go: "keyed by request ID".
    requests: map<uint16, request>,
}

// go: sdk 1.25.5 net/http/fcgi/child.go:159-165 newChild
pub fn newChild(
    rwc: alloc::boxed::Box<dyn super::fcgi::ReadWriteCloser + Send + Sync>,
    handler: alloc::sync::Arc<dyn super::super::server::Handler>,
) -> child {
    return child {
        conn: super::fcgi::newConn(rwc),
        handler,
        requests: map::new(),
    };
}

impl child {
    // go: sdk 1.25.5 net/http/fcgi/child.go:167-178 child.serve
    pub fn serve(&mut self) {
        let mut rec = super::fcgi::record::new();
        loop {
            // Go: `rec.read(c.conn.rwc)` — see __read_record on why
            // this goes through the conn here.
            if !self.conn.__read_record(&mut rec).IsNil() {
                break;
            }
            if !self.handleRecord(&rec).IsNil() {
                break;
            }
        }
        // Go defers both, in this order (cleanUp runs FIRST, being
        // the later defer).
        self.cleanUp();
        let _ = self.conn.Close();
        return;
    }

    // go: sdk 1.25.5 net/http/fcgi/child.go:193-276 child.handleRecord
    pub fn handleRecord(&mut self, rec: &super::fcgi::record) -> crate::errors::error {
        let (_, ok) = self.requests.Get(rec.h.Id);
        if !ok
            && rec.h.Type != super::fcgi::typeBeginRequest
            && rec.h.Type != super::fcgi::typeGetValues
        {
            // Go: "The spec says to ignore unknown request IDs."
            return crate::errors::nil;
        }

        if rec.h.Type == super::fcgi::typeBeginRequest {
            if ok {
                // Go: "The server is trying to begin a request with the
                // same ID as an in-progress request. This is an error."
                return crate::errors::New(string("fcgi: received ID that is already in-flight"));
            }
            let mut br = super::fcgi::beginRequest::default();
            let err = br.read(rec.content());
            if !err.IsNil() {
                return err;
            }
            if crate::int(br.role) != super::fcgi::roleResponder {
                let _ = self.conn.writeEndRequest(
                    rec.h.Id,
                    0,
                    crate::uint8(super::fcgi::statusUnknownRole),
                );
                return crate::errors::nil;
            }
            let req = newRequest(rec.h.Id, br.flags);
            self.requests.Set(rec.h.Id, req);
            return crate::errors::nil;
        }

        if rec.h.Type == super::fcgi::typeParams {
            // Go: "Technically a key-value pair can straddle the
            // boundary between two packets. We buffer until we've
            // received all parameters."
            let (mut req, _) = self.requests.Get(rec.h.Id);
            let content = rec.content();
            if crate::len(&content) > 0 {
                for i in 0..crate::len(&content) {
                    req.rawParams = crate::append!(req.rawParams, content[i]);
                }
                self.requests.Set(rec.h.Id, req);
                return crate::errors::nil;
            }
            req.parseParams();
            self.requests.Set(rec.h.Id, req);
            return crate::errors::nil;
        }

        if rec.h.Type == super::fcgi::typeStdin {
            let content = rec.content();
            let (mut req, _) = self.requests.Get(rec.h.Id);
            if crate::len(&content) > 0 {
                // Go writes into the pipe the handler is already
                // reading; goish accumulates, because the Request it
                // will build carries the body as bytes.
                for i in 0..crate::len(&content) {
                    req.body = crate::append!(req.body, content[i]);
                }
                self.requests.Set(rec.h.Id, req);
                return crate::errors::nil;
            }
            // Empty stdin record: the body is complete. Go has already
            // spawned the handler; goish runs it now.
            self.requests.Delete(rec.h.Id);
            let keepConn = req.keepConn;
            self.serveRequest(&req);
            if !keepConn {
                // Belt and braces: serveRequest has already closed the
                // conn on this path, so the next read would fail
                // anyway. Kept because it is what Go returns, and the
                // loop should not depend on the close winning a race.
                return errCloseConn.into();
            }
            return crate::errors::nil;
        }

        if rec.h.Type == super::fcgi::typeGetValues {
            let mut values: map<string, string> = map::new();
            values.Set(string("FCGI_MPXS_CONNS"), string("1"));
            let _ = super::fcgi::writePairs(
                &self.conn,
                super::fcgi::typeGetValuesResult,
                0,
                &values,
            );
            return crate::errors::nil;
        }

        if rec.h.Type == super::fcgi::typeData {
            // Go: "If the filter role is implemented, read the data
            // stream here."
            return crate::errors::nil;
        }

        if rec.h.Type == super::fcgi::typeAbortRequest {
            let (req, _) = self.requests.Get(rec.h.Id);
            self.requests.Delete(rec.h.Id);
            let _ = self.conn.writeEndRequest(
                rec.h.Id,
                0,
                crate::uint8(super::fcgi::statusRequestComplete),
            );
            if !req.keepConn {
                // Go: "connection will close upon return".
                return errCloseConn.into();
            }
            return crate::errors::nil;
        }

        // Go's default arm: tell the server we do not know this type.
        let mut b = crate::make!([]byte, 8);
        b[0] = rec.h.Type;
        let _ = self.conn.writeRecord(super::fcgi::typeUnknownType, 0, &b);
        return crate::errors::nil;
    }

    // go: sdk 1.25.5 net/http/fcgi/child.go:290-322 child.serveRequest
    // goishlint:ignore GOISH020 serveRequest — Go's third parameter is
    // the `io.ReadCloser` body it is about to stream; goish's request
    // already carries the body, for the reason in the serve-loop note.
    /// Build the http.Request from the CGI parameters, run the
    /// handler, and close out the FastCGI request.
    ///
    /// `r.Write(nil)` before Close is Go's, and it is not a no-op:
    /// "Make sure we serve something even if nothing was written to
    /// r" — it forces the CGI header block out for a handler that
    /// wrote no body.
    fn serveRequest(&mut self, req: &request) {
        let r = newResponse(&self.conn, req);
        let (httpReq, err) = super::super::cgi::RequestFromMap(&req.params);
        if !err.IsNil() {
            // Go: "there was an error reading the request".
            r.WriteHeader(super::super::status::StatusInternalServerError);
            let _ = self.conn.writeRecord(
                super::fcgi::typeStderr,
                req.reqId,
                &crate::convert::bytes(err.Error()),
            );
        } else {
            let mut httpReq = httpReq;
            httpReq.Body = req.body.clone();
            httpReq.ContentLength = crate::int64(crate::len(&req.body));
            let withoutUsedEnvVars = filterOutUsedEnvVars(&req.params);
            let envVarCtx = crate::context::WithValue(
                httpReq.Context(),
                envVarsContextKey,
                withoutUsedEnvVars,
            );
            let httpReq = httpReq.WithContext(envVarCtx);
            self.handler.ServeHTTP(&r, &httpReq);
        }
        // Go: "Make sure we serve something even if nothing was
        // written to r."
        let _ = r.Write(crate::goslice::slice::<byte>::new());
        let _ = r.Close();
        let _ = self.conn.writeEndRequest(
            req.reqId,
            0,
            crate::uint8(super::fcgi::statusRequestComplete),
        );
        // Go then drains the body so the host is not still writing when
        // the socket closes (issue 4183). goish already holds the whole
        // body, so there is nothing left in flight to drain.
        if !req.keepConn {
            let _ = self.conn.Close();
        }
        return;
    }

    // go: sdk 1.25.5 net/http/fcgi/child.go:322-331 child.cleanUp
    /// Fail every still-open request when the connection goes away.
    /// Go closes each request's pipe with ErrConnClosed so a handler
    /// blocked on the body wakes; goish's handlers already have their
    /// bodies, so what is left is dropping the records.
    pub fn cleanUp(&mut self) {
        let keys = self.requests.Keys();
        for i in 0..keys.len() {
            self.requests.Delete(keys[i]);
        }
        return;
    }
}

// go: sdk 1.25.5 net/http/fcgi/child.go:334-358 Serve
/// Go: "Serve accepts incoming FastCGI connections on the listener l,
/// creating a new goroutine for each. The goroutine reads requests and
/// then calls handler to reply to them."
///
/// Go also supports `l == nil`, meaning "the parent passed us the
/// listening socket as fd 0" — the standard FastCGI child protocol.
/// goish requires the listener, because that path needs
/// `net.FileListener` on an inherited fd.
pub fn Serve(
    l: crate::net::Listener,
    handler: alloc::sync::Arc<dyn super::super::server::Handler>,
) -> crate::errors::error {
    // Go's `for { … }` only leaves through a return; Rust needs the
    // value to come out of the loop.
    let out = loop {
        let (rw, err) = l.Accept();
        if !err.IsNil() {
            break err;
        }
        let h = handler.clone();
        crate::go!(stack(1024 * 1024), move || {
            let mut c = newChild(alloc::boxed::Box::new(rw), h);
            c.serve();
        });
    };
    return out;
}

// go: sdk 1.25.5 net/http/fcgi/child.go:366-369 ProcessEnv
/// Go: "ProcessEnv returns FastCGI environment variables associated
/// with the request r for which no effort was made to be included in
/// the request itself […] if REMOTE_USER is set for a request, it will
/// not be found anywhere in r, but it will be included in ProcessEnv's
/// response (via r's context)."
pub fn ProcessEnv(r: &super::super::request::Request) -> map<string, string> {
    let v = match r.Context().Value(envVarsContextKey) {
        None => {
            return map::new();
        }
        Some(v) => v,
    };
    return match v.downcast_ref::<map<string, string>>() {
        None => map::new(),
        Some(m) => m.clone(),
    };
}

impl super::super::responsewriter::ResponseWriter for response {
    // go: none — goish-only: Go's `*response` satisfies
    // http.ResponseWriter by having the three methods; Rust needs the
    // impl block, which forwards to them.
    fn Header(&self) -> super::super::responsewriter::HeaderHandle {
        return response::Header(self);
    }
    // go: none — see above.
    fn Write(&self, p: crate::goslice::slice<crate::types::byte>)
        -> (crate::types::int, crate::errors::error)
    {
        return response::Write(self, p);
    }
    // go: none — see above.
    fn WriteHeader(&self, statusCode: crate::types::int) {
        response::WriteHeader(self, statusCode);
    }
    // go: none — see above.
    fn __goish_as_dyn_any(&self) -> Option<&(dyn core::any::Any + Send + Sync)> {
        return Some(self);
    }
}

impl super::super::responsewriter::Flusher for response {
    // go: none — goish-only: Go's `*response` satisfies http.Flusher
    // the same way; this is the impl block for it.
    fn Flush(&self) {
        response::Flush(self);
    }
}

// go: none — goish idiom: fill the `#[goish::interface]` downcast
// registry for this module's ResponseWriter.
pub(crate) fn register_fcgi_impls() {
    super::super::responsewriter::__goish_register_ResponseWriter_impl::<response>();
    super::super::responsewriter::__goish_register_Flusher_impl::<response>();
}
