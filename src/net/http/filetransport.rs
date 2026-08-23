// net/http/filetransport — a RoundTripper for the "file" protocol.
//
// Port of Go 1.25.5 net/http/filetransport.go. `fileTransport` runs
// the ordinary `fileHandler` against a synthetic ResponseWriter whose
// writes go down an `io.Pipe`, so a large file streams to the caller
// instead of being buffered.
//
// Registered with a Transport as in Go's own doc comment:
//     t.RegisterProtocol("file", NewFileTransport(Dir("/")))

#![allow(non_snake_case, non_camel_case_types)]

extern crate alloc;

use alloc::boxed::Box;
use alloc::sync::Arc;

use crate::errors::{self, error};
use crate::goslice::slice;
use crate::string;
use crate::types::{byte, int};

use super::client::{Body, RoundTripper};
use super::fs::{fileHandler, FileSystem};
use super::header::Header;
use super::request::Request;
use super::response::Response;
use super::responsewriter::{HeaderHandle, ResponseWriter};
use super::server::Handler;

// go: sdk 1.25.5 net/http/filetransport.go:13-16 fileTransport
/// Go: "fileTransport implements RoundTripper for the 'file' protocol."
pub struct fileTransport {
    fh: fileHandler,
}

// go: sdk 1.25.5 net/http/filetransport.go:18-33 NewFileTransport
/// Go: "NewFileTransport returns a new RoundTripper, serving the
/// provided FileSystem. The returned RoundTripper ignores the URL host
/// in its incoming requests, as well as most other properties of the
/// request."
pub fn NewFileTransport(fs: Arc<dyn FileSystem + Send + Sync>) -> Arc<dyn RoundTripper> {
    return Arc::new(fileTransport {
        fh: fileHandler { root: fs },
    });
}

// go: sdk 1.25.5 net/http/filetransport.go:35-51 NewFileTransportFS
/// Go: "NewFileTransportFS returns a new RoundTripper, serving the
/// provided file system fsys. […] The files provided by fsys must
/// implement io.Seeker."
pub fn NewFileTransportFS(fsys: Arc<dyn crate::io::fs::FS + Send + Sync>) -> Arc<dyn RoundTripper> {
    return NewFileTransport(super::fs::FS(fsys));
}

impl RoundTripper for fileTransport {
    // go: sdk 1.25.5 net/http/filetransport.go:53-65 fileTransport.RoundTrip
    /// Go: "We start ServeHTTP in a goroutine, which may take a long
    /// time if the file is large. The newPopulateResponseWriter call
    /// returns a channel which either ServeHTTP or finish() sends our
    /// *Response on, once the *Response itself has been populated
    /// (even if the body itself is still being written to the
    /// res.Body, a pipe)."
    fn RoundTrip(&self, req: &Request) -> (Response, error) {
        let (rw, resc) = newPopulateResponseWriter();
        let fh = self.fh.clone();
        let req2 = req.clone();
        let rw2 = rw.clone();
        crate::go!(stack(256 * 1024), move || {
            fh.ServeHTTP(rw2.as_ref(), &req2);
            rw2.finish();
        });
        let (resp, _ok) = resc.Recv();
        return (resp, errors::nil);
    }
}

// go: sdk 1.25.5 net/http/filetransport.go:67-81 newPopulateResponseWriter
/// Go returns `(*populateResponse, <-chan *Response)`. goish returns
/// the writer behind an `Arc` because the serving goroutine and the
/// caller both hold it.
pub fn newPopulateResponseWriter() -> (Arc<populateResponse>, crate::gochan::chan<Response>) {
    let (pr, pw) = crate::io::Pipe();
    let ch = crate::make!(chan Response);
    let rw = Arc::new(populateResponse {
        res: crate::sync::Mutex::new(Response {
            Proto: string("HTTP/1.0"),
            ProtoMajor: 1,
            Header: Header::new(),
            Close: true,
            Body: Body::from_reader(Box::new(pr)),
            ..Default::default()
        }),
        hdr: Arc::new(crate::sync::Mutex::new(Header::new())),
        ch: ch.clone(),
        state: crate::sync::Mutex::new(populateState {
            wroteHeader: false,
            hasContent: false,
            sentResponse: false,
        }),
        pw,
    });
    return (rw, ch);
}

// go: none — goish-only: the three bools Go keeps as plain fields on
// populateResponse. goish's ResponseWriter methods take `&self`, so
// they live behind the same mutex.
struct populateState {
    wroteHeader: bool,
    hasContent: bool,
    sentResponse: bool,
}

// goishlint:ignore GOISH019 populateResponse — Go keeps `wroteHeader`,
// `hasContent` and `sentResponse` as plain bool fields and its
// ResponseWriter methods take a POINTER receiver. goish's
// ResponseWriter takes `&self`, so the three live inside
// `state: Mutex<populateState>` and the header inside `hdr`. Same
// data, and this is the file's only GOISH019 finding.
// go: sdk 1.25.5 net/http/filetransport.go:83-95 populateResponse
/// Go: "populateResponse is a ResponseWriter that populates the
/// *Response in res, and writes its body to a pipe connected to the
/// response body. Once writes begin or finish() is called, the
/// response is sent on ch."
pub struct populateResponse {
    res: crate::sync::Mutex<Response>,
    /// Go's `pr.res.Header` IS the map the handler mutates. goish's
    /// `HeaderHandle` wraps an `Arc<crate::sync::Mutex<Header>>`, so the header
    /// is held here and copied onto the Response when it is sent —
    /// returning a clone from `Header()` would silently drop every
    /// header the handler sets.
    hdr: Arc<crate::sync::Mutex<Header>>,
    ch: crate::gochan::chan<Response>,
    state: crate::sync::Mutex<populateState>,
    pw: crate::io::PipeWriter,
}

impl populateResponse {
    // go: sdk 1.25.5 net/http/filetransport.go:97-105 populateResponse.finish
    pub fn finish(&self) {
        let wrote = self.state.Lock().wroteHeader;
        if !wrote {
            self.WriteHeader(500);
        }
        let sent = self.state.Lock().sentResponse;
        if !sent {
            self.sendResponse();
        }
        let _ = self.pw.Close();
        return;
    }

    // go: sdk 1.25.5 net/http/filetransport.go:107-117 populateResponse.sendResponse
    pub fn sendResponse(&self) {
        {
            let mut st = self.state.Lock();
            if st.sentResponse {
                return;
            }
            st.sentResponse = true;
            if st.hasContent {
                self.res.Lock().ContentLength = -1;
            }
        }
        // Go: `pr.ch <- pr.res` — an UNBUFFERED send, so this blocks
        // until RoundTrip receives. That is what makes RoundTrip
        // return as soon as the head is known while the body is still
        // being written.
        let mut resp = self.res.Lock().clone();
        resp.Header = self.hdr.Lock().clone();
        self.ch.Send(resp);
        return;
    }
}

impl ResponseWriter for populateResponse {
    // go: sdk 1.25.5 net/http/filetransport.go:119-121 populateResponse.Header
    fn Header(&self) -> HeaderHandle {
        return HeaderHandle::__from_arc(self.hdr.clone());
    }

    // go: sdk 1.25.5 net/http/filetransport.go:123-131 populateResponse.WriteHeader
    fn WriteHeader(&self, code: int) {
        {
            let mut st = self.state.Lock();
            if st.wroteHeader {
                return;
            }
            st.wroteHeader = true;
        }
        let mut res = self.res.Lock();
        res.StatusCode = code;
        res.Status = crate::fmt::Sprintf!(
            "%s %s",
            crate::strconv::Itoa(code),
            super::status::StatusText(code)
        );
        return;
    }

    // go: sdk 1.25.5 net/http/filetransport.go:133-141 populateResponse.Write
    fn Write(&self, p: slice<byte>) -> (int, error) {
        let wrote = self.state.Lock().wroteHeader;
        if !wrote {
            self.WriteHeader(super::status::StatusOK);
        }
        {
            let mut st = self.state.Lock();
            st.hasContent = true;
        }
        let sent = self.state.Lock().sentResponse;
        if !sent {
            self.sendResponse();
        }
        return crate::io::Writer::Write(&mut self.pw.clone(), p);
    }

    // go: none — goish-only: the `cast!` hook every ResponseWriter
    // implementation carries so `v, ok := w.(Flusher)` can work.
    fn __goish_as_dyn_any(&self) -> Option<&(dyn core::any::Any + Send + Sync)> {
        return Some(self);
    }
}
