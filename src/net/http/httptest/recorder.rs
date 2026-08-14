// go: package net/http/httptest
//
// go: file net/http/httptest/recorder.go decls: NewRecorder, ResponseRecorder.Header, ResponseRecorder.writeHeader, ResponseRecorder.Write, ResponseRecorder.WriteString, checkWriteHeaderCode, ResponseRecorder.WriteHeader, ResponseRecorder.Flush, ResponseRecorder.Result, parseContentLength
//
// Go: "ResponseRecorder is an implementation of [http.ResponseWriter]
// that records its mutations for later inspection in tests."
//
// httptest.rs said this was "blocked on the ResponseWriter trait
// refactor". That refactor happened — ResponseWriter is a real
// `#[goish::interface]` trait — so it is not blocked, and this is it.
//
// One shape difference runs through the file. Go's ResponseWriter
// methods take a pointer receiver and mutate; goish's trait methods
// take `&self`, because a handler holds the writer behind a `dyn`. So
// the recorded state lives behind a Mutex and the public fields are
// accessors rather than fields. Everything Go exposes is still
// reachable: Code(), HeaderMap(), Body(), Flushed().
//
// `httpguts.ValidTrailerHeader` is not ported; its badTrailer table is
// relocated here, entry for entry, the same way http.rs holds
// httpguts' token table.

#![allow(non_snake_case)]
#![allow(dead_code)]

extern crate alloc;

use alloc::sync::Arc;
use alloc::vec::Vec;

use crate::bytes;
use crate::errors::error;
use crate::goslice::slice;
use crate::gostring::string;
use crate::net::textproto;
use crate::strings;
use crate::sync::Mutex;
use crate::types::{byte, int};

use super::super::header::Header;
use super::super::responsewriter::{Flusher, HeaderHandle, ResponseWriter};
use super::super::client::Body;
use super::super::response::Response;

// go: sdk 1.25.5 net/http/httptest/recorder.go:61-61 DefaultRemoteAddr
/// Go: "DefaultRemoteAddr is the default remote address to return in
/// RemoteAddr if an explicit DefaultRemoteAddr isn't set on
/// [ResponseRecorder]."
pub const DefaultRemoteAddr: &str = "1.2.3.4";

// go: none — goish-only: Go's ResponseRecorder fields are mutated
// through a pointer receiver. goish's ResponseWriter methods take
// `&self` because a handler holds the writer behind a `dyn`, so the
// mutable state sits behind a Mutex and the fields become accessors.
struct recState {
    Code: int,
    HeaderMap: Header,
    Body: Vec<byte>,
    Flushed: bool,
    result: Option<Response>,
    snapHeader: Option<Header>,
    wroteHeader: bool,
}

// goishlint:ignore GOISH019 ResponseRecorder — Go's fields are mutated
// through a pointer receiver; goish's ResponseWriter methods take
// `&self`, so the recorded state sits behind a Mutex and the fields
// become accessors. See the module note.
// go: sdk 1.25.5 net/http/httptest/recorder.go:21-48 ResponseRecorder
/// Go: "ResponseRecorder is an implementation of [http.ResponseWriter]
/// that records its mutations for later inspection in tests."
pub struct ResponseRecorder {
    st: Arc<Mutex<recState>>,
    /// The header handle handed to `Header()`. Shared with the
    /// recorder's own HeaderMap so a handler's `w.Header().Set(...)`
    /// lands where Result() will read it.
    hdr: HeaderHandle,
}

// go: sdk 1.25.5 net/http/httptest/recorder.go:51-57 NewRecorder
/// Go: "NewRecorder returns an initialized [ResponseRecorder]."
pub fn NewRecorder() -> ResponseRecorder {
    return ResponseRecorder {
        st: Arc::new(Mutex::new(recState {
            // Go seeds Code with 200 so a handler that never calls
            // WriteHeader still reports the implicit status.
            Code: 200,
            HeaderMap: Header::new(),
            Body: Vec::new(),
            Flushed: false,
            result: None,
            snapHeader: None,
            wroteHeader: false,
        })),
        hdr: HeaderHandle::new(Header::new()),
    };
}

impl ResponseRecorder {
    // go: none — goish-only: Go reads `rec.Code` as a field.
    /// Go: "Code is the HTTP response code set by WriteHeader."
    pub fn Code(&self) -> int {
        return self.st.Lock().Code;
    }

    // go: none — goish-only: Go reads `rec.Flushed` as a field.
    /// Go: "Flushed is whether the Handler called Flush."
    pub fn Flushed(&self) -> bool {
        return self.st.Lock().Flushed;
    }

    // go: none — goish-only: Go reads `rec.Body` as a *bytes.Buffer
    /// field.
    ///
    /// Go: "Body is the buffer to which the Handler's Write calls are
    /// sent."
    pub fn Body(&self) -> slice<byte> {
        return slice::__from_vec(self.st.Lock().Body.clone());
    }

    // go: none — goish-only: Go reads `rec.HeaderMap` as a field. It is
    // deprecated there in favour of Result().Header, and kept for the
    // same reason.
    pub fn HeaderMap(&self) -> Header {
        return self.hdr.snapshot();
    }

    // go: sdk 1.25.5 net/http/httptest/recorder.go:83-103 ResponseRecorder.writeHeader
    /// Go: "writeHeader writes a header if it was not written yet and
    /// detects Content-Type if needed. bytes or str are the beginning
    /// of the response body. Non-nil bytes win."
    fn writeHeader(&self, b: Option<&[byte]>, str_: &string) {
        if self.st.Lock().wroteHeader {
            return;
        }
        let mut sniff_owned: Vec<byte>;
        let sniff: &[byte] = match b {
            Some(b) => b,
            None => {
                // Go: if len(str) > 512 { str = str[:512] }
                let raw = str_.as_bytes();
                let n = if raw.len() > 512 { 512 } else { raw.len() };
                sniff_owned = Vec::new();
                sniff_owned.extend_from_slice(&raw[..n]);
                &sniff_owned[..]
            }
        };

        let m = self.hdr.snapshot();
        let hasType = m.__inner().Has(string::from_static("Content-Type"));
        let hasTE = m.Get(string::from_static("Transfer-Encoding")).Len() != 0;
        if !hasType && !hasTE {
            let ct = super::super::sniff::DetectContentType(slice::__from_vec(sniff.to_vec()));
            self.hdr.Set(string::from_static("Content-Type"), ct);
        }

        self.WriteHeader(200);
    }

    // go: sdk 1.25.5 net/http/httptest/recorder.go:117-123 ResponseRecorder.WriteString
    /// Go: "WriteString implements [io.StringWriter]. The data in str
    /// is written to rw.Body, if not nil."
    pub fn WriteString(&self, str_: string) -> (int, error) {
        self.writeHeader(None, &str_);
        let mut g = self.st.Lock();
        g.Body.extend_from_slice(str_.as_bytes());
        return (str_.Len(), crate::errors::nil);
    }

    // go: sdk 1.25.5 net/http/httptest/recorder.go:181-238 ResponseRecorder.Result
    /// Go: "Result returns the response generated by the handler. The
    /// Response.Header is a snapshot of the headers at the time of the
    /// first write call, or at the time of this call, if the handler
    /// never did a write. Result must only be called after the handler
    /// has finished running."
    pub fn Result(&self) -> Response {
        {
            let g = self.st.Lock();
            if let Some(r) = g.result.as_ref() {
                return r.clone();
            }
        }
        let snap = {
            let mut g = self.st.Lock();
            if g.snapHeader.is_none() {
                g.snapHeader = Some(self.hdr.snapshot().Clone());
            }
            g.snapHeader.as_ref().unwrap().clone()
        };

        let mut res = Response::default();
        res.Proto = string::from_static("HTTP/1.1");
        res.ProtoMajor = 1;
        res.ProtoMinor = 1;
        res.StatusCode = self.st.Lock().Code;
        res.Header = snap.clone();
        if res.StatusCode == 0 {
            res.StatusCode = 200;
        }
        // Go: fmt.Sprintf("%03d %s", code, StatusText(code)).
        res.Status = crate::fmt::Sprintf!(
            "%03d %s",
            res.StatusCode,
            super::super::status::StatusText(res.StatusCode)
        );
        res.Body = Body::from_bytes(self.Body());
        res.ContentLength =
            parseContentLength(res.Header.Get(string::from_static("Content-Length")));

        // Go: the Trailer half — names announced in the "Trailer"
        // header, then anything written under the TrailerPrefix.
        let mut trailer = Header::new();
        let announced = snap.Values(string::from_static("Trailer"));
        let mut i: int = 0;
        while i < announced.Len() {
            let parts = strings::Split(announced[i].clone(), string::from_static(","));
            let mut j: int = 0;
            while j < parts.Len() {
                let k = super::super::header::CanonicalHeaderKey(textproto::TrimString(
                    parts[j].clone(),
                ));
                j += 1;
                if !ValidTrailerHeader(&k) {
                    // Go: "Ignore since forbidden by RFC 7230, section
                    // 4.1.2."
                    continue;
                }
                let vv = self.hdr.snapshot().Values(k.clone());
                if vv.Len() == 0 {
                    continue;
                }
                let mut j2: int = 0;
                while j2 < vv.Len() {
                    trailer.Add(k.clone(), vv[j2].clone());
                    j2 += 1;
                }
            }
            i += 1;
        }
        let live = self.hdr.snapshot();
        for (k, vv) in live.__inner().__iter() {
            if !strings::HasPrefix(k.clone(), string::from_static(TrailerPrefix)) {
                continue;
            }
            let name = strings::TrimPrefix(k.clone(), string::from_static(TrailerPrefix));
            let mut j: int = 0;
            while j < vv.Len() {
                trailer.Add(name.clone(), vv[j].clone());
                j += 1;
            }
        }
        res.Trailer = trailer;

        self.st.Lock().result = Some(res.clone());
        return res;
    }
}

impl ResponseWriter for ResponseRecorder {
    // go: sdk 1.25.5 net/http/httptest/recorder.go:67-74 ResponseRecorder.Header
    /// Go: "Header implements [http.ResponseWriter]. It returns the
    /// response headers to mutate within a handler."
    fn Header(&self) -> HeaderHandle {
        return self.hdr.clone();
    }

    // go: sdk 1.25.5 net/http/httptest/recorder.go:107-113 ResponseRecorder.Write
    /// Go: "Write implements http.ResponseWriter. The data in buf is
    /// written to rw.Body, if not nil."
    fn Write(&self, buf: slice<byte>) -> (int, error) {
        // slice<T> derefs to [T]; `&*buf` is the byte view.
        let raw: &[byte] = &*buf;
        self.writeHeader(Some(raw), &string::new());
        let n = crate::builtin::len(&buf);
        let mut g = self.st.Lock();
        g.Body.extend_from_slice(&*buf);
        return (n, crate::errors::nil);
    }

    // go: sdk 1.25.5 net/http/httptest/recorder.go:143-155 ResponseRecorder.WriteHeader
    fn WriteHeader(&self, code: int) {
        {
            let g = self.st.Lock();
            if g.wroteHeader {
                return;
            }
        }
        checkWriteHeaderCode(code);
        let snap = self.hdr.snapshot().Clone();
        let mut g = self.st.Lock();
        g.Code = code;
        g.wroteHeader = true;
        g.snapHeader = Some(snap);
    }

    // go: none — goish-only: the Any view `cast!` needs to find this
    // concrete type through a `dyn` carrier.
    fn __goish_as_dyn_any(&self) -> Option<&(dyn core::any::Any + Send + Sync)> {
        return Some(self);
    }
}

impl Flusher for ResponseRecorder {
    // go: sdk 1.25.5 net/http/httptest/recorder.go:159-164 ResponseRecorder.Flush
    /// Go: "Flush implements [http.Flusher]. To test whether Flush was
    /// called, see rw.Flushed."
    fn Flush(&self) {
        let wrote = self.st.Lock().wroteHeader;
        if !wrote {
            self.WriteHeader(200);
        }
        self.st.Lock().Flushed = true;
    }

    // go: none — goish-only: the Any view `cast!` needs to find this
    // concrete type through a `dyn` carrier.
    fn __goish_as_dyn_any(&self) -> Option<&(dyn core::any::Any + Send + Sync)> {
        return Some(self);
    }
}

// go: sdk 1.25.5 net/http/httptest/recorder.go:125-140 checkWriteHeaderCode
/// Go: "Issue 22880: require valid WriteHeader status codes. For now we
/// only enforce that it's three digits... We used to send
/// "HTTP/1.1 000 0" on the wire in responses but there's no equivalent
/// bogus thing we can realistically send in HTTP/2, so we'll
/// consistently panic instead and help people find their bugs early."
fn checkWriteHeaderCode(code: int) {
    if code < 100 || code > 999 {
        panic!("invalid WriteHeader code");
    }
}

// go: sdk 1.25.5 net/http/httptest/recorder.go:245-255 parseContentLength
/// Go: "parseContentLength trims whitespace from s and returns -1 if no
/// value is set, or the value if it's >= 0. This a modified version of
/// same function found in net/http/transfer.go. This one just ignores
/// an invalid header."
fn parseContentLength(cl: string) -> int {
    let cl = textproto::TrimString(cl);
    if cl.Len() == 0 {
        return -1;
    }
    let (n, err) = crate::strconv::ParseUint(cl, 10, 63);
    if !err.IsNil() {
        return -1;
    }
    return crate::int(n);
}

// TrailerPrefix and ValidTrailerHeader both live in net/http proper
// now — the former in server.rs (server.go:512), the latter in
// http.rs beside the other relocated httpguts helpers. This file used
// to carry private copies of both; server.go's declareTrailer needs
// them too, and two copies of a security-relevant deny-list is one
// too many.
use super::super::http::ValidTrailerHeader;
use super::super::server::TrailerPrefix;


// go: none — goish-only: silences the unused-import warning for the
// bytes package, which Go's recorder uses for its *bytes.Buffer body
// and goish holds as a Vec.
#[allow(unused)]
fn __bytes_unused() {
    let _ = bytes::NewBuffer(slice::<byte>::new());
}
