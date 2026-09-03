// net/http/cgi/child.go — CGI from the perspective of a child process.
//
// Ported: envMap and RequestFromMap, the pair that turns a CGI
// environment into an http.Request. net/http/fcgi's child.go calls
// RequestFromMap, so this is the piece that unblocks it.
//
// Now also ported: Request(), Serve() and the `response` writer. The
// earlier note here claimed these needed "the same conn/writer design
// the fcgi record layer is waiting on" — that was wrong. goish's
// ResponseWriter is a plain trait with &self receivers, so `response`
// implements it directly, with its mutable fields behind one lock
// instead of Go's &mut receiver. Verified byte-for-byte against Go by
// driving the real unexported `response` over a bytes.Buffer.
//
// goishlint:ignore GOISH019 response — Go's `code`, `wroteHeader`,
// `wroteCGIHeader` and `bufw` are reached through a `*response`
// receiver; goish's ResponseWriter takes `&self`, so they live in a
// `responseState` behind one Mutex. `req` is held as `req_url` because
// only the URL is ever read from it (in Write's log line).
// goishlint:ignore GOISH020 writeCGIHeader — takes the already-held
// `&mut responseState` guard as its first parameter; Go reaches the
// same fields through its `&mut` receiver. Dropping it would mean
// re-locking a Mutex the caller already holds.

#![allow(non_snake_case)]

extern crate alloc;

use alloc::sync::Arc;
use alloc::vec::Vec;

use crate::errors::{self, error};
use crate::gomap::map;
use crate::goslice::slice;
use crate::string;
use crate::strings;
use crate::types::{byte, int};

use super::super::header::Header;
use super::super::request::{ParseHTTPVersion, Request};
use super::super::url::URL;

// go: sdk 1.25.5 net/http/cgi/child.go:39-48 envMap
//
/// Split `KEY=VALUE` environment strings into a map. An entry with no
/// `=` is skipped, and a later duplicate key wins.
pub fn envMap(env: slice<string>) -> map<string, string> {
    let mut m: map<string, string> = map::new();
    let n = crate::len(&env);
    let mut i: int = 0;
    while i < n {
        let (k, v, ok) = strings::Cut(env[i].clone(), string("="));
        i += 1;
        if ok {
            m.Set(k, v);
        }
    }
    return m;
}

// go: sdk 1.25.5 net/http/cgi/child.go:50-141 RequestFromMap
//
/// Build an [`Request`] from CGI variables.
///
/// Go's note: "The returned Request's Body field is not populated."
///
/// The URL is assembled rather than taken whole, because CGI gives the
/// pieces: REQUEST_URI when the server supplies it, otherwise
/// SCRIPT_NAME + PATH_INFO + "?" + QUERY_STRING. The scheme comes from
/// the de-facto HTTPS variable, which servers set to "on", "ON" or
/// "1" — all three are accepted, matching Go.
pub fn RequestFromMap(params: &map<string, string>) -> (Request, error) {
    let get = |k: &'static str| -> string {
        let (v, _) = params.Get(string(k));
        return v;
    };

    let mut r = Request {
        Close: true, // Go: r.Close = true
        Trailer: Header::new(),
        TLS: None,
        RequestURI: string::new(),
        Method: get("REQUEST_METHOD"),
        URL: URL::default(),
        Proto: string::new(),
        ProtoMajor: 0,
        ProtoMinor: 0,
        Header: Header::new(),
        Host: string::new(),
        ContentLength: 0,
        TransferEncoding: slice::<string>::__from_vec(Vec::new()),
        Body: super::super::Body::default(),
        GetBody: None,
        RemoteAddr: string::new(),
        pat: None,
        matches: slice::<string>::__from_vec(alloc::vec::Vec::new()),
        otherValues: map::<string, string>::new(),
        form_state: Arc::new(crate::sync::Mutex::new(Default::default())),
        ctx: None,
    };

    if r.Method == "" {
        return (
            r,
            errors::New(string("cgi: no REQUEST_METHOD in environment")),
        );
    }

    r.Proto = get("SERVER_PROTOCOL");
    let (major, minor, ok) = ParseHTTPVersion(r.Proto.clone());
    if !ok {
        return (
            r,
            errors::New(string("cgi: invalid SERVER_PROTOCOL version")),
        );
    }
    r.ProtoMajor = major;
    r.ProtoMinor = minor;

    r.Host = get("HTTP_HOST");

    let lenstr = get("CONTENT_LENGTH");
    if lenstr != "" {
        let (clen, err) = crate::strconv::ParseInt(lenstr.clone(), 10, 64);
        if err != crate::nil {
            return (
                r,
                errors::New(string("cgi: bad CONTENT_LENGTH in environment: ") + lenstr),
            );
        }
        r.ContentLength = clen;
    }

    let ct = get("CONTENT_TYPE");
    if ct != "" {
        r.Header.Set(string("Content-Type"), ct);
    }

    // Go: copy "HTTP_FOO_BAR" variables to "Foo-Bar" headers.
    // HTTP_HOST is skipped because it is already r.Host.
    for (k, v) in params.__iter() {
        if k == "HTTP_HOST" {
            continue;
        }
        let (after, found) = strings::CutPrefix(k.clone(), string("HTTP_"));
        if found {
            r.Header.Add(
                strings::ReplaceAll(after, string("_"), string("-")),
                v.clone(),
            );
        }
    }

    let mut uriStr = get("REQUEST_URI");
    if uriStr == "" {
        // Go: fall back to SCRIPT_NAME, PATH_INFO and QUERY_STRING.
        uriStr = get("SCRIPT_NAME") + get("PATH_INFO");
        let s = get("QUERY_STRING");
        if s != "" {
            uriStr = uriStr + "?" + s;
        }
    }

    // Go: "There's apparently a de-facto standard for this."
    let https = get("HTTPS");
    if https == "on" || https == "ON" || https == "1" {
        r.TLS = Some(Arc::new(crate::crypto::tls::ConnectionState {
            HandshakeComplete: true,
            ..Default::default()
        }));
    }

    let mut haveURL = false;
    if r.Host != "" {
        // Go: hostname is provided, so we can reasonably construct a URL.
        let mut rawurl = r.Host.clone() + uriStr.clone();
        if r.TLS.is_none() {
            rawurl = string("http://") + rawurl;
        } else {
            rawurl = string("https://") + rawurl;
        }
        let (u, err) = super::super::url::Parse(rawurl.clone());
        if err != crate::nil {
            return (
                r,
                errors::New(
                    string("cgi: failed to parse host and REQUEST_URI into a URL: ") + rawurl,
                ),
            );
        }
        r.URL = u;
        haveURL = true;
    }
    // Go: fallback logic if we don't have a Host header or the URL
    // failed to parse.
    if !haveURL {
        let (u, err) = super::super::url::Parse(uriStr.clone());
        if err != crate::nil {
            return (
                r,
                errors::New(string("cgi: failed to parse REQUEST_URI into a URL: ") + uriStr),
            );
        }
        r.URL = u;
    }

    // Go: "Request.RemoteAddr has its port set by Go's standard http
    // server, so we do here too." Atoi's error is deliberately dropped
    // — an unset or invalid REMOTE_PORT becomes zero.
    let (remotePort, _) = crate::strconv::Atoi(get("REMOTE_PORT"));
    r.RemoteAddr = crate::net::JoinHostPort(get("REMOTE_ADDR"), crate::strconv::Itoa(remotePort));

    return (r, errors::nil);
}

// go: sdk 1.25.5 net/http/cgi/child.go:28-37 Request
//
/// Returns the HTTP request as represented in the current
/// environment. This assumes the current program is being run by a
/// web server in a CGI environment.
///
/// Go populates `r.Body` with a `LimitReader` over stdin when
/// `ContentLength > 0`. goish's `Request.Body` is a `slice<byte>`, so
/// the equivalent is to READ that many bytes now rather than hand back
/// a lazy reader — the same eager-vs-streaming gap the rest of
/// net/http carries, and it closes with the Body model change.
pub fn Request() -> (Request, error) {
    let (mut r, err) = RequestFromMap(&envMap(crate::os::Environ()));
    if err != errors::nil {
        return (r, err);
    }
    if r.ContentLength > 0 {
        let mut stdin = crate::os::Stdin();
        let mut buf: Vec<byte> = alloc::vec![0u8; r.ContentLength as usize];
        let mut got: usize = 0;
        // Go's io.LimitReader stops at ContentLength; a short read is
        // not an error here, it just means a shorter body.
        while got < buf.len() {
            let mut tmp = slice::<byte>::__from_vec(alloc::vec![0u8; buf.len() - got]);
            let (n, rerr) = crate::io::Reader::Read(&mut stdin, &mut tmp);
            if n <= 0 || rerr != errors::nil {
                break;
            }
            buf[got..got + (n as usize)].copy_from_slice(&(&*tmp)[..n as usize]);
            got += n as usize;
        }
        buf.truncate(got);
        r.Body = super::super::Body::from_bytes(slice::<byte>::__from_vec(buf));
    }
    return (r, errors::nil);
}

// go: sdk 1.25.5 net/http/cgi/child.go:169-176 response
//
/// The `http.ResponseWriter` a CGI child hands its handler: headers
/// and body are written to stdout in CGI's `Status:`-first format.
///
/// goish's `ResponseWriter` takes `&self`, so every mutable field
/// lives behind a lock rather than in a `&mut` receiver as in Go.
pub struct response {
    req_url: string,
    header: super::super::responsewriter::HeaderHandle,
    st: crate::sync::Mutex<responseState>,
}

struct responseState {
    code: int,
    wroteHeader: bool,
    wroteCGIHeader: bool,
    bufw: crate::bufio::Writer<alloc::boxed::Box<dyn crate::io::Writer + Send + Sync>>,
}

impl response {
    // go: none — goish-only constructor. Go builds `response` with a
    // struct literal inside Serve; the fields are private and the
    // bufio::Writer must be created here, so the literal becomes a fn.
    //
    // `w` is type-erased for the same reason Go's `bufw *bufio.Writer`
    // is: the writer is stdout in production and a buffer under test,
    // and Go's own tests construct this struct over a bytes.Buffer.
    pub fn new(
        req: &Request,
        w: alloc::boxed::Box<dyn crate::io::Writer + Send + Sync>,
    ) -> response {
        return response {
            req_url: req.URL.String(),
            header: super::super::responsewriter::HeaderHandle::new(Header::new()),
            st: crate::sync::Mutex::new(responseState {
                code: 0,
                wroteHeader: false,
                wroteCGIHeader: false,
                bufw: crate::bufio::NewWriter(w),
            }),
        };
    }

    // go: sdk 1.25.5 net/http/cgi/child.go:210-224 response.writeCGIHeader
    //
    /// Finalizes the header sent to the client and writes it to the
    /// output. `p` is not written here, but is the first chunk of the
    /// body that will be written; it is sniffed for a Content-Type if
    /// none is set explicitly.
    fn writeCGIHeader(&self, g: &mut responseState, p: &slice<byte>) {
        if g.wroteCGIHeader {
            return;
        }
        g.wroteCGIHeader = true;
        let line = crate::fmt::Sprintf!(
            "Status: %d %s\r\n",
            g.code,
            super::super::StatusText(g.code)
        );
        let _ = g.bufw.WriteString(line);
        if !self.header.snapshot().has(string("Content-Type")) {
            self.header.Set(
                string("Content-Type"),
                super::super::DetectContentType(p.clone()),
            );
        }
        let _ = self.header.snapshot().Write(&mut g.bufw);
        let _ = g.bufw.WriteString(string("\r\n"));
        let _ = g.bufw.Flush();
    }

    // go: sdk 1.25.5 net/http/cgi/child.go:178-180 response.Flush
    pub fn Flush(&self) {
        let mut g = self.st.Lock();
        let _ = g.bufw.Flush();
    }
}

// go: sdk 1.25.5 net/http/cgi/child.go:178-180 response.Flush
//
// Go's `*response` satisfies http.Flusher by having a Flush method, so
// a CGI handler's `w.(http.Flusher)` finds it. goish had the method —
// `response::Flush` above — with no `Flusher` impl, no registration and
// no `__goish_as_dyn_any` on the ResponseWriter impl below, so the
// assertion missed and every CGI handler saw a writer that could not
// flush.
//
// That is the failure mode CGI exists to avoid: a long-running script
// streams progress by flushing, and a handler whose Flush is
// unreachable buffers its whole response instead. Nothing reports it —
// the output is identical, it just all arrives at the end.
impl super::super::responsewriter::Flusher for response {
    // go: sdk 1.25.5 net/http/cgi/child.go:178-180 response.Flush
    fn Flush(&self) {
        response::Flush(self);
    }
}

impl super::super::responsewriter::ResponseWriter for response {
    // go: none — goish idiom: the hidden Any-view hook every
    // `#[goish::interface]` concrete impl overrides. `cast!` cannot see
    // past a trait object without it, so an assertion for Flusher on
    // this writer missed even with the impl above registered.
    fn __goish_as_dyn_any(&self) -> Option<&(dyn core::any::Any + Send + Sync)> {
        return Some(self);
    }

    // go: sdk 1.25.5 net/http/cgi/child.go:182-184 response.Header
    fn Header(&self) -> super::super::responsewriter::HeaderHandle {
        return self.header.clone();
    }

    // go: sdk 1.25.5 net/http/cgi/child.go:186-194 response.Write
    fn Write(&self, p: slice<byte>) -> (int, error) {
        // Go guards this call: `if !r.wroteHeader`. Calling
        // WriteHeader unconditionally would be wrong even though it
        // is idempotent, because its already-wrote branch prints
        // "CGI attempted to write header twice" to stderr — so every
        // Write after the first would emit a spurious warning.
        {
            let g = self.st.Lock();
            if !g.wroteHeader {
                drop(g);
                self.WriteHeader(super::super::StatusOK);
            }
        }
        let mut g = self.st.Lock();
        if !g.wroteCGIHeader {
            self.writeCGIHeader(&mut g, &p);
        }
        return g.bufw.Write(p);
    }

    // go: sdk 1.25.5 net/http/cgi/child.go:196-204 response.WriteHeader
    fn WriteHeader(&self, code: int) {
        let mut g = self.st.Lock();
        if g.wroteHeader {
            // Note: explicitly using Stderr, as Stdout is our HTTP output.
            crate::fmt::Fprintf!(
                &mut crate::os::Stderr(),
                "CGI attempted to write header twice on request for %s",
                self.req_url.clone()
            );
            return;
        }
        g.wroteHeader = true;
        g.code = code;
    }
}

// go: sdk 1.25.5 net/http/cgi/child.go:145-167 Serve
//
/// Executes the provided [`Handler`] on the currently active CGI
/// request, if any. If there's no current CGI environment an error is
/// returned.
///
/// Go accepts a nil handler meaning `http.DefaultServeMux`; goish
/// takes the handler by `Arc<dyn Handler>`, so pass the mux
/// explicitly.
pub fn Serve(handler: Arc<dyn super::super::Handler>) -> error {
    let (req, err) = Request();
    if err != errors::nil {
        return err;
    }
    let rw = response::new(&req, alloc::boxed::Box::new(crate::os::Stdout()));
    handler.ServeHTTP(&rw, &req);
    // Make sure a response is sent.
    let _ = super::super::responsewriter::ResponseWriter::Write(&rw, slice::<byte>::new());
    let mut g = rw.st.Lock();
    return g.bufw.Flush();
}

// go: none — goish idiom: fill the `#[goish::interface]` downcast
// registry for this module's ResponseWriter, as fcgi's child does.
pub(crate) fn register_cgi_impls() {
    super::super::responsewriter::__goish_register_ResponseWriter_impl::<response>();
    super::super::responsewriter::__goish_register_Flusher_impl::<response>();
}
