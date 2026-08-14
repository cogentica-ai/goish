// net/http/httputil/dump.go — DumpRequest and DumpResponse.

#![allow(non_snake_case)]
#![allow(dead_code)]

use crate::errors::{self, error};
use crate::gomap::map;
use crate::goslice::slice;
use crate::string;
use crate::strings;
use crate::types::byte;

use super::super::response::Response;
use super::super::request::Request;

// go: sdk 1.25.5 net/http/httputil/dump.go:25-38 drainBody
/// Go: "drainBody reads all of b to memory and then returns two
/// equivalent ReadClosers yielding the same bytes."
///
/// Go's comment continues: "It returns an error if the initial slurp
/// of all bytes fails. It does not attempt to make the returned
/// ReadClosers have equal error-matching behavior." That last
/// sentence is the contract — a caller must not expect the copies to
/// reproduce the original's failure modes, only its bytes.
///
/// This is what lets DumpResponse show a body the caller can still
/// read afterwards. It drains a STREAMING body off the connection
/// (releasing the conn), which is why it returns an error at all.
pub fn drainBody(
    b: &super::super::client::Body,
) -> (
    super::super::client::Body,
    super::super::client::Body,
    error,
) {
    let (buf, err) = b.__drain_remainder();
    if !err.IsNil() {
        return (
            super::super::client::Body::from_bytes(slice::<byte>::__from_vec(
                alloc::vec::Vec::new(),
            )),
            super::super::client::Body::from_bytes(slice::<byte>::__from_vec(
                alloc::vec::Vec::new(),
            )),
            err,
        );
    }
    return (
        super::super::client::Body::from_bytes(buf.clone()),
        super::super::client::Body::from_bytes(buf),
        errors::nil,
    );
}

// go: sdk 1.25.5 net/http/httputil/dump.go:77-168 DumpRequestOut
//
/// Go: "DumpRequestOut is like DumpRequest but for outgoing client
/// requests. It includes any headers that the standard
/// http.Transport adds, such as User-Agent." Go achieves that by
/// round-tripping through a fake conn that records the wire; goish
/// reaches the same guarantee directly: `serialize_request` IS the
/// code path the goish client writes with, so the dump is exactly
/// what would go on the wire. (Divergences follow the client's own:
/// goish's transport does not add Accept-Encoding.)
///
/// `body == false` keeps the Content-Length header intact but cuts
/// the dump at the end of the head — Go's dummyBody truncation at
/// the first CRLFCRLF (dump.go:160-165).
pub fn DumpRequestOut(req: &Request, body: bool) -> (slice<byte>, error) {
    // Go computes host the way the transport does: URL.Host, unless
    // Request.Host overrides (request write, request.go:665).
    let host = if req.Host.Len() != 0 {
        req.Host.clone()
    } else {
        req.URL.Host.clone()
    };
    let (dump, derr) = super::super::client::serialize_request(req, &host);
    if !derr.IsNil() {
        return (dump, derr);
    }
    if !body {
        // Go: if i := bytes.Index(dump, "\r\n\r\n"); i >= 0 { dump = dump[:i+4] }
        let raw: &[u8] = &dump;
        if let Some(i) = raw.windows(4).position(|w| w == b"\r\n\r\n") {
            return (
                slice::<byte>::__from_vec(raw[..i + 4].to_vec()),
                errors::nil,
            );
        }
    }
    return (dump, errors::nil);
}

// go: sdk 1.25.5 net/http/httputil/dump.go:218-286 DumpRequest
/// `httputil.DumpRequest(req, body) -> ([]byte, error)` — render a
/// Request in HTTP/1.x wire format. Line-by-line port of Go 1.25
/// src/net/http/httputil/dump.go:218.
///
/// If `body` is true, the request body is included verbatim. A
/// buffered (Eager) body is viewed without consuming; a streaming one
/// is drained and left re-readable — Go's `drainBody` shape.
pub fn DumpRequest(req: &Request, body: bool) -> (slice<byte>, error) {
    let (body_bytes, _) = req.Body.__materialize();
    // Go: var b bytes.Buffer
    let mut b = strings::Builder::new();
    b.Grow(256 + body_bytes.Len());

    // Go: reqURI := req.RequestURI; if reqURI == "" { reqURI = req.URL.RequestURI() }
    // Goish doesn't store RequestURI separately; build from URL.Path + RawQuery.
    let mut req_uri = strings::Builder::new();
    if req.URL.Path.Len() == 0 {
        let _ = req_uri.WriteByte(b'/');
    } else {
        let _ = req_uri.WriteString(req.URL.Path.clone());
    }
    if req.URL.RawQuery.Len() > 0 {
        let _ = req_uri.WriteByte(b'?');
        let _ = req_uri.WriteString(req.URL.RawQuery.clone());
    }
    let req_uri = req_uri.String();

    // Go: fmt.Fprintf(&b, "%s %s HTTP/%d.%d\r\n", method, reqURI, major, minor)
    let method = if req.Method.Len() == 0 {
        string("GET")
    } else {
        req.Method.clone()
    };
    let _ = b.WriteString(method);
    let _ = b.WriteByte(b' ');
    let _ = b.WriteString(req_uri.clone());
    let _ = b.WriteByte(b' ');
    let _ = b.WriteString(string("HTTP/1.1\r\n"));

    // Go: absRequestURI := strings.HasPrefix(req.RequestURI, "http://") ...
    let abs_req_uri = strings::HasPrefix(req_uri.clone(), string("http://"))
        || strings::HasPrefix(req_uri.clone(), string("https://"));
    if !abs_req_uri {
        // Go: host := req.Host; if host == "" && req.URL != nil { host = req.URL.Host }
        let host = if req.Host.Len() > 0 {
            req.Host.clone()
        } else {
            req.URL.Host.clone()
        };
        if host.Len() > 0 {
            // Go: fmt.Fprintf(&b, "Host: %s\r\n", host)
            let _ = b.WriteString(string("Host: "));
            let _ = b.WriteString(host);
            let _ = b.WriteString(string("\r\n"));
        }
    }

    // Go: chunked := req.TransferEncoding[0] == "chunked" — read from header.
    let te = req.Header.Get(string("Transfer-Encoding"));
    if te.Len() > 0 {
        let _ = b.WriteString(string("Transfer-Encoding: "));
        let _ = b.WriteString(te.clone());
        let _ = b.WriteString(string("\r\n"));
    }

    // Go: req.Header.WriteSubset(&b, reqWriteExcludeHeaderDump)
    // The dump-exclude set: Host, Content-Length, Transfer-Encoding,
    // Trailer (we synthesize them or already wrote them).
    let mut excl: map<string, bool> = map::<string, bool>::new();
    excl.Set(string("Host"), true);
    excl.Set(string("Content-Length"), true);
    excl.Set(string("Transfer-Encoding"), true);
    excl.Set(string("Trailer"), true);
    let mut head_buf = crate::bytes::NewBuffer(slice::<byte>::__from_vec(alloc::vec::Vec::new()));
    let werr = req.Header.WriteSubset(&mut head_buf, &excl);
    if !werr.IsNil() {
        return (slice::<byte>::__from_vec(alloc::vec::Vec::new()), werr);
    }
    // Concatenate the WriteSubset output via slice<byte> indexing.
    let head_bytes = head_buf.Bytes();
    for i in 0..head_bytes.Len() {
        let _ = b.WriteByte(head_bytes[i]);
    }

    // Go: io.WriteString(&b, "\r\n")
    let _ = b.WriteString(string("\r\n"));

    // Go: if req.Body != nil { … }
    let mut out = crate::convert::bytes(b.String());
    if body && body_bytes.Len() > 0 {
        for i in 0..body_bytes.Len() {
            out = crate::append!(out, body_bytes[i]);
        }
    }

    return (out, errors::nil);
}

// go: sdk 1.25.5 net/http/httputil/dump.go:305-337 DumpResponse
/// `httputil.DumpResponse(resp, body) -> ([]byte, error)` — render a
/// Response in HTTP/1.x wire format. Line-by-line port of dump.go:305.
///
/// In Go, this delegates to `Response.Write`. Goish doesn't have a
/// Response.Write yet; we inline the wire serialization (status line +
/// headers + optional body) which is the dominant path anyway.
pub fn DumpResponse(resp: &Response, body: bool) -> (slice<byte>, error) {
    // Go: drainBody — read the body fully, then leave the Response
    // holding an equivalent re-readable copy. Streaming bodies get
    // drained off the conn here (and the conn released).
    let mut body_bytes = slice::<byte>::__from_vec(alloc::vec::Vec::new());
    if body {
        // Go: `save, resp.Body, err = drainBody(resp.Body)` — the
        // dumped copy and the one the caller keeps reading.
        let (mut save, restored, derr) = drainBody(&resp.Body);
        if !derr.IsNil() {
            return (slice::<byte>::__from_vec(alloc::vec::Vec::new()), derr);
        }
        let (bb, rerr) = crate::io::ReadAll(&mut save);
        if !rerr.IsNil() {
            return (slice::<byte>::__from_vec(alloc::vec::Vec::new()), rerr);
        }
        body_bytes = bb;
        // Go assigns the second copy back: `resp.Body = restored`.
        // goish's drain leaves the ORIGINAL body re-readable in place
        // (it becomes an eager copy of what it drained), so the second
        // copy is what a caller holding only the Response would have
        // got — the assignment has already happened.
        let _ = restored;
    }

    let mut b = strings::Builder::new();
    b.Grow(256 + body_bytes.Len());

    // Status line: "HTTP/X.Y CODE STATUS_TEXT\r\n"
    let _ = b.WriteString(string("HTTP/"));
    let _ = b.WriteString(crate::strconv::Itoa(resp.ProtoMajor));
    let _ = b.WriteByte(b'.');
    let _ = b.WriteString(crate::strconv::Itoa(resp.ProtoMinor));
    let _ = b.WriteByte(b' ');
    let _ = b.WriteString(crate::strconv::Itoa(resp.StatusCode));
    let _ = b.WriteByte(b' ');
    // Go: include the `Status` text or fall back to StatusText(StatusCode).
    let st = if resp.Status.Len() > 0 {
        // Status is "200 OK" — strip the leading code if present.
        let space = strings::IndexByte(resp.Status.clone(), b' ');
        if space >= 0 {
            // Drop the "200 " prefix; keep "OK"
            let raw = resp.Status.clone();
            let rest_bytes = &raw.as_bytes()[(space + 1) as usize..];
            string::from_bytes(rest_bytes)
        } else {
            resp.Status.clone()
        }
    } else {
        super::super::status::StatusText(resp.StatusCode)
    };
    let _ = b.WriteString(st);
    let _ = b.WriteString(string("\r\n"));

    // Content-Length / Transfer-Encoding from the canonical fields.
    if resp.ContentLength >= 0 {
        let _ = b.WriteString(string("Content-Length: "));
        let _ = b.WriteString(crate::strconv::Itoa(resp.ContentLength));
        let _ = b.WriteString(string("\r\n"));
    } else {
        // Go: TransferEncoding may be set; we approximate by checking
        // for a chunked Transfer-Encoding header.
        let te = resp.Header.Get(string("Transfer-Encoding"));
        if te.Len() > 0 {
            let _ = b.WriteString(string("Transfer-Encoding: "));
            let _ = b.WriteString(te);
            let _ = b.WriteString(string("\r\n"));
        }
    }

    // User-set headers, sorted, excluding ones we synthesize.
    let mut excl: map<string, bool> = map::<string, bool>::new();
    excl.Set(string("Content-Length"), true);
    excl.Set(string("Transfer-Encoding"), true);
    let mut head_buf = crate::bytes::NewBuffer(slice::<byte>::__from_vec(alloc::vec::Vec::new()));
    let werr = resp.Header.WriteSubset(&mut head_buf, &excl);
    if !werr.IsNil() {
        return (slice::<byte>::__from_vec(alloc::vec::Vec::new()), werr);
    }
    let head_bytes = head_buf.Bytes();
    for i in 0..head_bytes.Len() {
        let _ = b.WriteByte(head_bytes[i]);
    }

    // Header/body separator.
    let _ = b.WriteString(string("\r\n"));

    // Optional body.
    let mut out = crate::convert::bytes(b.String());
    if body && body_bytes.Len() > 0 {
        for i in 0..body_bytes.Len() {
            out = crate::append!(out, body_bytes[i]);
        }
    }
    return (out, errors::nil);
}

// ─── ReverseProxy (slim port of reverseproxy.go) ─────────────────────


// go: sdk 1.25.5 net/http/httputil/dump.go:53-53 neverEnding
//
/// A byte that reads forever. Go: `type neverEnding byte`, whose Read
/// fills the whole buffer and never reports EOF — used to feed
/// DumpRequestOut a body of known length without allocating one.
#[derive(Clone, Copy)]
pub struct neverEnding(pub byte);

impl crate::io::Reader for neverEnding {
    // go: sdk 1.25.5 net/http/httputil/dump.go:55-60 neverEnding.Read
    fn Read(&mut self, p: &mut slice<byte>) -> (crate::types::int, error) {
        let n = crate::len(p);
        let mut i: crate::types::int = 0;
        while i < n {
            p[i] = self.0;
            i += 1;
        }
        return (n, errors::nil);
    }
}

// go: sdk 1.25.5 net/http/httputil/dump.go:288-290 errNoBody
//
// Go: "sentinel error value" — returned by failureToReadBody so
// Request.Write / Response.Write abort, and recognised by name at the
// call site so it is turned back into a nil error.
crate::var! {
    pub errNoBody: error = "sentinel error value";
}

// go: sdk 1.25.5 net/http/httputil/dump.go:296-296 failureToReadBody
//
/// A body that refuses to be read.
///
/// DumpRequest/DumpResponse substitute this when the caller asked for
/// headers only: writing the message then fails at the body with
/// errNoBody, which the caller recognises and converts back to nil.
/// That is how the dump stops after the headers WITHOUT the writer
/// needing a "headers only" mode.
#[derive(Clone, Copy, Default)]
pub struct failureToReadBody;

impl crate::io::Reader for failureToReadBody {
    // go: sdk 1.25.5 net/http/httputil/dump.go:298-298 failureToReadBody.Read
    fn Read(&mut self, _p: &mut slice<byte>) -> (crate::types::int, error) {
        return (0, errNoBody.into());
    }
}

impl crate::io::Closer for failureToReadBody {
    // go: sdk 1.25.5 net/http/httputil/dump.go:299-299 failureToReadBody.Close
    fn Close(&mut self) -> error {
        return errors::nil;
    }
}

// go: sdk 1.25.5 net/http/httputil/dump.go:196-200 reqWriteExcludeHeaderDump
//
// The headers DumpRequest emits from the Request's own fields rather
// than from the Header map. Note this is a SHORTER list than
// request.go's reqWriteExcludeHeader: the dump keeps User-Agent and
// Content-Length, because seeing them is the point of a dump.
pub fn reqWriteExcludeHeaderDump() -> map<string, bool> {
    let mut m: map<string, bool> = map::new();
    m.Set(string("Host"), true); // not in Header map anyway
    m.Set(string("Transfer-Encoding"), true);
    m.Set(string("Trailer"), true);
    return m;
}

// go: sdk 1.25.5 net/http/httputil/dump.go:189-194 valueOrDefault
//
// Return value if nonempty, def otherwise.
pub fn valueOrDefault(value: string, def: string) -> string {
    if value != "" {
        return value;
    }
    return def;
}

// go: sdk 1.25.5 net/http/httputil/dump.go:64-73 outgoingLength
//
// A copy of the unexported `(*http.Request).outgoingLength` method.
//
// Go distinguishes three states through a `Body io.ReadCloser`
// interface: nil, the `http.NoBody` sentinel, and a real body.
// goish's `Request.Body` is a `slice<byte>`, which collapses nil and
// NoBody into "empty" — both mean "no body to send", which is what
// Go's first branch returns 0 for, so the observable result matches.
// It also means an EMPTY but non-nil Go body would answer 0 here and
// `ContentLength` there; that gap closes when Body becomes a real
// io.ReadCloser.
pub fn outgoingLength(req: &Request) -> crate::types::int64 {
    if matches!(req.Body.__eager_len(), Some(0)) {
        return 0;
    }
    if req.ContentLength != 0 {
        return crate::int64(req.ContentLength);
    }
    return -1;
}

// go: sdk 1.25.5 net/http/httputil/dump.go:41-44 dumpConn
//
/// A `net.Conn` which writes to Writer and reads from Reader — the
/// fake wire DumpRequestOut hands to a Transport so the bytes the
/// Transport would have sent land in a buffer instead of a socket.
///
/// goish's `net::Conn` declares `LocalAddr`/`RemoteAddr` returning a
/// concrete `TCPAddr`, not Go's `net.Addr` interface, so Go's
/// `return nil` becomes a zero-value `TCPAddr`. Nothing reads these
/// on a dump path; they exist to satisfy the trait, exactly as in Go.
pub struct dumpConn<W, R> {
    pub Writer: W,
    pub Reader: R,
}

impl<W, R> crate::net::Conn for dumpConn<W, R>
where
    W: crate::io::Writer + Send + Sync,
    R: crate::io::Reader + Send + Sync,
{
    // go: none — Go's dumpConn EMBEDS io.Reader, so the promoted
    // method is generated rather than written. Rust has no embedding;
    // the forward is explicit.
    fn Read(&mut self, p: &mut slice<byte>) -> (crate::types::int, error) {
        return self.Reader.Read(p);
    }

    // go: none — as Read above: Go promotes this from the embedded
    // io.Writer.
    fn Write(&mut self, p: slice<byte>) -> (crate::types::int, error) {
        return self.Writer.Write(p);
    }

    // go: sdk 1.25.5 net/http/httputil/dump.go:46-46 dumpConn.Close
    fn Close(&mut self) -> error {
        return errors::nil;
    }

    // go: sdk 1.25.5 net/http/httputil/dump.go:47-47 dumpConn.LocalAddr
    fn LocalAddr(&self) -> crate::net::TCPAddr {
        return crate::net::TCPAddr { IP: [0, 0, 0, 0], Port: 0 };
    }

    // go: sdk 1.25.5 net/http/httputil/dump.go:48-48 dumpConn.RemoteAddr
    fn RemoteAddr(&self) -> crate::net::TCPAddr {
        return crate::net::TCPAddr { IP: [0, 0, 0, 0], Port: 0 };
    }

    // go: sdk 1.25.5 net/http/httputil/dump.go:49-49 dumpConn.SetDeadline
    fn SetDeadline(&self, _t: crate::time::Time) -> error {
        return errors::nil;
    }

    // go: sdk 1.25.5 net/http/httputil/dump.go:50-50 dumpConn.SetReadDeadline
    fn SetReadDeadline(&self, _t: crate::time::Time) -> error {
        return errors::nil;
    }

    // go: sdk 1.25.5 net/http/httputil/dump.go:51-51 dumpConn.SetWriteDeadline
    fn SetWriteDeadline(&self, _t: crate::time::Time) -> error {
        return errors::nil;
    }
}

// ─── Deliberately unported, with reasons ─────────────────────────────
//
// goishlint:ignore GOISH018 — drainBody reads an `io.ReadCloser` and
// hands back TWO independent replacements (the classic "consume a
// stream and give the caller two copies" move). goish's
// `Request.Body` is a `slice<byte>`, already fully materialised, so
// the function has nothing to do and no type to express: its two
// return values would both be the same slice. Port it WITH the
// Body -> io.ReadCloser model change, not before — writing it now
// would bake the eager model into a signature that exists to hide it.
//
// goishlint:ignore GOISH018 — DumpRequestOut dumps the bytes an
// `http.Transport` WOULD put on the wire, by running a real Transport
// against a fake connection (dumpConn, ported above) and capturing
// the output. It needs a Transport whose dial step can be replaced.
// goish's Transport has no DialContext hook, so there is currently no
// way to interpose. `dumpConn` is ported and unused pending that —
// an orphan on purpose, unlike the four accidental ones that produced
// real bugs earlier in this port.
//
// goishlint:ignore GOISH018 — delegateReader is a reader that blocks
// on a channel until another goroutine supplies the real reader. Its
// only caller is DumpRequestOut, so it waits on the same hook.
