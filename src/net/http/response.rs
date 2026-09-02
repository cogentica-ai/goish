// go: package net/http
//
// net/http/response.go — the client-side `Response` type's methods.
//
// **This file is being grown, not written from scratch.** Go's
// response.go declarations currently live UNANCHORED in client.rs:
// the `Response` struct itself, `Cookies`, `ProtoAtLeast` and
// `ReadResponse` are all still over there. They move here one at a
// time, each verified against goref as it moves, because client.rs
// carries 1733 lines of hand-written code that nothing has ever
// diffed against Go — see the memory note on the client-path
// squatters. GOISH015 is what forces the move: the moment a
// declaration in client.rs cites response.go, the rule (correctly)
// says the file is misnamed.
//
// Nothing left to move from client.rs.
// Still missing entirely: fixPragmaCacheControl, closeBody,
// bodyIsWritable, isProtocolSwitch, isProtocolSwitchResponse,
// isProtocolSwitchHeader.

#![allow(non_snake_case)]

extern crate alloc;

use crate::errors::error;
use crate::string;

use super::client::{
    drain_to_eof, read_full_into, read_response_head, Body, BodyKind, BufioPassthrough,
};
use super::header::Header;
use super::request::Request;
use super::url::URL;
use crate::gonilable::nilable;
use crate::io::Reader;
use crate::types::byte;
use crate::types::int;
use crate::{bufio, errors, io, make};

// go: sdk 1.25.5 net/http/response.go:32-123 Response
//
/// `http.Response` — the response from an HTTP request.
///
/// `Body` streams from the wire
/// (Go's `io.ReadCloser` shape) — see the `Body` type below.
#[derive(Clone)]
pub struct Response {
    pub Status: string, // "200 OK"
    pub StatusCode: int,
    pub Proto: string,
    pub ProtoMajor: int,
    pub ProtoMinor: int,
    pub Header: Header,
    pub Body: Body,
    /// `-1` if unknown (chunked / no Content-Length on a non-empty body).
    pub ContentLength: int,
    /// Go: "TransferEncoding lists the transfer encodings from
    /// outermost to innermost. A nil or empty value means chunked
    /// encoding was not used." Populated by the wire reader.
    pub TransferEncoding: crate::goslice::slice<string>,
    /// Whether the connection should be closed after reading Body.
    pub Close: bool,
    /// Go: "Uncompressed reports whether the response was sent
    /// compressed but was decompressed by the http package." goish's
    /// Transport does no transparent gzip yet, so nothing sets this
    /// true — the field exists so the struct matches Go and so the
    /// flag has somewhere to land when it does.
    pub Uncompressed: bool,
    /// Go: "Trailer maps trailer keys to values in the same format as
    /// Header." Populated by httptest's recorder and, once transfer.go
    /// lands, by the wire reader.
    pub Trailer: Header,
    /// The Request that produced this Response. Populated by Client::Do.
    /// Modelled as `nilable<Request>` (Go's `*http.Request` shape) so
    /// Goish-side `resp.Request.URL` access can narrow via `.Must()`.
    pub Request: nilable<Request>,
    /// Go: "TLS contains information about the TLS connection on
    /// which the response was received. It is nil for unencrypted
    /// responses." Same shape as `Request.TLS`.
    pub TLS: Option<alloc::sync::Arc<crate::crypto::tls::ConnectionState>>,
}

impl Default for Response {
    // go: none — Rust's zero value for the struct. Go has no
    // constructor; a `Response{}` literal is the equivalent.
    fn default() -> Self {
        return Response {
            Trailer: Header::new(),
            Status: string::new(),
            StatusCode: 0,
            Proto: string::new(),
            ProtoMajor: 0,
            ProtoMinor: 0,
            Header: Header::new(),
            Body: Body::default(),
            ContentLength: 0,
            TransferEncoding: crate::goslice::slice::new(),
            Close: false,
            Uncompressed: false,
            Request: nilable::nil(),
            TLS: None,
        };
    }
}

// go: sdk 1.25.5 net/http/response.go:129-131 ErrNoLocation
//
// Returned by `Response.Location` when no Location header is present.
// Go exports this; goish had only an inline string literal, so
// callers could not match on it.
crate::var! {
    pub ErrNoLocation: error = "http: no Location header in response";
}

impl Response {
    // go: sdk 1.25.5 net/http/response.go:137-152 Response.Location
    //
    /// Returns the URL of the response's "Location" header, if
    /// present. Relative redirects are resolved relative to the
    /// Response's Request. `ErrNoLocation` is returned if no Location
    /// header is present.
    ///
    /// Go's whole body is `r.Request.URL.Parse(lv)` — full RFC 3986
    /// reference resolution — falling back to `url.Parse(lv)` when
    /// there is no Request.
    ///
    /// This replaced a hand-rolled resolver in client.rs that
    /// special-cased only "starts with /" and errored otherwise.
    /// Diffed against Go, that version got FOUR of seven cases wrong:
    /// a bare relative path ("c"), a dot-segment ("../q"), and the
    /// no-Request fallback all returned an error instead of a URL,
    /// and a protocol-relative Location ("//other/p") resolved to
    /// "http://x//other/p" — the ORIGINAL host with a doubled slash,
    /// rather than the new host. Because `Client::Do` calls this to
    /// decide a redirect, the practical effect was that goish
    /// silently DID NOT FOLLOW any relative redirect that was not in
    /// absolute-path form; it returned the 3xx to the caller instead.
    ///
    /// `URL::Parse` was already ported in the very module client.rs
    /// imports. Nothing was calling it.
    pub fn Location(&self) -> (URL, error) {
        let lv = self.Header.Get(string("Location"));
        if lv.Len() == 0 {
            return (URL::default(), ErrNoLocation.into());
        }
        if let Some(req) = self.Request.Try() {
            return req.URL.Parse(lv);
        }
        return super::url::Parse(lv);
    }
}

// go: sdk 1.25.5 net/http/response.go:24-28 respExcludeHeader
//
// The headers `Response.Write` emits from the Response's own fields
// rather than from the Header map.
pub fn respExcludeHeader() -> crate::gomap::map<string, bool> {
    let mut m: crate::gomap::map<string, bool> = crate::gomap::map::new();
    m.Set(string("Content-Length"), true);
    m.Set(string("Transfer-Encoding"), true);
    m.Set(string("Trailer"), true);
    return m;
}

// go: sdk 1.25.5 net/http/response.go:214-220 fixPragmaCacheControl
//
/// RFC 7234, section 5.4: "Pragma: no-cache" on a response with no
/// Cache-Control is treated as "Cache-Control: no-cache".
pub fn fixPragmaCacheControl(header: &mut super::header::Header) {
    let hp = header.Values(string("Pragma"));
    if hp.len() > 0 && hp[0] == "no-cache" {
        if header.Values(string("Cache-Control")).len() == 0 {
            header.Set(string("Cache-Control"), string("no-cache"));
        }
    }
}

// go: sdk 1.25.5 net/http/response.go:362-365 isProtocolSwitchResponse
//
/// Reports whether the response code and response header indicate a
/// successful protocol upgrade response.
pub fn isProtocolSwitchResponse(code: crate::types::int, h: &super::header::Header) -> bool {
    return code == super::StatusSwitchingProtocols && isProtocolSwitchHeader(h);
}

// go: sdk 1.25.5 net/http/response.go:368-371 isProtocolSwitchHeader
//
/// Reports whether the request or response header is for a protocol
/// switch.
///
/// Go calls `httpguts.HeaderValuesContainsToken(h["Connection"],
/// "Upgrade")`, which scans EVERY value of the Connection header;
/// goish's `hasToken` takes one value, so this loops.
pub fn isProtocolSwitchHeader(h: &super::header::Header) -> bool {
    if h.Get(string("Upgrade")) == "" {
        return false;
    }
    let conn = h.Values(string("Connection"));
    for i in 0..conn.len() {
        // `hasToken` requires a LOWERCASE token — it is Go's
        // net/http hasToken (header.go:236), whose doc says so — while
        // the header VALUE may be mixed case. Passing "Upgrade" here
        // silently failed to match `Connection: upgrade`, which is
        // the spelling most clients actually send.
        if super::header::hasToken(conn[i].clone(), string("upgrade")) {
            return true;
        }
    }
    return false;
}

impl Response {
    // go: sdk 1.25.5 net/http/response.go:125-127 Response.Cookies
    //
    /// Parses and returns the cookies set in the Set-Cookie headers.
    pub fn Cookies(&self) -> crate::goslice::slice<super::cookie::Cookie> {
        return super::cookie::readSetCookies(&self.Header);
    }

    // go: sdk 1.25.5 net/http/response.go:224-227 Response.ProtoAtLeast
    //
    /// Reports whether the HTTP protocol used in the response is at
    /// least major.minor.
    pub fn ProtoAtLeast(&self, major: crate::types::int, minor: crate::types::int) -> bool {
        return self.ProtoMajor > major || self.ProtoMajor == major && self.ProtoMinor >= minor;
    }

    // go: sdk 1.25.5 net/http/response.go:245-334 Response.Write
    /// Go: "Writes r to w in the HTTP/1.x server response format,
    /// including the status line, headers, body, and optional
    /// trailer. … The Response Body is closed after it is sent."
    ///
    /// The zero-ContentLength probe is the subtle half: 0 can mean
    /// "actually empty" or "unknown"; one byte is read to find out,
    /// and a non-empty body flips to unknown length (chunked or
    /// close-delimited via the transferWriter).
    pub fn Write<W: crate::io::Writer>(&self, w: &mut W) -> crate::errors::error {
        use crate::errors;
        // Go: "Status line"
        let mut text = self.Status.clone();
        if text.Len() == 0 {
            text = super::status::StatusText(self.StatusCode);
            if text.Len() == 0 {
                text = string("status code ") + crate::strconv::Itoa(self.StatusCode);
            }
        } else {
            // Go: "Just to reduce stutter" — strip a leading
            // "200 " if Status already includes the code.
            text = crate::strings::TrimPrefix(
                text,
                crate::strconv::Itoa(self.StatusCode) + string(" "),
            );
        }

        let line = crate::fmt::Sprintf!(
            "HTTP/%d.%d %03d %s\r\n",
            self.ProtoMajor,
            self.ProtoMinor,
            self.StatusCode,
            text
        );
        let (_, err) = w.Write(crate::convert::bytes(line));
        if !err.IsNil() {
            return err;
        }

        // Go: "Clone it, so we can modify r1 as needed."
        let mut r1 = self.clone();
        if r1.ContentLength == 0 && !matches!(r1.Body.__eager_len(), Some(0)) {
            // Go: "Is it actually 0 length? Or just unknown?"
            let mut buf = crate::make!([]crate::types::byte, 1);
            let mut probe = r1.Body.clone();
            let (n, perr) = crate::io::Reader::Read(&mut probe, &mut buf);
            if !perr.IsNil() && !errors::Is(perr.clone(), crate::io::EOF) {
                return perr;
            }
            if n == 0 {
                // Go: r1.Body = NoBody
                r1.Body = super::Body::default();
            } else {
                r1.ContentLength = -1;
                r1.Body = super::transfer::__rechain_probed_byte(buf[0], self.Body.clone());
            }
        }
        // Go: "If we're sending a non-chunked HTTP/1.1 response
        // without a content-length, the only way to do that is the
        // old HTTP/1.0 way, by noting the EOF with a connection
        // close, so we need to set Close."
        if r1.ContentLength == -1
            && !r1.Close
            && r1.ProtoAtLeast(1, 1)
            && !super::transfer::chunked(&r1.TransferEncoding)
            && !r1.Uncompressed
        {
            r1.Close = true;
        }

        // Go: "Process Body,ContentLength,Close,Trailer"
        let (mut tw, terr) =
            super::transfer::newTransferWriter(super::transfer::TransferMsg::Resp(&r1));
        if !terr.IsNil() {
            return terr;
        }
        {
            let mut hb = crate::bytes::Buffer::new();
            let herr = tw.writeHeader(&mut hb, None);
            if !herr.IsNil() {
                return herr;
            }
            let (_, we) = w.Write(hb.Bytes());
            if !we.IsNil() {
                return we;
            }
        }

        // Go: "Rest of header"
        let herr = self.Header.WriteSubset(w, &respExcludeHeader());
        if !herr.IsNil() {
            return herr;
        }

        // Go: "contentLengthAlreadySent may have been already sent for
        // POST/PUT requests, even if zero length. See Issue 8180."
        let contentLengthAlreadySent = tw.shouldSendContentLength();
        if r1.ContentLength == 0
            && !super::transfer::chunked(&r1.TransferEncoding)
            && !contentLengthAlreadySent
            && super::transfer::bodyAllowedForStatus(self.StatusCode)
        {
            let (_, we) = w.Write(crate::convert::bytes("Content-Length: 0\r\n"));
            if !we.IsNil() {
                return we;
            }
        }

        // Go: "End-of-header"
        let (_, we) = w.Write(crate::convert::bytes("\r\n"));
        if !we.IsNil() {
            return we;
        }

        // Go: "Write body and trailer"
        let mut bw: &mut dyn crate::io::Writer = w;
        let werr = tw.writeBody(&mut bw);
        if !werr.IsNil() {
            return werr;
        }

        // Go: "Success"
        return errors::nil;
    }

    // go: sdk 1.25.5 net/http/response.go:336-340 Response.closeBody
    #[allow(dead_code)] // consumer is transport.go, unported
    pub(crate) fn closeBody(&mut self) {
        let _ = crate::io::Closer::Close(&mut self.Body);
    }

    // go: sdk 1.25.5 net/http/response.go:349-352 Response.bodyIsWritable
    //
    /// Reports whether the Body supports writing. Go's Transport
    /// returns writable bodies for 101 Switching Protocols responses,
    /// and tests it with `_, ok := r.Body.(io.Writer)`.
    ///
    /// goish's `Body` is a CONCRETE struct, not an `io.ReadCloser`
    /// interface, so no response body can be an io.Writer and this is
    /// always false. It becomes a real question when Body becomes an
    /// interface — the same model change the rest of net/http waits
    /// on — so it is ported now with the constant answer rather than
    /// omitted.
    #[allow(dead_code)] // consumer is transport.go, unported
    pub(crate) fn bodyIsWritable(&self) -> bool {
        return false;
    }

    // go: sdk 1.25.5 net/http/response.go:356-359 Response.isProtocolSwitch
    //
    /// Reports whether the response code and header indicate a
    /// successful protocol upgrade response.
    #[allow(dead_code)] // consumer is transport.go, unported
    pub(crate) fn isProtocolSwitch(&self) -> bool {
        return isProtocolSwitchResponse(self.StatusCode, &self.Header);
    }
}

// go: sdk 1.25.5 net/http/response.go:154-205 ReadResponse
//
/// Reads and returns an HTTP response from `br`. The `req` parameter
/// optionally specifies the Request that corresponds to this
/// Response; if nil, a GET request is assumed.
///
/// Verified against goref over nine responses: Content-Length bodies,
/// 204 and 304 carrying no body, chunked (ContentLength -1 and
/// TransferEncoding ["chunked"]), HTTP/1.0 with no CL running to EOF
/// with Close true, Connection: close alongside a CL, a non-standard
/// status keeping its reason phrase verbatim, duplicate headers, and
/// a non-numeric status code being an ERROR rather than a silent 0.
///
/// On success the reader has consumed up through the response body,
/// which is returned pre-drained (an `Eager` Body) — the borrowed
/// reader can't move into a streaming Body. The client's `RoundTrip`
/// uses `read_response_head` + an owned reader to stream instead.
/// The `req` argument is recorded into `Response.Request` so callers
/// can chain `Location()` etc.
pub fn ReadResponse<R: Reader>(
    br: &mut bufio::Reader<R>,
    req: Option<Request>,
) -> (Response, error) {
    let (mut resp, kind, err) = read_response_head(br, req);
    if !err.IsNil() {
        return (resp, err);
    }
    match kind {
        BodyKind::Empty => {
            resp.Body = Body::default();
        }
        BodyKind::Chunked => {
            let body = make!([]byte, 0);
            let mut cr = super::internal::chunked::NewChunkedReader(BufioPassthrough { inner: br });
            let (b, err) = drain_to_eof(&mut cr, body);
            if !err.IsNil() && !errors::Is(err.clone(), io::EOF) {
                return (resp, err);
            }
            resp.Body = Body::from_bytes(b);
        }
        BodyKind::Cl(n) => {
            let want = n;
            let mut body = make!([]byte, want);
            // Go: io.ReadFull(r, body)
            let (got, ferr) = read_full_into(br, &mut body);
            if !ferr.IsNil() && !errors::Is(ferr.clone(), io::EOF) {
                return (resp, ferr);
            }
            if got < want {
                body = body.slice(0, got);
            }
            resp.Body = Body::from_bytes(body);
        }
        BodyKind::UntilEof => {
            let body = make!([]byte, 0);
            let (b, err) = drain_to_eof(br, body);
            if !err.IsNil() && !errors::Is(err.clone(), io::EOF) {
                return (resp, err);
            }
            resp.Body = Body::from_bytes(b);
        }
    }
    return (resp, errors::nil);
}
// ─── Still in client.rs, pending relocation ──────────────────────────
//
// goishlint:ignore GOISH018 — `Response.Write` is genuinely NOT
// ported. It is the only declaration in this file that is actually
// missing rather than misplaced. It needs transfer.go's
// newTransferWriter, which is unported, and it is what
// `respExcludeHeader` above exists to serve — that var is ported now
// so the Write port has its table ready.
