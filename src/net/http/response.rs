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
// Still to move from client.rs: Response, Response::Cookies,
// Response::ProtoAtLeast, ReadResponse.
// Still missing entirely: fixPragmaCacheControl, closeBody,
// bodyIsWritable, isProtocolSwitch, isProtocolSwitchResponse,
// isProtocolSwitchHeader.

#![allow(non_snake_case)]

use crate::errors::error;
use crate::string;

use super::client::Response;
use super::url::URL;

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
            return (URL::empty(), ErrNoLocation.into());
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
        if super::header::hasToken(conn[i].clone(), string("Upgrade")) {
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
        return self.ProtoMajor > major
            || self.ProtoMajor == major && self.ProtoMinor >= minor;
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

// ─── Still in client.rs, pending relocation ──────────────────────────
//
// goishlint:ignore GOISH021 — Go's `Response` TYPE is declared in
// client.rs (line 69), not dropped. It stays there until the Body
// type it embeds moves too; Body is goish-only framing machinery with
// no response.go counterpart, so untangling the two is its own step.
//
// goishlint:ignore GOISH018 — `ReadResponse` is likewise implemented
// in client.rs, unanchored, and is ~200 lines entangled with that
// file's private BodyKind/ConnSrc plumbing. Moving it is the next
// step of this split, not a drop.
//
// goishlint:ignore GOISH018 — `Response.Write` is genuinely NOT
// ported. It is the only declaration in this file that is actually
// missing rather than misplaced. It needs transfer.go's
// newTransferWriter, which is unported, and it is what
// `respExcludeHeader` above exists to serve — that var is ported now
// so the Write port has its table ready.
