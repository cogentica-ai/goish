// go: package net/http
//
// go: file net/http/http.go decls: Protocols.HTTP1, Protocols.SetHTTP1, Protocols.HTTP2, Protocols.SetHTTP2, Protocols.UnencryptedHTTP2, Protocols.SetUnencryptedHTTP2, Protocols.setBit, Protocols.String, contextKey.String, hasPort, removeEmptyPort, isNotToken, isToken, stringContainsCTLByte, hexEscapeNonASCII, noBody.Read, noBody.Close, noBody.WriteTo, aLongTimeAgo
//
// Go: "TODO(bradfitz): move common stuff here. The other files have
// accumulated generic http stuff in random places."
//
// goish had http.go split across two files — `helpers.rs` for the
// private string helpers and `protocols.rs` for Protocols and NoBody —
// which no Go file corresponds to and which GOISH017 cannot express.
// They are one file here, as upstream. PushOptions and Pusher came from
// response.rs for the same reason: they are declared in http.go.
//
// The one substitution: Go's isToken and isNotToken call into
// golang.org/x/net/http/httpguts, which is not ported. httpguts decides
// with a 256-entry `isTokenTable`, and the table below was diffed
// against it entry for entry — 77 bytes on each side, no difference. So
// this is a relocated table, not a reimplemented rule.
//
// goishlint:ignore GOISH021 incomparable — Go's `type incomparable
// [0]func()` exists only to make a struct that embeds it fail Go's ==
// while adding no size. Rust has no derived equality to defeat: a
// struct is comparable exactly when it derives PartialEq.

#![allow(non_snake_case)]
#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
// Several http.go declarations exist for a consumer goish has not ported
// yet (maxInt64 and aLongTimeAgo for Server/Transport deadlines,
// contextKey for the ServerContextKey values, omitBundledHTTP2 for the
// build-tag branch). They are ported anyway so the file matches Go.
#![allow(dead_code)]

use crate::gostring::string;
use crate::strconv;
use crate::strings;
use crate::types::{byte, int, int64, rune, uint8};
use crate::unicode::utf8;
use crate::{append, make};

use super::header::Header;

// ─── Protocols ────────────────────────────────────────────────────

// go: sdk 1.25.5 net/http/http.go:30-32 Protocols
/// Go: "Protocols is a set of HTTP protocols. The zero value is an
/// empty set of protocols. The supported protocols are: HTTP1 is the
/// HTTP/1.0 and HTTP/1.1 protocols, supported on both unsecured TCP and
/// secured TLS connections; HTTP2 is the HTTP/2 protocol over a TLS
/// connection; UnencryptedHTTP2 is the HTTP/2 protocol over an
/// unsecured TCP connection."
#[derive(Copy, Clone, Default, PartialEq, Eq)]
pub struct Protocols {
    bits: uint8,
}

// go: sdk 1.25.5 net/http/http.go:34-38 protoHTTP1
const protoHTTP1: uint8 = 1 << 0;
// go: sdk 1.25.5 net/http/http.go:34-38 protoHTTP2
const protoHTTP2: uint8 = 1 << 1;
// go: sdk 1.25.5 net/http/http.go:34-38 protoUnencryptedHTTP2
const protoUnencryptedHTTP2: uint8 = 1 << 2;

impl Protocols {
    // go: sdk 1.25.5 net/http/http.go:41-41 Protocols.HTTP1
    /// Go: "HTTP1 reports whether p includes HTTP/1."
    pub fn HTTP1(self) -> bool {
        return self.bits & protoHTTP1 != 0;
    }

    // go: sdk 1.25.5 net/http/http.go:44-44 Protocols.SetHTTP1
    /// Go: "SetHTTP1 adds or removes HTTP/1 from p."
    pub fn SetHTTP1(&mut self, ok: bool) {
        return self.setBit(protoHTTP1, ok);
    }

    // go: sdk 1.25.5 net/http/http.go:47-47 Protocols.HTTP2
    /// Go: "HTTP2 reports whether p includes HTTP/2."
    pub fn HTTP2(self) -> bool {
        return self.bits & protoHTTP2 != 0;
    }

    // go: sdk 1.25.5 net/http/http.go:50-50 Protocols.SetHTTP2
    /// Go: "SetHTTP2 adds or removes HTTP/2 from p."
    pub fn SetHTTP2(&mut self, ok: bool) {
        return self.setBit(protoHTTP2, ok);
    }

    // go: sdk 1.25.5 net/http/http.go:53-53 Protocols.UnencryptedHTTP2
    /// Go: "UnencryptedHTTP2 reports whether p includes unencrypted
    /// HTTP/2."
    pub fn UnencryptedHTTP2(self) -> bool {
        return self.bits & protoUnencryptedHTTP2 != 0;
    }

    // go: sdk 1.25.5 net/http/http.go:56-56 Protocols.SetUnencryptedHTTP2
    /// Go: "SetUnencryptedHTTP2 adds or removes unencrypted HTTP/2 from
    /// p."
    pub fn SetUnencryptedHTTP2(&mut self, ok: bool) {
        return self.setBit(protoUnencryptedHTTP2, ok);
    }

    // go: sdk 1.25.5 net/http/http.go:58-64 Protocols.setBit
    fn setBit(&mut self, bit: uint8, ok: bool) {
        if ok {
            self.bits |= bit;
        } else {
            // Go's &^= (AND NOT).
            self.bits &= !bit;
        }
    }

    // go: sdk 1.25.5 net/http/http.go:66-78 Protocols.String
    pub fn String(self) -> string {
        let mut s: crate::slice<string> = make!([]string, 0);
        if self.HTTP1() {
            s = append!(s, string::from_static("HTTP1"));
        }
        if self.HTTP2() {
            s = append!(s, string::from_static("HTTP2"));
        }
        if self.UnencryptedHTTP2() {
            s = append!(s, string::from_static("UnencryptedHTTP2"));
        }
        return string::from_static("{")
            + crate::strings::Join(s, string::from_static(","))
            + string::from_static("}");
    }
}

// go: none — Go's `type incomparable [0]func()` exists to make a struct
// embedding it non-comparable while adding no size. Rust derives
// PartialEq explicitly, so there is nothing to defeat.

// go: sdk 1.25.5 net/http/http.go:87-87 maxInt64
/// Go: "maxInt64 is the effective "infinite" value for the Server and
/// Transport's byte-limiting readers."
// Go writes `1<<63 - 1`, which in Go's untyped-constant arithmetic is
// exact; Rust evaluates `1i64 << 63` first and overflows, so spell the
// same value as int64::MAX.
pub(crate) const maxInt64: int64 = int64::MAX;

// go: sdk 1.25.5 net/http/http.go:91-91 aLongTimeAgo
/// Go: "aLongTimeAgo is a non-zero time, far in the past, used for
/// immediate cancellation of network operations."
///
/// A `var` in Go, evaluated once at init; time::Unix is pure, so a
/// function returning it is the same value every call.
pub(crate) fn aLongTimeAgo() -> crate::time::Time {
    return crate::time::Unix(1, 0);
}

// go: sdk 1.25.5 net/http/http.go:96-96 omitBundledHTTP2
/// Go: "omitBundledHTTP2 is set by omithttp2.go when the
/// nethttpomithttp2 build tag is set."
///
/// goish takes the `nethttpomithttp2` route, so omithttp2.go's `init`
/// is what runs and this is TRUE — see omithttp2.rs. An earlier note
/// here had it backwards: it read the flag as "goish never bundles
/// HTTP/2, so nothing sets it", which is the value for the build that
/// DOES bundle HTTP/2.
pub(crate) const omitBundledHTTP2: bool = true;

// go: sdk 1.25.5 net/http/http.go:103-105 contextKey
/// Go: "contextKey is a value for use with context.WithValue. It's used
/// as a pointer so it fits in an interface{} without allocation."
pub(crate) struct contextKey {
    pub(crate) name: &'static str,
}

impl contextKey {
    // go: sdk 1.25.5 net/http/http.go:107-107 contextKey.String
    pub(crate) fn String(&self) -> string {
        return string::from_static("net/http context value ") + string::from_static(self.name);
    }
}

// ─── string helpers ──────────────────────────────────────────────

// go: sdk 1.25.5 net/http/http.go:111-111 hasPort
/// Go: "Given a string of the form "host", "host:port", or
/// "[ipv6::address]:port", return true if the string includes a port."
pub fn hasPort(s: &string) -> bool {
    return strings::LastIndex(s.clone(), string::from_static(":"))
        > strings::LastIndex(s.clone(), string::from_static("]"));
}

// go: sdk 1.25.5 net/http/http.go:115-120 removeEmptyPort
/// Go: "removeEmptyPort strips the empty port in ":port" to "" as
/// mandated by RFC 3986 Section 6.2.3."
pub fn removeEmptyPort<H: Into<string>>(host: H) -> string {
    let host: string = host.into();
    if hasPort(&host) {
        return strings::TrimSuffix(host, string::from_static(":"));
    }
    return host;
}

// go: none — goish-only: httpguts.isTokenTable, relocated. Diffed
// against the upstream 256-entry table; identical, 77 bytes each side.
pub(crate) fn isTokenByte(b: byte) -> bool {
    return matches!(b,
        b'!' | b'#' | b'$' | b'%' | b'&' | b'\'' | b'*' | b'+' | b'-' | b'.' |
        b'^' | b'_' | b'`' | b'|' | b'~' |
        b'0'..=b'9' | b'A'..=b'Z' | b'a'..=b'z');
}

// go: sdk 1.25.5 net/http/http.go:122-124 isNotToken
pub fn isNotToken(r: rune) -> bool {
    // Go: !httpguts.IsTokenRune(r), which is
    // `r < utf8.RuneSelf && isTokenTable[byte(r)]`.
    return !(r < crate::int32(utf8::RuneSelf) && isTokenByte(crate::byte(r)));
}

// go: sdk 1.25.5 net/http/http.go:127-130 isToken
/// Go: "isToken reports whether v is a valid token
/// (https://www.rfc-editor.org/rfc/rfc2616#section-2.2). For historical
/// reasons, this function is called ValidHeaderFieldName (see issue
/// #67031)."
pub fn isToken(v: &string) -> bool {
    // httpguts.ValidHeaderFieldName rejects the empty string first,
    // then walks BYTES — not runes. An earlier note here claimed the
    // rune walk as a goish deviation; there is no deviation.
    if v.Len() == 0 {
        return false;
    }
    let mut i: int = 0;
    while i < v.Len() {
        if !isTokenByte(v[i]) {
            return false;
        }
        i += 1;
    }
    return true;
}

// go: sdk 1.25.5 net/http/http.go:133-141 stringContainsCTLByte
/// Go: "stringContainsCTLByte reports whether s contains any ASCII
/// control character."
pub fn stringContainsCTLByte(s: &string) -> bool {
    let mut i: int = 0;
    while i < s.Len() {
        let b = s[i];
        if b < b' ' || b == 0x7f {
            return true;
        }
        i += 1;
    }
    return false;
}

// go: sdk 1.25.5 net/http/http.go:143-171 hexEscapeNonASCII
pub fn hexEscapeNonASCII<S: Into<string>>(s: S) -> string {
    let s: string = s.into();
    let mut newLen: int = 0;
    let mut i: int = 0;
    while i < s.Len() {
        if s[i] >= utf8::RuneSelf {
            newLen += 3;
        } else {
            newLen += 1;
        }
        i += 1;
    }
    if newLen == s.Len() {
        return s;
    }
    let mut b = make!([]byte, 0, newLen);
    let mut pos: int = 0;
    i = 0;
    while i < s.Len() {
        if s[i] >= utf8::RuneSelf {
            if pos < i {
                let chunk = string::from_bytes(
                    &s.as_bytes()[crate::builtin::__make_size(pos)..crate::builtin::__make_size(i)],
                );
                let mut j: int = 0;
                while j < chunk.Len() {
                    b = append!(b, chunk[j]);
                    j += 1;
                }
            }
            b = append!(b, b'%');
            b = strconv::AppendInt(b, crate::int64(s[i]), 16);
            pos = i + 1;
        }
        i += 1;
    }
    if pos < s.Len() {
        let tail = string::from_bytes(&s.as_bytes()[crate::builtin::__make_size(pos)..]);
        let mut j: int = 0;
        while j < tail.Len() {
            b = append!(b, tail[j]);
            j += 1;
        }
    }
    return crate::convert::string(b);
}

// ─── NoBody ──────────────────────────────────────────────────────

// go: sdk 1.25.5 net/http/http.go:179-179 noBody
#[derive(Copy, Clone, Default)]
pub struct noBody {}

// go: sdk 1.25.5 net/http/http.go:177-177 NoBody
/// Go: "NoBody is an [io.ReadCloser] with no bytes. Read always returns
/// EOF and Close always returns nil. It can be used in an outgoing
/// client request to explicitly signal that a request has zero bytes.
/// An alternative, however, is to simply set [Request.Body] to nil."
///
/// A `var` in Go and a value, not a call: `http.NoBody`, not
/// `http.NoBody()`. noBody is a zero-sized type, so a const gives that
/// spelling exactly.
pub const NoBody: noBody = noBody {};

impl crate::io::Reader for noBody {
    // go: none — goish idiom: the hidden Any-view hooks every
    // `#[goish::interface]` concrete impl overrides so an assertion on
    // a `dyn io::Reader` / `dyn io::Writer` can reach this type. Go's
    // itabs make them unnecessary. Without the MUTABLE one, `io::Copy`
    // misses `src.(WriterTo)` / `dst.(ReaderFrom)` and the fast-path
    // impl on this type is unreachable through the interface.
    fn __goish_as_dyn_any(&self) -> Option<&(dyn core::any::Any + Send + Sync)> {
        return Some(self);
    }
    // go: none — goish idiom: see `__goish_as_dyn_any`.
    fn __goish_as_dyn_any_mut(&mut self) -> Option<&mut (dyn core::any::Any + Send + Sync)> {
        return Some(self);
    }

    // go: sdk 1.25.5 net/http/http.go:181-181 noBody.Read
    fn Read(&mut self, _p: &mut crate::slice<byte>) -> (int, crate::error) {
        return (0, crate::io::EOF.into());
    }
}

impl crate::io::Closer for noBody {
    // go: sdk 1.25.5 net/http/http.go:182-182 noBody.Close
    fn Close(&mut self) -> crate::error {
        return crate::errors::nil;
    }
}

impl crate::io::WriterTo for noBody {
    // go: sdk 1.25.5 net/http/http.go:183-183 noBody.WriteTo
    fn WriteTo(&mut self, _w: &mut dyn crate::io::Writer) -> (int64, crate::error) {
        return (0, crate::errors::nil);
    }
}

// ─── HTTP/2 server push ──────────────────────────────────────────

// go: sdk 1.25.5 net/http/http.go:192-201 PushOptions
/// Go: "PushOptions describes options for [Pusher.Push]."
#[derive(Clone)]
pub struct PushOptions {
    /// Go: "Method specifies the HTTP method for the promised request.
    /// If set, it must be "GET" or "HEAD". Empty means "GET"."
    pub Method: string,

    /// Go: "Header specifies additional promised request headers. This
    /// cannot include HTTP/2 pseudo header fields like ":path" and
    /// ":scheme", which will be added automatically."
    pub Header: Header,
}

// go: sdk 1.25.5 net/http/http.go:206-232 Pusher
/// Go: "Pusher is the interface implemented by ResponseWriters that
/// support HTTP/2 server push."
///
/// goish serves HTTP/1.x only, so nothing implements it — which is also
/// true of Go's own HTTP/1 `*response`.
#[goish::interface] // goishlint:ignore GOISH022 - `goish::interface`, not `goish::int`
pub trait Pusher {
    /// Go: "Push initiates an HTTP/2 server push. Push returns
    /// ErrNotSupported if the client has disabled push or if push is
    /// not supported on the underlying connection."
    fn Push(&self, target: string, opts: PushOptions) -> crate::error;
}

// go: sdk 1.25.5 net/http/http.go:236-297 HTTP2Config
/// Go: "HTTP2Config defines HTTP/2 configuration parameters common to
/// both [Transport] and [Server]."
///
/// Carried for shape only: goish has no HTTP/2 implementation to read
/// it, so a Server or Transport holding one behaves as Go's does with
/// HTTP/2 disabled.
#[derive(Clone, Default)]
pub struct HTTP2Config {
    /// Go: "optionally specifies the number of concurrent streams that
    /// a peer may have open at a time. If zero, defaults to at least
    /// 100."
    pub MaxConcurrentStreams: int,

    /// Go: "an upper limit for the size of the header compression table
    /// used for decoding headers sent by the peer."
    pub MaxDecoderHeaderTableSize: int,

    /// Go: "the header compression table used for sending headers to
    /// the peer."
    pub MaxEncoderHeaderTableSize: int,

    /// Go: "the largest frame this endpoint is willing to read. A valid
    /// value is between 16KiB and 16MiB, inclusive."
    pub MaxReadFrameSize: int,

    /// Go: "the maximum size of the flow control window for data
    /// received on a connection."
    pub MaxReceiveBufferPerConnection: int,

    /// Go: "the maximum size of the flow control window for data
    /// received on a stream (request)."
    pub MaxReceiveBufferPerStream: int,

    /// Go: "the timeout after which a health check using a ping frame
    /// will be carried out if no frame is received on a connection."
    pub SendPingTimeout: crate::time::Duration,

    /// Go: "the timeout after which a connection will be closed if a
    /// response to a ping is not received. If zero, a default of 15
    /// seconds is used."
    pub PingTimeout: crate::time::Duration,

    /// Go: "the timeout after which a connection will be closed if no
    /// data can be written to it."
    pub WriteByteTimeout: crate::time::Duration,

    /// Go: "if true, permits the use of cipher suites prohibited by the
    /// HTTP/2 spec."
    pub PermitProhibitedCipherSuites: bool,

    /// Go: "if non-nil, is called on HTTP/2 errors. It is intended to
    /// increment a metric for monitoring."
    pub CountError: Option<alloc::sync::Arc<dyn Fn(string) + Send + Sync>>,
}

extern crate alloc;

// go: none — goish-only: golang.org/x/net/http/httpguts is not ported.
// This is `httpguts.ValidTrailerHeader` (guts.go:20) with its
// `badTrailer` table relocated entry for entry — the same treatment
// httpguts' token table gets above. RFC 7230 §4.1.2 is the authority.
//
// Was a private copy in httptest/recorder.rs; server.go's
// declareTrailer needs it too, so it lives here rather than being
// duplicated.
pub fn ValidTrailerHeader(name: &crate::gostring::string) -> bool {
    let name = super::header::CanonicalHeaderKey(name.clone());
    if crate::strings::HasPrefix(name.clone(), crate::string("If-")) {
        return false;
    }
    let bad: [&str; 21] = [
        "Authorization",
        "Cache-Control",
        "Connection",
        "Content-Encoding",
        "Content-Length",
        "Content-Range",
        "Content-Type",
        "Expect",
        "Host",
        "Keep-Alive",
        "Max-Forwards",
        "Pragma",
        "Proxy-Authenticate",
        "Proxy-Authorization",
        "Proxy-Connection",
        "Range",
        "Realm",
        "Te",
        "Trailer",
        "Transfer-Encoding",
        "Www-Authenticate",
    ];
    for b in bad.iter() {
        if name == *b {
            return false;
        }
    }
    return true;
}

// go: none — goish-only: `httpguts.ValidHeaderFieldValue`
// (httplex.go:303), relocated like the other httpguts helpers here.
// Go: reject any CTL byte that is not linear whitespace, i.e. every
// byte < 0x20 except TAB, plus DEL. This is the check that stops a
// header value carrying a raw CR or LF onto the wire.
pub fn ValidHeaderFieldValue(v: &crate::gostring::string) -> bool {
    let b = v.as_bytes();
    let mut i: usize = 0;
    while i < b.len() {
        let c = b[i];
        // isCTL(b) && !isLWS(b)
        if (c < 0x20 || c == 0x7f) && c != b'\t' {
            return false;
        }
        i += 1;
    }
    return true;
}
