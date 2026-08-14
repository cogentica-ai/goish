// net/http/transfer — message-framing rules shared by requests and
// responses: how many body bytes to expect, whether the connection
// closes afterwards, and which headers a status suppresses.
//
// Partial port of Go 1.25.5 net/http/transfer.go. The framing
// DECISIONS port verbatim and are the security-sensitive half (RFC
// 9112 request smuggling and response splitting both live here). The
// framing MACHINERY — transferWriter, the `body` ReadCloser,
// readTransfer — does not port yet: it is built on `io.ReadCloser`
// bodies, whereas goish's Request/Response still carry `slice<byte>`.
// Those land with the Body redesign; see the module worklist below.
//
// Not yet ported from transfer.go (all Body-model dependent):
//   transferWriter and its 8 methods, newTransferWriter, readTransfer,
//   body + its 9 methods, bodyLocked, finishAsyncByteRead,
//   unwrapNopCloser, isKnownInMemoryReader, bufioFlushWriter.

#![allow(non_snake_case, non_camel_case_types)]

extern crate alloc;

use alloc::vec::Vec;

use crate::errors::{self, error};
use crate::goslice::slice;
use crate::string;
use crate::types::byte;
use crate::{int, int64};

use super::header::{hasToken, CanonicalHeaderKey, Header};

// go: sdk 1.25.5 net/http/transfer.go:31 ErrLineTooLong
//
// Go writes `var ErrLineTooLong = internal.ErrLineTooLong`, an ALIAS.
// Re-export rather than redeclare so `errors::Is` (which matches by
// Arc::ptr_eq) still succeeds against the internal sentinel.
pub use super::internal::chunked::ErrLineTooLong;

crate::var! {
    // go: sdk 1.25.5 net/http/transfer.go:829 ErrBodyReadAfterClose
    pub ErrBodyReadAfterClose: error = "http: invalid Read on closed Body";
}

// ─── trivial readers ────────────────────────────────────────────────

// go: sdk 1.25.5 net/http/transfer.go:33-35 errorReader
/// A reader that fails every Read with a fixed error.
pub struct errorReader {
    pub err: error,
}

impl crate::io::Reader for errorReader {
    // go: sdk 1.25.5 net/http/transfer.go:37-39 errorReader.Read
    fn Read(&mut self, _p: &mut slice<byte>) -> (int, error) {
        return (0, self.err.clone());
    }
}

// go: sdk 1.25.5 net/http/transfer.go:41-44 byteReader
/// A reader yielding exactly one byte, then EOF. Go returns the byte
/// AND `io.EOF` from the same call, which callers rely on.
pub struct byteReader {
    pub b: byte,
    pub done: bool,
}

impl crate::io::Reader for byteReader {
    // go: sdk 1.25.5 net/http/transfer.go:46-55 byteReader.Read
    fn Read(&mut self, p: &mut slice<byte>) -> (int, error) {
        if self.done {
            return (0, crate::io::EOF.into());
        }
        if p.Len() == 0 {
            return (0, errors::nil);
        }
        self.done = true;
        p[int(0)] = self.b;
        return (1, crate::io::EOF.into());
    }
}

// ─── transferReader ─────────────────────────────────────────────────

// go: sdk 1.25.5 net/http/transfer.go:440-453 transferReader
/// The inputs and outputs of reading a message's framing. Only the
/// header-derived half is populated today: `Body` waits on the Body
/// redesign, so `readTransfer` (which fills it) is not ported.
pub struct transferReader {
    // Input
    pub Header: Header,
    pub StatusCode: int,
    pub RequestMethod: string,
    pub ProtoMajor: int,
    pub ProtoMinor: int,
    // Output
    pub Body: Option<alloc::boxed::Box<dyn crate::io::ReadCloser>>,
    pub ContentLength: i64,
    pub Chunked: bool,
    pub Close: bool,
    pub Trailer: Header,
}

impl transferReader {
    // go: sdk 1.25.5 net/http/transfer.go:455-457 transferReader.protoAtLeast
    pub fn protoAtLeast(&self, m: int, n: int) -> bool {
        return self.ProtoMajor > m || (self.ProtoMajor == m && self.ProtoMinor >= n);
    }

    // go: sdk 1.25.5 net/http/transfer.go:631-658 transferReader.parseTransferEncoding
    /// Go: "parseTransferEncoding sets t.Chunked based on the
    /// Transfer-Encoding header."
    ///
    /// Go's comment is worth keeping verbatim: this is "one of the
    /// most security sensitive surfaces in HTTP/1.1 due to the risk of
    /// request smuggling, so we keep it strict and simple" — a single
    /// Transfer-Encoding header, and only if it is exactly `chunked`.
    pub fn parseTransferEncoding(&mut self) -> error {
        // Go: raw, present := t.Header["Transfer-Encoding"]
        if !self.Header.has(string("Transfer-Encoding")) {
            return errors::nil;
        }
        let raw = self.Header.Values(string("Transfer-Encoding"));
        self.Header.Del(string("Transfer-Encoding"));

        // Go: "Issue 12785; ignore Transfer-Encoding on HTTP/1.0
        // requests."
        if !self.protoAtLeast(1, 1) {
            return errors::nil;
        }

        if raw.Len() != 1 {
            return newUnsupportedTEError(crate::fmt::Sprintf!(
                "too many transfer encodings: %q",
                __quote_list(&raw)
            ));
        }
        if !super::internal::ascii::EqualFold(raw[int(0)].clone(), string("chunked")) {
            return newUnsupportedTEError(crate::fmt::Sprintf!(
                "unsupported transfer encoding: %q",
                raw[int(0)].clone()
            ));
        }

        self.Chunked = true;
        return errors::nil;
    }
}

// ─── status-driven rules ────────────────────────────────────────────

// go: sdk 1.25.5 net/http/transfer.go:250-252 noResponseBodyExpected
pub fn noResponseBodyExpected(requestMethod: string) -> bool {
    return requestMethod == "HEAD";
}

// go: sdk 1.25.5 net/http/transfer.go:459-471 bodyAllowedForStatus
/// Go: "bodyAllowedForStatus reports whether a given response status
/// code permits a body. See RFC 7230, section 3.3."
///
/// Note 99 and 205 DO permit a body — only 100..=199, 204 and 304 do
/// not. Verified against Go for 99/100/150/199/200/204/205/304/305/404.
pub fn bodyAllowedForStatus(status: int) -> bool {
    if status >= 100 && status <= 199 {
        return false;
    }
    if status == 204 {
        return false;
    }
    if status == 304 {
        return false;
    }
    return true;
}

// go: sdk 1.25.5 net/http/transfer.go:473-477 suppressedHeaders304
/// Go: RFC 7232 section 4.1 — a 304 must not carry these.
pub fn suppressedHeaders304() -> slice<string> {
    return slice::<string>::__from_vec(alloc::vec![
        string("Content-Type"),
        string("Content-Length"),
        string("Transfer-Encoding"),
    ]);
}

// go: sdk 1.25.5 net/http/transfer.go:473-477 suppressedHeadersNoBody
pub fn suppressedHeadersNoBody() -> slice<string> {
    return slice::<string>::__from_vec(alloc::vec![
        string("Content-Length"),
        string("Transfer-Encoding"),
    ]);
}

// go: sdk 1.25.5 net/http/transfer.go:473-477 excludedHeadersNoBody
pub fn excludedHeadersNoBody() -> crate::gomap::map<string, bool> {
    let mut m = crate::gomap::map::<string, bool>::new();
    m.Set(string("Content-Length"), true);
    m.Set(string("Transfer-Encoding"), true);
    return m;
}

// go: sdk 1.25.5 net/http/transfer.go:479-489 suppressedHeaders
/// Which headers must be dropped for `status`. Empty (Go's nil) when
/// the status permits a body.
pub fn suppressedHeaders(status: int) -> slice<string> {
    if status == 304 {
        // Go: RFC 7232 section 4.1
        return suppressedHeaders304();
    }
    if !bodyAllowedForStatus(status) {
        return suppressedHeadersNoBody();
    }
    return slice::<string>::new();
}

// ─── transfer-encoding predicates ───────────────────────────────────

// go: sdk 1.25.5 net/http/transfer.go:609 chunked
/// Go: "Checks whether chunked is part of the encodings stack."
///
/// Deliberately case-SENSITIVE and first-element-only, matching Go:
/// `["CHUNKED"]` is false, and so is `["gzip","chunked"]`.
pub fn chunked(te: &slice<string>) -> bool {
    return te.Len() > 0 && te[int(0)] == "chunked";
}

// go: sdk 1.25.5 net/http/transfer.go:612 isIdentity
/// Go: "Checks whether the encoding is explicitly \"identity\"."
pub fn isIdentity(te: &slice<string>) -> bool {
    return te.Len() == 1 && te[int(0)] == "identity";
}

// go: sdk 1.25.5 net/http/transfer.go:615-617 unsupportedTEError
//
// Go carries a distinct `*unsupportedTEError` struct so callers can
// type-assert it. goish's errors have no `errors::As`, so the port
// wraps a sentinel: `unsupportedTEError(msg)` builds an error whose
// Unwrap chain reaches `errUnsupportedTE`, and `isUnsupportedTEError`
// tests that with `errors::Is` — the shape recorded for typed errors
// generally.
crate::var! {
    pub(crate) errUnsupportedTE: error = "http: unsupported transfer encoding";
}

pub struct unsupportedTEError {
    pub err: string,
}

impl errors::ErrorTrait for unsupportedTEError {
    // go: sdk 1.25.5 net/http/transfer.go:619-621 unsupportedTEError.Error
    fn Error(&self) -> string {
        return self.err.clone();
    }
    // go: none — goish-only. Go type-asserts `*unsupportedTEError`;
    // goish has no errors::As, so the chain to a sentinel is what
    // `isUnsupportedTEError` matches on.
    fn Unwrap(&self) -> error {
        return errUnsupportedTE.into();
    }
}

// go: none — goish-only constructor: Go writes the composite literal
// `&unsupportedTEError{...}` inline, goish needs the errors::Wrap
// boxing step so it is named once here.
fn newUnsupportedTEError(msg: string) -> error {
    return errors::Wrap(unsupportedTEError { err: msg });
}

// go: sdk 1.25.5 net/http/transfer.go:625-628 isUnsupportedTEError
/// Go: "isUnsupportedTEError checks if the error is of type
/// unsupportedTEError. It is usually invoked with a non-nil err."
pub fn isUnsupportedTEError(err: error) -> bool {
    return errors::Is(err, errUnsupportedTE);
}

// ─── framing ────────────────────────────────────────────────────────

// go: sdk 1.25.5 net/http/transfer.go:661-743 fixLength
/// Go: "Determine the expected body length, using RFC 7230 Section
/// 3.3." Returns -1 for "read until EOF/end of chunks".
///
/// This is the request-smuggling hardening point. Two behaviours are
/// load-bearing and were checked against Go rather than inferred:
///   - duplicate Content-Length headers are an ERROR if they differ
///     after trimming, and are DEDUPLICATED if they agree
///     (`["5"," 5 "]` collapses to `["5"]`, n=5);
///   - when Transfer-Encoding is chunked, Content-Length is DELETED
///     from the header and -1 returned, so the two can never both be
///     honoured downstream (RFC 9112).
pub fn fixLength(
    isResponse: bool,
    status: int,
    requestMethod: string,
    header: &mut Header,
    chunked_: bool,
) -> (i64, error) {
    let isRequest = !isResponse;
    let mut contentLens = header.Values(string("Content-Length"));

    // Go: "Hardening against HTTP request smuggling"
    if contentLens.Len() > 1 {
        // Go: "Per RFC 7230 Section 3.3.2, prevent multiple
        // Content-Length headers if they differ in value. If there are
        // dups of the value, remove the dups. See Issue 16490."
        let first = crate::net::textproto::TrimString(contentLens[int(0)].clone());
        for i in 1..contentLens.Len() {
            let ct = crate::net::textproto::TrimString(contentLens[int(i)].clone());
            if first != ct {
                return (
                    0,
                    crate::fmt::Errorf!(
                        "http: message cannot contain multiple Content-Length headers; got %s",
                        __quote_list(&contentLens)
                    ),
                );
            }
        }

        // Go: deduplicate Content-Length
        header.Del(string("Content-Length"));
        header.Add(string("Content-Length"), first);

        contentLens = header.Values(string("Content-Length"));
    }

    // Go: "Reject requests with invalid Content-Length headers."
    let mut n: i64 = 0;
    if contentLens.Len() > 0 {
        let (parsed, err) = parseContentLength(&contentLens);
        if !err.IsNil() {
            return (-1, err);
        }
        n = parsed;
    }

    // Go: "Logic based on response type or status"
    if isResponse && noResponseBodyExpected(requestMethod) {
        return (0, errors::nil);
    }
    if status / 100 == 1 {
        return (0, errors::nil);
    }
    if status == 204 || status == 304 {
        return (0, errors::nil);
    }

    // Go: RFC 9112 — "If a message is received with both a
    // Transfer-Encoding and a Content-Length header field, the
    // Transfer-Encoding overrides the Content-Length."
    if chunked_ {
        header.Del(string("Content-Length"));
        return (-1, errors::nil);
    }

    // Go: "Logic based on Content-Length"
    if contentLens.Len() > 0 {
        return (n, errors::nil);
    }

    header.Del(string("Content-Length"));

    if isRequest {
        // Go: "RFC 7230 neither explicitly permits nor forbids an
        // entity-body on a GET request so we permit one if declared,
        // but we default to 0 here (not -1 below) if there's no
        // mention of a body."
        return (0, errors::nil);
    }

    // Go: "Body-EOF logic based on other methods (like closing, or
    // chunked coding)"
    return (-1, errors::nil);
}

// go: sdk 1.25.5 net/http/transfer.go:745-765 shouldClose
/// Go: "Determine whether to hang up after sending a request and body,
/// or receiving a response and body."
///
/// Go calls `httpguts.HeaderValuesContainsToken`, which scans the FULL
/// value list case-insensitively. goish has no httpguts; `hasToken`
/// is the substitute and requires a LOWERCASE token, so the loop below
/// passes `"close"` / `"keep-alive"` and never the header spelling.
pub fn shouldClose(
    major: int,
    minor: int,
    header: &mut Header,
    removeCloseHeader: bool,
) -> bool {
    if major < 1 {
        return true;
    }

    let conv = header.Values(string("Connection"));
    let hasClose = __values_contain_token(&conv, "close");
    if major == 1 && minor == 0 {
        return hasClose || !__values_contain_token(&conv, "keep-alive");
    }

    if hasClose && removeCloseHeader {
        header.Del(string("Connection"));
    }

    return hasClose;
}

// go: sdk 1.25.5 net/http/transfer.go:767-805 fixTrailer
/// Go: "Parse the trailer header." Returns an empty Header (Go's nil)
/// when there is no usable trailer — including the `Trailer` present
/// but not chunked case, which Go deliberately does NOT treat as an
/// error (issue #27197).
pub fn fixTrailer(header: &mut Header, chunked_: bool) -> (Header, error) {
    if !header.has(string("Trailer")) {
        return (Header::new(), errors::nil);
    }
    let vv = header.Values(string("Trailer"));
    if !chunked_ {
        // Go: "Trailer and no chunking: this is an invalid use case
        // for trailer header. Nevertheless, no error will be returned
        // and we let users decide if this is a valid HTTP message."
        return (Header::new(), errors::nil);
    }
    header.Del(string("Trailer"));

    let mut trailer = Header::new();
    let mut err: error = errors::nil;
    for i in 0..vv.Len() {
        let v = vv[int(i)].clone();
        super::server::foreachHeaderElement(v, |key: string| {
            let key = CanonicalHeaderKey(key);
            if key == "Transfer-Encoding" || key == "Trailer" || key == "Content-Length" {
                // Go's guard reads `if err == nil { err = …; return }`,
                // so only the FIRST bad key is reported.
                if err.IsNil() {
                    err = super::request::badStringError("bad trailer key", key);
                    return;
                }
            }
            trailer.__set_values(key, slice::<string>::new());
        });
    }
    if !err.IsNil() {
        return (Header::new(), err);
    }
    if trailer.Len() == 0 {
        return (Header::new(), errors::nil);
    }
    return (trailer, errors::nil);
}

// go: sdk 1.25.5 net/http/transfer.go:953-960 mergeSetHeader
/// Go takes `dst *Header` and replaces it wholesale when nil. goish's
/// `Header` has no nil state, so an empty `dst` takes `src` entire —
/// the same observable result.
pub fn mergeSetHeader(dst: &mut Header, src: Header) {
    if dst.Len() == 0 {
        *dst = src;
        return;
    }
    for (k, v) in crate::range!(&src) {
        dst.__set_values(k.clone(), v.clone());
    }
    return;
}

// go: sdk 1.25.5 net/http/transfer.go:894-907 seeUpcomingDoubleCRLF
/// Go: peek forward until the buffer is full, looking for the blank
/// line that ends a trailer block.
pub fn seeUpcomingDoubleCRLF<R: crate::io::Reader>(
    r: &mut crate::bufio::Reader<R>,
) -> bool {
    let mut peekSize: int = 4;
    loop {
        // Go: "This loop stops when Peek returns an error, which it
        // does when r's buffer has been filled."
        let (buf, err) = r.Peek(peekSize);
        if crate::bytes::HasSuffix(buf.clone(), crate::convert::bytes("\r\n\r\n")) {
            return true;
        }
        if !err.IsNil() {
            break;
        }
        peekSize += 1;
    }
    return false;
}

// go: sdk 1.25.5 net/http/transfer.go:1046-1069 parseContentLength
/// Go: "parseContentLength checks that the header is valid and then
/// trims whitespace. It returns -1 if no value is set otherwise the
/// value if it's >= 0."
///
/// Only the FIRST value is consulted — `["1","2"]` yields 1, not an
/// error; `fixLength` is what rejects disagreeing duplicates. The
/// bound is `ParseUint(cl, 10, 63)`, so 2^63-1 parses and a negative
/// or non-numeric value does not. The `httplaxcontentlength` GODEBUG
/// escape hatch is not ported (goish has no godebug); goish always
/// takes Go's default branch and rejects an empty value.
pub fn parseContentLength(clHeaders: &slice<string>) -> (i64, error) {
    if clHeaders.Len() == 0 {
        return (-1, errors::nil);
    }
    let cl = crate::net::textproto::TrimString(clHeaders[int(0)].clone());

    // Go: "The Content-Length must be a valid numeric value."
    if cl == "" {
        return (
            0,
            super::request::badStringError("invalid empty Content-Length", cl),
        );
    }
    let (n, err) = crate::strconv::ParseUint(cl.clone(), 10, 63);
    if !err.IsNil() {
        return (0, super::request::badStringError("bad Content-Length", cl));
    }
    return (int64(n), errors::nil);
}

// ─── goish-only helpers ─────────────────────────────────────────────

// go: none — goish-only. Go gets `%q` on a []string for free from fmt;
// goish's Sprintf has no slice verb, so render Go's exact
// `["a" "b"]` spelling by hand for the two error messages that use it.
fn __quote_list(v: &slice<string>) -> string {
    let mut out: Vec<u8> = Vec::new();
    out.push(b'[');
    for i in 0..v.Len() {
        if i > 0 {
            out.push(b' ');
        }
        out.push(b'"');
        out.extend_from_slice(v[int(i)].as_bytes());
        out.push(b'"');
    }
    out.push(b']');
    return string::from_bytes(&out);
}

// go: none — goish-only. Stands in for
// `httpguts.HeaderValuesContainsToken(values, token)`: scan every
// entry of the header's value list, not just the joined first one.
// `token` MUST be lowercase — that is `hasToken`'s precondition.
fn __values_contain_token(values: &slice<string>, token: &'static str) -> bool {
    for i in 0..values.Len() {
        if hasToken(values[int(i)].clone(), string(token)) {
            return true;
        }
    }
    return false;
}
