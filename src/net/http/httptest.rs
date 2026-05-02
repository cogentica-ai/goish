// net/http/httptest — utilities for HTTP testing.
//
// Reference: /share/go/src/net/http/httptest/httptest.go.
//
// Phase A (this file): NewRequest + NewRequestWithContext only.
// Phase B (deferred — task #166): ResponseRecorder, NewServer.
// ResponseRecorder is blocked on the ResponseWriter trait refactor.

#![allow(non_snake_case)]

extern crate alloc;

use alloc::sync::Arc;

use crate::errors;
use crate::goslice::slice;
use crate::gostring::string;
use crate::net::http::client::NewRequest as http_NewRequest;
use crate::net::http::request::Request;
use crate::types::byte;

/// Line-by-line port of `httptest.NewRequest(method, target, body)`
/// (httptest.go:19). Builds an incoming-server Request suitable for
/// passing to a Handler in tests.
///
/// Slim deviations from upstream:
///   - body is a `slice<byte>` (matches goish slim NewRequest), not an
///     io.Reader, so the `case *bytes.Buffer / *bytes.Reader / ...`
///     ContentLength inference collapses to `len(body)`.
///   - The TLS branch from httptest.go:91 is dropped — goish v1 has no
///     `tls.ConnectionState`.
///   - Error → panic translation from httptest.go:52 dropped: callers
///     get a Request with empty fields plus a nil-check-able error.
pub fn NewRequest<M: Into<string>, T: Into<string>>(method: M, target: T, body: slice<byte>) -> Request {
    let method: string = method.into();
    let target: string = target.into();
    NewRequestWithContext(crate::context::Background(), method, target, body)
}

/// `httptest.NewRequestWithContext` (httptest.go:46).
pub fn NewRequestWithContext<M: Into<string>, T: Into<string>>(_ctx: Arc<dyn crate::context::Context>, method: M, target: T, body: slice<byte>) -> Request {
    let method: string = method.into();
    let target: string = target.into();
    // Go: if method == "" { method = "GET" }
    let m = if method.Len() == 0 {
        string::from_static("GET")
    } else {
        method
    };
    // Go: req, err := http.ReadRequest(bufio.NewReader(strings.NewReader(method + " " + target + " HTTP/1.0\r\n\r\n")))
    // Slim: skip the synthetic-line+ReadRequest pump — call slim
    // NewRequest directly with the URL target. This shares the URL
    // parser already exercised by the real client path.
    let (mut req, err) = http_NewRequest(m, target.clone(), body);
    if !err.IsNil() {
        // httptest.go:52 panics on parse errors. We surface a Request
        // with an empty Method to let callers detect the failure.
        return Request {
            Method: string::new(),
            ..req
        };
    }

    // Go: req.Proto = "HTTP/1.1"; req.ProtoMinor = 1; req.Close = false
    req.Proto = string::from_static("HTTP/1.1");
    req.ProtoMajor = 1;
    req.ProtoMinor = 1;

    // Go: req.RemoteAddr = "192.0.2.1:1234"  (RFC 5737 TEST-NET)
    req.RemoteAddr = string::from_static("192.0.2.1:1234");

    // Go: if req.Host == "" { req.Host = "example.com" }
    if req.Host.Len() == 0 {
        req.Host = string::from_static("example.com");
    }

    // TLS branch dropped — goish v1 has no tls.ConnectionState.
    let _ = errors::nil; // silence unused-import in some builds
    let _ = target;

    req
}
