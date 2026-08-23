// go: package net/http
//
// go: file net/http/omithttp2.go decls: init, http2Transport.RoundTrip, http2Transport.CloseIdleConnections, http2noDialH2RoundTripper.RoundTrip, http2clientConn.idleState, http2configureTransports, http2isNoCachedConnError, http2NewPriorityWriteScheduler, http2ConfigureServer, http2noCachedConnError.IsHTTP2NoCachedConnError, http2noCachedConnError.Error, http2goAwayTimeout
//
// Go: `//go:build nethttpomithttp2`
//
// net/http ships HTTP/2 twice behind complementary build constraints:
// `h2_bundle.go` (`!nethttpomithttp2`), the whole of
// golang.org/x/net/http2 bundled in at ~12k lines, and this file
// (`nethttpomithttp2`), 80 lines of stubs that panic. A build compiles
// exactly one.
//
// **goish takes this route**, and this file is the declaration of that.
// It is not a placeholder for a future HTTP/2: it is the configuration
// Go itself supports for a build without one, ported as written. The
// 483 declarations in h2_bundle.go are the road not taken — scaffolding
// for an implementation this tree does not contain — and port_coverage
// drops them from the denominator on exactly the evidence below, the
// same way it already drops the assembly side of a purego pair.
//
// Every function here panics or returns a zero value, because that is
// what Go's do. `noHTTP2` is Go's own comment: "should never see this".

#![allow(non_snake_case)]
#![allow(non_camel_case_types)]
#![allow(dead_code)]

extern crate alloc;

use alloc::sync::Arc;
use alloc::vec::Vec;

use crate::errors::error;
use crate::gomap::map;
use crate::gostring::string;
use crate::sync::Mutex;
use crate::types::uint32;

use super::client::Transport;
use super::request::Request;
use super::response::Response;

// go: sdk 1.25.5 net/http/omithttp2.go:15-17 init
/// Go: `func init() { omitBundledHTTP2 = true }`.
///
/// goish has no package `init`, and `omitBundledHTTP2` is therefore a
/// const rather than a var set at startup — see http.rs. The value it
/// holds is this one.
pub(crate) fn init() {
    debug_assert!(super::http::omitBundledHTTP2);
}

// go: sdk 1.25.5 net/http/omithttp2.go:19-19 noHTTP2
/// Go: "should never see this".
const noHTTP2: &str = "no bundled HTTP/2";

crate::var! {
    // go: sdk 1.25.5 net/http/omithttp2.go:21-21 http2errRequestCanceled
    pub(crate) http2errRequestCanceled: error = "net/http: request canceled";
}

// go: sdk 1.25.5 net/http/omithttp2.go:23-23 http2goAwayTimeout
pub(crate) fn http2goAwayTimeout() -> crate::time::Duration {
    return crate::time::Seconds(1);
}

// go: sdk 1.25.5 net/http/omithttp2.go:25-25 http2NextProtoTLS
pub(crate) const http2NextProtoTLS: &str = "h2";

// go: sdk 1.25.5 net/http/omithttp2.go:27-30 http2Transport
#[derive(Default)]
pub(crate) struct http2Transport {
    pub(crate) MaxHeaderListSize: uint32,
    pub(crate) ConnPool: Option<crate::goany::Any>,
}

impl http2Transport {
    // go: sdk 1.25.5 net/http/omithttp2.go:32-32 http2Transport.RoundTrip
    pub(crate) fn RoundTrip(&self, _r: &Request) -> (Response, error) {
        panic!("{}", noHTTP2);
    }

    // go: sdk 1.25.5 net/http/omithttp2.go:33-33 http2Transport.CloseIdleConnections
    pub(crate) fn CloseIdleConnections(&self) {}
}

// go: sdk 1.25.5 net/http/omithttp2.go:35-35 http2noDialH2RoundTripper
pub(crate) struct http2noDialH2RoundTripper;

impl http2noDialH2RoundTripper {
    // go: sdk 1.25.5 net/http/omithttp2.go:37-37 http2noDialH2RoundTripper.RoundTrip
    pub(crate) fn RoundTrip(&self, _r: &Request) -> (Response, error) {
        panic!("{}", noHTTP2);
    }
}

// go: sdk 1.25.5 net/http/omithttp2.go:39-41 http2noDialClientConnPool
pub(crate) struct http2noDialClientConnPool {
    pub(crate) http2clientConnPool: http2clientConnPool,
}

// go: sdk 1.25.5 net/http/omithttp2.go:43-46 http2clientConnPool
pub(crate) struct http2clientConnPool {
    pub(crate) mu: Arc<Mutex<()>>,
    pub(crate) conns: map<string, Vec<Arc<http2clientConn>>>,
}

// go: sdk 1.25.5 net/http/omithttp2.go:48-48 http2clientConn
pub(crate) struct http2clientConn;

// go: sdk 1.25.5 net/http/omithttp2.go:50-52 http2clientConnIdleState
#[derive(Default)]
pub(crate) struct http2clientConnIdleState {
    pub(crate) canTakeNewRequest: bool,
}

impl http2clientConn {
    // go: sdk 1.25.5 net/http/omithttp2.go:54-54 http2clientConn.idleState
    pub(crate) fn idleState(&self) -> http2clientConnIdleState {
        return http2clientConnIdleState::default();
    }
}

// go: sdk 1.25.5 net/http/omithttp2.go:56-56 http2configureTransports
pub(crate) fn http2configureTransports(_t: &Transport) -> (http2Transport, error) {
    panic!("{}", noHTTP2);
}

// go: sdk 1.25.5 net/http/omithttp2.go:58-61 http2isNoCachedConnError
/// Go asserts the error to `interface{ IsHTTP2NoCachedConnError() }`.
/// goish has no structural interface assertion, so this checks for the
/// one type in the tree that implements it — which is also the only one
/// Go can find, since the method is unexported-by-convention and
/// declared here.
pub(crate) fn http2isNoCachedConnError(err: &error) -> bool {
    let target: error = http2ErrNoCachedConn.into();
    return crate::errors::Is(err.clone(), target);
}

// go: sdk 1.25.5 net/http/omithttp2.go:63-65 http2Server
#[derive(Default)]
pub(crate) struct http2Server {
    pub(crate) NewWriteScheduler: Option<Arc<dyn Fn() -> http2WriteScheduler + Send + Sync>>,
}

// go: sdk 1.25.5 net/http/omithttp2.go:67-67 http2WriteScheduler
/// Go: `type http2WriteScheduler any`.
pub(crate) type http2WriteScheduler = Option<crate::goany::Any>;

// go: sdk 1.25.5 net/http/omithttp2.go:69-69 http2NewPriorityWriteScheduler
pub(crate) fn http2NewPriorityWriteScheduler(_: Option<crate::goany::Any>) -> http2WriteScheduler {
    panic!("{}", noHTTP2);
}

// go: sdk 1.25.5 net/http/omithttp2.go:71-71 http2ConfigureServer
pub(crate) fn http2ConfigureServer(_s: &super::server::Server, _conf: &http2Server) -> error {
    panic!("{}", noHTTP2);
}

crate::var! {
    // go: sdk 1.25.5 net/http/omithttp2.go:73-73 http2ErrNoCachedConn
    pub(crate) http2ErrNoCachedConn: error = "http2: no cached connection was available";
}

// go: sdk 1.25.5 net/http/omithttp2.go:75-75 http2noCachedConnError
pub(crate) struct http2noCachedConnError;

impl http2noCachedConnError {
    // go: sdk 1.25.5 net/http/omithttp2.go:77-77 http2noCachedConnError.IsHTTP2NoCachedConnError
    pub(crate) fn IsHTTP2NoCachedConnError(&self) {}

    // go: sdk 1.25.5 net/http/omithttp2.go:79-79 http2noCachedConnError.Error
    pub(crate) fn Error(&self) -> string {
        return string::from_static("http2: no cached connection was available");
    }
}
