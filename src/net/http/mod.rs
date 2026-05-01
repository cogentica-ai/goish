// net/http — Go's HTTP/1.x server, ported.
//
//   Go                                      goish
//   ─────────────────────────────────────   ──────────────────────────────────
//   http.ListenAndServe(":8080", h)         http::ListenAndServe(string(":8080"), &h)
//   http.HandleFunc("/", fn)                mux.HandleFunc(string("/"), fn)
//   http.ReadRequest(b)                     http::ReadRequest(&mut br)
//
// Phases:
//   M27c — request parser (this commit): URL, Header, Request,
//          ReadRequest. ports of net/url/url.go,
//          net/http/header.go, net/http/request.go.
//   M27d — server: ResponseWriter, Server, ServeMux, ListenAndServe.

#![allow(non_snake_case)]

pub mod chunked;
pub mod client;
pub mod cookie;
pub mod fs;
pub mod header;
pub mod httputil;
pub mod pattern;
pub mod request;
pub mod response;
pub mod server;
pub mod sniff;
pub mod status;
pub mod url;

pub use client::{
    Client, Get, Head, NewRequest, Post, PostForm, ReadResponse, Response, RoundTripper, Transport,
};
pub use cookie::{Cookie, ParseCookie, ParseSetCookie, SameSite, SetCookie};
pub use fs::{Dir, FileServer, NewDir, ServeFile};
pub use header::{CanonicalHeaderKey, Header, ParseTime, TimeFormat};
pub use request::{
    ErrMaxBytes, MaxBytesReader, NewMaxBytesReader, ParseHTTPVersion, ReadRequest, Request,
};
pub use response::ResponseWriter;
pub use server::{
    DefaultServeMux, Error, ErrServerClosed, Handle, HandleFunc, Handler, HandlerFunc,
    ListenAndServe, NotFound, NotFoundHandler, Redirect, RedirectHandler, Serve, ServeMux,
    Server, StripPrefix,
};
pub use sniff::DetectContentType;
pub use status::{
    StatusAccepted, StatusBadGateway, StatusBadRequest, StatusConflict, StatusContinue,
    StatusCreated, StatusEarlyHints, StatusExpectationFailed, StatusFailedDependency,
    StatusForbidden, StatusFound, StatusGatewayTimeout, StatusGone,
    StatusHTTPVersionNotSupported, StatusIMUsed, StatusInsufficientStorage,
    StatusInternalServerError, StatusLengthRequired, StatusLocked, StatusLoopDetected,
    StatusMethodNotAllowed, StatusMisdirectedRequest, StatusMovedPermanently,
    StatusMultiStatus, StatusMultipleChoices, StatusNetworkAuthenticationRequired,
    StatusNoContent, StatusNonAuthoritativeInfo, StatusNotAcceptable, StatusNotExtended,
    StatusNotFound, StatusNotImplemented, StatusNotModified, StatusOK, StatusPartialContent,
    StatusPaymentRequired, StatusPermanentRedirect, StatusPreconditionFailed,
    StatusPreconditionRequired, StatusProcessing, StatusProxyAuthRequired,
    StatusRequestEntityTooLarge, StatusRequestHeaderFieldsTooLarge, StatusRequestTimeout,
    StatusRequestURITooLong, StatusRequestedRangeNotSatisfiable, StatusResetContent,
    StatusSeeOther, StatusServiceUnavailable, StatusSwitchingProtocols, StatusTeapot,
    StatusTemporaryRedirect, StatusText, StatusTooEarly, StatusTooManyRequests,
    StatusUnauthorized, StatusUnavailableForLegalReasons, StatusUnprocessableEntity,
    StatusUnsupportedMediaType, StatusUpgradeRequired, StatusUseProxy,
    StatusVariantAlsoNegotiates, StatusAlreadyReported,
};
pub use url::URL;
