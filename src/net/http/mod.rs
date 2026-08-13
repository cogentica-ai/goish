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


pub mod client;
pub mod cookie;
pub mod cookiejar;
pub mod csrf;
pub mod fs;
pub mod header;
pub mod http;
pub mod httptest;
pub mod httptrace;
pub mod httputil;
pub mod internal;
pub mod jar;
pub mod method;
pub mod pattern;
pub mod request;
pub mod response;
pub mod server;
pub mod server_tls;
pub mod sniff;
pub mod status;
pub mod url;

pub use client::{
    Client, DialContextFn, Get, Head, NewRequest, NewRequestWithContext, Post, PostForm,
    Body, ProxyFromEnvironment, ProxyResolver, ReadResponse, Response, RoundTripper, Transport,
};
pub use cookie::{
    Cookie, ParseCookie, ParseSetCookie, SameSite, SameSiteDefaultMode, SameSiteLaxMode,
    SameSiteNoneMode, SameSiteStrictMode, SetCookie,
};
pub use csrf::{
    errCrossOriginRequest, errCrossOriginRequestFromOldBrowser, CrossOriginProtection,
    NewCrossOriginProtection,
};
pub use fs::{Dir, FileServer, HttpRange, NewDir, ParseRange, ServeFile};
pub use header::{CanonicalHeaderKey, Header, ParseTime, TimeFormat};
pub use jar::CookieJar;
pub use method::{
    MethodConnect, MethodDelete, MethodGet, MethodHead, MethodOptions, MethodPatch, MethodPost,
    MethodPut, MethodTrace,
};
pub use http::{HTTP2Config, NoBody, Protocols, PushOptions, Pusher};
pub use request::{
    ErrHeaderTooLong, ErrMaxBytes, ErrMissingBoundary, ErrMissingContentLength, ErrMissingFile,
    ErrNoCookie, ErrNotMultipart, ErrNotSupported, ErrShortBody, ErrUnexpectedTrailer,
    MaxBytesError, MaxBytesReader, NewMaxBytesError, NewMaxBytesReader, ParseHTTPVersion,
    ProtocolError, ReadRequest, Request,
};
pub use response::{
    Flusher, HeaderHandle, Hijacker, ResponseWriter,
};
pub use httputil::NewSingleHostReverseProxy;
pub use server::{
    handler, AllowQuerySemicolons, DefaultServeMux, ErrAbortHandler, ErrBodyNotAllowed,
    ErrContentLength, ErrHandlerTimeout, ErrHijacked, ErrServerClosed, Error, Handle, HandleFunc,
    Handler, HandlerFunc, ListenAndServe, NewServeMux, NotFound, NotFoundHandler, Redirect,
    RedirectHandler, Serve, ServeMux, Server, StripPrefix, TimeoutHandler,
};
pub use server_tls::ListenAndServeTLS;
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
pub use url::{
    JoinPath as JoinURLPath, Parse as ParseURL, ParseRequestURI, PathEscape, PathUnescape,
    QueryEscape, QueryUnescape, ResolvePath, User, UserPassword, Userinfo, ValuesEncode, ValuesHas,
    URL,
};
