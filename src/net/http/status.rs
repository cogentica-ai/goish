// go: package net/http
//
// go: file net/http/status.go decls: StatusText
//
// Go: "HTTP status codes as registered with IANA."
// See: https://www.iana.org/assignments/http-status-codes/http-status-codes.xhtml
//
// StatusText switches on the NAMED constants, as Go does, rather than
// on the numbers. Both spellings compile; only this one keeps a
// mistyped constant from producing a status line whose code and
// reason phrase disagree, because there is then one place the number
// is written down.

#![allow(non_snake_case)]
#![allow(dead_code)]

use crate::string;
use crate::types::int;

// ─── status code constants ──────────────────────────────────────────

// go: sdk 1.25.5 net/http/status.go:9-77 StatusContinue
pub const StatusContinue: int = 100; // RFC 9110, 15.2.1
// go: sdk 1.25.5 net/http/status.go:9-77 StatusSwitchingProtocols
pub const StatusSwitchingProtocols: int = 101; // RFC 9110, 15.2.2
// go: sdk 1.25.5 net/http/status.go:9-77 StatusProcessing
pub const StatusProcessing: int = 102; // RFC 2518, 10.1
// go: sdk 1.25.5 net/http/status.go:9-77 StatusEarlyHints
pub const StatusEarlyHints: int = 103; // RFC 8297

// go: sdk 1.25.5 net/http/status.go:9-77 StatusOK
pub const StatusOK: int = 200; // RFC 9110, 15.3.1
// go: sdk 1.25.5 net/http/status.go:9-77 StatusCreated
pub const StatusCreated: int = 201; // RFC 9110, 15.3.2
// go: sdk 1.25.5 net/http/status.go:9-77 StatusAccepted
pub const StatusAccepted: int = 202; // RFC 9110, 15.3.3
// go: sdk 1.25.5 net/http/status.go:9-77 StatusNonAuthoritativeInfo
pub const StatusNonAuthoritativeInfo: int = 203; // RFC 9110, 15.3.4
// go: sdk 1.25.5 net/http/status.go:9-77 StatusNoContent
pub const StatusNoContent: int = 204; // RFC 9110, 15.3.5
// go: sdk 1.25.5 net/http/status.go:9-77 StatusResetContent
pub const StatusResetContent: int = 205; // RFC 9110, 15.3.6
// go: sdk 1.25.5 net/http/status.go:9-77 StatusPartialContent
pub const StatusPartialContent: int = 206; // RFC 9110, 15.3.7
// go: sdk 1.25.5 net/http/status.go:9-77 StatusMultiStatus
pub const StatusMultiStatus: int = 207; // RFC 4918, 11.1
// go: sdk 1.25.5 net/http/status.go:9-77 StatusAlreadyReported
pub const StatusAlreadyReported: int = 208; // RFC 5842, 7.1
// go: sdk 1.25.5 net/http/status.go:9-77 StatusIMUsed
pub const StatusIMUsed: int = 226; // RFC 3229, 10.4.1

// go: sdk 1.25.5 net/http/status.go:9-77 StatusMultipleChoices
pub const StatusMultipleChoices: int = 300; // RFC 9110, 15.4.1
// go: sdk 1.25.5 net/http/status.go:9-77 StatusMovedPermanently
pub const StatusMovedPermanently: int = 301; // RFC 9110, 15.4.2
// go: sdk 1.25.5 net/http/status.go:9-77 StatusFound
pub const StatusFound: int = 302; // RFC 9110, 15.4.3
// go: sdk 1.25.5 net/http/status.go:9-77 StatusSeeOther
pub const StatusSeeOther: int = 303; // RFC 9110, 15.4.4
// go: sdk 1.25.5 net/http/status.go:9-77 StatusNotModified
pub const StatusNotModified: int = 304; // RFC 9110, 15.4.5
// go: sdk 1.25.5 net/http/status.go:9-77 StatusUseProxy
pub const StatusUseProxy: int = 305; // RFC 9110, 15.4.6
// go: none — Go writes `_ = 306 // RFC 9110, 15.4.7 (Unused)` to keep
// the blank code visible in the list. There is no name to bind, and
// `pub const _` would be a different thing, so the comment carries it.
// go: sdk 1.25.5 net/http/status.go:9-77 StatusTemporaryRedirect
pub const StatusTemporaryRedirect: int = 307; // RFC 9110, 15.4.8
// go: sdk 1.25.5 net/http/status.go:9-77 StatusPermanentRedirect
pub const StatusPermanentRedirect: int = 308; // RFC 9110, 15.4.9

// go: sdk 1.25.5 net/http/status.go:9-77 StatusBadRequest
pub const StatusBadRequest: int = 400; // RFC 9110, 15.5.1
// go: sdk 1.25.5 net/http/status.go:9-77 StatusUnauthorized
pub const StatusUnauthorized: int = 401; // RFC 9110, 15.5.2
// go: sdk 1.25.5 net/http/status.go:9-77 StatusPaymentRequired
pub const StatusPaymentRequired: int = 402; // RFC 9110, 15.5.3
// go: sdk 1.25.5 net/http/status.go:9-77 StatusForbidden
pub const StatusForbidden: int = 403; // RFC 9110, 15.5.4
// go: sdk 1.25.5 net/http/status.go:9-77 StatusNotFound
pub const StatusNotFound: int = 404; // RFC 9110, 15.5.5
// go: sdk 1.25.5 net/http/status.go:9-77 StatusMethodNotAllowed
pub const StatusMethodNotAllowed: int = 405; // RFC 9110, 15.5.6
// go: sdk 1.25.5 net/http/status.go:9-77 StatusNotAcceptable
pub const StatusNotAcceptable: int = 406; // RFC 9110, 15.5.7
// go: sdk 1.25.5 net/http/status.go:9-77 StatusProxyAuthRequired
pub const StatusProxyAuthRequired: int = 407; // RFC 9110, 15.5.8
// go: sdk 1.25.5 net/http/status.go:9-77 StatusRequestTimeout
pub const StatusRequestTimeout: int = 408; // RFC 9110, 15.5.9
// go: sdk 1.25.5 net/http/status.go:9-77 StatusConflict
pub const StatusConflict: int = 409; // RFC 9110, 15.5.10
// go: sdk 1.25.5 net/http/status.go:9-77 StatusGone
pub const StatusGone: int = 410; // RFC 9110, 15.5.11
// go: sdk 1.25.5 net/http/status.go:9-77 StatusLengthRequired
pub const StatusLengthRequired: int = 411; // RFC 9110, 15.5.12
// go: sdk 1.25.5 net/http/status.go:9-77 StatusPreconditionFailed
pub const StatusPreconditionFailed: int = 412; // RFC 9110, 15.5.13
// go: sdk 1.25.5 net/http/status.go:9-77 StatusRequestEntityTooLarge
pub const StatusRequestEntityTooLarge: int = 413; // RFC 9110, 15.5.14
// go: sdk 1.25.5 net/http/status.go:9-77 StatusRequestURITooLong
pub const StatusRequestURITooLong: int = 414; // RFC 9110, 15.5.15
// go: sdk 1.25.5 net/http/status.go:9-77 StatusUnsupportedMediaType
pub const StatusUnsupportedMediaType: int = 415; // RFC 9110, 15.5.16
// go: sdk 1.25.5 net/http/status.go:9-77 StatusRequestedRangeNotSatisfiable
pub const StatusRequestedRangeNotSatisfiable: int = 416; // RFC 9110, 15.5.17
// go: sdk 1.25.5 net/http/status.go:9-77 StatusExpectationFailed
pub const StatusExpectationFailed: int = 417; // RFC 9110, 15.5.18
// go: sdk 1.25.5 net/http/status.go:9-77 StatusTeapot
pub const StatusTeapot: int = 418; // RFC 9110, 15.5.19 (Unused)
// go: sdk 1.25.5 net/http/status.go:9-77 StatusMisdirectedRequest
pub const StatusMisdirectedRequest: int = 421; // RFC 9110, 15.5.20
// go: sdk 1.25.5 net/http/status.go:9-77 StatusUnprocessableEntity
pub const StatusUnprocessableEntity: int = 422; // RFC 9110, 15.5.21
// go: sdk 1.25.5 net/http/status.go:9-77 StatusLocked
pub const StatusLocked: int = 423; // RFC 4918, 11.3
// go: sdk 1.25.5 net/http/status.go:9-77 StatusFailedDependency
pub const StatusFailedDependency: int = 424; // RFC 4918, 11.4
// go: sdk 1.25.5 net/http/status.go:9-77 StatusTooEarly
pub const StatusTooEarly: int = 425; // RFC 8470, 5.2.
// go: sdk 1.25.5 net/http/status.go:9-77 StatusUpgradeRequired
pub const StatusUpgradeRequired: int = 426; // RFC 9110, 15.5.22
// go: sdk 1.25.5 net/http/status.go:9-77 StatusPreconditionRequired
pub const StatusPreconditionRequired: int = 428; // RFC 6585, 3
// go: sdk 1.25.5 net/http/status.go:9-77 StatusTooManyRequests
pub const StatusTooManyRequests: int = 429; // RFC 6585, 4
// go: sdk 1.25.5 net/http/status.go:9-77 StatusRequestHeaderFieldsTooLarge
pub const StatusRequestHeaderFieldsTooLarge: int = 431; // RFC 6585, 5
// go: sdk 1.25.5 net/http/status.go:9-77 StatusUnavailableForLegalReasons
pub const StatusUnavailableForLegalReasons: int = 451; // RFC 7725, 3

// go: sdk 1.25.5 net/http/status.go:9-77 StatusInternalServerError
pub const StatusInternalServerError: int = 500; // RFC 9110, 15.6.1
// go: sdk 1.25.5 net/http/status.go:9-77 StatusNotImplemented
pub const StatusNotImplemented: int = 501; // RFC 9110, 15.6.2
// go: sdk 1.25.5 net/http/status.go:9-77 StatusBadGateway
pub const StatusBadGateway: int = 502; // RFC 9110, 15.6.3
// go: sdk 1.25.5 net/http/status.go:9-77 StatusServiceUnavailable
pub const StatusServiceUnavailable: int = 503; // RFC 9110, 15.6.4
// go: sdk 1.25.5 net/http/status.go:9-77 StatusGatewayTimeout
pub const StatusGatewayTimeout: int = 504; // RFC 9110, 15.6.5
// go: sdk 1.25.5 net/http/status.go:9-77 StatusHTTPVersionNotSupported
pub const StatusHTTPVersionNotSupported: int = 505; // RFC 9110, 15.6.6
// go: sdk 1.25.5 net/http/status.go:9-77 StatusVariantAlsoNegotiates
pub const StatusVariantAlsoNegotiates: int = 506; // RFC 2295, 8.1
// go: sdk 1.25.5 net/http/status.go:9-77 StatusInsufficientStorage
pub const StatusInsufficientStorage: int = 507; // RFC 4918, 11.5
// go: sdk 1.25.5 net/http/status.go:9-77 StatusLoopDetected
pub const StatusLoopDetected: int = 508; // RFC 5842, 7.2
// go: sdk 1.25.5 net/http/status.go:9-77 StatusNotExtended
pub const StatusNotExtended: int = 510; // RFC 2774, 7
// go: sdk 1.25.5 net/http/status.go:9-77 StatusNetworkAuthenticationRequired
pub const StatusNetworkAuthenticationRequired: int = 511; // RFC 6585, 6

// ─── StatusText ─────────────────────────────────────────────────────

// go: sdk 1.25.5 net/http/status.go:81-210 StatusText
/// Go: "StatusText returns a text for the HTTP status code. It returns
/// the empty string if the code is unknown."
pub fn StatusText(code: int) -> string {
    let s: &'static str = match code {
        StatusContinue => "Continue",
        StatusSwitchingProtocols => "Switching Protocols",
        StatusProcessing => "Processing",
        StatusEarlyHints => "Early Hints",
        StatusOK => "OK",
        StatusCreated => "Created",
        StatusAccepted => "Accepted",
        StatusNonAuthoritativeInfo => "Non-Authoritative Information",
        StatusNoContent => "No Content",
        StatusResetContent => "Reset Content",
        StatusPartialContent => "Partial Content",
        StatusMultiStatus => "Multi-Status",
        StatusAlreadyReported => "Already Reported",
        StatusIMUsed => "IM Used",
        StatusMultipleChoices => "Multiple Choices",
        StatusMovedPermanently => "Moved Permanently",
        StatusFound => "Found",
        StatusSeeOther => "See Other",
        StatusNotModified => "Not Modified",
        StatusUseProxy => "Use Proxy",
        StatusTemporaryRedirect => "Temporary Redirect",
        StatusPermanentRedirect => "Permanent Redirect",
        StatusBadRequest => "Bad Request",
        StatusUnauthorized => "Unauthorized",
        StatusPaymentRequired => "Payment Required",
        StatusForbidden => "Forbidden",
        StatusNotFound => "Not Found",
        StatusMethodNotAllowed => "Method Not Allowed",
        StatusNotAcceptable => "Not Acceptable",
        StatusProxyAuthRequired => "Proxy Authentication Required",
        StatusRequestTimeout => "Request Timeout",
        StatusConflict => "Conflict",
        StatusGone => "Gone",
        StatusLengthRequired => "Length Required",
        StatusPreconditionFailed => "Precondition Failed",
        StatusRequestEntityTooLarge => "Request Entity Too Large",
        StatusRequestURITooLong => "Request URI Too Long",
        StatusUnsupportedMediaType => "Unsupported Media Type",
        StatusRequestedRangeNotSatisfiable => "Requested Range Not Satisfiable",
        StatusExpectationFailed => "Expectation Failed",
        StatusTeapot => "I'm a teapot",
        StatusMisdirectedRequest => "Misdirected Request",
        StatusUnprocessableEntity => "Unprocessable Entity",
        StatusLocked => "Locked",
        StatusFailedDependency => "Failed Dependency",
        StatusTooEarly => "Too Early",
        StatusUpgradeRequired => "Upgrade Required",
        StatusPreconditionRequired => "Precondition Required",
        StatusTooManyRequests => "Too Many Requests",
        StatusRequestHeaderFieldsTooLarge => "Request Header Fields Too Large",
        StatusUnavailableForLegalReasons => "Unavailable For Legal Reasons",
        StatusInternalServerError => "Internal Server Error",
        StatusNotImplemented => "Not Implemented",
        StatusBadGateway => "Bad Gateway",
        StatusServiceUnavailable => "Service Unavailable",
        StatusGatewayTimeout => "Gateway Timeout",
        StatusHTTPVersionNotSupported => "HTTP Version Not Supported",
        StatusVariantAlsoNegotiates => "Variant Also Negotiates",
        StatusInsufficientStorage => "Insufficient Storage",
        StatusLoopDetected => "Loop Detected",
        StatusNotExtended => "Not Extended",
        StatusNetworkAuthenticationRequired => "Network Authentication Required",
        _ => "",
    };
    return string::from_static(s);
}
