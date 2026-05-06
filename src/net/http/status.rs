// net/http/status — line-by-line port of Go 1.25 src/net/http/status.go.
//
// Public Status* constants and StatusText(code) -> string. Self-
// contained — no new infrastructure required. Each constant carries
// its RFC reference verbatim from the Go source.

#![allow(non_snake_case)]
#![allow(dead_code)]

use crate::string;
use crate::types::int;

// ─── status code constants ──────────────────────────────────────────

pub const StatusContinue: int = 100; // RFC 9110, 15.2.1
pub const StatusSwitchingProtocols: int = 101; // RFC 9110, 15.2.2
pub const StatusProcessing: int = 102; // RFC 2518, 10.1
pub const StatusEarlyHints: int = 103; // RFC 8297

pub const StatusOK: int = 200; // RFC 9110, 15.3.1
pub const StatusCreated: int = 201; // RFC 9110, 15.3.2
pub const StatusAccepted: int = 202; // RFC 9110, 15.3.3
pub const StatusNonAuthoritativeInfo: int = 203; // RFC 9110, 15.3.4
pub const StatusNoContent: int = 204; // RFC 9110, 15.3.5
pub const StatusResetContent: int = 205; // RFC 9110, 15.3.6
pub const StatusPartialContent: int = 206; // RFC 9110, 15.3.7
pub const StatusMultiStatus: int = 207; // RFC 4918, 11.1
pub const StatusAlreadyReported: int = 208; // RFC 5842, 7.1
pub const StatusIMUsed: int = 226; // RFC 3229, 10.4.1

pub const StatusMultipleChoices: int = 300; // RFC 9110, 15.4.1
pub const StatusMovedPermanently: int = 301; // RFC 9110, 15.4.2
pub const StatusFound: int = 302; // RFC 9110, 15.4.3
pub const StatusSeeOther: int = 303; // RFC 9110, 15.4.4
pub const StatusNotModified: int = 304; // RFC 9110, 15.4.5
pub const StatusUseProxy: int = 305; // RFC 9110, 15.4.6
pub const StatusTemporaryRedirect: int = 307; // RFC 9110, 15.4.8
pub const StatusPermanentRedirect: int = 308; // RFC 9110, 15.4.9

pub const StatusBadRequest: int = 400; // RFC 9110, 15.5.1
pub const StatusUnauthorized: int = 401; // RFC 9110, 15.5.2
pub const StatusPaymentRequired: int = 402; // RFC 9110, 15.5.3
pub const StatusForbidden: int = 403; // RFC 9110, 15.5.4
pub const StatusNotFound: int = 404; // RFC 9110, 15.5.5
pub const StatusMethodNotAllowed: int = 405; // RFC 9110, 15.5.6
pub const StatusNotAcceptable: int = 406; // RFC 9110, 15.5.7
pub const StatusProxyAuthRequired: int = 407; // RFC 9110, 15.5.8
pub const StatusRequestTimeout: int = 408; // RFC 9110, 15.5.9
pub const StatusConflict: int = 409; // RFC 9110, 15.5.10
pub const StatusGone: int = 410; // RFC 9110, 15.5.11
pub const StatusLengthRequired: int = 411; // RFC 9110, 15.5.12
pub const StatusPreconditionFailed: int = 412; // RFC 9110, 15.5.13
pub const StatusRequestEntityTooLarge: int = 413; // RFC 9110, 15.5.14
pub const StatusRequestURITooLong: int = 414; // RFC 9110, 15.5.15
pub const StatusUnsupportedMediaType: int = 415; // RFC 9110, 15.5.16
pub const StatusRequestedRangeNotSatisfiable: int = 416; // RFC 9110, 15.5.17
pub const StatusExpectationFailed: int = 417; // RFC 9110, 15.5.18
pub const StatusTeapot: int = 418; // RFC 9110, 15.5.19 (Unused)
pub const StatusMisdirectedRequest: int = 421; // RFC 9110, 15.5.20
pub const StatusUnprocessableEntity: int = 422; // RFC 9110, 15.5.21
pub const StatusLocked: int = 423; // RFC 4918, 11.3
pub const StatusFailedDependency: int = 424; // RFC 4918, 11.4
pub const StatusTooEarly: int = 425; // RFC 8470, 5.2
pub const StatusUpgradeRequired: int = 426; // RFC 9110, 15.5.22
pub const StatusPreconditionRequired: int = 428; // RFC 6585, 3
pub const StatusTooManyRequests: int = 429; // RFC 6585, 4
pub const StatusRequestHeaderFieldsTooLarge: int = 431; // RFC 6585, 5
pub const StatusUnavailableForLegalReasons: int = 451; // RFC 7725, 3

pub const StatusInternalServerError: int = 500; // RFC 9110, 15.6.1
pub const StatusNotImplemented: int = 501; // RFC 9110, 15.6.2
pub const StatusBadGateway: int = 502; // RFC 9110, 15.6.3
pub const StatusServiceUnavailable: int = 503; // RFC 9110, 15.6.4
pub const StatusGatewayTimeout: int = 504; // RFC 9110, 15.6.5
pub const StatusHTTPVersionNotSupported: int = 505; // RFC 9110, 15.6.6
pub const StatusVariantAlsoNegotiates: int = 506; // RFC 2295, 8.1
pub const StatusInsufficientStorage: int = 507; // RFC 4918, 11.5
pub const StatusLoopDetected: int = 508; // RFC 5842, 7.2
pub const StatusNotExtended: int = 510; // RFC 2774, 7
pub const StatusNetworkAuthenticationRequired: int = 511; // RFC 6585, 6

// ─── StatusText ─────────────────────────────────────────────────────

/// `http.StatusText(code)` — text for the HTTP status code; empty
/// string if unknown. Line-by-line port of status.go:81.
pub fn StatusText(code: int) -> string {
    // Go: switch code { case StatusContinue: return "Continue"; … }
    let s: &'static str = match code {
        100 => "Continue",
        101 => "Switching Protocols",
        102 => "Processing",
        103 => "Early Hints",
        200 => "OK",
        201 => "Created",
        202 => "Accepted",
        203 => "Non-Authoritative Information",
        204 => "No Content",
        205 => "Reset Content",
        206 => "Partial Content",
        207 => "Multi-Status",
        208 => "Already Reported",
        226 => "IM Used",
        300 => "Multiple Choices",
        301 => "Moved Permanently",
        302 => "Found",
        303 => "See Other",
        304 => "Not Modified",
        305 => "Use Proxy",
        307 => "Temporary Redirect",
        308 => "Permanent Redirect",
        400 => "Bad Request",
        401 => "Unauthorized",
        402 => "Payment Required",
        403 => "Forbidden",
        404 => "Not Found",
        405 => "Method Not Allowed",
        406 => "Not Acceptable",
        407 => "Proxy Authentication Required",
        408 => "Request Timeout",
        409 => "Conflict",
        410 => "Gone",
        411 => "Length Required",
        412 => "Precondition Failed",
        413 => "Request Entity Too Large",
        414 => "Request URI Too Long",
        415 => "Unsupported Media Type",
        416 => "Requested Range Not Satisfiable",
        417 => "Expectation Failed",
        418 => "I'm a teapot",
        421 => "Misdirected Request",
        422 => "Unprocessable Entity",
        423 => "Locked",
        424 => "Failed Dependency",
        425 => "Too Early",
        426 => "Upgrade Required",
        428 => "Precondition Required",
        429 => "Too Many Requests",
        431 => "Request Header Fields Too Large",
        451 => "Unavailable For Legal Reasons",
        500 => "Internal Server Error",
        501 => "Not Implemented",
        502 => "Bad Gateway",
        503 => "Service Unavailable",
        504 => "Gateway Timeout",
        505 => "HTTP Version Not Supported",
        506 => "Variant Also Negotiates",
        507 => "Insufficient Storage",
        508 => "Loop Detected",
        510 => "Not Extended",
        511 => "Network Authentication Required",
        _ => "",
    };
    string(s)
}
