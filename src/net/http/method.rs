// net/http/method — HTTP method constants.
//
// Line-by-line port of Go 1.25 src/net/http/method.go (~20 LOC).
// RFC 7231 §4.3 (PATCH from RFC 5789).

#![allow(non_upper_case_globals)]

pub const MethodGet: &str = "GET";
pub const MethodHead: &str = "HEAD";
pub const MethodPost: &str = "POST";
pub const MethodPut: &str = "PUT";
pub const MethodPatch: &str = "PATCH"; // RFC 5789
pub const MethodDelete: &str = "DELETE";
pub const MethodConnect: &str = "CONNECT";
pub const MethodOptions: &str = "OPTIONS";
pub const MethodTrace: &str = "TRACE";
