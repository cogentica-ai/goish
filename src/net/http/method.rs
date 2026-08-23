// go: package net/http
//
// go: file net/http/method.go decls:
//
// Go: "Common HTTP methods. Unless otherwise noted, these are defined
// in RFC 7231 section 4.3."
//
// Nine constants and no functions, so the coverage count does not move.

#![allow(non_upper_case_globals)]

// go: sdk 1.25.5 net/http/method.go:10-20 MethodGet
pub const MethodGet: &str = "GET";
// go: sdk 1.25.5 net/http/method.go:10-20 MethodHead
pub const MethodHead: &str = "HEAD";
// go: sdk 1.25.5 net/http/method.go:10-20 MethodPost
pub const MethodPost: &str = "POST";
// go: sdk 1.25.5 net/http/method.go:10-20 MethodPut
pub const MethodPut: &str = "PUT";
// go: sdk 1.25.5 net/http/method.go:10-20 MethodPatch
pub const MethodPatch: &str = "PATCH"; // RFC 5789
                                       // go: sdk 1.25.5 net/http/method.go:10-20 MethodDelete
pub const MethodDelete: &str = "DELETE";
// go: sdk 1.25.5 net/http/method.go:10-20 MethodConnect
pub const MethodConnect: &str = "CONNECT";
// go: sdk 1.25.5 net/http/method.go:10-20 MethodOptions
pub const MethodOptions: &str = "OPTIONS";
// go: sdk 1.25.5 net/http/method.go:10-20 MethodTrace
pub const MethodTrace: &str = "TRACE";
