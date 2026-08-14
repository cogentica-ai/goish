// go: package net/http/cgi
//
// net/http/cgi — CGI from the perspective of a child process.
//
// Go splits the package three ways: child.go (the child side —
// reading CGI environment variables into an http.Request), host.go
// (the host side — running a CGI executable with os/exec), and
// cgi_main.go (a test helper). Only host.go needs os/exec and
// golang.org/x/net/http/httpguts, so child.go ports first.
//
// port_deps reports this package NO-GO on httpguts. That is a
// package-level union of every file's imports: host.go:283 is the only
// user, and goish already HAS the predicate — net/http/http.rs's
// `isToken` IS httpguts.ValidHeaderFieldName, as its own comment
// records. The real blocker was Request lacking Close/Trailer/TLS,
// added in 7167f33.
//
// This file is a module root, so it carries no `// go:` anchors.

#![allow(non_snake_case)]
#![allow(dead_code)]

pub mod child;
pub mod host;

pub use child::{envMap, response, Request, RequestFromMap, Serve};
