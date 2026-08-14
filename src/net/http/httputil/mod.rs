// go: package net/http/httputil
//
// net/http/httputil — HTTP utility functions complementing net/http.
//
// Split from a single `httputil.rs` that held FOUR Go files' worth
// (dump.go, httputil.go, persist.go, reverseproxy.go). GOISH015
// forbids two Go files per Rust file, so nothing in it could carry a
// provenance anchor — the whole package read as unverified. One file
// per Go file is what lets each be anchored and diffed.
//
// persist.go (ServerConn/ClientConn) is not ported; it is deprecated
// in Go and needs a pluggable net.Conn.
//
// This file is a module root, so it carries no `// go:` anchors.

#![allow(non_snake_case)]
#![allow(dead_code)]

pub mod dump;
pub mod httputil;
pub mod persist;
pub mod reverseproxy;

pub use dump::{dumpConn, outgoingLength, valueOrDefault, DumpRequest, DumpResponse};
pub use httputil::{ErrLineTooLong, NewChunkedReader, NewChunkedWriter};
pub use reverseproxy::{
    cleanQueryParams, joinURLPath, rewriteRequestURL, upgradeType, NewSingleHostReverseProxy,
};
pub(crate) use reverseproxy::register_httputil_impls;
