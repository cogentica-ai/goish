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
// persist.go (ServerConn/ClientConn) IS ported, in persist.rs — the
// claim that it is not outlived the file by some margin. Deprecated
// in Go, and pinned against 1.25.5 by examples/http_persist_smoke.rs.
//
// This file is a module root, so it carries no `// go:` anchors.

#![allow(non_snake_case)]
#![allow(dead_code)]

pub mod dump;
pub mod httputil;
pub mod persist;
pub mod reverseproxy;

// DumpRequestOut is exported here because Go exports it. It was
// reachable only as `httputil::dump::DumpRequestOut` before, which is
// not the name Go users write.
pub use dump::{
    dumpConn, outgoingLength, valueOrDefault, DumpRequest, DumpRequestOut, DumpResponse,
};
pub use httputil::{ErrLineTooLong, NewChunkedReader, NewChunkedWriter};
pub(crate) use reverseproxy::register_httputil_impls;
pub use reverseproxy::{
    cleanQueryParams, joinURLPath, rewriteRequestURL, upgradeType, NewSingleHostReverseProxy,
};
