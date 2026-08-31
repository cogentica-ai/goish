// go: package io/ioutil
//
// io/ioutil — Go's `io/ioutil` package, ported.
//
//
// `io/ioutil` was split into `io` and `os` in Go 1.16, but a long
// tail of code (rs/xid, hashicorp libs, K8s client deps) still spells
// `ioutil.ReadFile`, `ioutil.WriteFile`, etc. The module here is a
// compatibility shim — every entry is a thin forwarder to the
// post-split home.
//
// Module root only: one `.rs` per Go `.go`, and the `pub use` surface.
//
//   ioutil.rs    io/ioutil/ioutil.go   — ReadAll, ReadFile, WriteFile,
//                                        ReadDir, NopCloser, Discard
//   tempfile.rs  io/ioutil/tempfile.go — TempFile, TempDir

#![allow(non_snake_case)]

#[path = "ioutil.rs"]
mod ioutil_go;
pub use ioutil_go::{Discard, NopCloser, ReadAll, ReadDir, ReadFile, WriteFile};

#[path = "tempfile.rs"]
mod tempfile;
pub use tempfile::{TempDir, TempFile};
