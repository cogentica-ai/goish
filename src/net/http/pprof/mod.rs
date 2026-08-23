// go: package net/http/pprof
//
// net/http/pprof — HTTP handlers for the runtime profiler.
//
// This file is a module root, so it carries no `// go:` anchors. See
// pprof.rs for what is ported and which package each unported
// declaration actually needs.

#![allow(non_snake_case)]
#![allow(dead_code)]

pub mod pprof;

pub use pprof::{
    handler, indexTmplExecute, profileEntry, serveError, Cmdline, Handler, Index, Profile, Symbol,
    Trace,
};
