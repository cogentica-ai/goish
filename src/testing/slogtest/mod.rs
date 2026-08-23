// go: package testing/slogtest
// testing/slogtest — the conformance checks a slog.Handler must pass.
//
// Package root: declarations live in slogtest[rs], which GOISH015
// requires (a module root may hold only `mod` / `pub use`).

#![allow(non_snake_case)]

mod slogtest;
pub use slogtest::{
    cases, check, hasAttr, hasKey, inGroup, missingKey, replace, testCase, wrapper, Run,
    TestHandler,
};
