// go: package net/http/httptest
//
// net/http/httptest — utilities for HTTP testing.
//
//   Go                                       goish
//   ──────────────────────────────────────   ─────────────────────────────────
//   httptest.NewRequest("GET", "/", nil)     httptest::NewRequest("GET", "/", ())
//   httptest.NewRecorder()                   httptest::NewRecorder()
//   rec.Result()                             rec.Result()
//
// This was a single file at src/net/http/httptest.rs — package code
// living in net/http's own directory, the same shape that made
// net/http/internal read as a SQUATTER at 0/12. It mirrors Go's
// directory now, one Rust file per Go file.

#![allow(non_snake_case)]

pub mod httptest;
pub mod recorder;

pub use httptest::{NewRequest, NewRequestWithContext};
pub use recorder::{NewRecorder, ResponseRecorder, DefaultRemoteAddr};
