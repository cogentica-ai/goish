// net/http/internal — internal helpers shared across net/http subpackages.
//
//   Go                                       goish
//   ──────────────────────────────────────   ─────────────────────────────────
//   net/http/internal/ascii.EqualFold(...)   http::internal::ascii::EqualFold(...)
//
// This mirrors Go's net/http/internal/ directory layout. Modules here are
// considered private to net/http (Go's `internal/` convention); we still
// expose them under `pub mod` because Rust's pub(crate)/pub(super) gate is
// the actual visibility boundary for the crate, not the path name.

#![allow(non_snake_case)]

pub mod ascii;
pub mod chunked;
pub mod httpcommon;
pub mod testcert;
