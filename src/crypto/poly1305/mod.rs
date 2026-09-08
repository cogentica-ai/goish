// crypto/poly1305 — module root.
//
// Split the way Go splits it: `poly1305.rs` for the public MAC
// surface, `sum_generic.rs` for the portable arithmetic. This file
// re-exports, so callers keep writing `poly1305::MAC::New(&key)` and
// `poly1305::TagSize`.

pub mod poly1305;
mod sum_generic;

pub use poly1305::{Sum, TagSize, Verify, MAC};
