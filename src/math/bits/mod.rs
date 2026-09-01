// go: package math/bits
//
// math/bits — Go's `math/bits`, ported.

#![allow(non_snake_case, non_upper_case_globals)]

#[path = "bits.rs"]
mod bits_go;
pub use bits_go::*;
