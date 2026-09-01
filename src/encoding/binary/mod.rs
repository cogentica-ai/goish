// go: package encoding/binary
//
// encoding/binary — Go's byte-order-aware fixed-width integer codec.

#![allow(non_snake_case)]
#![allow(non_upper_case_globals)]

#[path = "binary.rs"]
mod binary_go;
#[path = "native_endian_little.rs"]
mod native_endian_little;
pub use binary_go::*;
pub use native_endian_little::*;
