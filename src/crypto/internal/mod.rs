// crypto/internal — Go's `crypto/internal/` tree.
//
// Internal packages used by the FIPS 140 crypto modules. Go's
// `internal/` path convention is advisory; in goish the visibility
// boundary is Rust's `pub`/`pub(crate)`, so submodules are `pub mod`.

#![allow(non_snake_case)]

pub mod entropy;
pub mod fips140;
pub mod fips140deps;
pub mod randutil;
