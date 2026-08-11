// go: package crypto/internal/fips140/rsa
//
// crypto/internal/fips140/rsa — the FIPS-internal RSA core.
//
// This is the INTERNAL fips140 RSA package, distinct from the public
// `crypto/rsa`: the modulus is a constant-time `bigmod.Modulus`, not a
// `*big.Int`. One `.rs` per Go `.go` — see each file's header for its
// manifest and its deviations from the Go original.

#![allow(non_snake_case, non_camel_case_types, non_upper_case_globals)]

mod cast;
mod keygen;
mod pkcs1v15;
mod pkcs1v22;
mod rsa;

pub use keygen::*;
pub use pkcs1v15::*;
pub use pkcs1v22::*;
pub use rsa::*;
