// go: package crypto/internal/fips140/drbg
//
// Package drbg provides cryptographically secure random bytes usable by
// FIPS code. In FIPS mode it uses an SP 800-90A Rev. 1 Deterministic
// Random Bit Generator; otherwise it uses the operating system's random
// number generator.

mod ctrdrbg;
mod rand;

pub use ctrdrbg::{Counter, NewCounter, SeedSize};
pub use rand::{DefaultReader, Read, ReadWithReader, ReadWithReaderDeterministic};
// goish idiom: the `#[goish::interface]` downcast-registry hook that
// concrete impls of `DefaultReader` call to become castable.
pub use rand::__goish_register_DefaultReader_impl;
