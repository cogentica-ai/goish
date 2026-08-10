// go: package crypto/internal/fips140/drbg
//
// Package drbg provides cryptographically secure random bytes usable by
// FIPS code. In FIPS mode it uses an SP 800-90A Rev. 1 Deterministic
// Random Bit Generator; otherwise it uses the operating system's random
// number generator.

mod ctrdrbg;

pub use ctrdrbg::{Counter, NewCounter, SeedSize};
