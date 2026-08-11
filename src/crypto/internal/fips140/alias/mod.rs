// go: package crypto/internal/fips140/alias
//
// Package alias implements memory aliasing tests. This code also exists
// as golang.org/x/crypto/internal/alias.

mod alias;

pub use alias::{AnyOverlap, InexactOverlap};
