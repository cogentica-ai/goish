// crypto — Go's `crypto` parent package.
//
// Currently only re-exports submodules; the package proper has hashing
// + cipher infrastructure that goish doesn't ship.

#![allow(non_snake_case)]

pub mod hmac;
pub mod md5;
pub mod rand;
pub mod sha1;
pub mod sha256;
