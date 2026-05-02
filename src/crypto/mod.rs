// crypto — Go's `crypto` parent package.
//
// Currently only re-exports submodules; the package proper has hashing
// + cipher infrastructure that goish doesn't ship.

#![allow(non_snake_case)]

pub mod cipher;
pub mod hkdf;
pub mod hmac;
pub mod md5;
pub mod pbkdf2;
pub mod rand;
pub mod rc4;
pub mod sha1;
pub mod sha256;
pub mod sha512;
pub mod subtle;
