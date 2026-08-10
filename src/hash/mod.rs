// go: package hash
//
// Package hash provides interfaces for hash functions.

#![allow(non_snake_case)]

mod hash;

pub mod adler32;
pub mod crc32;
pub mod crc64;
pub mod fnv;
pub mod maphash;

pub use hash::{Cloner, Hash, Hash32, Hash64, XOF, __NilCloner};

// Downcast-registry entry points emitted by `#[goish::interface]`; the
// implementing packages call these to register their concrete types.
pub use hash::{__goish_register_Cloner_impl, __goish_register_Hash_impl};
