// go: package crypto/sha1
//
// Package sha1 implements the SHA-1 hash algorithm as defined in RFC 3174.
//
// SHA-1 is cryptographically broken and should not be used for secure
// applications.

mod sha1;
mod sha1block;
mod sha1block_generic;

pub use sha1::{register_sha1_impls, BlockSize, Digest, New, NewHash, Size, Sum};
