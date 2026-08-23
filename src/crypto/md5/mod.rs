// go: package crypto/md5
//
// Package md5 implements the MD5 hash algorithm as defined in RFC 1321.
//
// MD5 is cryptographically broken and should not be used for secure
// applications.

mod md5;
mod md5block;
mod md5block_generic;

pub use md5::{register_md5_impls, BlockSize, Digest, New, NewHash, Size, Sum};
