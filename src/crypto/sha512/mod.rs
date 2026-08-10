// go: package crypto/sha512
//
// Package sha512 implements the SHA-384, SHA-512, SHA-512/224 and
// SHA-512/256 hash algorithms as defined in FIPS 180-4.

mod sha512;

pub use sha512::{
    BlockSize, Digest, New, New384, New512_224, New512_256, NewHash, NewHash384, NewHash512_224,
    NewHash512_256, Size, Size224, Size256, Size384, Sum384, Sum512, Sum512_224, Sum512_256,
};
