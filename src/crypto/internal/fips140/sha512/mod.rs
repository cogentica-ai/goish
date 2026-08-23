// go: package crypto/internal/fips140/sha512

mod sha512;
mod sha512block;
mod sha512block_noasm;

pub use sha512::{
    register_sha512_impls, BlockSize, Digest, New, New384, New512_224, New512_256, NewHash,
    NewHash384, NewHash512_224, NewHash512_256, Size224, Size256, Size384, Size512,
};
