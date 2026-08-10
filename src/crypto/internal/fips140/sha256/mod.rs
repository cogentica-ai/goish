// go: package crypto/internal/fips140/sha256

mod sha256;
mod sha256block;
mod sha256block_noasm;

pub use sha256::{
    register_sha256_impls, BlockSize, Digest, New, New224, NewHash, NewHash224, Size, Size224,
};
