// go: package crypto/sha3
//
// Package sha3 implements the SHA-3 fixed-output-length hash functions
// and the SHAKE variable-output-length functions defined by FIPS 202, as
// well as the cSHAKE extendable-output-length functions defined by
// SP 800-185.

mod sha3;

pub use sha3::{
    register_sha3_impls, New224, New256, New384, New512, NewCSHAKE128, NewCSHAKE256, NewHash224,
    NewHash256, NewHash384, NewHash512, NewSHAKE128, NewSHAKE256, Size224, Size256, Size384,
    Size512, Sum224, Sum256, Sum384, Sum512, SumSHAKE128, SumSHAKE256, SHA3, SHAKE,
};

// go: none — goish idiom: goish's pre-fips140 port named the hash type
// `Digest`; Go 1.25 calls it `sha3.SHA3`. Kept so existing call sites
// keep compiling.
pub type Digest = SHA3;
