// go: package crypto/internal/fips140/subtle
//
// Package subtle implements functions that are often useful in
// cryptographic code but require careful thought to use correctly.
//
// This is the FIPS 140-3 module's copy; `crypto/subtle` re-exports a
// subset of it (Go: crypto/subtle/xor.go delegates here).

mod constant_time;
mod xor;
mod xor_generic;

pub use constant_time::{
    ConstantTimeByteEq, ConstantTimeCompare, ConstantTimeCopy, ConstantTimeEq,
    ConstantTimeLessOrEq, ConstantTimeLessOrEqBytes, ConstantTimeSelect,
};
pub use xor::XORBytes;
