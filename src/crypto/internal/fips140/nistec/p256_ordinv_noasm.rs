// go: file crypto/internal/fips140/nistec/p256_ordinv_noasm.go decls: P256OrdInverse
//
// The no-assembly side of p256_ordinv.go's build-tag pair
// (`//go:build (!amd64 && !arm64) || purego`). Go's amd64 path computes
// the inverse of a P-256 scalar with the p256Ord* assembly; without it
// the function is a stub that reports "unimplemented", and callers
// (crypto/ecdsa) fall back to bigmod. goish implements the portable side
// of these pairs, so this is the stub, verbatim.

#![allow(non_snake_case)]

extern crate alloc;
use alloc::vec::Vec;

use crate::error;
use crate::errors;
use crate::goslice::slice;
use crate::types::byte;

// go: sdk 1.25.5 crypto/internal/fips140/nistec/p256_ordinv_noasm.go:11-13 P256OrdInverse
pub fn P256OrdInverse(k: &slice<byte>) -> (slice<byte>, error) {
    let _ = k;
    return (
        slice::__from_vec(Vec::<byte>::new()),
        errors::New("unimplemented"),
    );
}
