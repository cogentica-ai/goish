// go: file crypto/internal/fips140/mlkem/mlkem768.go decls:
//
// Package mlkem implements the quantum-resistant key encapsulation method
// ML-KEM (formerly known as Kyber), as specified in [NIST FIPS 203].
//
// [NIST FIPS 203]: https://doi.org/10.6028/NIST.FIPS.203
//
// This package targets security, correctness, simplicity, readability, and
// reviewability as its primary goals. All critical operations are performed in
// constant time.
//
// Variable and function names, as well as code layout, are selected to
// facilitate reviewing the implementation against the NIST FIPS 203 document.
//
// Reviewers unfamiliar with polynomials or linear algebra might find the
// background at https://words.filippo.io/kyber-math/ useful.
//
// This file implements the recommended parameter set ML-KEM-768. The
// ML-KEM-1024 parameter set implementation is auto-generated from this file.
//
// PORT STATUS: the parameter block only. The key-generation, encapsulation
// and decapsulation functions of mlkem768.go are not yet ported; field.rs
// (all 32 functions of field.go) is complete and stands on these constants.
//
// goishlint:ignore GOISH018 — see PORT STATUS above: this file
// deliberately carries only mlkem768.go's const block for now, so every
// function of mlkem768.go reads as missing. Removing this suppression is
// the checklist item for finishing the package.

#![allow(non_upper_case_globals)]

use crate::types::uint16;


// Go: mlkem768.go:35-53 — ML-KEM global constants.
/// Go: `n = 256`
pub const n: usize = 256;
/// Go: `q = 3329`
pub const q: uint16 = 3329;

// encodingSizeX is the byte size of a ringElement or nttElement encoded
// by ByteEncode_X (FIPS 203, Algorithm 5).
/// Go: `encodingSize12 = n * 12 / 8`
pub const encodingSize12: usize = n * 12 / 8;
/// Go: `encodingSize11 = n * 11 / 8`
pub const encodingSize11: usize = n * 11 / 8;
/// Go: `encodingSize10 = n * 10 / 8`
pub const encodingSize10: usize = n * 10 / 8;
/// Go: `encodingSize5  = n * 5 / 8`
pub const encodingSize5: usize = n * 5 / 8;
/// Go: `encodingSize4  = n * 4 / 8`
pub const encodingSize4: usize = n * 4 / 8;
/// Go: `encodingSize1  = n * 1 / 8`
pub const encodingSize1: usize = n * 1 / 8;

/// Go: `messageSize = encodingSize1`
pub const messageSize: usize = encodingSize1;

/// Go: `SharedKeySize = 32`
pub const SharedKeySize: usize = 32;
/// Go: `SeedSize = 32 + 32`
pub const SeedSize: usize = 32 + 32;

// Go: mlkem768.go:55-62 — ML-KEM-768 parameters.
/// Go: `k = 3`
pub const k: usize = 3;
/// Go: `CiphertextSize768 = k*encodingSize10 + encodingSize4`
pub const CiphertextSize768: usize = k * encodingSize10 + encodingSize4;
/// Go: `EncapsulationKeySize768 = k*encodingSize12 + 32`
pub const EncapsulationKeySize768: usize = k * encodingSize12 + 32;
/// Go: `decapsulationKeySize768 = k*encodingSize12 + EncapsulationKeySize768 + 32 + 32`
pub const decapsulationKeySize768: usize =
    k * encodingSize12 + EncapsulationKeySize768 + 32 + 32;

// Go: mlkem768.go:64-70 — ML-KEM-1024 parameters.
/// Go: `k1024 = 4`
pub const k1024: usize = 4;
/// Go: `CiphertextSize1024 = k1024*encodingSize11 + encodingSize5`
pub const CiphertextSize1024: usize = k1024 * encodingSize11 + encodingSize5;
/// Go: `EncapsulationKeySize1024 = k1024*encodingSize12 + 32`
pub const EncapsulationKeySize1024: usize = k1024 * encodingSize12 + 32;
/// Go: `decapsulationKeySize1024 = k1024*encodingSize12 + EncapsulationKeySize1024 + 32 + 32`
pub const decapsulationKeySize1024: usize =
    k1024 * encodingSize12 + EncapsulationKeySize1024 + 32 + 32;
