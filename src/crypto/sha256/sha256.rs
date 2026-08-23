// goishlint:ignore GOISH018 — `init` (sha256[go]) is
// `crypto.RegisterHash(crypto.SHA224/SHA256, New224/New)`. goish has no
// crypto.Hash registry, so there is nothing to register into; port it
// with that registry.
// go: file crypto/sha256/sha256.go decls: New, New224, Sum256, Sum224
//
// Package sha256 implements the SHA-224 and SHA-256 hash algorithms as
// defined in FIPS 180-4. Go 1.25 makes this a thin wrapper over
// crypto/internal/fips140/sha256; goish follows.
//
// Deviation: no crypto.RegisterHash init (goish has no hash registry) and
// no boring/fips140only branches.

#![allow(non_snake_case, non_upper_case_globals)]

extern crate alloc;

use crate::crypto::internal::fips140::sha256 as fips;
use crate::goslice::slice;
use crate::hash::Hash;
use crate::io;
use crate::types::{byte, int};
use alloc::vec::Vec;

pub use fips::Digest;

// ─── Constants (Go: sha256.go:21-28; fips140 sha256.go:17-23) ─────────

/// `sha256.Size` — SHA-256 checksum length (bytes).
pub const Size: int = 32;

/// `sha256.Size224` — SHA-224 checksum length (bytes).
pub const Size224: int = 28;

/// `sha256.BlockSize` — block size of SHA-256/SHA-224 (bytes).
pub const BlockSize: int = 64;

// go: sdk 1.25.5 crypto/sha256/sha256.go:34-43 New
/// `sha256.New()` — a new SHA-256 hash.
pub fn New() -> Digest {
    // Go: return sha256.New()
    return fips::New();
}

// go: sdk 1.25.5 crypto/sha256/sha256.go:45-51 New224
/// `sha256.New224()` — a new SHA-224 hash.
pub fn New224() -> Digest {
    // Go: return sha256.New224()
    return fips::New224();
}

// go: sdk 1.25.5 crypto/sha256/sha256.go:53-63 Sum256
/// `sha256.Sum256(data)` — SHA-256 of `data`.
pub fn Sum256(data: slice<byte>) -> [byte; 32] {
    // Go: h := New(); h.Write(data); var sum [Size]byte; h.Sum(sum[:0]); return sum
    let mut h = New();
    let _ = io::Writer::Write(&mut h, data);
    let empty: Vec<byte> = Vec::new();
    let out = h.Sum(slice::__from_vec(empty));
    let raw: &[byte] = &out;
    let mut sum = [0u8; 32];
    sum.copy_from_slice(&raw[..32]);
    return sum;
}

// go: sdk 1.25.5 crypto/sha256/sha256.go:65-75 Sum224
/// `sha256.Sum224(data)` — SHA-224 of `data`.
pub fn Sum224(data: slice<byte>) -> [byte; 28] {
    let mut h = New224();
    let _ = io::Writer::Write(&mut h, data);
    let empty: Vec<byte> = Vec::new();
    let out = h.Sum(slice::__from_vec(empty));
    let raw: &[byte] = &out;
    let mut sum = [0u8; 28];
    sum.copy_from_slice(&raw[..28]);
    return sum;
}

// ─── Boxed constructors for trait-object consumers (e.g. hmac::New) ───

/// `sha256.NewHash()` — boxed constructor matching `hash.Hash` interface.

// go: none — goish idiom: boxed-trait constructors for call sites that
// need `Box<dyn Hash>` (Go returns the hash.Hash interface directly).
pub fn NewHash() -> alloc::boxed::Box<dyn Hash + Send + Sync> {
    return fips::NewHash();
}

// go: none — see NewHash.
pub fn NewHash224() -> alloc::boxed::Box<dyn Hash + Send + Sync> {
    return fips::NewHash224();
}
