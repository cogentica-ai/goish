// goishlint:ignore GOISH018 — `init` (sha512[go]) is
// `crypto.RegisterHash(crypto.SHA384/SHA512/SHA512_224/SHA512_256, …)`.
// goish has no crypto.Hash registry, so there is nothing to register
// into; port it with that registry.
// go: file crypto/sha512/sha512.go decls: New, New384, New512_224, New512_256, Sum512, Sum384, Sum512_224, Sum512_256
//
// Package sha512 implements the SHA-384, SHA-512, SHA-512/224 and
// SHA-512/256 hash algorithms as defined in FIPS 180-4. Go 1.25 makes
// this a thin wrapper over crypto/internal/fips140/sha512; goish follows.
//
// Deviation: no crypto.RegisterHash init (goish has no hash registry) and
// no boring branches.

#![allow(non_snake_case, non_upper_case_globals)]

extern crate alloc;

use crate::crypto::internal::fips140::sha512 as fips;
use crate::goslice::slice;
use crate::hash::Hash;
use crate::io;
use crate::types::{byte, int};
use alloc::vec::Vec;

pub use fips::Digest;

// ─── Constants (Go: sha512.go:27-43) ──────────────────────────────────

/// `sha512.Size` — SHA-512 checksum length (bytes).
pub const Size: int = 64;

/// `sha512.Size224` — SHA-512/224 checksum length (bytes).
pub const Size224: int = 28;

/// `sha512.Size256` — SHA-512/256 checksum length (bytes).
pub const Size256: int = 32;

/// `sha512.Size384` — SHA-384 checksum length (bytes).
pub const Size384: int = 48;

/// `sha512.BlockSize` — SHA-512 family block size (bytes).
pub const BlockSize: int = 128;

// go: sdk 1.25.5 crypto/sha512/sha512.go:49-54 New
/// `sha512.New()` — a new SHA-512 hash. The Hash also implements
/// `encoding::BinaryMarshaler`, `encoding::BinaryAppender`,
/// `encoding::BinaryUnmarshaler` and `hash::Cloner`.
pub fn New() -> Digest {
    // Go: return sha512.New()
    return fips::New();
}

// go: sdk 1.25.5 crypto/sha512/sha512.go:60-62 New512_224
/// `sha512.New512_224()` — a new SHA-512/224 hash.
pub fn New512_224() -> Digest {
    // Go: return sha512.New512_224()
    return fips::New512_224();
}

// go: sdk 1.25.5 crypto/sha512/sha512.go:68-70 New512_256
/// `sha512.New512_256()` — a new SHA-512/256 hash.
pub fn New512_256() -> Digest {
    // Go: return sha512.New512_256()
    return fips::New512_256();
}

// go: sdk 1.25.5 crypto/sha512/sha512.go:76-81 New384
/// `sha512.New384()` — a new SHA-384 hash.
pub fn New384() -> Digest {
    // Go: return sha512.New384()
    return fips::New384();
}

// go: sdk 1.25.5 crypto/sha512/sha512.go:84-93 Sum512
/// `sha512.Sum512(data)` — SHA-512 of `data`.
pub fn Sum512(data: slice<byte>) -> [byte; 64] {
    // Go: h := New(); h.Write(data); var sum [Size]byte; h.Sum(sum[:0]); return sum
    let mut h = New();
    let _ = io::Writer::Write(&mut h, data);
    let out = h.Sum(slice::__from_vec(Vec::new()));
    let raw: &[byte] = &out;
    let mut sum = [0u8; 64];
    sum.copy_from_slice(&raw[..64]);
    return sum;
}

// go: sdk 1.25.5 crypto/sha512/sha512.go:96-105 Sum384
/// `sha512.Sum384(data)` — SHA-384 of `data`.
pub fn Sum384(data: slice<byte>) -> [byte; 48] {
    let mut h = New384();
    let _ = io::Writer::Write(&mut h, data);
    let out = h.Sum(slice::__from_vec(Vec::new()));
    let raw: &[byte] = &out;
    let mut sum = [0u8; 48];
    sum.copy_from_slice(&raw[..48]);
    return sum;
}

// go: sdk 1.25.5 crypto/sha512/sha512.go:108-114 Sum512_224
/// `sha512.Sum512_224(data)` — SHA-512/224 of `data`.
pub fn Sum512_224(data: slice<byte>) -> [byte; 28] {
    let mut h = New512_224();
    let _ = io::Writer::Write(&mut h, data);
    let out = h.Sum(slice::__from_vec(Vec::new()));
    let raw: &[byte] = &out;
    let mut sum = [0u8; 28];
    sum.copy_from_slice(&raw[..28]);
    return sum;
}

// go: sdk 1.25.5 crypto/sha512/sha512.go:117-123 Sum512_256
/// `sha512.Sum512_256(data)` — SHA-512/256 of `data`.
pub fn Sum512_256(data: slice<byte>) -> [byte; 32] {
    let mut h = New512_256();
    let _ = io::Writer::Write(&mut h, data);
    let out = h.Sum(slice::__from_vec(Vec::new()));
    let raw: &[byte] = &out;
    let mut sum = [0u8; 32];
    sum.copy_from_slice(&raw[..32]);
    return sum;
}

// ─── Boxed constructors for trait-object consumers (e.g. hmac::New) ───

// go: none — goish idiom: boxed-trait constructors for call sites that
// need `Box<dyn Hash>` (Go returns the hash.Hash interface directly).
/// `sha512.NewHash()` — boxed constructor matching `hash.Hash`.
pub fn NewHash() -> alloc::boxed::Box<dyn Hash + Send + Sync> {
    return fips::NewHash();
}

// go: none — see NewHash.
/// `sha512.NewHash384()` — boxed SHA-384 constructor.
pub fn NewHash384() -> alloc::boxed::Box<dyn Hash + Send + Sync> {
    return fips::NewHash384();
}

// go: none — see NewHash.
/// `sha512.NewHash512_224()` — boxed SHA-512/224 constructor.
pub fn NewHash512_224() -> alloc::boxed::Box<dyn Hash + Send + Sync> {
    return fips::NewHash512_224();
}

// go: none — see NewHash.
/// `sha512.NewHash512_256()` — boxed SHA-512/256 constructor.
pub fn NewHash512_256() -> alloc::boxed::Box<dyn Hash + Send + Sync> {
    return fips::NewHash512_256();
}
