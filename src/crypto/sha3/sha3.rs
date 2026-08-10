// goishlint:ignore GOISH018 — two functions are not ported. `init` is
// `crypto.RegisterHash(crypto.SHA3_224, …)`; goish has no crypto.Hash
// registry. `fips140hash_sha3Unwrap` is the target of a `//go:linkname`
// from crypto/internal/fips140hash, which reaches into this package to
// recover the inner fips140 Digest; goish has no linkname and no
// fips140hash port, and the `d` field is `pub(crate)` here so the same
// unwrap is a plain field access once that package lands.
// go: file crypto/sha3/sha3.go decls: Sum224, Sum256, Sum384, Sum512, SumSHAKE128, sumSHAKE128, SumSHAKE256, sumSHAKE256, New224, New256, New384, New512, SHA3.Write, SHA3.Sum, SHA3.Reset, SHA3.Size, SHA3.BlockSize, SHA3.MarshalBinary, SHA3.AppendBinary, SHA3.UnmarshalBinary, SHA3.Clone, NewSHAKE128, NewSHAKE256, NewCSHAKE128, NewCSHAKE256, SHAKE.Write, SHAKE.Read, SHAKE.Reset, SHAKE.BlockSize, SHAKE.MarshalBinary, SHAKE.AppendBinary, SHAKE.UnmarshalBinary, NewHash224, NewHash256, NewHash384, NewHash512, register_sha3_impls, __goish_as_dyn_any, __goish_as_dyn_any_mut
//
// Package sha3 implements the SHA-3 fixed-output-length hash functions
// and the SHAKE variable-output-length functions defined by FIPS 202, as
// well as the cSHAKE extendable-output-length functions defined by
// SP 800-185. Go 1.25 makes this a thin wrapper over
// crypto/internal/fips140/sha3; goish follows.
//
// Deviations: constructors return the concrete type by value rather than
// `*SHA3` / `*SHAKE`, and `SHA3.Clone` returns `SHA3` rather than the
// `hash.Cloner` interface (the boxed-interface form is on the inner
// fips140 Digest, which implements `hash::Cloner`).

#![allow(non_snake_case, non_upper_case_globals)]

use crate::crypto::internal::fips140::sha3 as fips;
use crate::errors::error;
use crate::goslice::slice;
use crate::hash::Hash;
use crate::io;
use crate::types::{byte, int};

extern crate alloc;
use alloc::boxed::Box;
use alloc::vec::Vec;

/// `sha3.Size224` — SHA3-224 checksum length in bytes.
pub const Size224: int = 28;
/// `sha3.Size256` — SHA3-256 checksum length in bytes.
pub const Size256: int = 32;
/// `sha3.Size384` — SHA3-384 checksum length in bytes.
pub const Size384: int = 48;
/// `sha3.Size512` — SHA3-512 checksum length in bytes.
pub const Size512: int = 64;

// Go: sha3.go:100
//   type SHA3 struct { s sha3.Digest }
/// `sha3.SHA3` — a SHA-3 hash. goish's pre-fips140 port called this
/// `Digest`; the alias in mod[rs] keeps that name working.
#[derive(Clone)]
pub struct SHA3 {
    pub(crate) s: fips::Digest,
}

// ─── Constructors ─────────────────────────────────────────────────────

// go: sdk 1.25.5 crypto/sha3/sha3.go:110-112 New224
/// `sha3.New224()` — a new SHA3-224 hash.
pub fn New224() -> SHA3 {
    // Go: return &SHA3{*sha3.New224()}
    return SHA3 { s: fips::New224() };
}

// go: sdk 1.25.5 crypto/sha3/sha3.go:115-117 New256
/// `sha3.New256()` — a new SHA3-256 hash.
pub fn New256() -> SHA3 {
    return SHA3 { s: fips::New256() };
}

// go: sdk 1.25.5 crypto/sha3/sha3.go:120-122 New384
/// `sha3.New384()` — a new SHA3-384 hash.
pub fn New384() -> SHA3 {
    return SHA3 { s: fips::New384() };
}

// go: sdk 1.25.5 crypto/sha3/sha3.go:125-127 New512
/// `sha3.New512()` — a new SHA3-512 hash.
pub fn New512() -> SHA3 {
    return SHA3 { s: fips::New512() };
}

impl SHA3 {
    // go: sdk 1.25.5 crypto/sha3/sha3.go:130-132 Write
    /// `(*SHA3).Write(p)` — absorb more data.
    pub fn Write(&mut self, p: slice<byte>) -> (int, error) {
        // Go: return h.s.Write(p)
        return self.s.Write(p);
    }

    // go: sdk 1.25.5 crypto/sha3/sha3.go:135-137 Sum
    /// `(*SHA3).Sum(b)` — append the current hash to `b`.
    pub fn Sum<B: Into<slice<byte>>>(&self, b: B) -> slice<byte> {
        // Go: return h.s.Sum(b)
        return self.s.Sum(b.into());
    }

    // go: sdk 1.25.5 crypto/sha3/sha3.go:140-142 Reset
    /// `(*SHA3).Reset()` — reset to the initial state.
    pub fn Reset(&mut self) {
        // Go: h.s.Reset()
        self.s.Reset();
    }

    // go: sdk 1.25.5 crypto/sha3/sha3.go:145-147 Size
    /// `(*SHA3).Size()` — output size in bytes.
    pub fn Size(&self) -> int {
        // Go: return h.s.Size()
        return self.s.Size();
    }

    // go: sdk 1.25.5 crypto/sha3/sha3.go:150-152 BlockSize
    /// `(*SHA3).BlockSize()` — the sponge rate in bytes.
    pub fn BlockSize(&self) -> int {
        // Go: return h.s.BlockSize()
        return self.s.BlockSize();
    }

    // go: sdk 1.25.5 crypto/sha3/sha3.go:155-157 MarshalBinary
    /// `(*SHA3).MarshalBinary()` — the sponge's internal state.
    pub fn MarshalBinary(&self) -> (slice<byte>, error) {
        // Go: return h.s.MarshalBinary()
        return self.s.MarshalBinary();
    }

    // go: sdk 1.25.5 crypto/sha3/sha3.go:160-162 AppendBinary
    /// `(*SHA3).AppendBinary(b)` — append the marshaled state to `b`.
    pub fn AppendBinary(&self, b: slice<byte>) -> (slice<byte>, error) {
        // Go: return h.s.AppendBinary(b)
        return self.s.AppendBinary(b);
    }

    // go: sdk 1.25.5 crypto/sha3/sha3.go:165-167 UnmarshalBinary
    /// `(*SHA3).UnmarshalBinary(b)` — restore a marshaled state.
    pub fn UnmarshalBinary(&mut self, b: slice<byte>) -> error {
        // Go: return h.s.UnmarshalBinary(b)
        return self.s.UnmarshalBinary(b);
    }

    // go: sdk 1.25.5 crypto/sha3/sha3.go:170-173 Clone
    /// `(*SHA3).Clone()` — an independent copy of this hash's state.
    pub fn Clone(&self) -> SHA3 {
        // Go: r := *h; return &r, nil
        return Clone::clone(self);
    }
}

// ─── One-shot sums ────────────────────────────────────────────────────

// go: sdk 1.25.5 crypto/sha3/sha3.go:24-30 Sum224
/// `sha3.Sum224(data)` — SHA3-224 of `data`.
pub fn Sum224(data: slice<byte>) -> [byte; 28] {
    // Go: var out [28]byte; h := New224(); h.Write(data); h.Sum(out[:0]); return out
    let mut h = New224();
    let _ = h.Write(data);
    let s = h.Sum(slice::__from_vec(Vec::new()));
    let raw: &[byte] = &s;
    let mut out = [0u8; 28];
    out.copy_from_slice(&raw[..28]);
    return out;
}

// go: sdk 1.25.5 crypto/sha3/sha3.go:33-39 Sum256
/// `sha3.Sum256(data)` — SHA3-256 of `data`.
pub fn Sum256(data: slice<byte>) -> [byte; 32] {
    let mut h = New256();
    let _ = h.Write(data);
    let s = h.Sum(slice::__from_vec(Vec::new()));
    let raw: &[byte] = &s;
    let mut out = [0u8; 32];
    out.copy_from_slice(&raw[..32]);
    return out;
}

// go: sdk 1.25.5 crypto/sha3/sha3.go:42-48 Sum384
/// `sha3.Sum384(data)` — SHA3-384 of `data`.
pub fn Sum384(data: slice<byte>) -> [byte; 48] {
    let mut h = New384();
    let _ = h.Write(data);
    let s = h.Sum(slice::__from_vec(Vec::new()));
    let raw: &[byte] = &s;
    let mut out = [0u8; 48];
    out.copy_from_slice(&raw[..48]);
    return out;
}

// go: sdk 1.25.5 crypto/sha3/sha3.go:51-57 Sum512
/// `sha3.Sum512(data)` — SHA3-512 of `data`.
pub fn Sum512(data: slice<byte>) -> [byte; 64] {
    let mut h = New512();
    let _ = h.Write(data);
    let s = h.Sum(slice::__from_vec(Vec::new()));
    let raw: &[byte] = &s;
    let mut out = [0u8; 64];
    out.copy_from_slice(&raw[..64]);
    return out;
}

// ─── SHAKE ────────────────────────────────────────────────────────────

// Go: sha3.go:176
//   type SHAKE struct { s sha3.SHAKE }
/// `sha3.SHAKE` — a SHAKE or cSHAKE extendable-output function.
#[derive(Clone)]
pub struct SHAKE {
    pub(crate) s: fips::SHAKE,
}

// go: sdk 1.25.5 crypto/sha3/sha3.go:181-183 NewSHAKE128
/// `sha3.NewSHAKE128()` — a new SHAKE128 XOF.
pub fn NewSHAKE128() -> SHAKE {
    // Go: return &SHAKE{*sha3.NewShake128()}
    return SHAKE {
        s: fips::NewShake128(),
    };
}

// go: sdk 1.25.5 crypto/sha3/sha3.go:186-188 NewSHAKE256
/// `sha3.NewSHAKE256()` — a new SHAKE256 XOF.
pub fn NewSHAKE256() -> SHAKE {
    return SHAKE {
        s: fips::NewShake256(),
    };
}

// go: sdk 1.25.5 crypto/sha3/sha3.go:195-197 NewCSHAKE128
/// `sha3.NewCSHAKE128(N, S)` — a new cSHAKE128 XOF. `N` names a function
/// built on cSHAKE; `S` is a customization string for domain separation.
/// When both are empty this is equivalent to [`NewSHAKE128`].
pub fn NewCSHAKE128(N: slice<byte>, S: slice<byte>) -> SHAKE {
    // Go: return &SHAKE{*sha3.NewCShake128(N, S)}
    return SHAKE {
        s: fips::NewCShake128(N, S),
    };
}

// go: sdk 1.25.5 crypto/sha3/sha3.go:204-206 NewCSHAKE256
/// `sha3.NewCSHAKE256(N, S)` — a new cSHAKE256 XOF. See [`NewCSHAKE128`].
pub fn NewCSHAKE256(N: slice<byte>, S: slice<byte>) -> SHAKE {
    return SHAKE {
        s: fips::NewCShake256(N, S),
    };
}

impl SHAKE {
    // go: sdk 1.25.5 crypto/sha3/sha3.go:211-213 Write
    /// `(*SHAKE).Write(p)` — absorb more data. Panics if any output has
    /// already been read.
    pub fn Write(&mut self, p: slice<byte>) -> (int, error) {
        // Go: return s.s.Write(p)
        return self.s.Write(p);
    }

    // go: sdk 1.25.5 crypto/sha3/sha3.go:218-220 Read
    /// `(*SHAKE).Read(out)` — squeeze output. Never returns an error.
    pub fn Read(&mut self, out: &mut [byte]) -> usize {
        // Go: return s.s.Read(p)
        return self.s.Read(out);
    }

    // go: sdk 1.25.5 crypto/sha3/sha3.go:223-225 Reset
    /// `(*SHAKE).Reset()` — reset to the initial state.
    pub fn Reset(&mut self) {
        // Go: s.s.Reset()
        self.s.Reset();
    }

    // go: sdk 1.25.5 crypto/sha3/sha3.go:228-230 BlockSize
    /// `(*SHAKE).BlockSize()` — the sponge rate in bytes.
    pub fn BlockSize(&self) -> int {
        // Go: return s.s.BlockSize()
        return self.s.BlockSize();
    }

    // go: sdk 1.25.5 crypto/sha3/sha3.go:233-235 MarshalBinary
    /// `(*SHAKE).MarshalBinary()` — the sponge state plus cSHAKE init
    /// block.
    pub fn MarshalBinary(&self) -> (slice<byte>, error) {
        // Go: return s.s.MarshalBinary()
        return self.s.MarshalBinary();
    }

    // go: sdk 1.25.5 crypto/sha3/sha3.go:238-240 AppendBinary
    /// `(*SHAKE).AppendBinary(b)` — append the marshaled state to `b`.
    pub fn AppendBinary(&self, b: slice<byte>) -> (slice<byte>, error) {
        // Go: return s.s.AppendBinary(b)
        return self.s.AppendBinary(b);
    }

    // go: sdk 1.25.5 crypto/sha3/sha3.go:243-245 UnmarshalBinary
    /// `(*SHAKE).UnmarshalBinary(b)` — restore a marshaled state.
    pub fn UnmarshalBinary(&mut self, b: slice<byte>) -> error {
        // Go: return s.s.UnmarshalBinary(b)
        return self.s.UnmarshalBinary(b);
    }
}

// go: sdk 1.25.5 crypto/sha3/sha3.go:61-65 SumSHAKE128
/// `sha3.SumSHAKE128(data, length)` — `length` bytes of SHAKE128 output
/// over `data`.
pub fn SumSHAKE128(data: slice<byte>, length: int) -> slice<byte> {
    // Go: return sumSHAKE128(data, length)
    return sumSHAKE128(data, length);
}

// go: sdk 1.25.5 crypto/sha3/sha3.go:67-77 sumSHAKE128
/// Go: `func sumSHAKE128(data []byte, length int) []byte`
fn sumSHAKE128(data: slice<byte>, length: int) -> slice<byte> {
    // Go: h := sha3.NewShake128(); h.Write(data); return h.Sum(…)
    let mut h = NewSHAKE128();
    let _ = h.Write(data);
    let mut out: Vec<byte> = alloc::vec![0u8; length as usize];
    h.Read(&mut out);
    return slice::__from_vec(out);
}

// go: sdk 1.25.5 crypto/sha3/sha3.go:81-85 SumSHAKE256
/// `sha3.SumSHAKE256(data, length)` — `length` bytes of SHAKE256 output
/// over `data`.
pub fn SumSHAKE256(data: slice<byte>, length: int) -> slice<byte> {
    // Go: return sumSHAKE256(data, length)
    return sumSHAKE256(data, length);
}

// go: sdk 1.25.5 crypto/sha3/sha3.go:87-97 sumSHAKE256
/// Go: `func sumSHAKE256(data []byte, length int) []byte`
fn sumSHAKE256(data: slice<byte>, length: int) -> slice<byte> {
    let mut h = NewSHAKE256();
    let _ = h.Write(data);
    let mut out: Vec<byte> = alloc::vec![0u8; length as usize];
    h.Read(&mut out);
    return slice::__from_vec(out);
}

// ─── hash.Hash trait impls ────────────────────────────────────────────

impl io::Writer for SHA3 {
    // go: sdk 1.25.5 crypto/sha3/sha3.go:130-132 Write
    fn Write(&mut self, p: slice<byte>) -> (int, error) {
        return SHA3::Write(self, p);
    }
    // go: none — goish idiom: the hidden Any-view hook every
    // `#[goish::interface]` concrete impl overrides so `carrier.As::<…>()`
    // can reach this type. Go's itabs make it unnecessary.
    fn __goish_as_dyn_any(&self) -> Option<&(dyn core::any::Any + Send + Sync)> {
        return Some(self);
    }
    // go: none — goish idiom: see __goish_as_dyn_any above.
    fn __goish_as_dyn_any_mut(&mut self) -> Option<&mut (dyn core::any::Any + Send + Sync)> {
        return Some(self);
    }
}

impl Hash for SHA3 {
    // go: sdk 1.25.5 crypto/sha3/sha3.go:135-137 Sum
    fn Sum(&self, b: slice<byte>) -> slice<byte> {
        return SHA3::Sum(self, b);
    }
    // go: sdk 1.25.5 crypto/sha3/sha3.go:140-142 Reset
    fn Reset(&mut self) {
        SHA3::Reset(self);
    }
    // go: sdk 1.25.5 crypto/sha3/sha3.go:145-147 Size
    fn Size(&self) -> int {
        return SHA3::Size(self);
    }
    // go: sdk 1.25.5 crypto/sha3/sha3.go:150-152 BlockSize
    fn BlockSize(&self) -> int {
        return SHA3::BlockSize(self);
    }
}

// ─── Boxed constructors for trait-object consumers (e.g. hmac::New) ───

// go: none — goish idiom: boxed-trait constructors for call sites that
// need `Box<dyn Hash>` (Go returns the hash.Hash interface directly).
/// Use with `hmac::New(crypto::sha3::NewHash256, key)`.
pub fn NewHash224() -> Box<dyn Hash + Send + Sync> {
    return Box::new(New224());
}

// go: none — see NewHash224.
/// `sha3.NewHash256()` — boxed SHA3-256 constructor.
pub fn NewHash256() -> Box<dyn Hash + Send + Sync> {
    return Box::new(New256());
}

// go: none — see NewHash224.
/// `sha3.NewHash384()` — boxed SHA3-384 constructor.
pub fn NewHash384() -> Box<dyn Hash + Send + Sync> {
    return Box::new(New384());
}

// go: none — see NewHash224.
/// `sha3.NewHash512()` — boxed SHA3-512 constructor.
pub fn NewHash512() -> Box<dyn Hash + Send + Sync> {
    return Box::new(New512());
}

// go: none — goish idiom: `#[goish::interface]` downcast registries are
// filled at runtime, one entry per `impl Trait for Concrete`; Go's itabs
// are built by the linker. Idempotent and cheap.
/// Register the inner fips140 `Digest` into the `hash::Cloner` and
/// `encoding::Binary*` registries.
pub fn register_sha3_impls() {
    fips::register_sha3_impls();
}
