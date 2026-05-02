// hash — Go's `hash` package, ported.
//
// Trait surface mirrors Go's interface hierarchy:
//
//   Go                                     goish
//   ────────────────────────────────────   ─────────────────────────────
//   type Hash interface { io.Writer; ... }  pub trait Hash: io::Writer
//   type Hash32 interface { Hash; ... }     pub trait Hash32: Hash
//   type Hash64 interface { Hash; ... }     pub trait Hash64: Hash
//
// Implementations live in submodules: hash::fnv (FNV-1, FNV-1a),
// future hash::crc32, etc. Each Write returns `(int, error)` — `error`
// is always nil per Go's spec ("It never returns an error.").
//
// Slim deviations from Go:
//   * No Cloner / XOF / encoding.BinaryMarshaler — extras can be added
//     per-implementation later.
//   * Sum takes `slice<byte>` and returns `slice<byte>` (matches the
//     goish primitive convention; Go uses `[]byte`).

#![allow(non_snake_case)]

pub mod adler32;
pub mod crc32;
pub mod crc64;
pub mod fnv;

use crate::goslice::slice;
use crate::io;
use crate::types::{byte, int};

/// `hash.Hash` (hash/hash.go:26) — common interface for all hash
/// functions. Implementors must also implement `io::Writer` (Write is
/// inherited; it never returns an error per Go's contract).
pub trait Hash: io::Writer {
    /// `Sum(b)` — append the current hash to `b` and return the
    /// resulting slice. Does not change the underlying hash state.
    fn Sum(&self, b: slice<byte>) -> slice<byte>;
    /// `Reset()` — reset the Hash to its initial state.
    fn Reset(&mut self);
    /// `Size()` — number of bytes Sum will append.
    fn Size(&self) -> int;
    /// `BlockSize()` — the hash's underlying block size.
    fn BlockSize(&self) -> int;
}

/// `hash.Hash32` (hash/hash.go:49) — 32-bit hash with `Sum32`.
pub trait Hash32: Hash {
    fn Sum32(&self) -> u32;
}

/// `hash.Hash64` (hash/hash.go:55) — 64-bit hash with `Sum64`.
pub trait Hash64: Hash {
    fn Sum64(&self) -> u64;
}
