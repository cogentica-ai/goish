// go: file crypto/internal/randutil/randutil.go decls: MaybeReadByte
//
// Package randutil contains internal randomness utilities for various
// crypto packages.

#![allow(non_snake_case)]

extern crate alloc;

use crate::goslice::slice;
use crate::io;
use crate::math::rand;
use crate::types::byte;

// go: sdk 1.25.5 crypto/internal/randutil/randutil.go:13-25 MaybeReadByte
/// Read a single byte from `r` with 50% probability. This is used to
/// ensure that callers do not depend on non-guaranteed behaviour, e.g.
/// assuming that rsa.GenerateKey is deterministic w.r.t. a given random
/// stream.
///
/// This does not affect tests that pass a stream of fixed bytes as the
/// random source (e.g. a zeroReader).
pub fn MaybeReadByte(r: &mut (dyn io::Reader + Send + Sync + 'static)) {
    // Go: if rand.Uint64()&1 == 1 { return }
    if rand::Uint64() & 1 == 1 {
        return;
    }
    // Go: var buf [1]byte; r.Read(buf[:])
    let mut buf = slice::__from_vec(alloc::vec![0u8; 1]);
    let _ = r.Read(&mut buf);
    let _: &[byte] = &buf;
}
