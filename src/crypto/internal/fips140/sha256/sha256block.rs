// go: file crypto/internal/fips140/sha256/sha256block.go decls: blockGeneric
//
// Deviation: goish names the function `block` and calls it directly.
// Go splits the dispatch across sha256block_asm[go] (`//go:build !purego`,
// SHA-NI) and sha256block_noasm[go] (`block` -> `blockGeneric`); goish has
// no SHA-NI path yet, so `block` IS the generic implementation. Porting
// sha256block_amd64.s is tracked as performance work (CRYPTO_PORT.md).

#![allow(non_snake_case, non_upper_case_globals)]

use crate::math::bits;
use crate::types::byte;

extern crate alloc;

use super::sha256::{Digest, CHUNK};

// Round constants (FIPS 180-4 §4.2.2).
const _K: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
    0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
    0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
    0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
    0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
    0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

// ─── Digest (Go: fips140 sha256[go]:50) ────────────────────────────────

/// `sha256` digest — partial SHA-224/SHA-256 evaluation.

// go: sdk 1.25.5 crypto/internal/fips140/sha256/sha256block.go:80-128
//
// goish names it `block`: Go's sha256block_noasm[go] defines
// `block(dig,p) { blockGeneric(dig,p) }` and sha256block_asm[go] defines
// the SHA-NI dispatch. With no SHA-NI path yet, the two collapse.
// Go: blockGeneric (sha256block[go]:80)
pub(crate) fn blockGeneric(dig: &mut Digest, mut p: &[byte]) {
    let mut w = [0u32; 64];
    // Go: h0..h7 := dig.h[0..7]
    let mut h0 = dig.h[0];
    let mut h1 = dig.h[1];
    let mut h2 = dig.h[2];
    let mut h3 = dig.h[3];
    let mut h4 = dig.h[4];
    let mut h5 = dig.h[5];
    let mut h6 = dig.h[6];
    let mut h7 = dig.h[7];
    // Go: for len(p) >= chunk
    while p.len() >= CHUNK {
        // Go: for i := 0; i < 16; i++ { w[i] = BE u32 of p[i*4..] }
        let mut i: usize = 0;
        while i < 16 {
            let j = i * 4;
            w[i] = ((p[j] as u32) << 24)
                | ((p[j + 1] as u32) << 16)
                | ((p[j + 2] as u32) << 8)
                | (p[j + 3] as u32);
            i += 1;
        }
        // Go: for i := 16; i < 64; i++
        let mut i = 16;
        while i < 64 {
            // Go: t1 := (RotateLeft32(v1, -17)) ^ (RotateLeft32(v1, -19)) ^ (v1 >> 10)
            let v1 = w[i - 2];
            let t1 = bits::RotateLeft32(v1, -17)
                ^ bits::RotateLeft32(v1, -19)
                ^ (v1 >> 10);
            let v2 = w[i - 15];
            let t2 = bits::RotateLeft32(v2, -7)
                ^ bits::RotateLeft32(v2, -18)
                ^ (v2 >> 3);
            w[i] = t1
                .wrapping_add(w[i - 7])
                .wrapping_add(t2)
                .wrapping_add(w[i - 16]);
            i += 1;
        }

        let (mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h) =
            (h0, h1, h2, h3, h4, h5, h6, h7);

        let mut i = 0;
        while i < 64 {
            // Go: t1 := h + (RotateLeft32(e,-6) ^ RotateLeft32(e,-11) ^ RotateLeft32(e,-25))
            //          + ((e & f) ^ (^e & g)) + _K[i] + w[i]
            let s1 = bits::RotateLeft32(e, -6)
                ^ bits::RotateLeft32(e, -11)
                ^ bits::RotateLeft32(e, -25);
            let ch = (e & f) ^ ((!e) & g);
            let t1 = h
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(_K[i])
                .wrapping_add(w[i]);
            // Go: t2 := (RotateLeft32(a,-2) ^ RotateLeft32(a,-13) ^ RotateLeft32(a,-22))
            //          + ((a & b) ^ (a & c) ^ (b & c))
            let s0 = bits::RotateLeft32(a, -2)
                ^ bits::RotateLeft32(a, -13)
                ^ bits::RotateLeft32(a, -22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let t2 = s0.wrapping_add(maj);

            h = g;
            g = f;
            f = e;
            e = d.wrapping_add(t1);
            d = c;
            c = b;
            b = a;
            a = t1.wrapping_add(t2);
            i += 1;
        }

        h0 = h0.wrapping_add(a);
        h1 = h1.wrapping_add(b);
        h2 = h2.wrapping_add(c);
        h3 = h3.wrapping_add(d);
        h4 = h4.wrapping_add(e);
        h5 = h5.wrapping_add(f);
        h6 = h6.wrapping_add(g);
        h7 = h7.wrapping_add(h);

        // Go: p = p[chunk:]
        p = &p[CHUNK..];
    }

    dig.h[0] = h0;
    dig.h[1] = h1;
    dig.h[2] = h2;
    dig.h[3] = h3;
    dig.h[4] = h4;
    dig.h[5] = h5;
    dig.h[6] = h6;
    dig.h[7] = h7;
}

// ─── Inherent Digest methods — Go-faithful surface ────────────────────
//
// Mirrors `(*Digest).Write` / `Sum` / `Reset` / `Size` / `BlockSize`
// from Go's `hash` package. The same signatures are exposed via the
// `io::Writer` and `Hash` trait impls below; the inherent forms let
// callers reach for `d.Write(p)` / `d.Sum(b)` without bringing the
// traits into scope. Goish's call-as-Go convention expects this:
// transpiled code reads `hw.Write(bytes(hid))` and `hw.Sum(nil)`
// without an extra `use io::Writer; use hash::Hash;` import the
// caller never wrote in Go.
