// crypto/sha256 — Go's `crypto/sha256`, ported (SHA-224 + SHA-256).
//
// FIPS 180-4. Inlines the generic block function from
// crypto/internal/fips140/sha256/{sha256.go, sha256block.go}; goish
// has no separate fips140 internal package layer.
//
// Slim deviations:
//   * No MarshalBinary / UnmarshalBinary / AppendBinary / Clone
//     (cosmetic state save/restore; not needed for HTTP work).
//   * No assembly fast path; only the generic block function.
//     Go's amd64/arm64/etc. files use SHA-NI / NEON; goish uses the
//     scalar loop. Performance is ~3-5x slower than Go on native amd64
//     but algorithmically identical.
//   * `New()` / `New224()` return `Digest` directly, not `hash.Hash`.

#![allow(non_snake_case, non_upper_case_globals)]

use crate::errors::{error, nil};
use crate::goslice::slice;
use crate::hash::Hash;
use crate::io;
use crate::math::bits;
use crate::types::{byte, int};

extern crate alloc;
use alloc::vec::Vec;

// ─── Constants (Go: sha256.go:21-28; fips140 sha256.go:17-23) ─────────

/// `sha256.Size` — SHA-256 checksum length (bytes).
pub const Size: int = 32;

/// `sha256.Size224` — SHA-224 checksum length (bytes).
pub const Size224: int = 28;

/// `sha256.BlockSize` — block size of SHA-256/SHA-224 (bytes).
pub const BlockSize: int = 64;

const CHUNK: usize = 64;

// SHA-256 IV (FIPS 180-4 §5.3.3).
const init0: u32 = 0x6A09E667;
const init1: u32 = 0xBB67AE85;
const init2: u32 = 0x3C6EF372;
const init3: u32 = 0xA54FF53A;
const init4: u32 = 0x510E527F;
const init5: u32 = 0x9B05688C;
const init6: u32 = 0x1F83D9AB;
const init7: u32 = 0x5BE0CD19;

// SHA-224 IV (FIPS 180-4 §5.3.2).
const init0_224: u32 = 0xC1059ED8;
const init1_224: u32 = 0x367CD507;
const init2_224: u32 = 0x3070DD17;
const init3_224: u32 = 0xF70E5939;
const init4_224: u32 = 0xFFC00B31;
const init5_224: u32 = 0x68581511;
const init6_224: u32 = 0x64F98FA7;
const init7_224: u32 = 0xBEFA4FA4;

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

// ─── Digest (Go: fips140 sha256.go:50) ────────────────────────────────

/// `sha256` digest — partial SHA-224/SHA-256 evaluation.
pub struct Digest {
    h: [u32; 8],
    x: [byte; CHUNK],
    nx: usize,
    len: u64,
    is224: bool,
}

/// `sha256.New()` (sha256.go:34) — new SHA-256 digest.
pub fn New() -> Digest {
    // Go: d := new(Digest); d.Reset(); return d
    let mut d = Digest {
        h: [0; 8],
        x: [0; CHUNK],
        nx: 0,
        len: 0,
        is224: false,
    };
    d.Reset();
    d
}

/// `sha256.New224()` (sha256.go:45) — new SHA-224 digest.
pub fn New224() -> Digest {
    // Go: d := new(Digest); d.is224 = true; d.Reset(); return d
    let mut d = Digest {
        h: [0; 8],
        x: [0; CHUNK],
        nx: 0,
        len: 0,
        is224: true,
    };
    d.Reset();
    d
}

// Go: blockGeneric (sha256block.go:80)
fn block(dig: &mut Digest, mut p: &[byte]) {
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

// ─── Hash trait impls for Digest ──────────────────────────────────────

impl io::Writer for Digest {
    fn Write(&mut self, p: slice<byte>) -> (int, error) {
        // Go: nn = len(p); d.len += uint64(nn)
        let raw: &[byte] = &p;
        let nn = raw.len();
        self.len += nn as u64;
        let mut q: &[byte] = raw;
        // Go: if d.nx > 0 { copy into d.x; if full, block; }
        if self.nx > 0 {
            let copy_n = core::cmp::min(CHUNK - self.nx, q.len());
            self.x[self.nx..self.nx + copy_n].copy_from_slice(&q[..copy_n]);
            self.nx += copy_n;
            if self.nx == CHUNK {
                // Slim: clone the buffer to avoid double-borrow on self.
                let buf = self.x;
                block(self, &buf);
                self.nx = 0;
            }
            q = &q[copy_n..];
        }
        // Go: if len(p) >= chunk { ... block(d, p[:n]) ... }
        if q.len() >= CHUNK {
            let n = q.len() & !(CHUNK - 1);
            block(self, &q[..n]);
            q = &q[n..];
        }
        // Go: if len(p) > 0 { d.nx = copy(d.x[:], p) }
        if !q.is_empty() {
            self.x[..q.len()].copy_from_slice(q);
            self.nx = q.len();
        }
        (nn as int, nil)
    }
}

impl Hash for Digest {
    fn Sum(&self, b: slice<byte>) -> slice<byte> {
        // Go: d0 := *d; hash := d0.checkSum(); ...
        // Slim: copy state into a fresh struct (no Clone derive on
        // arrays — write each field).
        let mut d0 = Digest {
            h: self.h,
            x: self.x,
            nx: self.nx,
            len: self.len,
            is224: self.is224,
        };
        let digest = check_sum(&mut d0);
        // Go: if d0.is224 { return append(in, hash[:size224]...) }
        //     return append(in, hash[:]...)
        let mut out: Vec<byte> = b.__into_vec();
        let limit = if self.is224 { Size224 as usize } else { Size as usize };
        out.extend_from_slice(&digest[..limit]);
        slice::__from_vec(out)
    }
    fn Reset(&mut self) {
        if !self.is224 {
            self.h[0] = init0;
            self.h[1] = init1;
            self.h[2] = init2;
            self.h[3] = init3;
            self.h[4] = init4;
            self.h[5] = init5;
            self.h[6] = init6;
            self.h[7] = init7;
        } else {
            self.h[0] = init0_224;
            self.h[1] = init1_224;
            self.h[2] = init2_224;
            self.h[3] = init3_224;
            self.h[4] = init4_224;
            self.h[5] = init5_224;
            self.h[6] = init6_224;
            self.h[7] = init7_224;
        }
        self.nx = 0;
        self.len = 0;
    }
    fn Size(&self) -> int {
        // Go: if !d.is224 { return size }; return size224
        if !self.is224 { Size } else { Size224 }
    }
    fn BlockSize(&self) -> int {
        BlockSize
    }
}

// Go: checkSum (sha256.go:211) — finalize and return digest array.
fn check_sum(d: &mut Digest) -> [byte; 32] {
    // Go: len := d.len
    let mut len = d.len;
    // Go: var tmp [64+8]byte; tmp[0] = 0x80
    let mut tmp = [0u8; 64 + 8];
    tmp[0] = 0x80;
    // Go: if len%64 < 56 { t = 56 - len%64 } else { t = 64 + 56 - len%64 }
    let t: u64 = if len % 64 < 56 {
        56 - (len % 64)
    } else {
        64 + 56 - (len % 64)
    };
    // Go: len <<= 3 (length in bits)
    len <<= 3;
    // Go: padlen := tmp[:t+8]; BEPutUint64(padlen[t+0:], len); d.Write(padlen)
    let pad_end = (t + 8) as usize;
    let t_us = t as usize;
    tmp[t_us] = (len >> 56) as byte;
    tmp[t_us + 1] = (len >> 48) as byte;
    tmp[t_us + 2] = (len >> 40) as byte;
    tmp[t_us + 3] = (len >> 32) as byte;
    tmp[t_us + 4] = (len >> 24) as byte;
    tmp[t_us + 5] = (len >> 16) as byte;
    tmp[t_us + 6] = (len >> 8) as byte;
    tmp[t_us + 7] = len as byte;
    // Reuse Write via a slice<byte> of the padding buffer.
    let padv: Vec<byte> = tmp[..pad_end].to_vec();
    let _ = io::Writer::Write(d, slice::__from_vec(padv));

    if d.nx != 0 {
        // Go: panic("d.nx != 0") — should be impossible if padding is correct.
        panic!("d.nx != 0");
    }

    // Go: var digest [size]byte; BEPutUint32(digest[k:], d.h[k/4]) for k in 0..7
    let mut digest = [0u8; 32];
    for i in 0..7 {
        let h = d.h[i];
        digest[i * 4] = (h >> 24) as byte;
        digest[i * 4 + 1] = (h >> 16) as byte;
        digest[i * 4 + 2] = (h >> 8) as byte;
        digest[i * 4 + 3] = h as byte;
    }
    // Go: if !d.is224 { BEPutUint32(digest[28:], d.h[7]) }
    if !d.is224 {
        let h = d.h[7];
        digest[28] = (h >> 24) as byte;
        digest[29] = (h >> 16) as byte;
        digest[30] = (h >> 8) as byte;
        digest[31] = h as byte;
    }
    digest
}

// ─── One-shot helpers (Go: sha256.go:53, 65) ──────────────────────────

/// `sha256.Sum256(data)` (sha256.go:53) — SHA-256 of `data`.
pub fn Sum256(data: slice<byte>) -> [byte; 32] {
    // Go: h := New(); h.Write(data); var sum [Size]byte; h.Sum(sum[:0]); return sum
    let mut h = New();
    let _ = io::Writer::Write(&mut h, data);
    let empty: Vec<byte> = Vec::new();
    let out = h.Sum(slice::__from_vec(empty));
    let raw: &[byte] = &out;
    let mut sum = [0u8; 32];
    sum.copy_from_slice(&raw[..32]);
    sum
}

/// `sha256.Sum224(data)` (sha256.go:65) — SHA-224 of `data`.
pub fn Sum224(data: slice<byte>) -> [byte; 28] {
    let mut h = New224();
    let _ = io::Writer::Write(&mut h, data);
    let empty: Vec<byte> = Vec::new();
    let out = h.Sum(slice::__from_vec(empty));
    let raw: &[byte] = &out;
    let mut sum = [0u8; 28];
    sum.copy_from_slice(&raw[..28]);
    sum
}
