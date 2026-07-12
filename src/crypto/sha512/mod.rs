// crypto/sha512 — Go's `crypto/sha512`, ported.
//
// FIPS 180-4: SHA-384, SHA-512, SHA-512/224, SHA-512/256.
// Inlines blockGeneric from crypto/internal/fips140/sha512/sha512block.go.
//
// Slim deviations:
//   * No MarshalBinary / UnmarshalBinary / AppendBinary / Clone.
//   * No assembly fast path; only the generic block function.
//   * `New()` / `New384()` / `New512_224()` / `New512_256()` return
//     `Digest` directly, not `hash.Hash` interface.

#![allow(non_snake_case, non_upper_case_globals)]

use crate::errors::{error, nil};
use crate::goslice::slice;
use crate::hash::Hash;
use crate::io;
use crate::math::bits;
use crate::types::{byte, int};

extern crate alloc;
use alloc::vec::Vec;

// ─── Constants (Go: sha512.go:27-43; fips140 sha512.go:16-67) ─────────

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

const CHUNK: usize = 128;

// SHA-512 IV (FIPS 180-4 §5.3.5).
const init0: u64 = 0x6a09e667f3bcc908;
const init1: u64 = 0xbb67ae8584caa73b;
const init2: u64 = 0x3c6ef372fe94f82b;
const init3: u64 = 0xa54ff53a5f1d36f1;
const init4: u64 = 0x510e527fade682d1;
const init5: u64 = 0x9b05688c2b3e6c1f;
const init6: u64 = 0x1f83d9abfb41bd6b;
const init7: u64 = 0x5be0cd19137e2179;

// SHA-512/224 IV (FIPS 180-4 §5.3.6.1).
const init0_224: u64 = 0x8c3d37c819544da2;
const init1_224: u64 = 0x73e1996689dcd4d6;
const init2_224: u64 = 0x1dfab7ae32ff9c82;
const init3_224: u64 = 0x679dd514582f9fcf;
const init4_224: u64 = 0x0f6d2b697bd44da8;
const init5_224: u64 = 0x77e36f7304c48942;
const init6_224: u64 = 0x3f9d85a86a1d36c8;
const init7_224: u64 = 0x1112e6ad91d692a1;

// SHA-512/256 IV (FIPS 180-4 §5.3.6.2).
const init0_256: u64 = 0x22312194fc2bf72c;
const init1_256: u64 = 0x9f555fa3c84c64c2;
const init2_256: u64 = 0x2393b86b6f53b151;
const init3_256: u64 = 0x963877195940eabd;
const init4_256: u64 = 0x96283ee2a88effe3;
const init5_256: u64 = 0xbe5e1e2553863992;
const init6_256: u64 = 0x2b0199fc2c85b8aa;
const init7_256: u64 = 0x0eb72ddc81c52ca2;

// SHA-384 IV (FIPS 180-4 §5.3.4).
const init0_384: u64 = 0xcbbb9d5dc1059ed8;
const init1_384: u64 = 0x629a292a367cd507;
const init2_384: u64 = 0x9159015a3070dd17;
const init3_384: u64 = 0x152fecd8f70e5939;
const init4_384: u64 = 0x67332667ffc00b31;
const init5_384: u64 = 0x8eb44a8768581511;
const init6_384: u64 = 0xdb0c2e0d64f98fa7;
const init7_384: u64 = 0x47b5481dbefa4fa4;

// SHA-512 round constants (FIPS 180-4 §4.2.3).
const _K: [u64; 80] = [
    0x428a2f98d728ae22, 0x7137449123ef65cd, 0xb5c0fbcfec4d3b2f, 0xe9b5dba58189dbbc,
    0x3956c25bf348b538, 0x59f111f1b605d019, 0x923f82a4af194f9b, 0xab1c5ed5da6d8118,
    0xd807aa98a3030242, 0x12835b0145706fbe, 0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2,
    0x72be5d74f27b896f, 0x80deb1fe3b1696b1, 0x9bdc06a725c71235, 0xc19bf174cf692694,
    0xe49b69c19ef14ad2, 0xefbe4786384f25e3, 0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65,
    0x2de92c6f592b0275, 0x4a7484aa6ea6e483, 0x5cb0a9dcbd41fbd4, 0x76f988da831153b5,
    0x983e5152ee66dfab, 0xa831c66d2db43210, 0xb00327c898fb213f, 0xbf597fc7beef0ee4,
    0xc6e00bf33da88fc2, 0xd5a79147930aa725, 0x06ca6351e003826f, 0x142929670a0e6e70,
    0x27b70a8546d22ffc, 0x2e1b21385c26c926, 0x4d2c6dfc5ac42aed, 0x53380d139d95b3df,
    0x650a73548baf63de, 0x766a0abb3c77b2a8, 0x81c2c92e47edaee6, 0x92722c851482353b,
    0xa2bfe8a14cf10364, 0xa81a664bbc423001, 0xc24b8b70d0f89791, 0xc76c51a30654be30,
    0xd192e819d6ef5218, 0xd69906245565a910, 0xf40e35855771202a, 0x106aa07032bbd1b8,
    0x19a4c116b8d2d0c8, 0x1e376c085141ab53, 0x2748774cdf8eeb99, 0x34b0bcb5e19b48a8,
    0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb, 0x5b9cca4f7763e373, 0x682e6ff3d6b2b8a3,
    0x748f82ee5defb2fc, 0x78a5636f43172f60, 0x84c87814a1f0ab72, 0x8cc702081a6439ec,
    0x90befffa23631e28, 0xa4506cebde82bde9, 0xbef9a3f7b2c67915, 0xc67178f2e372532b,
    0xca273eceea26619c, 0xd186b8c721c0c207, 0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178,
    0x06f067aa72176fba, 0x0a637dc5a2c898a6, 0x113f9804bef90dae, 0x1b710b35131c471b,
    0x28db77f523047d84, 0x32caab7b40c72493, 0x3c9ebe0a15c9bebc, 0x431d67c49c100d4c,
    0x4cc5d4becb3e42b6, 0x597f299cfc657e2a, 0x5fcb6fab3ad6faec, 0x6c44198c4a475817,
];

// ─── Digest (Go: fips140 sha512.go:72) ────────────────────────────────

/// `sha512` digest — partial SHA-384 / SHA-512 / SHA-512/224 / SHA-512/256
/// evaluation. The `size` field selects the variant.
pub struct Digest {
    h: [u64; 8],
    x: [byte; CHUNK],
    nx: usize,
    len: u64,
    size: int,
}

fn make_digest(sz: int) -> Digest {
    let mut d = Digest {
        h: [0; 8],
        x: [0; CHUNK],
        nx: 0,
        len: 0,
        size: sz,
    };
    d.Reset();
    d
}

/// `sha512.New()` (sha512.go:49) — new SHA-512 digest.
pub fn New() -> Digest {
    make_digest(Size)
}

/// `sha512.New384()` (sha512.go:76) — new SHA-384 digest.
pub fn New384() -> Digest {
    make_digest(Size384)
}

/// `sha512.New512_224()` (sha512.go:60) — new SHA-512/224 digest.
pub fn New512_224() -> Digest {
    make_digest(Size224)
}

/// `sha512.New512_256()` (sha512.go:68) — new SHA-512/256 digest.
pub fn New512_256() -> Digest {
    make_digest(Size256)
}

// Go: blockGeneric (sha512block.go:96)
fn block(dig: &mut Digest, mut p: &[byte]) {
    let mut w = [0u64; 80];
    let mut h0 = dig.h[0];
    let mut h1 = dig.h[1];
    let mut h2 = dig.h[2];
    let mut h3 = dig.h[3];
    let mut h4 = dig.h[4];
    let mut h5 = dig.h[5];
    let mut h6 = dig.h[6];
    let mut h7 = dig.h[7];

    while p.len() >= CHUNK {
        // Go: for i := 0; i < 16; i++ { w[i] = BE u64 of p[i*8..] }
        let mut i = 0;
        while i < 16 {
            let j = i * 8;
            w[i] = ((p[j] as u64) << 56)
                | ((p[j + 1] as u64) << 48)
                | ((p[j + 2] as u64) << 40)
                | ((p[j + 3] as u64) << 32)
                | ((p[j + 4] as u64) << 24)
                | ((p[j + 5] as u64) << 16)
                | ((p[j + 6] as u64) << 8)
                | (p[j + 7] as u64);
            i += 1;
        }
        // Go: for i := 16; i < 80; i++
        let mut i = 16;
        while i < 80 {
            // Go: t1 := RotateLeft64(v1,-19) ^ RotateLeft64(v1,-61) ^ (v1>>6)
            let v1 = w[i - 2];
            let t1 = bits::RotateLeft64(v1, -19)
                ^ bits::RotateLeft64(v1, -61)
                ^ (v1 >> 6);
            // Go: t2 := RotateLeft64(v2,-1) ^ RotateLeft64(v2,-8) ^ (v2>>7)
            let v2 = w[i - 15];
            let t2 = bits::RotateLeft64(v2, -1)
                ^ bits::RotateLeft64(v2, -8)
                ^ (v2 >> 7);
            // Go: w[i] = t1 + w[i-7] + t2 + w[i-16]
            w[i] = t1
                .wrapping_add(w[i - 7])
                .wrapping_add(t2)
                .wrapping_add(w[i - 16]);
            i += 1;
        }

        let (mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h) =
            (h0, h1, h2, h3, h4, h5, h6, h7);

        let mut i = 0;
        while i < 80 {
            // Go: t1 := h + (RotateLeft64(e,-14) ^ RotateLeft64(e,-18) ^ RotateLeft64(e,-41))
            //          + ((e & f) ^ (^e & g)) + _K[i] + w[i]
            let s1 = bits::RotateLeft64(e, -14)
                ^ bits::RotateLeft64(e, -18)
                ^ bits::RotateLeft64(e, -41);
            let ch = (e & f) ^ ((!e) & g);
            let t1 = h
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(_K[i])
                .wrapping_add(w[i]);
            // Go: t2 := (RotateLeft64(a,-28) ^ RotateLeft64(a,-34) ^ RotateLeft64(a,-39))
            //          + ((a & b) ^ (a & c) ^ (b & c))
            let s0 = bits::RotateLeft64(a, -28)
                ^ bits::RotateLeft64(a, -34)
                ^ bits::RotateLeft64(a, -39);
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
        // Go: fips140 sha512.go:237
        let raw: &[byte] = &p;
        let nn = raw.len();
        self.len += nn as u64;
        let mut q: &[byte] = raw;
        if self.nx > 0 {
            let copy_n = core::cmp::min(CHUNK - self.nx, q.len());
            self.x[self.nx..self.nx + copy_n].copy_from_slice(&q[..copy_n]);
            self.nx += copy_n;
            if self.nx == CHUNK {
                let buf = self.x;
                block(self, &buf);
                self.nx = 0;
            }
            q = &q[copy_n..];
        }
        if q.len() >= CHUNK {
            let n = q.len() & !(CHUNK - 1);
            block(self, &q[..n]);
            q = &q[n..];
        }
        if !q.is_empty() {
            self.x[..q.len()].copy_from_slice(q);
            self.nx = q.len();
        }
        (nn as int, nil)
    }
}

impl Hash for Digest {
    fn Sum(&self, b: slice<byte>) -> slice<byte> {
        // Go: d0 := *d; hash := d0.checkSum(); return append(in, hash[:d.size]...)
        let mut d0 = Digest {
            h: self.h,
            x: self.x,
            nx: self.nx,
            len: self.len,
            size: self.size,
        };
        let digest = check_sum(&mut d0);
        let mut out: Vec<byte> = b.__into_vec();
        out.extend_from_slice(&digest[..self.size as usize]);
        slice::__from_vec(out)
    }

    fn Reset(&mut self) {
        // Go: fips140 sha512.go:80
        match self.size {
            v if v == Size384 => {
                self.h[0] = init0_384;
                self.h[1] = init1_384;
                self.h[2] = init2_384;
                self.h[3] = init3_384;
                self.h[4] = init4_384;
                self.h[5] = init5_384;
                self.h[6] = init6_384;
                self.h[7] = init7_384;
            }
            v if v == Size224 => {
                self.h[0] = init0_224;
                self.h[1] = init1_224;
                self.h[2] = init2_224;
                self.h[3] = init3_224;
                self.h[4] = init4_224;
                self.h[5] = init5_224;
                self.h[6] = init6_224;
                self.h[7] = init7_224;
            }
            v if v == Size256 => {
                self.h[0] = init0_256;
                self.h[1] = init1_256;
                self.h[2] = init2_256;
                self.h[3] = init3_256;
                self.h[4] = init4_256;
                self.h[5] = init5_256;
                self.h[6] = init6_256;
                self.h[7] = init7_256;
            }
            v if v == Size => {
                self.h[0] = init0;
                self.h[1] = init1;
                self.h[2] = init2;
                self.h[3] = init3;
                self.h[4] = init4;
                self.h[5] = init5;
                self.h[6] = init6;
                self.h[7] = init7;
            }
            _ => panic!("unknown size"),
        }
        self.nx = 0;
        self.len = 0;
    }

    fn Size(&self) -> int {
        self.size
    }

    fn BlockSize(&self) -> int {
        BlockSize
    }
}

// Go: checkSum (fips140 sha512.go:269) — returns 64-byte buffer; caller
// truncates to d.size when consumed via Sum.
fn check_sum(d: &mut Digest) -> [byte; 64] {
    // Go: tmp := [128+16]byte{0x80}
    let mut tmp = [0u8; 128 + 16];
    tmp[0] = 0x80;
    let mut len = d.len;
    // Go: t := if len%128 < 112 { 112 - len%128 } else { 128 + 112 - len%128 }
    let t: u64 = if len % 128 < 112 {
        112 - len % 128
    } else {
        128 + 112 - len % 128
    };
    // Go: byteorder.BEPutUint64(padlen[t+8:], len) — len in bits.
    len <<= 3;
    let pad_end = (t + 16) as usize;
    let off = (t + 8) as usize;
    tmp[off] = (len >> 56) as byte;
    tmp[off + 1] = (len >> 48) as byte;
    tmp[off + 2] = (len >> 40) as byte;
    tmp[off + 3] = (len >> 32) as byte;
    tmp[off + 4] = (len >> 24) as byte;
    tmp[off + 5] = (len >> 16) as byte;
    tmp[off + 6] = (len >> 8) as byte;
    tmp[off + 7] = len as byte;
    let padv: Vec<byte> = tmp[..pad_end].to_vec();
    let _ = io::Writer::Write(d, slice::__from_vec(padv));

    if d.nx != 0 {
        panic!("d.nx != 0");
    }

    // Go: BEPutUint64(digest[k*8:], d.h[k]) for k in 0..7 (skip last for SHA-384)
    let mut digest = [0u8; 64];
    for k in 0..6 {
        let h = d.h[k];
        digest[k * 8] = (h >> 56) as byte;
        digest[k * 8 + 1] = (h >> 48) as byte;
        digest[k * 8 + 2] = (h >> 40) as byte;
        digest[k * 8 + 3] = (h >> 32) as byte;
        digest[k * 8 + 4] = (h >> 24) as byte;
        digest[k * 8 + 5] = (h >> 16) as byte;
        digest[k * 8 + 6] = (h >> 8) as byte;
        digest[k * 8 + 7] = h as byte;
    }
    if d.size != Size384 {
        for k in 6..8 {
            let h = d.h[k];
            digest[k * 8] = (h >> 56) as byte;
            digest[k * 8 + 1] = (h >> 48) as byte;
            digest[k * 8 + 2] = (h >> 40) as byte;
            digest[k * 8 + 3] = (h >> 32) as byte;
            digest[k * 8 + 4] = (h >> 24) as byte;
            digest[k * 8 + 5] = (h >> 16) as byte;
            digest[k * 8 + 6] = (h >> 8) as byte;
            digest[k * 8 + 7] = h as byte;
        }
    }
    digest
}

// ─── One-shot helpers (Go: sha512.go:84-122) ──────────────────────────

/// `sha512.Sum512(data)` (sha512.go:84) — SHA-512 of `data`.
pub fn Sum512(data: slice<byte>) -> [byte; 64] {
    let mut h = New();
    let _ = io::Writer::Write(&mut h, data);
    check_sum(&mut h)
}

/// `sha512.Sum384(data)` (sha512.go:96) — SHA-384 of `data`.
pub fn Sum384(data: slice<byte>) -> [byte; 48] {
    let mut h = New384();
    let _ = io::Writer::Write(&mut h, data);
    let full = check_sum(&mut h);
    let mut sum = [0u8; 48];
    sum.copy_from_slice(&full[..48]);
    sum
}

/// `sha512.Sum512_224(data)` (sha512.go:108) — SHA-512/224 of `data`.
pub fn Sum512_224(data: slice<byte>) -> [byte; 28] {
    let mut h = New512_224();
    let _ = io::Writer::Write(&mut h, data);
    let full = check_sum(&mut h);
    let mut sum = [0u8; 28];
    sum.copy_from_slice(&full[..28]);
    sum
}

/// `sha512.Sum512_256(data)` (sha512.go:117) — SHA-512/256 of `data`.
pub fn Sum512_256(data: slice<byte>) -> [byte; 32] {
    let mut h = New512_256();
    let _ = io::Writer::Write(&mut h, data);
    let full = check_sum(&mut h);
    let mut sum = [0u8; 32];
    sum.copy_from_slice(&full[..32]);
    sum
}

// ─── Boxed constructors for trait-object consumers (e.g. hmac::New) ───

/// `sha512.NewHash()` — boxed constructor matching `hash.Hash` interface.
pub fn NewHash() -> alloc::boxed::Box<dyn Hash + Send + Sync> {
    alloc::boxed::Box::new(New())
}

/// `sha512.NewHash384()` — boxed SHA-384 constructor.
pub fn NewHash384() -> alloc::boxed::Box<dyn Hash + Send + Sync> {
    alloc::boxed::Box::new(New384())
}

/// `sha512.NewHash512_224()` — boxed SHA-512/224 constructor.
pub fn NewHash512_224() -> alloc::boxed::Box<dyn Hash + Send + Sync> {
    alloc::boxed::Box::new(New512_224())
}

/// `sha512.NewHash512_256()` — boxed SHA-512/256 constructor.
pub fn NewHash512_256() -> alloc::boxed::Box<dyn Hash + Send + Sync> {
    alloc::boxed::Box::new(New512_256())
}
