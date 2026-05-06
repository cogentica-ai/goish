// crypto/sha1 — Go's `crypto/sha1`, ported (RFC 3174).
//
// SHA-1 is cryptographically broken; provided for HTTP/HTTPS-adjacent
// use cases (e.g. WebSocket Sec-WebSocket-Accept handshake, legacy
// integrity checks) — not for security.
//
// Inlines blockGeneric from sha1block.go since goish has no separate
// fips140 internal layer.
//
// Slim deviations:
//   * No MarshalBinary / UnmarshalBinary / Clone (cosmetic).
//   * No assembly fast path (Go's amd64/arm64/etc. use SHA-1 NI/NEON).
//   * No ConstantTimeSum (only used internally by TLS — not needed
//     until TLS lands).
//   * No crypto.RegisterHash / boring / fips140only hooks.

#![allow(non_snake_case, non_upper_case_globals)]

use crate::errors::{error, nil};
use crate::goslice::slice;
use crate::hash::Hash;
use crate::io;
use crate::math::bits;
use crate::types::{byte, int};

extern crate alloc;
use alloc::vec::Vec;

// ─── Constants (Go: sha1.go:24-37) ────────────────────────────────────

/// `sha1.Size` — SHA-1 checksum length in bytes.
pub const Size: int = 20;

/// `sha1.BlockSize` — SHA-1 block size in bytes.
pub const BlockSize: int = 64;

const CHUNK: usize = 64;

const init0: u32 = 0x67452301;
const init1: u32 = 0xEFCDAB89;
const init2: u32 = 0x98BADCFE;
const init3: u32 = 0x10325476;
const init4: u32 = 0xC3D2E1F0;

// Round constants (sha1block.go:11-15).
const _K0: u32 = 0x5A827999;
const _K1: u32 = 0x6ED9EBA1;
const _K2: u32 = 0x8F1BBCDC;
const _K3: u32 = 0xCA62C1D6;

// ─── Digest (Go: sha1.go:40) ──────────────────────────────────────────

/// `sha1` digest — partial SHA-1 evaluation.
pub struct Digest {
    h: [u32; 5],
    x: [byte; CHUNK],
    nx: usize,
    len: u64,
}

/// `sha1.New()` (sha1.go:115) — new SHA-1 digest.
pub fn New() -> Digest {
    // Go: d := new(digest); d.Reset(); return d
    let mut d = Digest {
        h: [0; 5],
        x: [0; CHUNK],
        nx: 0,
        len: 0,
    };
    d.Reset();
    d
}

// Go: blockGeneric (sha1block.go:20)
fn block(dig: &mut Digest, mut p: &[byte]) {
    let mut w = [0u32; 16];
    let mut h0 = dig.h[0];
    let mut h1 = dig.h[1];
    let mut h2 = dig.h[2];
    let mut h3 = dig.h[3];
    let mut h4 = dig.h[4];
    while p.len() >= CHUNK {
        // Go: for i := 0; i < 16; i++ { w[i] = BE u32 of p[i*4..] }
        let mut i = 0;
        while i < 16 {
            let j = i * 4;
            w[i] = ((p[j] as u32) << 24)
                | ((p[j + 1] as u32) << 16)
                | ((p[j + 2] as u32) << 8)
                | (p[j + 3] as u32);
            i += 1;
        }

        let (mut a, mut b, mut c, mut d, mut e) = (h0, h1, h2, h3, h4);

        // Round 1: i = 0..16, no w[] expansion yet.
        let mut i = 0;
        while i < 16 {
            // Go: f := b&c | (^b)&d
            let f = (b & c) | ((!b) & d);
            // Go: t := RotateLeft32(a, 5) + f + e + w[i&0xf] + _K0
            let t = bits::RotateLeft32(a, 5)
                .wrapping_add(f)
                .wrapping_add(e)
                .wrapping_add(w[i & 0xf])
                .wrapping_add(_K0);
            // Go: a, b, c, d, e = t, a, RotateLeft32(b, 30), c, d
            e = d;
            d = c;
            c = bits::RotateLeft32(b, 30);
            b = a;
            a = t;
            i += 1;
        }
        // Round 1 cont: i = 16..20, with w expansion.
        while i < 20 {
            let tmp = w[(i - 3) & 0xf]
                ^ w[(i - 8) & 0xf]
                ^ w[(i - 14) & 0xf]
                ^ w[i & 0xf];
            w[i & 0xf] = bits::RotateLeft32(tmp, 1);
            let f = (b & c) | ((!b) & d);
            let t = bits::RotateLeft32(a, 5)
                .wrapping_add(f)
                .wrapping_add(e)
                .wrapping_add(w[i & 0xf])
                .wrapping_add(_K0);
            e = d;
            d = c;
            c = bits::RotateLeft32(b, 30);
            b = a;
            a = t;
            i += 1;
        }
        // Round 2: i = 20..40.
        while i < 40 {
            let tmp = w[(i - 3) & 0xf]
                ^ w[(i - 8) & 0xf]
                ^ w[(i - 14) & 0xf]
                ^ w[i & 0xf];
            w[i & 0xf] = bits::RotateLeft32(tmp, 1);
            let f = b ^ c ^ d;
            let t = bits::RotateLeft32(a, 5)
                .wrapping_add(f)
                .wrapping_add(e)
                .wrapping_add(w[i & 0xf])
                .wrapping_add(_K1);
            e = d;
            d = c;
            c = bits::RotateLeft32(b, 30);
            b = a;
            a = t;
            i += 1;
        }
        // Round 3: i = 40..60.
        while i < 60 {
            let tmp = w[(i - 3) & 0xf]
                ^ w[(i - 8) & 0xf]
                ^ w[(i - 14) & 0xf]
                ^ w[i & 0xf];
            w[i & 0xf] = bits::RotateLeft32(tmp, 1);
            // Go: f := ((b | c) & d) | (b & c)
            let f = ((b | c) & d) | (b & c);
            let t = bits::RotateLeft32(a, 5)
                .wrapping_add(f)
                .wrapping_add(e)
                .wrapping_add(w[i & 0xf])
                .wrapping_add(_K2);
            e = d;
            d = c;
            c = bits::RotateLeft32(b, 30);
            b = a;
            a = t;
            i += 1;
        }
        // Round 4: i = 60..80.
        while i < 80 {
            let tmp = w[(i - 3) & 0xf]
                ^ w[(i - 8) & 0xf]
                ^ w[(i - 14) & 0xf]
                ^ w[i & 0xf];
            w[i & 0xf] = bits::RotateLeft32(tmp, 1);
            let f = b ^ c ^ d;
            let t = bits::RotateLeft32(a, 5)
                .wrapping_add(f)
                .wrapping_add(e)
                .wrapping_add(w[i & 0xf])
                .wrapping_add(_K3);
            e = d;
            d = c;
            c = bits::RotateLeft32(b, 30);
            b = a;
            a = t;
            i += 1;
        }

        h0 = h0.wrapping_add(a);
        h1 = h1.wrapping_add(b);
        h2 = h2.wrapping_add(c);
        h3 = h3.wrapping_add(d);
        h4 = h4.wrapping_add(e);

        p = &p[CHUNK..];
    }

    dig.h[0] = h0;
    dig.h[1] = h1;
    dig.h[2] = h2;
    dig.h[3] = h3;
    dig.h[4] = h4;
}

// ─── Hash trait impls for Digest ──────────────────────────────────────

impl io::Writer for Digest {
    fn Write(&mut self, p: slice<byte>) -> (int, error) {
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
        // Go: d0 := *d; hash := d0.checkSum(); return append(in, hash[:]...)
        let mut d0 = Digest {
            h: self.h,
            x: self.x,
            nx: self.nx,
            len: self.len,
        };
        let digest = check_sum(&mut d0);
        let mut out: Vec<byte> = b.__into_vec();
        out.extend_from_slice(&digest);
        slice::__from_vec(out)
    }
    fn Reset(&mut self) {
        self.h[0] = init0;
        self.h[1] = init1;
        self.h[2] = init2;
        self.h[3] = init3;
        self.h[4] = init4;
        self.nx = 0;
        self.len = 0;
    }
    fn Size(&self) -> int {
        Size
    }
    fn BlockSize(&self) -> int {
        BlockSize
    }
}

// Go: checkSum (sha1.go:163)
fn check_sum(d: &mut Digest) -> [byte; 20] {
    let mut len = d.len;
    let mut tmp = [0u8; 64 + 8];
    tmp[0] = 0x80;
    let t: u64 = if len % 64 < 56 {
        56 - (len % 64)
    } else {
        64 + 56 - (len % 64)
    };
    len <<= 3;
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
    let padv: Vec<byte> = tmp[..pad_end].to_vec();
    let _ = io::Writer::Write(d, slice::__from_vec(padv));

    if d.nx != 0 {
        panic!("d.nx != 0");
    }

    let mut digest = [0u8; 20];
    for i in 0..5 {
        let h = d.h[i];
        digest[i * 4] = (h >> 24) as byte;
        digest[i * 4 + 1] = (h >> 16) as byte;
        digest[i * 4 + 2] = (h >> 8) as byte;
        digest[i * 4 + 3] = h as byte;
    }
    digest
}

// ─── One-shot helper (Go: sha1.go:273) ────────────────────────────────

/// `sha1.Sum(data)` (sha1.go:273) — SHA-1 of `data`.
pub fn Sum(data: slice<byte>) -> [byte; 20] {
    // Go: var d digest; d.Reset(); d.Write(data); return d.checkSum()
    let mut d = New();
    let _ = io::Writer::Write(&mut d, data);
    check_sum(&mut d)
}

// ─── Boxed constructor for trait-object consumers (e.g. hmac::New) ────

/// `sha1.NewHash()` — boxed constructor matching `hash.Hash` interface.
/// Use with `hmac::New(crypto::sha1::NewHash, key)`.
pub fn NewHash() -> alloc::boxed::Box<dyn Hash> {
    alloc::boxed::Box::new(New())
}
