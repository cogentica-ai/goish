// goishlint:ignore GOISH018 — MarshalBinary, AppendBinary,
// UnmarshalBinary, consumeUint32, consumeUint64 and Clone are not ported:
// goish's hash::Hash exposes no binary-marshaling or Cloner surface for
// them to implement. They unblock HMAC's FIPS 198-1 §6 state cache, so
// port them together with that.
// goishlint:ignore GOISH021 — same reason for the `marshalable` shape.
// go: file crypto/internal/fips140/sha256/sha256.go decls: Digest.Reset, New, New224, Digest.Size, Digest.BlockSize, Digest.Write, Digest.Sum, Digest.checkSum, NewHash, NewHash224
//
// crypto/internal/fips140/sha256 — SHA-224 and SHA-256. The public
// crypto/sha256 package is a thin wrapper over this.
//
// Deviations from sha256[go] @ Go 1.25.5:
//
//   * MarshalBinary / AppendBinary / UnmarshalBinary / consumeUint32 /
//     consumeUint64 / Clone are not ported: goish's hash::Hash has no
//     binary-marshaling or Cloner surface to hang them off. Tracked in
//     the GOISH018 ignore below.
//   * New/New224 return `Digest` by value rather than `*Digest`.

#![allow(non_snake_case, non_upper_case_globals)]

use crate::errors::{error, nil};
use crate::goslice::slice;
use crate::hash::Hash;
use crate::io;
use crate::types::{byte, int};

extern crate alloc;
use alloc::vec::Vec;

use super::sha256block_noasm::block;

// ─── Constants (Go: sha256[go]:21-28; fips140 sha256[go]:17-23) ─────────

/// `sha256.Size` — SHA-256 checksum length (bytes).
pub const Size: int = 32;

/// `sha256.Size224` — SHA-224 checksum length (bytes).
pub const Size224: int = 28;

/// `sha256.BlockSize` — block size of SHA-256/SHA-224 (bytes).
pub const BlockSize: int = 64;

pub(crate) const CHUNK: usize = 64;

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

pub struct Digest {
    pub(crate) h: [u32; 8],
    pub(crate) x: [byte; CHUNK],
    pub(crate) nx: usize,
    pub(crate) len: u64,
    pub(crate) is224: bool,
}

// go: sdk 1.25.5 crypto/internal/fips140/sha256/sha256.go:149-153 New
/// `sha256.New()` (sha256[go]:34) — new SHA-256 digest.
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

// go: sdk 1.25.5 crypto/internal/fips140/sha256/sha256.go:156-161 New224
/// `sha256.New224()` (sha256[go]:45) — new SHA-224 digest.
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

impl Digest {
    // go: sdk 1.25.5 crypto/internal/fips140/sha256/sha256.go:172-198 Write
    /// `(*Digest).Write(p)` — feed bytes into the running digest.
    /// Inherent forwarder to the `io::Writer` trait method.
    pub fn Write(&mut self, p: slice<byte>) -> (int, error) {
        <Self as io::Writer>::Write(self, p)
    }

    // go: sdk 1.25.5 crypto/internal/fips140/sha256/sha256.go:200-209 Sum
    /// `(*Digest).Sum(b)` — append the digest to `b` and return.
    /// Inherent forwarder to the `Hash::Sum` trait method. Accepts
    /// `impl Into<slice<byte>>` so callers can pass `nil` directly
    /// (Goish's `From<Nil> for slice<T>` resolves to an empty slice).
    pub fn Sum<B: Into<slice<byte>>>(&self, b: B) -> slice<byte> {
        <Self as Hash>::Sum(self, b.into())
    }
}

// ─── Hash trait impls for Digest ──────────────────────────────────────

impl io::Writer for Digest {
    // go: sdk 1.25.5 crypto/internal/fips140/sha256/sha256.go:172-198 Write
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
    // go: sdk 1.25.5 crypto/internal/fips140/sha256/sha256.go:200-209 Sum
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
    // go: sdk 1.25.5 crypto/internal/fips140/sha256/sha256.go:124-146 Reset
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
    // go: sdk 1.25.5 crypto/internal/fips140/sha256/sha256.go:163-168 Size
    fn Size(&self) -> int {
        // Go: if !d.is224 { return size }; return size224
        if !self.is224 { Size } else { Size224 }
    }
    // go: sdk 1.25.5 crypto/internal/fips140/sha256/sha256.go:170-170 BlockSize
    fn BlockSize(&self) -> int {
        BlockSize
    }
}

// go: sdk 1.25.5 crypto/internal/fips140/sha256/sha256.go:211-247 check_sum
// Go: checkSum (sha256[go]:211) — finalize and return digest array.
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

// ─── One-shot helpers (Go: sha256[go]:53, 65) ──────────────────────────

/// `sha256.Sum256(data)` (sha256[go]:53) — SHA-256 of `data`.

// go: none — goish idiom (trait impl / local helper)
/// Use with `hmac::New(crypto::sha256::NewHash, key)`.
pub fn NewHash() -> alloc::boxed::Box<dyn Hash + Send + Sync> {
    alloc::boxed::Box::new(New())
}

// go: none — goish idiom (trait impl / local helper)
/// `sha256.NewHash224()` — boxed SHA-224 constructor.
pub fn NewHash224() -> alloc::boxed::Box<dyn Hash + Send + Sync> {
    alloc::boxed::Box::new(New224())
}

