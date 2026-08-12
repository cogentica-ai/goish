// goishlint:ignore GOISH018 — `init` (sha1[go]) is
// `crypto.RegisterHash(crypto.SHA1, New)`. goish has no crypto.Hash
// registry, so there is nothing to register into; port it with that
// registry.
// goishlint:ignore GOISH021 — Go's `digest` is unexported (New returns
// hash.Hash); goish exports it as `Digest` and returns it by value, the
// same deviation md5/sha256/sha512 carry.
// go: file crypto/sha1/sha1.go decls: Digest.MarshalBinary, Digest.AppendBinary, Digest.UnmarshalBinary, consumeUint64, consumeUint32, Digest.Clone, Digest.Reset, New, Digest.Size, Digest.BlockSize, Digest.Write, Digest.Sum, Digest.checkSum, Digest.ConstantTimeSum, Digest.constSum, Sum, NewHash, register_sha1_impls, __goish_as_dyn_any, __goish_as_dyn_any_mut
//
// Package sha1 implements the SHA-1 hash algorithm as defined in RFC 3174.
//
// SHA-1 is cryptographically broken and should not be used for secure
// applications.
//
// Deviations from sha1[go] @ Go 1.25.5:
//
//   * `New` returns `Digest` by value rather than the `hash.Hash`
//     interface; `NewHash` is the boxed-interface form.
//   * No `fips140only.Enabled` checks: goish has no FIPS-140-only mode.

#![allow(non_snake_case, non_upper_case_globals)]

use crate::encoding;
use crate::errors::{error, nil};
use crate::goslice::slice;
use crate::hash::{Cloner, Hash};
use crate::internal::byteorder;
use crate::io;
use crate::types::{byte, int, uint32, uint64};

extern crate alloc;
use alloc::boxed::Box;
use alloc::vec::Vec;

use super::sha1block_generic::block;


// ─── Constants (sha1[go]:24-37) ────────────────────────────────────

/// `sha1.Size` — SHA-1 checksum length in bytes.
pub const Size: int = 20;

/// `sha1.BlockSize` — SHA-1 block size in bytes.
pub const BlockSize: int = 64;

pub(crate) const CHUNK: usize = 64;

const init0: u32 = 0x67452301;
const init1: u32 = 0xEFCDAB89;
const init2: u32 = 0x98BADCFE;
const init3: u32 = 0x10325476;
const init4: u32 = 0xC3D2E1F0;


// ─── digest (sha1[go]:40) ──────────────────────────────────────────

/// `sha1` digest — partial SHA-1 evaluation.
#[derive(Clone)]
pub struct Digest {
    pub(crate) h: [u32; 5],
    pub(crate) x: [byte; CHUNK],
    pub(crate) nx: usize,
    pub(crate) len: u64,
}

// go: sdk 1.25.5 crypto/sha1/sha1.go:115-122 New
/// `sha1.New()` — a new SHA-1 digest. The Hash also implements
/// `encoding::BinaryMarshaler`, `encoding::BinaryAppender`,
/// `encoding::BinaryUnmarshaler` and `hash::Cloner`.
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


// ─── Marshaling (sha1[go]:46-49) ──────────────────────────────────────

/// Go: `magic = "sha\x01"`
const magic: &[byte] = b"sha\x01";

/// Go: `marshaledSize = len(magic) + 5*4 + chunk + 8`
const marshaledSize: usize = 4 + 5 * 4 + CHUNK + 8;

impl Digest {
    // go: sdk 1.25.5 crypto/sha1/sha1.go:52-54 MarshalBinary
    /// `(*digest).MarshalBinary()` — the digest's internal state.
    pub fn MarshalBinary(&self) -> (slice<byte>, error) {
        // Go: return d.AppendBinary(make([]byte, 0, marshaledSize))
        let buf: Vec<byte> = Vec::with_capacity(marshaledSize);
        return self.AppendBinary(slice::__from_vec(buf));
    }

    // go: sdk 1.25.5 crypto/sha1/sha1.go:56-67 AppendBinary
    /// `(*digest).AppendBinary(b)` — append the marshaled state to `b`.
    pub fn AppendBinary(&self, b: slice<byte>) -> (slice<byte>, error) {
        // Go: b = append(b, magic...)
        let mut out: Vec<byte> = b.__into_vec();
        out.extend_from_slice(magic);
        // Go: b = byteorder.BEAppendUint32(b, d.h[i]) for i in 0..4
        let mut acc = slice::__from_vec(out);
        let mut i: usize = 0;
        while i < 5 {
            acc = byteorder::BEAppendUint32(acc, self.h[i]);
            i += 1;
        }
        // Go: b = append(b, d.x[:d.nx]...); b = append(b, make([]byte, len(d.x)-d.nx)...)
        let mut out: Vec<byte> = acc.__into_vec();
        out.extend_from_slice(&self.x[..self.nx]);
        out.resize(out.len() + (CHUNK - self.nx), 0);
        // Go: b = byteorder.BEAppendUint64(b, d.len); return b, nil
        return (byteorder::BEAppendUint64(slice::__from_vec(out), self.len), nil);
    }

    // go: sdk 1.25.5 crypto/sha1/sha1.go:69-86 UnmarshalBinary
    /// `(*digest).UnmarshalBinary(b)` — restore state produced by
    /// [`Digest::MarshalBinary`].
    pub fn UnmarshalBinary(&mut self, b: slice<byte>) -> error {
        let raw: &[byte] = &b;
        // Go: if len(b) < len(magic) || string(b[:len(magic)]) != magic { … }
        if raw.len() < magic.len() || &raw[..magic.len()] != magic {
            return crate::errors::New("crypto/sha1: invalid hash state identifier");
        }
        // Go: if len(b) != marshaledSize { … }
        if raw.len() != marshaledSize {
            return crate::errors::New("crypto/sha1: invalid hash state size");
        }
        // Go: b = b[len(magic):]
        let mut rest: &[byte] = &raw[magic.len()..];
        // Go: b, d.h[i] = consumeUint32(b) for i in 0..4
        let mut i: usize = 0;
        while i < 5 {
            let (t, v) = consumeUint32(rest);
            self.h[i] = v;
            rest = t;
            i += 1;
        }
        // Go: b = b[copy(d.x[:], b):]
        let n = core::cmp::min(CHUNK, rest.len());
        self.x[..n].copy_from_slice(&rest[..n]);
        rest = &rest[n..];
        // Go: b, d.len = consumeUint64(b)
        let (_, len) = consumeUint64(rest);
        self.len = len;
        // Go: d.nx = int(d.len % chunk)
        self.nx = usize::try_from(self.len % (CHUNK as uint64)).unwrap_or(0);
        return nil;
    }

    // go: sdk 1.25.5 crypto/sha1/sha1.go:96-99 Clone
    /// `(*digest).Clone()` — an independent copy of this digest's state.
    pub fn Clone(&self) -> (Box<dyn Cloner + Send + Sync>, error) {
        // Go: r := *d; return &r, nil
        let r = Clone::clone(self);
        return (Box::new(r), nil);
    }

    // go: sdk 1.25.5 crypto/sha1/sha1.go:128-153 Write
    /// `(*digest).Write(p)` — inherent forwarder to `io::Writer::Write`.
    pub fn Write(&mut self, p: slice<byte>) -> (int, error) {
        return <Self as io::Writer>::Write(self, p);
    }

    // go: sdk 1.25.5 crypto/sha1/sha1.go:155-161 Sum
    /// `(*digest).Sum(b)` — inherent forwarder to `Hash::Sum`.
    pub fn Sum<B: Into<slice<byte>>>(&self, b: B) -> slice<byte> {
        return <Self as Hash>::Sum(self, b.into());
    }

    // go: sdk 1.25.5 crypto/sha1/sha1.go:201-205 ConstantTimeSum
    /// `(*digest).ConstantTimeSum(b)` — like `Sum`, but the padding and
    /// finalization run in time independent of the amount buffered.
    /// Used by crypto/tls's CBC MAC path, where the branch on how much
    /// data remains would otherwise be a Lucky-13-style oracle.
    pub fn ConstantTimeSum(&self, b: slice<byte>) -> slice<byte> {
        // Go: d0 := *d; hash := d0.constSum(); return append(in, hash[:]...)
        let mut d0 = Clone::clone(self);
        let hash = constSum(&mut d0);
        let mut out: Vec<byte> = b.__into_vec();
        out.extend_from_slice(&hash);
        return slice::__from_vec(out);
    }
}

// go: sdk 1.25.5 crypto/sha1/sha1.go:88-90 consumeUint64
/// Go: `func consumeUint64(b []byte) ([]byte, uint64)` — borrows rather
/// than wrapping, as an unexported cursor helper.
fn consumeUint64(b: &[byte]) -> (&[byte], uint64) {
    // Go: return b[8:], byteorder.BEUint64(b[0:8])
    return (&b[8..], byteorder::BEUint64(slice::__from_vec(b[..8].to_vec())));
}

// go: sdk 1.25.5 crypto/sha1/sha1.go:92-94 consumeUint32
/// Go: `func consumeUint32(b []byte) ([]byte, uint32)` — see
/// [`consumeUint64`].
fn consumeUint32(b: &[byte]) -> (&[byte], uint32) {
    // Go: return b[4:], byteorder.BEUint32(b[0:4])
    return (&b[4..], byteorder::BEUint32(slice::__from_vec(b[..4].to_vec())));
}

// ─── Hash trait impls for Digest ──────────────────────────────────────

impl io::Writer for Digest {
    // go: sdk 1.25.5 crypto/sha1/sha1.go:128-153 Write
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
        return (nn as int, nil);
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

impl Hash for Digest {
    // go: sdk 1.25.5 crypto/sha1/sha1.go:155-161 Sum
    fn Sum(&self, b: slice<byte>) -> slice<byte> {
        // Go: d0 := *d; hash := d0.checkSum(); return append(in, hash[:]...)
        let mut d0 = Digest {
            h: self.h,
            x: self.x,
            nx: self.nx,
            len: self.len,
        };
        let digest = checkSum(&mut d0);
        let mut out: Vec<byte> = b.__into_vec();
        out.extend_from_slice(&digest);
        slice::__from_vec(out)
    }
    // go: sdk 1.25.5 crypto/sha1/sha1.go:101-109 Reset
    fn Reset(&mut self) {
        self.h[0] = init0;
        self.h[1] = init1;
        self.h[2] = init2;
        self.h[3] = init3;
        self.h[4] = init4;
        self.nx = 0;
        self.len = 0;
    }
    // go: sdk 1.25.5 crypto/sha1/sha1.go:124-124 Size
    fn Size(&self) -> int {
        Size
    }
    // go: sdk 1.25.5 crypto/sha1/sha1.go:126-126 BlockSize
    fn BlockSize(&self) -> int {
        BlockSize
    }
}

// go: sdk 1.25.5 crypto/sha1/sha1.go:163-198 checkSum
/// Go: `func (d *digest) checkSum() [Size]byte`
fn checkSum(d: &mut Digest) -> [byte; 20] {
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

// ─── One-shot helper (sha1[go]:273) ────────────────────────────────

// go: sdk 1.25.5 crypto/sha1/sha1.go:273-284 Sum
/// `sha1.Sum(data)` — SHA-1 checksum of `data`.
pub fn Sum(data: slice<byte>) -> [byte; 20] {
    // Go: var d digest; d.Reset(); d.Write(data); return d.checkSum()
    let mut d = New();
    let _ = io::Writer::Write(&mut d, data);
    checkSum(&mut d)
}

// ─── Boxed constructor for trait-object consumers (e.g. hmac::New) ────

// go: none — goish idiom: boxed-trait constructor for call sites that
// need `Box<dyn Hash>` (Go returns the hash.Hash interface directly).
/// `sha1.NewHash()` — boxed constructor matching `hash.Hash`.
pub fn NewHash() -> alloc::boxed::Box<dyn Hash + Send + Sync> {
    alloc::boxed::Box::new(New())
}

// go: sdk 1.25.5 crypto/sha1/sha1.go:207-270 constSum
/// Go: `func (d *digest) constSum() [Size]byte`
///
/// Constant-time finalization: instead of branching on how much data is
/// buffered, it builds both possible final blocks and selects with a mask
/// derived from `d.nx`. Both compressions always run.
fn constSum(d: &mut Digest) -> [byte; 20] {
    // Go: var length [8]byte; l := d.len << 3
    let mut length = [0u8; 8];
    let l = d.len << 3;
    // Go: for i := uint(0); i < 8; i++ { length[i] = byte(l >> (56 - 8*i)) }
    let mut i: usize = 0;
    while i < 8 {
        length[i] = ((l >> (56 - 8 * i)) & 0xff) as byte;
        i += 1;
    }

    // Go: nx := byte(d.nx); t := nx - 56
    let nx = (d.nx & 0xff) as byte;
    let t = nx.wrapping_sub(56);
    // Go: mask1b := byte(int8(t) >> 7) — 0xFF iff one block is enough
    let mask1b = ((t as i8) >> 7) as byte;

    // Go: separator := byte(0x80) — gets reset to 0x00 once used
    let mut separator: byte = 0x80;
    let mut i: byte = 0;
    while (i as usize) < CHUNK {
        // Go: mask := byte(int8(i-nx) >> 7) — 0x00 after the end of data
        let mask = ((i.wrapping_sub(nx) as i8) >> 7) as byte;

        // Go: if we reached the end of the data, replace with 0x80 or 0x00
        d.x[i as usize] = ((!mask) & separator) | (mask & d.x[i as usize]);

        // Go: zero the separator once used
        separator &= mask;

        if i >= 56 {
            // Go: we might have to write the length here if all fit in one block
            d.x[i as usize] |= mask1b & length[(i - 56) as usize];
        }
        i += 1;
    }

    // Go: compress, and only keep the digest if all fit in one block
    let buf = d.x;
    block(d, &buf);

    // Go: var digest [Size]byte; for i, s := range d.h { … }
    let mut digest = [0u8; 20];
    let mut k: usize = 0;
    while k < 5 {
        let s = d.h[k];
        digest[k * 4] = mask1b & ((s >> 24) & 0xff) as byte;
        digest[k * 4 + 1] = mask1b & ((s >> 16) & 0xff) as byte;
        digest[k * 4 + 2] = mask1b & ((s >> 8) & 0xff) as byte;
        digest[k * 4 + 3] = mask1b & (s & 0xff) as byte;
        k += 1;
    }

    // Go: second block, always past the end of data, might start with 0x80
    let mut i: byte = 0;
    while (i as usize) < CHUNK {
        if i < 56 {
            d.x[i as usize] = separator;
            separator = 0;
        } else {
            d.x[i as usize] = length[(i - 56) as usize];
        }
        i += 1;
    }

    // Go: compress, and only keep the digest if we actually needed the
    // second block
    let buf = d.x;
    block(d, &buf);

    let mut k: usize = 0;
    while k < 5 {
        let s = d.h[k];
        digest[k * 4] |= (!mask1b) & ((s >> 24) & 0xff) as byte;
        digest[k * 4 + 1] |= (!mask1b) & ((s >> 16) & 0xff) as byte;
        digest[k * 4 + 2] |= (!mask1b) & ((s >> 8) & 0xff) as byte;
        digest[k * 4 + 3] |= (!mask1b) & (s & 0xff) as byte;
        k += 1;
    }

    // Go: return digest
    return digest;
}

// ─── hash.Cloner + encoding interface impls ───────────────────────────
//
// Go's *digest satisfies these structurally; goish's interfaces are
// nominal, so each impl forwards to the inherent method above.

impl encoding::BinaryMarshaler for Digest {
    // go: sdk 1.25.5 crypto/sha1/sha1.go:52-54 MarshalBinary
    fn MarshalBinary(&self) -> (slice<byte>, error) {
        return Digest::MarshalBinary(self);
    }
    // go: none — goish idiom: see __goish_as_dyn_any in the io::Writer impl.
    fn __goish_as_dyn_any(&self) -> Option<&(dyn core::any::Any + Send + Sync)> {
        return Some(self);
    }
    // go: none — goish idiom: see __goish_as_dyn_any in the io::Writer impl.
    fn __goish_as_dyn_any_mut(&mut self) -> Option<&mut (dyn core::any::Any + Send + Sync)> {
        return Some(self);
    }
}

impl encoding::BinaryAppender for Digest {
    // go: sdk 1.25.5 crypto/sha1/sha1.go:56-67 AppendBinary
    fn AppendBinary(&self, b: slice<byte>) -> (slice<byte>, error) {
        return Digest::AppendBinary(self, b);
    }
    // go: none — goish idiom: see __goish_as_dyn_any in the io::Writer impl.
    fn __goish_as_dyn_any(&self) -> Option<&(dyn core::any::Any + Send + Sync)> {
        return Some(self);
    }
    // go: none — goish idiom: see __goish_as_dyn_any in the io::Writer impl.
    fn __goish_as_dyn_any_mut(&mut self) -> Option<&mut (dyn core::any::Any + Send + Sync)> {
        return Some(self);
    }
}

impl encoding::BinaryUnmarshaler for Digest {
    // go: sdk 1.25.5 crypto/sha1/sha1.go:69-86 UnmarshalBinary
    fn UnmarshalBinary(&mut self, data: slice<byte>) -> error {
        return Digest::UnmarshalBinary(self, data);
    }
    // go: none — goish idiom: see __goish_as_dyn_any in the io::Writer impl.
    fn __goish_as_dyn_any(&self) -> Option<&(dyn core::any::Any + Send + Sync)> {
        return Some(self);
    }
    // go: none — goish idiom: see __goish_as_dyn_any in the io::Writer impl.
    fn __goish_as_dyn_any_mut(&mut self) -> Option<&mut (dyn core::any::Any + Send + Sync)> {
        return Some(self);
    }
}

impl Cloner for Digest {
    // go: sdk 1.25.5 crypto/sha1/sha1.go:96-99 Clone
    fn Clone(&self) -> (Box<dyn Cloner + Send + Sync>, error) {
        return Digest::Clone(self);
    }
}

// go: none — goish idiom: `#[goish::interface]` downcast registries are
// filled at runtime, one entry per `impl Trait for Concrete`; Go's itabs
// are built by the linker. Idempotent and cheap.
/// Register `Digest` into the `hash::Cloner` and `encoding::Binary*`
/// downcast registries so `carrier.As::<…>()` finds it.
pub fn register_sha1_impls() {
    crate::hash::__goish_register_Hash_impl::<Digest>();
    crate::io::__goish_register_Writer_impl::<Digest>();
    crate::hash::__goish_register_Cloner_impl::<Digest>();
    encoding::__goish_register_BinaryMarshaler_impl::<Digest>();
    encoding::__goish_register_BinaryAppender_impl::<Digest>();
    encoding::__goish_register_BinaryUnmarshaler_impl::<Digest>();
}
