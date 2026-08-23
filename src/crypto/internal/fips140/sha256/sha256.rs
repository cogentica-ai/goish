// go: file crypto/internal/fips140/sha256/sha256.go decls: Digest.Reset, New, New224, Digest.Size, Digest.BlockSize, Digest.Write, Digest.Sum, Digest.checkSum, Digest.MarshalBinary, Digest.AppendBinary, Digest.UnmarshalBinary, Digest.Clone, consumeUint32, consumeUint64, NewHash, NewHash224, register_sha256_impls, __goish_as_dyn_any, __goish_as_dyn_any_mut
//
// crypto/internal/fips140/sha256 — SHA-224 and SHA-256. The public
// crypto/sha256 package is a thin wrapper over this.
//
// Deviations from sha256[go] @ Go 1.25.5:
//
//   * New/New224 return `Digest` by value rather than `*Digest`.
//   * `Clone` returns the boxed `hash::Cloner` trait object. Go returns
//     the `hash.Cloner` interface; goish's interface objects are boxed.

#![allow(non_snake_case, non_upper_case_globals)]

use crate::crypto::internal::fips140deps::byteorder;
use crate::encoding;
use crate::errors::{error, nil};
use crate::goslice::slice;
use crate::hash::{Cloner, Hash};
use crate::io;
use crate::types::{byte, int, uint32, uint64};

extern crate alloc;
use alloc::boxed::Box;
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

// The maximum number of bytes that can be passed to block(). The limit
// exists because implementations that rely on assembly routines are not
// preemptible.
//
// Go: `const maxAsmIters = 1024`
const maxAsmIters: usize = 1024;
/// Go: `const maxAsmSize = blockSize * maxAsmIters // 64KiB`
const maxAsmSize: usize = (BlockSize as usize) * maxAsmIters;

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

#[derive(Clone)]
pub struct Digest {
    pub(crate) h: [u32; 8],
    pub(crate) x: [byte; CHUNK],
    pub(crate) nx: usize,
    pub(crate) len: u64,
    pub(crate) is224: bool,
}

// ─── Marshaling (Go: sha256.go:58-62) ─────────────────────────────────

/// Go: `magic224 = "sha\x02"`
const magic224: &[byte] = b"sha\x02";

/// Go: `magic256 = "sha\x03"`
const magic256: &[byte] = b"sha\x03";

/// Go: `marshaledSize = len(magic256) + 8*4 + chunk + 8`
const marshaledSize: usize = 4 + 8 * 4 + CHUNK + 8;

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
    // go: sdk 1.25.5 crypto/internal/fips140/sha256/sha256.go:172-198 Digest.Write
    /// `(*Digest).Write(p)` — feed bytes into the running digest.
    /// Inherent forwarder to the `io::Writer` trait method.
    pub fn Write(&mut self, p: slice<byte>) -> (int, error) {
        <Self as io::Writer>::Write(self, p)
    }

    // go: sdk 1.25.5 crypto/internal/fips140/sha256/sha256.go:200-209 Digest.Sum
    /// `(*Digest).Sum(b)` — append the digest to `b` and return.
    /// Inherent forwarder to the `Hash::Sum` trait method. Accepts
    /// `impl Into<slice<byte>>` so callers can pass `nil` directly
    /// (Goish's `From<Nil> for slice<T>` resolves to an empty slice).
    pub fn Sum<B: Into<slice<byte>>>(&self, b: B) -> slice<byte> {
        <Self as Hash>::Sum(self, b.into())
    }

    // go: sdk 1.25.5 crypto/internal/fips140/sha256/sha256.go:64-66 Digest.MarshalBinary
    /// `(*Digest).MarshalBinary()` — the digest's internal state, so a
    /// running hash can be saved and resumed without re-feeding input.
    pub fn MarshalBinary(&self) -> (slice<byte>, error) {
        // Go: return d.AppendBinary(make([]byte, 0, marshaledSize))
        let buf: Vec<byte> = Vec::with_capacity(marshaledSize);
        return self.AppendBinary(slice::__from_vec(buf));
    }

    // go: sdk 1.25.5 crypto/internal/fips140/sha256/sha256.go:69-87 Digest.AppendBinary
    /// `(*Digest).AppendBinary(b)` — append the marshaled state to `b`.
    pub fn AppendBinary(&self, b: slice<byte>) -> (slice<byte>, error) {
        // Go: if d.is224 { b = append(b, magic224...) } else { b = append(b, magic256...) }
        let mut out: Vec<byte> = b.__into_vec();
        if self.is224 {
            out.extend_from_slice(magic224);
        } else {
            out.extend_from_slice(magic256);
        }
        // Go: b = byteorder.BEAppendUint32(b, d.h[i]) for i in 0..7
        let mut acc = slice::__from_vec(out);
        let mut i: usize = 0;
        while i < 8 {
            acc = byteorder::BEAppendUint32(acc, self.h[i]);
            i += 1;
        }
        // Go: b = append(b, d.x[:d.nx]...); b = append(b, make([]byte, len(d.x)-d.nx)...)
        let mut out: Vec<byte> = acc.__into_vec();
        out.extend_from_slice(&self.x[..self.nx]);
        out.resize(out.len() + (CHUNK - self.nx), 0);
        // Go: b = byteorder.BEAppendUint64(b, d.len); return b, nil
        return (
            byteorder::BEAppendUint64(slice::__from_vec(out), self.len),
            nil,
        );
    }

    // go: sdk 1.25.5 crypto/internal/fips140/sha256/sha256.go:89-109 Digest.UnmarshalBinary
    /// `(*Digest).UnmarshalBinary(b)` — restore state produced by
    /// [`Digest::MarshalBinary`].
    pub fn UnmarshalBinary(&mut self, b: slice<byte>) -> error {
        let raw: &[byte] = &b;
        // Go: if len(b) < len(magic224) || (d.is224 && string(b[:len(magic224)]) != magic224) ||
        //        (!d.is224 && string(b[:len(magic256)]) != magic256) { … }
        let want: &[byte] = if self.is224 { magic224 } else { magic256 };
        if raw.len() < magic224.len() || &raw[..want.len()] != want {
            return crate::errors::New("crypto/sha256: invalid hash state identifier");
        }
        // Go: if len(b) != marshaledSize { … }
        if raw.len() != marshaledSize {
            return crate::errors::New("crypto/sha256: invalid hash state size");
        }
        // Go: b = b[len(magic224):]
        let mut rest: &[byte] = &raw[magic224.len()..];
        // Go: b, d.h[i] = consumeUint32(b) for i in 0..7
        let mut i: usize = 0;
        while i < 8 {
            let (tail, v) = consumeUint32(rest);
            self.h[i] = v;
            rest = tail;
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

    // go: sdk 1.25.5 crypto/internal/fips140/sha256/sha256.go:118-121 Digest.Clone
    /// `(*Digest).Clone()` — an independent copy of this digest's state.
    /// Never fails, so the error is always nil (Go says the same).
    pub fn Clone(&self) -> (Box<dyn Cloner + Send + Sync>, error) {
        // Go: r := *d; return &r, nil
        let r = Clone::clone(self);
        return (Box::new(r), nil);
    }
}

// go: sdk 1.25.5 crypto/internal/fips140/sha256/sha256.go:111-113 consumeUint64
/// Go: `func consumeUint64(b []byte) ([]byte, uint64)`
///
/// Takes/returns a borrowed `&[byte]` rather than `slice<byte>`: it is
/// an unexported cursor helper, never part of the package's Go API
/// surface, and the borrow avoids a re-wrap per field.
fn consumeUint64(b: &[byte]) -> (&[byte], uint64) {
    // Go: return b[8:], byteorder.BEUint64(b)
    return (
        &b[8..],
        byteorder::BEUint64(slice::__from_vec(b[..8].to_vec())),
    );
}

// go: sdk 1.25.5 crypto/internal/fips140/sha256/sha256.go:115-117 consumeUint32
/// Go: `func consumeUint32(b []byte) ([]byte, uint32)` — see
/// [`consumeUint64`] for why this borrows.
fn consumeUint32(b: &[byte]) -> (&[byte], uint32) {
    // Go: return b[4:], byteorder.BEUint32(b)
    return (
        &b[4..],
        byteorder::BEUint32(slice::__from_vec(b[..4].to_vec())),
    );
}

// ─── encoding + hash.Cloner interface impls ───────────────────────────
//
// Go's Digest satisfies encoding.BinaryMarshaler, encoding.BinaryAppender,
// encoding.BinaryUnmarshaler and hash.Cloner structurally. goish's
// interfaces are nominal, so the impls are spelled out; each forwards to
// the inherent method above.

impl encoding::BinaryMarshaler for Digest {
    // go: sdk 1.25.5 crypto/internal/fips140/sha256/sha256.go:64-66 Digest.MarshalBinary
    fn MarshalBinary(&self) -> (slice<byte>, error) {
        return Digest::MarshalBinary(self);
    }
    // go: none — goish idiom: the hidden Any-view hook every
    // `#[goish::interface]` concrete impl overrides so `carrier.As::<…>()`
    // can reach this type. Go's itabs make it unnecessary.
    fn __goish_as_dyn_any(&self) -> Option<&(dyn core::any::Any + Send + Sync)> {
        return Some(self);
    }
    // go: none — goish idiom: the hidden Any-view hook every
    // `#[goish::interface]` concrete impl overrides so `carrier.As::<…>()`
    // can reach this type. Go's itabs make it unnecessary.
    fn __goish_as_dyn_any_mut(&mut self) -> Option<&mut (dyn core::any::Any + Send + Sync)> {
        return Some(self);
    }
}

impl encoding::BinaryAppender for Digest {
    // go: sdk 1.25.5 crypto/internal/fips140/sha256/sha256.go:69-87 Digest.AppendBinary
    fn AppendBinary(&self, b: slice<byte>) -> (slice<byte>, error) {
        return Digest::AppendBinary(self, b);
    }
    // go: none — goish idiom: the hidden Any-view hook every
    // `#[goish::interface]` concrete impl overrides so `carrier.As::<…>()`
    // can reach this type. Go's itabs make it unnecessary.
    fn __goish_as_dyn_any(&self) -> Option<&(dyn core::any::Any + Send + Sync)> {
        return Some(self);
    }
    // go: none — goish idiom: the hidden Any-view hook every
    // `#[goish::interface]` concrete impl overrides so `carrier.As::<…>()`
    // can reach this type. Go's itabs make it unnecessary.
    fn __goish_as_dyn_any_mut(&mut self) -> Option<&mut (dyn core::any::Any + Send + Sync)> {
        return Some(self);
    }
}

impl encoding::BinaryUnmarshaler for Digest {
    // go: sdk 1.25.5 crypto/internal/fips140/sha256/sha256.go:89-109 Digest.UnmarshalBinary
    fn UnmarshalBinary(&mut self, data: slice<byte>) -> error {
        return Digest::UnmarshalBinary(self, data);
    }
    // go: none — goish idiom: the hidden Any-view hook every
    // `#[goish::interface]` concrete impl overrides so `carrier.As::<…>()`
    // can reach this type. Go's itabs make it unnecessary.
    fn __goish_as_dyn_any(&self) -> Option<&(dyn core::any::Any + Send + Sync)> {
        return Some(self);
    }
    // go: none — goish idiom: the hidden Any-view hook every
    // `#[goish::interface]` concrete impl overrides so `carrier.As::<…>()`
    // can reach this type. Go's itabs make it unnecessary.
    fn __goish_as_dyn_any_mut(&mut self) -> Option<&mut (dyn core::any::Any + Send + Sync)> {
        return Some(self);
    }
}

impl Cloner for Digest {
    // go: sdk 1.25.5 crypto/internal/fips140/sha256/sha256.go:118-121 Digest.Clone
    fn Clone(&self) -> (Box<dyn Cloner + Send + Sync>, error) {
        return Digest::Clone(self);
    }
}

// go: none — goish idiom: `#[goish::interface]` downcast registries are
// filled at runtime, one entry per `impl Trait for Concrete`; Go's
// itabs are built by the linker. Idempotent and cheap.
/// Register `Digest` into the `hash::Cloner` and `encoding::Binary*`
/// downcast registries so `carrier.As::<…>()` finds it. Called at the
/// head of every goish API that asserts on a hash interface.
pub fn register_sha256_impls() {
    crate::hash::__goish_register_Hash_impl::<Digest>();
    crate::io::__goish_register_Writer_impl::<Digest>();
    crate::hash::__goish_register_Cloner_impl::<Digest>();
    encoding::__goish_register_BinaryMarshaler_impl::<Digest>();
    encoding::__goish_register_BinaryAppender_impl::<Digest>();
    encoding::__goish_register_BinaryUnmarshaler_impl::<Digest>();
}

// ─── Hash trait impls for Digest ──────────────────────────────────────

impl io::Writer for Digest {
    // go: sdk 1.25.5 crypto/internal/fips140/sha256/sha256.go:172-198 Digest.Write
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
        // Go: if len(p) >= chunk { n := len(p) &^ (chunk - 1); … }
        if q.len() >= CHUNK {
            let mut n = q.len() & !(CHUNK - 1);
            // Go: for n > maxAsmSize { block(d, p[:maxAsmSize]); … }
            //
            // Caps a single block() call at 64 KiB. Once the SHA-NI path
            // lands this bounds how long the goroutine is unpreemptible;
            // the generic path is preemptible either way, but the loop is
            // kept so the asm port is a drop-in.
            while n > maxAsmSize {
                block(self, &q[..maxAsmSize]);
                q = &q[maxAsmSize..];
                n -= maxAsmSize;
            }
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
    // go: none — goish idiom: the hidden Any-view hook every
    // `#[goish::interface]` concrete impl overrides so `carrier.As::<…>()`
    // can reach this type. Go's itabs make it unnecessary.
    // `hash::Hash` and `hash::Cloner` are composite interfaces: they
    // inherit this hook from `io::Writer`, so overriding it once here
    // makes `Digest` reachable through every interface in the chain.
    fn __goish_as_dyn_any(&self) -> Option<&(dyn core::any::Any + Send + Sync)> {
        return Some(self);
    }
    // go: none — goish idiom: the hidden Any-view hook every
    // `#[goish::interface]` concrete impl overrides so `carrier.As::<…>()`
    // can reach this type. Go's itabs make it unnecessary.
    fn __goish_as_dyn_any_mut(&mut self) -> Option<&mut (dyn core::any::Any + Send + Sync)> {
        return Some(self);
    }
}

impl Hash for Digest {
    // go: sdk 1.25.5 crypto/internal/fips140/sha256/sha256.go:200-209 Digest.Sum
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
        let digest = checkSum(&mut d0);
        // Go: if d0.is224 { return append(in, hash[:size224]...) }
        //     return append(in, hash[:]...)
        let mut out: Vec<byte> = b.__into_vec();
        let limit = if self.is224 {
            Size224 as usize
        } else {
            Size as usize
        };
        out.extend_from_slice(&digest[..limit]);
        slice::__from_vec(out)
    }
    // go: sdk 1.25.5 crypto/internal/fips140/sha256/sha256.go:124-146 Digest.Reset
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
    // go: sdk 1.25.5 crypto/internal/fips140/sha256/sha256.go:163-168 Digest.Size
    fn Size(&self) -> int {
        // Go: if !d.is224 { return size }; return size224
        if !self.is224 {
            Size
        } else {
            Size224
        }
    }
    // go: sdk 1.25.5 crypto/internal/fips140/sha256/sha256.go:170-170 Digest.BlockSize
    fn BlockSize(&self) -> int {
        BlockSize
    }
}

// go: sdk 1.25.5 crypto/internal/fips140/sha256/sha256.go:211-247 Digest.checkSum
// Go: checkSum (sha256[go]:211) — finalize and return digest array.
fn checkSum(d: &mut Digest) -> [byte; 32] {
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
