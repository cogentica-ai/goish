// goishlint:ignore GOISH018 — `init` (md5[go]) is
// `crypto.RegisterHash(crypto.MD5, New)`. goish has no crypto.Hash
// registry, so there is nothing to register into; port it with that
// registry.
// goishlint:ignore GOISH021 — Go's `digest` is unexported (New returns
// hash.Hash); goish exports it as `Digest` and returns it by value, the
// same deviation sha1/sha256/sha512 carry. `haveAsm` lives in
// md5block_generic[go]'s port, where Go declares it.
// go: file crypto/md5/md5.go decls: Digest.Reset, Digest.MarshalBinary, Digest.AppendBinary, Digest.UnmarshalBinary, consumeUint64, consumeUint32, Digest.Clone, New, Digest.Size, Digest.BlockSize, Digest.Write, Digest.Sum, Digest.checkSum, Sum, NewHash, register_md5_impls, __goish_as_dyn_any, __goish_as_dyn_any_mut
//
// Package md5 implements the MD5 hash algorithm as defined in RFC 1321.
//
// MD5 is cryptographically broken and should not be used for secure
// applications. goish keeps it for legacy integrity checks (Content-MD5,
// ETag derivations, file checksums).
//
// Deviations from md5[go] @ Go 1.25.5:
//
//   * `New` returns `Digest` by value rather than the `hash.Hash`
//     interface; `NewHash` is the boxed-interface form.
//   * No `init` — `crypto.RegisterHash(crypto.MD5, New)` needs a
//     crypto.Hash registry goish does not have.
//   * No `fips140only.Enabled` checks in Write/checkSum: goish has no
//     FIPS-140-only mode, so the branch is unreachable.

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

use super::md5block_generic::block;

// ─── Constants (md5[go]:26-41) ─────────────────────────────────────

/// `md5.Size` — the size of an MD5 checksum in bytes.
pub const Size: int = 16;

/// `md5.BlockSize` — the blocksize of MD5 in bytes.
pub const BlockSize: int = 64;

pub(crate) const CHUNK: usize = 64;

// The maximum number of bytes that can be passed to block(). The limit
// exists because implementations that rely on assembly routines are not
// preemptible.
//
// Go: `const maxAsmIters = 1024`
const maxAsmIters: usize = 1024;
/// Go: `const maxAsmSize = BlockSize * maxAsmIters // 64KiB`
const maxAsmSize: usize = (BlockSize as usize) * maxAsmIters;

const init0: u32 = 0x67452301;
const init1: u32 = 0xEFCDAB89;
const init2: u32 = 0x98BADCFE;
const init3: u32 = 0x10325476;

// ─── digest (md5[go]:43-48) ────────────────────────────────────────

/// Go: `type digest struct` — the partial evaluation of a checksum.
#[derive(Clone)]
pub struct Digest {
    pub(crate) s: [u32; 4],
    pub(crate) x: [byte; CHUNK],
    pub(crate) nx: usize,
    pub(crate) len: u64,
}

// ─── Marshaling (md5[go]:59-62) ────────────────────────────────────

/// Go: `magic = "md5\x01"`
const magic: &[byte] = b"md5\x01";

/// Go: `marshaledSize = len(magic) + 4*4 + BlockSize + 8`
const marshaledSize: usize = 4 + 4 * 4 + CHUNK + 8;

// go: sdk 1.25.5 crypto/md5/md5.go:116-120 New
/// `md5.New()` — a new MD5 digest. The Hash also implements
/// `encoding::BinaryMarshaler`, `encoding::BinaryAppender`,
/// `encoding::BinaryUnmarshaler` and `hash::Cloner`.
pub fn New() -> Digest {
    // Go: d := new(digest); d.Reset(); return d
    let mut d = Digest {
        s: [0; 4],
        x: [0; CHUNK],
        nx: 0,
        len: 0,
    };
    d.Reset();
    return d;
}

impl Digest {
    // go: sdk 1.25.5 crypto/md5/md5.go:64-66 digest.MarshalBinary
    /// `(*digest).MarshalBinary()` — the digest's internal state.
    pub fn MarshalBinary(&self) -> (slice<byte>, error) {
        // Go: return d.AppendBinary(make([]byte, 0, marshaledSize))
        let buf: Vec<byte> = Vec::with_capacity(marshaledSize);
        return self.AppendBinary(slice::__from_vec(buf));
    }

    // go: sdk 1.25.5 crypto/md5/md5.go:68-78 digest.AppendBinary
    /// `(*digest).AppendBinary(b)` — append the marshaled state to `b`.
    pub fn AppendBinary(&self, b: slice<byte>) -> (slice<byte>, error) {
        // Go: b = append(b, magic...)
        let mut out: Vec<byte> = b.__into_vec();
        out.extend_from_slice(magic);
        // Go: b = byteorder.BEAppendUint32(b, d.s[i]) for i in 0..3
        let mut acc = slice::__from_vec(out);
        let mut i: usize = 0;
        while i < 4 {
            acc = byteorder::BEAppendUint32(acc, self.s[i]);
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

    // go: sdk 1.25.5 crypto/md5/md5.go:81-97 digest.UnmarshalBinary
    /// `(*digest).UnmarshalBinary(b)` — restore state produced by
    /// [`Digest::MarshalBinary`].
    pub fn UnmarshalBinary(&mut self, b: slice<byte>) -> error {
        let raw: &[byte] = &b;
        // Go: if len(b) < len(magic) || string(b[:len(magic)]) != magic { … }
        if raw.len() < magic.len() || &raw[..magic.len()] != magic {
            return crate::errors::New("crypto/md5: invalid hash state identifier");
        }
        // Go: if len(b) != marshaledSize { … }
        if raw.len() != marshaledSize {
            return crate::errors::New("crypto/md5: invalid hash state size");
        }
        // Go: b = b[len(magic):]
        let mut rest: &[byte] = &raw[magic.len()..];
        // Go: b, d.s[i] = consumeUint32(b) for i in 0..3
        let mut i: usize = 0;
        while i < 4 {
            let (tail, v) = consumeUint32(rest);
            self.s[i] = v;
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
        // Go: d.nx = int(d.len % BlockSize)
        self.nx = usize::try_from(self.len % (CHUNK as uint64)).unwrap_or(0);
        return nil;
    }

    // go: sdk 1.25.5 crypto/md5/md5.go:107-110 digest.Clone
    /// `(*digest).Clone()` — an independent copy of this digest's state.
    pub fn Clone(&self) -> (Box<dyn Cloner + Send + Sync>, error) {
        // Go: r := *d; return &r, nil
        let r = Clone::clone(self);
        return (Box::new(r), nil);
    }

    // go: sdk 1.25.5 crypto/md5/md5.go:126-166 digest.Write
    /// `(*digest).Write(p)` — inherent forwarder to `io::Writer::Write`.
    pub fn Write(&mut self, p: slice<byte>) -> (int, error) {
        return <Self as io::Writer>::Write(self, p);
    }

    // go: sdk 1.25.5 crypto/md5/md5.go:168-173 digest.Sum
    /// `(*digest).Sum(b)` — inherent forwarder to `Hash::Sum`.
    pub fn Sum<B: Into<slice<byte>>>(&self, b: B) -> slice<byte> {
        return <Self as Hash>::Sum(self, b.into());
    }
}

// go: sdk 1.25.5 crypto/md5/md5.go:99-101 consumeUint64
/// Go: `func consumeUint64(b []byte) ([]byte, uint64)` — borrows rather
/// than wrapping, as an unexported cursor helper.
fn consumeUint64(b: &[byte]) -> (&[byte], uint64) {
    // Go: return b[8:], byteorder.BEUint64(b[0:8])
    return (
        &b[8..],
        byteorder::BEUint64(slice::__from_vec(b[..8].to_vec())),
    );
}

// go: sdk 1.25.5 crypto/md5/md5.go:103-105 consumeUint32
/// Go: `func consumeUint32(b []byte) ([]byte, uint32)` — see
/// [`consumeUint64`].
fn consumeUint32(b: &[byte]) -> (&[byte], uint32) {
    // Go: return b[4:], byteorder.BEUint32(b[0:4])
    return (
        &b[4..],
        byteorder::BEUint32(slice::__from_vec(b[..4].to_vec())),
    );
}

// ─── Hash trait impls for Digest ──────────────────────────────────────

impl io::Writer for Digest {
    // go: sdk 1.25.5 crypto/md5/md5.go:126-166 digest.Write
    fn Write(&mut self, p: slice<byte>) -> (int, error) {
        // Go: nn = len(p); d.len += uint64(nn)
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
        // Go: if len(p) >= BlockSize { n := len(p) &^ (BlockSize - 1); … }
        if q.len() >= CHUNK {
            let mut n = q.len() & !(CHUNK - 1);
            // Go: for n > maxAsmSize { block(d, p[:maxAsmSize]); … }
            //
            // Caps one block() call at 64 KiB, bounding how long an
            // assembly implementation runs unpreemptibly. Go guards this
            // on haveAsm; goish keeps the loop unconditionally so the
            // asm port is a drop-in.
            while n > maxAsmSize {
                block(self, &q[..maxAsmSize]);
                q = &q[maxAsmSize..];
                n -= maxAsmSize;
            }
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
    // go: none — goish idiom: see __goish_as_dyn_any.
    fn __goish_as_dyn_any_mut(&mut self) -> Option<&mut (dyn core::any::Any + Send + Sync)> {
        return Some(self);
    }
}

impl Hash for Digest {
    // go: sdk 1.25.5 crypto/md5/md5.go:168-173 digest.Sum
    fn Sum(&self, b: slice<byte>) -> slice<byte> {
        // Go: d0 := *d; hash := d0.checkSum(); return append(in, hash[:]...)
        let mut d0 = Digest {
            s: self.s,
            x: self.x,
            nx: self.nx,
            len: self.len,
        };
        let digest = checkSum(&mut d0);
        let mut out: Vec<byte> = b.__into_vec();
        out.extend_from_slice(&digest);
        slice::__from_vec(out)
    }
    // go: sdk 1.25.5 crypto/md5/md5.go:50-57 digest.Reset
    fn Reset(&mut self) {
        // Go: md5.go:51
        self.s[0] = init0;
        self.s[1] = init1;
        self.s[2] = init2;
        self.s[3] = init3;
        self.nx = 0;
        self.len = 0;
    }
    // go: sdk 1.25.5 crypto/md5/md5.go:122-122 digest.Size
    fn Size(&self) -> int {
        Size
    }
    // go: sdk 1.25.5 crypto/md5/md5.go:124-124 digest.BlockSize
    fn BlockSize(&self) -> int {
        BlockSize
    }
}

// go: sdk 1.25.5 crypto/md5/md5.go:175-202 digest.checkSum
/// Go: `func (d *digest) checkSum() [Size]byte`
fn checkSum(d: &mut Digest) -> [byte; 16] {
    // Go: tmp := [1+63+8]byte{0x80}
    let mut tmp = [0u8; 1 + 63 + 8];
    tmp[0] = 0x80;
    // Go: pad := (55 - d.len) % 64
    // (subtraction wraps in unsigned, then modulo masks to 0..63)
    let pad = (55u64.wrapping_sub(d.len)) % 64;
    let pad_us = pad as usize;
    // Go: byteorder.LEPutUint64(tmp[1+pad:], d.len<<3)
    let bit_len = d.len << 3;
    let off = 1 + pad_us;
    tmp[off] = bit_len as byte;
    tmp[off + 1] = (bit_len >> 8) as byte;
    tmp[off + 2] = (bit_len >> 16) as byte;
    tmp[off + 3] = (bit_len >> 24) as byte;
    tmp[off + 4] = (bit_len >> 32) as byte;
    tmp[off + 5] = (bit_len >> 40) as byte;
    tmp[off + 6] = (bit_len >> 48) as byte;
    tmp[off + 7] = (bit_len >> 56) as byte;
    // Go: d.Write(tmp[:1+pad+8])
    let total = 1 + pad_us + 8;
    let padv: Vec<byte> = tmp[..total].to_vec();
    let _ = io::Writer::Write(d, slice::__from_vec(padv));

    if d.nx != 0 {
        panic!("d.nx != 0");
    }

    // Go: byteorder.LEPutUint32(digest[i*4:], d.s[i])
    let mut digest = [0u8; 16];
    for i in 0..4 {
        let s = d.s[i];
        digest[i * 4] = s as byte;
        digest[i * 4 + 1] = (s >> 8) as byte;
        digest[i * 4 + 2] = (s >> 16) as byte;
        digest[i * 4 + 3] = (s >> 24) as byte;
    }
    digest
}

// ─── One-shot helper (md5[go]:205) ─────────────────────────────────

// go: sdk 1.25.5 crypto/md5/md5.go:205-212 Sum
/// `md5.Sum(data)` — MD5 of `data`.
pub fn Sum(data: slice<byte>) -> [byte; 16] {
    // Go: var d digest; d.Reset(); d.Write(data); return d.checkSum()
    let mut d = New();
    let _ = io::Writer::Write(&mut d, data);
    checkSum(&mut d)
}

// ─── Boxed constructor for trait-object consumers (e.g. hmac::New) ────

// go: none — goish idiom: boxed-trait constructor for call sites that
// need `Box<dyn Hash>` (Go returns the hash.Hash interface directly).
/// `md5.NewHash()` — boxed constructor matching `hash.Hash`.
/// Use with `hmac::New(crypto::md5::NewHash, key)`.
pub fn NewHash() -> alloc::boxed::Box<dyn Hash + Send + Sync> {
    alloc::boxed::Box::new(New())
}

// ─── hash.Cloner + encoding interface impls ───────────────────────────
//
// Go's *digest satisfies these structurally; goish's interfaces are
// nominal, so each impl forwards to the inherent method above.

impl encoding::BinaryMarshaler for Digest {
    // go: sdk 1.25.5 crypto/md5/md5.go:64-66 digest.MarshalBinary
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
    // go: sdk 1.25.5 crypto/md5/md5.go:68-78 digest.AppendBinary
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
    // go: sdk 1.25.5 crypto/md5/md5.go:81-97 digest.UnmarshalBinary
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
    // go: sdk 1.25.5 crypto/md5/md5.go:107-110 digest.Clone
    fn Clone(&self) -> (Box<dyn Cloner + Send + Sync>, error) {
        return Digest::Clone(self);
    }
}

// go: none — goish idiom: `#[goish::interface]` downcast registries are
// filled at runtime, one entry per `impl Trait for Concrete`; Go's itabs
// are built by the linker. Idempotent and cheap.
/// Register `Digest` into the `hash::Cloner` and `encoding::Binary*`
/// downcast registries so `carrier.As::<…>()` finds it.
pub fn register_md5_impls() {
    crate::hash::__goish_register_Hash_impl::<Digest>();
    crate::io::__goish_register_Writer_impl::<Digest>();
    crate::hash::__goish_register_Cloner_impl::<Digest>();
    encoding::__goish_register_BinaryMarshaler_impl::<Digest>();
    encoding::__goish_register_BinaryAppender_impl::<Digest>();
    encoding::__goish_register_BinaryUnmarshaler_impl::<Digest>();
}
