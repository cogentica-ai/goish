// go: file crypto/internal/fips140/sha512/sha512.go decls: Digest.Reset, Digest.MarshalBinary, Digest.AppendBinary, Digest.UnmarshalBinary, consumeUint64, Digest.Clone, New, New512_224, New512_256, New384, Digest.Size, Digest.BlockSize, Digest.Write, Digest.Sum, Digest.checkSum, NewHash, NewHash384, NewHash512_224, NewHash512_256, register_sha512_impls, __goish_as_dyn_any, __goish_as_dyn_any_mut
//
// crypto/internal/fips140/sha512 — SHA-384, SHA-512, SHA-512/224 and
// SHA-512/256 as defined in FIPS 180-4. The public crypto/sha512 package
// is a thin wrapper over this.
//
// Deviations from sha512[go] @ Go 1.25.5:
//
//   * New/New512_224/New512_256/New384 return `Digest` by value rather
//     than `*Digest`.
//   * `Clone` returns the boxed `hash::Cloner` trait object. Go returns
//     the `hash.Cloner` interface; goish's interface objects are boxed.
//   * cast[go]'s `init` — `fips140.CAST("SHA2-512", …)`, the pre-use
//     self-test — is not ported: goish's fips140 stub has no CAST
//     registry. Port it with that registry. The vector it checks is
//     covered by examples/sha512_smoke.rs.

#![allow(non_snake_case, non_upper_case_globals)]

use crate::crypto::internal::fips140deps::byteorder;
use crate::encoding;
use crate::errors::{error, nil};
use crate::goslice::slice;
use crate::hash::{Cloner, Hash};
use crate::io;
use crate::types::{byte, int, uint64};

extern crate alloc;
use alloc::boxed::Box;
use alloc::vec::Vec;

use super::sha512block_noasm::block;

// ─── Constants (Go: sha512.go:16-67) ──────────────────────────────────

/// `size512` — SHA-512 checksum length (bytes).
pub const Size512: int = 64;

/// `size224` — SHA-512/224 checksum length (bytes).
pub const Size224: int = 28;

/// `size256` — SHA-512/256 checksum length (bytes).
pub const Size256: int = 32;

/// `size384` — SHA-384 checksum length (bytes).
pub const Size384: int = 48;

/// `blockSize` — block size of the SHA-512 family (bytes).
pub const BlockSize: int = 128;

pub(crate) const CHUNK: usize = 128;

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

// ─── Digest (Go: sha512.go:72-78) ─────────────────────────────────────

/// `sha512.Digest` — a SHA-384, SHA-512, SHA-512/224 or SHA-512/256
/// `hash.Hash` implementation. The `size` field selects the variant.
#[derive(Clone)]
pub struct Digest {
    pub(crate) h: [u64; 8],
    pub(crate) x: [byte; CHUNK],
    pub(crate) nx: usize,
    pub(crate) len: u64,
    pub(crate) size: int,
}

// ─── Marshaling (Go: sha512.go:125-131) ───────────────────────────────

/// Go: `magic384 = "sha\x04"`
const magic384: &[byte] = b"sha\x04";

/// Go: `magic512_224 = "sha\x05"`
const magic512_224: &[byte] = b"sha\x05";

/// Go: `magic512_256 = "sha\x06"`
const magic512_256: &[byte] = b"sha\x06";

/// Go: `magic512 = "sha\x07"`
const magic512: &[byte] = b"sha\x07";

/// Go: `marshaledSize = len(magic512) + 8*8 + chunk + 8`
const marshaledSize: usize = 4 + 8 * 8 + CHUNK + 8;

// go: sdk 1.25.5 crypto/internal/fips140/sha512/sha512.go:204-208 New
/// `sha512.New()` — a new Digest computing the SHA-512 hash.
pub fn New() -> Digest {
    // Go: d := &Digest{size: size512}; d.Reset(); return d
    let mut d = new_digest(Size512);
    d.Reset();
    return d;
}

// go: sdk 1.25.5 crypto/internal/fips140/sha512/sha512.go:211-215 New512_224
/// `sha512.New512_224()` — a new Digest computing the SHA-512/224 hash.
pub fn New512_224() -> Digest {
    let mut d = new_digest(Size224);
    d.Reset();
    return d;
}

// go: sdk 1.25.5 crypto/internal/fips140/sha512/sha512.go:218-222 New512_256
/// `sha512.New512_256()` — a new Digest computing the SHA-512/256 hash.
pub fn New512_256() -> Digest {
    let mut d = new_digest(Size256);
    d.Reset();
    return d;
}

// go: sdk 1.25.5 crypto/internal/fips140/sha512/sha512.go:225-229 New384
/// `sha512.New384()` — a new Digest computing the SHA-384 hash.
pub fn New384() -> Digest {
    let mut d = new_digest(Size384);
    d.Reset();
    return d;
}

// go: none — goish idiom: Go writes the composite literal `&Digest{size:
// sz}` inline at each constructor; Rust needs every field named, so the
// zero value is factored out rather than repeated four times.
fn new_digest(sz: int) -> Digest {
    return Digest {
        h: [0; 8],
        x: [0; CHUNK],
        nx: 0,
        len: 0,
        size: sz,
    };
}

impl Digest {
    // go: sdk 1.25.5 crypto/internal/fips140/sha512/sha512.go:237-258 Digest.Write
    /// `(*Digest).Write(p)` — feed bytes into the running digest.
    /// Inherent forwarder to the `io::Writer` trait method.
    pub fn Write(&mut self, p: slice<byte>) -> (int, error) {
        return <Self as io::Writer>::Write(self, p);
    }

    // go: sdk 1.25.5 crypto/internal/fips140/sha512/sha512.go:260-267 Digest.Sum
    /// `(*Digest).Sum(b)` — append the digest to `b` and return it.
    /// Accepts `impl Into<slice<byte>>` so callers can pass `nil`.
    pub fn Sum<B: Into<slice<byte>>>(&self, b: B) -> slice<byte> {
        return <Self as Hash>::Sum(self, b.into());
    }

    // go: sdk 1.25.5 crypto/internal/fips140/sha512/sha512.go:133-135 Digest.MarshalBinary
    /// `(*Digest).MarshalBinary()` — the digest's internal state, so a
    /// running hash can be saved and resumed without re-feeding input.
    pub fn MarshalBinary(&self) -> (slice<byte>, error) {
        // Go: return d.AppendBinary(make([]byte, 0, marshaledSize))
        let buf: Vec<byte> = Vec::with_capacity(marshaledSize);
        return self.AppendBinary(slice::__from_vec(buf));
    }

    // go: sdk 1.25.5 crypto/internal/fips140/sha512/sha512.go:137-162 Digest.AppendBinary
    /// `(*Digest).AppendBinary(b)` — append the marshaled state to `b`.
    pub fn AppendBinary(&self, b: slice<byte>) -> (slice<byte>, error) {
        // Go: switch d.size { case size384: b = append(b, magic384...); … }
        let mut out: Vec<byte> = b.__into_vec();
        match self.size {
            v if v == Size384 => out.extend_from_slice(magic384),
            v if v == Size224 => out.extend_from_slice(magic512_224),
            v if v == Size256 => out.extend_from_slice(magic512_256),
            v if v == Size512 => out.extend_from_slice(magic512),
            // Go: default: panic("unknown size")
            _ => panic!("unknown size"),
        }
        // Go: b = byteorder.BEAppendUint64(b, d.h[i]) for i in 0..7
        let mut acc = slice::__from_vec(out);
        let mut i: usize = 0;
        while i < 8 {
            acc = byteorder::BEAppendUint64(acc, self.h[i]);
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

    // go: sdk 1.25.5 crypto/internal/fips140/sha512/sha512.go:164-192 Digest.UnmarshalBinary
    /// `(*Digest).UnmarshalBinary(b)` — restore state produced by
    /// [`Digest::MarshalBinary`].
    pub fn UnmarshalBinary(&mut self, b: slice<byte>) -> error {
        let raw: &[byte] = &b;
        // Go: if len(b) < len(magic512) { … }
        if raw.len() < magic512.len() {
            return crate::errors::New("crypto/sha512: invalid hash state identifier");
        }
        // Go: switch { case d.size == size384 && string(b[:4]) == magic384: … }
        let want: &[byte] = match self.size {
            v if v == Size384 => magic384,
            v if v == Size224 => magic512_224,
            v if v == Size256 => magic512_256,
            v if v == Size512 => magic512,
            // Go: default: return errors.New(…)
            _ => return crate::errors::New("crypto/sha512: invalid hash state identifier"),
        };
        if &raw[..want.len()] != want {
            return crate::errors::New("crypto/sha512: invalid hash state identifier");
        }
        // Go: if len(b) != marshaledSize { … }
        if raw.len() != marshaledSize {
            return crate::errors::New("crypto/sha512: invalid hash state size");
        }
        // Go: b = b[len(magic512):]
        let mut rest: &[byte] = &raw[magic512.len()..];
        // Go: b, d.h[i] = consumeUint64(b) for i in 0..7
        let mut i: usize = 0;
        while i < 8 {
            let (tail, v) = consumeUint64(rest);
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

    // go: sdk 1.25.5 crypto/internal/fips140/sha512/sha512.go:198-201 Digest.Clone
    /// `(*Digest).Clone()` — an independent copy of this digest's state.
    /// Never fails, so the error is always nil (Go says the same).
    pub fn Clone(&self) -> (Box<dyn Cloner + Send + Sync>, error) {
        // Go: r := *d; return &r, nil
        let r = Clone::clone(self);
        return (Box::new(r), nil);
    }
}

// go: sdk 1.25.5 crypto/internal/fips140/sha512/sha512.go:194-196 consumeUint64
/// Go: `func consumeUint64(b []byte) ([]byte, uint64)`
///
/// Takes/returns a borrowed `&[byte]` rather than `slice<byte>`: it is an
/// unexported cursor helper, never part of the package's Go API surface,
/// and the borrow avoids a re-wrap per field.
fn consumeUint64(b: &[byte]) -> (&[byte], uint64) {
    // Go: return b[8:], byteorder.BEUint64(b)
    return (
        &b[8..],
        byteorder::BEUint64(slice::__from_vec(b[..8].to_vec())),
    );
}

// ─── Hash trait impls for Digest ──────────────────────────────────────

impl io::Writer for Digest {
    // go: sdk 1.25.5 crypto/internal/fips140/sha512/sha512.go:237-258 Digest.Write
    fn Write(&mut self, p: slice<byte>) -> (int, error) {
        // Go: nn = len(p); d.len += uint64(nn)
        let raw: &[byte] = &p;
        let nn = raw.len();
        self.len += nn as u64;
        let mut q: &[byte] = raw;
        // Go: if d.nx > 0 { n := copy(d.x[d.nx:], p); … }
        if self.nx > 0 {
            let copy_n = core::cmp::min(CHUNK - self.nx, q.len());
            self.x[self.nx..self.nx + copy_n].copy_from_slice(&q[..copy_n]);
            self.nx += copy_n;
            if self.nx == CHUNK {
                // Slim: copy the buffer out to avoid a double borrow on self.
                let buf = self.x;
                block(self, &buf);
                self.nx = 0;
            }
            q = &q[copy_n..];
        }
        // Go: if len(p) >= chunk { n := len(p) &^ (chunk - 1); block(d, p[:n]); … }
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
        return (nn as int, nil);
    }
    // go: none — goish idiom: the hidden Any-view hook every
    // `#[goish::interface]` concrete impl overrides so `carrier.As::<…>()`
    // can reach this type. Go's itabs make it unnecessary.
    //
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
    // go: sdk 1.25.5 crypto/internal/fips140/sha512/sha512.go:260-267 Digest.Sum
    fn Sum(&self, b: slice<byte>) -> slice<byte> {
        // Go: d0 := *d; hash := d0.checkSum(); return append(in, hash[:d.size]...)
        let mut d0 = Clone::clone(self);
        let digest = checkSum(&mut d0);
        let mut out: Vec<byte> = b.__into_vec();
        out.extend_from_slice(&digest[..self.size as usize]);
        return slice::__from_vec(out);
    }

    // go: sdk 1.25.5 crypto/internal/fips140/sha512/sha512.go:80-123 Digest.Reset
    fn Reset(&mut self) {
        // Go: switch d.size { case size384: d.h[0] = init0_384; … }
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
            v if v == Size512 => {
                self.h[0] = init0;
                self.h[1] = init1;
                self.h[2] = init2;
                self.h[3] = init3;
                self.h[4] = init4;
                self.h[5] = init5;
                self.h[6] = init6;
                self.h[7] = init7;
            }
            // Go: default: panic("unknown size")
            _ => panic!("unknown size"),
        }
        self.nx = 0;
        self.len = 0;
    }

    // go: sdk 1.25.5 crypto/internal/fips140/sha512/sha512.go:231-233 Digest.Size
    fn Size(&self) -> int {
        // Go: return d.size
        return self.size;
    }

    // go: sdk 1.25.5 crypto/internal/fips140/sha512/sha512.go:235-235 Digest.BlockSize
    fn BlockSize(&self) -> int {
        // Go: func (d *Digest) BlockSize() int { return blockSize }
        return BlockSize;
    }
}

// go: sdk 1.25.5 crypto/internal/fips140/sha512/sha512.go:269-307 Digest.checkSum
/// Go: `checkSum` — finalize and return the full 64-byte digest buffer;
/// `Sum` truncates it to `d.size`.
fn checkSum(d: &mut Digest) -> [byte; 64] {
    // Go: len := d.len; var tmp [128 + 16]byte; tmp[0] = 0x80
    let mut len = d.len;
    let mut tmp = [0u8; 128 + 16];
    tmp[0] = 0x80;
    // Go: if len%128 < 112 { t = 112 - len%128 } else { t = 128 + 112 - len%128 }
    let t: u64 = if len % 128 < 112 {
        112 - len % 128
    } else {
        128 + 112 - len % 128
    };

    // Go: len <<= 3 — length in bits.
    len <<= 3;
    // Go: padlen := tmp[:t+16]; byteorder.BEPutUint64(padlen[t+8:], len); d.Write(padlen)
    //
    // Go zeroes padlen[t:t+8] as the high 64 bits of a 128-bit length
    // field; tmp starts zeroed, so that is already the case.
    let pad_end = (t + 16) as usize;
    let mut padv: Vec<byte> = tmp[..pad_end].to_vec();
    let off = (t + 8) as usize;
    let mut tail = slice::__from_vec(padv.split_off(off));
    byteorder::BEPutUint64(&mut tail, len);
    padv.extend_from_slice(&tail);
    let _ = io::Writer::Write(d, slice::__from_vec(padv));

    // Go: if d.nx != 0 { panic("d.nx != 0") }
    if d.nx != 0 {
        panic!("d.nx != 0");
    }

    // Go: var digest [size512]byte
    //     byteorder.BEPutUint64(digest[0:], d.h[0]) … through h[5]
    let mut digest = [0u8; 64];
    let mut i: usize = 0;
    while i < 6 {
        let mut w = slice::__from_vec(alloc::vec![0u8; 8]);
        byteorder::BEPutUint64(&mut w, d.h[i]);
        digest[i * 8..i * 8 + 8].copy_from_slice(&w);
        i += 1;
    }
    // Go: if d.size != size384 { BEPutUint64(digest[48:], d.h[6]);
    //                            BEPutUint64(digest[56:], d.h[7]) }
    if d.size != Size384 {
        let mut i: usize = 6;
        while i < 8 {
            let mut w = slice::__from_vec(alloc::vec![0u8; 8]);
            byteorder::BEPutUint64(&mut w, d.h[i]);
            digest[i * 8..i * 8 + 8].copy_from_slice(&w);
            i += 1;
        }
    }

    // Go: return digest
    return digest;
}

// ─── hash.Cloner + encoding interface impls ───────────────────────────
//
// Go's Digest satisfies encoding.BinaryMarshaler, encoding.BinaryAppender,
// encoding.BinaryUnmarshaler and hash.Cloner structurally. goish's
// interfaces are nominal, so the impls are spelled out; each forwards to
// the inherent method above.

impl encoding::BinaryMarshaler for Digest {
    // go: sdk 1.25.5 crypto/internal/fips140/sha512/sha512.go:133-135 Digest.MarshalBinary
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
    // go: sdk 1.25.5 crypto/internal/fips140/sha512/sha512.go:137-162 Digest.AppendBinary
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
    // go: sdk 1.25.5 crypto/internal/fips140/sha512/sha512.go:164-192 Digest.UnmarshalBinary
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
    // go: sdk 1.25.5 crypto/internal/fips140/sha512/sha512.go:198-201 Digest.Clone
    fn Clone(&self) -> (Box<dyn Cloner + Send + Sync>, error) {
        return Digest::Clone(self);
    }
}

// go: none — goish idiom: `#[goish::interface]` downcast registries are
// filled at runtime, one entry per `impl Trait for Concrete`; Go's itabs
// are built by the linker. Idempotent and cheap.
/// Register `Digest` into the `hash::Cloner` and `encoding::Binary*`
/// downcast registries so `carrier.As::<…>()` finds it.
pub fn register_sha512_impls() {
    crate::hash::__goish_register_Hash_impl::<Digest>();
    crate::io::__goish_register_Writer_impl::<Digest>();
    crate::hash::__goish_register_Cloner_impl::<Digest>();
    encoding::__goish_register_BinaryMarshaler_impl::<Digest>();
    encoding::__goish_register_BinaryAppender_impl::<Digest>();
    encoding::__goish_register_BinaryUnmarshaler_impl::<Digest>();
}

// ─── Boxed constructors for trait-object consumers ────────────────────

// go: none — goish idiom: boxed-trait constructors for call sites that
// need `Box<dyn Hash>` (Go returns the hash.Hash interface directly).
/// Use with `hmac::New(crypto::sha512::NewHash, key)`.
pub fn NewHash() -> Box<dyn Hash + Send + Sync> {
    return Box::new(New());
}

// go: none — see NewHash.
/// `sha512.NewHash384()` — boxed SHA-384 constructor.
pub fn NewHash384() -> Box<dyn Hash + Send + Sync> {
    return Box::new(New384());
}

// go: none — see NewHash.
/// `sha512.NewHash512_224()` — boxed SHA-512/224 constructor.
pub fn NewHash512_224() -> Box<dyn Hash + Send + Sync> {
    return Box::new(New512_224());
}

// go: none — see NewHash.
/// `sha512.NewHash512_256()` — boxed SHA-512/256 constructor.
pub fn NewHash512_256() -> Box<dyn Hash + Send + Sync> {
    return Box::new(New512_256());
}
