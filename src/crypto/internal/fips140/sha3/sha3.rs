// go: file crypto/internal/fips140/sha3/sha3.go decls: Digest.BlockSize, Digest.Size, Digest.Reset, Digest.Clone, Digest.permute, Digest.padAndPermute, Digest.Write, Digest.writeGeneric, Digest.readGeneric, Digest.Sum, Digest.sumGeneric, Digest.MarshalBinary, Digest.AppendBinary, Digest.UnmarshalBinary, register_sha3_impls, __goish_as_dyn_any, __goish_as_dyn_any_mut
//
// crypto/internal/fips140/sha3 — the SHA-3 fixed-output-length hash
// functions and the SHAKE variable-output-length functions defined by
// FIPS 202, plus the cSHAKE extendable-output-length functions defined by
// SP 800-185.
//
// The public crypto/sha3 package is a thin wrapper over this.
//
// Deviations from sha3[go] @ Go 1.25.5:
//
//   * Constructors return `Digest` by value rather than `*Digest`.
//   * `spongeDirection` is a `byte` rather than a named int type; the two
//     values keep Go's names and meaning.
//   * `fips140.RecordApproved()` in Sum is dropped: goish's fips140 stub
//     has no service indicator.
//   * cast[go]'s `init` — `fips140.CAST("SHA3-256", …)` — is not ported:
//     goish's fips140 stub has no CAST registry.

#![allow(non_snake_case, non_upper_case_globals)]
#![allow(non_camel_case_types)] // Go names (spongeDirection)

use crate::encoding;
use crate::errors::{error, nil};
use crate::goslice::slice;
use crate::hash::{Cloner, Hash};
use crate::io;
use crate::types::{byte, int};

extern crate alloc;
use alloc::boxed::Box;
use alloc::vec::Vec;

use super::sha3_noasm::{read, sum, write};

/// `sha3.spongeDirection` — which direction bytes are flowing through
/// the sponge. Go declares a named `int` type; goish uses `byte` so the
/// value marshals directly (AppendBinary writes it as one byte).
pub(crate) type spongeDirection = byte;

/// Go: `const spongeAbsorbing spongeDirection = iota` — the sponge is
/// absorbing input.
pub(crate) const spongeAbsorbing: spongeDirection = 0;
/// Go: `spongeSqueezing` — the sponge is being squeezed.
pub(crate) const spongeSqueezing: spongeDirection = 1;

/// Go: `a [1600 / 8]byte` — the state is 200 bytes.
pub(crate) const STATE_BYTES: usize = 1600 / 8;

// Go: sha3.go:26
//   type Digest struct { a [1600/8]byte; n, rate int; dsbyte byte;
//                        outputLen int; state spongeDirection }
/// `sha3.Digest` — a SHA-3 or SHAKE sponge.
#[derive(Clone)]
pub struct Digest {
    /// main state of the hash
    pub(crate) a: [byte; STATE_BYTES],

    /// `a[n:rate]` is the buffer. If absorbing, it's the remaining space
    /// to XOR into before running the permutation. If squeezing, it's the
    /// remaining output to produce before running the permutation.
    pub(crate) n: usize,
    pub(crate) rate: usize,

    /// dsbyte contains the "domain separation" bits and the first bit of
    /// the padding. FIPS 202 §6.1/§6.2 separate the outputs of the SHA-3
    /// and SHAKE functions by appending bitstrings to the message. Using
    /// a little-endian bit-ordering convention, these are "01" for SHA-3
    /// and "1111" for SHAKE, or 00000010b and 00001111b. Then the padding
    /// rule from §5.1 pads the message to a multiple of the rate, which
    /// adds a "1" bit, zero or more "0" bits, and a final "1" bit. The
    /// first "1" bit of the padding is merged into dsbyte, giving
    /// 00000110b (0x06) and 00011111b (0x1f).
    pub(crate) dsbyte: byte,

    /// the default output size in bytes
    pub(crate) outputLen: usize,
    /// whether the sponge is absorbing or squeezing
    pub(crate) state: spongeDirection,
}

// go: none — goish idiom: Go builds each Digest with a composite literal
// (`&Digest{rate: rateK448, outputLen: 28, dsbyte: dsbyteSHA3}`) at every
// constructor; Rust needs every field named, so the zero value is
// factored out rather than repeated eight times.
pub(crate) fn newDigest(rate: usize, outputLen: usize, dsbyte: byte) -> Digest {
    return Digest {
        a: [0; STATE_BYTES],
        n: 0,
        rate,
        dsbyte,
        outputLen,
        state: spongeAbsorbing,
    };
}

impl Digest {
    // go: sdk 1.25.5 crypto/internal/fips140/sha3/sha3.go:56-56 Digest.BlockSize
    /// Go: `func (d *Digest) BlockSize() int { return d.rate }` — the
    /// rate of the sponge underlying this hash function.
    pub fn BlockSize(&self) -> int {
        return self.rate as int;
    }

    // go: sdk 1.25.5 crypto/internal/fips140/sha3/sha3.go:59-59 Digest.Size
    /// Go: `func (d *Digest) Size() int { return d.outputLen }`
    pub fn Size(&self) -> int {
        return self.outputLen as int;
    }

    // go: sdk 1.25.5 crypto/internal/fips140/sha3/sha3.go:62-69 Digest.Reset
    /// `(*Digest).Reset()` — reset the Digest to its initial state.
    pub fn Reset(&mut self) {
        // Go: for i := range d.a { d.a[i] = 0 }
        let mut i: usize = 0;
        while i < STATE_BYTES {
            self.a[i] = 0;
            i += 1;
        }
        // Go: d.state = spongeAbsorbing; d.n = 0
        self.state = spongeAbsorbing;
        self.n = 0;
    }

    // go: sdk 1.25.5 crypto/internal/fips140/sha3/sha3.go:71-74 Digest.Clone
    /// Go: `func (d *Digest) Clone() *Digest { ret := *d; return &ret }`
    pub fn Clone(&self) -> Digest {
        return Clone::clone(self);
    }

    // go: sdk 1.25.5 crypto/internal/fips140/sha3/sha3.go:77-80 Digest.permute
    /// Apply the Keccak-f[1600] permutation.
    pub(crate) fn permute(&mut self) {
        // Go: keccakF1600(&d.a); d.n = 0
        super::sha3_noasm::keccakF1600(&mut self.a);
        self.n = 0;
    }

    // go: sdk 1.25.5 crypto/internal/fips140/sha3/sha3.go:84-97 Digest.padAndPermute
    /// Append the domain separation bits in `dsbyte`, apply the
    /// multi-bitrate 10..1 padding rule, and permute the state.
    pub(crate) fn padAndPermute(&mut self) {
        // Go: d.a[d.n] ^= d.dsbyte
        //
        // There is at least one byte of space in the sponge: if it were
        // full, permute would already have emptied it. dsbyte also holds
        // the first one bit of the padding.
        self.a[self.n] ^= self.dsbyte;
        // Go: d.a[d.rate-1] ^= 0x80 — the final one bit. Bits are
        // numbered from the LSB upward, so it is the MSB of the last byte.
        self.a[self.rate - 1] ^= 0x80;
        // Go: d.permute(); d.state = spongeSqueezing
        self.permute();
        self.state = spongeSqueezing;
    }

    // go: sdk 1.25.5 crypto/internal/fips140/sha3/sha3.go:100-100 Digest.Write
    /// `(*Digest).Write(p)` — absorb more data into the hash's state.
    pub fn Write(&mut self, p: slice<byte>) -> (int, error) {
        // Go: return d.write(p)
        return write(self, p);
    }

    // go: sdk 1.25.5 crypto/internal/fips140/sha3/sha3.go:101-120 Digest.writeGeneric
    /// Go: `func (d *Digest) writeGeneric(p []byte) (n int, err error)`
    pub(crate) fn writeGeneric(&mut self, p: slice<byte>) -> (int, error) {
        // Go: if d.state != spongeAbsorbing { panic("sha3: Write after Read") }
        if self.state != spongeAbsorbing {
            panic!("sha3: Write after Read");
        }
        // Go: n = len(p)
        let nn: int = p.Len();
        let raw: &[byte] = &p;
        let total = raw.len();
        let mut i: usize = 0;
        // Go: for len(p) > 0 { … }
        while i < total {
            // Go: x := subtle.XORBytes(d.a[d.n:d.rate], d.a[d.n:d.rate], p)
            let space = self.rate - self.n;
            let take = if total - i < space { total - i } else { space };
            let mut k: usize = 0;
            while k < take {
                self.a[self.n + k] ^= raw[i + k];
                k += 1;
            }
            // Go: d.n += x; p = p[x:]
            self.n += take;
            i += take;
            // Go: if d.n == d.rate { d.permute() } — the sponge is full.
            if self.n == self.rate {
                self.permute();
            }
        }
        return (nn, nil);
    }

    // go: sdk 1.25.5 crypto/internal/fips140/sha3/sha3.go:123-144 Digest.readGeneric
    /// Squeeze an arbitrary number of bytes from the sponge.
    pub(crate) fn readGeneric(&mut self, out: &mut [byte]) -> usize {
        // Go: if d.state == spongeAbsorbing { d.padAndPermute() }
        if self.state == spongeAbsorbing {
            self.padAndPermute();
        }
        // Go: n = len(out)
        let nn = out.len();
        let mut i: usize = 0;
        // Go: for len(out) > 0 { … }
        while i < nn {
            // Go: if d.n == d.rate { d.permute() } — squeezed dry.
            if self.n == self.rate {
                self.permute();
            }
            // Go: x := copy(out, d.a[d.n:d.rate])
            let avail = self.rate - self.n;
            let take = if nn - i < avail { nn - i } else { avail };
            let mut k: usize = 0;
            while k < take {
                out[i + k] = self.a[self.n + k];
                k += 1;
            }
            self.n += take;
            i += take;
        }
        return nn;
    }

    // go: sdk 1.25.5 crypto/internal/fips140/sha3/sha3.go:148-151 Digest.Sum
    /// `(*Digest).Sum(b)` — append the current hash to `b`. Does not
    /// change the underlying hash state.
    pub fn Sum<B: Into<slice<byte>>>(&self, b: B) -> slice<byte> {
        // Go: fips140.RecordApproved(); return d.sum(b)
        return sum(self, b.into());
    }

    // go: sdk 1.25.5 crypto/internal/fips140/sha3/sha3.go:153-164 Digest.sumGeneric
    /// Go: `func (d *Digest) sumGeneric(b []byte) []byte`
    pub(crate) fn sumGeneric(&self, b: slice<byte>) -> slice<byte> {
        // Go: if d.state != spongeAbsorbing { panic("sha3: Sum after Read") }
        if self.state != spongeAbsorbing {
            panic!("sha3: Sum after Read");
        }
        // Go: dup := d.Clone() — so the caller can keep writing and summing.
        let mut dup = self.Clone();
        // Go: hash := make([]byte, dup.outputLen, 64); dup.read(hash)
        let mut hash: Vec<byte> = alloc::vec![0u8; dup.outputLen];
        read(&mut dup, &mut hash);
        // Go: return append(b, hash...)
        let mut out: Vec<byte> = b.__into_vec();
        out.extend_from_slice(&hash);
        return slice::__from_vec(out);
    }

    // go: sdk 1.25.5 crypto/internal/fips140/sha3/sha3.go:175-177 Digest.MarshalBinary
    /// `(*Digest).MarshalBinary()` — the sponge's internal state.
    pub fn MarshalBinary(&self) -> (slice<byte>, error) {
        // Go: return d.AppendBinary(make([]byte, 0, marshaledSize))
        let buf: Vec<byte> = Vec::with_capacity(marshaledSize);
        return self.AppendBinary(slice::__from_vec(buf));
    }

    // go: sdk 1.25.5 crypto/internal/fips140/sha3/sha3.go:179-197 Digest.AppendBinary
    /// `(*Digest).AppendBinary(b)` — append the marshaled state to `b`.
    pub fn AppendBinary(&self, b: slice<byte>) -> (slice<byte>, error) {
        let mut out: Vec<byte> = b.__into_vec();
        // Go: switch d.dsbyte { case dsbyteSHA3: b = append(b, magicSHA3...); … }
        match self.dsbyte {
            v if v == super::hashes::dsbyteSHA3 => out.extend_from_slice(magicSHA3),
            v if v == super::hashes::dsbyteShake => out.extend_from_slice(magicShake),
            v if v == super::hashes::dsbyteCShake => out.extend_from_slice(magicCShake),
            v if v == super::hashes::dsbyteKeccak => out.extend_from_slice(magicKeccak),
            // Go: default: panic("unknown dsbyte")
            _ => panic!("unknown dsbyte"),
        }
        // Go: b = append(b, byte(d.rate)) — rate is at most 168, n at most rate.
        out.push((self.rate & 0xff) as byte);
        // Go: b = append(b, d.a[:]...)
        out.extend_from_slice(&self.a);
        // Go: b = append(b, byte(d.n), byte(d.state)); return b, nil
        out.push((self.n & 0xff) as byte);
        out.push(self.state);
        return (slice::__from_vec(out), nil);
    }

    // go: sdk 1.25.5 crypto/internal/fips140/sha3/sha3.go:199-235 Digest.UnmarshalBinary
    /// `(*Digest).UnmarshalBinary(b)` — restore state produced by
    /// [`Digest::MarshalBinary`].
    pub fn UnmarshalBinary(&mut self, b: slice<byte>) -> error {
        let raw: &[byte] = &b;
        // Go: if len(b) != marshaledSize { return errors.New("sha3: invalid hash state") }
        if raw.len() != marshaledSize {
            return crate::errors::New("sha3: invalid hash state");
        }

        // Go: magic := string(b[:len(magicSHA3)]); b = b[len(magicSHA3):]
        let magic = &raw[..magicSHA3.len()];
        let rest = &raw[magicSHA3.len()..];
        // Go: switch { case magic == magicSHA3 && d.dsbyte == dsbyteSHA3: … }
        let ok = (magic == magicSHA3 && self.dsbyte == super::hashes::dsbyteSHA3)
            || (magic == magicShake && self.dsbyte == super::hashes::dsbyteShake)
            || (magic == magicCShake && self.dsbyte == super::hashes::dsbyteCShake)
            || (magic == magicKeccak && self.dsbyte == super::hashes::dsbyteKeccak);
        if !ok {
            return crate::errors::New("sha3: invalid hash state identifier");
        }

        // Go: rate := int(b[0]); b = b[1:]
        let rate = rest[0] as usize;
        let rest = &rest[1..];
        // Go: if rate != d.rate { return errors.New("sha3: invalid hash state function") }
        if rate != self.rate {
            return crate::errors::New("sha3: invalid hash state function");
        }

        // Go: copy(d.a[:], b); b = b[len(d.a):]
        self.a.copy_from_slice(&rest[..STATE_BYTES]);
        let rest = &rest[STATE_BYTES..];

        // Go: n, state := int(b[0]), spongeDirection(b[1])
        let n = rest[0] as usize;
        let state = rest[1];
        // Go: if n > d.rate { return errors.New("sha3: invalid hash state") }
        if n > self.rate {
            return crate::errors::New("sha3: invalid hash state");
        }
        self.n = n;
        // Go: if state != spongeAbsorbing && state != spongeSqueezing { … }
        if state != spongeAbsorbing && state != spongeSqueezing {
            return crate::errors::New("sha3: invalid hash state");
        }
        self.state = state;

        return nil;
    }
}

// ─── Marshaling magics (sha3[go]:164-169) ─────────────────────────────

/// Go: `magicSHA3 = "sha\x08"`
const magicSHA3: &[byte] = b"sha\x08";
/// Go: `magicShake = "sha\x09"`
const magicShake: &[byte] = b"sha\x09";
/// Go: `magicCShake = "sha\x0a"`
const magicCShake: &[byte] = b"sha\x0a";
/// Go: `magicKeccak = "sha\x0b"`
const magicKeccak: &[byte] = b"sha\x0b";
/// Go: `marshaledSize = len(magicSHA3) + 1 + 200 + 1 + 1`
pub(crate) const marshaledSize: usize = 4 + 1 + 200 + 1 + 1;

// ─── hash.Hash / Cloner / encoding impls ──────────────────────────────

impl io::Writer for Digest {
    // go: sdk 1.25.5 crypto/internal/fips140/sha3/sha3.go:100-100 Digest.Write
    fn Write(&mut self, p: slice<byte>) -> (int, error) {
        return Digest::Write(self, p);
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
    // go: sdk 1.25.5 crypto/internal/fips140/sha3/sha3.go:148-151 Digest.Sum
    fn Sum(&self, b: slice<byte>) -> slice<byte> {
        return Digest::Sum(self, b);
    }
    // go: sdk 1.25.5 crypto/internal/fips140/sha3/sha3.go:62-69 Digest.Reset
    fn Reset(&mut self) {
        Digest::Reset(self);
    }
    // go: sdk 1.25.5 crypto/internal/fips140/sha3/sha3.go:59-59 Digest.Size
    fn Size(&self) -> int {
        return Digest::Size(self);
    }
    // go: sdk 1.25.5 crypto/internal/fips140/sha3/sha3.go:56-56 Digest.BlockSize
    fn BlockSize(&self) -> int {
        return Digest::BlockSize(self);
    }
}

impl encoding::BinaryMarshaler for Digest {
    // go: sdk 1.25.5 crypto/internal/fips140/sha3/sha3.go:175-177 Digest.MarshalBinary
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
    // go: sdk 1.25.5 crypto/internal/fips140/sha3/sha3.go:179-197 Digest.AppendBinary
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
    // go: sdk 1.25.5 crypto/internal/fips140/sha3/sha3.go:199-235 Digest.UnmarshalBinary
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
    // go: sdk 1.25.5 crypto/internal/fips140/sha3/sha3.go:71-74 Digest.Clone
    fn Clone(&self) -> (Box<dyn Cloner + Send + Sync>, error) {
        return (Box::new(Digest::Clone(self)), nil);
    }
}

// go: none — goish idiom: `#[goish::interface]` downcast registries are
// filled at runtime, one entry per `impl Trait for Concrete`; Go's itabs
// are built by the linker. Idempotent and cheap.
/// Register `Digest` into the `hash::Cloner` and `encoding::Binary*`
/// downcast registries so `carrier.As::<…>()` finds it.
pub fn register_sha3_impls() {
    crate::hash::__goish_register_Hash_impl::<Digest>();
    crate::io::__goish_register_Writer_impl::<Digest>();
    crate::hash::__goish_register_Cloner_impl::<Digest>();
    encoding::__goish_register_BinaryMarshaler_impl::<Digest>();
    encoding::__goish_register_BinaryAppender_impl::<Digest>();
    encoding::__goish_register_BinaryUnmarshaler_impl::<Digest>();
}
