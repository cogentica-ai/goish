// go: file crypto/internal/fips140/sha3/shake.go decls: bytepad, leftEncode, newCShake, SHAKE.BlockSize, SHAKE.Size, SHAKE.Sum, SHAKE.Write, SHAKE.Read, SHAKE.Reset, SHAKE.Clone, SHAKE.MarshalBinary, SHAKE.AppendBinary, SHAKE.UnmarshalBinary, NewShake128, NewShake256, NewCShake128, NewCShake256
//
// SHAKE128/256 (FIPS 202) and cSHAKE128/256 (SP 800-185).
//
// Deviation: `fips140.RecordApproved()` in Read is dropped — goish's
// fips140 stub has no service indicator.

#![allow(non_snake_case, non_upper_case_globals)]

use crate::crypto::internal::fips140deps::byteorder;
use crate::errors::{error, nil};
use crate::goslice::slice;
use crate::math::bits;
use crate::types::{byte, int, uint64};

use super::hashes::{dsbyteCShake, dsbyteShake, rateK256, rateK512};
use super::sha3::{marshaledSize, newDigest, Digest};
use super::sha3_noasm::read;

extern crate alloc;
use alloc::vec::Vec;

// Go: shake.go:16
//   type SHAKE struct { d Digest; initBlock []byte }
/// `sha3.SHAKE` — a SHAKE or cSHAKE extendable-output function.
#[derive(Clone)]
pub struct SHAKE {
    /// SHA-3 state context and Read/Write operations
    d: Digest,

    /// The cSHAKE-specific initialization set of bytes, built by
    /// `newCShake` as the concatenation of N followed by S, encoded per
    /// SP 800-185 §3.3. Stored so `Reset` can restore the initial state.
    initBlock: Vec<byte>,
}

// go: sdk 1.25.5 crypto/internal/fips140/sha3/shake.go:26-34 bytepad
/// Go: `func bytepad(data []byte, rate int) []byte`
fn bytepad(data: &[byte], rate: usize) -> Vec<byte> {
    // Go: out := make([]byte, 0, 9+len(data)+rate-1)
    let mut out: Vec<byte> = Vec::with_capacity(9 + data.len() + rate - 1);
    // Go: out = append(out, leftEncode(uint64(rate))...)
    out.extend_from_slice(&leftEncode(rate as uint64));
    // Go: out = append(out, data...)
    out.extend_from_slice(data);
    // Go: if padlen := rate - len(out)%rate; padlen < rate { … }
    let padlen = rate - out.len() % rate;
    if padlen < rate {
        out.resize(out.len() + padlen, 0);
    }
    return out;
}

// go: sdk 1.25.5 crypto/internal/fips140/sha3/shake.go:36-47 leftEncode
/// Go: `func leftEncode(x uint64) []byte`
fn leftEncode(x: uint64) -> Vec<byte> {
    // Go: n := (bits.Len64(x) + 7) / 8; if n == 0 { n = 1 }
    let mut n = ((bits::Len64(x) as usize) + 7) / 8;
    if n == 0 {
        n = 1;
    }
    // Go: b := make([]byte, 9); byteorder.BEPutUint64(b[1:], x)
    let mut b: Vec<byte> = alloc::vec![0u8; 9];
    let mut tail = slice::__from_vec(alloc::vec![0u8; 8]);
    byteorder::BEPutUint64(&mut tail, x);
    let tr: &[byte] = &tail;
    b[1..9].copy_from_slice(tr);
    // Go: b = b[9-n-1:]; b[0] = byte(n)
    let mut out: Vec<byte> = b[9 - n - 1..].to_vec();
    out[0] = (n & 0xff) as byte;
    return out;
}

// go: sdk 1.25.5 crypto/internal/fips140/sha3/shake.go:50-59 newCShake
/// Go: `func newCShake(N, S []byte, rate, outputLen int, dsbyte byte) *SHAKE`
fn newCShake(N: &[byte], S: &[byte], rate: usize, outputLen: usize, dsbyte: byte) -> SHAKE {
    // Go: c := &SHAKE{d: Digest{rate: rate, outputLen: outputLen, dsbyte: dsbyte}}
    let mut c = SHAKE {
        d: newDigest(rate, outputLen, dsbyte),
        initBlock: Vec::with_capacity(9 + N.len() + 9 + S.len()),
    };
    // Go: c.initBlock = append(c.initBlock, leftEncode(uint64(len(N))*8)...)
    let mut ib: Vec<byte> = Vec::with_capacity(9 + N.len() + 9 + S.len());
    ib.extend_from_slice(&leftEncode((N.len() as uint64) * 8));
    // Go: c.initBlock = append(c.initBlock, N...)
    ib.extend_from_slice(N);
    // Go: c.initBlock = append(c.initBlock, leftEncode(uint64(len(S))*8)...)
    ib.extend_from_slice(&leftEncode((S.len() as uint64) * 8));
    // Go: c.initBlock = append(c.initBlock, S...)
    ib.extend_from_slice(S);
    c.initBlock = ib;
    // Go: c.Write(bytepad(c.initBlock, c.d.rate))
    let pad = bytepad(&c.initBlock, c.d.rate);
    let _ = c.Write(slice::__from_vec(pad));
    return c;
}

impl SHAKE {
    // go: sdk 1.25.5 crypto/internal/fips140/sha3/shake.go:61-61 SHAKE.BlockSize
    /// Go: `func (s *SHAKE) BlockSize() int { return s.d.BlockSize() }`
    pub fn BlockSize(&self) -> int {
        return self.d.BlockSize();
    }

    // go: sdk 1.25.5 crypto/internal/fips140/sha3/shake.go:62-62 SHAKE.Size
    /// Go: `func (s *SHAKE) Size() int { return s.d.Size() }`
    pub fn Size(&self) -> int {
        return self.d.Size();
    }

    // go: sdk 1.25.5 crypto/internal/fips140/sha3/shake.go:68-68 SHAKE.Sum
    /// `(*SHAKE).Sum(b)` — append a portion of output to `b`. The output
    /// length gives full-strength generic security: 32 bytes for
    /// SHAKE128, 64 for SHAKE256. Does not change the underlying state.
    /// Panics if any output has already been read.
    pub fn Sum<B: Into<slice<byte>>>(&self, b: B) -> slice<byte> {
        // Go: return s.d.Sum(in)
        return self.d.Sum(b.into());
    }

    // go: sdk 1.25.5 crypto/internal/fips140/sha3/shake.go:72-72 SHAKE.Write
    /// `(*SHAKE).Write(p)` — absorb more data into the state. Panics if
    /// any output has already been read.
    pub fn Write(&mut self, p: slice<byte>) -> (int, error) {
        // Go: return s.d.Write(p)
        return self.d.Write(p);
    }

    // go: sdk 1.25.5 crypto/internal/fips140/sha3/shake.go:74-79 SHAKE.Read
    /// `(*SHAKE).Read(out)` — squeeze output. Note that `read` is not
    /// exposed on `Digest`, since SHA-3 offers no variable output length;
    /// it is used there only by `Sum`.
    pub fn Read(&mut self, out: &mut [byte]) -> usize {
        // Go: fips140.RecordApproved(); return s.d.read(out)
        return read(&mut self.d, out);
    }

    // go: sdk 1.25.5 crypto/internal/fips140/sha3/shake.go:82-87 SHAKE.Reset
    /// `(*SHAKE).Reset()` — reset the hash to its initial state.
    pub fn Reset(&mut self) {
        // Go: s.d.Reset()
        self.d.Reset();
        // Go: if len(s.initBlock) != 0 { s.Write(bytepad(s.initBlock, s.d.rate)) }
        if !self.initBlock.is_empty() {
            let pad = bytepad(&self.initBlock, self.d.rate);
            let _ = self.Write(slice::__from_vec(pad));
        }
    }

    // go: sdk 1.25.5 crypto/internal/fips140/sha3/shake.go:90-93 SHAKE.Clone
    /// `(*SHAKE).Clone()` — a copy of the SHAKE context in its current
    /// state.
    pub fn Clone(&self) -> SHAKE {
        return Clone::clone(self);
    }

    // go: sdk 1.25.5 crypto/internal/fips140/sha3/shake.go:95-97 SHAKE.MarshalBinary
    /// `(*SHAKE).MarshalBinary()` — the sponge state plus the cSHAKE
    /// init block.
    pub fn MarshalBinary(&self) -> (slice<byte>, error) {
        // Go: return s.AppendBinary(make([]byte, 0, marshaledSize+len(s.initBlock)))
        let buf: Vec<byte> = Vec::with_capacity(marshaledSize + self.initBlock.len());
        return self.AppendBinary(slice::__from_vec(buf));
    }

    // go: sdk 1.25.5 crypto/internal/fips140/sha3/shake.go:99-106 SHAKE.AppendBinary
    /// `(*SHAKE).AppendBinary(b)` — append the marshaled state to `b`.
    pub fn AppendBinary(&self, b: slice<byte>) -> (slice<byte>, error) {
        // Go: b, err := s.d.AppendBinary(b); if err != nil { return nil, err }
        let (acc, err) = self.d.AppendBinary(b);
        if err != nil {
            return (slice::__from_vec(Vec::new()), err);
        }
        // Go: b = append(b, s.initBlock...); return b, nil
        let mut out: Vec<byte> = acc.__into_vec();
        out.extend_from_slice(&self.initBlock);
        return (slice::__from_vec(out), nil);
    }

    // go: sdk 1.25.5 crypto/internal/fips140/sha3/shake.go:108-117 SHAKE.UnmarshalBinary
    /// `(*SHAKE).UnmarshalBinary(b)` — restore state produced by
    /// [`SHAKE::MarshalBinary`].
    pub fn UnmarshalBinary(&mut self, b: slice<byte>) -> error {
        let raw: &[byte] = &b;
        // Go: if len(b) < marshaledSize { return errors.New("sha3: invalid hash state") }
        if raw.len() < marshaledSize {
            return crate::errors::New("sha3: invalid hash state");
        }
        // Go: if err := s.d.UnmarshalBinary(b[:marshaledSize]); err != nil { return err }
        let err = self
            .d
            .UnmarshalBinary(slice::__from_vec(raw[..marshaledSize].to_vec()));
        if err != nil {
            return err;
        }
        // Go: s.initBlock = bytes.Clone(b[marshaledSize:])
        self.initBlock = raw[marshaledSize..].to_vec();
        return nil;
    }
}

// go: sdk 1.25.5 crypto/internal/fips140/sha3/shake.go:120-122 NewShake128
/// `sha3.NewShake128()` — a new SHAKE128 XOF.
pub fn NewShake128() -> SHAKE {
    // Go: return &SHAKE{d: Digest{rate: rateK256, outputLen: 32, dsbyte: dsbyteShake}}
    return SHAKE {
        d: newDigest(rateK256, 32, dsbyteShake),
        initBlock: Vec::new(),
    };
}

// go: sdk 1.25.5 crypto/internal/fips140/sha3/shake.go:125-127 NewShake256
/// `sha3.NewShake256()` — a new SHAKE256 XOF.
pub fn NewShake256() -> SHAKE {
    return SHAKE {
        d: newDigest(rateK512, 64, dsbyteShake),
        initBlock: Vec::new(),
    };
}

// go: sdk 1.25.5 crypto/internal/fips140/sha3/shake.go:134-139 NewCShake128
/// `sha3.NewCShake128(N, S)` — a new cSHAKE128 XOF.
///
/// `N` names a function built on cSHAKE and may be empty when plain
/// cSHAKE is wanted. `S` is a customization string used for domain
/// separation. When both are empty this is equivalent to
/// [`NewShake128`].
pub fn NewCShake128(N: slice<byte>, S: slice<byte>) -> SHAKE {
    let nr: &[byte] = &N;
    let sr: &[byte] = &S;
    // Go: if len(N) == 0 && len(S) == 0 { return NewShake128() }
    if nr.is_empty() && sr.is_empty() {
        return NewShake128();
    }
    // Go: return newCShake(N, S, rateK256, 32, dsbyteCShake)
    return newCShake(nr, sr, rateK256, 32, dsbyteCShake);
}

// go: sdk 1.25.5 crypto/internal/fips140/sha3/shake.go:146-151 NewCShake256
/// `sha3.NewCShake256(N, S)` — a new cSHAKE256 XOF. See
/// [`NewCShake128`].
pub fn NewCShake256(N: slice<byte>, S: slice<byte>) -> SHAKE {
    let nr: &[byte] = &N;
    let sr: &[byte] = &S;
    // Go: if len(N) == 0 && len(S) == 0 { return NewShake256() }
    if nr.is_empty() && sr.is_empty() {
        return NewShake256();
    }
    // Go: return newCShake(N, S, rateK512, 64, dsbyteCShake)
    return newCShake(nr, sr, rateK512, 64, dsbyteCShake);
}
