// go: file crypto/internal/fips140/ecdsa/hmacdrbg.go decls: plainPersonalizationString.isPersonalizationString, blockAlignedPersonalizationString.isPersonalizationString, newDRBG, TestingOnlyNewDRBG, pad000, hmacDRBG.Generate
//
// Deviations from hmacdrbg[go] @ Go 1.25.5:
//
//   * Go's `newHMAC func(key []byte) *hmac.HMAC` field is a closure over
//     the hash constructor. The closure captures only `hash`, so the field
//     holds that constructor and the one call site builds the HMAC inline.
//     It is a `hash::HashFunc` — the carrier that keeps `Arc<dyn Fn>`
//     inside a concrete goish type rather than in a struct field
//     (AGENTS.md §5 rule 3).
//   * `personalizationString` is a Go interface with two implementing
//     types and a nil case, consumed exclusively by a type switch. That
//     is an enum here; the two named types survive as its payloads so
//     the call sites still read `plainPersonalizationString(persStr)`.
//   * Go's `hash func() H` generic parameter collapses to
//     `impl IntoHashFunc`, the factory shape the rest of the crypto tree
//     takes — a plain function or a closure.

#![allow(non_snake_case, non_camel_case_types)]

extern crate alloc;
use alloc::vec::Vec;

use crate::crypto::internal::fips140;
use crate::crypto::internal::fips140::hmac::{self, HMAC};
use crate::goslice::slice;
use crate::hash::{Hash, HashFunc, IntoHashFunc};
use crate::io;
use crate::types::{byte, int, uint64};

// Go: hmacdrbg.go:22-29
//   type hmacDRBG struct { newHMAC func(key []byte) *hmac.HMAC; hK *hmac.HMAC; V []byte; reseedCounter uint64 }
/// An SP 800-90A Rev. 1 HMAC_DRBG.
///
/// It is only intended to be used to generate ECDSA nonces. Since it will
/// be instantiated ex-novo for each signature, its Generate function will
/// only be invoked once or twice (only for P-256, with probability 2⁻³²).
///
/// Per Table 2, it has a reseed interval of 2^48 requests, and a maximum
/// request size of 2^19 bits (2^16 bytes, 64 KiB).
pub struct hmacDRBG {
    /// Go holds `func(key []byte) *hmac.HMAC`; this holds the hash
    /// constructor that closure captured.
    newHMAC: HashFunc,

    hK: HMAC,
    V: slice<byte>,

    reseedCounter: uint64,
}

// Go: hmacdrbg.go:31-34 — `const ( reseedInterval = 1 << 48; maxRequestSize = (1 << 19) / 8 )`
/// Go: `const reseedInterval = 1 << 48`
pub const reseedInterval: uint64 = 1 << 48;
/// Go: `const maxRequestSize = (1 << 19) / 8`
pub const maxRequestSize: usize = (1 << 19) / 8;

// Go: hmacdrbg.go:36-37
//   type plainPersonalizationString []byte
/// Used by HMAC_DRBG as-is.
pub struct plainPersonalizationString(pub slice<byte>);

impl plainPersonalizationString {
    // go: sdk 1.25.5 crypto/internal/fips140/ecdsa/hmacdrbg.go:39-39 plainPersonalizationString.isPersonalizationString
    //
    // Go's marker method. Nothing calls it; membership in the interface
    // is the entire point, and here that is the enum below.
    #[allow(dead_code)]
    fn isPersonalizationString(&self) {}
}

// Go: hmacdrbg.go:41-44
//   type blockAlignedPersonalizationString [][]byte
/// Each entry is written to the HMAC at a block boundary, as specified in
/// draft-irtf-cfrg-det-sigs-with-noise-04, Section 4.
pub struct blockAlignedPersonalizationString(pub slice<slice<byte>>);

impl blockAlignedPersonalizationString {
    // go: sdk 1.25.5 crypto/internal/fips140/ecdsa/hmacdrbg.go:46-46 blockAlignedPersonalizationString.isPersonalizationString
    #[allow(dead_code)]
    fn isPersonalizationString(&self) {}
}

// Go: hmacdrbg.go:48-50
//   type personalizationString interface { isPersonalizationString() }
pub enum personalizationString {
    plain(plainPersonalizationString),
    blockAligned(blockAlignedPersonalizationString),
    /// Go passes a nil `personalizationString` from SignDeterministic and
    /// from fipsPCT.
    nil,
}

// go: sdk 1.25.5 crypto/internal/fips140/ecdsa/hmacdrbg.go:52-118 newDRBG
pub(super) fn newDRBG(
    hash: impl IntoHashFunc,
    entropy: &slice<byte>,
    nonce: &slice<byte>,
    s: personalizationString,
) -> hmacDRBG {
    // HMAC_DRBG_Instantiate_algorithm, per Section 10.1.2.3.
    fips140::RecordApproved();

    let hash = hash.into_hash_func();
    let size = hash.Call().Size() as usize;

    // K = 0x00 0x00 0x00 ... 0x00
    let mut K = slice::__from_vec(alloc::vec![0u8; size]);

    // V = 0x01 0x01 0x01 ... 0x01
    let mut V = slice::__from_vec(alloc::vec![0x01u8; size]);

    // HMAC_DRBG_Update, per Section 10.1.2.2.
    // K = HMAC (K, V || 0x00 || provided_data)
    let mut h = hmac::New(hash.clone(), K.clone());
    let _ = io::Writer::Write(&mut h, V.clone());
    let _ = io::Writer::Write(&mut h, slice::__from_vec(alloc::vec![0x00u8]));
    let _ = io::Writer::Write(&mut h, entropy.clone());
    let _ = io::Writer::Write(&mut h, nonce.clone());
    writePersonalization(&mut h, &s, V.Len() + 1 + entropy.Len() + nonce.Len());
    K = Hash::Sum(&h, empty());
    // V = HMAC (K, V)
    let mut h = hmac::New(hash.clone(), K.clone());
    let _ = io::Writer::Write(&mut h, V.clone());
    V = Hash::Sum(&h, empty());
    // K = HMAC (K, V || 0x01 || provided_data).
    Hash::Reset(&mut h);
    let _ = io::Writer::Write(&mut h, V.clone());
    let _ = io::Writer::Write(&mut h, slice::__from_vec(alloc::vec![0x01u8]));
    let _ = io::Writer::Write(&mut h, entropy.clone());
    let _ = io::Writer::Write(&mut h, nonce.clone());
    writePersonalization(&mut h, &s, V.Len() + 1 + entropy.Len() + nonce.Len());
    K = Hash::Sum(&h, empty());
    // V = HMAC (K, V)
    let mut h = hmac::New(hash.clone(), K.clone());
    let _ = io::Writer::Write(&mut h, V.clone());
    V = Hash::Sum(&h, empty());

    return hmacDRBG {
        newHMAC: hash,
        hK: h,
        V,
        reseedCounter: 1,
    };
}

// go: none — Go inlines this `switch s := s.(type)` twice, verbatim, in
// newDRBG. One helper keeps the two copies from drifting.
fn writePersonalization(h: &mut HMAC, s: &personalizationString, mut l: int) {
    match s {
        personalizationString::plain(p) => {
            let _ = io::Writer::Write(h, p.0.clone());
        }
        personalizationString::blockAligned(b) => {
            for (_, e) in crate::range!(&b.0) {
                pad000(h, l);
                let _ = io::Writer::Write(h, e.clone());
                l = e.Len();
            }
        }
        personalizationString::nil => {}
    }
}

// go: sdk 1.25.5 crypto/internal/fips140/ecdsa/hmacdrbg.go:120-127 TestingOnlyNewDRBG
/// Create an SP 800-90A Rev. 1 HMAC_DRBG with a plain personalization
/// string.
///
/// This should only be used for ACVP testing. hmacDRBG is not intended to
/// be used directly.
pub fn TestingOnlyNewDRBG(
    hash: impl IntoHashFunc,
    entropy: &slice<byte>,
    nonce: &slice<byte>,
    s: &slice<byte>,
) -> hmacDRBG {
    return newDRBG(
        hash,
        entropy,
        nonce,
        personalizationString::plain(plainPersonalizationString(s.clone())),
    );
}

// go: sdk 1.25.5 crypto/internal/fips140/ecdsa/hmacdrbg.go:129-134 pad000
fn pad000(h: &mut HMAC, writtenSoFar: int) {
    let blockSize = Hash::BlockSize(h);
    let rem = writtenSoFar % blockSize;
    if rem != 0 {
        let _ = io::Writer::Write(
            h,
            slice::__from_vec(alloc::vec![0u8; (blockSize - rem) as usize]),
        );
    }
}

impl hmacDRBG {
    // go: sdk 1.25.5 crypto/internal/fips140/ecdsa/hmacdrbg.go:136-175 hmacDRBG.Generate
    /// Produce at most maxRequestSize bytes of random data in out.
    pub(super) fn Generate(&mut self, out: &mut slice<byte>) {
        // HMAC_DRBG_Generate_algorithm, per Section 10.1.2.5.
        fips140::RecordApproved();

        if out.Len() as usize > maxRequestSize {
            panic!("ecdsa: internal error: request size exceeds maximum");
        }

        if self.reseedCounter > reseedInterval {
            panic!("ecdsa: reseed interval exceeded");
        }

        let outLen = out.Len() as usize;
        let mut tlen: usize = 0;
        while tlen < outLen {
            // V = HMAC_K(V)
            // T = T || V
            Hash::Reset(&mut self.hK);
            let _ = io::Writer::Write(&mut self.hK, self.V.clone());
            self.V = Hash::Sum(&self.hK, empty());
            let v: &[byte] = &self.V;
            let n = core::cmp::min(outLen - tlen, v.len());
            let o: &mut [byte] = out;
            o[tlen..tlen + n].copy_from_slice(&v[..n]);
            tlen += n;
        }

        // Note that if this function shows up on ECDSA-level profiles,
        // this can be optimized in the common case by deferring the rest
        // to the next Generate call, which will never come in nearly all
        // cases.

        // HMAC_DRBG_Update, per Section 10.1.2.2, without provided_data.
        // K = HMAC (K, V || 0x00)
        Hash::Reset(&mut self.hK);
        let _ = io::Writer::Write(&mut self.hK, self.V.clone());
        let _ = io::Writer::Write(&mut self.hK, slice::__from_vec(alloc::vec![0x00u8]));
        let K = Hash::Sum(&self.hK, empty());
        // V = HMAC (K, V)
        self.hK = hmac::New(self.newHMAC.clone(), K);
        let _ = io::Writer::Write(&mut self.hK, self.V.clone());
        self.V = Hash::Sum(&self.hK, empty());

        self.reseedCounter += 1;
    }
}

// go: none — Go writes `h.Sum(K[:0])`, reusing K's backing array as a
// zero-length destination. goish's `slice` does not expose that capacity
// trick, and Sum appends to whatever it is given, so an empty slice is
// the same result.
fn empty() -> slice<byte> {
    return slice::__from_vec(Vec::<byte>::new());
}
