// go: file crypto/internal/fips140/mlkem/mlkem768.go decls: DecapsulationKey768.Bytes, TestingOnlyExpandedBytes768, DecapsulationKey768.EncapsulationKey, EncapsulationKey768.Bytes, EncapsulationKey768.bytes, GenerateKey768, generateKey, GenerateKeyInternal768, NewDecapsulationKey768, newKeyFromSeed, TestingOnlyNewDecapsulationKey768, kemKeyGen, kemPCT, EncapsulationKey768.Encapsulate, EncapsulationKey768.encapsulate, EncapsulationKey768.EncapsulateInternal, kemEncaps, NewEncapsulationKey768, parseEK, pkeEncrypt, DecapsulationKey768.Decapsulate, kemDecaps, pkeDecrypt
//
// Package mlkem implements the quantum-resistant key encapsulation method
// ML-KEM (formerly known as Kyber), as specified in [NIST FIPS 203].
//
// [NIST FIPS 203]: https://doi.org/10.6028/NIST.FIPS.203
//
// This package targets security, correctness, simplicity, readability, and
// reviewability as its primary goals. All critical operations are performed
// in constant time.
//
// Variable and function names, as well as code layout, are selected to
// facilitate reviewing the implementation against the NIST FIPS 203
// document.
//
// Reviewers unfamiliar with polynomials or linear algebra might find the
// background at https://words.filippo.io/kyber-math/ useful.
//
// This file implements the recommended parameter set ML-KEM-768. The
// ML-KEM-1024 parameter set implementation is auto-generated from this file.
//
// Deviations from mlkem768[go] @ Go 1.25.5:
//
//   * Go embeds `encryptionKey` and `decryptionKey` in
//     DecapsulationKey768 and reaches their fields by promotion (`dk.s`,
//     `dk.t`, `dk.a`). Rust has no embedding, so they are named fields
//     and the accesses are spelled `dk.decryptionKey.s` and
//     `dk.encryptionKey.t`. The struct layout is otherwise Go's exactly
//     (AGENTS.md §5): no bundling, no renaming.
//   * `drbg.Read` is `crypto::rand::Read`. Go's drbg.Read branches on
//     `fips140.Enabled` and, when it is false, forwards verbatim to
//     `sysrand.Read`. goish has no GODEBUG and so no way to enable FIPS
//     mode, which makes that branch the only reachable one — this is the
//     reduction of Go's code under goish's configuration, not a
//     substitute algorithm. Porting drbg/rand.go properly needs
//     sync.Pool + crypto/internal/entropy + crypto/internal/sysrand.
//   * `fips140.PCT` / `RecordApproved` are goish's existing no-op stubs.

#![allow(non_snake_case, non_upper_case_globals, non_camel_case_types)]

extern crate alloc;
use alloc::boxed::Box;
use alloc::vec::Vec;

use crate::crypto::internal::fips140;
use crate::crypto::internal::fips140::sha3;
use crate::crypto::internal::fips140::subtle;
use crate::crypto::rand;
use crate::errors;
use crate::goslice::slice;
use crate::types::uint16;
use crate::{append, byte, error, int64};

use super::field::{
    inverseNTT, ntt, nttElement, nttMul, polyAdd, polyByteDecode, polyByteEncode, polySub,
    ringCompressAndEncode1, ringCompressAndEncode10, ringCompressAndEncode4,
    ringDecodeAndDecompress1, ringDecodeAndDecompress10, ringDecodeAndDecompress4, ringElement,
    sampleNTT, samplePolyCBD,
};

// Go: mlkem768.go:35-53 — ML-KEM global constants.
/// Go: `n = 256`
pub const n: usize = 256;
/// Go: `q = 3329`
pub const q: uint16 = 3329;

// encodingSizeX is the byte size of a ringElement or nttElement encoded
// by ByteEncode_X (FIPS 203, Algorithm 5).
/// Go: `encodingSize12 = n * 12 / 8`
pub const encodingSize12: usize = n * 12 / 8;
/// Go: `encodingSize11 = n * 11 / 8`
pub const encodingSize11: usize = n * 11 / 8;
/// Go: `encodingSize10 = n * 10 / 8`
pub const encodingSize10: usize = n * 10 / 8;
/// Go: `encodingSize5  = n * 5 / 8`
pub const encodingSize5: usize = n * 5 / 8;
/// Go: `encodingSize4  = n * 4 / 8`
pub const encodingSize4: usize = n * 4 / 8;
/// Go: `encodingSize1  = n * 1 / 8`
pub const encodingSize1: usize = n * 1 / 8;

/// Go: `messageSize = encodingSize1`
pub const messageSize: usize = encodingSize1;

/// Go: `SharedKeySize = 32`
pub const SharedKeySize: usize = 32;
/// Go: `SeedSize = 32 + 32`
pub const SeedSize: usize = 32 + 32;

// Go: mlkem768.go:55-62 — ML-KEM-768 parameters.
/// Go: `k = 3`
pub const k: usize = 3;
/// Go: `CiphertextSize768 = k*encodingSize10 + encodingSize4`
pub const CiphertextSize768: usize = k * encodingSize10 + encodingSize4;
/// Go: `EncapsulationKeySize768 = k*encodingSize12 + 32`
pub const EncapsulationKeySize768: usize = k * encodingSize12 + 32;
/// Go: `decapsulationKeySize768 = k*encodingSize12 + EncapsulationKeySize768 + 32 + 32`
pub const decapsulationKeySize768: usize = k * encodingSize12 + EncapsulationKeySize768 + 32 + 32;

// Go: mlkem768.go:64-70 — ML-KEM-1024 parameters.
/// Go: `k1024 = 4`
pub const k1024: usize = 4;
/// Go: `CiphertextSize1024 = k1024*encodingSize11 + encodingSize5`
pub const CiphertextSize1024: usize = k1024 * encodingSize11 + encodingSize5;
/// Go: `EncapsulationKeySize1024 = k1024*encodingSize12 + 32`
pub const EncapsulationKeySize1024: usize = k1024 * encodingSize12 + 32;
/// Go: `decapsulationKeySize1024 = k1024*encodingSize12 + EncapsulationKeySize1024 + 32 + 32`
pub const decapsulationKeySize1024: usize =
    k1024 * encodingSize12 + EncapsulationKeySize1024 + 32 + 32;

// Go: mlkem768.go:154-159
//   type encryptionKey struct { t [k]nttElement; a [k*k]nttElement }
/// The parsed and expanded form of a PKE encryption key.
#[derive(Clone, Copy)]
pub struct encryptionKey {
    /// Go: `t [k]nttElement // ByteDecode₁₂(ek[:384k])`
    pub t: [nttElement; k],
    /// Go: `a [k * k]nttElement // A[i*k+j] = sampleNTT(ρ, j, i)`
    pub a: [nttElement; k * k],
}

// Go: mlkem768.go:161-164
//   type decryptionKey struct { s [k]nttElement }
/// The parsed and expanded form of a PKE decryption key.
#[derive(Clone, Copy)]
pub struct decryptionKey {
    /// Go: `s [k]nttElement // ByteDecode₁₂(dk[:decryptionKeySize])`
    pub s: [nttElement; k],
}

// Go: mlkem768.go:72-83
//   type DecapsulationKey768 struct { d, z, ρ, h [32]byte; encryptionKey; decryptionKey }
/// The secret key used to decapsulate a shared key from a ciphertext. It
/// includes various precomputed values.
#[derive(Clone, Copy)]
pub struct DecapsulationKey768 {
    /// Go: `d [32]byte // decapsulation key seed`
    d: [byte; 32],
    /// Go: `z [32]byte // implicit rejection sampling seed`
    z: [byte; 32],
    /// Go: `ρ [32]byte // sampleNTT seed for A, stored for the encapsulation key`
    ρ: [byte; 32],
    /// Go: `h [32]byte // H(ek), stored for ML-KEM.Decaps_internal`
    h: [byte; 32],
    pub encryptionKey: encryptionKey,
    pub decryptionKey: decryptionKey,
}

// Go: mlkem768.go:132-138
//   type EncapsulationKey768 struct { ρ, h [32]byte; encryptionKey }
/// The public key used to produce ciphertexts to be decapsulated by the
/// corresponding [DecapsulationKey768].
#[derive(Clone, Copy)]
pub struct EncapsulationKey768 {
    /// Go: `ρ [32]byte // sampleNTT seed for A`
    ρ: [byte; 32],
    /// Go: `h [32]byte // H(ek)`
    h: [byte; 32],
    pub encryptionKey: encryptionKey,
}

// go: none — Go gets zero values from `&DecapsulationKey768{}`; Rust
// needs the zero polynomial spelled once for the array initialisers.
fn zeroNTT() -> nttElement {
    return nttElement([0; n]);
}

// go: none — Go's `&DecapsulationKey768{}` composite literal.
fn zeroDK() -> DecapsulationKey768 {
    return DecapsulationKey768 {
        d: [0; 32],
        z: [0; 32],
        ρ: [0; 32],
        h: [0; 32],
        encryptionKey: encryptionKey {
            t: [zeroNTT(); k],
            a: [zeroNTT(); k * k],
        },
        decryptionKey: decryptionKey { s: [zeroNTT(); k] },
    };
}

// go: none — Go's `&EncapsulationKey768{}` composite literal.
fn zeroEK() -> EncapsulationKey768 {
    return EncapsulationKey768 {
        ρ: [0; 32],
        h: [0; 32],
        encryptionKey: encryptionKey {
            t: [zeroNTT(); k],
            a: [zeroNTT(); k * k],
        },
    };
}

// go: none — Go writes `[]byte(nil)` / `make([]byte, 0, N)` at append
// sites; this is the empty-slice constructor for them.
fn empty() -> slice<byte> {
    return slice::__from_vec(Vec::new());
}

impl DecapsulationKey768 {
    // go: sdk 1.25.5 crypto/internal/fips140/mlkem/mlkem768.go:85-95 DecapsulationKey768.Bytes
    /// Return the decapsulation key as a 64-byte seed in the "d || z" form.
    ///
    /// The decapsulation key must be kept secret.
    pub fn Bytes(&self) -> slice<byte> {
        // Go: var b [SeedSize]byte; copy(b[:], dk.d[:]); copy(b[32:], dk.z[:])
        let mut b = [0u8; SeedSize];
        b[..32].copy_from_slice(&self.d);
        b[32..].copy_from_slice(&self.z);
        // Go: return b[:]
        return slice::__from_vec(b.to_vec());
    }

    // go: sdk 1.25.5 crypto/internal/fips140/mlkem/mlkem768.go:120-130 DecapsulationKey768.EncapsulationKey
    /// Return the public encapsulation key necessary to produce
    /// ciphertexts.
    pub fn EncapsulationKey(&self) -> EncapsulationKey768 {
        // Go: return &EncapsulationKey768{ρ: dk.ρ, h: dk.h,
        //                                 encryptionKey: dk.encryptionKey}
        return EncapsulationKey768 {
            ρ: self.ρ,
            h: self.h,
            encryptionKey: self.encryptionKey,
        };
    }

    // go: sdk 1.25.5 crypto/internal/fips140/mlkem/mlkem768.go:450-466 DecapsulationKey768.Decapsulate
    /// Generate a shared key from a ciphertext and a decapsulation key.
    /// If the ciphertext is not valid, Decapsulate returns an error.
    ///
    /// The shared key must be kept secret.
    pub fn Decapsulate(&self, ciphertext: slice<byte>) -> (slice<byte>, error) {
        // Go: if len(ciphertext) != CiphertextSize768 { return nil, errors.New(…) }
        if ciphertext.Len() != int64(CiphertextSize768) {
            return (empty(), errors::New("mlkem: invalid ciphertext length"));
        }
        // Go: c := (*[CiphertextSize768]byte)(ciphertext)
        let raw: &[byte] = &ciphertext;
        let mut c = [0u8; CiphertextSize768];
        c.copy_from_slice(raw);
        // Note that the hash check (step 3 of the decapsulation input check
        // from FIPS 203, Section 7.3) is foregone as a DecapsulationKey is
        // always validly generated by ML-KEM.KeyGen_internal.
        // Go: return kemDecaps(dk, c), nil
        return (kemDecaps(self, &c), crate::nil.into());
    }
}

// go: sdk 1.25.5 crypto/internal/fips140/mlkem/mlkem768.go:101-120 TestingOnlyExpandedBytes768
/// Return the decapsulation key as a byte slice using the full expanded
/// NIST encoding.
///
/// This should only be used for ACVP testing. For all other purposes
/// prefer the Bytes method that returns the (much smaller) seed.
pub fn TestingOnlyExpandedBytes768(dk: &DecapsulationKey768) -> slice<byte> {
    // Go: b := make([]byte, 0, decapsulationKeySize768)
    let mut b = empty();

    // ByteEncode₁₂(s)
    let mut i: usize = 0;
    while i < k {
        b = polyByteEncode(b, dk.decryptionKey.s[i]);
        i += 1;
    }

    // ByteEncode₁₂(t) || ρ
    let mut i: usize = 0;
    while i < k {
        b = polyByteEncode(b, dk.encryptionKey.t[i]);
        i += 1;
    }
    b = append!(b, slice::__from_vec(dk.ρ.to_vec())...);

    // H(ek) || z
    b = append!(b, slice::__from_vec(dk.h.to_vec())...);
    b = append!(b, slice::__from_vec(dk.z.to_vec())...);

    return b;
}

impl EncapsulationKey768 {
    // go: sdk 1.25.5 crypto/internal/fips140/mlkem/mlkem768.go:140-145 EncapsulationKey768.Bytes
    /// Return the encapsulation key as a byte slice.
    pub fn Bytes(&self) -> slice<byte> {
        // The actual logic is in a separate function to outline this allocation.
        // Go: b := make([]byte, 0, EncapsulationKeySize768); return ek.bytes(b)
        return self.bytes(empty());
    }

    // go: sdk 1.25.5 crypto/internal/fips140/mlkem/mlkem768.go:147-154 EncapsulationKey768.bytes
    fn bytes(&self, b: slice<byte>) -> slice<byte> {
        // Go: for i := range ek.t { b = polyByteEncode(b, ek.t[i]) }
        let mut b = b;
        let mut i: usize = 0;
        while i < k {
            b = polyByteEncode(b, self.encryptionKey.t[i]);
            i += 1;
        }
        // Go: b = append(b, ek.ρ[:]...)
        b = append!(b, slice::__from_vec(self.ρ.to_vec())...);
        return b;
    }

    // go: sdk 1.25.5 crypto/internal/fips140/mlkem/mlkem768.go:329-337 EncapsulationKey768.Encapsulate
    /// Generate a shared key and an associated ciphertext from an
    /// encapsulation key, drawing random bytes from a DRBG.
    ///
    /// The shared key must be kept secret.
    pub fn Encapsulate(&self) -> (slice<byte>, slice<byte>) {
        // The actual logic is in a separate function to outline this allocation.
        // Go: var cc [CiphertextSize768]byte; return ek.encapsulate(&cc)
        let mut cc = [0u8; CiphertextSize768];
        return self.encapsulate(&mut cc);
    }

    // go: sdk 1.25.5 crypto/internal/fips140/mlkem/mlkem768.go:339-347 EncapsulationKey768.encapsulate
    fn encapsulate(&self, cc: &mut [byte; CiphertextSize768]) -> (slice<byte>, slice<byte>) {
        // Go: var m [messageSize]byte; drbg.Read(m[:])
        let mut m = [0u8; messageSize];
        let mut mb = slice::__from_vec(m.to_vec());
        let _ = rand::Read(&mut mb);
        let mr: &[byte] = &mb;
        m.copy_from_slice(mr);
        // Note that the modulus check (step 2 of the encapsulation key check
        // from FIPS 203, Section 7.2) is performed by polyByteDecode in parseEK.
        fips140::RecordApproved();
        // Go: return kemEncaps(cc, ek, &m)
        return kemEncaps(cc, self, &m);
    }

    // go: sdk 1.25.5 crypto/internal/fips140/mlkem/mlkem768.go:349-355 EncapsulationKey768.EncapsulateInternal
    /// A derandomized version of Encapsulate, exclusively for use in tests.
    pub fn EncapsulateInternal(&self, m: &[byte; 32]) -> (slice<byte>, slice<byte>) {
        // Go: cc := &[CiphertextSize768]byte{}; return kemEncaps(cc, ek, m)
        let mut cc = [0u8; CiphertextSize768];
        return kemEncaps(&mut cc, self, m);
    }
}

// go: sdk 1.25.5 crypto/internal/fips140/mlkem/mlkem768.go:166-172 GenerateKey768
/// Generate a new decapsulation key, drawing random bytes from a DRBG.
/// The decapsulation key must be kept secret.
pub fn GenerateKey768() -> (Box<DecapsulationKey768>, error) {
    // The actual logic is in a separate function to outline this allocation.
    // Go: dk := &DecapsulationKey768{}; return generateKey(dk)
    let dk = Box::new(zeroDK());
    return generateKey(dk);
}

// go: sdk 1.25.5 crypto/internal/fips140/mlkem/mlkem768.go:174-185 generateKey
fn generateKey(dk: Box<DecapsulationKey768>) -> (Box<DecapsulationKey768>, error) {
    // Go: var d [32]byte; drbg.Read(d[:]); var z [32]byte; drbg.Read(z[:])
    let mut dk = dk;
    let d = randomSeed();
    let z = randomSeed();
    // Go: kemKeyGen(dk, &d, &z)
    kemKeyGen(&mut dk, &d, &z);
    // Go: fips140.PCT("ML-KEM PCT", func() error { return kemPCT(dk) })
    //
    // The closure must stay lazy: PCT returns without calling it when FIPS
    // mode is off, and a full encapsulate+decapsulate round trip is not
    // something to run on every key generation by accident.
    fips140::PCT("ML-KEM PCT", || kemPCT(&dk));
    // Go: fips140.RecordApproved(); return dk, nil
    fips140::RecordApproved();
    return (dk, crate::nil.into());
}

// go: none — Go writes `var d [32]byte; drbg.Read(d[:])` inline at three
// call sites; this is that pair, with drbg.Read reduced to
// crypto/rand.Read as the file header explains.
fn randomSeed() -> [byte; 32] {
    let mut b = slice::__from_vec(alloc::vec![0u8; 32]);
    let _ = rand::Read(&mut b);
    let r: &[byte] = &b;
    let mut out = [0u8; 32];
    out.copy_from_slice(r);
    return out;
}

// go: sdk 1.25.5 crypto/internal/fips140/mlkem/mlkem768.go:187-193 GenerateKeyInternal768
/// A derandomized version of GenerateKey768, exclusively for use in tests.
pub fn GenerateKeyInternal768(d: &[byte; 32], z: &[byte; 32]) -> Box<DecapsulationKey768> {
    // Go: dk := &DecapsulationKey768{}; kemKeyGen(dk, d, z); return dk
    let mut dk = Box::new(zeroDK());
    kemKeyGen(&mut dk, d, z);
    return dk;
}

// go: sdk 1.25.5 crypto/internal/fips140/mlkem/mlkem768.go:195-199 NewDecapsulationKey768
/// Parse a decapsulation key from a 64-byte seed in the "d || z" form.
/// The seed must be uniformly random.
pub fn NewDecapsulationKey768(seed: slice<byte>) -> (Box<DecapsulationKey768>, error) {
    // The actual logic is in a separate function to outline this allocation.
    // Go: dk := &DecapsulationKey768{}; return newKeyFromSeed(dk, seed)
    let dk = Box::new(zeroDK());
    return newKeyFromSeed(dk, seed);
}

// go: sdk 1.25.5 crypto/internal/fips140/mlkem/mlkem768.go:201-210 newKeyFromSeed
fn newKeyFromSeed(
    dk: Box<DecapsulationKey768>,
    seed: slice<byte>,
) -> (Box<DecapsulationKey768>, error) {
    // Go: if len(seed) != SeedSize { return nil, errors.New("mlkem: invalid seed length") }
    if seed.Len() != int64(SeedSize) {
        return (
            Box::new(zeroDK()),
            errors::New("mlkem: invalid seed length"),
        );
    }
    let mut dk = dk;
    // Go: d := (*[32]byte)(seed[:32]); z := (*[32]byte)(seed[32:])
    let raw: &[byte] = &seed;
    let mut d = [0u8; 32];
    d.copy_from_slice(&raw[..32]);
    let mut z = [0u8; 32];
    z.copy_from_slice(&raw[32..]);
    // Go: kemKeyGen(dk, d, z); fips140.RecordApproved(); return dk, nil
    kemKeyGen(&mut dk, &d, &z);
    fips140::RecordApproved();
    return (dk, crate::nil.into());
}

// go: sdk 1.25.5 crypto/internal/fips140/mlkem/mlkem768.go:212-262 TestingOnlyNewDecapsulationKey768
/// Parse a decapsulation key from its expanded NIST format.
///
/// Bytes() must not be called on the returned key, as it will not produce
/// the original seed.
///
/// This function should only be used for ACVP testing. Prefer
/// NewDecapsulationKey768 for all other purposes.
pub fn TestingOnlyNewDecapsulationKey768(b: slice<byte>) -> (Box<DecapsulationKey768>, error) {
    // Go: if len(b) != decapsulationKeySize768 { return nil, errors.New(…) }
    if b.Len() != int64(decapsulationKeySize768) {
        return (
            Box::new(zeroDK()),
            errors::New("mlkem: invalid NIST decapsulation key length"),
        );
    }

    // Go: dk := &DecapsulationKey768{}
    let mut dk = Box::new(zeroDK());
    let raw: &[byte] = &b;
    let mut p: usize = 0;
    // Go: for i := range dk.s { dk.s[i], err = polyByteDecode[nttElement](b[:encodingSize12]) … }
    let mut i: usize = 0;
    while i < k {
        let chunk = slice::__from_vec(raw[p..p + encodingSize12].to_vec());
        let (v, err) = polyByteDecode::<nttElement>(chunk);
        if err != crate::nil {
            return (
                Box::new(zeroDK()),
                errors::New("mlkem: invalid secret key encoding"),
            );
        }
        dk.decryptionKey.s[i] = v;
        p += encodingSize12;
        i += 1;
    }

    // Go: ek, err := NewEncapsulationKey768(b[:EncapsulationKeySize768])
    let (ek, err) = NewEncapsulationKey768(slice::__from_vec(
        raw[p..p + EncapsulationKeySize768].to_vec(),
    ));
    if err != crate::nil {
        return (Box::new(zeroDK()), err);
    }
    // Go: dk.ρ = ek.ρ; dk.h = ek.h; dk.encryptionKey = ek.encryptionKey
    dk.ρ = ek.ρ;
    dk.h = ek.h;
    dk.encryptionKey = ek.encryptionKey;
    p += EncapsulationKeySize768;

    // Go: if !bytes.Equal(dk.h[:], b[:32]) { return nil, errors.New(…) }
    if dk.h[..] != raw[p..p + 32] {
        return (
            Box::new(zeroDK()),
            errors::New("mlkem: inconsistent H(ek) in encoded bytes"),
        );
    }
    p += 32;

    // Go: copy(dk.z[:], b)
    dk.z.copy_from_slice(&raw[p..p + 32]);

    // Generate a random d value for use in Bytes(). This is a safety
    // mechanism that avoids returning a broken key vs a random key if this
    // function is called in contravention of the
    // TestingOnlyNewDecapsulationKey768 function comment advising against it.
    // Go: drbg.Read(dk.d[:])
    dk.d = randomSeed();

    return (dk, crate::nil.into());
}

// go: sdk 1.25.5 crypto/internal/fips140/mlkem/mlkem768.go:264-306 kemKeyGen
/// Generate a decapsulation key.
///
/// It implements ML-KEM.KeyGen_internal according to FIPS 203,
/// Algorithm 16, and K-PKE.KeyGen according to FIPS 203, Algorithm 13.
/// The two are merged to save copies and allocations.
fn kemKeyGen(dk: &mut DecapsulationKey768, d: &[byte; 32], z: &[byte; 32]) {
    // Go: dk.d = *d; dk.z = *z
    dk.d = *d;
    dk.z = *z;

    // Go: g := sha3.New512(); g.Write(d[:]); g.Write([]byte{k})
    let mut g = sha3::New512();
    let _ = g.Write(slice::__from_vec(d.to_vec()));
    // Module dimension as a domain separator.
    let _ = g.Write(slice::__from_vec(alloc::vec![byte(k)]));
    // Go: G := g.Sum(make([]byte, 0, 64)); ρ, σ := G[:32], G[32:]
    let G = g.Sum(empty());
    let Graw: &[byte] = &G;
    let ρ: &[byte] = &Graw[..32];
    let σ: &[byte] = &Graw[32..];
    // Go: dk.ρ = [32]byte(ρ)
    dk.ρ.copy_from_slice(ρ);

    // Go: A := &dk.a
    //     for i := byte(0); i < k; i++ { for j := byte(0); j < k; j++ {
    //         A[i*k+j] = sampleNTT(ρ, j, i) } }
    let mut i: usize = 0;
    while i < k {
        let mut j: usize = 0;
        while j < k {
            dk.encryptionKey.a[i * k + j] = sampleNTT(ρ, byte(j), byte(i));
            j += 1;
        }
        i += 1;
    }

    // Go: var N byte; s := &dk.s
    //     for i := range s { s[i] = ntt(samplePolyCBD(σ, N)); N++ }
    let mut N: byte = 0;
    let mut i: usize = 0;
    while i < k {
        dk.decryptionKey.s[i] = ntt(samplePolyCBD(σ, N));
        N += 1;
        i += 1;
    }
    // Go: e := make([]nttElement, k)
    //     for i := range e { e[i] = ntt(samplePolyCBD(σ, N)); N++ }
    let mut e = [zeroNTT(); k];
    let mut i: usize = 0;
    while i < k {
        e[i] = ntt(samplePolyCBD(σ, N));
        N += 1;
        i += 1;
    }

    // Go: t := &dk.t
    //     for i := range t { t[i] = e[i]; for j := range s {
    //         t[i] = polyAdd(t[i], nttMul(A[i*k+j], s[j])) } }
    let mut i: usize = 0;
    while i < k {
        // t = A ◦ s + e
        dk.encryptionKey.t[i] = e[i];
        let mut j: usize = 0;
        while j < k {
            dk.encryptionKey.t[i] = polyAdd(
                dk.encryptionKey.t[i],
                nttMul(dk.encryptionKey.a[i * k + j], dk.decryptionKey.s[j]),
            );
            j += 1;
        }
        i += 1;
    }

    // Go: H := sha3.New256(); ek := dk.EncapsulationKey().Bytes()
    //     H.Write(ek); H.Sum(dk.h[:0])
    let mut H = sha3::New256();
    let ek = dk.EncapsulationKey().Bytes();
    let _ = H.Write(ek);
    let sum = H.Sum(empty());
    let sr: &[byte] = &sum;
    dk.h.copy_from_slice(&sr[..32]);
}

// go: sdk 1.25.5 crypto/internal/fips140/mlkem/mlkem768.go:306-326 kemPCT
/// Perform a Pairwise Consistency Test per FIPS 140-3 IG 10.3.A
/// Additional Comment 1: "For key pairs generated for use with approved
/// KEMs in FIPS 203, the PCT shall consist of applying the encapsulation
/// key ek to encapsulate a shared secret K leading to ciphertext c, and
/// then applying decapsulation key dk to retrieve the same shared secret
/// K. The PCT passes if the two shared secret K values are equal. The PCT
/// shall be performed either when keys are generated/imported, prior to
/// the first exportation, or prior to the first operational use (if not
/// exported before the first use)."
///
fn kemPCT(dk: &DecapsulationKey768) -> error {
    // Go: ek := dk.EncapsulationKey(); K, c := ek.Encapsulate()
    let ek = dk.EncapsulationKey();
    let (K, c) = ek.Encapsulate();
    // Go: K1, err := dk.Decapsulate(c); if err != nil { return err }
    let (K1, err) = dk.Decapsulate(c);
    if err != crate::nil {
        return err;
    }
    // Go: if subtle.ConstantTimeCompare(K, K1) != 1 { return errors.New("mlkem: PCT failed") }
    if subtle::ConstantTimeCompare(&K, &K1) != 1 {
        return errors::New("mlkem: PCT failed");
    }
    // Go: return nil
    return crate::nil.into();
}

// go: sdk 1.25.5 crypto/internal/fips140/mlkem/mlkem768.go:357-368 kemEncaps
/// Generate a shared key and an associated ciphertext.
///
/// It implements ML-KEM.Encaps_internal according to FIPS 203,
/// Algorithm 17.
fn kemEncaps(
    cc: &mut [byte; CiphertextSize768],
    ek: &EncapsulationKey768,
    m: &[byte; messageSize],
) -> (slice<byte>, slice<byte>) {
    // Go: g := sha3.New512(); g.Write(m[:]); g.Write(ek.h[:]); G := g.Sum(nil)
    let mut g = sha3::New512();
    let _ = g.Write(slice::__from_vec(m.to_vec()));
    let _ = g.Write(slice::__from_vec(ek.h.to_vec()));
    let G = g.Sum(empty());
    let Graw: &[byte] = &G;
    // Go: K, r := G[:SharedKeySize], G[SharedKeySize:]
    let K = slice::__from_vec(Graw[..SharedKeySize].to_vec());
    let r: &[byte] = &Graw[SharedKeySize..];
    // Go: c = pkeEncrypt(cc, &ek.encryptionKey, m, r); return K, c
    let c = pkeEncrypt(cc, &ek.encryptionKey, m, r);
    return (K, c);
}

// go: sdk 1.25.5 crypto/internal/fips140/mlkem/mlkem768.go:370-376 NewEncapsulationKey768
/// Parse an encapsulation key from its encoded form. If the encapsulation
/// key is not valid, NewEncapsulationKey768 returns an error.
pub fn NewEncapsulationKey768(encapsulationKey: slice<byte>) -> (EncapsulationKey768, error) {
    // The actual logic is in a separate function to outline this allocation.
    // Go: ek := &EncapsulationKey768{}; return parseEK(ek, encapsulationKey)
    let ek = zeroEK();
    return parseEK(ek, encapsulationKey);
}

// go: sdk 1.25.5 crypto/internal/fips140/mlkem/mlkem768.go:378-408 parseEK
/// Parse an encryption key from its encoded form.
///
/// It implements the initial stages of K-PKE.Encrypt according to
/// FIPS 203, Algorithm 14.
fn parseEK(ek: EncapsulationKey768, ekPKE: slice<byte>) -> (EncapsulationKey768, error) {
    // Go: if len(ekPKE) != EncapsulationKeySize768 { return nil, errors.New(…) }
    if ekPKE.Len() != int64(EncapsulationKeySize768) {
        return (
            zeroEK(),
            errors::New("mlkem: invalid encapsulation key length"),
        );
    }
    let mut ek = ek;

    // Go: h := sha3.New256(); h.Write(ekPKE); h.Sum(ek.h[:0])
    let mut h = sha3::New256();
    let _ = h.Write(ekPKE.clone());
    let sum = h.Sum(empty());
    let sr: &[byte] = &sum;
    ek.h.copy_from_slice(&sr[..32]);

    // Go: for i := range ek.t { ek.t[i], err = polyByteDecode[nttElement](ekPKE[:encodingSize12]) … }
    let raw: &[byte] = &ekPKE;
    let mut p: usize = 0;
    let mut i: usize = 0;
    while i < k {
        let chunk = slice::__from_vec(raw[p..p + encodingSize12].to_vec());
        let (v, err) = polyByteDecode::<nttElement>(chunk);
        if err != crate::nil {
            return (zeroEK(), err);
        }
        ek.encryptionKey.t[i] = v;
        p += encodingSize12;
        i += 1;
    }
    // Go: copy(ek.ρ[:], ekPKE)
    ek.ρ.copy_from_slice(&raw[p..p + 32]);

    // Go: for i := byte(0); i < k; i++ { for j := byte(0); j < k; j++ {
    //         ek.a[i*k+j] = sampleNTT(ek.ρ[:], j, i) } }
    let ρ = ek.ρ;
    let mut i: usize = 0;
    while i < k {
        let mut j: usize = 0;
        while j < k {
            ek.encryptionKey.a[i * k + j] = sampleNTT(&ρ, byte(j), byte(i));
            j += 1;
        }
        i += 1;
    }

    return (ek, crate::nil.into());
}

// go: sdk 1.25.5 crypto/internal/fips140/mlkem/mlkem768.go:410-448 pkeEncrypt
/// Encrypt a plaintext message.
///
/// It implements K-PKE.Encrypt according to FIPS 203, Algorithm 14,
/// although the computation of t and AT is done in parseEK.
fn pkeEncrypt(
    cc: &mut [byte; CiphertextSize768],
    ex: &encryptionKey,
    m: &[byte; messageSize],
    rnd: &[byte],
) -> slice<byte> {
    // Go: var N byte; r, e1 := make([]nttElement, k), make([]ringElement, k)
    let mut N: byte = 0;
    let mut r = [zeroNTT(); k];
    let mut e1 = [ringElement([0; n]); k];
    // Go: for i := range r { r[i] = ntt(samplePolyCBD(rnd, N)); N++ }
    let mut i: usize = 0;
    while i < k {
        r[i] = ntt(samplePolyCBD(rnd, N));
        N += 1;
        i += 1;
    }
    // Go: for i := range e1 { e1[i] = samplePolyCBD(rnd, N); N++ }
    let mut i: usize = 0;
    while i < k {
        e1[i] = samplePolyCBD(rnd, N);
        N += 1;
        i += 1;
    }
    // Go: e2 := samplePolyCBD(rnd, N)
    let e2 = samplePolyCBD(rnd, N);

    // Go: u := make([]ringElement, k) // NTT⁻¹(AT ◦ r) + e1
    let mut u = [ringElement([0; n]); k];
    let mut i: usize = 0;
    while i < k {
        u[i] = e1[i];
        let mut j: usize = 0;
        while j < k {
            // Note that i and j are inverted, as we need the transposed of A.
            u[i] = polyAdd(u[i], inverseNTT(nttMul(ex.a[j * k + i], r[j])));
            j += 1;
        }
        i += 1;
    }

    // Go: μ := ringDecodeAndDecompress1(m)
    let μ = ringDecodeAndDecompress1(m);

    // Go: var vNTT nttElement // t⊺ ◦ r
    //     for i := range ex.t { vNTT = polyAdd(vNTT, nttMul(ex.t[i], r[i])) }
    let mut vNTT = zeroNTT();
    let mut i: usize = 0;
    while i < k {
        vNTT = polyAdd(vNTT, nttMul(ex.t[i], r[i]));
        i += 1;
    }
    // Go: v := polyAdd(polyAdd(inverseNTT(vNTT), e2), μ)
    let v = polyAdd(polyAdd(inverseNTT(vNTT), e2), μ);

    // Go: c := cc[:0]
    //     for _, f := range u { c = ringCompressAndEncode10(c, f) }
    //     c = ringCompressAndEncode4(c, v)
    let mut c = empty();
    let mut i: usize = 0;
    while i < k {
        c = ringCompressAndEncode10(c, u[i]);
        i += 1;
    }
    c = ringCompressAndEncode4(c, v);

    // Go writes through `cc[:0]`, so the caller's array holds the result;
    // goish's slices don't alias, so fill it explicitly.
    let cr: &[byte] = &c;
    cc.copy_from_slice(cr);
    return c;
}

// go: sdk 1.25.5 crypto/internal/fips140/mlkem/mlkem768.go:468-491 kemDecaps
/// Produce a shared key from a ciphertext.
///
/// It implements ML-KEM.Decaps_internal according to FIPS 203,
/// Algorithm 18.
fn kemDecaps(dk: &DecapsulationKey768, c: &[byte; CiphertextSize768]) -> slice<byte> {
    fips140::RecordApproved();
    // Go: m := pkeDecrypt(&dk.decryptionKey, c)
    let m = pkeDecrypt(&dk.decryptionKey, c);
    // Go: g := sha3.New512(); g.Write(m[:]); g.Write(dk.h[:])
    let mut g = sha3::New512();
    let _ = g.Write(m.clone());
    let _ = g.Write(slice::__from_vec(dk.h.to_vec()));
    // Go: G := g.Sum(make([]byte, 0, 64)); Kprime, r := G[:SharedKeySize], G[SharedKeySize:]
    let G = g.Sum(empty());
    let Graw: &[byte] = &G;
    let Kprime = slice::__from_vec(Graw[..SharedKeySize].to_vec());
    let r: &[byte] = &Graw[SharedKeySize..];
    // Go: J := sha3.NewShake256(); J.Write(dk.z[:]); J.Write(c[:])
    let mut J = sha3::NewShake256();
    let _ = J.Write(slice::__from_vec(dk.z.to_vec()));
    let _ = J.Write(slice::__from_vec(c.to_vec()));
    // Go: Kout := make([]byte, SharedKeySize); J.Read(Kout)
    let mut KoutV: Vec<byte> = alloc::vec![0u8; SharedKeySize];
    J.Read(&mut KoutV);
    let mut Kout = slice::__from_vec(KoutV);
    // Go: var cc [CiphertextSize768]byte
    //     c1 := pkeEncrypt(&cc, &dk.encryptionKey, (*[32]byte)(m), r)
    let mut cc = [0u8; CiphertextSize768];
    let mraw: &[byte] = &m;
    let mut m32 = [0u8; 32];
    m32.copy_from_slice(mraw);
    let c1 = pkeEncrypt(&mut cc, &dk.encryptionKey, &m32, r);

    // Go: subtle.ConstantTimeCopy(subtle.ConstantTimeCompare(c[:], c1), Kout, Kprime)
    let cs = slice::__from_vec(c.to_vec());
    subtle::ConstantTimeCopy(subtle::ConstantTimeCompare(&cs, &c1), &mut Kout, &Kprime);
    return Kout;
}

// go: sdk 1.25.5 crypto/internal/fips140/mlkem/mlkem768.go:493-510 pkeDecrypt
/// Decrypt a ciphertext.
///
/// It implements K-PKE.Decrypt according to FIPS 203, Algorithm 15,
/// although s is retained from kemKeyGen.
fn pkeDecrypt(dx: &decryptionKey, c: &[byte; CiphertextSize768]) -> slice<byte> {
    // Go: u := make([]ringElement, k)
    //     for i := range u { b := (*[encodingSize10]byte)(c[…]); u[i] = ringDecodeAndDecompress10(b) }
    let mut u = [ringElement([0; n]); k];
    let mut i: usize = 0;
    while i < k {
        let mut b = [0u8; encodingSize10];
        b.copy_from_slice(&c[encodingSize10 * i..encodingSize10 * (i + 1)]);
        u[i] = ringDecodeAndDecompress10(&b);
        i += 1;
    }

    // Go: b := (*[encodingSize4]byte)(c[encodingSize10*k:]); v := ringDecodeAndDecompress4(b)
    let mut b = [0u8; encodingSize4];
    b.copy_from_slice(&c[encodingSize10 * k..]);
    let v = ringDecodeAndDecompress4(&b);

    // Go: var mask nttElement // s⊺ ◦ NTT(u)
    //     for i := range dx.s { mask = polyAdd(mask, nttMul(dx.s[i], ntt(u[i]))) }
    let mut mask = zeroNTT();
    let mut i: usize = 0;
    while i < k {
        mask = polyAdd(mask, nttMul(dx.s[i], ntt(u[i])));
        i += 1;
    }
    // Go: w := polySub(v, inverseNTT(mask))
    let w = polySub(v, inverseNTT(mask));

    // Go: return ringCompressAndEncode1(nil, w)
    return ringCompressAndEncode1(empty(), w);
}
