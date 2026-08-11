// go: file crypto/mlkem/mlkem.go decls: GenerateKey768, NewDecapsulationKey768, DecapsulationKey768.Bytes, DecapsulationKey768.Decapsulate, DecapsulationKey768.EncapsulationKey, NewEncapsulationKey768, EncapsulationKey768.Bytes, EncapsulationKey768.Encapsulate, GenerateKey1024, NewDecapsulationKey1024, DecapsulationKey1024.Bytes, DecapsulationKey1024.Decapsulate, DecapsulationKey1024.EncapsulationKey, NewEncapsulationKey1024, EncapsulationKey1024.Bytes, EncapsulationKey1024.Encapsulate
//
// Package mlkem implements the quantum-resistant key encapsulation method
// ML-KEM (formerly known as Kyber), as specified in [NIST FIPS 203].
//
// Most applications should use the ML-KEM-768 parameter set, as
// implemented by [DecapsulationKey768] and [EncapsulationKey768].
//
// [NIST FIPS 203]: https://doi.org/10.6028/NIST.FIPS.203
//
// Deviations from mlkem[go] @ Go 1.25.5:
//
//   * Constructors returning `(*T, error)` return `(T, error)` with the
//     zero value on the error path, the shape used throughout the goish
//     crypto tree.
//   * Go wraps a `*mlkem.DecapsulationKey768`; the fips140 package hands
//     back a `Box<DecapsulationKey768>` (it is large and Go outlines its
//     allocation too), so the wrapper holds that box.

#![allow(non_snake_case)]

extern crate alloc;
use alloc::boxed::Box;

use crate::crypto::internal::fips140::mlkem;
use crate::error;
use crate::goslice::slice;
use crate::types::byte;

// Go: mlkem.go:16-34 — `const ( SharedKeySize = 32; … )`
/// The size of a shared key produced by ML-KEM.
pub const SharedKeySize: usize = 32;
/// The size of a seed used to generate a decapsulation key.
pub const SeedSize: usize = 64;
/// The size of a ciphertext produced by ML-KEM-768.
pub const CiphertextSize768: usize = 1088;
/// The size of an ML-KEM-768 encapsulation key.
pub const EncapsulationKeySize768: usize = 1184;
/// The size of a ciphertext produced by ML-KEM-1024.
pub const CiphertextSize1024: usize = 1568;
/// The size of an ML-KEM-1024 encapsulation key.
pub const EncapsulationKeySize1024: usize = 1568;

// Go: mlkem.go:36-40
//   type DecapsulationKey768 struct { key *mlkem.DecapsulationKey768 }
/// The secret key used to decapsulate a shared key from a ciphertext. It
/// includes various precomputed values.
pub struct DecapsulationKey768 {
    key: Box<mlkem::DecapsulationKey768>,
}

// go: sdk 1.25.5 crypto/mlkem/mlkem.go:42-51 GenerateKey768
/// Generate a new decapsulation key, drawing random bytes from the default
/// crypto/rand source. The decapsulation key must be kept secret.
pub fn GenerateKey768() -> (DecapsulationKey768, error) {
    let (key, err) = mlkem::GenerateKey768();
    if err != crate::nil {
        return (zero768(), err);
    }

    return (DecapsulationKey768 { key }, crate::nil.into());
}

// go: sdk 1.25.5 crypto/mlkem/mlkem.go:53-62 NewDecapsulationKey768
/// Expand a decapsulation key from a 64-byte seed in the "d || z" form.
/// The seed must be uniformly random.
pub fn NewDecapsulationKey768(seed: &slice<byte>) -> (DecapsulationKey768, error) {
    let (key, err) = mlkem::NewDecapsulationKey768(seed.clone());
    if err != crate::nil {
        return (zero768(), err);
    }

    return (DecapsulationKey768 { key }, crate::nil.into());
}

impl DecapsulationKey768 {
    // go: sdk 1.25.5 crypto/mlkem/mlkem.go:64-69 Bytes
    /// Return the decapsulation key as a 64-byte seed in the "d || z" form.
    ///
    /// The decapsulation key must be kept secret.
    pub fn Bytes(&self) -> slice<byte> {
        return self.key.Bytes();
    }

    // go: sdk 1.25.5 crypto/mlkem/mlkem.go:71-77 Decapsulate
    /// Generate a shared key from a ciphertext and a decapsulation key. If
    /// the ciphertext is not valid, Decapsulate returns an error.
    ///
    /// The shared key must be kept secret.
    pub fn Decapsulate(&self, ciphertext: &slice<byte>) -> (slice<byte>, error) {
        return self.key.Decapsulate(ciphertext.clone());
    }

    // go: sdk 1.25.5 crypto/mlkem/mlkem.go:79-83 EncapsulationKey
    /// Return the public encapsulation key necessary to produce ciphertexts.
    pub fn EncapsulationKey(&self) -> EncapsulationKey768 {
        return EncapsulationKey768 {
            key: self.key.EncapsulationKey(),
        };
    }
}

// Go: mlkem.go:85-89
//   type EncapsulationKey768 struct { key *mlkem.EncapsulationKey768 }
/// The public key used to produce ciphertexts to be decapsulated by the
/// corresponding DecapsulationKey768.
pub struct EncapsulationKey768 {
    key: mlkem::EncapsulationKey768,
}

// go: sdk 1.25.5 crypto/mlkem/mlkem.go:91-100 NewEncapsulationKey768
/// Parse an encapsulation key from its encoded form. If the encapsulation
/// key is not valid, NewEncapsulationKey768 returns an error.
pub fn NewEncapsulationKey768(encapsulationKey: &slice<byte>) -> (EncapsulationKey768, error) {
    let (key, err) = mlkem::NewEncapsulationKey768(encapsulationKey.clone());
    if err != crate::nil {
        return (EncapsulationKey768 { key }, err);
    }

    return (EncapsulationKey768 { key }, crate::nil.into());
}

impl EncapsulationKey768 {
    // go: sdk 1.25.5 crypto/mlkem/mlkem.go:102-105 Bytes
    /// Return the encapsulation key as a byte slice.
    pub fn Bytes(&self) -> slice<byte> {
        return self.key.Bytes();
    }

    // go: sdk 1.25.5 crypto/mlkem/mlkem.go:107-113 Encapsulate
    /// Generate a shared key and an associated ciphertext from an
    /// encapsulation key, drawing random bytes from the default crypto/rand
    /// source.
    ///
    /// The shared key must be kept secret.
    pub fn Encapsulate(&self) -> (slice<byte>, slice<byte>) {
        return self.key.Encapsulate();
    }
}

// Go: mlkem.go:115-119
//   type DecapsulationKey1024 struct { key *mlkem.DecapsulationKey1024 }
/// The secret key used to decapsulate a shared key from a ciphertext. It
/// includes various precomputed values.
pub struct DecapsulationKey1024 {
    key: Box<mlkem::DecapsulationKey1024>,
}

// go: sdk 1.25.5 crypto/mlkem/mlkem.go:121-130 GenerateKey1024
/// Generate a new decapsulation key, drawing random bytes from the default
/// crypto/rand source. The decapsulation key must be kept secret.
pub fn GenerateKey1024() -> (DecapsulationKey1024, error) {
    let (key, err) = mlkem::GenerateKey1024();
    if err != crate::nil {
        return (zero1024(), err);
    }

    return (DecapsulationKey1024 { key }, crate::nil.into());
}

// go: sdk 1.25.5 crypto/mlkem/mlkem.go:132-141 NewDecapsulationKey1024
/// Expand a decapsulation key from a 64-byte seed in the "d || z" form.
/// The seed must be uniformly random.
pub fn NewDecapsulationKey1024(seed: &slice<byte>) -> (DecapsulationKey1024, error) {
    let (key, err) = mlkem::NewDecapsulationKey1024(seed.clone());
    if err != crate::nil {
        return (zero1024(), err);
    }

    return (DecapsulationKey1024 { key }, crate::nil.into());
}

impl DecapsulationKey1024 {
    // go: sdk 1.25.5 crypto/mlkem/mlkem.go:143-148 Bytes
    /// Return the decapsulation key as a 64-byte seed in the "d || z" form.
    ///
    /// The decapsulation key must be kept secret.
    pub fn Bytes(&self) -> slice<byte> {
        return self.key.Bytes();
    }

    // go: sdk 1.25.5 crypto/mlkem/mlkem.go:150-156 Decapsulate
    /// Generate a shared key from a ciphertext and a decapsulation key. If
    /// the ciphertext is not valid, Decapsulate returns an error.
    ///
    /// The shared key must be kept secret.
    pub fn Decapsulate(&self, ciphertext: &slice<byte>) -> (slice<byte>, error) {
        return self.key.Decapsulate(ciphertext.clone());
    }

    // go: sdk 1.25.5 crypto/mlkem/mlkem.go:158-162 EncapsulationKey
    /// Return the public encapsulation key necessary to produce ciphertexts.
    pub fn EncapsulationKey(&self) -> EncapsulationKey1024 {
        return EncapsulationKey1024 {
            key: self.key.EncapsulationKey(),
        };
    }
}

// Go: mlkem.go:164-168
//   type EncapsulationKey1024 struct { key *mlkem.EncapsulationKey1024 }
/// The public key used to produce ciphertexts to be decapsulated by the
/// corresponding DecapsulationKey1024.
pub struct EncapsulationKey1024 {
    key: mlkem::EncapsulationKey1024,
}

// go: sdk 1.25.5 crypto/mlkem/mlkem.go:170-179 NewEncapsulationKey1024
/// Parse an encapsulation key from its encoded form. If the encapsulation
/// key is not valid, NewEncapsulationKey1024 returns an error.
pub fn NewEncapsulationKey1024(encapsulationKey: &slice<byte>) -> (EncapsulationKey1024, error) {
    let (key, err) = mlkem::NewEncapsulationKey1024(encapsulationKey.clone());
    if err != crate::nil {
        return (EncapsulationKey1024 { key }, err);
    }

    return (EncapsulationKey1024 { key }, crate::nil.into());
}

impl EncapsulationKey1024 {
    // go: sdk 1.25.5 crypto/mlkem/mlkem.go:181-184 Bytes
    /// Return the encapsulation key as a byte slice.
    pub fn Bytes(&self) -> slice<byte> {
        return self.key.Bytes();
    }

    // go: sdk 1.25.5 crypto/mlkem/mlkem.go:186-192 Encapsulate
    /// Generate a shared key and an associated ciphertext from an
    /// encapsulation key, drawing random bytes from the default crypto/rand
    /// source.
    ///
    /// The shared key must be kept secret.
    pub fn Encapsulate(&self) -> (slice<byte>, slice<byte>) {
        return self.key.Encapsulate();
    }
}

// go: none — Go returns a nil *DecapsulationKey768 on the error paths;
// goish returns a value, so the error paths need a zero one.
fn zero768() -> DecapsulationKey768 {
    let (key, _) = mlkem::NewDecapsulationKey768(slice::__from_vec(alloc::vec![
        0u8;
        SeedSize
    ]));
    return DecapsulationKey768 { key };
}

// go: none — the same, for *DecapsulationKey1024.
fn zero1024() -> DecapsulationKey1024 {
    let (key, _) = mlkem::NewDecapsulationKey1024(slice::__from_vec(alloc::vec![
        0u8;
        SeedSize
    ]));
    return DecapsulationKey1024 { key };
}
