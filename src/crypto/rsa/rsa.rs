// go: file crypto/rsa/rsa.go decls: PublicKey.Size, PublicKey.Equal, PrivateKey.Public, PrivateKey.Equal, bigIntEqual, PrivateKey.Sign, PrivateKey.Decrypt, PrivateKey.Validate, checkKeySize, checkPublicKeySize, GenerateKey, GenerateMultiPrimeKey, PrivateKey.Precompute, PrivateKey.precompute, PrivateKey.precomputeLegacy, fipsPublicKey, fipsPrivateKey
//
// The PUBLIC `crypto/rsa` key types. Go keeps them built on `math/big`
// (`PublicKey{N *big.Int; E int}`) for backwards compatibility and does
// every actual RSA operation by converting into the FIPS-internal
// `crypto/internal/fips140/rsa` key types, whose modulus is a
// constant-time `bigmod.Modulus`. `fipsPublicKey` / `fipsPrivateKey` at
// the bottom of this file are that bridge.
//
// Deviations from rsa[go] @ Go 1.25.5:
//
//   * `crypto/internal/boring` and `crypto/internal/boring/bbig` do not
//     exist in goish — there is no cgo, so there is no BoringSSL. Every
//     `if boring.Enabled` branch is therefore absent rather than ported
//     as dead code; `notboring.rs` carries the two functions those
//     branches would have called, with Go's own panicking bodies.
//   * `PrecomputedValues` has no `fips *rsa.PrivateKey` field. It is
//     unexported in Go, and Rust struct literals must name every field,
//     so adding it would break `crypto/x509`'s
//     `PrecomputedValues{Dp, Dq, Qinv, CRTValues}` construction, which
//     Go can write because Go allows partial keyed literals. The field
//     is only a cache of the validated FIPS key: without it `Validate`
//     and `fipsPrivateKey` re-run `precompute` instead of reusing it.
//     Same results, more work per call.
//   * `PublicKey.Equal` / `PrivateKey.Equal` / `PrivateKey.Public` take
//     and return the concrete type instead of Go's `crypto.PublicKey`
//     (`any`). goish spells `crypto::PublicKey` as
//     `Arc<dyn Any + Send + Sync>`; the concrete signatures keep the
//     comma-ok type assertion out of every call site. The `crypto::Signer`
//     and `crypto::Decrypter` impls at the end of the file expose the
//     `any`-shaped versions Go's interfaces require.
//   * `bigOne` and `rsa1024min` are Go package-level `var`s holding
//     values goish cannot spell as a `const` (a heap-backed `big::Int`
//     and a `godebug.Setting` holding a `string`). Both are functions
//     that build the value on demand.
//   * `rsa1024min` reads `crypto/internal/fips140deps/godebug`, which
//     parses `$GODEBUG` on each call. Go's `internal/godebug` also
//     supports the `//go:debug` directive and an `IncNonDefault` metrics
//     counter; goish has neither, so `checkKeySize` skips the counter
//     bump. Setting `GODEBUG=rsa1024min=0` in the environment works.
//   * `fips140only.ApprovedRandomReader` wants
//     `&mut (dyn io::Reader + Send + Sync + 'static)`, but `crypto::Signer`
//     and `crypto::Decrypter` hand this package a bare
//     `&mut dyn io::Reader`, so widening every reader here would fork the
//     package's API away from the interfaces it must satisfy. The guard
//     is omitted; it is unreachable while `fips140only::Enabled` is
//     `const false`. The same reasoning omits `randutil::MaybeReadByte`.
//   * `GenerateMultiPrimeKey` handles `nprimes == 2` by delegating to
//     `GenerateKey`, as Go does, and errors for anything else: Go's
//     multi-prime loop needs `crypto/rand.Prime`, which goish does not
//     have. Multi-prime RSA is deprecated in Go for exactly the security,
//     compatibility and performance reasons its doc comment lists.
//   * `fipsPublicKey` / `fipsPrivateKey` return `Option<…>` where Go
//     returns a pointer that is nil on the error path.

#![allow(non_snake_case, non_upper_case_globals)]

extern crate alloc;

use alloc::vec::Vec;

use crate::crypto;
use crate::crypto::internal::fips140::bigmod::Modulus;
use crate::crypto::internal::fips140::rsa;
use crate::crypto::internal::fips140deps::godebug;
use crate::crypto::internal::fips140only;
use crate::crypto::subtle;
use crate::errors;
use crate::goslice::slice;
use crate::io;
use crate::math::big;
use crate::nilval::nil;
use crate::types::{byte, int};
use crate::error;

// go: none — Go's package-level `var bigOne = big.NewInt(1)`. A goish
// `big::Int` is heap-backed and cannot be a `const`, so the one value is
// built on demand at each read.
fn bigOne() -> big::Int {
    return big::NewInt(1);
}

// Go: rsa.go:68-71
//   type PublicKey struct { N *big.Int; E int }
/// A `PublicKey` represents the public part of an RSA key.
///
/// The values of `N` and `E` are not considered confidential, and may
/// leak through side channels, or could be mathematically derived from
/// other public values.
#[derive(Clone, Default)]
pub struct PublicKey {
    /// Modulus.
    pub N: big::Int,
    /// Public exponent.
    pub E: int,
}

// Polymorphic-nil for Go's `*rsa.PublicKey`: goish models the pointer as
// a value, so the nil pointer is the zero key.
impl PartialEq<crate::nilval::Nil> for PublicKey {
    // go: none — goish idiom: AGENTS.md §6 nilable-type impl.
    fn eq(&self, _: &crate::nilval::Nil) -> bool {
        return self.N == nil && self.E == 0;
    }
}
impl PartialEq<PublicKey> for crate::nilval::Nil {
    // go: none — goish idiom: AGENTS.md §6 nilable-type impl.
    fn eq(&self, other: &PublicKey) -> bool {
        return other.N == nil && other.E == 0;
    }
}
impl From<crate::nilval::Nil> for PublicKey {
    // go: none — goish idiom: AGENTS.md §6 nilable-type impl.
    fn from(_: crate::nilval::Nil) -> Self {
        return PublicKey::default();
    }
}

// Any methods implemented on PublicKey might need to also be implemented
// on PrivateKey, as the latter embeds the former and will expose its
// methods.
impl PublicKey {
    // go: sdk 1.25.5 crypto/rsa/rsa.go:78-80 PublicKey.Size
    /// Size returns the modulus size in bytes. Raw signatures and
    /// ciphertexts for or by this public key will have the same size.
    pub fn Size(&self) -> int {
        return (self.N.BitLen() + 7) / 8;
    }

    // go: sdk 1.25.5 crypto/rsa/rsa.go:83-89 PublicKey.Equal
    /// Equal reports whether `self` and `x` have the same value.
    ///
    /// Go takes `crypto.PublicKey` and type-asserts to `*PublicKey`,
    /// returning false on a miss; the concrete parameter makes the miss
    /// unrepresentable.
    pub fn Equal(&self, x: &PublicKey) -> bool {
        return bigIntEqual(&self.N, &x.N) && self.E == x.E;
    }
}

// Go: rsa.go:93-104
//   type OAEPOptions struct { Hash, MGFHash crypto.Hash; Label []byte }
/// `OAEPOptions` is an interface for passing options to OAEP decryption
/// using the `crypto.Decrypter` interface.
#[derive(Clone, Default)]
pub struct OAEPOptions {
    /// Hash is the hash function that will be used when generating the
    /// mask.
    pub Hash: crypto::Hash,
    /// MGFHash is the hash function used for MGF1. If zero, `Hash` is
    /// used instead.
    pub MGFHash: crypto::Hash,
    /// Label is an arbitrary byte string that must be equal to the value
    /// used when encrypting.
    pub Label: slice<byte>,
}

// Go: rsa.go:107-116
//   type PrivateKey struct { PublicKey; D *big.Int; Primes []*big.Int
//                            Precomputed PrecomputedValues }
/// A `PrivateKey` represents an RSA key.
///
/// Go embeds `PublicKey` anonymously; goish has no struct embedding, so
/// the public part is a field literally named `PublicKey`. Read it as
/// `priv.PublicKey.N` — Go's `priv.N` reaches the same field through
/// promotion.
#[derive(Clone, Default)]
pub struct PrivateKey {
    /// Public part of the key.
    pub PublicKey: PublicKey,
    /// Private exponent.
    pub D: big::Int,
    /// Prime factors of `N`; has >= 2 elements.
    pub Primes: slice<big::Int>,
    /// Precomputed contains precomputed values that speed up RSA
    /// operations, if available. It must be generated by calling
    /// `PrivateKey::Precompute` and must not be modified.
    pub Precomputed: PrecomputedValues,
}

// Go: rsa.go:201-217
//   type PrecomputedValues struct { Dp, Dq, Qinv *big.Int
//                                   CRTValues []CRTValue
//                                   fips *rsa.PrivateKey }
/// See the banner for why the unexported `fips` cache field is absent.
#[derive(Clone, Default)]
pub struct PrecomputedValues {
    /// `D mod (P-1)`.
    pub Dp: big::Int,
    /// `D mod (Q-1)`.
    pub Dq: big::Int,
    /// `Q⁻¹ mod P`.
    pub Qinv: big::Int,
    /// CRTValues is used for the 3rd and subsequent primes. Due to a
    /// historical accident, the CRT for the first two primes is handled
    /// differently in PKCS #1, and interoperability is sufficiently
    /// important that we mirror this.
    ///
    /// Deprecated: These values are still filled in by `Precompute` for
    /// backwards compatibility but are not used. Multi-prime RSA is very
    /// rare, and is implemented by this package without CRT optimizations
    /// to limit complexity.
    pub CRTValues: slice<CRTValue>,
}

// Go: rsa.go:220-224
//   type CRTValue struct { Exp, Coeff, R *big.Int }
/// `CRTValue` contains the precomputed Chinese remainder theorem values.
#[derive(Clone, Default)]
pub struct CRTValue {
    /// `D mod (prime-1)`.
    pub Exp: big::Int,
    /// `R·Coeff ≡ 1 mod Prime`.
    pub Coeff: big::Int,
    /// Product of primes prior to this (inc p and q).
    pub R: big::Int,
}

impl PrivateKey {
    // go: sdk 1.25.5 crypto/rsa/rsa.go:119-121 PrivateKey.Public
    /// Public returns the public key corresponding to `self`.
    pub fn Public(&self) -> PublicKey {
        return self.PublicKey.clone();
    }

    // go: sdk 1.25.5 crypto/rsa/rsa.go:125-142 PrivateKey.Equal
    /// Equal reports whether `self` and `x` have equivalent values. It
    /// ignores `Precomputed` values.
    pub fn Equal(&self, x: &PrivateKey) -> bool {
        if !self.PublicKey.Equal(&x.PublicKey) || !bigIntEqual(&self.D, &x.D) {
            return false;
        }
        if self.Primes.Len() != x.Primes.Len() {
            return false;
        }
        for (i, p) in crate::range!(self.Primes) {
            if !bigIntEqual(p, &x.Primes[i]) {
                return false;
            }
        }
        return true;
    }

    // go: sdk 1.25.5 crypto/rsa/rsa.go:158-164 PrivateKey.Sign
    /// Sign signs `digest` with `self`, reading randomness from `rand`.
    /// If `opts` is a [`PSSOptions`] then the PSS algorithm is used,
    /// otherwise PKCS #1 v1.5 is. `digest` must be the result of hashing
    /// the input message using `opts.HashFunc()`.
    ///
    /// This method implements `crypto::Signer`. Common uses should use
    /// the `Sign*` functions in this package directly.
    ///
    /// Go writes the dispatch as `opts.(*PSSOptions)`. `SignerOpts` is a
    /// `#[goish::interface]`, so the comma-ok assertion to a *concrete*
    /// type goes through the macro's `__goish_as_dyn_any` view and a
    /// `downcast_ref` — `cast!` only assertsion to other interfaces.
    pub fn Sign(
        &self,
        rand: &mut dyn io::Reader,
        digest: slice<byte>,
        opts: &dyn crypto::SignerOpts,
    ) -> (slice<byte>, error) {
        if let Some(anyOpts) = crypto::SignerOpts::__goish_as_dyn_any(opts) {
            if let Some(pssOpts) = anyOpts.downcast_ref::<super::fips::PSSOptions>() {
                return super::fips::SignPSS(rand, self, pssOpts.Hash, digest, Some(pssOpts));
            }
        }
        return super::fips::SignPKCS1v15(rand, self, opts.HashFunc(), digest);
    }

    // go: sdk 1.25.5 crypto/rsa/rsa.go:169-199 PrivateKey.Decrypt
    /// Decrypt decrypts `ciphertext` with `self`. If `opts` is nil or of
    /// type [`PKCS1v15DecryptOptions`](super::pkcs1v15::PKCS1v15DecryptOptions)
    /// then PKCS #1 v1.5 decryption is performed. Otherwise `opts` must
    /// have type [`OAEPOptions`] and OAEP decryption is done.
    pub fn Decrypt(
        &self,
        rand: &mut dyn io::Reader,
        ciphertext: slice<byte>,
        opts: Option<&crypto::DecrypterOpts>,
    ) -> (slice<byte>, error) {
        let opts = match opts {
            None => {
                return super::pkcs1v15::DecryptPKCS1v15(rand, self, ciphertext);
            }
            Some(o) => o,
        };

        if let Some(o) = opts.downcast_ref::<OAEPOptions>() {
            let mut hash = o.Hash.New();
            if o.MGFHash == crypto::Hash(0) {
                let mut mgfHash = o.Hash.New();
                return super::fips::decryptOAEP(
                    hash.as_mut(),
                    Some(mgfHash.as_mut()),
                    self,
                    ciphertext,
                    o.Label.clone(),
                );
            }
            let mut mgfHash = o.MGFHash.New();
            return super::fips::decryptOAEP(
                hash.as_mut(),
                Some(mgfHash.as_mut()),
                self,
                ciphertext,
                o.Label.clone(),
            );
        }

        if let Some(o) = opts.downcast_ref::<super::pkcs1v15::PKCS1v15DecryptOptions>() {
            let l = o.SessionKeyLen;
            if l > 0 {
                let mut plaintext: slice<byte> =
                    slice::__from_vec(alloc::vec![0u8; usize::try_from(l).unwrap_or(0)]);
                let (_, err) = io::ReadFull(rand, &mut plaintext);
                if err != nil {
                    return (slice::default(), err);
                }
                let err =
                    super::pkcs1v15::DecryptPKCS1v15SessionKey(rand, self, ciphertext, &mut plaintext);
                if err != nil {
                    return (slice::default(), err);
                }
                return (plaintext, nil.into());
            }
            return super::pkcs1v15::DecryptPKCS1v15(rand, self, ciphertext);
        }

        return (
            slice::default(),
            errors::New("crypto/rsa: invalid options for Decrypt"),
        );
    }

    // go: sdk 1.25.5 crypto/rsa/rsa.go:230-244 PrivateKey.Validate
    /// Validate performs basic sanity checks on the key. It returns nil
    /// if the key is valid, or else an error describing a problem.
    ///
    /// Go short-circuits when `Precomputed.fips` is set, because the key
    /// was then already validated by `rsa.NewPrivateKey`. Without that
    /// field (see the banner) `precompute` runs every time.
    pub fn Validate(&self) -> error {
        // We can operate on keys based on d alone, but it isn't possible
        // to encode with `crypto/x509.MarshalPKCS1PrivateKey`, which
        // unfortunately doesn't return an error.
        if self.Primes.Len() < 2 {
            return errors::New("crypto/rsa: missing primes");
        }
        let (_, err) = self.precompute();
        return err;
    }

    // go: sdk 1.25.5 crypto/rsa/rsa.go:507-519 PrivateKey.Precompute
    /// Precompute performs some calculations that speed up private key
    /// operations in the future. It is safe to run on non-validated
    /// private keys.
    pub fn Precompute(&mut self) {
        let (precomputed, err) = self.precompute();
        if err != nil {
            // We don't have a way to report errors, so just leave the key
            // unmodified. Validate will re-run precompute.
            return;
        }
        self.Precomputed = precomputed;
    }

    // go: sdk 1.25.5 crypto/rsa/rsa.go:521-567 PrivateKey.precompute
    fn precompute(&self) -> (PrecomputedValues, error) {
        let precomputed = PrecomputedValues::default();

        if self.PublicKey.N == nil {
            return (
                precomputed,
                errors::New("crypto/rsa: missing public modulus"),
            );
        }
        if self.D == nil {
            return (
                precomputed,
                errors::New("crypto/rsa: missing private exponent"),
            );
        }
        if self.Primes.Len() != 2 {
            return self.precomputeLegacy();
        }
        if self.Primes[0] == nil {
            return (precomputed, errors::New("crypto/rsa: prime P is nil"));
        }
        if self.Primes[1] == nil {
            return (precomputed, errors::New("crypto/rsa: prime Q is nil"));
        }

        // If the CRT values are already set, use them.
        if self.Precomputed.Dp != nil && self.Precomputed.Dq != nil && self.Precomputed.Qinv != nil
        {
            let (_, err) = rsa::NewPrivateKeyWithPrecomputation(
                self.PublicKey.N.Bytes(),
                self.PublicKey.E,
                self.D.Bytes(),
                self.Primes[0].Bytes(),
                self.Primes[1].Bytes(),
                self.Precomputed.Dp.Bytes(),
                self.Precomputed.Dq.Bytes(),
                self.Precomputed.Qinv.Bytes(),
            );
            if err != nil {
                return (precomputed, err);
            }
            let mut precomputed = self.Precomputed.clone();
            precomputed.CRTValues = slice::__from_vec(Vec::new());
            return (precomputed, nil.into());
        }

        let (k, err) = rsa::NewPrivateKey(
            self.PublicKey.N.Bytes(),
            self.PublicKey.E,
            self.D.Bytes(),
            self.Primes[0].Bytes(),
            self.Primes[1].Bytes(),
        );
        if err != nil {
            return (precomputed, err);
        }

        let mut precomputed = precomputed;
        let (_, _, _, _, _, dP, dQ, qInv) = k.Export();
        precomputed.Dp.SetBytes(dP);
        precomputed.Dq.SetBytes(dQ);
        precomputed.Qinv.SetBytes(qInv);
        precomputed.CRTValues = slice::__from_vec(Vec::new());
        return (precomputed, nil.into());
    }

    // go: sdk 1.25.5 crypto/rsa/rsa.go:569-622 PrivateKey.precomputeLegacy
    fn precomputeLegacy(&self) -> (PrecomputedValues, error) {
        let mut precomputed = PrecomputedValues::default();

        let (_, err) = rsa::NewPrivateKeyWithoutCRT(
            self.PublicKey.N.Bytes(),
            self.PublicKey.E,
            self.D.Bytes(),
        );
        if err != nil {
            return (precomputed, err);
        }

        if self.Primes.Len() < 2 {
            return (precomputed, nil.into());
        }

        // Ensure the Mod and ModInverse calls below don't panic.
        let one = bigOne();
        for (_, prime) in crate::range!(self.Primes) {
            if *prime == nil {
                return (
                    precomputed,
                    errors::New("crypto/rsa: prime factor is nil"),
                );
            }
            if prime.Cmp(&one) <= 0 {
                return (
                    precomputed,
                    errors::New("crypto/rsa: prime factor is <= 1"),
                );
            }
        }

        let mut pMinusOne = big::Int::new();
        pMinusOne.Sub(&self.Primes[0], &one);
        precomputed.Dp.Mod(&self.D, &pMinusOne);

        let mut qMinusOne = big::Int::new();
        qMinusOne.Sub(&self.Primes[1], &one);
        precomputed.Dq.Mod(&self.D, &qMinusOne);

        // Go's `ModInverse` returns nil when the inverse does not exist;
        // goish's leaves the receiver untouched, so a zero `Qinv` is the
        // same signal.
        precomputed.Qinv.ModInverse(&self.Primes[1], &self.Primes[0]);
        if precomputed.Qinv.Sign() == 0 {
            return (
                precomputed,
                errors::New("crypto/rsa: prime factors are not relatively prime"),
            );
        }

        let mut r = big::Int::new();
        r.Mul(&self.Primes[0], &self.Primes[1]);
        let mut crtValues: Vec<CRTValue> = Vec::new();
        for (i, prime) in crate::range!(self.Primes) {
            if i < 2 {
                continue;
            }
            let mut values = CRTValue::default();

            values.Exp.Sub(prime, &one);
            let primeMinusOne = values.Exp.clone();
            values.Exp.Mod(&self.D, &primeMinusOne);

            values.R.Set(&r);
            values.Coeff.ModInverse(&r, prime);
            if values.Coeff.Sign() == 0 {
                return (
                    precomputed,
                    errors::New("crypto/rsa: prime factors are not relatively prime"),
                );
            }

            let mut next = big::Int::new();
            next.Mul(&r, prime);
            r = next;
            crtValues.push(values);
        }
        precomputed.CRTValues = slice::__from_vec(crtValues);

        return (precomputed, nil.into());
    }
}

// go: sdk 1.25.5 crypto/rsa/rsa.go:146-148 bigIntEqual
/// bigIntEqual reports whether `a` and `b` are equal, leaking only their
/// bit length through timing side-channels.
fn bigIntEqual(a: &big::Int, b: &big::Int) -> bool {
    return subtle::ConstantTimeCompare(&a.Bytes(), &b.Bytes()) == 1;
}

// go: none — Go's package-level `var rsa1024min = godebug.New("rsa1024min")`.
// goish's `godebug::Setting` holds a `string` and cannot be a `const`, so
// the setting is constructed at each read; `Value()` re-parses `$GODEBUG`
// either way.
fn rsa1024min() -> godebug::Setting {
    return godebug::New("rsa1024min");
}

// go: sdk 1.25.5 crypto/rsa/rsa.go:250-259 checkKeySize
/// Reject keys below the 1024-bit minimum. `GODEBUG=rsa1024min=0`
/// suppresses the error; Go additionally bumps a non-default metrics
/// counter there, which goish's godebug shim does not carry.
pub(super) fn checkKeySize(size: int) -> error {
    if size >= 1024 {
        return nil.into();
    }
    if rsa1024min().Value() == "0" {
        return nil.into();
    }
    return crate::fmt::Errorf!(
        "crypto/rsa: %d-bit keys are insecure (see https://go.dev/pkg/crypto/rsa#hdr-Minimum_key_size)",
        size
    );
}

// go: sdk 1.25.5 crypto/rsa/rsa.go:261-266 checkPublicKeySize
pub(super) fn checkPublicKeySize(k: &PublicKey) -> error {
    if k.N == nil {
        return errors::New("crypto/rsa: missing public modulus");
    }
    return checkKeySize(k.N.BitLen());
}

// go: sdk 1.25.5 crypto/rsa/rsa.go:278-368 GenerateKey
/// GenerateKey generates a random RSA private key of the given bit size.
///
/// If `bits` is less than 1024, GenerateKey returns an error — see
/// [`checkKeySize`].
///
/// Most applications should use `crypto/rand`'s reader as `random`. Note
/// that the returned key does not depend deterministically on the bytes
/// read from `random`, and may change between calls and/or between
/// versions.
pub fn GenerateKey(random: &mut dyn io::Reader, bits: int) -> (PrivateKey, error) {
    let err = checkKeySize(bits);
    if err != nil {
        return (PrivateKey::default(), err);
    }

    if fips140only::Enabled && bits < 2048 {
        return (
            PrivateKey::default(),
            errors::New(
                "crypto/rsa: use of keys smaller than 2048 bits is not allowed in FIPS 140-only mode",
            ),
        );
    }
    if fips140only::Enabled && bits % 2 == 1 {
        return (
            PrivateKey::default(),
            errors::New(
                "crypto/rsa: use of keys with odd size is not allowed in FIPS 140-only mode",
            ),
        );
    }
    // Go's third guard here is `!fips140only.ApprovedRandomReader(random)`
    // — see the banner for why it is absent.

    let (mut k, mut err) = rsa::GenerateKey(random, bits);
    if bits < 256 && err != nil {
        // Toy-sized keys have a non-negligible chance of hitting two hard
        // failure cases: p == q and d <= 2^(nlen / 2).
        //
        // Since these are impossible to hit for real keys, we don't want
        // to make the production code path more complex and harder to
        // think about to handle them.
        //
        // Instead, just rerun the whole process a total of 8 times, which
        // brings the chance of failure for 32-bit keys down to the same as
        // for 256-bit keys.
        let mut i: int = 1;
        while i < 8 && err != nil {
            let (k2, err2) = rsa::GenerateKey(random, bits);
            k = k2;
            err = err2;
            i += 1;
        }
    }
    if err != nil {
        return (PrivateKey::default(), err);
    }

    let (N, e, d, p, q, dP, dQ, qInv) = k.Export();
    let mut nN = big::Int::new();
    nN.SetBytes(N);
    let mut dD = big::Int::new();
    dD.SetBytes(d);
    let mut pP = big::Int::new();
    pP.SetBytes(p);
    let mut qQ = big::Int::new();
    qQ.SetBytes(q);
    let mut dp = big::Int::new();
    dp.SetBytes(dP);
    let mut dq = big::Int::new();
    dq.SetBytes(dQ);
    let mut qinv = big::Int::new();
    qinv.SetBytes(qInv);

    let mut primes: Vec<big::Int> = Vec::with_capacity(2);
    primes.push(pP);
    primes.push(qQ);

    let key = PrivateKey {
        PublicKey: PublicKey { N: nN, E: e },
        D: dD,
        Primes: slice::__from_vec(primes),
        Precomputed: PrecomputedValues {
            Dp: dp,
            Dq: dq,
            Qinv: qinv,
            // non-nil, to match Precompute
            CRTValues: slice::__from_vec(Vec::new()),
        },
    };
    return (key, nil.into());
}

// go: sdk 1.25.5 crypto/rsa/rsa.go:389-490 GenerateMultiPrimeKey
/// GenerateMultiPrimeKey generates a multi-prime RSA keypair of the given
/// bit size and the given random source.
///
/// Deprecated: The use of this function with a number of primes different
/// from two is not recommended for security, compatibility and
/// performance reasons. Use [`GenerateKey`] instead. goish implements
/// only the `nprimes == 2` case — see the banner.
pub fn GenerateMultiPrimeKey(
    random: &mut dyn io::Reader,
    nprimes: int,
    bits: int,
) -> (PrivateKey, error) {
    if nprimes == 2 {
        return GenerateKey(random, bits);
    }
    if fips140only::Enabled {
        return (
            PrivateKey::default(),
            errors::New("crypto/rsa: multi-prime RSA is not allowed in FIPS 140-only mode"),
        );
    }
    if nprimes < 2 {
        return (
            PrivateKey::default(),
            errors::New("crypto/rsa: GenerateMultiPrimeKey: nprimes must be >= 2"),
        );
    }
    return (
        PrivateKey::default(),
        errors::New("crypto/rsa: multi-prime key generation is not implemented"),
    );
}

goish::var! {
    /// ErrMessageTooLong is returned when attempting to encrypt or sign a
    /// message which is too large for the size of the key. When using
    /// [`SignPSS`](super::fips::SignPSS), this can also be returned if
    /// the size of the salt is too large.
    pub ErrMessageTooLong: error = "crypto/rsa: message too long for RSA key size";

    /// ErrDecryption represents a failure to decrypt a message. It is
    /// deliberately vague to avoid adaptive attacks.
    pub ErrDecryption: error = "crypto/rsa: decryption error";

    /// ErrVerification represents a failure to verify a signature. It is
    /// deliberately vague to avoid adaptive attacks.
    pub ErrVerification: error = "crypto/rsa: verification error";
}

// go: sdk 1.25.5 crypto/rsa/rsa.go:624-630 fipsPublicKey
pub(super) fn fipsPublicKey(pub_: &PublicKey) -> (Option<rsa::PublicKey>, error) {
    let (N, err) = Modulus::NewModulus(pub_.N.Bytes());
    if err != nil {
        return (None, err);
    }
    return (
        Some(rsa::PublicKey {
            N: N,
            E: pub_.E,
        }),
        nil.into(),
    );
}

// go: sdk 1.25.5 crypto/rsa/rsa.go:632-641 fipsPrivateKey
/// Go returns the cached `priv.Precomputed.fips` when it is set; goish
/// has no such field (see the banner), so the FIPS key is rebuilt from
/// `precompute` on every call.
pub(super) fn fipsPrivateKey(priv_: &PrivateKey) -> (Option<rsa::PrivateKey>, error) {
    if priv_.PublicKey.N == nil {
        return (None, errors::New("crypto/rsa: missing public modulus"));
    }
    if priv_.D == nil {
        return (None, errors::New("crypto/rsa: missing private exponent"));
    }

    if priv_.Primes.Len() == 2 {
        if priv_.Precomputed.Dp != nil
            && priv_.Precomputed.Dq != nil
            && priv_.Precomputed.Qinv != nil
        {
            let (k, err) = rsa::NewPrivateKeyWithPrecomputation(
                priv_.PublicKey.N.Bytes(),
                priv_.PublicKey.E,
                priv_.D.Bytes(),
                priv_.Primes[0].Bytes(),
                priv_.Primes[1].Bytes(),
                priv_.Precomputed.Dp.Bytes(),
                priv_.Precomputed.Dq.Bytes(),
                priv_.Precomputed.Qinv.Bytes(),
            );
            if err != nil {
                return (None, err);
            }
            return (Some(k), nil.into());
        }
        let (k, err) = rsa::NewPrivateKey(
            priv_.PublicKey.N.Bytes(),
            priv_.PublicKey.E,
            priv_.D.Bytes(),
            priv_.Primes[0].Bytes(),
            priv_.Primes[1].Bytes(),
        );
        if err != nil {
            return (None, err);
        }
        return (Some(k), nil.into());
    }

    // Deprecated multi-prime (or d-only) key: the CRT-less FIPS key, which
    // is what `precomputeLegacy` builds.
    let (k, err) = rsa::NewPrivateKeyWithoutCRT(
        priv_.PublicKey.N.Bytes(),
        priv_.PublicKey.E,
        priv_.D.Bytes(),
    );
    if err != nil {
        return (None, err);
    }
    return (Some(k), nil.into());
}

impl crypto::Signer for PrivateKey {
    // go: none — goish idiom: Go's `*PrivateKey` satisfies `crypto.Signer`
    // with the single method above; the trait impl forwards to it and
    // widens the return to `crypto::PublicKey` (`Arc<dyn Any>`).
    fn Public(&self) -> crypto::PublicKey {
        return alloc::sync::Arc::new(self.PublicKey.clone());
    }

    // go: none — goish idiom: see Public.
    fn Sign(
        &self,
        rand: &mut dyn io::Reader,
        digest: slice<byte>,
        opts: &dyn crypto::SignerOpts,
    ) -> (slice<byte>, error) {
        return PrivateKey::Sign(self, rand, digest, opts);
    }
}

impl crypto::Decrypter for PrivateKey {
    // go: none — goish idiom: see the `crypto::Signer` impl.
    fn Public(&self) -> crypto::PublicKey {
        return alloc::sync::Arc::new(self.PublicKey.clone());
    }

    // go: none — goish idiom: see the `crypto::Signer` impl.
    fn Decrypt(
        &self,
        rand: &mut dyn io::Reader,
        msg: slice<byte>,
        opts: Option<&crypto::DecrypterOpts>,
    ) -> (slice<byte>, error) {
        return PrivateKey::Decrypt(self, rand, msg, opts);
    }
}
