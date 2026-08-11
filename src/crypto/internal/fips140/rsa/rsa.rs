// go: file crypto/internal/fips140/rsa/rsa.go decls: PublicKey.Size, PrivateKey.PublicKey, NewPrivateKey, newPrivateKey, NewPrivateKeyWithPrecomputation, NewPrivateKeyWithoutCRT, PrivateKey.Export, checkPrivateKey, checkPublicKey, Encrypt, encrypt, DecryptWithoutCheck, DecryptWithCheck, decrypt
//
// crypto/internal/fips140/rsa — the FIPS-internal RSA core.
//
// This is the INTERNAL fips140 RSA type, distinct from the public
// `crypto/rsa.PublicKey`/`PrivateKey`. Here the modulus is a
// constant-time `bigmod.Modulus`, not a `*big.Int`. This file ports the
// raw key types, their constructors/validation, and the raw
// constant-time encrypt/decrypt.
//
// Deviations from rsa[go] @ Go 1.25.5:
//
//   * `bigmod` returns owned `Nat`/`Modulus` clones where Go returns
//     receiver-aliasing `*Nat`. Each Go `x.Foo(...)` that mutates and
//     returns the receiver becomes a mutate-then-read sequence here.
//   * Go's `*PrivateKey`/`*PublicKey` returns are nilable pointers;
//     goish returns values, so every error path needs a zero value.
//     `zero_private_key` / `zero_public_key` / `zero_modulus` fill that
//     slot — they are never observed by a caller that checks `err`.
//   * The drbg shims (`read_with_reader`, `drbg_read`) stand in for
//     `crypto/internal/fips140/drbg`, which has no goish package yet.

extern crate alloc;

use crate::bytes;
use crate::crypto::internal::fips140;
use crate::crypto::internal::fips140::bigmod::{Modulus, Nat};
use crate::error;
use crate::errors;
use crate::goslice::slice;
use crate::io;
use crate::types::{byte, int, uint};

// ─── PublicKey ────────────────────────────────────────────────────────

// go: sdk 1.25.5 crypto/internal/fips140/rsa/rsa.go:14-17 PublicKey
/// `PublicKey` — the FIPS-internal RSA public key. The modulus is a
/// constant-time `bigmod.Modulus`; `E` is the public exponent.
#[derive(Clone)]
pub struct PublicKey {
    pub N: Modulus,
    pub E: int,
}

impl PublicKey {
    // go: sdk 1.25.5 crypto/internal/fips140/rsa/rsa.go:21-23 PublicKey.Size
    /// `Size` returns the modulus size in bytes. Raw signatures and
    /// ciphertexts for or by this public key have the same size.
    pub fn Size(&self) -> int {
        return (self.N.BitLen() + 7) / 8;
    }
}

// ─── PrivateKey ───────────────────────────────────────────────────────

// go: sdk 1.25.5 crypto/internal/fips140/rsa/rsa.go:25-42 PrivateKey
/// `PrivateKey` — the FIPS-internal RSA private key.
///
/// `pub` has already been checked with `checkPublicKey`. `p`/`q`/`dP`/
/// `dQ`/`qInv` are unset for deprecated multi-prime keys (CRT-less);
/// exactly as in Go, `dP == nil` is the discriminator.
#[derive(Clone)]
pub struct PrivateKey {
    // pub has already been checked with checkPublicKey.
    pub pub_: PublicKey,
    pub d: Nat,
    // The following values are not set for deprecated multi-prime keys.
    // Since they are always set for keys in FIPS mode, for SP 800-56B
    // Rev. 2 purposes we always use the Chinese Remainder Theorem (CRT)
    // format.
    pub p: Modulus, // p × q = n
    pub q: Modulus,
    // dP and dQ are used as exponents, so we store them as big-endian
    // byte slices to be passed to bigmod.Nat.Exp.
    pub dP: slice<byte>, // d mod (p - 1)
    pub dQ: slice<byte>, // d mod (q - 1)
    pub qInv: Nat,       // qInv = q⁻¹ mod p
    // fipsApproved is false if this key does not comply with FIPS 186-5
    // or SP 800-56B Rev. 2.
    pub fipsApproved: bool,
}

impl PrivateKey {
    // go: sdk 1.25.5 crypto/internal/fips140/rsa/rsa.go:44-46 PrivateKey.PublicKey
    /// The embedded public key.
    pub fn PublicKey(&self) -> PublicKey {
        return self.pub_.clone();
    }

    // go: sdk 1.25.5 crypto/internal/fips140/rsa/rsa.go:175-188 PrivateKey.Export
    /// `Export` returns the key parameters in big-endian byte slice
    /// format. `P`, `Q`, `dP`, `dQ`, `qInv` are nil (empty) if the key
    /// was created with `NewPrivateKeyWithoutCRT`.
    pub fn Export(
        &self,
    ) -> (
        slice<byte>,
        int,
        slice<byte>,
        slice<byte>,
        slice<byte>,
        slice<byte>,
        slice<byte>,
        slice<byte>,
    ) {
        let N = self.pub_.N.Nat().Bytes(&self.pub_.N);
        let e = self.pub_.E;
        let d = self.d.Bytes(&self.pub_.N);
        if self.dP == crate::nilval::nil {
            return (
                N,
                e,
                d,
                slice::<byte>::new(),
                slice::<byte>::new(),
                slice::<byte>::new(),
                slice::<byte>::new(),
                slice::<byte>::new(),
            );
        }
        let P = self.p.Nat().Bytes(&self.p);
        let Q = self.q.Nat().Bytes(&self.q);
        let dP = bytes::Clone(self.dP.clone());
        let dQ = bytes::Clone(self.dQ.clone());
        let qInv = self.qInv.Bytes(&self.p);
        return (N, e, d, P, Q, dP, dQ, qInv);
    }
}

// ─── constructors ─────────────────────────────────────────────────────

// go: sdk 1.25.5 crypto/internal/fips140/rsa/rsa.go:52-70 NewPrivateKey
/// `NewPrivateKey` creates a new RSA private key from the given
/// parameters. All values are big-endian byte slices; they may have
/// leading zeros or be shorter if leading zeroes were trimmed.
pub fn NewPrivateKey(
    N: slice<byte>,
    e: int,
    d: slice<byte>,
    P: slice<byte>,
    Q: slice<byte>,
) -> (PrivateKey, error) {
    let (n, err) = Modulus::NewModulus(N);
    if !err.IsNil() {
        return (zero_private_key(), err);
    }
    let (p, err) = Modulus::NewModulus(P);
    if !err.IsNil() {
        return (zero_private_key(), err);
    }
    let (q, err) = Modulus::NewModulus(Q);
    if !err.IsNil() {
        return (zero_private_key(), err);
    }
    let mut dScratch = Nat::NewNat();
    let (dN, err) = dScratch.SetBytes(d, &n);
    if !err.IsNil() {
        return (zero_private_key(), err);
    }
    return newPrivateKey(n, e, dN, p, q);
}

// go: sdk 1.25.5 crypto/internal/fips140/rsa/rsa.go:72-108 newPrivateKey
/// `newPrivateKey` assembles + validates a CRT private key, computing
/// `dP`, `dQ` and `qInv` from `d`, `p`, `q`.
pub(super) fn newPrivateKey(
    n: Modulus,
    e: int,
    d: Nat,
    p: Modulus,
    q: Modulus,
) -> (PrivateKey, error) {
    // pMinusOne = p - 1
    let mut pMinusOne = p.Nat();
    pMinusOne.SubOne(&p);
    let (pMinusOneMod, err) = Modulus::NewModulus(pMinusOne.Bytes(&p));
    if !err.IsNil() {
        return (zero_private_key(), err);
    }
    let mut dPNat = Nat::NewNat();
    dPNat.Mod(&d, &pMinusOneMod);
    let dP = dPNat.Bytes(&pMinusOneMod);

    // qMinusOne = q - 1
    let mut qMinusOne = q.Nat();
    qMinusOne.SubOne(&q);
    let (qMinusOneMod, err) = Modulus::NewModulus(qMinusOne.Bytes(&q));
    if !err.IsNil() {
        return (zero_private_key(), err);
    }
    let mut dQNat = Nat::NewNat();
    dQNat.Mod(&d, &qMinusOneMod);
    let dQ = dQNat.Bytes(&qMinusOneMod);

    // Constant-time modular inversion with prime modulus by Fermat's
    // Little Theorem: qInv = q⁻¹ mod p = q^(p-2) mod p.
    if p.Nat().IsOdd() == 0 {
        // bigmod.Nat.Exp requires an odd modulus.
        return (zero_private_key(), errors::New("crypto/rsa: p is even"));
    }
    // pMinusTwo = (p - 1) - 1, as big-endian bytes.
    let mut pMinusTwoNat = p.Nat();
    pMinusTwoNat.SubOne(&p);
    pMinusTwoNat.SubOne(&p);
    let pMinusTwo = pMinusTwoNat.Bytes(&p);

    // qInv = q mod p, then qInv = qInv^(p-2) mod p (Fermat inversion).
    let mut qInv = Nat::NewNat();
    qInv.Mod(&q.Nat(), &p);
    let qInvBase = qInv.clone();
    qInv.Exp(&qInvBase, pMinusTwo, &p);

    let mut pk = PrivateKey {
        pub_: PublicKey { N: n, E: e },
        d,
        p,
        q,
        dP,
        dQ,
        qInv,
        fipsApproved: false,
    };
    let err = checkPrivateKey(&mut pk);
    if !err.IsNil() {
        return (zero_private_key(), err);
    }
    return (pk, errors::nil);
}

// go: sdk 1.25.5 crypto/internal/fips140/rsa/rsa.go:112-145 NewPrivateKeyWithPrecomputation
/// `NewPrivateKeyWithPrecomputation` creates a new RSA private key from
/// the given parameters, which include precomputed CRT values.
pub fn NewPrivateKeyWithPrecomputation(
    N: slice<byte>,
    e: int,
    d: slice<byte>,
    P: slice<byte>,
    Q: slice<byte>,
    dP: slice<byte>,
    dQ: slice<byte>,
    qInv: slice<byte>,
) -> (PrivateKey, error) {
    let (n, err) = Modulus::NewModulus(N);
    if !err.IsNil() {
        return (zero_private_key(), err);
    }
    let (p, err) = Modulus::NewModulus(P);
    if !err.IsNil() {
        return (zero_private_key(), err);
    }
    let (q, err) = Modulus::NewModulus(Q);
    if !err.IsNil() {
        return (zero_private_key(), err);
    }
    let mut dNScratch = Nat::NewNat();
    let (dN, err) = dNScratch.SetBytes(d, &n);
    if !err.IsNil() {
        return (zero_private_key(), err);
    }
    let mut qInvScratch = Nat::NewNat();
    let (qInvNat, err) = qInvScratch.SetBytes(qInv, &p);
    if !err.IsNil() {
        return (zero_private_key(), err);
    }

    let mut pk = PrivateKey {
        pub_: PublicKey { N: n, E: e },
        d: dN,
        p,
        q,
        dP,
        dQ,
        qInv: qInvNat,
        fipsApproved: false,
    };
    let err = checkPrivateKey(&mut pk);
    if !err.IsNil() {
        return (zero_private_key(), err);
    }
    return (pk, errors::nil);
}

// go: sdk 1.25.5 crypto/internal/fips140/rsa/rsa.go:150-169 NewPrivateKeyWithoutCRT
/// `NewPrivateKeyWithoutCRT` creates a new RSA private key from the
/// given parameters. Meant for deprecated multi-prime keys; NOT FIPS 140
/// compliant.
pub fn NewPrivateKeyWithoutCRT(
    N: slice<byte>,
    e: int,
    d: slice<byte>,
) -> (PrivateKey, error) {
    let (n, err) = Modulus::NewModulus(N);
    if !err.IsNil() {
        return (zero_private_key(), err);
    }
    let mut dNScratch = Nat::NewNat();
    let (dN, err) = dNScratch.SetBytes(d, &n);
    if !err.IsNil() {
        return (zero_private_key(), err);
    }
    let mut pk = PrivateKey {
        pub_: PublicKey { N: n, E: e },
        d: dN,
        p: zero_modulus(),
        q: zero_modulus(),
        dP: nil_bytes(),
        dQ: nil_bytes(),
        qInv: Nat::NewNat(),
        fipsApproved: false,
    };
    let err = checkPrivateKey(&mut pk);
    if !err.IsNil() {
        return (zero_private_key(), err);
    }
    return (pk, errors::nil);
}

// go: none — goish-only checked constructor; Go's callers build the
// `PublicKey` struct literally, which goish's `crypto/rsa` layer cannot
// do because the field is a `bigmod.Modulus` value, not a pointer.
/// Validate `N`/`e` via `checkPublicKey` and return the resulting key.
pub fn NewPublicKey(N: slice<byte>, e: int) -> (PublicKey, error) {
    let (n, err) = Modulus::NewModulus(N);
    if !err.IsNil() {
        return (zero_public_key(), err);
    }
    let pub_ = PublicKey { N: n, E: e };
    let (_, err) = checkPublicKey(&pub_);
    if !err.IsNil() {
        return (zero_public_key(), err);
    }
    return (pub_, errors::nil);
}

// ─── validation ───────────────────────────────────────────────────────

// go: sdk 1.25.5 crypto/internal/fips140/rsa/rsa.go:192-314 checkPrivateKey
/// `checkPrivateKey` is called by the NewPrivateKey and GenerateKey
/// functions, and is allowed to modify `priv.fipsApproved`.
pub(super) fn checkPrivateKey(priv_: &mut PrivateKey) -> error {
    priv_.fipsApproved = true;

    let (fipsApproved, err) = checkPublicKey(&priv_.pub_);
    if !err.IsNil() {
        return err;
    } else if !fipsApproved {
        priv_.fipsApproved = false;
    }

    if priv_.dP == crate::nilval::nil {
        // Legacy and deprecated multi-prime keys.
        priv_.fipsApproved = false;
        return errors::nil;
    }

    // N is priv_.pub_.N; p, q are priv_.p, priv_.q.
    // FIPS 186-5, Section 5.1 requires p and q be the same bit length.
    if priv_.p.BitLen() != priv_.q.BitLen() {
        priv_.fipsApproved = false;
    }

    // Check that pq ≡ 1 mod N (and that p < N and q < N).
    let mut pN = Nat::NewNat();
    pN.ExpandFor(&priv_.pub_.N);
    {
        let (_, e) = pN.SetBytes(priv_.p.Nat().Bytes(&priv_.p), &priv_.pub_.N);
        if !e.IsNil() {
            return errors::New("crypto/rsa: invalid prime");
        }
    }
    let mut qN = Nat::NewNat();
    qN.ExpandFor(&priv_.pub_.N);
    {
        let (_, e) = qN.SetBytes(priv_.q.Nat().Bytes(&priv_.q), &priv_.pub_.N);
        if !e.IsNil() {
            return errors::New("crypto/rsa: invalid prime");
        }
    }
    {
        let mut pq = pN.clone();
        pq.Mul(&qN, &priv_.pub_.N);
        if pq.IsZero() != 1 {
            return errors::New("crypto/rsa: p * q != n");
        }
    }

    // Check that de ≡ 1 mod p-1, and de ≡ 1 mod q-1.
    let mut pMinus1Nat = priv_.p.Nat();
    pMinus1Nat.SubOne(&priv_.p);
    let (pMinus1, err) = Modulus::NewModulus(pMinus1Nat.Bytes(&priv_.p));
    if !err.IsNil() {
        return errors::New("crypto/rsa: invalid prime");
    }
    let mut dPScratch = Nat::NewNat();
    let (dPNat, e) = dPScratch.SetBytes(priv_.dP.clone(), &pMinus1);
    if !e.IsNil() {
        return errors::New("crypto/rsa: invalid CRT exponent");
    }
    {
        let mut de = Nat::NewNat();
        de.SetUint(uint::try_from(priv_.pub_.E).unwrap_or(0));
        de.ExpandFor(&pMinus1);
        de.Mul(&dPNat, &pMinus1);
        if de.IsOne() != 1 {
            return errors::New("crypto/rsa: invalid CRT exponent");
        }
    }

    let mut qMinus1Nat = priv_.q.Nat();
    qMinus1Nat.SubOne(&priv_.q);
    let (qMinus1, err) = Modulus::NewModulus(qMinus1Nat.Bytes(&priv_.q));
    if !err.IsNil() {
        return errors::New("crypto/rsa: invalid prime");
    }
    let mut dQScratch = Nat::NewNat();
    let (dQNat, e) = dQScratch.SetBytes(priv_.dQ.clone(), &qMinus1);
    if !e.IsNil() {
        return errors::New("crypto/rsa: invalid CRT exponent");
    }
    {
        let mut de = Nat::NewNat();
        de.SetUint(uint::try_from(priv_.pub_.E).unwrap_or(0));
        de.ExpandFor(&qMinus1);
        de.Mul(&dQNat, &qMinus1);
        if de.IsOne() != 1 {
            return errors::New("crypto/rsa: invalid CRT exponent");
        }
    }

    // Check that qInv * q ≡ 1 mod p.
    let qP = {
        let mut scratch = Nat::NewNat();
        let (val, e) = scratch.SetOverflowingBytes(priv_.q.Nat().Bytes(&priv_.q), &priv_.p);
        if !e.IsNil() {
            // q >= 2^⌈log2(p)⌉
            let mut m = Nat::NewNat();
            m.Mod(&priv_.q.Nat(), &priv_.p);
            m
        } else {
            val
        }
    };
    {
        let mut t = qP.clone();
        t.Mul(&priv_.qInv, &priv_.p);
        if t.IsOne() != 1 {
            return errors::New("crypto/rsa: invalid CRT coefficient");
        }
    }

    // Check that |p - q| > 2^(nlen/2 - 100).
    let mut diff = Nat::NewNat();
    {
        let mut scratch = Nat::NewNat();
        let (qPval, e) = scratch.SetBytes(priv_.q.Nat().Bytes(&priv_.q), &priv_.p);
        if !e.IsNil() {
            // q > p
            let mut scratch2 = Nat::NewNat();
            let (pQ, e2) = scratch2.SetBytes(priv_.p.Nat().Bytes(&priv_.p), &priv_.q);
            if !e2.IsNil() {
                return errors::New("crypto/rsa: p == q");
            }
            // diff = 0 - p mod q = q - p
            diff.ExpandFor(&priv_.q);
            diff.Sub(&pQ, &priv_.q);
        } else {
            // p > q
            // diff = 0 - q mod p = p - q
            diff.ExpandFor(&priv_.p);
            diff.Sub(&qPval, &priv_.p);
        }
    }
    if diff.BitLenVarTime() <= priv_.pub_.N.BitLen() / 2 - 100 {
        return errors::New("crypto/rsa: |p - q| too small");
    }

    // Check that d > 2^(nlen/2).
    if priv_.d.BitLenVarTime() <= priv_.pub_.N.BitLen() / 2 {
        return errors::New("crypto/rsa: d too small");
    }

    return errors::nil;
}

// go: sdk 1.25.5 crypto/internal/fips140/rsa/rsa.go:316-354 checkPublicKey
/// `checkPublicKey` validates a public key, returning whether it is
/// FIPS-approved plus an error for hard failures.
pub(super) fn checkPublicKey(pub_: &PublicKey) -> (bool, error) {
    let mut fipsApproved = true;
    // Go's `pub.N == nil` — goish stores N inline; an unset modulus
    // surfaces as a zero-valued (BitLen 0) Modulus.
    if pub_.N.BitLen() == 0 {
        return (false, errors::New("crypto/rsa: missing public modulus"));
    }
    if pub_.N.Nat().IsOdd() == 0 {
        return (false, errors::New("crypto/rsa: public modulus is even"));
    }
    // FIPS 186-5, Section 5.1: modulus bit length must be an even
    // integer >= 2048.
    if pub_.N.BitLen() < 2048 {
        fipsApproved = false;
    }
    if pub_.N.BitLen() % 2 == 1 {
        fipsApproved = false;
    }
    if pub_.E < 2 {
        return (
            false,
            errors::New("crypto/rsa: public exponent too small or negative"),
        );
    }
    // e must be coprime with p-1 and q-1 (invertible mod λ(pq)); since
    // p, q are prime this means e must be odd.
    if pub_.E & 1 == 0 {
        return (false, errors::New("crypto/rsa: public exponent is even"));
    }
    // FIPS 186-5, Section 5.5(e): 2¹⁶ < e < 2²⁵⁶.
    if pub_.E <= 1 << 16 {
        fipsApproved = false;
    }
    // We require E to fit into a 32-bit integer so behavior does not
    // depend on int width.
    if pub_.E > (1 << 31) - 1 {
        return (false, errors::New("crypto/rsa: public exponent too large"));
    }
    return (fipsApproved, errors::nil);
}

// ─── raw encrypt / decrypt ────────────────────────────────────────────

// go: sdk 1.25.5 crypto/internal/fips140/rsa/rsa.go:357-363 Encrypt
/// `Encrypt` performs the RSA public key operation.
pub fn Encrypt(pub_: &PublicKey, plaintext: slice<byte>) -> (slice<byte>, error) {
    fips140::RecordNonApproved();
    let (_, err) = checkPublicKey(pub_);
    if !err.IsNil() {
        return (nil_bytes(), err);
    }
    return encrypt(pub_, plaintext);
}

// go: sdk 1.25.5 crypto/internal/fips140/rsa/rsa.go:365-371 encrypt
/// The raw RSA public key operation: m^e mod N.
pub fn encrypt(pub_: &PublicKey, plaintext: slice<byte>) -> (slice<byte>, error) {
    let mut mScratch = Nat::NewNat();
    let (m, err) = mScratch.SetBytes(plaintext, &pub_.N);
    if !err.IsNil() {
        return (nil_bytes(), err);
    }
    let mut out = Nat::NewNat();
    out.ExpShortVarTime(&m, uint::try_from(pub_.E).unwrap_or(0), &pub_.N);
    return (out.Bytes(&pub_.N), errors::nil);
}

// ─── sentinel errors ──────────────────────────────────────────────────

crate::var! {
    /// `ErrMessageTooLong` — message too long for the RSA key size.
    pub ErrMessageTooLong: error = "crypto/rsa: message too long for RSA key size";
    /// `ErrDecryption` — generic RSA decryption error.
    pub ErrDecryption: error = "crypto/rsa: decryption error";
    /// `ErrVerification` — generic RSA verification error.
    pub ErrVerification: error = "crypto/rsa: verification error";
}

pub(super) const withCheck: bool = true;
pub(super) const noCheck: bool = false;

// go: sdk 1.25.5 crypto/internal/fips140/rsa/rsa.go:381-384 DecryptWithoutCheck
/// `DecryptWithoutCheck` performs the RSA private key operation.
pub fn DecryptWithoutCheck(priv_: &PrivateKey, ciphertext: slice<byte>) -> (slice<byte>, error) {
    fips140::RecordNonApproved();
    return decrypt(priv_, ciphertext, noCheck);
}

// go: sdk 1.25.5 crypto/internal/fips140/rsa/rsa.go:388-391 DecryptWithCheck
/// `DecryptWithCheck` performs the RSA private key operation and checks
/// the result to defend against errors in the CRT computation.
pub fn DecryptWithCheck(priv_: &PrivateKey, ciphertext: slice<byte>) -> (slice<byte>, error) {
    fips140::RecordNonApproved();
    return decrypt(priv_, ciphertext, withCheck);
}

// go: sdk 1.25.5 crypto/internal/fips140/rsa/rsa.go:396-439 decrypt
/// `decrypt` performs an RSA decryption of `ciphertext`. If `check` is
/// true, m^e is recomputed and compared with the ciphertext to defend
/// against errors in the CRT computation.
pub fn decrypt(priv_: &PrivateKey, ciphertext: slice<byte>, check: bool) -> (slice<byte>, error) {
    if !priv_.fipsApproved {
        fips140::RecordNonApproved();
    }

    let N = &priv_.pub_.N;
    let E = priv_.pub_.E;

    let mut cScratch = Nat::NewNat();
    let (c, err) = cScratch.SetBytes(ciphertext, N);
    if !err.IsNil() {
        return (nil_bytes(), ErrDecryption.into());
    }

    let m: Nat;
    if priv_.dP == crate::nilval::nil {
        // Legacy codepath for deprecated multi-prime keys.
        fips140::RecordNonApproved();
        let mut mm = Nat::NewNat();
        mm.Exp(&c, priv_.d.Bytes(N), N);
        m = mm;
    } else {
        let P = &priv_.p;
        let Q = &priv_.q;

        // m = c ^ Dp mod p
        let mut mP = {
            let mut t0 = Nat::NewNat();
            t0.Mod(&c, P);
            let mut mm = Nat::NewNat();
            mm.Exp(&t0, priv_.dP.clone(), P);
            mm
        };
        // m2 = c ^ Dq mod q
        let m2 = {
            let mut t0 = Nat::NewNat();
            t0.Mod(&c, Q);
            let mut mm = Nat::NewNat();
            mm.Exp(&t0, priv_.dQ.clone(), Q);
            mm
        };
        // m = m - m2 mod p
        {
            let mut t0 = Nat::NewNat();
            t0.Mod(&m2, P);
            mP.Sub(&t0, P);
        }
        // m = m * Qinv mod p
        mP.Mul(&priv_.qInv, P);
        // m = m * q mod N
        mP.ExpandFor(N);
        {
            let mut t0 = Nat::NewNat();
            t0.Mod(&Q.Nat(), N);
            mP.Mul(&t0, N);
        }
        // m = m + m2 mod N
        {
            let mut m2N = m2.clone();
            m2N.ExpandFor(N);
            mP.Add(&m2N, N);
        }
        m = mP;
    }

    if check {
        let mut c1 = Nat::NewNat();
        c1.ExpShortVarTime(&m, uint::try_from(E).unwrap_or(0), N);
        if c1.Equal(&c) != 1 {
            return (nil_bytes(), ErrDecryption.into());
        }
    }

    return (m.Bytes(N), errors::nil);
}

// ─── drbg shims (Go: crypto/internal/fips140/drbg) ────────────────────

// go: none — `drbg.ReadWithReader` shim; crypto/internal/fips140/drbg
// has no goish package yet. With FIPS mode off Go's body is exactly
// `io.ReadFull(r, b)`; the `DefaultReader` fast path and
// `randutil.MaybeReadByte` are FIPS-mode-only.
pub(super) fn read_with_reader(r: &mut dyn io::Reader, b: &mut [byte]) -> error {
    fips140::RecordNonApproved();
    let mut buf = slice::<byte>::__from_vec(b.to_vec());
    let (_, err) = io::ReadFull(r, &mut buf);
    if !err.IsNil() {
        return err;
    }
    let n = buf.Len();
    let mut i: int = 0;
    while i < n && usize::try_from(i).unwrap_or(usize::MAX) < b.len() {
        b[usize::try_from(i).unwrap_or(0)] = buf[i];
        i += 1;
    }
    return errors::nil;
}

// go: none — `drbg.Read` shim; crypto/internal/fips140/drbg has no goish
// package yet. With FIPS mode off it draws from the kernel CSPRNG.
pub(super) fn drbg_read(b: &mut [byte]) {
    let mut buf = slice::<byte>::__from_vec(alloc::vec![0u8; b.len()]);
    let (_, err) = crate::crypto::rand::Read(&mut buf);
    if !err.IsNil() {
        panic!("crypto/rand: kernel CSPRNG read failed");
    }
    let n = buf.Len();
    let mut i: int = 0;
    while i < n && usize::try_from(i).unwrap_or(usize::MAX) < b.len() {
        b[usize::try_from(i).unwrap_or(0)] = buf[i];
        i += 1;
    }
}

// ─── zero-value constructors ──────────────────────────────────────────

// go: none — Go returns a nil `[]byte`; goish's slice has no nil header,
// so an empty slice is its `nil` (`s == nil` is `len(s) == 0`).
pub(super) fn nil_bytes() -> slice<byte> {
    return slice::<byte>::new();
}

// go: none — Go returns a nil `*bigmod.Modulus` on the error path; goish
// returns a value, so the error slot needs a placeholder.
pub(super) fn zero_modulus() -> Modulus {
    let (m, _) = Modulus::NewModulus(slice::<byte>::__from_vec(alloc::vec![0u8; 2]));
    return m;
}

// go: none — Go returns a nil `*PublicKey` on the error path; goish
// returns a value, so the error slot needs a placeholder.
pub(super) fn zero_public_key() -> PublicKey {
    return PublicKey {
        N: zero_modulus(),
        E: 0,
    };
}

// go: none — Go returns a nil `*PrivateKey` on the error path; goish
// returns a value, so the error slot needs a placeholder.
pub(super) fn zero_private_key() -> PrivateKey {
    return PrivateKey {
        pub_: zero_public_key(),
        d: Nat::NewNat(),
        p: zero_modulus(),
        q: zero_modulus(),
        dP: nil_bytes(),
        dQ: nil_bytes(),
        qInv: Nat::NewNat(),
        fipsApproved: false,
    };
}
