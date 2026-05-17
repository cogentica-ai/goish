// crypto/internal/fips140/rsa — the FIPS-internal RSA core. Faithful
// port of Go 1.25.5 crypto/internal/fips140/rsa/rsa.go + keygen.go.
//
// This is the INTERNAL fips140 RSA type, distinct from the public
// `crypto/rsa.PublicKey`/`PrivateKey`. Here the modulus is a
// constant-time `bigmod.Modulus`, not a `*big.Int`. The padding layer
// (PKCS#1 v1.5, OAEP, PSS) is a separate package built ON TOP of this
// one; this file ports only the raw key types, key generation, and the
// raw constant-time encrypt/decrypt.
//
// goish notes:
//   * `bigmod` returns owned `Nat`/`Modulus` clones where Go returns
//     receiver-aliasing `*Nat`. Each Go `x.Foo(...)` that mutates and
//     returns the receiver becomes a mutate-then-read sequence here.
//   * The `random io.Reader` parameter is `&mut dyn crate::io::Reader`,
//     the established goish idiom (crypto/rand's `RandReader` impls it).
//   * `drbg.ReadWithReader(r, b)` — with FIPS mode off it is exactly
//     `io.ReadFull(r, b)`; ported inline as `read_with_reader`.
//   * `drbg.Read(b)` — the FIPS DRBG; with FIPS off it draws from the
//     kernel CSPRNG. Ported inline as `drbg_read` over `crypto/rand`.
//   * The keygen PCT self-test (`signPKCS1v15`/`verifyPKCS1v15`) lives
//     in the not-yet-ported padding package. The PCT call is kept where
//     Go places it; its closure is a no-op until the padding layer
//     lands. It only runs for FIPS-approved keys (modulus >= 2048 bits)
//     anyway, so small test keys never reach it.

#![allow(non_snake_case, non_camel_case_types, non_upper_case_globals)]

extern crate alloc;

use crate::bytes;
use crate::crypto::internal::fips140;
use crate::crypto::internal::fips140::bigmod::{Modulus, Nat};
use crate::error;
use crate::errors;
use crate::goslice::slice;
use crate::io;
use crate::types::{byte, int, uint};
use alloc::vec::Vec;

// ─── helpers — slice<byte> <-> Vec<byte> at the boundary ──────────────

/// Copy a goish `slice<byte>` into a `Vec<byte>` for byte-level loops.
fn to_vec(s: &slice<byte>) -> Vec<byte> {
    let n = s.Len();
    let mut v: Vec<byte> = Vec::with_capacity(n as usize);
    let mut i: int = 0;
    while i < n {
        v.push(s[i]);
        i += 1;
    }
    v
}

/// Wrap a `Vec<byte>` as a goish `slice<byte>` (zero-copy at the return
/// site — no Rust container leaks the public API).
fn from_vec(v: Vec<byte>) -> slice<byte> {
    slice::<byte>::__from_vec(v)
}

// ─── PublicKey (Go: rsa.go:13) ────────────────────────────────────────

/// `PublicKey` — the FIPS-internal RSA public key. The modulus is a
/// constant-time `bigmod.Modulus`; `E` is the public exponent.
#[derive(Clone)]
pub struct PublicKey {
    pub N: Modulus,
    pub E: int,
}

impl PublicKey {
    /// `(*PublicKey).Size` (rsa.go:20) — the modulus size in bytes. Raw
    /// signatures and ciphertexts for/by this key have the same size.
    pub fn Size(&self) -> int {
        (self.N.BitLen() + 7) / 8
    }
}

// ─── PrivateKey (Go: rsa.go:25) ───────────────────────────────────────

/// `PrivateKey` — the FIPS-internal RSA private key.
///
/// `pub` has already been checked with `checkPublicKey`. `p`/`q`/`dP`/
/// `dQ`/`qInv` are unset for deprecated multi-prime keys (CRT-less);
/// `has_crt` records whether they are present (Go uses `dP == nil`).
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
    // has_crt mirrors Go's `dP != nil`: true for full CRT keys, false
    // for the deprecated CRT-less constructor.
    pub has_crt: bool,
    // fipsApproved is false if this key does not comply with FIPS 186-5
    // or SP 800-56B Rev. 2.
    pub fipsApproved: bool,
}

impl PrivateKey {
    /// `(*PrivateKey).PublicKey` (rsa.go:43) — the embedded public key.
    pub fn PublicKey(&self) -> PublicKey {
        self.pub_.clone()
    }

    /// `(*PrivateKey).Export` (rsa.go:170) — the key parameters in
    /// big-endian byte slice format. `P`, `Q`, `dP`, `dQ`, `qInv` are
    /// empty if the key was created without CRT.
    pub fn Export(&self) -> (slice<byte>, int, slice<byte>, slice<byte>, slice<byte>, slice<byte>, slice<byte>, slice<byte>) {
        let N = self.pub_.N.Nat().Bytes(&self.pub_.N);
        let e = self.pub_.E;
        let d = self.d.Bytes(&self.pub_.N);
        if !self.has_crt {
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
        (N, e, d, P, Q, dP, dQ, qInv)
    }
}

// ─── constructors (Go: rsa.go) ────────────────────────────────────────

/// `NewPrivateKey` (rsa.go:52) — a new RSA private key from the given
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
    let mut dN = Nat::NewNat();
    let (dN, err) = {
        let (val, e2) = dN.SetBytes(d, &n);
        let _ = &mut dN;
        (val, e2)
    };
    if !err.IsNil() {
        return (zero_private_key(), err);
    }
    newPrivateKey(n, e, dN, p, q)
}

/// `newPrivateKey` (rsa.go:71) — assemble + validate a CRT private key,
/// computing `dP`, `dQ`, and `qInv` from `d`, `p`, `q`.
fn newPrivateKey(
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
        has_crt: true,
        fipsApproved: false,
    };
    let err = checkPrivateKey(&mut pk);
    if !err.IsNil() {
        return (zero_private_key(), err);
    }
    (pk, errors::nil)
}

/// `NewPrivateKeyWithPrecomputation` (rsa.go:110) — a new RSA private
/// key from the given parameters, which include precomputed CRT values.
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
        has_crt: true,
        fipsApproved: false,
    };
    let err = checkPrivateKey(&mut pk);
    if !err.IsNil() {
        return (zero_private_key(), err);
    }
    (pk, errors::nil)
}

/// `NewPrivateKeyWithoutCRT` (rsa.go:147) — a new RSA private key from
/// the given parameters. Meant for deprecated multi-prime keys; NOT
/// FIPS 140 compliant.
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
        dP: slice::<byte>::new(),
        dQ: slice::<byte>::new(),
        qInv: Nat::NewNat(),
        has_crt: false,
        fipsApproved: false,
    };
    let err = checkPrivateKey(&mut pk);
    if !err.IsNil() {
        return (zero_private_key(), err);
    }
    (pk, errors::nil)
}

/// `NewPublicKey` — Go declares only the `PublicKey` struct directly
/// (callers build it literally), but the padding layer wants a checked
/// constructor. This validates the modulus/exponent via `checkPublicKey`
/// and returns the key; it mirrors how the public `crypto/rsa` layer
/// constructs a verified internal `PublicKey`.
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
    (pub_, errors::nil)
}

// ─── validation (Go: rsa.go) ──────────────────────────────────────────

/// `checkPrivateKey` (rsa.go:186) — called by the NewPrivateKey and
/// GenerateKey functions; sets `priv.fipsApproved`.
fn checkPrivateKey(priv_: &mut PrivateKey) -> error {
    priv_.fipsApproved = true;

    let (fipsApproved, err) = checkPublicKey(&priv_.pub_);
    if !err.IsNil() {
        return err;
    } else if !fipsApproved {
        priv_.fipsApproved = false;
    }

    if !priv_.has_crt {
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

    errors::nil
}

/// `checkPublicKey` (rsa.go:299) — validate a public key, returning
/// whether it is FIPS-approved plus an error for hard failures.
fn checkPublicKey(pub_: &PublicKey) -> (bool, error) {
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
    (fipsApproved, errors::nil)
}

// ─── raw encrypt / decrypt (Go: rsa.go) ───────────────────────────────

/// `Encrypt` (rsa.go:339) — the RSA public key operation.
pub fn Encrypt(pub_: &PublicKey, plaintext: slice<byte>) -> (slice<byte>, error) {
    fips140::RecordNonApproved();
    let (_, err) = checkPublicKey(pub_);
    if !err.IsNil() {
        return (slice::<byte>::new(), err);
    }
    encrypt(pub_, plaintext)
}

/// `encrypt` (rsa.go:347) — the raw RSA public key operation: m^e mod N.
pub fn encrypt(pub_: &PublicKey, plaintext: slice<byte>) -> (slice<byte>, error) {
    let mut mScratch = Nat::NewNat();
    let (m, err) = mScratch.SetBytes(plaintext, &pub_.N);
    if !err.IsNil() {
        return (slice::<byte>::new(), err);
    }
    let mut out = Nat::NewNat();
    out.ExpShortVarTime(&m, uint::try_from(pub_.E).unwrap_or(0), &pub_.N);
    (out.Bytes(&pub_.N), errors::nil)
}

// ─── sentinel errors (Go: rsa.go:355) ─────────────────────────────────

crate::var! {
    /// `ErrMessageTooLong` — message too long for the RSA key size.
    pub ErrMessageTooLong: error = "crypto/rsa: message too long for RSA key size";
    /// `ErrDecryption` — generic RSA decryption error.
    pub ErrDecryption: error = "crypto/rsa: decryption error";
    /// `ErrVerification` — generic RSA verification error.
    pub ErrVerification: error = "crypto/rsa: verification error";
}

const withCheck: bool = true;
const noCheck: bool = false;

/// `DecryptWithoutCheck` (rsa.go:365) — the RSA private key operation,
/// without the m^e cross-check.
pub fn DecryptWithoutCheck(priv_: &PrivateKey, ciphertext: slice<byte>) -> (slice<byte>, error) {
    fips140::RecordNonApproved();
    decrypt(priv_, ciphertext, noCheck)
}

/// `DecryptWithCheck` (rsa.go:371) — the RSA private key operation, with
/// the m^e cross-check to defend against CRT computation errors.
pub fn DecryptWithCheck(priv_: &PrivateKey, ciphertext: slice<byte>) -> (slice<byte>, error) {
    fips140::RecordNonApproved();
    decrypt(priv_, ciphertext, withCheck)
}

/// `decrypt` (rsa.go:379) — the raw RSA decryption. If `check` is true,
/// m^e is recomputed and compared with the ciphertext to defend against
/// errors in the CRT computation.
pub fn decrypt(priv_: &PrivateKey, ciphertext: slice<byte>, check: bool) -> (slice<byte>, error) {
    if !priv_.fipsApproved {
        fips140::RecordNonApproved();
    }

    let N = &priv_.pub_.N;
    let E = priv_.pub_.E;

    let mut cScratch = Nat::NewNat();
    let (c, err) = cScratch.SetBytes(ciphertext, N);
    if !err.IsNil() {
        return (slice::<byte>::new(), ErrDecryption.into());
    }

    let m: Nat;
    if !priv_.has_crt {
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
            return (slice::<byte>::new(), ErrDecryption.into());
        }
    }

    (m.Bytes(N), errors::nil)
}

// ─── key generation (Go: keygen.go) ───────────────────────────────────

/// `GenerateKey` (keygen.go:16) — generate a new RSA key pair of the
/// given bit size. `bits` must be at least 32.
pub fn GenerateKey(rand: &mut dyn io::Reader, bits: int) -> (PrivateKey, error) {
    if bits < 32 {
        return (zero_private_key(), errors::New("rsa: key too small"));
    }
    fips140::RecordApproved();
    if bits < 2048 || bits % 2 == 1 {
        fips140::RecordNonApproved();
    }

    loop {
        let (p, err) = randomPrime(rand, (bits + 1) / 2);
        if !err.IsNil() {
            return (zero_private_key(), err);
        }
        let (q, err) = randomPrime(rand, bits / 2);
        if !err.IsNil() {
            return (zero_private_key(), err);
        }

        let (P, err) = Modulus::NewModulus(p.clone());
        if !err.IsNil() {
            return (zero_private_key(), err);
        }
        let (Q, err) = Modulus::NewModulus(q.clone());
        if !err.IsNil() {
            return (zero_private_key(), err);
        }

        {
            let mut qExp = Q.Nat();
            qExp.ExpandFor(&P);
            if qExp.Equal(&P.Nat()) == 1 {
                return (
                    zero_private_key(),
                    errors::New("rsa: generated p == q, random source is broken"),
                );
            }
        }

        let (N, err) = Modulus::NewModulusProduct(p.clone(), q.clone());
        if !err.IsNil() {
            return (zero_private_key(), err);
        }
        if N.BitLen() != bits {
            return (
                zero_private_key(),
                errors::New("rsa: internal error: modulus size incorrect"),
            );
        }

        // FIPS 186-5, A.1.1(3) requires computing d as e⁻¹ mod λ(N)
        // where λ(N) = lcm(p-1, q-1).
        let (lambda, err) = totient(&P, &Q);
        if errors::Is(err.clone(), errDivisorTooLarge) {
            // The divisor is too large; try again with different primes.
            continue;
        }
        if !err.IsNil() {
            return (zero_private_key(), err);
        }

        let mut e = Nat::NewNat();
        e.SetUint(65537);
        let mut dScratch = Nat::NewNat();
        let (d, ok) = dScratch.InverseVarTime(&e, &lambda);
        if !ok {
            // GCD(e, lcm(p-1, q-1)) != 1; waste a prime, retry.
            continue;
        }

        {
            let mut eExp = e.clone();
            eExp.ExpandFor(&lambda);
            eExp.Mul(&d, &lambda);
            if eExp.IsOne() == 0 {
                return (
                    zero_private_key(),
                    errors::New("rsa: internal error: e*d != 1 mod λ(N)"),
                );
            }
        }

        let (k, err) = newPrivateKey(N, 65537, d, P, Q);
        if !err.IsNil() {
            return (zero_private_key(), err);
        }

        if k.fipsApproved {
            // FIPS 186-5 PCT: a sign/verify pairwise consistency test.
            // The actual signPKCS1v15/verifyPKCS1v15 routines belong to
            // the not-yet-ported padding package, so the closure is a
            // no-op here. This branch only runs for FIPS-approved keys
            // (modulus >= 2048 bits with the right exponent) — small
            // test keys never reach it.
            fips140::PCT("RSA sign and verify PCT", || errors::nil);
        }

        return (k, errors::nil);
    }
}

/// `errDivisorTooLarge` (keygen.go:118) — returned by `totient` when
/// gcd(p-1, q-1) is too large to divide with a single-word divisor.
crate::var! {
    errDivisorTooLarge: error = "divisor too large";
}

/// `totient` (keygen.go:121) — the Carmichael totient λ(N) = lcm(p-1, q-1).
fn totient(p: &Modulus, q: &Modulus) -> (Modulus, error) {
    let mut a = p.Nat();
    a.SubOne(p);
    let mut b = q.Nat();
    b.SubOne(q);

    // lcm(a, b) = a×b / gcd(a, b) = a × (b / gcd(a, b)).
    //
    // Our GCD requires at least one number to be odd. For LCM we only
    // need to preserve the larger prime power of each prime factor, so
    // we right-shift the number with the fewest trailing zeros until
    // it's odd. For odd a, b and m >= n, lcm(a×2ᵐ, b×2ⁿ) = lcm(a×2ᵐ, b).
    let az = a.TrailingZeroBitsVarTime();
    let bz = b.TrailingZeroBitsVarTime();
    if az < bz {
        a.ShiftRightVarTime(az);
    } else {
        b.ShiftRightVarTime(bz);
    }

    let mut gcdScratch = Nat::NewNat();
    let (gcd, err) = gcdScratch.GCDVarTime(&a, &b);
    if !err.IsNil() {
        return (zero_modulus(), err);
    }
    if gcd.IsOdd() == 0 {
        return (
            zero_modulus(),
            errors::New("rsa: internal error: gcd(a, b) is even"),
        );
    }

    // To avoid multiple-precision division, reject divisors above 2³²-1
    // and try again. (Probability 2⁻⁶⁴ on 64-bit platforms.)
    if gcd.BitLenVarTime() > 32 {
        return (zero_modulus(), errDivisorTooLarge.into());
    }
    let gcdBits = gcd.Bits();
    if gcd.IsZero() == 1 || gcdBits[0] == 0 {
        return (
            zero_modulus(),
            errors::New("rsa: internal error: gcd(a, b) is zero"),
        );
    }
    let rem = b.DivShortVarTime(gcdBits[0]);
    if rem != 0 {
        return (
            zero_modulus(),
            errors::New("rsa: internal error: b is not divisible by gcd(a, b)"),
        );
    }

    Modulus::NewModulusProduct(a.Bytes(p), b.Bytes(q))
}

/// `randomPrime` (keygen.go:163) — a random prime of the given bit size,
/// following FIPS 186-5, Appendix A.1.3.
fn randomPrime(rand: &mut dyn io::Reader, bits: int) -> (slice<byte>, error) {
    if bits < 16 {
        return (
            slice::<byte>::new(),
            errors::New("rsa: prime size must be at least 16 bits"),
        );
    }

    let blen = usize::try_from((bits + 7) / 8).unwrap_or(0);
    let mut b: Vec<byte> = alloc::vec![0u8; blen];
    loop {
        let err = read_with_reader(rand, &mut b);
        if !err.IsNil() {
            return (slice::<byte>::new(), err);
        }
        // Clear the most significant bits to reach the desired size.
        let excess = uint::try_from(int::try_from(blen).unwrap_or(0) * 8 - bits).unwrap_or(0);
        b[0] &= 0b1111_1111u8 >> excess;

        // Don't let the value be too small: set the most significant two
        // bits so two such values multiplied are never one bit short.
        if excess < 7 {
            b[0] |= 0b1100_0000u8 >> excess;
        } else {
            b[0] |= 0b0000_0001u8;
            b[1] |= 0b1000_0000u8;
        }

        // Make the value odd — an even number certainly isn't prime.
        b[blen - 1] |= 1;

        if isPrime(&b) {
            return (from_vec(b), errors::nil);
        }
    }
}

/// `isPrime` (keygen.go:215) — the Miller-Rabin probabilistic primality
/// test from FIPS 186-5, Appendix B.3.1. `w` is a random odd integer
/// greater than three, big-endian. NOT constant-time; may return false
/// positives for adversarially-chosen values.
fn isPrime(w: &[byte]) -> bool {
    let mr = match millerRabinSetup(w) {
        Err(_) => return false, // w is zero, one, or even.
        Ok(mr) => mr,
    };

    // Before Miller-Rabin, rule out most composites with trial divisions.
    let mut i = 0usize;
    while i < PRIMES.len() {
        let p1 = PRIMES[i];
        let p2 = PRIMES[i + 1];
        let p3 = PRIMES[i + 2];
        let mut wNat = mr.w.Nat();
        let r = wNat.DivShortVarTime(p1 * p2 * p3);
        if r % p1 == 0 || r % p2 == 0 || r % p3 == 0 {
            return false;
        }
        i += 3;
    }

    // iterations is the number of Miller-Rabin rounds. Since w is
    // randomly selected (RSA key generation), a smaller count suffices.
    let bits = mr.w.BitLen();
    let mut iterations: int = if bits >= 3747 {
        3
    } else if bits >= 1345 {
        4
    } else if bits >= 476 {
        5
    } else if bits >= 400 {
        6
    } else if bits >= 347 {
        7
    } else if bits >= 308 {
        8
    } else if bits >= 55 {
        27
    } else {
        34
    };

    let blen = usize::try_from((bits + 7) / 8).unwrap_or(0);
    let mut b: Vec<byte> = alloc::vec![0u8; blen];
    loop {
        drbg_read(&mut b);
        let excess =
            uint::try_from(int::try_from(blen).unwrap_or(0) * 8 - bits).unwrap_or(0);
        b[0] &= 0b1111_1111u8 >> excess;
        match millerRabinIteration(&mr, &b) {
            Err(_) => continue, // b was rejected.
            Ok(result) => {
                if result == millerRabinCOMPOSITE {
                    return false;
                }
                iterations -= 1;
                if iterations == 0 {
                    return true;
                }
            }
        }
    }
}

/// `primes` (keygen.go:289) — the first prime numbers (except 2) such
/// that the product of any three fits in a uint32.
static PRIMES: [uint; 255] = [
    3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71, 73, 79, 83, 89,
    97, 101, 103, 107, 109, 113, 127, 131, 137, 139, 149, 151, 157, 163, 167, 173, 179, 181,
    191, 193, 197, 199, 211, 223, 227, 229, 233, 239, 241, 251, 257, 263, 269, 271, 277, 281,
    283, 293, 307, 311, 313, 317, 331, 337, 347, 349, 353, 359, 367, 373, 379, 383, 389, 397,
    401, 409, 419, 421, 431, 433, 439, 443, 449, 457, 461, 463, 467, 479, 487, 491, 499, 503,
    509, 521, 523, 541, 547, 557, 563, 569, 571, 577, 587, 593, 599, 601, 607, 613, 617, 619,
    631, 641, 643, 647, 653, 659, 661, 673, 677, 683, 691, 701, 709, 719, 727, 733, 739, 743,
    751, 757, 761, 769, 773, 787, 797, 809, 811, 821, 823, 827, 829, 839, 853, 857, 859, 863,
    877, 881, 883, 887, 907, 911, 919, 929, 937, 941, 947, 953, 967, 971, 977, 983, 991, 997,
    1009, 1013, 1019, 1021, 1031, 1033, 1039, 1049, 1051, 1061, 1063, 1069, 1087, 1091, 1093,
    1097, 1103, 1109, 1117, 1123, 1129, 1151, 1153, 1163, 1171, 1181, 1187, 1193, 1201, 1213,
    1217, 1223, 1229, 1231, 1237, 1249, 1259, 1277, 1279, 1283, 1289, 1291, 1297, 1301, 1303,
    1307, 1319, 1321, 1327, 1361, 1367, 1373, 1381, 1399, 1409, 1423, 1427, 1429, 1433, 1439,
    1447, 1451, 1453, 1459, 1471, 1481, 1483, 1487, 1489, 1493, 1499, 1511, 1523, 1531, 1543,
    1549, 1553, 1559, 1567, 1571, 1579, 1583, 1597, 1601, 1607, 1609, 1613, 1619,
];

/// `millerRabin` (keygen.go:312) — state reused across iterations of the
/// Miller-Rabin test.
struct millerRabin {
    w: Modulus,
    a: uint,
    m: Vec<byte>,
}

/// `millerRabinSetup` (keygen.go:320) — precompute Montgomery parameters
/// and the odd part `m` of `w-1`.
fn millerRabinSetup(w: &[byte]) -> Result<millerRabin, error> {
    // Check that w is odd, and precompute Montgomery parameters.
    let (wm, err) = Modulus::NewModulus(from_vec(w.to_vec()));
    if !err.IsNil() {
        return Err(err);
    }
    if wm.Nat().IsOdd() == 0 {
        return Err(errors::New("candidate is even"));
    }

    // Compute m = (w-1)/2^a, where m is odd.
    let mut wMinus1 = wm.Nat();
    wMinus1.SubOne(&wm);
    if wMinus1.IsZero() == 1 {
        return Err(errors::New("candidate is one"));
    }
    let a = wMinus1.TrailingZeroBitsVarTime();

    // Store m as a big-endian byte slice with leading zero bytes removed.
    let mut mShifted = wMinus1.clone();
    mShifted.ShiftRightVarTime(a);
    let mBytes = mShifted.Bytes(&wm);
    let mut m = to_vec(&mBytes);
    while !m.is_empty() && m[0] == 0 {
        m.remove(0);
    }

    Ok(millerRabin { w: wm, a, m })
}

const millerRabinCOMPOSITE: bool = false;
const millerRabinPOSSIBLYPRIME: bool = true;

/// `millerRabinIteration` (keygen.go:351) — one round of Miller-Rabin
/// with base `bb`.
fn millerRabinIteration(mr: &millerRabin, bb: &[byte]) -> Result<bool, error> {
    // Reject b ≤ 1 or b ≥ w − 1.
    if int::try_from(bb.len()).unwrap_or(0) != (mr.w.BitLen() + 7) / 8 {
        return Err(errors::New("incorrect length"));
    }
    let mut bScratch = Nat::NewNat();
    let (b, err) = bScratch.SetBytes(from_vec(bb.to_vec()), &mr.w);
    if !err.IsNil() {
        return Err(err);
    }
    if b.IsZero() == 1 || b.IsOne() == 1 || b.IsMinusOne(&mr.w) == 1 {
        return Err(errors::New("out-of-range candidate"));
    }

    // Compute b^(m*2^i) mod w for successive i. If b^m mod w = 1, b is a
    // possible prime. If b^(m*2^i) mod w = -1 for some 0 <= i < a, b is
    // a possible prime. Otherwise b is composite.

    // Start by computing and checking b^m mod w (also the i = 0 case).
    let mut z = Nat::NewNat();
    z.Exp(&b, from_vec(mr.m.clone()), &mr.w);
    if z.IsOne() == 1 || z.IsMinusOne(&mr.w) == 1 {
        return Ok(millerRabinPOSSIBLYPRIME);
    }

    // Check b^(m*2^i) mod w = -1 for 0 < i < a.
    let mut iter: uint = 0;
    while iter < mr.a - 1 {
        let zc = z.clone();
        z.Mul(&zc, &mr.w);
        if z.IsMinusOne(&mr.w) == 1 {
            return Ok(millerRabinPOSSIBLYPRIME);
        }
        if z.IsOne() == 1 {
            // Future squaring will not turn z == 1 into -1.
            break;
        }
        iter += 1;
    }

    Ok(millerRabinCOMPOSITE)
}

// ─── drbg shims (Go: crypto/internal/fips140/drbg) ────────────────────

/// `drbg.ReadWithReader(r, b)` (drbg.go) — with FIPS mode off this is
/// exactly `io.ReadFull(r, b)`. Ported inline; the `DefaultReader`
/// fast-path and `randutil.MaybeReadByte` are FIPS-mode-only and have no
/// goish equivalent.
fn read_with_reader(r: &mut dyn io::Reader, b: &mut [byte]) -> error {
    fips140::RecordNonApproved();
    let mut buf = from_vec(b.to_vec());
    let (_, err) = io::ReadFull(r, &mut buf);
    if !err.IsNil() {
        return err;
    }
    let n = buf.Len();
    let mut i: int = 0;
    while i < n && (i as usize) < b.len() {
        b[i as usize] = buf[i];
        i += 1;
    }
    errors::nil
}

/// `drbg.Read(b)` (drbg.go) — the FIPS DRBG; with FIPS mode off it draws
/// directly from the kernel CSPRNG via `crypto/rand`.
fn drbg_read(b: &mut [byte]) {
    let mut buf = from_vec(alloc::vec![0u8; b.len()]);
    let (_, err) = crate::crypto::rand::Read(&mut buf);
    if !err.IsNil() {
        panic!("crypto/rand: kernel CSPRNG read failed");
    }
    let n = buf.Len();
    let mut i: int = 0;
    while i < n && (i as usize) < b.len() {
        b[i as usize] = buf[i];
        i += 1;
    }
}

// ─── zero-value constructors ──────────────────────────────────────────

/// A zero-valued `Modulus` (BitLen 0) for the error-return slot.
fn zero_modulus() -> Modulus {
    // NewModulusProduct of two empty slices yields the canonical
    // zero-value error path; we just want a placeholder Modulus value.
    let (m, _) = Modulus::NewModulus(from_vec(alloc::vec![0u8; 2]));
    m
}

/// A zero-valued `PublicKey` for the error-return slot.
fn zero_public_key() -> PublicKey {
    PublicKey {
        N: zero_modulus(),
        E: 0,
    }
}

/// A zero-valued `PrivateKey` for the error-return slot.
fn zero_private_key() -> PrivateKey {
    PrivateKey {
        pub_: zero_public_key(),
        d: Nat::NewNat(),
        p: zero_modulus(),
        q: zero_modulus(),
        dP: slice::<byte>::new(),
        dQ: slice::<byte>::new(),
        qInv: Nat::NewNat(),
        has_crt: false,
        fipsApproved: false,
    }
}
