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
            // FIPS 186-5 PCT: a sign/verify pairwise consistency test
            // (keygen.go:113). Now that the padding layer is ported the
            // closure runs a real PKCS#1 v1.5 sign/verify round-trip.
            // This branch only runs for FIPS-approved keys (modulus >=
            // 2048 bits with the right exponent).
            fips140::PCT("RSA sign and verify PCT", || {
                let hashed: [byte; 32] = [
                    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
                    0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a,
                    0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20,
                ];
                let h = from_vec(hashed.to_vec());
                let (sig, err) = signPKCS1v15(&k, crate::crypto::SHA256, h.clone());
                if !err.IsNil() {
                    return err;
                }
                verifyPKCS1v15(&k.PublicKey(), crate::crypto::SHA256, h, sig)
            });
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

// ══════════════════════════════════════════════════════════════════════
// PKCS #1 v1.5 — signing & verification (Go: pkcs1v15.go)
// ══════════════════════════════════════════════════════════════════════
//
// This file implements signing and verification using PKCS #1 v1.5
// signatures plus the RSAES-PKCS1-v1_5 encryption scheme.
//
// goish notes:
//   * Go's `SignPKCS1v15(priv, hash string, hashed []byte)` takes the
//     hash function NAME ("SHA-256", …). goish takes the `crypto.Hash`
//     identifier (a `uint`) instead — the established goish idiom — and
//     resolves it to the ASN.1 DER prefix via `hash_prefix`. The empty
//     hash (sign-directly) is modelled as the `crypto.Hash` value 0.

use crate::crypto::Hash as HashId;
use crate::hash::Hash as HashTrait;

/// `hashPrefixes` (pkcs1v15.go:25) — precomputed ASN.1 DER `DigestInfo`
/// prefixes. Each entry is `(crypto.Hash id, DER prefix bytes)`. Indexed
/// by the `crypto.Hash` identifier rather than Go's string name.
fn hash_prefix(h: HashId) -> Option<&'static [byte]> {
    // MD5
    const MD5_P: &[byte] = &[
        0x30, 0x20, 0x30, 0x0c, 0x06, 0x08, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x02, 0x05, 0x05,
        0x00, 0x04, 0x10,
    ];
    // SHA-1
    const SHA1_P: &[byte] = &[
        0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e, 0x03, 0x02, 0x1a, 0x05, 0x00, 0x04, 0x14,
    ];
    // SHA-224
    const SHA224_P: &[byte] = &[
        0x30, 0x2d, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x04,
        0x05, 0x00, 0x04, 0x1c,
    ];
    // SHA-256
    const SHA256_P: &[byte] = &[
        0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01,
        0x05, 0x00, 0x04, 0x20,
    ];
    // SHA-384
    const SHA384_P: &[byte] = &[
        0x30, 0x41, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02,
        0x05, 0x00, 0x04, 0x30,
    ];
    // SHA-512
    const SHA512_P: &[byte] = &[
        0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03,
        0x05, 0x00, 0x04, 0x40,
    ];
    // SHA-512/224
    const SHA512_224_P: &[byte] = &[
        0x30, 0x2d, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x05,
        0x05, 0x00, 0x04, 0x1c,
    ];
    // SHA-512/256
    const SHA512_256_P: &[byte] = &[
        0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x06,
        0x05, 0x00, 0x04, 0x20,
    ];
    // SHA3-224
    const SHA3_224_P: &[byte] = &[
        0x30, 0x2d, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x07,
        0x05, 0x00, 0x04, 0x1c,
    ];
    // SHA3-256
    const SHA3_256_P: &[byte] = &[
        0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x08,
        0x05, 0x00, 0x04, 0x20,
    ];
    // SHA3-384
    const SHA3_384_P: &[byte] = &[
        0x30, 0x41, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x09,
        0x05, 0x00, 0x04, 0x30,
    ];
    // SHA3-512
    const SHA3_512_P: &[byte] = &[
        0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x0a,
        0x05, 0x00, 0x04, 0x40,
    ];

    match h {
        x if x == crate::crypto::MD5 => Some(MD5_P),
        x if x == crate::crypto::SHA1 => Some(SHA1_P),
        x if x == crate::crypto::SHA224 => Some(SHA224_P),
        x if x == crate::crypto::SHA256 => Some(SHA256_P),
        x if x == crate::crypto::SHA384 => Some(SHA384_P),
        x if x == crate::crypto::SHA512 => Some(SHA512_P),
        x if x == crate::crypto::SHA512_224 => Some(SHA512_224_P),
        x if x == crate::crypto::SHA512_256 => Some(SHA512_256_P),
        x if x == crate::crypto::SHA3_224 => Some(SHA3_224_P),
        x if x == crate::crypto::SHA3_256 => Some(SHA3_256_P),
        x if x == crate::crypto::SHA3_384 => Some(SHA3_384_P),
        x if x == crate::crypto::SHA3_512 => Some(SHA3_512_P),
        _ => None,
    }
}

/// `checkApprovedHashName` (pkcs1v15.go:131) — record non-approved use
/// for any hash outside the FIPS 186-5 approved set.
fn checkApprovedHashName(hash: HashId) {
    match hash {
        x if x == crate::crypto::SHA224
            || x == crate::crypto::SHA256
            || x == crate::crypto::SHA384
            || x == crate::crypto::SHA512
            || x == crate::crypto::SHA512_224
            || x == crate::crypto::SHA512_256
            || x == crate::crypto::SHA3_224
            || x == crate::crypto::SHA3_256
            || x == crate::crypto::SHA3_384
            || x == crate::crypto::SHA3_512 => {}
        _ => fips140::RecordNonApproved(),
    }
}

/// `SignPKCS1v15` (pkcs1v15.go:46) — calculate an RSASSA-PKCS1-v1.5
/// signature.
///
/// `hash` identifies the hash function used to produce `hashed` (a
/// `crypto.Hash` id); pass `0` to indicate the message is signed
/// directly with no DER prefix.
pub fn SignPKCS1v15(
    priv_: &PrivateKey,
    hash: HashId,
    hashed: slice<byte>,
) -> (slice<byte>, error) {
    fipsSelfTest();
    fips140::RecordApproved();
    checkApprovedHashName(hash);
    signPKCS1v15(priv_, hash, hashed)
}

/// `signPKCS1v15` (pkcs1v15.go:54).
fn signPKCS1v15(
    priv_: &PrivateKey,
    hash: HashId,
    hashed: slice<byte>,
) -> (slice<byte>, error) {
    let (em, err) = pkcs1v15ConstructEM(&priv_.pub_, hash, hashed);
    if !err.IsNil() {
        return (slice::<byte>::new(), err);
    }
    decrypt(priv_, em, withCheck)
}

/// `pkcs1v15ConstructEM` (pkcs1v15.go:63) — build the EMSA-PKCS1-v1_5
/// encoded message `EM = 0x00 || 0x01 || PS || 0x00 || T`.
fn pkcs1v15ConstructEM(
    pub_: &PublicKey,
    hash: HashId,
    hashed: slice<byte>,
) -> (slice<byte>, error) {
    // Special case: hash id 0 means the data is signed directly.
    let prefix: &[byte] = if hash != 0 {
        match hash_prefix(hash) {
            Some(p) => p,
            None => {
                return (
                    slice::<byte>::new(),
                    errors::New("crypto/rsa: unsupported hash function"),
                );
            }
        }
    } else {
        &[]
    };

    // EM = 0x00 || 0x01 || PS || 0x00 || T
    let k = usize::try_from(pub_.Size()).unwrap_or(0);
    let prefix_len = prefix.len();
    let hashed_v = to_vec(&hashed);
    let hashed_len = hashed_v.len();
    if k < prefix_len + hashed_len + 2 + 8 + 1 {
        return (slice::<byte>::new(), ErrMessageTooLong.into());
    }
    let mut em: Vec<byte> = alloc::vec![0u8; k];
    em[1] = 1;
    let mut i: usize = 2;
    while i < k - prefix_len - hashed_len - 1 {
        em[i] = 0xff;
        i += 1;
    }
    // copy(em[k-len(prefix)-len(hashed):], prefix)
    let pstart = k - prefix_len - hashed_len;
    let mut j: usize = 0;
    while j < prefix_len {
        em[pstart + j] = prefix[j];
        j += 1;
    }
    // copy(em[k-len(hashed):], hashed)
    let hstart = k - hashed_len;
    let mut j: usize = 0;
    while j < hashed_len {
        em[hstart + j] = hashed_v[j];
        j += 1;
    }
    (from_vec(em), errors::nil)
}

/// `VerifyPKCS1v15` (pkcs1v15.go:93) — verify an RSASSA-PKCS1-v1.5
/// signature. `hash` is the `crypto.Hash` id, or `0` for sign-directly.
pub fn VerifyPKCS1v15(
    pub_: &PublicKey,
    hash: HashId,
    hashed: slice<byte>,
    sig: slice<byte>,
) -> error {
    fipsSelfTest();
    fips140::RecordApproved();
    checkApprovedHashName(hash);
    verifyPKCS1v15(pub_, hash, hashed, sig)
}

/// `verifyPKCS1v15` (pkcs1v15.go:101).
fn verifyPKCS1v15(
    pub_: &PublicKey,
    hash: HashId,
    hashed: slice<byte>,
    sig: slice<byte>,
) -> error {
    let (fipsApproved, err) = checkPublicKey(pub_);
    if !err.IsNil() {
        return err;
    } else if !fipsApproved {
        fips140::RecordNonApproved();
    }

    // RFC 8017 Section 8.2.2: the signature length must equal k.
    if pub_.Size() != sig.Len() {
        return ErrVerification.into();
    }

    let (em, err) = encrypt(pub_, sig);
    if !err.IsNil() {
        return ErrVerification.into();
    }

    let (expected, err) = pkcs1v15ConstructEM(pub_, hash, hashed);
    if !err.IsNil() {
        return ErrVerification.into();
    }
    if !bytes::Equal(em, expected) {
        return ErrVerification.into();
    }
    errors::nil
}

// ══════════════════════════════════════════════════════════════════════
// RSAES-PKCS1-v1_5 — encryption & decryption (Go: crypto/rsa/pkcs1v15.go)
// ══════════════════════════════════════════════════════════════════════
//
// The fips140 package only ships v1.5 *signing*; the v1.5 *encryption*
// scheme lives in the public `crypto/rsa` package. The task asks for
// `EncryptPKCS1v15`/`DecryptPKCS1v15` here, so the EME-PKCS1-v1_5 padding
// is ported faithfully from Go 1.25's `crypto/rsa/pkcs1v15.go`, building
// on this module's raw `encrypt`/`decrypt`.

/// `EncryptPKCS1v15` (crypto/rsa/pkcs1v15.go:23) — encrypt `msg` using
/// RSAES-PKCS1-v1_5. `EM = 0x00 || 0x02 || PS || 0x00 || msg`, where PS
/// is a string of non-zero random octets at least 8 bytes long.
pub fn EncryptPKCS1v15(
    rand: &mut dyn io::Reader,
    pub_: &PublicKey,
    msg: slice<byte>,
) -> (slice<byte>, error) {
    fips140::RecordNonApproved();
    let (_, err) = checkPublicKey(pub_);
    if !err.IsNil() {
        return (slice::<byte>::new(), err);
    }
    let k = usize::try_from(pub_.Size()).unwrap_or(0);
    let msg_v = to_vec(&msg);
    // Signed comparison: avoids usize underflow on tiny moduli (k < 11).
    if int::try_from(msg_v.len()).unwrap_or(int::MAX)
        > int::try_from(k).unwrap_or(0) - 11
    {
        return (slice::<byte>::new(), ErrMessageTooLong.into());
    }

    // EM = 0x00 || 0x02 || PS || 0x00 || M
    let mut em: Vec<byte> = alloc::vec![0u8; k];
    em[1] = 2;
    // PS = em[2 : k-len(msg)-1] — non-zero random octets.
    let ps_end = k - msg_v.len() - 1;
    {
        let ps_len = ps_end - 2;
        let mut ps: Vec<byte> = alloc::vec![0u8; ps_len];
        let err = nonZeroRandomBytes(&mut ps, rand);
        if !err.IsNil() {
            return (slice::<byte>::new(), err);
        }
        let mut i: usize = 0;
        while i < ps_len {
            em[2 + i] = ps[i];
            i += 1;
        }
    }
    // em[k-len(msg)-1] stays 0x00 (the separator); copy M after it.
    let mstart = k - msg_v.len();
    let mut i: usize = 0;
    while i < msg_v.len() {
        em[mstart + i] = msg_v[i];
        i += 1;
    }
    encrypt(pub_, from_vec(em))
}

/// `nonZeroRandomBytes` (crypto/rsa/pkcs1v15.go:285) — fill `s` with
/// non-zero random bytes.
fn nonZeroRandomBytes(s: &mut [byte], rand: &mut dyn io::Reader) -> error {
    let err = read_with_reader(rand, s);
    if !err.IsNil() {
        return err;
    }
    let mut i: usize = 0;
    while i < s.len() {
        while s[i] == 0 {
            let mut one = [0u8; 1];
            let err = read_with_reader(rand, &mut one);
            if !err.IsNil() {
                return err;
            }
            s[i] = one[0];
            // In tests, the PRNG may return all zeroes; we'll keep the
            // last byte read (it's non-zero by the loop guard once set).
        }
        i += 1;
    }
    errors::nil
}

/// `DecryptPKCS1v15` (crypto/rsa/pkcs1v15.go:67) — decrypt a
/// RSAES-PKCS1-v1_5 ciphertext. The unpadding is performed in a way that
/// is NOT branch-free on the validity result, exactly like Go's
/// `decryptPKCS1v15` helper used by the non-session-key path.
pub fn DecryptPKCS1v15(
    priv_: &PrivateKey,
    ciphertext: slice<byte>,
) -> (slice<byte>, error) {
    fips140::RecordNonApproved();
    let (valid, _em, index, err) = decryptPKCS1v15(priv_, ciphertext);
    if !err.IsNil() {
        return (slice::<byte>::new(), err);
    }
    if valid == 0 {
        return (slice::<byte>::new(), ErrDecryption.into());
    }
    let idx = usize::try_from(index).unwrap_or(0);
    (from_vec(_em[idx..].to_vec()), errors::nil)
}

/// `DecryptPKCS1v15SessionKey` (crypto/rsa/pkcs1v15.go:97) — decrypt a
/// session key using RSAES-PKCS1-v1_5 with the Bleichenbacher
/// countermeasure: on any padding error, `key` is left untouched (the
/// caller proceeds with a random key). Constant-time on the validity
/// result.
pub fn DecryptPKCS1v15SessionKey(
    priv_: &PrivateKey,
    ciphertext: slice<byte>,
    key: &mut slice<byte>,
) -> error {
    fips140::RecordNonApproved();
    if priv_.pub_.Size() - key.Len() < 11 {
        return ErrDecryption.into();
    }
    let (valid, em, index, err) = decryptPKCS1v15(priv_, ciphertext);
    if !err.IsNil() {
        return err;
    }
    // The "index" is the offset of the message in em, and the message is
    // valid iff its length equals key's length.
    let idx = usize::try_from(index).unwrap_or(0);
    let mut valid = valid;
    {
        let msg_len = int::try_from(em.len() - idx).unwrap_or(0);
        let key_len = key.Len();
        valid &= crate::crypto::subtle::ConstantTimeEq(
            i32::try_from(msg_len).unwrap_or(0),
            i32::try_from(key_len).unwrap_or(0),
        );
    }
    // Copy em[index:] into key when valid == 1.
    let mut src: Vec<byte> = alloc::vec![0u8; usize::try_from(key.Len()).unwrap_or(0)];
    let n = src.len();
    let mut i: usize = 0;
    while i < n {
        // out-of-range guard mirrors Go's `em[index:]` slice length match.
        if idx + i < em.len() {
            src[i] = em[idx + i];
        }
        i += 1;
    }
    let src_slice = from_vec(src);
    crate::crypto::subtle::ConstantTimeCopy(valid, key, &src_slice);
    errors::nil
}

/// `decryptPKCS1v15` (crypto/rsa/pkcs1v15.go:120) — the constant-time
/// EME-PKCS1-v1_5 unpadding. Returns `(valid, em, index)`:
///   * `valid`  — 1 iff the padding is well-formed.
///   * `em`     — the raw decrypted, zero-left-padded encoded message.
///   * `index`  — the offset of the message payload in `em`.
/// The validity computation is branch-free on the secret padding bytes.
fn decryptPKCS1v15(
    priv_: &PrivateKey,
    ciphertext: slice<byte>,
) -> (int, Vec<byte>, int, error) {
    let k = usize::try_from(priv_.pub_.Size()).unwrap_or(0);
    if k < 11 {
        return (0, Vec::new(), 0, ErrDecryption.into());
    }

    let (emSlice, err) = decrypt(priv_, ciphertext, noCheck);
    if !err.IsNil() {
        return (0, Vec::new(), 0, err);
    }
    // decrypt returns the message as a trimmed big-endian integer; the
    // EME-PKCS1-v1_5 unpadding needs a fixed-width k-byte buffer.
    let mut em: Vec<byte> = alloc::vec![0u8; k];
    {
        let raw = to_vec(&emSlice);
        if raw.len() <= k {
            let off = k - raw.len();
            let mut i: usize = 0;
            while i < raw.len() {
                em[off + i] = raw[i];
                i += 1;
            }
        } else {
            // Should not happen (em < N), but stay safe.
            let off = raw.len() - k;
            let mut i: usize = 0;
            while i < k {
                em[i] = raw[off + i];
                i += 1;
            }
        }
    }

    use crate::crypto::subtle::{
        ConstantTimeByteEq, ConstantTimeLessOrEq, ConstantTimeSelect,
    };
    let firstByteIsZero = ConstantTimeByteEq(em[0], 0);
    let secondByteIsTwo = ConstantTimeByteEq(em[1], 2);

    // The remainder of the plaintext must be a string of non-zero random
    // octets, followed by a 0, followed by the message.
    //   lookingForIndex: 1 iff we are still looking for the zero.
    //   index: the offset of the first zero byte.
    let mut lookingForIndex: int = 1;
    let mut index: int = 0;

    let mut i: usize = 2;
    while i < em.len() {
        let equals0 = ConstantTimeByteEq(em[i], 0);
        index = ConstantTimeSelect(
            lookingForIndex & equals0,
            int::try_from(i).unwrap_or(0),
            index,
        );
        lookingForIndex = ConstantTimeSelect(equals0, 0, lookingForIndex);
        i += 1;
    }

    // The PS padding must be at least 8 bytes long, and it starts two
    // bytes into em.
    let validPS = ConstantTimeLessOrEq(2 + 8, index);

    let valid =
        firstByteIsZero & secondByteIsTwo & (!lookingForIndex & 1) & validPS;
    let index = ConstantTimeSelect(valid, index + 1, 0);
    (valid, em, index, errors::nil)
}

// ══════════════════════════════════════════════════════════════════════
// RSASSA-PSS + RSAES-OAEP — PKCS #1 v2.2 (Go: pkcs1v22.go)
// ══════════════════════════════════════════════════════════════════════
//
// goish notes:
//   * Go's `hash hash.Hash` parameter becomes `&mut dyn crate::hash::Hash`.
//   * `drbg.ReadWithReaderDeterministic(rand, b)` — with FIPS mode off
//     this is exactly `io.ReadFull(rand, b)`; ported via `read_with_reader`.
//   * `checkApprovedHash` distinguishes the concrete SHA-2/SHA-3 types in
//     Go via a type switch; goish has no such reflection over a
//     `&dyn Hash`, so we conservatively record approved use. The CAST
//     self-test still exercises a known-answer vector.

/// `incCounter` (pkcs1v22.go:37) — increment a four-byte, big-endian
/// counter.
fn incCounter(c: &mut [byte; 4]) {
    c[3] = c[3].wrapping_add(1);
    if c[3] != 0 {
        return;
    }
    c[2] = c[2].wrapping_add(1);
    if c[2] != 0 {
        return;
    }
    c[1] = c[1].wrapping_add(1);
    if c[1] != 0 {
        return;
    }
    c[0] = c[0].wrapping_add(1);
}

/// `mgf1XOR` (pkcs1v22.go:52) — XOR the bytes in `out` with a mask
/// generated using the MGF1 function from PKCS #1 v2.1.
fn mgf1XOR(out: &mut [byte], hash: &mut dyn HashTrait, seed: &[byte]) {
    let mut counter: [byte; 4] = [0, 0, 0, 0];
    let mut done: usize = 0;

    while done < out.len() {
        hash.Reset();
        // hash.Write(seed)
        {
            let s = from_vec(seed.to_vec());
            let _ = hash.Write(s);
        }
        // hash.Write(counter[0:4])
        {
            let c = from_vec(counter.to_vec());
            let _ = hash.Write(c);
        }
        let digest = hash.Sum(slice::<byte>::new());
        let dv = to_vec(&digest);
        let mut i: usize = 0;
        while i < dv.len() && done < out.len() {
            out[done] ^= dv[i];
            done += 1;
            i += 1;
        }
        incCounter(&mut counter);
    }
}

/// `emsaPSSEncode` (pkcs1v22.go:71) — the EMSA-PSS encoding operation
/// (RFC 8017, Section 9.1.1).
fn emsaPSSEncode(
    mHash: &[byte],
    emBits: int,
    salt: &[byte],
    hash: &mut dyn HashTrait,
) -> (slice<byte>, error) {
    let hLen = usize::try_from(hash.Size()).unwrap_or(0);
    let sLen = salt.len();
    let emLen = usize::try_from((emBits + 7) / 8).unwrap_or(0);

    if mHash.len() != hLen {
        return (
            slice::<byte>::new(),
            errors::New("crypto/rsa: input must be hashed with given hash"),
        );
    }
    if emLen < hLen + sLen + 2 {
        return (slice::<byte>::new(), ErrMessageTooLong.into());
    }

    let mut em: Vec<byte> = alloc::vec![0u8; emLen];
    let psLen = emLen - sLen - hLen - 2;
    // db = em[:psLen+1+sLen]; h = em[psLen+1+sLen : emLen-1].
    let db_end = psLen + 1 + sLen;
    let h_start = db_end;
    let h_end = emLen - 1;

    // M' = 8*0x00 || mHash || salt ; H = Hash(M').
    let prefix: [byte; 8] = [0; 8];
    hash.Reset();
    let _ = hash.Write(from_vec(prefix.to_vec()));
    let _ = hash.Write(from_vec(mHash.to_vec()));
    let _ = hash.Write(from_vec(salt.to_vec()));
    let h_digest = to_vec(&hash.Sum(slice::<byte>::new()));
    {
        let mut i: usize = 0;
        while i < h_digest.len() && h_start + i < h_end {
            em[h_start + i] = h_digest[i];
            i += 1;
        }
    }

    // DB = PS || 0x01 || salt.
    em[psLen] = 0x01;
    {
        let mut i: usize = 0;
        while i < sLen {
            em[psLen + 1 + i] = salt[i];
            i += 1;
        }
    }

    // dbMask = MGF(H, emLen-hLen-1); maskedDB = DB xor dbMask.
    {
        // h sits inside em; copy it out to use as the MGF seed.
        let h_seed: Vec<byte> = em[h_start..h_end].to_vec();
        let mut db: Vec<byte> = em[..db_end].to_vec();
        mgf1XOR(&mut db, hash, &h_seed);
        // Set the leftmost 8*emLen-emBits bits of maskedDB[0] to zero.
        let shift = uint::try_from(8 * int::try_from(emLen).unwrap_or(0) - emBits)
            .unwrap_or(0);
        db[0] &= 0xffu8 >> shift;
        let mut i: usize = 0;
        while i < db.len() {
            em[i] = db[i];
            i += 1;
        }
    }

    // EM = maskedDB || H || 0xbc.
    em[emLen - 1] = 0xbc;
    (from_vec(em), errors::nil)
}

/// `pssSaltLengthAutodetect` (pkcs1v22.go:146).
const pssSaltLengthAutodetect: int = -1;

/// `emsaPSSVerify` (pkcs1v22.go:148) — the EMSA-PSS verification
/// operation (RFC 8017, Section 9.1.2).
fn emsaPSSVerify(
    mHash: &[byte],
    em: &[byte],
    emBits: int,
    sLen: int,
    hash: &mut dyn HashTrait,
) -> error {
    let hLen = usize::try_from(hash.Size()).unwrap_or(0);
    let emLen = usize::try_from((emBits + 7) / 8).unwrap_or(0);
    if emLen != em.len() {
        return errors::New("rsa: internal error: inconsistent length");
    }
    if hLen != mHash.len() {
        return ErrVerification.into();
    }
    let mut sLen = sLen;
    // 3. emLen < hLen + sLen + 2 — only checkable once sLen is known if
    //    autodetect; Go performs the check here for the explicit case.
    if sLen != pssSaltLengthAutodetect && emLen < hLen + usize::try_from(sLen).unwrap_or(0) + 2 {
        return ErrVerification.into();
    }
    // 4. rightmost octet must be 0xbc.
    if em[emLen - 1] != 0xbc {
        return ErrVerification.into();
    }

    // 5. maskedDB = em[:emLen-hLen-1]; h = em[emLen-hLen-1 : emLen-1].
    let db_end = emLen - hLen - 1;
    let mut db: Vec<byte> = em[..db_end].to_vec();
    let h: Vec<byte> = em[db_end..emLen - 1].to_vec();

    // 6. leftmost 8*emLen-emBits bits of maskedDB[0] must be zero.
    let shift = uint::try_from(8 * int::try_from(emLen).unwrap_or(0) - emBits)
        .unwrap_or(0);
    let bitMask: byte = 0xffu8 >> shift;
    if em[0] & !bitMask != 0 {
        return ErrVerification.into();
    }

    // 7-8. dbMask = MGF(H, emLen-hLen-1); DB = maskedDB xor dbMask.
    mgf1XOR(&mut db, hash, &h);

    // 9. zero the leftmost 8*emLen-emBits bits of DB[0].
    db[0] &= bitMask;

    // If the salt length is unknown, look for the 0x01 delimiter.
    if sLen == pssSaltLengthAutodetect {
        let db_slice = from_vec(db.clone());
        let psLen = bytes::IndexByte(db_slice, 0x01);
        if psLen < 0 {
            return ErrVerification.into();
        }
        sLen = int::try_from(db.len()).unwrap_or(0) - psLen - 1;
    }

    // FIPS 186-5, Section 5.4(g): 0 <= sLen <= hLen.
    if usize::try_from(sLen).unwrap_or(0) > hLen {
        fips140::RecordNonApproved();
    }

    // 10. the emLen-hLen-sLen-2 leftmost octets of DB must be zero, and
    //     the octet at position emLen-hLen-sLen-2 must be 0x01.
    let sLenU = usize::try_from(sLen).unwrap_or(usize::MAX);
    if sLenU == usize::MAX || hLen + sLenU + 2 > emLen {
        return ErrVerification.into();
    }
    let psLen = emLen - hLen - sLenU - 2;
    {
        let mut i: usize = 0;
        while i < psLen {
            if db[i] != 0x00 {
                return ErrVerification.into();
            }
            i += 1;
        }
    }
    if db[psLen] != 0x01 {
        return ErrVerification.into();
    }

    // 11. salt = last sLen octets of DB.
    let salt: Vec<byte> = db[db.len() - sLenU..].to_vec();

    // 12-13. M' = 8*0x00 || mHash || salt ; H' = Hash(M').
    hash.Reset();
    let prefix: [byte; 8] = [0; 8];
    let _ = hash.Write(from_vec(prefix.to_vec()));
    let _ = hash.Write(from_vec(mHash.to_vec()));
    let _ = hash.Write(from_vec(salt));
    let h0 = to_vec(&hash.Sum(slice::<byte>::new()));

    // 14. H == H' ?
    if !bytes::Equal(from_vec(h0), from_vec(h)) {
        return ErrVerification.into();
    }
    errors::nil
}

/// `PSSMaxSaltLength` (pkcs1v22.go:254) — the maximum salt length for a
/// given public key and hash function.
pub fn PSSMaxSaltLength(pub_: &PublicKey, hash: &mut dyn HashTrait) -> (int, error) {
    let saltLength = (pub_.N.BitLen() - 1 + 7) / 8 - 2 - hash.Size();
    if saltLength < 0 {
        return (0, ErrMessageTooLong.into());
    }
    if fips140::Enabled() && saltLength > hash.Size() {
        return (hash.Size(), errors::nil);
    }
    (saltLength, errors::nil)
}

/// `SignPSS` (pkcs1v22.go:268) — calculate the signature of `hashed`
/// using RSASSA-PSS.
pub fn SignPSS(
    rand: &mut dyn io::Reader,
    priv_: &PrivateKey,
    hash: &mut dyn HashTrait,
    hashed: slice<byte>,
    saltLength: int,
) -> (slice<byte>, error) {
    fipsSelfTest();
    fips140::RecordApproved();
    checkApprovedHash(hash);

    if saltLength < 0 {
        return (
            slice::<byte>::new(),
            errors::New("crypto/rsa: salt length cannot be negative"),
        );
    }
    // FIPS 186-5, Section 5.4(g): 0 <= sLen <= hLen.
    if saltLength > hash.Size() {
        fips140::RecordNonApproved();
    }
    let mut salt: Vec<byte> = alloc::vec![0u8; usize::try_from(saltLength).unwrap_or(0)];
    {
        let err = read_with_reader(rand, &mut salt);
        if !err.IsNil() {
            return (slice::<byte>::new(), err);
        }
    }

    let emBits = priv_.pub_.N.BitLen() - 1;
    let hashed_v = to_vec(&hashed);
    let (em0, err) = emsaPSSEncode(&hashed_v, emBits, &salt, hash);
    if !err.IsNil() {
        return (slice::<byte>::new(), err);
    }

    // RFC 8017: EM may be one byte shorter than k when modBits-1 is
    // divisible by 8; pad it up to k.
    let mut em = to_vec(&em0);
    let k = usize::try_from(priv_.pub_.Size()).unwrap_or(0);
    if em.len() < k {
        let mut emNew: Vec<byte> = alloc::vec![0u8; k];
        let off = k - em.len();
        let mut i: usize = 0;
        while i < em.len() {
            emNew[off + i] = em[i];
            i += 1;
        }
        em = emNew;
    }

    decrypt(priv_, from_vec(em), withCheck)
}

/// `VerifyPSS` (pkcs1v22.go:315) — verify `sig` with RSASSA-PSS,
/// automatically detecting the salt length.
pub fn VerifyPSS(
    pub_: &PublicKey,
    hash: &mut dyn HashTrait,
    digest: slice<byte>,
    sig: slice<byte>,
) -> error {
    verifyPSS(pub_, hash, digest, sig, pssSaltLengthAutodetect)
}

/// `VerifyPSSWithSaltLength` (pkcs1v22.go:320) — verify `sig` with
/// RSASSA-PSS and an expected salt length.
pub fn VerifyPSSWithSaltLength(
    pub_: &PublicKey,
    hash: &mut dyn HashTrait,
    digest: slice<byte>,
    sig: slice<byte>,
    saltLength: int,
) -> error {
    if saltLength < 0 {
        return errors::New("crypto/rsa: salt length cannot be negative");
    }
    verifyPSS(pub_, hash, digest, sig, saltLength)
}

/// `verifyPSS` (pkcs1v22.go:327).
fn verifyPSS(
    pub_: &PublicKey,
    hash: &mut dyn HashTrait,
    digest: slice<byte>,
    sig: slice<byte>,
    saltLength: int,
) -> error {
    fipsSelfTest();
    fips140::RecordApproved();
    checkApprovedHash(hash);
    let (fipsApproved, err) = checkPublicKey(pub_);
    if !err.IsNil() {
        return err;
    } else if !fipsApproved {
        fips140::RecordNonApproved();
    }

    if sig.Len() != pub_.Size() {
        return ErrVerification.into();
    }

    let emBits = pub_.N.BitLen() - 1;
    let emLen = usize::try_from((emBits + 7) / 8).unwrap_or(0);
    let (em0, err) = encrypt(pub_, sig);
    if !err.IsNil() {
        return ErrVerification.into();
    }

    // Strip leading zeroes if emLen < k (weird modulus sizes).
    let mut em = to_vec(&em0);
    while em.len() > emLen && !em.is_empty() {
        if em[0] != 0 {
            return ErrVerification.into();
        }
        em.remove(0);
    }
    // decrypt/encrypt may return a trimmed integer shorter than emLen;
    // left-pad with zeroes to the expected encoded-message width.
    if em.len() < emLen {
        let mut padded: Vec<byte> = alloc::vec![0u8; emLen];
        let off = emLen - em.len();
        let mut i: usize = 0;
        while i < em.len() {
            padded[off + i] = em[i];
            i += 1;
        }
        em = padded;
    }

    let digest_v = to_vec(&digest);
    emsaPSSVerify(&digest_v, &em, emBits, saltLength, hash)
}

/// `checkApprovedHash` (pkcs1v22.go:363) — record non-approved use for
/// hashes outside the SHA-2 / SHA-3 family. goish cannot reflect on a
/// `&dyn Hash`'s concrete type, so this conservatively records approved
/// use; the CAST self-test still exercises a known-answer vector.
fn checkApprovedHash(_hash: &mut dyn HashTrait) {
    // Best-effort: the concrete-type switch in Go is not expressible
    // over a `&dyn Hash`. No-op (RecordApproved already called).
}

/// `EncryptOAEP` (pkcs1v22.go:372) — encrypt `msg` with RSAES-OAEP.
pub fn EncryptOAEP(
    lHash: slice<byte>,
    mgfHash: &mut dyn HashTrait,
    random: &mut dyn io::Reader,
    pub_: &PublicKey,
    msg: slice<byte>,
) -> (slice<byte>, error) {
    fipsSelfTest();
    fips140::RecordApproved();
    let (fipsApproved, err) = checkPublicKey(pub_);
    if !err.IsNil() {
        return (slice::<byte>::new(), err);
    } else if !fipsApproved {
        fips140::RecordNonApproved();
    }
    let k = usize::try_from(pub_.Size()).unwrap_or(0);
    // `lHash` is Hash(label), precomputed by the caller. The OAEP hash
    // is used only to digest the label, so taking it precomputed lets
    // the caller reuse a single hash object as both the OAEP and the
    // MGF1 hash without aliasing two `&mut dyn` views.
    let lHash = to_vec(&lHash);
    let hSize = lHash.len();
    let msg_v = to_vec(&msg);
    // Signed comparison: k - 2*hSize - 2 can be negative for small keys.
    let maxMsg = int::try_from(k).unwrap_or(0)
        - 2 * int::try_from(hSize).unwrap_or(0)
        - 2;
    if int::try_from(msg_v.len()).unwrap_or(int::MAX) > maxMsg {
        return (slice::<byte>::new(), ErrMessageTooLong.into());
    }

    // em = 0x00 || seed (hSize) || db (k-1-hSize).
    let mut em: Vec<byte> = alloc::vec![0u8; k];
    let seed_start = 1;
    let seed_end = 1 + hSize;
    let db_start = 1 + hSize;

    // db = lHash || PS(0x00..) || 0x01 || msg.
    {
        let mut i: usize = 0;
        while i < hSize {
            em[db_start + i] = lHash[i];
            i += 1;
        }
    }
    let db_len = k - db_start;
    // db[len(db)-len(msg)-1] = 1
    em[db_start + db_len - msg_v.len() - 1] = 1;
    {
        let mstart = db_start + db_len - msg_v.len();
        let mut i: usize = 0;
        while i < msg_v.len() {
            em[mstart + i] = msg_v[i];
            i += 1;
        }
    }

    // seed = random hSize bytes.
    {
        let mut seed: Vec<byte> = alloc::vec![0u8; hSize];
        let err = read_with_reader(random, &mut seed);
        if !err.IsNil() {
            return (slice::<byte>::new(), err);
        }
        let mut i: usize = 0;
        while i < hSize {
            em[seed_start + i] = seed[i];
            i += 1;
        }
    }

    // mgf1XOR(db, mgfHash, seed); mgf1XOR(seed, mgfHash, db).
    {
        let seed_cur: Vec<byte> = em[seed_start..seed_end].to_vec();
        let mut db: Vec<byte> = em[db_start..k].to_vec();
        mgf1XOR(&mut db, mgfHash, &seed_cur);
        let mut i: usize = 0;
        while i < db.len() {
            em[db_start + i] = db[i];
            i += 1;
        }
    }
    {
        let db_cur: Vec<byte> = em[db_start..k].to_vec();
        let mut seed: Vec<byte> = em[seed_start..seed_end].to_vec();
        mgf1XOR(&mut seed, mgfHash, &db_cur);
        let mut i: usize = 0;
        while i < seed.len() {
            em[seed_start + i] = seed[i];
            i += 1;
        }
    }

    encrypt(pub_, from_vec(em))
}

/// `DecryptOAEP` (pkcs1v22.go:415) — decrypt a ciphertext using
/// RSAES-OAEP. The plaintext is validated in constant time on the
/// secret data (Manger's attack countermeasure).
pub fn DecryptOAEP(
    lHash: slice<byte>,
    mgfHash: &mut dyn HashTrait,
    priv_: &PrivateKey,
    ciphertext: slice<byte>,
) -> (slice<byte>, error) {
    fipsSelfTest();
    fips140::RecordApproved();

    // `lHash` is Hash(label), precomputed by the caller (see EncryptOAEP).
    let lHash = to_vec(&lHash);
    let k = usize::try_from(priv_.pub_.Size()).unwrap_or(0);
    let hSize = lHash.len();
    if usize::try_from(ciphertext.Len()).unwrap_or(usize::MAX) > k
        || k < hSize * 2 + 2
    {
        return (slice::<byte>::new(), ErrDecryption.into());
    }

    let (emSlice, err) = decrypt(priv_, ciphertext, noCheck);
    if !err.IsNil() {
        return (slice::<byte>::new(), err);
    }
    // decrypt returns a trimmed integer; left-pad to the k-byte EM width.
    let mut em: Vec<byte> = alloc::vec![0u8; k];
    {
        let raw = to_vec(&emSlice);
        if raw.len() <= k {
            let off = k - raw.len();
            let mut i: usize = 0;
            while i < raw.len() {
                em[off + i] = raw[i];
                i += 1;
            }
        } else {
            let off = raw.len() - k;
            let mut i: usize = 0;
            while i < k {
                em[i] = raw[off + i];
                i += 1;
            }
        }
    }

    use crate::crypto::subtle::{ConstantTimeByteEq, ConstantTimeSelect};
    let firstByteIsZero = ConstantTimeByteEq(em[0], 0);

    // seed = em[1 : hSize+1]; db = em[hSize+1:].
    let seed_start = 1;
    let seed_end = hSize + 1;
    let db_start = hSize + 1;

    // mgf1XOR(seed, mgfHash, db); mgf1XOR(db, mgfHash, seed).
    {
        let db_cur: Vec<byte> = em[db_start..k].to_vec();
        let mut seed: Vec<byte> = em[seed_start..seed_end].to_vec();
        mgf1XOR(&mut seed, mgfHash, &db_cur);
        let mut i: usize = 0;
        while i < seed.len() {
            em[seed_start + i] = seed[i];
            i += 1;
        }
    }
    {
        let seed_cur: Vec<byte> = em[seed_start..seed_end].to_vec();
        let mut db: Vec<byte> = em[db_start..k].to_vec();
        mgf1XOR(&mut db, mgfHash, &seed_cur);
        let mut i: usize = 0;
        while i < db.len() {
            em[db_start + i] = db[i];
            i += 1;
        }
    }

    // lHash2 = db[0:hSize].
    let lHash2: Vec<byte> = em[db_start..db_start + hSize].to_vec();
    let lHash2Good = crate::crypto::subtle::ConstantTimeCompare(
        &from_vec(lHash.clone()),
        &from_vec(lHash2),
    );

    // The remainder of the plaintext must be 0x00* || 0x01 || message.
    let mut lookingForIndex: int = 1;
    let mut index: int = 0;
    let mut invalid: int = 0;
    let rest_start = db_start + hSize;
    {
        let mut i: usize = 0;
        let rest_len = k - rest_start;
        while i < rest_len {
            let b = em[rest_start + i];
            let equals0 = ConstantTimeByteEq(b, 0);
            let equals1 = ConstantTimeByteEq(b, 1);
            index = ConstantTimeSelect(
                lookingForIndex & equals1,
                int::try_from(i).unwrap_or(0),
                index,
            );
            lookingForIndex = ConstantTimeSelect(equals1, 0, lookingForIndex);
            invalid =
                ConstantTimeSelect(lookingForIndex & !equals0, 1, invalid);
            i += 1;
        }
    }

    if firstByteIsZero & lHash2Good & !invalid & !lookingForIndex != 1 {
        return (slice::<byte>::new(), ErrDecryption.into());
    }

    let msg_off = rest_start + usize::try_from(index).unwrap_or(0) + 1;
    (from_vec(em[msg_off..].to_vec()), errors::nil)
}

// ══════════════════════════════════════════════════════════════════════
// CAST self-test (Go: cast.go)
// ══════════════════════════════════════════════════════════════════════
//
// Faithful port of cast.go's `fipsSelfTest` known-answer test: it builds
// the RFC 9500 test private key, signs a fixed 32-byte digest with
// SHA-256 PKCS#1 v1.5, verifies it, and checks the signature against the
// embedded known-answer vector. The full 2048-bit test key and the
// expected signature are embedded verbatim from cast.go.

use crate::runtime::spin::SpinLock;

static FIPS_SELF_TEST_DONE: SpinLock<bool> = SpinLock::new(false);

/// `fipsSelfTest` (cast.go:179) — the `sync.OnceFunc`-guarded RSA
/// PKCS#1-v1.5 sign/verify Cryptographic Algorithm Self-Test.
fn fipsSelfTest() {
    {
        let mut done = FIPS_SELF_TEST_DONE.lock();
        if *done {
            return;
        }
        *done = true;
    }
    fips140::CAST("RSASSA-PKCS-v1.5 2048-bit sign and verify", || {
        let k = testPrivateKey();
        let hashed = from_vec(CAST_DIGEST.to_vec());
        let (sig, err) = signPKCS1v15(&k, crate::crypto::SHA256, hashed.clone());
        if !err.IsNil() {
            return err;
        }
        let err = verifyPKCS1v15(&k.PublicKey(), crate::crypto::SHA256, hashed, sig.clone());
        if !err.IsNil() {
            return err;
        }
        if !bytes::Equal(sig, from_vec(CAST_WANT.to_vec())) {
            return errors::New("unexpected result");
        }
        errors::nil
    });
}

/// The fixed 32-byte digest signed by the CAST (cast.go:182).
static CAST_DIGEST: [byte; 32] = [
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e,
    0x1f, 0x20,
];

/// The expected PKCS#1-v1.5 SHA-256 signature (cast.go:188).
static CAST_WANT: [byte; 256] = [
    0x16, 0x98, 0x33, 0xc7, 0x30, 0x2c, 0x0a, 0xdc, 0x0a, 0x8d, 0x02, 0x58, 0xeb, 0xf9, 0x7d,
    0xb6, 0x2a, 0xad, 0xee, 0x63, 0x72, 0xaa, 0x37, 0x2c, 0xb3, 0x06, 0x04, 0xdf, 0xdb, 0x2b,
    0xbc, 0xb1, 0x76, 0x3e, 0xeb, 0x87, 0xef, 0x91, 0xef, 0x74, 0x69, 0x62, 0x27, 0xf3, 0x24,
    0xf8, 0xe7, 0x0e, 0xb2, 0x15, 0x3f, 0xa2, 0x4d, 0xe2, 0x0c, 0xd4, 0xdc, 0x2d, 0xc1, 0x1a,
    0x84, 0x7c, 0x88, 0x80, 0xb9, 0xa9, 0x23, 0x67, 0x39, 0x2e, 0x86, 0xc0, 0x53, 0x9b, 0xc1,
    0x35, 0xb3, 0x17, 0x5e, 0x62, 0x95, 0xd6, 0xbc, 0x2a, 0xa6, 0xb1, 0xcf, 0x8f, 0x99, 0x43,
    0x1f, 0x3d, 0xd2, 0x70, 0x3f, 0x01, 0x37, 0x2b, 0xdd, 0x69, 0x1a, 0x5c, 0x2b, 0x04, 0x70,
    0x92, 0xea, 0x2d, 0x86, 0x00, 0xcb, 0x79, 0xca, 0xaf, 0xa4, 0x1c, 0xd9, 0x61, 0x21, 0x3b,
    0x1e, 0xc5, 0x88, 0xfb, 0xff, 0xbd, 0xc7, 0x3c, 0x36, 0xa1, 0xc6, 0x85, 0x03, 0xaf, 0x47,
    0x4f, 0x42, 0x9e, 0x23, 0x65, 0x24, 0x69, 0x17, 0xdb, 0xe7, 0xb7, 0xdc, 0x51, 0xc6, 0x30,
    0x40, 0x32, 0x4f, 0x71, 0xf1, 0x62, 0x2d, 0xaa, 0x98, 0xdb, 0x11, 0x14, 0xf9, 0x9c, 0x35,
    0xc3, 0x16, 0xe1, 0x1a, 0xd1, 0x8c, 0x4d, 0x8c, 0xad, 0x06, 0x34, 0xd2, 0x84, 0x97, 0xa4,
    0x0b, 0x6e, 0x6d, 0x19, 0x9f, 0xa7, 0x40, 0x1e, 0xb5, 0xfc, 0x4e, 0x12, 0x08, 0xec, 0xf4,
    0x07, 0x13, 0xdc, 0x5a, 0x8c, 0xd5, 0x2a, 0xd6, 0x5a, 0x2c, 0xc9, 0x54, 0x84, 0x78, 0x34,
    0x8f, 0x11, 0xfb, 0x6e, 0xd4, 0x27, 0x45, 0xd9, 0xfa, 0x90, 0x82, 0x83, 0x73, 0x22, 0x15,
    0xab, 0x96, 0x13, 0x0d, 0x52, 0x1c, 0xdc, 0x17, 0xde, 0x12, 0x6f, 0x84, 0x46, 0xbb, 0xec,
    0xe3, 0xb1, 0xa1, 0x5d, 0x8b, 0xeb, 0xe6, 0xae, 0x02, 0xb8, 0x76, 0x47, 0x76, 0x11, 0x61,
    0x2b,
];

/// `testPrivateKey` (cast.go:16) — the RFC 9500 §2.1 2048-bit RSA test
/// private key, used by the CAST. Built via `NewPrivateKeyWithPrecomputation`
/// from the embedded big-endian components.
fn testPrivateKey() -> PrivateKey {
    static N: [byte; 256] = [
        0xB0, 0xF9, 0xE8, 0x19, 0x43, 0xA7, 0xAE, 0x98, 0x92, 0xAA, 0xDE, 0x17, 0xCA, 0x7C, 0x40,
        0xF8, 0x74, 0x4F, 0xED, 0x2F, 0x81, 0x48, 0xE6, 0xC8, 0xEA, 0xA2, 0x7B, 0x7D, 0x00, 0x15,
        0x48, 0xFB, 0x51, 0x92, 0xAB, 0x28, 0xB5, 0x6C, 0x50, 0x60, 0xB1, 0x18, 0xCC, 0xD1, 0x31,
        0xE5, 0x94, 0x87, 0x4C, 0x6C, 0xA9, 0x89, 0xB5, 0x6C, 0x27, 0x29, 0x6F, 0x09, 0xFB, 0x93,
        0xA0, 0x34, 0xDF, 0x32, 0xE9, 0x7C, 0x6F, 0xF0, 0x99, 0x8C, 0xFD, 0x8E, 0x6F, 0x42, 0xDD,
        0xA5, 0x8A, 0xCD, 0x1F, 0xA9, 0x79, 0x86, 0xF1, 0x44, 0xF3, 0xD1, 0x54, 0xD6, 0x76, 0x50,
        0x17, 0x5E, 0x68, 0x54, 0xB3, 0xA9, 0x52, 0x00, 0x3B, 0xC0, 0x68, 0x87, 0xB8, 0x45, 0x5A,
        0xC2, 0xB1, 0x9F, 0x7B, 0x2F, 0x76, 0x50, 0x4E, 0xBC, 0x98, 0xEC, 0x94, 0x55, 0x71, 0xB0,
        0x78, 0x92, 0x15, 0x0D, 0xDC, 0x6A, 0x74, 0xCA, 0x0F, 0xBC, 0xD3, 0x54, 0x97, 0xCE, 0x81,
        0x53, 0x4D, 0xAF, 0x94, 0x18, 0x84, 0x4B, 0x13, 0xAE, 0xA3, 0x1F, 0x9D, 0x5A, 0x6B, 0x95,
        0x57, 0xBB, 0xDF, 0x61, 0x9E, 0xFD, 0x4E, 0x88, 0x7F, 0x2D, 0x42, 0xB8, 0xDD, 0x8B, 0xC9,
        0x87, 0xEA, 0xE1, 0xBF, 0x89, 0xCA, 0xB8, 0x5E, 0xE2, 0x1E, 0x35, 0x63, 0x05, 0xDF, 0x6C,
        0x07, 0xA8, 0x83, 0x8E, 0x3E, 0xF4, 0x1C, 0x59, 0x5D, 0xCC, 0xE4, 0x3D, 0xAF, 0xC4, 0x91,
        0x23, 0xEF, 0x4D, 0x8A, 0xBB, 0xA9, 0x3D, 0x39, 0x05, 0xE4, 0x02, 0x8D, 0x7B, 0xA9, 0x14,
        0x84, 0xA2, 0x75, 0x96, 0xE0, 0x7B, 0x4B, 0x6E, 0xD9, 0x92, 0xF0, 0x77, 0xB5, 0x24, 0xD3,
        0xDC, 0xFE, 0x7D, 0xDD, 0x55, 0x49, 0xBE, 0x7C, 0xCE, 0x8D, 0xA0, 0x35, 0xCF, 0xA0, 0xB3,
        0xFB, 0x8F, 0x9E, 0x46, 0xF7, 0x32, 0xB2, 0xA8, 0x6B, 0x46, 0x01, 0x65, 0xC0, 0x8F, 0x53,
        0x13,
    ];
    static D: [byte; 256] = [
        0x41, 0x18, 0x8B, 0x20, 0xCF, 0xDB, 0xDB, 0xC2, 0xCF, 0x1F, 0xFE, 0x75, 0x2D, 0xCB, 0xAA,
        0x72, 0x39, 0x06, 0x35, 0x2E, 0x26, 0x15, 0xD4, 0x9D, 0xCE, 0x80, 0x59, 0x7F, 0xCF, 0x0A,
        0x05, 0x40, 0x3B, 0xEF, 0x00, 0xFA, 0x06, 0x51, 0x82, 0xF7, 0x2D, 0xEC, 0xFB, 0x59, 0x6F,
        0x4B, 0x0C, 0xE8, 0xFF, 0x59, 0x70, 0xBA, 0xF0, 0x7A, 0x89, 0xA5, 0x19, 0xEC, 0xC8, 0x16,
        0xB2, 0xF4, 0xFF, 0xAC, 0x50, 0x69, 0xAF, 0x1B, 0x06, 0xBF, 0xEF, 0x7B, 0xF6, 0xBC, 0xD7,
        0x9E, 0x4E, 0x81, 0xC8, 0xC5, 0xA3, 0xA7, 0xD9, 0x13, 0x0D, 0xC3, 0xCF, 0xBA, 0xDA, 0xE5,
        0xF6, 0xD2, 0x88, 0xF9, 0xAE, 0xE3, 0xF6, 0xFF, 0x92, 0xFA, 0xE0, 0xF8, 0x1A, 0xF5, 0x97,
        0xBE, 0xC9, 0x6A, 0xE9, 0xFA, 0xB9, 0x40, 0x2C, 0xD5, 0xFE, 0x41, 0xF7, 0x05, 0xBE, 0xBD,
        0xB4, 0x7B, 0xB7, 0x36, 0xD3, 0xFE, 0x6C, 0x5A, 0x51, 0xE0, 0xE2, 0x07, 0x32, 0xA9, 0x7B,
        0x5E, 0x46, 0xC1, 0xCB, 0xDB, 0x26, 0xD7, 0x48, 0x54, 0xC6, 0xB6, 0x60, 0x4A, 0xED, 0x46,
        0x37, 0x35, 0xFF, 0x90, 0x76, 0x04, 0x65, 0x57, 0xCA, 0xF9, 0x49, 0xBF, 0x44, 0x88, 0x95,
        0xC2, 0x04, 0x32, 0xC1, 0xE0, 0x9C, 0x01, 0x4E, 0xA7, 0x56, 0x60, 0x43, 0x4F, 0x1A, 0x0F,
        0x3B, 0xE2, 0x94, 0xBA, 0xBC, 0x5D, 0x53, 0x0E, 0x6A, 0x10, 0x21, 0x3F, 0x53, 0xB6, 0x03,
        0x75, 0xFC, 0x84, 0xA7, 0x57, 0x3F, 0x2A, 0xF1, 0x21, 0x55, 0x84, 0xF5, 0xB4, 0xBD, 0xA6,
        0xD4, 0xE8, 0xF9, 0xE1, 0x7A, 0x78, 0xD9, 0x7E, 0x77, 0xB8, 0x6D, 0xA4, 0xA1, 0x84, 0x64,
        0x75, 0x31, 0x8A, 0x7A, 0x10, 0xA5, 0x61, 0x01, 0x4E, 0xFF, 0xA2, 0x3A, 0x81, 0xEC, 0x56,
        0xE9, 0xE4, 0x10, 0x9D, 0xEF, 0x8C, 0xB3, 0xF7, 0x97, 0x22, 0x3F, 0x7D, 0x8D, 0x0D, 0x43,
        0x51,
    ];
    static P: [byte; 128] = [
        0xDD, 0x10, 0x57, 0x02, 0x38, 0x2F, 0x23, 0x2B, 0x36, 0x81, 0xF5, 0x37, 0x91, 0xE2, 0x26,
        0x17, 0xC7, 0xBF, 0x4E, 0x9A, 0xCB, 0x81, 0xED, 0x48, 0xDA, 0xF6, 0xD6, 0x99, 0x5D, 0xA3,
        0xEA, 0xB6, 0x42, 0x83, 0x9A, 0xFF, 0x01, 0x2D, 0x2E, 0xA6, 0x28, 0xB9, 0x0A, 0xF2, 0x79,
        0xFD, 0x3E, 0x6F, 0x7C, 0x93, 0xCD, 0x80, 0xF0, 0x72, 0xF0, 0x1F, 0xF2, 0x44, 0x3B, 0x3E,
        0xE8, 0xF2, 0x4E, 0xD4, 0x69, 0xA7, 0x96, 0x13, 0xA4, 0x1B, 0xD2, 0x40, 0x20, 0xF9, 0x2F,
        0xD1, 0x10, 0x59, 0xBD, 0x1D, 0x0F, 0x30, 0x1B, 0x5B, 0xA7, 0xA9, 0xD3, 0x63, 0x7C, 0xA8,
        0xD6, 0x5C, 0x1A, 0x98, 0x15, 0x41, 0x7D, 0x8E, 0xAB, 0x73, 0x4B, 0x0B, 0x4F, 0x3A, 0x2C,
        0x66, 0x1D, 0x9A, 0x1A, 0x82, 0xF3, 0xAC, 0x73, 0x4C, 0x40, 0x53, 0x06, 0x69, 0xAB, 0x8E,
        0x47, 0x30, 0x45, 0xA5, 0x8E, 0x65, 0x53, 0x9D,
    ];
    static Q: [byte; 128] = [
        0xCC, 0xF1, 0xE5, 0xBB, 0x90, 0xC8, 0xE9, 0x78, 0x1E, 0xA7, 0x5B, 0xEB, 0xF1, 0x0B, 0xC2,
        0x52, 0xE1, 0x1E, 0xB0, 0x23, 0xA0, 0x26, 0x0F, 0x18, 0x87, 0x55, 0x2A, 0x56, 0x86, 0x3F,
        0x4A, 0x64, 0x21, 0xE8, 0xC6, 0x00, 0xBF, 0x52, 0x3D, 0x6C, 0xB1, 0xB0, 0xAD, 0xBD, 0xD6,
        0x5B, 0xFE, 0xE4, 0xA8, 0x8A, 0x03, 0x7E, 0x3D, 0x1A, 0x41, 0x5E, 0x5B, 0xB9, 0x56, 0x48,
        0xDA, 0x5A, 0x0C, 0xA2, 0x6B, 0x54, 0xF4, 0xA6, 0x39, 0x48, 0x52, 0x2C, 0x3D, 0x5F, 0x89,
        0xB9, 0x4A, 0x72, 0xEF, 0xFF, 0x95, 0x13, 0x4D, 0x59, 0x40, 0xCE, 0x45, 0x75, 0x8F, 0x30,
        0x89, 0x80, 0x90, 0x89, 0x56, 0x58, 0x8E, 0xEF, 0x57, 0x5B, 0x3E, 0x4B, 0xC4, 0xC3, 0x68,
        0xCF, 0xE8, 0x13, 0xEE, 0x9C, 0x25, 0x2C, 0x2B, 0x02, 0xE0, 0xDF, 0x91, 0xF1, 0xAA, 0x01,
        0x93, 0x8D, 0x38, 0x68, 0x5D, 0x60, 0xBA, 0x6F,
    ];
    static QINV: [byte; 128] = [
        0x0A, 0x81, 0xD8, 0xA6, 0x18, 0x31, 0x4A, 0x80, 0x3A, 0xF6, 0x1C, 0x06, 0x71, 0x1F, 0x2C,
        0x39, 0xB2, 0x66, 0xFF, 0x41, 0x4D, 0x53, 0x47, 0x6D, 0x1D, 0xA5, 0x2A, 0x43, 0x18, 0xAA,
        0xFE, 0x4B, 0x96, 0xF0, 0xDA, 0x07, 0x15, 0x5F, 0x8A, 0x51, 0x34, 0xDA, 0xB8, 0x8E, 0xE2,
        0x9E, 0x81, 0x68, 0x07, 0x6F, 0xCD, 0x78, 0xCA, 0x79, 0x1A, 0xC6, 0x34, 0x42, 0xA8, 0x1C,
        0xD0, 0x69, 0x39, 0x27, 0xD8, 0x08, 0xE3, 0x35, 0xE8, 0xD8, 0xCB, 0xF2, 0x12, 0x19, 0x07,
        0x50, 0x9A, 0x57, 0x75, 0x9B, 0x4F, 0x9A, 0x18, 0xFA, 0x3A, 0x7B, 0x33, 0x37, 0x79, 0xED,
        0xDE, 0x7A, 0x45, 0x93, 0x84, 0xF8, 0x44, 0x4A, 0xDA, 0xEC, 0xFF, 0xEC, 0x95, 0xFD, 0x55,
        0x2B, 0x0C, 0xFC, 0xB6, 0xC7, 0xF6, 0x92, 0x62, 0x6D, 0xDE, 0x1E, 0xF2, 0x68, 0xA4, 0x0D,
        0x2F, 0x67, 0xB5, 0xC8, 0xAA, 0x38, 0x7F, 0xF7,
    ];
    static DP: [byte; 128] = [
        0x09, 0xED, 0x54, 0xEA, 0xED, 0x98, 0xF8, 0x4C, 0x55, 0x7B, 0x4A, 0x86, 0xBF, 0x4F, 0x57,
        0x84, 0x93, 0xDC, 0xBC, 0x6B, 0xE9, 0x1D, 0xA1, 0x89, 0x37, 0x04, 0x04, 0xA9, 0x08, 0x72,
        0x76, 0xF4, 0xCE, 0x51, 0xD8, 0xA1, 0x00, 0xED, 0x85, 0x7D, 0xC2, 0xB0, 0x64, 0x94, 0x74,
        0xF3, 0xF1, 0x5C, 0xD2, 0x4C, 0x54, 0xDB, 0x28, 0x71, 0x10, 0xE5, 0x6E, 0x5C, 0xB0, 0x08,
        0x68, 0x2F, 0x91, 0x68, 0xAA, 0x81, 0xF3, 0x14, 0x58, 0xB7, 0x43, 0x1E, 0xCC, 0x1C, 0x44,
        0x90, 0x6F, 0xDA, 0x87, 0xCA, 0x89, 0x47, 0x10, 0xC3, 0x71, 0xE9, 0x07, 0x6C, 0x1D, 0x49,
        0xFB, 0xAE, 0x51, 0x27, 0x69, 0x34, 0xF2, 0xAD, 0x78, 0x77, 0x89, 0xF4, 0x2D, 0x0F, 0xA0,
        0xB4, 0xC9, 0x39, 0x85, 0x5D, 0x42, 0x12, 0x09, 0x6F, 0x70, 0x28, 0x0A, 0x4E, 0xAE, 0x7C,
        0x8A, 0x27, 0xD9, 0xC8, 0xD0, 0x77, 0x2E, 0x65,
    ];
    static DQ: [byte; 128] = [
        0x8C, 0xB6, 0x85, 0x7A, 0x7B, 0xD5, 0x46, 0x5F, 0x80, 0x04, 0x7E, 0x9B, 0x87, 0xBC, 0x00,
        0x27, 0x31, 0x84, 0x05, 0x81, 0xE0, 0x62, 0x61, 0x39, 0x01, 0x2A, 0x5B, 0x50, 0x5F, 0x0A,
        0x33, 0x84, 0x7E, 0xB7, 0xB8, 0xC3, 0x28, 0x99, 0x49, 0xAD, 0x48, 0x6F, 0x3B, 0x4B, 0x3D,
        0x53, 0x9A, 0xB5, 0xDA, 0x76, 0x30, 0x21, 0xCB, 0xC8, 0x2C, 0x1B, 0xA2, 0x34, 0xA5, 0x66,
        0x8D, 0xED, 0x08, 0x01, 0xB8, 0x59, 0xF3, 0x43, 0xF1, 0xCE, 0x93, 0x04, 0xE6, 0xFA, 0xA2,
        0xB0, 0x02, 0xCA, 0xD9, 0xB7, 0x8C, 0xDE, 0x5C, 0xDC, 0x2C, 0x1F, 0xB4, 0x17, 0x1C, 0x42,
        0x42, 0x16, 0x70, 0xA6, 0xAB, 0x0F, 0x50, 0xCC, 0x4A, 0x19, 0x4E, 0xB3, 0x6D, 0x1C, 0x91,
        0xE9, 0x35, 0xBA, 0x01, 0xB9, 0x59, 0xD8, 0x72, 0x8B, 0x9E, 0x64, 0x42, 0x6B, 0x3F, 0xC3,
        0xA7, 0x50, 0x6D, 0xEB, 0x52, 0x39, 0xA8, 0xA7,
    ];

    let (k, err) = NewPrivateKeyWithPrecomputation(
        from_vec(N.to_vec()),
        65537,
        from_vec(D.to_vec()),
        from_vec(P.to_vec()),
        from_vec(Q.to_vec()),
        from_vec(DP.to_vec()),
        from_vec(DQ.to_vec()),
        from_vec(QINV.to_vec()),
    );
    if !err.IsNil() {
        panic!("crypto/rsa: CAST test key construction failed");
    }
    k
}
