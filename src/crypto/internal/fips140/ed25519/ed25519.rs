// go: file crypto/internal/fips140/ed25519/ed25519.go decls: zero, empty_slice, bytes_slice, slice_as_bytes, slice_range, bytes_equal, write_bytes, u8_len, PrivateKey.Bytes, PrivateKey.Seed, PrivateKey.PublicKey, PublicKey.Bytes, GenerateKey, generateKey, NewPrivateKeyFromSeed, newPrivateKeyFromSeed, precomputePrivateKey, NewPrivateKey, newPrivateKey, NewPublicKey, newPublicKey, Sign, sign, SignPH, signPH, SignCtx, signCtx, signWithDom, Verify, verify, VerifyPH, VerifyCtx, verifyWithDom
//
// crypto/internal/fips140/ed25519 — the FIPS module's Ed25519. The public
// crypto/ed25519 package is a thin wrapper over this.

#![allow(non_snake_case)]
#![allow(non_upper_case_globals)]

extern crate alloc;

use alloc::vec::Vec;

use crate::crypto::internal::fips140;
use super::cast::{fipsPCT, fipsSelfTest};
use crate::crypto::internal::fips140::edwards25519::{NewScalar, Scalar};
use crate::crypto::internal::fips140::edwards25519::Point;
use crate::crypto::sha512;
use crate::errors::{self, error};
use crate::goslice::slice;
use crate::io;
use crate::strconv;
use crate::string;
use crate::types::{byte, int};


const seedSize: usize = 32;
const publicKeySize: usize = 32;
const privateKeySize: usize = seedSize + publicKeySize;
const signatureSize: usize = 64;
const sha512Size: usize = 64;

// ─── PrivateKey (Go: ed25519.go:28-50) ────────────────────────────────

/// `ed25519.PrivateKey` — a FIPS Ed25519 private key. Byte-backed:
/// the 32-byte `seed`, the derived 32-byte public key `pub`, the
/// secret `s` scalar, and the 32-byte SHA-512 `prefix` half.
pub struct PrivateKey {
    pub(crate) seed: [byte; seedSize],
    pub_: [byte; publicKeySize],
    s: Scalar,
    prefix: [byte; sha512Size / 2],
}

impl PrivateKey {
    // go: none — goish idiom (local helper / no Go counterpart)
    pub(crate) fn zero() -> Self {
        PrivateKey {
            seed: [0; seedSize],
            pub_: [0; publicKeySize],
            s: NewScalar(),
            prefix: [0; sha512Size / 2],
        }
    }

    // go: sdk 1.25.5 crypto/internal/fips140/ed25519/ed25519.go:35-40 Bytes
    /// `(*PrivateKey).Bytes()` — the 64-byte `seed || publicKey`.
    pub fn Bytes(&self) -> slice<byte> {
        let mut k: Vec<byte> = Vec::with_capacity(privateKeySize);
        k.extend_from_slice(&self.seed);
        k.extend_from_slice(&self.pub_);
        slice::__from_vec(k)
    }

    // go: sdk 1.25.5 crypto/internal/fips140/ed25519/ed25519.go:42-45 Seed
    /// `(*PrivateKey).Seed()` — the 32-byte seed.
    pub fn Seed(&self) -> slice<byte> {
        slice::__from_vec(self.seed.to_vec())
    }

    // go: sdk 1.25.5 crypto/internal/fips140/ed25519/ed25519.go:47-50 PublicKey
    /// `(*PrivateKey).PublicKey()` — the 32-byte public key.
    pub fn PublicKey(&self) -> slice<byte> {
        slice::__from_vec(self.pub_.to_vec())
    }
}

// ─── PublicKey (Go: ed25519.go:52-60) ─────────────────────────────────

/// `ed25519.PublicKey` — a FIPS Ed25519 public key: the curve point
/// `a` and its 32-byte encoding `aBytes`.
pub struct PublicKey {
    a: Point,
    aBytes: [byte; 32],
}

impl PublicKey {
    // go: none — goish idiom (local helper / no Go counterpart)
    pub(crate) fn zero() -> Self {
        PublicKey {
            a: Point::new(),
            aBytes: [0; 32],
        }
    }

    // go: sdk 1.25.5 crypto/internal/fips140/ed25519/ed25519.go:35-40 Bytes
    /// `(*PublicKey).Bytes()` — the 32-byte public key encoding.
    pub fn Bytes(&self) -> slice<byte> {
        slice::__from_vec(self.aBytes.to_vec())
    }
}

// ─── Key generation (Go: ed25519.go:62-104) ───────────────────────────

// go: sdk 1.25.5 crypto/internal/fips140/ed25519/ed25519.go:68-74 GenerateKey
/// `GenerateKey()` — generate a new Ed25519 private key pair. The seed
/// is drawn from the kernel CSPRNG (Go uses `drbg.Read`).
pub fn GenerateKey() -> (PrivateKey, error) {
    let priv_ = PrivateKey::zero();
    generateKey(priv_)
}

// go: sdk 1.25.5 crypto/internal/fips140/ed25519/ed25519.go:68-74 generateKey
fn generateKey(mut priv_: PrivateKey) -> (PrivateKey, error) {
    fips140::RecordApproved();
    // Go: drbg.Read(priv.seed[:]) — with FIPS mode off this is the
    // kernel CSPRNG.
    let mut seed_buf: slice<byte> = slice::__from_vec(alloc::vec![0u8; seedSize]);
    let (_, err) = crate::crypto::rand::Read(&mut seed_buf);
    if !err.IsNil() {
        panic!("ed25519: internal error: reading random seed failed");
    }
    for i in 0..seedSize {
        priv_.seed[i] = seed_buf[i as int];
    }
    precomputePrivateKey(&mut priv_);
    fipsPCT(&priv_);
    (priv_, errors::nil)
}

// go: sdk 1.25.5 crypto/internal/fips140/ed25519/ed25519.go:81-89 NewPrivateKeyFromSeed
/// `NewPrivateKeyFromSeed(seed)` — derive a private key from a 32-byte
/// seed.
pub fn NewPrivateKeyFromSeed(seed: slice<byte>) -> (PrivateKey, error) {
    let priv_ = PrivateKey::zero();
    newPrivateKeyFromSeed(priv_, seed)
}

// go: sdk 1.25.5 crypto/internal/fips140/ed25519/ed25519.go:81-89 newPrivateKeyFromSeed
fn newPrivateKeyFromSeed(mut priv_: PrivateKey, seed: slice<byte>) -> (PrivateKey, error) {
    fips140::RecordApproved();
    let l = seed.Len();
    if l as usize != seedSize {
        let mut msg = string::from_static("ed25519: bad seed length: ");
        msg = msg + strconv::Itoa(l);
        return (PrivateKey::zero(), errors::New(msg));
    }
    for i in 0..seedSize {
        priv_.seed[i] = seed[i as int];
    }
    precomputePrivateKey(&mut priv_);
    (priv_, errors::nil)
}

// go: sdk 1.25.5 crypto/internal/fips140/ed25519/ed25519.go:91-104 precomputePrivateKey
pub(crate) fn precomputePrivateKey(priv_: &mut PrivateKey) {
    // Go: hs := sha512.New(); hs.Write(priv.seed[:]); h := hs.Sum(...)
    let mut hs = sha512::New();
    let _ = io::Writer::Write(&mut hs, slice::__from_vec(priv_.seed.to_vec()));
    let h: slice<byte> = hs.Sum(slice::__from_vec(Vec::with_capacity(sha512Size)));

    // s = SetBytesWithClamping(h[:32])
    let err = priv_.s.SetBytesWithClamping(slice_range(&h, 0, 32));
    if !err.IsNil() {
        panic!("ed25519: internal error: setting scalar failed");
    }
    // A = [s]B; priv.pub = A.Bytes()
    let mut A = Point::new();
    A.ScalarBaseMult(&priv_.s);
    let aBytes = A.Bytes();
    for i in 0..publicKeySize {
        priv_.pub_[i] = aBytes[i as int];
    }
    // prefix = h[32:]
    for i in 0..(sha512Size / 2) {
        priv_.prefix[i] = h[(32 + i) as int];
    }
}

// go: sdk 1.25.5 crypto/internal/fips140/ed25519/ed25519.go:111-134 NewPrivateKey
/// `NewPrivateKey(priv)` — parse a 64-byte `seed || publicKey` private
/// key encoding.
pub fn NewPrivateKey(priv_: slice<byte>) -> (PrivateKey, error) {
    let p = PrivateKey::zero();
    newPrivateKey(p, priv_)
}

// go: sdk 1.25.5 crypto/internal/fips140/ed25519/ed25519.go:111-134 newPrivateKey
fn newPrivateKey(mut priv_: PrivateKey, privBytes: slice<byte>) -> (PrivateKey, error) {
    fips140::RecordApproved();
    let l = privBytes.Len();
    if l as usize != privateKeySize {
        let mut msg = string::from_static("ed25519: bad private key length: ");
        msg = msg + strconv::Itoa(l);
        return (PrivateKey::zero(), errors::New(msg));
    }

    for i in 0..seedSize {
        priv_.seed[i] = privBytes[i as int];
    }

    let mut hs = sha512::New();
    let _ = io::Writer::Write(&mut hs, slice::__from_vec(priv_.seed.to_vec()));
    let h: slice<byte> = hs.Sum(slice::__from_vec(Vec::with_capacity(sha512Size)));

    let err = priv_.s.SetBytesWithClamping(slice_range(&h, 0, 32));
    if !err.IsNil() {
        panic!("ed25519: internal error: setting scalar failed");
    }
    // Note that we are not decompressing the public key point here,
    // because signing doesn't use it as a point anyway.
    for i in 0..publicKeySize {
        priv_.pub_[i] = privBytes[(seedSize + i) as int];
    }

    for i in 0..(sha512Size / 2) {
        priv_.prefix[i] = h[(32 + i) as int];
    }

    (priv_, errors::nil)
}

// go: sdk 1.25.5 crypto/internal/fips140/ed25519/ed25519.go:141-151 NewPublicKey
/// `NewPublicKey(pub)` — parse a 32-byte public key encoding; verifies
/// the point is on the curve.
pub fn NewPublicKey(pub_: slice<byte>) -> (PublicKey, error) {
    let p = PublicKey::zero();
    newPublicKey(p, pub_)
}

// go: sdk 1.25.5 crypto/internal/fips140/ed25519/ed25519.go:141-151 newPublicKey
fn newPublicKey(mut pub_: PublicKey, pubBytes: slice<byte>) -> (PublicKey, error) {
    let l = pubBytes.Len();
    if l as usize != publicKeySize {
        let mut msg = string::from_static("ed25519: bad public key length: ");
        msg = msg + strconv::Itoa(l);
        return (PublicKey::zero(), errors::New(msg));
    }
    // SetBytes checks that the point is on the curve.
    let err = pub_.a.SetBytes(pubBytes.clone());
    if !err.IsNil() {
        return (
            PublicKey::zero(),
            errors::New(string::from_static("ed25519: bad public key")),
        );
    }
    for i in 0..publicKeySize {
        pub_.aBytes[i] = pubBytes[i as int];
    }
    (pub_, errors::nil)
}

// ─── Domain separation prefixes (Go: ed25519.go:153-164) ──────────────
//
// RFC 8032 §2 / §5.1. domPrefixPure is empty for pure Ed25519.
pub(crate) const domPrefixPure: &[u8] = b"";
// dom2(phflag=1) for Ed25519ph, followed by a uint8-length-prefixed ctx.
const domPrefixPh: &[u8] = b"SigEd25519 no Ed25519 collisions\x01";
// dom2(phflag=0) for Ed25519ctx, followed by a uint8-length-prefixed ctx.
const domPrefixCtx: &[u8] = b"SigEd25519 no Ed25519 collisions\x00";

// ─── Signing (Go: ed25519.go:166-256) ─────────────────────────────────

// go: sdk 1.25.5 crypto/internal/fips140/ed25519/ed25519.go:173-177 Sign
/// `Sign(priv, message)` — pure Ed25519 signature over `message`.
/// 64-byte `R || S`.
pub fn Sign(priv_: &PrivateKey, message: slice<byte>) -> slice<byte> {
    sign(priv_, message)
}

// go: sdk 1.25.5 crypto/internal/fips140/ed25519/ed25519.go:173-177 sign
fn sign(priv_: &PrivateKey, message: slice<byte>) -> slice<byte> {
    fipsSelfTest();
    fips140::RecordApproved();
    signWithDom(priv_, message, domPrefixPure, b"")
}

// go: sdk 1.25.5 crypto/internal/fips140/ed25519/ed25519.go:186-196 SignPH
/// `SignPH(priv, message, context)` — Ed25519ph: `message` must be the
/// 64-byte SHA-512 prehash; `context` at most 255 bytes.
pub fn SignPH(
    priv_: &PrivateKey,
    message: slice<byte>,
    context: slice<byte>,
) -> (slice<byte>, error) {
    signPH(priv_, message, context)
}

// go: sdk 1.25.5 crypto/internal/fips140/ed25519/ed25519.go:186-196 signPH
fn signPH(
    priv_: &PrivateKey,
    message: slice<byte>,
    context: slice<byte>,
) -> (slice<byte>, error) {
    fipsSelfTest();
    fips140::RecordApproved();
    let l = message.Len();
    if l as usize != sha512Size {
        let mut msg = string::from_static("ed25519: bad Ed25519ph message hash length: ");
        msg = msg + strconv::Itoa(l);
        return (empty_slice(), errors::New(msg));
    }
    let lc = context.Len();
    if lc > 255 {
        let mut msg = string::from_static("ed25519: bad Ed25519ph context length: ");
        msg = msg + strconv::Itoa(lc);
        return (empty_slice(), errors::New(msg));
    }
    (
        signWithDom(priv_, message, domPrefixPh, slice_as_bytes(&context).as_slice()),
        errors::nil,
    )
}

// go: sdk 1.25.5 crypto/internal/fips140/ed25519/ed25519.go:205-214 SignCtx
/// `SignCtx(priv, message, context)` — Ed25519ctx (not FIPS-approved):
/// `context` at most 255 bytes and SHOULD NOT be empty (RFC 8032 §5.1).
pub fn SignCtx(
    priv_: &PrivateKey,
    message: slice<byte>,
    context: slice<byte>,
) -> (slice<byte>, error) {
    signCtx(priv_, message, context)
}

// go: sdk 1.25.5 crypto/internal/fips140/ed25519/ed25519.go:205-214 signCtx
fn signCtx(
    priv_: &PrivateKey,
    message: slice<byte>,
    context: slice<byte>,
) -> (slice<byte>, error) {
    fipsSelfTest();
    // FIPS 186-5 specifies Ed25519 and Ed25519ph, but not Ed25519ctx.
    fips140::RecordNonApproved();
    let lc = context.Len();
    if lc > 255 {
        let mut msg = string::from_static("ed25519: bad Ed25519ctx context length: ");
        msg = msg + strconv::Itoa(lc);
        return (empty_slice(), errors::New(msg));
    }
    (
        signWithDom(priv_, message, domPrefixCtx, slice_as_bytes(&context).as_slice()),
        errors::nil,
    )
}

// go: sdk 1.25.5 crypto/internal/fips140/ed25519/ed25519.go:216-256 signWithDom
pub(crate) fn signWithDom(
    priv_: &PrivateKey,
    message: slice<byte>,
    domPrefix: &[u8],
    context: &[u8],
) -> slice<byte> {
    // r = SetUniformBytes(SHA512(dom || prefix || M))
    let mut mh = sha512::New();
    if domPrefix != domPrefixPure {
        write_bytes(&mut mh, domPrefix);
        write_bytes(&mut mh, &[u8_len(context)]);
        write_bytes(&mut mh, context);
    }
    write_bytes(&mut mh, &priv_.prefix);
    let _ = io::Writer::Write(&mut mh, message.clone());
    let messageDigest: slice<byte> = mh.Sum(slice::__from_vec(Vec::with_capacity(sha512Size)));
    let mut r = NewScalar();
    let err = r.SetUniformBytes(messageDigest);
    if !err.IsNil() {
        panic!("ed25519: internal error: setting scalar failed");
    }

    // R = [r]B
    let mut R = Point::new();
    R.ScalarBaseMult(&r);

    // k = SetUniformBytes(SHA512(dom || R || A || M))
    let mut kh = sha512::New();
    if domPrefix != domPrefixPure {
        write_bytes(&mut kh, domPrefix);
        write_bytes(&mut kh, &[u8_len(context)]);
        write_bytes(&mut kh, context);
    }
    let _ = io::Writer::Write(&mut kh, R.Bytes());
    write_bytes(&mut kh, &priv_.pub_);
    let _ = io::Writer::Write(&mut kh, message);
    let hramDigest: slice<byte> = kh.Sum(slice::__from_vec(Vec::with_capacity(sha512Size)));
    let mut k = NewScalar();
    let err = k.SetUniformBytes(hramDigest);
    if !err.IsNil() {
        panic!("ed25519: internal error: setting scalar failed");
    }

    // S = k*s + r mod L
    let mut S = NewScalar();
    S.MultiplyAdd(&k, &priv_.s, &r);

    // signature = R.Bytes() || S.Bytes()
    let mut sig: Vec<byte> = alloc::vec![0u8; signatureSize];
    let rBytes = R.Bytes();
    let sBytes = S.Bytes();
    for i in 0..32 {
        sig[i] = rBytes[i as int];
        sig[32 + i] = sBytes[i as int];
    }
    slice::__from_vec(sig)
}

// ─── Verification (Go: ed25519.go:258-328) ────────────────────────────

// go: sdk 1.25.5 crypto/internal/fips140/ed25519/ed25519.go:262-266 Verify
/// `Verify(pub, message, sig)` — pure Ed25519 verification. Returns
/// `nil` if the signature is valid, an error otherwise.
pub fn Verify(pub_: &PublicKey, message: slice<byte>, sig: slice<byte>) -> error {
    verify(pub_, message, sig)
}

// go: sdk 1.25.5 crypto/internal/fips140/ed25519/ed25519.go:262-266 verify
fn verify(pub_: &PublicKey, message: slice<byte>, sig: slice<byte>) -> error {
    fipsSelfTest();
    fips140::RecordApproved();
    verifyWithDom(pub_, message, sig, domPrefixPure, b"")
}

// go: sdk 1.25.5 crypto/internal/fips140/ed25519/ed25519.go:268-278 VerifyPH
/// `VerifyPH(pub, message, sig, context)` — Ed25519ph verification:
/// `message` must be the 64-byte SHA-512 prehash.
pub fn VerifyPH(
    pub_: &PublicKey,
    message: slice<byte>,
    sig: slice<byte>,
    context: slice<byte>,
) -> error {
    fipsSelfTest();
    fips140::RecordApproved();
    let l = message.Len();
    if l as usize != sha512Size {
        let mut msg = string::from_static("ed25519: bad Ed25519ph message hash length: ");
        msg = msg + strconv::Itoa(l);
        return errors::New(msg);
    }
    let lc = context.Len();
    if lc > 255 {
        let mut msg = string::from_static("ed25519: bad Ed25519ph context length: ");
        msg = msg + strconv::Itoa(lc);
        return errors::New(msg);
    }
    verifyWithDom(pub_, message, sig, domPrefixPh, slice_as_bytes(&context).as_slice())
}

// go: sdk 1.25.5 crypto/internal/fips140/ed25519/ed25519.go:280-288 VerifyCtx
/// `VerifyCtx(pub, message, sig, context)` — Ed25519ctx verification
/// (not FIPS-approved).
pub fn VerifyCtx(
    pub_: &PublicKey,
    message: slice<byte>,
    sig: slice<byte>,
    context: slice<byte>,
) -> error {
    fipsSelfTest();
    // FIPS 186-5 specifies Ed25519 and Ed25519ph, but not Ed25519ctx.
    fips140::RecordNonApproved();
    let lc = context.Len();
    if lc > 255 {
        let mut msg = string::from_static("ed25519: bad Ed25519ctx context length: ");
        msg = msg + strconv::Itoa(lc);
        return errors::New(msg);
    }
    verifyWithDom(pub_, message, sig, domPrefixCtx, slice_as_bytes(&context).as_slice())
}

// go: sdk 1.25.5 crypto/internal/fips140/ed25519/ed25519.go:290-328 verifyWithDom
pub(crate) fn verifyWithDom(
    pub_: &PublicKey,
    message: slice<byte>,
    sig: slice<byte>,
    domPrefix: &[u8],
    context: &[u8],
) -> error {
    let l = sig.Len();
    if l as usize != signatureSize {
        let mut msg = string::from_static("ed25519: bad signature length: ");
        msg = msg + strconv::Itoa(l);
        return errors::New(msg);
    }

    if (sig[63] & 224) != 0 {
        return errors::New(string::from_static("ed25519: invalid signature"));
    }

    // k = SetUniformBytes(SHA512(dom || R || A || M))
    let mut kh = sha512::New();
    if domPrefix != domPrefixPure {
        write_bytes(&mut kh, domPrefix);
        write_bytes(&mut kh, &[u8_len(context)]);
        write_bytes(&mut kh, context);
    }
    let _ = io::Writer::Write(&mut kh, slice_range(&sig, 0, 32));
    write_bytes(&mut kh, &pub_.aBytes);
    let _ = io::Writer::Write(&mut kh, message);
    let hramDigest: slice<byte> = kh.Sum(slice::__from_vec(Vec::with_capacity(sha512Size)));
    let mut k = NewScalar();
    let err = k.SetUniformBytes(hramDigest);
    if !err.IsNil() {
        panic!("ed25519: internal error: setting scalar failed");
    }

    let mut S = NewScalar();
    let err = S.SetCanonicalBytes(slice_range(&sig, 32, 64));
    if !err.IsNil() {
        return errors::New(string::from_static("ed25519: invalid signature"));
    }

    // [S]B = R + [k]A  -->  [k](-A) + [S]B = R
    let mut minusA = Point::new();
    minusA.Negate(&pub_.a);
    let mut R = Point::new();
    R.VarTimeDoubleScalarBaseMult(&k, &minusA, &S);

    if !bytes_equal(&slice_range(&sig, 0, 32), &R.Bytes()) {
        return errors::New(string::from_static("ed25519: invalid signature"));
    }
    errors::nil
}


// go: none — goish idiom (local helper / no Go counterpart)
// Empty `slice<byte>` for the `nil` return slot of failing Sign* fns.
pub(crate) fn empty_slice() -> slice<byte> {
    slice::__from_vec(Vec::new())
}

// go: none — goish idiom (local helper / no Go counterpart)
// Build a `slice<byte>` from a borrowed byte buffer.
pub(crate) fn bytes_slice(b: &[u8]) -> slice<byte> {
    slice::__from_vec(b.to_vec())
}

// go: none — goish idiom (local helper / no Go counterpart)
// Materialize a `slice<byte>` into a contiguous `Vec<u8>` for the
// internal SHA-512 `Write` calls that need a borrowed buffer.
pub(crate) fn slice_as_bytes(s: &slice<byte>) -> Vec<u8> {
    let n = s.Len();
    let mut v: Vec<u8> = Vec::with_capacity(n as usize);
    let mut i: int = 0;
    while i < n {
        v.push(s[i]);
        i += 1;
    }
    v
}

// go: none — goish idiom (local helper / no Go counterpart)
// `s[lo:hi]` — a fresh sub-slice copy.
pub(crate) fn slice_range(s: &slice<byte>, lo: usize, hi: usize) -> slice<byte> {
    let mut v: Vec<u8> = Vec::with_capacity(hi - lo);
    for i in lo..hi {
        v.push(s[i as int]);
    }
    slice::__from_vec(v)
}

// go: none — goish idiom (local helper / no Go counterpart)
// `bytes.Equal` over two byte slices.
pub(crate) fn bytes_equal(a: &slice<byte>, b: &slice<byte>) -> bool {
    if a.Len() != b.Len() {
        return false;
    }
    let mut i: int = 0;
    while i < a.Len() {
        if a[i] != b[i] {
            return false;
        }
        i += 1;
    }
    true
}

// go: none — goish idiom (local helper / no Go counterpart)
// Feed a borrowed byte buffer to a SHA-512 digest.
pub(crate) fn write_bytes(h: &mut sha512::Digest, b: &[u8]) {
    let _ = io::Writer::Write(h, slice::__from_vec(b.to_vec()));
}


// ─── small helpers ────────────────────────────────────────────────────

// go: none — goish idiom (local helper / no Go counterpart)
// `byte(len(context))` — uint8 truncation of the context length.
pub(crate) fn u8_len(context: &[u8]) -> u8 {
    let n = context.len();
    (n & 0xff) as u8
}
