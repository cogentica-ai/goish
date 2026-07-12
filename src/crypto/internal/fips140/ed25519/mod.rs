// crypto/internal/fips140/ed25519 — Go's FIPS 140-3 Ed25519, ported.
//
// RFC 8032 EdDSA over edwards25519: key generation, signing, and
// verification, plus the Ed25519ph and Ed25519ctx domain-separated
// variants. A faithful translation of Go 1.25's
// `crypto/internal/fips140/ed25519/ed25519.go` + `cast.go`.
//
// Slim deviations from the Go original:
//   * Go's `generateKey` reads the seed from `drbg.Read`; goish has no
//     validated DRBG, so the seed is drawn from `crypto/rand` (the
//     kernel CSPRNG) — exactly what `drbg.Read` falls back to with
//     FIPS mode off (see the RSA port's `drbg_read`).
//   * The CAST self-test runs once via an `AtomicBool` latch instead
//     of `sync.OnceFunc`.

#![allow(non_snake_case)]

extern crate alloc;

use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, Ordering};

use crate::crypto::internal::fips140;
use crate::crypto::internal::fips140::edwards25519::scalar::{NewScalar, Scalar};
use crate::crypto::internal::fips140::edwards25519::Point;
use crate::crypto::sha512;
use crate::errors::{self, error};
use crate::goslice::slice;
use crate::hash::Hash;
use crate::io;
use crate::strconv;
use crate::string;
use crate::types::{byte, int};

// ─── Constants (Go: ed25519.go:20-26) ─────────────────────────────────

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
    seed: [byte; seedSize],
    pub_: [byte; publicKeySize],
    s: Scalar,
    prefix: [byte; sha512Size / 2],
}

impl PrivateKey {
    fn zero() -> Self {
        PrivateKey {
            seed: [0; seedSize],
            pub_: [0; publicKeySize],
            s: NewScalar(),
            prefix: [0; sha512Size / 2],
        }
    }

    /// `(*PrivateKey).Bytes()` — the 64-byte `seed || publicKey`.
    pub fn Bytes(&self) -> slice<byte> {
        let mut k: Vec<byte> = Vec::with_capacity(privateKeySize);
        k.extend_from_slice(&self.seed);
        k.extend_from_slice(&self.pub_);
        slice::__from_vec(k)
    }

    /// `(*PrivateKey).Seed()` — the 32-byte seed.
    pub fn Seed(&self) -> slice<byte> {
        slice::__from_vec(self.seed.to_vec())
    }

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
    fn zero() -> Self {
        PublicKey {
            a: Point::new(),
            aBytes: [0; 32],
        }
    }

    /// `(*PublicKey).Bytes()` — the 32-byte public key encoding.
    pub fn Bytes(&self) -> slice<byte> {
        slice::__from_vec(self.aBytes.to_vec())
    }
}

// ─── Key generation (Go: ed25519.go:62-104) ───────────────────────────

/// `GenerateKey()` — generate a new Ed25519 private key pair. The seed
/// is drawn from the kernel CSPRNG (Go uses `drbg.Read`).
pub fn GenerateKey() -> (PrivateKey, error) {
    let priv_ = PrivateKey::zero();
    generateKey(priv_)
}

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

/// `NewPrivateKeyFromSeed(seed)` — derive a private key from a 32-byte
/// seed.
pub fn NewPrivateKeyFromSeed(seed: slice<byte>) -> (PrivateKey, error) {
    let priv_ = PrivateKey::zero();
    newPrivateKeyFromSeed(priv_, seed)
}

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

fn precomputePrivateKey(priv_: &mut PrivateKey) {
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

/// `NewPrivateKey(priv)` — parse a 64-byte `seed || publicKey` private
/// key encoding.
pub fn NewPrivateKey(priv_: slice<byte>) -> (PrivateKey, error) {
    let p = PrivateKey::zero();
    newPrivateKey(p, priv_)
}

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

/// `NewPublicKey(pub)` — parse a 32-byte public key encoding; verifies
/// the point is on the curve.
pub fn NewPublicKey(pub_: slice<byte>) -> (PublicKey, error) {
    let p = PublicKey::zero();
    newPublicKey(p, pub_)
}

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
const domPrefixPure: &[u8] = b"";
// dom2(phflag=1) for Ed25519ph, followed by a uint8-length-prefixed ctx.
const domPrefixPh: &[u8] = b"SigEd25519 no Ed25519 collisions\x01";
// dom2(phflag=0) for Ed25519ctx, followed by a uint8-length-prefixed ctx.
const domPrefixCtx: &[u8] = b"SigEd25519 no Ed25519 collisions\x00";

// ─── Signing (Go: ed25519.go:166-256) ─────────────────────────────────

/// `Sign(priv, message)` — pure Ed25519 signature over `message`.
/// 64-byte `R || S`.
pub fn Sign(priv_: &PrivateKey, message: slice<byte>) -> slice<byte> {
    sign(priv_, message)
}

fn sign(priv_: &PrivateKey, message: slice<byte>) -> slice<byte> {
    fipsSelfTest();
    fips140::RecordApproved();
    signWithDom(priv_, message, domPrefixPure, b"")
}

/// `SignPH(priv, message, context)` — Ed25519ph: `message` must be the
/// 64-byte SHA-512 prehash; `context` at most 255 bytes.
pub fn SignPH(
    priv_: &PrivateKey,
    message: slice<byte>,
    context: slice<byte>,
) -> (slice<byte>, error) {
    signPH(priv_, message, context)
}

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

/// `SignCtx(priv, message, context)` — Ed25519ctx (not FIPS-approved):
/// `context` at most 255 bytes and SHOULD NOT be empty (RFC 8032 §5.1).
pub fn SignCtx(
    priv_: &PrivateKey,
    message: slice<byte>,
    context: slice<byte>,
) -> (slice<byte>, error) {
    signCtx(priv_, message, context)
}

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

fn signWithDom(
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

/// `Verify(pub, message, sig)` — pure Ed25519 verification. Returns
/// `nil` if the signature is valid, an error otherwise.
pub fn Verify(pub_: &PublicKey, message: slice<byte>, sig: slice<byte>) -> error {
    verify(pub_, message, sig)
}

fn verify(pub_: &PublicKey, message: slice<byte>, sig: slice<byte>) -> error {
    fipsSelfTest();
    fips140::RecordApproved();
    verifyWithDom(pub_, message, sig, domPrefixPure, b"")
}

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

fn verifyWithDom(
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

// ─── CAST self-test (Go: cast.go) ─────────────────────────────────────

fn fipsPCT(k: &PrivateKey) {
    fips140::PCT("Ed25519 sign and verify PCT", || pairwiseTest(k));
}

// Go's pairwiseTest: sign a fixed message, then re-derive the public
// key and verify.
fn pairwiseTest(k: &PrivateKey) -> error {
    let msg = bytes_slice(b"PCT");
    let sig = Sign(k, msg.clone());
    let (pub_, err) = NewPublicKey(k.PublicKey());
    if !err.IsNil() {
        return err;
    }
    Verify(&pub_, msg, sig)
}

fn signWithoutSelfTest(priv_: &PrivateKey, message: slice<byte>) -> slice<byte> {
    signWithDom(priv_, message, domPrefixPure, b"")
}

fn verifyWithoutSelfTest(pub_: &PublicKey, message: slice<byte>, sig: slice<byte>) -> error {
    verifyWithDom(pub_, message, sig, domPrefixPure, b"")
}

static FIPS_SELF_TEST_DONE: AtomicBool = AtomicBool::new(false);

// Go: var fipsSelfTest = sync.OnceFunc(...) — runs the CAST once.
fn fipsSelfTest() {
    if FIPS_SELF_TEST_DONE.swap(true, Ordering::SeqCst) {
        return;
    }
    fips140::CAST("Ed25519 sign and verify", castSelfTest);
}

fn castSelfTest() -> error {
    // Known-answer seed and the expected signature of "CAST".
    let seed: [u8; 32] = [
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e,
        0x1f, 0x20,
    ];
    let msg = bytes_slice(b"CAST");
    let want: [u8; 64] = [
        0xbd, 0xe7, 0xa5, 0xf3, 0x40, 0x73, 0xb9, 0x5a, 0x2e, 0x6d, 0x63, 0x20, 0x0a, 0xd5, 0x92,
        0x9b, 0xa2, 0x3d, 0x00, 0x44, 0xb4, 0xc5, 0xfd, 0x62, 0x1d, 0x5e, 0x33, 0x2f, 0xe4, 0x61,
        0x42, 0x31, 0x5b, 0x10, 0x53, 0x13, 0x4d, 0xcb, 0xd1, 0x1b, 0x2a, 0xf6, 0xcd, 0x0e, 0xdb,
        0x9a, 0xd3, 0x1e, 0x35, 0xdb, 0x0b, 0xcf, 0x58, 0x90, 0x4f, 0xd7, 0x69, 0x38, 0xed, 0x30,
        0x51, 0x0f, 0xaa, 0x03,
    ];
    let mut k = PrivateKey::zero();
    k.seed = seed;
    precomputePrivateKey(&mut k);
    let (pub_, err) = NewPublicKey(k.PublicKey());
    if !err.IsNil() {
        return err;
    }
    let sig = signWithoutSelfTest(&k, msg.clone());
    if !bytes_equal(&sig, &slice::__from_vec(want.to_vec())) {
        return errors::New(string::from_static("unexpected result"));
    }
    verifyWithoutSelfTest(&pub_, msg, sig)
}

// ─── small helpers ────────────────────────────────────────────────────

// `byte(len(context))` — uint8 truncation of the context length.
fn u8_len(context: &[u8]) -> u8 {
    let n = context.len();
    (n & 0xff) as u8
}

// Empty `slice<byte>` for the `nil` return slot of failing Sign* fns.
fn empty_slice() -> slice<byte> {
    slice::__from_vec(Vec::new())
}

// Build a `slice<byte>` from a borrowed byte buffer.
fn bytes_slice(b: &[u8]) -> slice<byte> {
    slice::__from_vec(b.to_vec())
}

// Materialize a `slice<byte>` into a contiguous `Vec<u8>` for the
// internal SHA-512 `Write` calls that need a borrowed buffer.
fn slice_as_bytes(s: &slice<byte>) -> Vec<u8> {
    let n = s.Len();
    let mut v: Vec<u8> = Vec::with_capacity(n as usize);
    let mut i: int = 0;
    while i < n {
        v.push(s[i]);
        i += 1;
    }
    v
}

// `s[lo:hi]` — a fresh sub-slice copy.
fn slice_range(s: &slice<byte>, lo: usize, hi: usize) -> slice<byte> {
    let mut v: Vec<u8> = Vec::with_capacity(hi - lo);
    for i in lo..hi {
        v.push(s[i as int]);
    }
    slice::__from_vec(v)
}

// `bytes.Equal` over two byte slices.
fn bytes_equal(a: &slice<byte>, b: &slice<byte>) -> bool {
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

// Feed a borrowed byte buffer to a SHA-512 digest.
fn write_bytes(h: &mut sha512::Digest, b: &[u8]) {
    let _ = io::Writer::Write(h, slice::__from_vec(b.to_vec()));
}
