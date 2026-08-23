// go: file crypto/internal/fips140/ed25519/cast.go decls: fipsSelfTest, castSelfTest, fipsPCT, pairwiseTest, signWithoutSelfTest, verifyWithoutSelfTest, fipsSelfTest, castSelfTest
//
// Deviation: Go drives the CAST once via `sync.Once` inside
// `fips140.CAST`; no_std has no sync::Once, so an AtomicBool latch
// (`FIPS_SELF_TEST_DONE`) gates `fipsSelfTest`. Same once-per-process
// semantics.

#![allow(non_snake_case)]

extern crate alloc;

use core::sync::atomic::{AtomicBool, Ordering};

use crate::crypto::internal::fips140;
use crate::errors::{self, error};
use crate::goslice::slice;
use crate::string;
use crate::types::byte;

use super::ed25519::{
    bytes_equal, bytes_slice, domPrefixPure, precomputePrivateKey, signWithDom, verifyWithDom,
    NewPublicKey, PrivateKey, PublicKey, Sign, Verify,
};

// go: sdk 1.25.5 crypto/internal/fips140/ed25519/cast.go:15-19 fipsPCT
pub(crate) fn fipsPCT(k: &PrivateKey) {
    fips140::PCT("Ed25519 sign and verify PCT", || pairwiseTest(k));
}

// go: sdk 1.25.5 crypto/internal/fips140/ed25519/cast.go:23-34 pairwiseTest
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

// go: sdk 1.25.5 crypto/internal/fips140/ed25519/cast.go:36-39 signWithoutSelfTest
fn signWithoutSelfTest(priv_: &PrivateKey, message: slice<byte>) -> slice<byte> {
    signWithDom(priv_, message, domPrefixPure, b"")
}

// go: sdk 1.25.5 crypto/internal/fips140/ed25519/cast.go:41-43 verifyWithoutSelfTest
fn verifyWithoutSelfTest(pub_: &PublicKey, message: slice<byte>, sig: slice<byte>) -> error {
    verifyWithDom(pub_, message, sig, domPrefixPure, b"")
}

static FIPS_SELF_TEST_DONE: AtomicBool = AtomicBool::new(false);

// go: none — goish idiom (local helper / no Go counterpart)
// Go: var fipsSelfTest = sync.OnceFunc(...) — runs the CAST once.
pub(crate) fn fipsSelfTest() {
    if FIPS_SELF_TEST_DONE.swap(true, Ordering::SeqCst) {
        return;
    }
    fips140::CAST("Ed25519 sign and verify", castSelfTest);
}

// go: none — goish idiom (local helper / no Go counterpart)
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
