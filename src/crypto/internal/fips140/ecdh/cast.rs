// go: file crypto/internal/fips140/ecdh/cast.go decls: fipsSelfTest
//
// Deviation: Go writes `var fipsSelfTest = sync.OnceFunc(func() { … })`,
// a package-level variable of func type. no_std has no `sync.Once`, so an
// AtomicBool latch gates the body — the same once-per-process semantics,
// and the same shape crypto/internal/fips140/ed25519's cast.rs already
// uses.

#![allow(non_snake_case)]

extern crate alloc;

use core::sync::atomic::{AtomicBool, Ordering};

use crate::crypto::internal::fips140;
use crate::errors;
use crate::goslice::slice;
use crate::types::byte;
use crate::error;

use super::ecdh::{bytesEqual, ecdh, p256, PrivateKey, PublicKey, P256};

static FIPS_SELF_TEST_DONE: AtomicBool = AtomicBool::new(false);

// go: sdk 1.25.5 crypto/internal/fips140/ecdh/cast.go:15-52 fipsSelfTest
pub(super) fn fipsSelfTest() {
    if FIPS_SELF_TEST_DONE.swap(true, Ordering::SeqCst) {
        return;
    }
    // Per IG D.F, Scenario 2, path (1).
    fips140::CAST("KAS-ECC-SSC P-256", || {
        let privateKey = slice::__from_vec(alloc::vec![
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
            0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c,
            0x1d, 0x1e, 0x1f, 0x20,
        ]);
        let publicKey = slice::__from_vec(alloc::vec![
            0x04, 0x51, 0x5c, 0x3d, 0x6e, 0xb9, 0xe3, 0x96, 0xb9, 0x04, 0xd3, 0xfe, 0xca, 0x7f,
            0x54, 0xfd, 0xcd, 0x0c, 0xc1, 0xe9, 0x97, 0xbf, 0x37, 0x5d, 0xca, 0x51, 0x5a, 0xd0,
            0xa6, 0xc3, 0xb4, 0x03, 0x5f, 0x45, 0x36, 0xbe, 0x3a, 0x50, 0xf3, 0x18, 0xfb, 0xf9,
            0xa5, 0x47, 0x59, 0x02, 0xa2, 0x21, 0x50, 0x2b, 0xef, 0x0d, 0x57, 0xe0, 0x8c, 0x53,
            0xb2, 0xcc, 0x0a, 0x56, 0xf1, 0x7d, 0x9f, 0x93, 0x54,
        ]);
        let want = slice::__from_vec(alloc::vec![
            0xb4, 0xf1, 0xfc, 0xce, 0x40, 0x73, 0x5f, 0x83, 0x6a, 0xf8, 0xd6, 0x31, 0x2d, 0x24,
            0x8d, 0x1a, 0x83, 0x48, 0x40, 0x56, 0x69, 0xa1, 0x95, 0xfa, 0xc5, 0x35, 0x04, 0x06,
            0xba, 0x76, 0xbc, 0xce,
        ]);
        let k = PrivateKey {
            d: privateKey,
            r#pub: PublicKey {
                curve: p256,
                q: slice::__from_vec(alloc::vec::Vec::<byte>::new()),
            },
        };
        let peer = PublicKey {
            curve: p256,
            q: publicKey,
        };
        let c = P256();
        let (got, err) = ecdh(&c, &k, &peer);
        if err != crate::nil {
            return err;
        }
        if !bytesEqual(&got, &want) {
            return errors::New("unexpected result");
        }
        return crate::nil.into();
    });
}

// Keep the imports honest: `byte` and `error` name the types the vectors
// and the CAST closure are built from.
const _: fn(&'static str) -> error = errors::New;
const _: byte = 0;
