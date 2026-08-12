// go: file crypto/ecdh/nist.go decls: nistCurve.String, nistCurve.GenerateKey, nistCurve.NewPrivateKey, nistCurve.NewPublicKey, nistCurve.ecdh, P256, P384, P521
//
// Deviations from nist[go] @ Go 1.25.5:
//
//   * `crypto/internal/boring` is out of scope (goish has no cgo), so
//     every `if boring.Enabled` arm and the `boring` fields are dropped.
//     What remains is Go's non-boring path.
//   * Go's four fields are closures over one `crypto/internal/fips140/ecdh`
//     curve (`func(r io.Reader) { return ecdh.GenerateKey(ecdh.P256(), r) }`).
//     goish's fips140/ecdh entry points are generic over the point type, so
//     each closure is a distinct monomorphic function and the fields are
//     plain `fn` pointers — no capture, so no carrier needed.
//   * `PrivateKey`/`PublicKey` carry no `fips` field: it caches the parsed
//     fips140 key, and goish re-parses in `ecdh` instead. That is the same
//     trade crypto/internal/fips140cache documents — correctness identical,
//     the saved work forfeited.
//
// goishlint:ignore GOISH021 — `nistCurve` is declared below; Go's
// `p256`/`p384`/`p521` vars are the `Lazy` statics behind the three
// accessors.

#![allow(non_snake_case, non_camel_case_types, non_upper_case_globals)]

extern crate alloc;
use alloc::vec::Vec;

use crate::crypto::internal::fips140::ecdh as fips;
use crate::crypto::internal::fips140::nistec;
use crate::crypto::internal::fips140only;
use crate::errors;
use crate::goslice::slice;
use crate::io;
use crate::string;
use crate::types::byte;
use crate::error;

use super::ecdh::{Curve, PrivateKey, PublicKey};

// Go: nist.go:12-18
//   type nistCurve struct { name string; generate/newPrivateKey/newPublicKey/sharedSecret func… }
pub struct nistCurve {
    name: &'static str,
    generate: fn(&mut (dyn io::Reader + Send + Sync + 'static)) -> (fips::PrivateKey, error),
    newPrivateKey: fn(&slice<byte>) -> (fips::PrivateKey, error),
    newPublicKey: fn(&slice<byte>) -> (fips::PublicKey, error),
    sharedSecret: fn(&fips::PrivateKey, &fips::PublicKey) -> (slice<byte>, error),
}

impl Curve for nistCurve {
    // go: sdk 1.25.5 crypto/ecdh/nist.go:24-26 nistCurve.String
    fn String(&self) -> string {
        return string::from_static(self.name);
    }

    // go: sdk 1.25.5 crypto/ecdh/nist.go:28-79 nistCurve.GenerateKey
    fn GenerateKey(
        &self,
        rand: &mut (dyn io::Reader + Send + Sync + 'static),
    ) -> (PrivateKey, error) {
        // Go's `boring.Enabled && rand == boring.RandReader` arm is dropped.
        if fips140only::Enabled && !fips140only::ApprovedRandomReader(rand) {
            return (
                zeroPrivateKey(self.me()),
                errors::New("crypto/ecdh: only crypto/rand.Reader is allowed in FIPS 140-only mode"),
            );
        }

        let (privateKey, err) = (self.generate)(rand);
        if err != crate::nil {
            return (zeroPrivateKey(self.me()), err);
        }

        return (
            PrivateKey {
                curve: self.me(),
                privateKey: privateKey.Bytes(),
                publicKey: PublicKey {
                    curve: self.me(),
                    publicKey: privateKey.PublicKey().Bytes(),
                },
            },
            crate::nil.into(),
        );
    }

    // go: sdk 1.25.5 crypto/ecdh/nist.go:81-115 nistCurve.NewPrivateKey
    fn NewPrivateKey(&self, key: &slice<byte>) -> (PrivateKey, error) {
        let (fk, err) = (self.newPrivateKey)(key);
        if err != crate::nil {
            return (zeroPrivateKey(self.me()), err);
        }
        let raw: &[byte] = key;
        return (
            PrivateKey {
                curve: self.me(),
                privateKey: slice::__from_vec(raw.to_vec()),
                publicKey: PublicKey {
                    curve: self.me(),
                    publicKey: fk.PublicKey().Bytes(),
                },
            },
            crate::nil.into(),
        );
    }

    // go: sdk 1.25.5 crypto/ecdh/nist.go:117-141 nistCurve.NewPublicKey
    fn NewPublicKey(&self, key: &slice<byte>) -> (PublicKey, error) {
        let raw: &[byte] = key;
        if raw.is_empty() || raw[0] != 4 {
            return (
                zeroPublicKey(self.me()),
                errors::New("crypto/ecdh: invalid public key"),
            );
        }
        let (_, err) = (self.newPublicKey)(key);
        if err != crate::nil {
            return (zeroPublicKey(self.me()), err);
        }
        return (
            PublicKey {
                curve: self.me(),
                publicKey: slice::__from_vec(raw.to_vec()),
            },
            crate::nil.into(),
        );
    }

    // go: sdk 1.25.5 crypto/ecdh/nist.go:143-155 nistCurve.ecdh
    fn ecdh(&self, local: &PrivateKey, remote: &PublicKey) -> (slice<byte>, error) {
        // Go reads the cached `local.fips` / `remote.fips`; goish re-parses
        // (see the file header).
        let (fk, err) = (self.newPrivateKey)(&local.privateKey);
        if err != crate::nil {
            return (slice::__from_vec(Vec::<byte>::new()), err);
        }
        let (fp, err) = (self.newPublicKey)(&remote.publicKey);
        if err != crate::nil {
            return (slice::__from_vec(Vec::<byte>::new()), err);
        }
        return (self.sharedSecret)(&fk, &fp);
    }

    // go: none — goish idiom: the hidden Any-view hook.
    fn __goish_as_dyn_any(&self) -> Option<&(dyn core::any::Any + Send + Sync)> {
        return Some(self);
    }
    // go: none — goish idiom: see __goish_as_dyn_any above.
    fn __goish_as_dyn_any_mut(&mut self) -> Option<&mut (dyn core::any::Any + Send + Sync)> {
        return Some(self);
    }
}

impl nistCurve {
    // go: none — Go stores the `Curve` interface value straight into each
    // key; goish needs the `&'static dyn` back from `&self`, which the
    // three accessors below own.
    fn me(&self) -> &'static (dyn Curve + Send + Sync) {
        if self.name == "P-256" {
            return &p256;
        }
        if self.name == "P-384" {
            return &p384;
        }
        return &p521;
    }
}

macro_rules! __nist_curve {
    ($stat:ident, $name:literal, $C:ident, $P:ident) => {
        static $stat: nistCurve = nistCurve {
            name: $name,
            generate: |r| fips::GenerateKey(&fips::$C(), r),
            newPrivateKey: |b| fips::NewPrivateKey(&fips::$C(), b),
            newPublicKey: |b| fips::NewPublicKey(&fips::$C(), b),
            sharedSecret: |priv_, pub_| fips::ECDH(&fips::$C(), priv_, pub_),
        };
    };
}

__nist_curve!(p256, "P-256", P256, P256Point);
__nist_curve!(p384, "P-384", P384, P384Point);
__nist_curve!(p521, "P-521", P521, P521Point);

// go: sdk 1.25.5 crypto/ecdh/nist.go:162-162 P256
pub fn P256() -> &'static (dyn Curve + Send + Sync) {
    return &p256;
}

// go: sdk 1.25.5 crypto/ecdh/nist.go:185-185 P384
pub fn P384() -> &'static (dyn Curve + Send + Sync) {
    return &p384;
}

// go: sdk 1.25.5 crypto/ecdh/nist.go:208-208 P521
pub fn P521() -> &'static (dyn Curve + Send + Sync) {
    return &p521;
}

// go: none — Go returns a nil *PrivateKey on the error paths.
fn zeroPrivateKey(c: &'static (dyn Curve + Send + Sync)) -> PrivateKey {
    return PrivateKey {
        curve: c,
        privateKey: slice::__from_vec(Vec::<byte>::new()),
        publicKey: zeroPublicKey(c),
    };
}

// go: none — the same, for *PublicKey.
fn zeroPublicKey(c: &'static (dyn Curve + Send + Sync)) -> PublicKey {
    return PublicKey {
        curve: c,
        publicKey: slice::__from_vec(Vec::<byte>::new()),
    };
}

// Keep the nistec import honest: the fips140 curves are built over it.
const _: fn() -> nistec::P256Point = nistec::NewP256Point;
