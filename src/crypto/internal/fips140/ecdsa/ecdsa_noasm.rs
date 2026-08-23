// go: file crypto/internal/fips140/ecdsa/ecdsa_noasm.go decls: sign, verify
//
// The portable side of ecdsa_noasm.go / ecdsa_s390x.go's build-tag pair
// (`//go:build !s390x || purego`). goish is x86_64-only, so this is the
// side that compiles: both entry points forward straight to the generic
// implementations in ecdsa.rs.

#![allow(non_snake_case)]

use crate::error;
use crate::goslice::slice;
use crate::types::byte;

use super::ecdsa::{signGeneric, verifyGeneric, Curve, Point, PrivateKey, PublicKey, Signature};
use super::hmacdrbg::hmacDRBG;

// go: sdk 1.25.5 crypto/internal/fips140/ecdsa/ecdsa_noasm.go:9-11 sign
pub(super) fn sign<P: Point>(
    c: &Curve<P>,
    priv_: &PrivateKey,
    drbg: &mut hmacDRBG,
    hash: &slice<byte>,
) -> (Signature, error) {
    return signGeneric(c, priv_, drbg, hash);
}

// go: sdk 1.25.5 crypto/internal/fips140/ecdsa/ecdsa_noasm.go:13-15 verify
pub(super) fn verify<P: Point>(
    c: &Curve<P>,
    pubKey: &PublicKey,
    hash: &slice<byte>,
    sig: &Signature,
) -> error {
    return verifyGeneric(c, pubKey, hash, sig);
}
