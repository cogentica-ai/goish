// go: package crypto/ed25519
//
// Package ed25519 implements the Ed25519 signature algorithm. See
// https://ed25519.cr.yp.to/.
//
// These functions are also compatible with the "Ed25519" function
// defined in RFC 8032. However, unlike RFC 8032's formulation, this
// package's private key representation includes a public key suffix to
// make multiple signing operations with the same key more efficient.

mod ed25519;

pub use ed25519::{
    GenerateKey, NewKeyFromSeed, Options, PrivateKey, PrivateKeySize, PublicKey, PublicKeySize,
    SeedSize, Sign, SignatureSize, Verify, VerifyWithOptions,
};
