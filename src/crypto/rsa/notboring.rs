// go: file crypto/rsa/notboring.go decls: boringPublicKey, boringPrivateKey
//
// Go builds this file under `//go:build !boringcrypto` — the branch where
// BoringSSL is not linked in. Both functions exist only so that the
// `if boring.Enabled { … }` call sites in rsa.go, pkcs1v15.go and fips.go
// still compile; reaching one is a bug, which is why Go's bodies are a
// bare `panic`.
//
// goish has no cgo, so `crypto/internal/boring` does not exist and never
// will: `boring.Enabled` is not merely false, it is unspellable. The two
// functions are ported anyway, with Go's bodies, so that the file set of
// this package matches Go's and a future reader can see that the
// boringcrypto path was considered rather than quietly dropped.
//
// Deviations from notboring[go] @ Go 1.25.5:
//
//   * Go returns `(*boring.PublicKeyRSA, error)` / `(*boring.PrivateKeyRSA,
//     error)`. There is no such type here, and the bodies never return, so
//     the return type is `!`.
//   * Nothing calls them — the `boring.Enabled` branches they belong to
//     are absent from the ports of the other three files — hence the
//     module-level `allow(dead_code)`.

#![allow(non_snake_case, dead_code)]

use super::rsa::{PrivateKey, PublicKey};

// go: sdk 1.25.5 crypto/rsa/notboring.go:11-13 boringPublicKey
fn boringPublicKey(_pub: &PublicKey) -> ! {
    panic!("boringcrypto: not available");
}

// go: sdk 1.25.5 crypto/rsa/notboring.go:14-16 boringPrivateKey
fn boringPrivateKey(_priv: &PrivateKey) -> ! {
    panic!("boringcrypto: not available");
}
