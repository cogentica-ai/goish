// go: file crypto/ecdsa/notboring.go decls: boringPublicKey, boringPrivateKey
//
// Go builds this file under `//go:build !boringcrypto` — the branch that
// is always taken here, since goish has no cgo and `crypto/internal/boring`
// is out of scope across the whole tree (it is in port_coverage's SKIP and
// port_deps's OUT_OF_SCOPE).
//
// Deviation: Go's signatures return `(*boring.PublicKeyECDSA, error)`.
// There is no goish `boring` package to name, and both bodies are a bare
// `panic`, so the return type is Rust's never type. That is what the Go
// functions do, spelled in a type system that can say it.

#![allow(non_snake_case, dead_code)]

use super::ecdsa::{PrivateKey, PublicKey};

// go: sdk 1.25.5 crypto/ecdsa/notboring.go:11-13 boringPublicKey
pub(super) fn boringPublicKey(_: &PublicKey) -> ! {
    panic!("boringcrypto: not available");
}

// go: sdk 1.25.5 crypto/ecdsa/notboring.go:14-16 boringPrivateKey
pub(super) fn boringPrivateKey(_: &PrivateKey) -> ! {
    panic!("boringcrypto: not available");
}
