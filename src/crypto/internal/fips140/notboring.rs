// go: file crypto/internal/fips140/notboring.go decls:
//
// Go pairs this with boring.go under `//go:build boringcrypto` /
// `!boringcrypto`. goish has no BoringCrypto build, so only this side
// exists.

#![allow(non_upper_case_globals)]

/// Go: `const boringEnabled = false`
pub(crate) const boringEnabled: bool = false;
