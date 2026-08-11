// go: file crypto/internal/fips140/notasan.go decls:
//
// Go pairs this with asan.go under `//go:build asan` / `!asan`. goish has
// no AddressSanitizer build, so only this side exists — the same
// build-tag decision recorded for nistec's purego files.

#![allow(non_upper_case_globals)]

/// Go: `const asanEnabled = false`
pub(crate) const asanEnabled: bool = false;
