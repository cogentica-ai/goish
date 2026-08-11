// go: file crypto/internal/fips140/nistec/nistec.go decls:
//
// Package nistec implements the elliptic curves from NIST SP 800-186.
//
// This package uses fiat-crypto or specialized assembly and Go code for
// its backend field arithmetic (not math/big) and exposes constant-time,
// heap allocation-free, byte slice-based safe APIs. Group operations use
// modern and safe complete addition formulas where possible. The point at
// infinity is handled and encoded according to SEC 1, Version 2.0, and
// invalid curve points can't be represented.
//
// nistec.go declares no functions: it is the package doc plus the blank
// import of crypto/internal/fips140/check, which registers the module
// integrity self-test. goish has no equivalent blank-import side effect —
// `crypto/internal/fips140/check` is not ported — so this file carries
// the doc alone.
