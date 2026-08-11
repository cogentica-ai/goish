// go: package crypto/internal/fips140deps
//
// crypto/internal/fips140deps — the allow-listed dependencies the
// FIPS 140-3 module may reach outside itself. In Go these are thin
// re-export shims over `internal/*` packages so the module's source can
// be vendored and validated on its own.
//
// goish ships the shims that the ported fips140 packages actually use.
// `cpu` and the `fipsdeps` dependency test land with the packages that
// need them.

pub mod byteorder;
pub mod godebug;
