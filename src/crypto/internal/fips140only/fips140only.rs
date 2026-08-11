// go: file crypto/internal/fips140only/fips140only.go decls: ApprovedHash, ApprovedRandomReader
//
// Deviation from fips140only[go] @ Go 1.25.5: Go's
// `var Enabled = godebug.New("fips140").Value() == "only"` reads a
// GODEBUG setting. goish has no GODEBUG — `internal/godebug` is a runtime
// registry with linkname hooks into the metrics system, and porting a
// stub of it would be inventing, not porting — so `Enabled` is a `const
// false`, matching how `crypto/internal/fips140::Enabled()` is already
// spelled in this tree.
//
// The consequence is that every `if fips140only.Enabled` guard in the
// public crypto packages is statically dead. Those guards are still
// ported in full: they are real Go code, and the day goish grows a
// GODEBUG they must already be correct.

#![allow(non_snake_case, non_upper_case_globals)]

use crate::crypto::internal::fips140::drbg;
use crate::crypto::internal::fips140::sha256;
use crate::crypto::internal::fips140::sha3;
use crate::crypto::internal::fips140::sha512;
use crate::goany::AsExt;
use crate::hash::Hash;
use crate::io;

extern crate alloc;
use alloc::boxed::Box;

/// Go: `var Enabled = godebug.New("fips140").Value() == "only"` — whether
/// FIPS 140-only mode is enabled, in which non-approved cryptography
/// returns an error or panics. Always false in goish; see the file
/// header.
pub const Enabled: bool = false;

// go: sdk 1.25.5 crypto/internal/fips140only/fips140only.go:21-28 ApprovedHash
/// Go: `switch h.(type) { case *sha256.Digest, *sha512.Digest,
/// *sha3.Digest: return true; default: return false }`.
pub fn ApprovedHash(h: &Box<dyn Hash + Send + Sync>) -> bool {
    // Go's type switch becomes three concrete downcasts through the
    // interface's registry — `.As::<T>()` is `v.(*T)` without the
    // comma-ok, which is exactly what the switch arms test.
    let h: &(dyn Hash + Send + Sync) = &**h;
    return h.As::<sha256::Digest>().is_some()
        || h.As::<sha512::Digest>().is_some()
        || h.As::<sha3::Digest>().is_some();
}

// go: sdk 1.25.5 crypto/internal/fips140only/fips140only.go:30-33 ApprovedRandomReader
/// Go: `_, ok := r.(drbg.DefaultReader); return ok`.
pub fn ApprovedRandomReader(r: &mut (dyn io::Reader + Send + Sync + 'static)) -> bool {
    let (_, ok) = goish::cast!(r, drbg::DefaultReader);
    return ok;
}
