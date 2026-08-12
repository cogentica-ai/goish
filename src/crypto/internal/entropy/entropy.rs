// go: file crypto/internal/entropy/entropy.go decls: Depleted
//
// Package entropy provides the passive entropy source for the FIPS 140-3
// module. It is only used in FIPS mode by
// [crypto/internal/fips140/drbg.Read].
//
// This complies with IG 9.3.A, Additional Comment 12, which until January
// 1, 2026 allows new modules to meet an [earlier version] of Resolution
// 2(b): "A software module that contains an approved DRBG that receives a
// LOAD command (or its logical equivalent) with entropy obtained from
// [...] inside the physical perimeter of the operational environment of
// the module [...]."
//
// Distributions that have their own SP 800-90B entropy source should
// replace this package with their own implementation.
//
// [earlier version]: https://csrc.nist.gov/CSRC/media/Projects/cryptographic-module-validation-program/documents/IG%209.3.A%20Resolution%202b%5BMarch%2026%202024%5D.pdf
//

#![allow(non_snake_case)]

extern crate alloc;

use crate::crypto::internal::sysrand;
use crate::goslice::slice;
use crate::types::byte;

// go: sdk 1.25.5 crypto/internal/entropy/entropy.go:24-28 Depleted
/// Notify the entropy source that the entropy in the module is
/// "depleted" and provide the callback for the LOAD command.
pub fn Depleted<F: FnOnce(&[byte; 48])>(LOAD: F) {
    // Go: var entropy [48]byte; sysrand.Read(entropy[:]); LOAD(&entropy)
    let mut b = slice::__from_vec(alloc::vec![0u8; 48]);
    sysrand::Read(&mut b);
    let raw: &[byte] = &b;
    let mut entropy = [0u8; 48];
    entropy.copy_from_slice(raw);
    LOAD(&entropy);
}
