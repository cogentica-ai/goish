// go: file crypto/internal/fips140/aes/gcm/gcm_noasm.go decls: checkGenericIsExpected, initGCM, seal, open
//
// The GCM dispatch points. Go builds this file under
// `(!amd64 && !s390x && !ppc64 && !ppc64le && !arm64) || purego`; the
// assembly builds carry per-platform state in `gcmPlatformData` (the
// precomputed GHASH key powers) and replace seal/open with a fused
// AES-NI + PCLMULQDQ implementation.
//
// When that lands here, `gcmPlatformData` grows the product table,
// `initGCM` fills it, and `checkGenericIsExpected` gains the panic that
// catches the variable-time GHASH running while hardware support exists.

#![allow(non_snake_case)]
#![allow(non_camel_case_types)] // Go names (gcmPlatformData)

use crate::error;
use crate::goslice::slice;
use crate::types::byte;

use super::gcm::GCM;
use super::gcm_generic::{openGeneric, sealGeneric};

/// Go: `type gcmPlatformData struct{}` — empty on the generic build.
#[derive(Clone, Default)]
pub(crate) struct gcmPlatformData {}

// go: sdk 1.25.5 crypto/internal/fips140/aes/gcm/gcm_noasm.go:9-9 checkGenericIsExpected
/// Go: `func checkGenericIsExpected() {}`
pub(crate) fn checkGenericIsExpected() {}

// go: sdk 1.25.5 crypto/internal/fips140/aes/gcm/gcm_noasm.go:13-13 initGCM
/// Go: `func initGCM(g *GCM) {}`
pub(crate) fn initGCM(_g: &mut GCM) {}

// go: sdk 1.25.5 crypto/internal/fips140/aes/gcm/gcm_noasm.go:15-17 seal
/// Go: `func seal(out []byte, g *GCM, nonce, plaintext, data []byte)`
pub(crate) fn seal(
    out: &mut [byte],
    g: &GCM,
    nonce: &slice<byte>,
    plaintext: &slice<byte>,
    data: &slice<byte>,
) {
    // Go: sealGeneric(out, g, nonce, plaintext, data)
    sealGeneric(out, g, nonce, plaintext, data);
}

// go: sdk 1.25.5 crypto/internal/fips140/aes/gcm/gcm_noasm.go:19-21 open
/// Go: `func open(out []byte, g *GCM, nonce, ciphertext, data []byte) error`
pub(crate) fn open(
    out: &mut [byte],
    g: &GCM,
    nonce: &slice<byte>,
    ciphertext: &slice<byte>,
    data: &slice<byte>,
) -> error {
    // Go: return openGeneric(out, g, nonce, ciphertext, data)
    return openGeneric(out, g, nonce, ciphertext, data);
}
