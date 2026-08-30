// go: file hash/crc32/crc32_otherarch.go decls: archAvailableIEEE, archInitIEEE, archUpdateIEEE, archAvailableCastagnoli, archInitCastagnoli, archUpdateCastagnoli
//
// hash/crc32/crc32_otherarch.go — the `arch*` interface for targets
// with no hardware CRC-32, which reports that there is none.
//
// Go guards this file with
// `//go:build !amd64 && !s390x && !ppc64le && !arm64 && !loong64`, and
// picks crc32_amd64.go instead on this host. goish ports *this* half
// deliberately: the amd64 half is SSE 4.2 and PCLMUL assembly
// (`castagnoliSSE42`, `castagnoliSSE42Triple`, `ieeeCLMUL`), which is
// not something you port by reading Go. Reporting "no acceleration" is
// therefore the truthful answer for goish, not a stub — every update
// really does go through crc32_generic.rs, and the `panic("not
// available")` bodies really are unreachable, exactly as they are on
// the Go builds that compile this file.

#![allow(non_snake_case)]

use crate::types::{byte, uint32};

// go: sdk 1.25.5 hash/crc32/crc32_otherarch.go:9-9 archAvailableIEEE
/// `crc32.archAvailableIEEE()` — whether an architecture-specific
/// CRC32-IEEE algorithm is available. It is not, in goish.
pub(super) fn archAvailableIEEE() -> bool {
    return false;
}

// go: sdk 1.25.5 hash/crc32/crc32_otherarch.go:10-10 archInitIEEE
/// `crc32.archInitIEEE()` — unreachable; [`archAvailableIEEE`] is false.
pub(super) fn archInitIEEE() {
    panic!("not available")
}

// go: sdk 1.25.5 hash/crc32/crc32_otherarch.go:11-11 archUpdateIEEE
/// `crc32.archUpdateIEEE(crc, p)` — unreachable; see [`archInitIEEE`].
pub(super) fn archUpdateIEEE(_crc: uint32, _p: &[byte]) -> uint32 {
    panic!("not available")
}

// go: sdk 1.25.5 hash/crc32/crc32_otherarch.go:13-13 archAvailableCastagnoli
/// `crc32.archAvailableCastagnoli()` — whether an
/// architecture-specific CRC32-C algorithm is available. It is not.
pub(super) fn archAvailableCastagnoli() -> bool {
    return false;
}

// go: sdk 1.25.5 hash/crc32/crc32_otherarch.go:14-14 archInitCastagnoli
/// `crc32.archInitCastagnoli()` — unreachable; see
/// [`archAvailableCastagnoli`].
pub(super) fn archInitCastagnoli() {
    panic!("not available")
}

// go: sdk 1.25.5 hash/crc32/crc32_otherarch.go:15-15 archUpdateCastagnoli
/// `crc32.archUpdateCastagnoli(crc, p)` — unreachable; see
/// [`archInitCastagnoli`].
pub(super) fn archUpdateCastagnoli(_crc: uint32, _p: &[byte]) -> uint32 {
    panic!("not available")
}
