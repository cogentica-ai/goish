// go: file crypto/internal/fips140/aes/ctr_noasm.go decls: ctrBlocks1, ctrBlocks2, ctrBlocks4, ctrBlocks8
//
// The CTR block-batch dispatch points. Go builds this file under
// `(!amd64 && !arm64 && !s390x && !ppc64 && !ppc64le) || purego`; the
// assembly builds substitute ctr_asm[go]'s `ctrBlocksNAsm` calls, which
// is where AES-NI pipelining pays off for CTR (and therefore for GCM).
//
// When those land they replace each body here with the same
// `if !supportsAES { … } else { ctrBlocksNAsm(…) }` branch, leaving
// ctr[go]'s caller untouched.

#![allow(non_snake_case)]

use crate::goslice::slice;
use crate::types::{byte, uint64};

use super::aes::Block;
use super::ctr::ctrBlocks;

// go: sdk 1.25.5 crypto/internal/fips140/aes/ctr_noasm.go:9-11 ctrBlocks1
/// Go: `func ctrBlocks1(b *Block, dst, src *[BlockSize]byte, ivlo, ivhi uint64)`
pub(crate) fn ctrBlocks1(
    b: &Block,
    dst: &mut slice<byte>,
    src: &slice<byte>,
    ivlo: uint64,
    ivhi: uint64,
) {
    // Go: ctrBlocks(b, dst[:], src[:], ivlo, ivhi)
    ctrBlocks(b, dst, src, ivlo, ivhi);
}

// go: sdk 1.25.5 crypto/internal/fips140/aes/ctr_noasm.go:13-15 ctrBlocks2
/// Go: `func ctrBlocks2(b *Block, dst, src *[2 * BlockSize]byte, ivlo, ivhi uint64)`
pub(crate) fn ctrBlocks2(
    b: &Block,
    dst: &mut slice<byte>,
    src: &slice<byte>,
    ivlo: uint64,
    ivhi: uint64,
) {
    // Go: ctrBlocks(b, dst[:], src[:], ivlo, ivhi)
    ctrBlocks(b, dst, src, ivlo, ivhi);
}

// go: sdk 1.25.5 crypto/internal/fips140/aes/ctr_noasm.go:17-19 ctrBlocks4
/// Go: `func ctrBlocks4(b *Block, dst, src *[4 * BlockSize]byte, ivlo, ivhi uint64)`
pub(crate) fn ctrBlocks4(
    b: &Block,
    dst: &mut slice<byte>,
    src: &slice<byte>,
    ivlo: uint64,
    ivhi: uint64,
) {
    // Go: ctrBlocks(b, dst[:], src[:], ivlo, ivhi)
    ctrBlocks(b, dst, src, ivlo, ivhi);
}

// go: sdk 1.25.5 crypto/internal/fips140/aes/ctr_noasm.go:21-23 ctrBlocks8
/// Go: `func ctrBlocks8(b *Block, dst, src *[8 * BlockSize]byte, ivlo, ivhi uint64)`
pub(crate) fn ctrBlocks8(
    b: &Block,
    dst: &mut slice<byte>,
    src: &slice<byte>,
    ivlo: uint64,
    ivhi: uint64,
) {
    // Go: ctrBlocks(b, dst[:], src[:], ivlo, ivhi)
    ctrBlocks(b, dst, src, ivlo, ivhi);
}
