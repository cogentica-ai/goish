// go: file crypto/internal/fips140/aes/cbc_noasm.go decls: cryptBlocksEnc, cryptBlocksDec
//
// The CBC dispatch points. Go builds this file under `(!s390x && !ppc64
// && !ppc64le) || purego`; the s390x and POWER8 builds substitute
// hardware chaining-mode instructions. amd64 has no CBC assembly even in
// Go — AES-NI accelerates the block function, and cbc.go's loop calls it
// per block — so this file is the amd64 path in Go too, not a goish
// simplification.

#![allow(non_snake_case)]

use crate::goslice::slice;
use crate::types::byte;

use super::aes::Block;
use super::cbc::{cryptBlocksDecGeneric, cryptBlocksEncGeneric};

// go: sdk 1.25.5 crypto/internal/fips140/aes/cbc_noasm.go:9-11 cryptBlocksEnc
/// Go: `func cryptBlocksEnc(b *Block, civ *[BlockSize]byte, dst, src []byte)`
pub(crate) fn cryptBlocksEnc(
    b: &Block,
    civ: &mut [byte; 16],
    dst: &mut slice<byte>,
    src: &slice<byte>,
) {
    // Go: cryptBlocksEncGeneric(b, civ, dst, src)
    cryptBlocksEncGeneric(b, civ, dst, src);
}

// go: sdk 1.25.5 crypto/internal/fips140/aes/cbc_noasm.go:13-15 cryptBlocksDec
/// Go: `func cryptBlocksDec(b *Block, civ *[BlockSize]byte, dst, src []byte)`
pub(crate) fn cryptBlocksDec(
    b: &Block,
    civ: &mut [byte; 16],
    dst: &mut slice<byte>,
    src: &slice<byte>,
) {
    // Go: cryptBlocksDecGeneric(b, civ, dst, src)
    cryptBlocksDecGeneric(b, civ, dst, src);
}
