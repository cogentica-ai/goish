// go: file crypto/internal/fips140/aes/aes_noasm.go decls: newBlock, encryptBlock, decryptBlock, checkGenericIsExpected
//
// The `block` type and the encrypt/decrypt/key-schedule dispatch points.
// Go builds this file under `(!amd64 && !s390x && !ppc64 && !ppc64le &&
// !arm64) || purego`, and swaps in aes_asm[go]'s AES-NI-dispatching
// versions otherwise.
//
// goish has only the generic path so far. When `expandKeyAsm`,
// `encryptBlockAsm` and `decryptBlockAsm` land they replace this file's
// bodies with the same `supportsAES` branch, and
// `checkGenericIsExpected` gains the panic that catches the generic
// implementation running while hardware support is available. Every
// caller stays untouched.

#![allow(non_snake_case)]
#![allow(non_camel_case_types)] // Go names (block)

use crate::goslice::slice;
use crate::types::byte;

use super::aes::{newBlockExpanded, zeroBlock, Block};
use super::aes_generic::{decryptBlockGeneric, encryptBlockGeneric};

/// Go: `type block struct { blockExpanded }` — the per-architecture block
/// representation. Every target but s390x uses the expanded key schedule,
/// so goish aliases it (see the note on [`Block`]).
#[allow(dead_code)]
pub(crate) type block = Block;

// go: sdk 1.25.5 crypto/internal/fips140/aes/aes_noasm.go:13-16 newBlock
/// Go: `func newBlock(c *Block, key []byte) *Block` — `c` is a
/// caller-allocated buffer that Go fills and hands back; goish returns
/// the Block by value.
/// goishlint:ignore GOISH020 newBlock — Go's out-param `c` is a return value here
pub(crate) fn newBlock(key: slice<byte>) -> Block {
    // Go: newBlockExpanded(&c.blockExpanded, key); return c
    let mut c = zeroBlock();
    newBlockExpanded(&mut c, &key);
    return c;
}

// go: sdk 1.25.5 crypto/internal/fips140/aes/aes_noasm.go:18-20 encryptBlock
/// Go: `func encryptBlock(c *Block, dst, src []byte)`
pub(crate) fn encryptBlock(c: &Block, dst: &mut slice<byte>, src: &slice<byte>) {
    // Go: encryptBlockGeneric(&c.blockExpanded, dst, src)
    encryptBlockGeneric(c, dst, src);
}

// go: sdk 1.25.5 crypto/internal/fips140/aes/aes_noasm.go:22-24 decryptBlock
/// Go: `func decryptBlock(c *Block, dst, src []byte)`
pub(crate) fn decryptBlock(c: &Block, dst: &mut slice<byte>, src: &slice<byte>) {
    // Go: decryptBlockGeneric(&c.blockExpanded, dst, src)
    decryptBlockGeneric(c, dst, src);
}

// go: sdk 1.25.5 crypto/internal/fips140/aes/aes_noasm.go:26-26 checkGenericIsExpected
/// Go: `func checkGenericIsExpected() {}`
///
/// A no-op on the generic build. aes_asm[go]'s version panics if the
/// variable-time implementation is reached while AES-NI is available.
pub(crate) fn checkGenericIsExpected() {}
