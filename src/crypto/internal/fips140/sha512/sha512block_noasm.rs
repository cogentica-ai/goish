// go: file crypto/internal/fips140/sha512/sha512block_noasm.go decls: block
//
// The `block` dispatch point. Go builds this file under
// `(!amd64 && !arm64 && …) || purego` and swaps in
// sha512block_amd64[go]'s AVX2-dispatching `block` otherwise. goish has
// only the generic path so far; when `blockAVX2` lands it replaces this
// file's body with the same `useAVX2` branch, leaving every caller
// untouched.

#![allow(non_snake_case)]

use crate::types::byte;

use super::sha512::Digest;
use super::sha512block::blockGeneric;

// go: sdk 1.25.5 crypto/internal/fips140/sha512/sha512block_noasm.go:9-11 block
/// Go: `func block(dig *Digest, p []byte) { blockGeneric(dig, p) }`
pub(crate) fn block(dig: &mut Digest, p: &[byte]) {
    // Go: blockGeneric(dig, p)
    blockGeneric(dig, p);
}
