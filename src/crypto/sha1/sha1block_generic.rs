// go: file crypto/sha1/sha1block_generic.go decls: block
//
// The SHA-1 block dispatch point. Go builds this file under
// `(!amd64 && !arm64 && !s390x) || purego`; sha1block_amd64[go]
// substitutes a `block` that picks between SHA-NI, AVX2 and the generic
// path at runtime.
//
// goish has only the generic path so far; when blockSHANI/blockAVX2 land
// they replace this body with the same runtime branch.

#![allow(non_snake_case)]

use crate::types::byte;

use super::sha1::Digest;
use super::sha1block::blockGeneric;

// go: sdk 1.25.5 crypto/sha1/sha1block_generic.go:9-11 block
/// Go: `func block(dig *digest, p []byte) { blockGeneric(dig, p) }`
pub(crate) fn block(dig: &mut Digest, p: &[byte]) {
    // Go: blockGeneric(dig, p)
    blockGeneric(dig, p);
}
