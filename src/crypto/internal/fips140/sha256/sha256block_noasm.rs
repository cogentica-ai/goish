// go: file crypto/internal/fips140/sha256/sha256block_noasm.go decls: block

#![allow(non_snake_case)]

use crate::types::byte;

use super::sha256::Digest;
use super::sha256block::blockGeneric;

// go: sdk 1.25.5 crypto/internal/fips140/sha256/sha256block_noasm.go:9-11 block
//
//   func block(dig *Digest, p []byte) { blockGeneric(dig, p) }
//
// goish has no SHA-NI path yet, so the noasm dispatcher is the only one.
// Porting sha256block_amd64.s is tracked as performance work.
pub(crate) fn block(dig: &mut Digest, p: &[byte]) {
    blockGeneric(dig, p);
}
