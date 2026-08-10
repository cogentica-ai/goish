// go: file crypto/md5/md5block_generic.go decls: block
//
// The MD5 block dispatch point. Go builds this file under
// `(!386 && !amd64 && !arm && … ) || purego`; md5block_decl[go] declares
// the assembly `block` for every other target and sets `haveAsm = true`.
//
// goish has only the generic path so far, so `haveAsm` is false here.
// When md5block_amd64's port lands it becomes the decl file's `true` and
// md5[go]'s Write picks the asm path — no caller changes.

#![allow(non_snake_case, non_upper_case_globals)]

use crate::types::byte;

use super::md5::Digest;
use super::md5block::blockGeneric;

/// Go: `const haveAsm = false`
#[allow(dead_code)]
pub(crate) const haveAsm: bool = false;

// go: sdk 1.25.5 crypto/md5/md5block_generic.go:11-13 block
/// Go: `func block(dig *digest, p []byte) { blockGeneric(dig, p) }`
pub(crate) fn block(dig: &mut Digest, p: &[byte]) {
    // Go: blockGeneric(dig, p)
    blockGeneric(dig, p);
}
