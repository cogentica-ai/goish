// go: file crypto/rand/text.go decls: Text
//
// Deviation from text[go] @ Go 1.25.5: `for i := range src { src[i] = … }`
// is an index-only range over a buffer the body writes into. goish's
// `range!` borrows the collection immutably, so an in-place rewrite uses
// the counter loop the tree already uses for this Go shape (see
// `crypto/internal/fips140/subtle/xor_generic.rs::xorLoop`).

#![allow(non_snake_case, non_upper_case_globals)]

use crate::gostring::string;
use crate::types::byte;

use super::rand::Read;

// go: sdk 1.25.5 crypto/rand/text.go:7 base32alphabet
const base32alphabet: &str = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

// go: sdk 1.25.5 crypto/rand/text.go:9-22 Text
/// Return a cryptographically random string using the standard RFC 4648
/// base32 alphabet for use when a secret string, token, password, or
/// other text is needed. The result contains at least 128 bits of
/// randomness, enough to prevent brute force guessing attacks and to
/// make the likelihood of collisions vanishingly small. A future version
/// may return longer texts as needed to maintain those properties.
pub fn Text() -> string {
    // ⌈log₃₂ 2¹²⁸⌉ = 26 chars
    // Go: src := make([]byte, 26); Read(src)
    let mut src = crate::make!([]byte, 26);
    let _ = Read(&mut src);
    // Go: for i := range src { src[i] = base32alphabet[src[i]%32] }
    let alphabet: &[byte] = base32alphabet.as_bytes();
    let s: &mut [byte] = &mut src;
    let mut i: usize = 0;
    while i < s.len() {
        s[i] = alphabet[(s[i] % 32) as usize];
        i += 1;
    }
    // Go: return string(src)
    return string::from_bytes(&src);
}
