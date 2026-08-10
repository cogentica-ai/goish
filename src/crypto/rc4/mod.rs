// go: package crypto/rc4
//
// Package rc4 implements RC4 encryption, as defined in Bruce Schneier's
// Applied Cryptography.
//
// RC4 is cryptographically broken and should not be used for secure
// applications.

mod rc4;

pub use rc4::{Cipher, KeySizeError, NewCipher};
