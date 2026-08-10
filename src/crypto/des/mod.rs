// go: package crypto/des
//
// Package des implements the Data Encryption Standard (DES) and the
// Triple Data Encryption Algorithm (TDEA) as defined in U.S. Federal
// Information Processing Standards Publication 46-3.
//
// DES is cryptographically broken and should not be used for secure
// applications.

mod block;
mod cipher;
#[path = "const.rs"] // `const` is a Rust keyword; the FILE keeps Go's name
mod konst;

pub use cipher::{BlockSize, Cipher, KeySizeError, NewCipher, NewTripleDESCipher, TripleDESCipher};
