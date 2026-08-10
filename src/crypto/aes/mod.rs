// go: package crypto/aes
//
// Package aes implements AES encryption (formerly Rijndael), as defined
// in U.S. Federal Information Processing Standards Publication 197.

mod aes;

pub use aes::{Block, BlockSize, KeySizeError, NewCipher};
