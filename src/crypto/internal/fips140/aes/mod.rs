// go: package crypto/internal/fips140/aes

mod aes;
pub mod gcm;
mod aes_generic;
mod aes_noasm;
mod cbc;
mod cbc_noasm;
mod ctr;
mod ctr_noasm;
// `const` is a Rust keyword; mount const.rs under a legal name. The file
// stem still matches Go's const.go, which is what GOISH015 checks.
#[path = "const.rs"]
mod konst;

pub use aes::{Block, BlockSize, EncryptBlockInternal, KeySizeError, New};
pub use cbc::{CBCDecrypter, CBCEncrypter, NewCBCDecrypter, NewCBCEncrypter};
pub use ctr::{NewCTR, RoundToBlock, CTR};
