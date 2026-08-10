// go: package crypto/internal/fips140/aes/gcm

mod gcm;
mod gcm_generic;
mod gcm_noasm;
mod ghash;

pub use gcm::{New, GCM};
pub use ghash::GHASH;
