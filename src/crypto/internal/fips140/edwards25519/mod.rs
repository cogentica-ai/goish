// go: package crypto/internal/fips140/edwards25519

mod edwards25519;
pub mod field;
mod scalar;
mod scalar_fiat;

pub use edwards25519::*;
pub use scalar::*;
