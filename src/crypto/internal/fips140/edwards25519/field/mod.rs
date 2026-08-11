// go: package crypto/internal/fips140/edwards25519/field

mod fe;
mod fe_amd64_noasm;
mod fe_generic;

pub use fe::*;
