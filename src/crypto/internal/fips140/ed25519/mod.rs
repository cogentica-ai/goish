// go: package crypto/internal/fips140/ed25519

mod cast;
mod ed25519;

pub use ed25519::{
    GenerateKey, NewPrivateKey, NewPrivateKeyFromSeed, NewPublicKey, PrivateKey, PublicKey, Sign,
    SignCtx, SignPH, Verify, VerifyCtx, VerifyPH,
};
