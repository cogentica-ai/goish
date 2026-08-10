// go: package crypto/internal/fips140/hmac

mod hmac;

pub use hmac::{errCloneUnsupported, marshalable, MarkAsUsedInKDF, New, HMAC};
