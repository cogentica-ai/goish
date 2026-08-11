// go: package crypto/internal/sysrand

pub mod internal;
mod rand;
mod rand_getrandom;

pub use rand::Read;
