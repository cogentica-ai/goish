// go: package crypto/internal/impl

// `impl` is a Rust keyword, so the module binding is renamed while the
// file keeps Go's name (GOISH015 matches on the file stem).
#[path = "impl.rs"]
mod impl_;

pub use impl_::*;
