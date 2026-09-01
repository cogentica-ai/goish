// internal — Go's top-level `internal/` tree.
//
// Packages the standard library shares with itself but does not export.
// Go's `internal/` path convention is advisory; in goish the visibility
// boundary is Rust's `pub`/`pub(crate)`, so submodules are `pub mod`.

#![allow(non_snake_case)]

pub mod byteorder;
pub mod poll;
pub mod syscall;
