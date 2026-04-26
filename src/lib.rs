// goish v1 — Go-style stdlib for Rust.
//
// no_std + no glibc. Built bottom-up like Go's standard library:
//
//   syscall (raw asm)  →  runtime (alloc + rt0)  →  string / slice<T>
//                     →  io  →  fmt
//
// User binaries opt in by adding `#![no_std]`, `#![no_main]`, and
// decorating their entry point with `#[goish::main]`.

#![no_std]
#![cfg_attr(not(test), no_main)]
#![allow(non_snake_case, non_upper_case_globals)]

// Pull in `alloc` so Vec / String / Box are available across all of
// goish, backed by our mmap allocator (registered as #[global_allocator]
// in runtime::heap). User crates that want these types should also add
// `extern crate alloc;` to their root.
extern crate alloc;

pub mod builtin;
pub mod convert;
pub mod goslice;
pub mod gostring;
pub mod range;
pub mod runtime;
pub mod syscall;
pub mod types;
pub mod unicode;

// Re-export Go's predeclared identifiers at the crate root so a single
// `use goish::{len, string, ...}` mirrors Go's always-available builtins.
pub use builtin::len;
// Both `string` (the type, in gostring) and `string` (the conversion
// function, in convert) are re-exported here. They occupy different
// namespaces (type vs value), exactly like Go's `string` type and
// `string(...)` conversion. Same for `slice<T>`.
pub use convert::{bytes, runes, string};
pub use goslice::slice;
pub use gostring::string;
pub use types::{byte, int, rune, uint};

// Re-export the entry-point attribute so users write `#[goish::main]`.
pub use goish_macros::main;
