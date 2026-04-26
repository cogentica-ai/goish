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

// Hidden re-export so `make!`/`slice!`/`append!` macros can reach Vec
// from inside user binaries that haven't added `extern crate alloc;`.
// Users never write this path directly.
#[doc(hidden)]
pub mod __macro_alloc {
    pub use alloc::vec::Vec;
    pub use alloc::vec;
}

pub mod bufio;
pub mod builtin;
pub mod builtin_macros;
pub mod bytes;
pub mod convert;
pub mod defer;
pub mod errors;
pub mod fmt;
pub mod goslice;
pub mod gostring;
pub mod io;
pub mod os;
pub mod range;
pub mod runtime;
pub mod slices;
pub mod strconv;
pub mod strings;
pub mod syscall;
pub mod types;
pub mod unicode;

// Re-export Go's predeclared identifiers at the crate root so a single
// `use goish::{len, string, ...}` mirrors Go's always-available builtins.
pub use builtin::{cap, len};
// Both `string` (the type, in gostring) and `string` (the conversion
// function, in convert) are re-exported here. They occupy different
// namespaces (type vs value), exactly like Go's `string` type and
// `string(...)` conversion. Same for `slice<T>`.
pub use convert::{bytes, runes, string};
pub use errors::{error, nil};
pub use goslice::slice;
pub use gostring::string;
pub use types::{byte, int, rune, uint};

// Re-export the entry-point attribute so users write `#[goish::main]`.
pub use goish_macros::main;
