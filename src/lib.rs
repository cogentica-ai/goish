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
    pub use alloc::boxed::Box;
    pub use alloc::vec::Vec;
    pub use alloc::vec;
}

// ─── byte-size unit constants ───────────────────────────────────────
//
// Convenience constants for sizes (stack sizes, buffer caps, etc.):
//
//   go!(stack(8 * KB), || tiny_helper());
//   go!(stack(1 * MB), || deep_recursion());
//
// Mirrors Go's idiom of writing literal multiplications (`8 << 10`
// or `8 * 1024`); having named constants is purely ergonomic.

/// One kilobyte (1024 bytes).
pub const KB: usize = 1024;
/// One megabyte (1024 KiB).
pub const MB: usize = 1024 * 1024;
/// One gigabyte (1024 MiB).
pub const GB: usize = 1024 * 1024 * 1024;

pub mod bufio;
pub mod builtin;
pub mod builtin_macros;
pub mod bytes;
pub mod cmp;
pub mod compress;
pub mod container;
pub mod context;
pub mod convert;
pub mod crypto;
pub mod defer;
pub mod encoding;
pub mod errors;
pub mod expvar;
pub mod flag;
pub mod fmt;
pub mod gochan;
pub mod gomap;
pub mod goslice;
pub mod gostring;
pub mod hash;
pub mod html;
pub mod maps;
pub mod io;
pub mod log;
pub mod math;
pub mod mime;
pub mod net;
pub mod os;
pub mod path;
pub mod range;
pub mod reflect;
pub mod runtime;
pub mod select_macro;
pub mod slices;
pub mod sort;
pub mod strconv;
pub mod strings;
pub mod sync;
pub mod syscall;
pub mod testing;
pub mod text;
pub mod time;
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
pub use gomap::map;
pub use goslice::slice;
pub use gostring::string;
pub use types::{byte, float32, float64, int, rune, uint};

// Re-export the entry-point attribute so users write `#[goish::main]`.
pub use goish_macros::main;
// Re-export the reflect attribute so users write `#[goish::reflect]`.
// (The `goish::reflect` module path coexists — attributes and modules
// occupy different namespaces, just like `goish::main` doesn't conflict.)
pub use goish_macros::reflect;
