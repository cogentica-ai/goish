// goish v1 — Go-style stdlib for Rust.
//
// no_std + no glibc. Built bottom-up like Go's standard library:
//
//   syscall (raw asm)  →  runtime (alloc + rt0)  →  GoString / GoSlice
//                     →  io  →  fmt
//
// User binaries opt in by adding `#![no_std]`, `#![no_main]`, and
// decorating their entry point with `#[goish::main]`.

#![no_std]
#![cfg_attr(not(test), no_main)]
#![allow(non_snake_case, non_upper_case_globals)]

pub mod builtin;
pub mod runtime;
pub mod syscall;

// Re-export Go's predeclared identifiers at the crate root so a single
// `use goish::{len, ...}` mirrors Go's always-available builtins.
pub use builtin::len;

// Re-export the entry-point attribute so users write `#[goish::main]`.
pub use goish_macros::main;
