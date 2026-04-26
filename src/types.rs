// types — Go's predeclared numeric type aliases.
//
//   Go              goish
//   ─────────────   ──────────────
//   byte = uint8    byte = u8
//   rune = int32    rune = i32
//   int             int  = i64       ← matches Go's `int` width on amd64
//   uint            uint = u64
//
// We pin `int = i64` (rather than `isize`) so `From<i32>` and friends
// are implemented in core, which makes `.into()` Just Work in the
// `slice!`/`append!` macros for integer literals. v1 targets 64-bit
// Linux only, so this matches Go's int width exactly. (On a true
// 32-bit port, this alias would change to i32; v1 defers that.)
//
// `rune` is signed like Go's `type rune = int32`, even though valid
// code points are non-negative — keeps literal arithmetic well-behaved.

#![allow(non_camel_case_types)]

pub type byte = u8;
pub type rune = i32;
pub type int = i64;
pub type uint = u64;
pub type float32 = f32;
pub type float64 = f64;
