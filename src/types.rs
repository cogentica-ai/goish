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
pub type uintptr = u64;
pub type float32 = f32;
pub type float64 = f64;

// Fixed-width Go integer types — Go's int8/int16/int32/int64 and uint8/uint16/uint32/uint64.
// int32 == rune, int64 == int, uint8 == byte, uint64 == uint.
pub type int8 = i8;
pub type int16 = i16;
pub type int32 = i32;
pub type int64 = i64;
pub type uint8 = u8;
pub type uint16 = u16;
pub type uint32 = u32;
pub type uint64 = u64;

// Goish has no native complex arithmetic; we model `complex64`/`complex128`
// as `(real, imag)` tuples so `reflect::Value::Complex()` and ports that
// merely format complex values (e.g. kylelemons' pretty-printer) compile.
// Arithmetic on these types is *not* supported — call sites that perform
// real complex math must hand-port using a dedicated crate.
pub type complex64 = (f32, f32);
pub type complex128 = (f64, f64);
