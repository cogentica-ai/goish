// types — Go's predeclared numeric type aliases.
//
//   Go              goish
//   ─────────────   ──────────────
//   byte = uint8    byte = u8
//   rune = int32    rune = i32
//   int             int  = isize    ← platform-sized signed (Go's `int`)
//   uint            uint = usize
//
// `int` matches Go's int width on amd64 (64-bit). `rune` is signed
// just like Go's `type rune = int32`, even though valid code points
// are non-negative — this keeps literal arithmetic well-behaved.

#![allow(non_camel_case_types)]

pub type byte = u8;
pub type rune = i32;
pub type int = isize;
pub type uint = usize;
