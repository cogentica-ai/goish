// go: package encoding/gob
//
// encoding/gob — Go's self-describing binary stream codec.
//
// This file is a module root, so it carries no `// go:` anchors.
//
// WHAT IS HERE AND WHAT IS NOT. The wire PRIMITIVES are ported: the two
// buffers, the variable-length uint and int encodings, the byte-reversed
// float encoding, and the reader-side length decoder. The engines that
// sit on them — encode.go's encOp table, decode.go's decOp table,
// type.go's wire types and the Encoder/Decoder themselves — are not,
// and they are blocked on TWO things that live outside this package:
//
//   1. reflect. gob's engines walk a `reflect.Value` and the decoder
//      WRITES through it. goish's `reflect::Value` is a read-only deep
//      clone, and goish's reflect has no `Implements` / `CanAddr` /
//      `Addr` / `NumMethod` / `Method`, so GobEncoder / GobDecoder
//      dispatch cannot be expressed either. Same blocker encoding/xml's
//      marshalValue hit; see ROADMAP §2.
//
//   2. recover. gob signals every internal error by PANICKING with a
//      `gobError` and catching it at the top of Encode/Decode
//      (`error.go`'s error_/errorf/catchError). goish's `recover!()`
//      observes a panic but does NOT stop its propagation — the
//      goroutine still dies (src/defer.rs says so in as many words) —
//      so that whole error-signalling scheme has no goish equivalent.
//      Porting it means turning ~50 `error_(...)` call sites into
//      explicit error returns, which is a structural port, not a
//      faithful one, and that is a decision rather than typing.
//
// Everything in this module is reachable without either, which is why
// it is the part that got written down first.

#![allow(non_snake_case, non_camel_case_types, non_upper_case_globals)]

pub mod decode;
pub mod decoder;
pub mod encode;

pub use decode::{decBuffer, decodeUintReader, float64FromBits, overflow};
pub use encode::{encBuffer, encoderState, floatBits};
