// go: package unicode/utf8
//
// unicode/utf8 — UTF-8 encoding and decoding.
//
// One Rust file per Go file, so each carries its own provenance
// anchors (GOISH015):
//
//   utf8.rs      utf8.go      — the whole package
//
// This file is a module root, so it carries no `// go:` anchors.

#![allow(non_snake_case, non_upper_case_globals)]

pub mod utf8;

pub use utf8::{
    AppendRune, DecodeLastRune, DecodeLastRuneInString, DecodeRune, DecodeRuneInString, EncodeRune,
    FullRune, FullRuneInString, MaxRune, RuneCount, RuneCountInString, RuneError, RuneLen,
    RuneSelf, RuneStart, UTFMax, Valid, ValidRune, ValidString,
};
