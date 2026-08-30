// go: package text/scanner
//
// text/scanner — a scanner and tokenizer for UTF-8-encoded text.
//
// One Rust file per Go file, so each carries its own provenance
// anchors (GOISH015):
//
//   scanner.rs    scanner.go    — the whole package
//
// This file is a module root, so it carries no `// go:` anchors.

#![allow(non_snake_case, non_camel_case_types, non_upper_case_globals)]

pub mod scanner;

pub use scanner::{
    Char, Comment, Float, GoTokens, GoWhitespace, Ident, Int, NewScanner, Position, RawString,
    ScanChars, ScanComments, ScanFloats, ScanIdents, ScanInts, ScanRawStrings, ScanStrings,
    Scanner, SkipComments, String, TokenString, EOF,
};
