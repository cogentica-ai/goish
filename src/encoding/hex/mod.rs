// go: package encoding/hex
//
// encoding/hex — hexadecimal encoding and decoding.
//
// One Rust file per Go file, so each carries its own provenance
// anchors (GOISH015):
//
//   hex.rs    hex.go    — the whole package
//
// This file is a module root, so it carries no `// go:` anchors.

#![allow(non_snake_case, non_camel_case_types, non_upper_case_globals)]

pub mod hex;

pub use hex::{
    AppendDecode, AppendEncode, Decode, DecodeString, DecodedLen, Dump, Dumper, Encode,
    EncodeToString, EncodedLen, ErrLength, InvalidByteError, NewDecoder, NewEncoder,
};
