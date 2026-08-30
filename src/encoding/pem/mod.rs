// go: package encoding/pem
//
// encoding/pem — the PEM data encoding, which originated in Privacy
// Enhanced Mail (RFC 1421). Its most common use today is in TLS keys
// and certificates.
//
// One Rust file per Go file, so each carries its own provenance
// anchors (GOISH015):
//
//   pem.rs    pem.go    — the whole package
//
// This file is a module root, so it carries no `// go:` anchors.

#![allow(non_snake_case, non_camel_case_types, non_upper_case_globals)]

pub mod pem;

pub use pem::{Block, Decode, Encode, EncodeToMemory};
