// go: package net/http/internal/testcert
//
// net/http/internal/testcert — a test-only localhost certificate.
//
// The code lives in testcert.rs, mirroring Go's single testcert.go,
// because anchored code may not sit in a module root (GOISH015).

#![allow(non_snake_case)]

mod testcert;

pub use testcert::{LocalhostCert, LocalhostKey};
