// go: package crypto/internal/sysrand/internal
//
// Go has no `internal` package here — the directory exists only to scope
// `seccomp` to crypto/internal/sysrand. This module is the Rust spelling
// of that directory and declares no items of its own.

pub mod seccomp;
