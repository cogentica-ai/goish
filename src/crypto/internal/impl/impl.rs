// go: file crypto/internal/impl/impl.go decls: Register, Packages, List, available, Select, Reset
//
// Package impl is a registry of alternative implementations of
// cryptographic primitives, to allow selecting them for testing.
//
// Deviations from impl[go] @ Go 1.25.5:
//
//   * `Toggle *bool` points at a package-level `var` in another package
//     (e.g. aes's `useAsm`), which Go's tests flip to force a code path.
//     A `*mut bool` into another module's static is not expressible
//     safely in Rust, so the field is `&'static AtomicBool` and the
//     registering package passes a reference to its own flag. Same
//     aliasing, same effect, no raw pointer.
//   * `var allImplementations []implementation` is a mutable global. It is
//     behind the runtime's `SpinLock` here — not `sync::Mutex`, because
//     `Register` is called from package initialisation, which in goish is
//     not a goroutine (see AGENTS.md and the "main is not a goroutine"
//     rule), and `sync::Mutex` needs one.
//   * Go's `strings.Contains` is spelled with the goish `strings` package.

#![allow(non_snake_case, non_camel_case_types, non_upper_case_globals)]

extern crate alloc;
use alloc::vec::Vec;

use core::sync::atomic::{AtomicBool, Ordering};

use crate::goslice::slice;
use crate::runtime::spin::SpinLock;
use crate::string;
use crate::strings;

// Go: impl.go:11-16
//   type implementation struct { Package, Name string; Available bool; Toggle *bool }
struct implementation {
    Package: string,
    Name: string,
    Available: bool,
    Toggle: &'static AtomicBool,
}

// Go: impl.go:18 — `var allImplementations []implementation`
static allImplementations: SpinLock<Vec<implementation>> = SpinLock::new(Vec::new());

// go: sdk 1.25.5 crypto/internal/impl/impl.go:20-39 Register
/// Record an alternative implementation of a cryptographic primitive. The
/// implementation might be available or not based on CPU support. If
/// available is false, the implementation is unavailable and can't be
/// tested on this machine. If available is true, it can be set to false to
/// disable the implementation. If all alternative implementations but one
/// are disabled, the remaining one must be used (i.e. disabling one
/// implementation must not implicitly disable any other). Each package has
/// an implicit base implementation that is selected when all alternatives
/// are unavailable or disabled. pkg must be the package name, not path
/// (e.g. "aes" not "crypto/aes").
pub fn Register<P: Into<string>, N: Into<string>>(pkg: P, name: N, available: &'static AtomicBool) {
    let pkg = pkg.into();
    if strings::Contains(&pkg, "/") {
        panic!("impl: package name must not contain slashes");
    }
    let mut all = allImplementations.lock();
    all.push(implementation {
        Package: pkg,
        Name: name.into(),
        Available: available.load(Ordering::SeqCst),
        Toggle: available,
    });
}

// go: sdk 1.25.5 crypto/internal/impl/impl.go:41-53 Packages
/// Return the list of all packages for which alternative implementations
/// are registered.
pub fn Packages() -> slice<string> {
    let mut pkgs: Vec<string> = Vec::new();
    let mut seen: Vec<string> = Vec::new();
    let all = allImplementations.lock();
    for i in all.iter() {
        if !seen.iter().any(|s| *s == i.Package) {
            pkgs.push(i.Package.clone());
            seen.push(i.Package.clone());
        }
    }
    return slice::__from_vec(pkgs);
}

// go: sdk 1.25.5 crypto/internal/impl/impl.go:55-66 List
/// Return the names of all alternative implementations registered for the
/// given package, whether available or not. The implicit base
/// implementation is not included.
pub fn List<P: Into<string>>(pkg: P) -> slice<string> {
    let pkg = pkg.into();
    let mut names: Vec<string> = Vec::new();
    let all = allImplementations.lock();
    for i in all.iter() {
        if i.Package == pkg {
            names.push(i.Name.clone());
        }
    }
    return slice::__from_vec(names);
}

// go: sdk 1.25.5 crypto/internal/impl/impl.go:68-75 available
fn available(pkg: &string, name: &string) -> bool {
    let all = allImplementations.lock();
    for i in all.iter() {
        if i.Package == *pkg && i.Name == *name {
            return i.Available;
        }
    }
    panic!("unknown implementation");
}

// go: sdk 1.25.5 crypto/internal/impl/impl.go:77-98 Select
/// Disable all implementations for the given package except the one with
/// the given name. If name is empty, the base implementation is selected.
/// It returns whether the selected implementation is available.
pub fn Select<P: Into<string>, N: Into<string>>(pkg: P, name: N) -> bool {
    let pkg = pkg.into();
    let name = name.into();
    if name == string::from_static("") {
        let all = allImplementations.lock();
        for i in all.iter() {
            if i.Package == pkg {
                i.Toggle.store(false, Ordering::SeqCst);
            }
        }
        return true;
    }
    if !available(&pkg, &name) {
        return false;
    }
    let all = allImplementations.lock();
    for i in all.iter() {
        if i.Package == pkg {
            i.Toggle.store(i.Name == name, Ordering::SeqCst);
        }
    }
    return true;
}

// go: sdk 1.25.5 crypto/internal/impl/impl.go:100-107 Reset
pub fn Reset<P: Into<string>>(pkg: P) {
    let pkg = pkg.into();
    let all = allImplementations.lock();
    for i in all.iter() {
        if i.Package == pkg {
            i.Toggle.store(i.Available, Ordering::SeqCst);
            return;
        }
    }
}
