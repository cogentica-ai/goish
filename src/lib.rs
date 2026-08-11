// goish v1 — Go-style stdlib for Rust.
//
// no_std + no glibc. Built bottom-up like Go's standard library:
//
//   syscall (raw asm)  →  runtime (alloc + rt0)  →  string / slice<T>
//                     →  io  →  fmt
//
// User binaries opt in by adding `#![no_std]`, `#![no_main]`, and
// decorating their entry point with `#[goish::main]`.

#![no_std]
#![cfg_attr(not(test), no_main)]
#![allow(non_snake_case, non_upper_case_globals)]
// goish mirrors Go identifiers verbatim, and Go's crypto packages use the
// Greek letters of the specs they implement (ML-KEM's ρ/σ/μ from FIPS 203).
// The confusable-idents lint fires on those against ASCII names elsewhere
// in the crate; renaming them would break the 1:1 mapping to the Go source.
#![allow(confusable_idents)]

// Pull in `alloc` so Vec / String / Box are available across all of
// goish, backed by our mmap allocator (registered as #[global_allocator]
// in runtime::heap). User crates that want these types should also add
// `extern crate alloc;` to their root.
extern crate alloc;

// Self-alias so proc-macros (e.g. `goish::var!` from `goish-macros`) that
// emit `::goish::...` paths resolve correctly when expanded INSIDE this
// crate. External users get the same name via the crate's package name.
extern crate self as goish;

// Hidden re-export so `make!`/`slice!`/`append!` macros can reach Vec
// from inside user binaries that haven't added `extern crate alloc;`.
// Users never write this path directly.
#[doc(hidden)]
pub mod __macro_alloc {
    pub use alloc::boxed::Box;
    pub use alloc::vec::Vec;
    pub use alloc::vec;
}

// ─── byte-size unit constants ───────────────────────────────────────
//
// Convenience constants for sizes (stack sizes, buffer caps, etc.):
//
//   go!(stack(8 * KB), || tiny_helper());
//   go!(stack(1 * MB), || deep_recursion());
//
// Mirrors Go's idiom of writing literal multiplications (`8 << 10`
// or `8 * 1024`); having named constants is purely ergonomic.

/// One kilobyte (1024 bytes).
pub const KB: usize = 1024;
/// One megabyte (1024 KiB).
pub const MB: usize = 1024 * 1024;
/// One gigabyte (1024 MiB).
pub const GB: usize = 1024 * 1024 * 1024;

pub mod archive;
pub mod bufio;
pub mod builtin;
pub mod builtin_macros;
pub mod bytes;
pub mod cmp;
pub mod compress;
pub mod container;
pub mod context;
pub mod convert;
pub mod crypto;
pub mod database;
pub mod defer;
pub mod embed;
pub mod encoding;
pub mod errors;
pub mod expvar;
pub mod flag;
pub mod fmt;
pub mod goany;
pub mod goarray;
pub mod gochan;
pub mod gomap;
pub mod goslice;
pub mod gostring;
pub mod r#go;
pub mod hook;
pub mod lazy;
pub mod gonilable;
pub mod gonilable_ref;
pub mod nilval;
pub mod hash;
pub mod html;
pub mod internal;
pub mod maps;
pub mod io;
pub mod iter;
pub mod xxh3;
pub mod log;
pub mod math;
pub mod mime;
pub mod net;
pub mod os;
pub mod path;
pub mod range;
pub mod reflect;
pub mod regexp;
pub mod runtime;
pub mod select_macro;
pub mod slices;
pub mod sort;
pub mod strconv;
pub mod strings;
pub mod sync;
pub mod syscall;
pub mod term;
pub mod testing;
pub mod text;
pub mod time;
pub mod types;
pub mod unicode;

// Top-level `fs` is Go's `io/fs` (Go 1.16+). Re-export rather than
// declare a second copy so paths `goish::fs::FileMode` and
// `goish::io::fs::FileMode` refer to the same type. The transpiler's
// prelude rule (pass4_decls.goishPreludeItems) routes `fs::*` bare paths
// through `use goish::{fs, ...}`.
pub use crate::io::fs;

// Re-export Go's predeclared identifiers at the crate root so a single
// `use goish::{len, string, ...}` mirrors Go's always-available builtins.
pub use builtin::{cap, len, Len};
// Both `string` (the type, in gostring) and `string` (the conversion
// function, in convert) are re-exported here. They occupy different
// namespaces (type vs value), exactly like Go's `string` type and
// `string(...)` conversion. Same for `slice<T>`.
pub use convert::{
    byte, bytes, float32, float64, int, int16, int32, int64, int8, rune, runes, string, uint,
    uint16, uint32, uint64, uint8, NumCast,
};
pub use errors::error;
pub use goany::Any;
pub use goany::try_consume_box;
pub use gonilable::nilable;
pub use gonilable_ref::{nilable_ref, nilable_refmut};

// Carry-form aliases — shorthand for the `Arc<dyn TRAIT>` shapes the
// reasoner cache shows are spelled at >900 stdlib call sites. Trailing
// underscore reads as "the trait-object carry of TRAIT" without
// shadowing the underlying trait name. (See goishc-reasoner cache
// info for the slot counts; these were chosen as the top non-Fn
// `Arc<dyn>` shapes by frequency.)
pub type Reader_ = alloc::sync::Arc<dyn io::Reader>;
pub type Writer_ = alloc::sync::Arc<dyn io::Writer>;
pub type Context_ = alloc::sync::Arc<dyn context::Context>;

/// `&mut slice<byte>` — the mutable-byte-slice borrow, used at 271
/// stdlib param positions (BufferTo, AppendTo, ReadFull-style APIs).
#[allow(non_camel_case_types)]
pub type bytes_mut<'a> = &'a mut goslice::slice<types::byte>;

/// `bytes_` — the borrow form of a byte slice (read-only). 660 stdlib
/// param positions. Use over `&slice<byte>` when call-site brevity
/// matters; both spellings compile identically.
#[allow(non_camel_case_types)]
pub type bytes_<'a> = &'a goslice::slice<types::byte>;

/// `nilable!` — single surface spelling for the three nilable cells.
///
/// Expands at parse time to the concrete runtime type:
///
///   nilable![T]        → goish::nilable<T>
///   nilable![&T]       → goish::nilable_ref<'_, T>
///   nilable![&mut T]   → goish::nilable_refmut<'_, T>
///
/// The three underlying types must remain distinct because their
/// runtime layouts differ (Option<Arc<T>> for owned; #[repr(transparent)]
/// Option<&T> / Option<&mut T> for the borrow flavors). The macro hides
/// that split at the source level: function signatures, locals, and
/// return types spell every cell as `nilable![...]`.
///
/// The lowercase name shadows the `nilable` type in macro position only
/// — Rust separates type / value / macro namespaces, so `nilable<T>`
/// (type) and `nilable![T]` (macro) coexist. Brackets convey
/// "type-position" more clearly than parens.
///
/// Usable in type position (fn params, returns, let bindings). Anon
/// lifetime `'_` is emitted for the borrow forms, so struct-field
/// position — which forbids `'_` — should still spell the owned form
/// `nilable![T]` directly.
#[macro_export]
macro_rules! nilable {
    [&mut $T:ty] => { $crate::nilable_refmut<'_, $T> };
    [&$T:ty] => { $crate::nilable_ref<'_, $T> };
    [$T:ty] => { $crate::nilable<$T> };
}

/// Trait-impl registry for `goish::Any::As::<dyn Trait>()`.
/// `#[goish::interface]` emits per-trait `static REGISTRY` plus a
/// `from_any` impl referencing this module's `lookup_with`. Each
/// `impl Trait for Concrete` site emits `register_with` to populate
/// the registry. By the time `Any::As::<dyn Trait>()` is called at
/// runtime, all reachable impls have registered.
pub mod any {
    pub use crate::goany::{
        register_with, lookup_with, lookup_with_mut, AsExt, AsExtMut,
        DowncastableFromAny, DowncastableFromAnyMut, HasDynAny, HasDynAnyMut,
        NilDyn, TraitProbe, TraitRegistry, __HasNilSentinel,
    };
}

// AsExt + HasDynAny are also re-exported at root so
// `use goish::AsExt;` brings the `.As::<T>()` extension into scope
// for trait-borrow receivers. HasDynAny is what
// `#[goish::interface]` emits per-trait (`impl HasDynAny for dyn
// Trait + Send + Sync`) — keeping it at root simplifies the macro's
// generated path.
pub use goany::{AsExt, AsExtMut, HasDynAny, HasDynAnyMut};
pub use nilval::{nil, Nil};
pub use goarray::array;
pub use gochan::chan;
pub use gomap::map;
pub use goslice::slice;
pub use gostring::string;
pub use types::{byte, complex64, complex128, float32, float64, int, int8, int16, int32, int64, rune, uint, uint8, uint16, uint32, uint64, uintptr};

// Re-export the entry-point attribute so users write `#[goish::main]`.
pub use goish_macros::main;
// Re-export the package-init attribute — port authors use
// `#[goish::init] fn init() { … }` instead of the manual
// `pkg_init_once!("crate", { … })` boilerplate. The attribute lives
// in Rust's macro namespace; coexists with the `goish::init()`
// bootstrap function (value namespace).
pub use goish_macros::init;
// Re-export the file-scope `import!` proc-macro — emits `use` lines
// AND registers a `.init_array` slot calling each port's init().
// `__run_pkg_inits` (below) walks the section before main runs.
pub use goish_macros::import;
// Re-export the `goish::embed!` proc-macro — Go's //go:embed
// directive. Declares string / slice<byte> / embed::FS statics from
// files resolved relative to the invoking source file; see the
// `embed` module docs. (The `goish::embed` module path coexists —
// macros and modules occupy different namespaces.)
pub use goish_macros::embed;
// Re-export the `#[goish::interface]` attribute — Go-faithful interface
// declaration. Auto-emits Send + Sync supertraits, a per-trait nil
// sentinel, `Default for Arc<dyn T + Send + Sync>` returning the
// sentinel, and `PartialEq<Nil>` in both directions. See the
// proc-macro's docs in goish-macros/src/lib.rs.
pub use goish_macros::interface;
// Re-export the reflect attribute so users write `#[goish::reflect]`.
// (The `goish::reflect` module path coexists — attributes and modules
// occupy different namespaces, just like `goish::main` doesn't conflict.)
pub use goish_macros::reflect;

// `__var_emit_error_marker!` — proc-macro helper used by the
// `goish::var!` muncher to emit per-sentinel ZST + impls. Hidden from
// docs; users only see `goish::var!`.
#[doc(hidden)]
pub use goish_macros::var_emit_error_marker as __var_emit_error_marker;

// ─── Goish package init — Go's `runtime.initTask` analogue ──────────
//
// Goish-stdlib bootstrap. Runs once on first call (idempotent), wires
// up registries that Go's per-package `init()` functions would
// populate at link time:
//
//   * `crypto::RegisterStandardHashes()` — SHA1/SHA224/SHA256/SHA384/
//     SHA512/SHA512_224/SHA512_256/SHA3_*/MD5 are available to
//     `crypto::HashNew(h)`.
//
// Ports that depend on goish-stdlib state should call `goish::init()`
// at the top of their own `init()` body — the state machine
// deduplicates, so calling it from many ports in one binary is free.
//
// Pattern in a port:
// ```ignore
// pub fn init() {
//     goish::pkg_init_once!("my_port", {
//         goish::init();  // bootstrap goish first
//         // package-level registrations
//     });
// }
// ```
//
// User binaries call each top-level port's `init()` once before any
// other library work, mirroring Go's `import _ "..."` side-effect
// imports — except listed at the start of `main` rather than at the
// import line.
pub fn init() {
    pkg_init_once!("goish", {
        crypto::RegisterStandardHashes();
        crypto::RegisterStandardSigners();
    });
}

// ─── .init_array walk for goish::import! file-scope side-effect imports
//
// Each `goish::import! { … }` macro invocation emits an
// `extern "C" fn` and a `#[link_section = ".init_array"]` static
// pointer to it. The linker concatenates `.init_array` from every
// translation unit into one section in the final binary, between
// `__init_array_start` and `__init_array_end` (provided by the
// linker for ELF targets).
//
// `#[goish::main]` calls `__run_pkg_inits()` after `goish::init()`
// and before the user main body — so port `init()`s run after
// goish-stdlib is up but before user code touches anything.
//
// Mirrors libc's csu/elf-init.c walk used by C/C++ static
// constructors. Fully Go-equivalent for ordering: linker section
// order is "imported-packages-first" because the linker walks the
// dependency graph when building. Within a single crate, declaration
// order is preserved.
extern "C" {
    static __init_array_start: extern "C" fn();
    static __init_array_end: extern "C" fn();
}

#[doc(hidden)]
pub fn __run_pkg_inits() {
    // SAFETY: `__init_array_*` symbols come from the linker; the
    // section between them holds an array of `extern "C" fn()`
    // pointers, populated by `#[link_section = ".init_array"]`
    // statics emitted by `goish::import!`. Reading each pointer and
    // calling it is the standard ELF-CRT init protocol.
    //
    // The `as *const _ as *const extern "C" fn()` casts go via
    // `*const ()` rather than reinterpreting the function-pointer
    // value itself — `&__init_array_start` is the ADDRESS of the
    // start slot, not the start pointer's value.
    unsafe {
        let mut p = &__init_array_start as *const _ as *const extern "C" fn();
        let end = &__init_array_end as *const _ as *const extern "C" fn();
        while p < end {
            (*p)();
            p = p.add(1);
        }
    }
}
