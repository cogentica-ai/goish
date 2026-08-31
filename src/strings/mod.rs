// go: package strings
//
// strings — simple functions to manipulate UTF-8 encoded strings.
//
// One Rust file per Go file, so each carries its own provenance
// anchors (GOISH015):
//
//   strings.rs   strings.go   — the bulk of the package
//   builder.rs   builder.go   — Builder
//   reader.rs    reader.go    — Reader
//   replace.rs   replace.go   — Replacer and its four algorithms
//   search.rs    search.go    — the Boyer-Moore string finder
//   iter.rs      iter.go      — the iter.Seq splitters
//   clone.rs     clone.go     — Clone
//   compare.rs   compare.go   — Compare
//
// This file is a module root: `mod`, `pub use`, and the one goish-only
// registration hook the interface machinery needs.
//
#![allow(non_snake_case)]

extern crate alloc;

#[path = "search.rs"]
mod search;

#[path = "builder.rs"]
mod builder;
pub use builder::Builder;

#[path = "reader.rs"]
mod reader;
pub use reader::{NewReader, Reader};

#[path = "clone.rs"]
mod clone;
pub use clone::Clone;

#[path = "compare.rs"]
mod compare;
pub use compare::Compare;

#[path = "iter.rs"]
mod iter_go;
pub use iter_go::{FieldsFuncSeq, FieldsSeq, Lines, SplitAfterSeq, SplitSeq};

#[path = "strings.rs"]
pub(crate) mod strings;
// `Title` is `#[deprecated]`, as Go marks it, and re-exporting a
// deprecated item is itself a use of it.
#[allow(deprecated)]
pub use strings::{
    Contains, ContainsAny, ContainsFunc, ContainsRune, Count, Cut, CutPrefix, CutSuffix, EqualFold,
    Fields, FieldsFunc, HasPrefix, HasSuffix, Index, IndexAny, IndexByte, IndexFunc, IndexRune,
    Join, LastIndex, LastIndexAny, LastIndexByte, LastIndexFunc, Map, Repeat, Replace, ReplaceAll,
    Split, SplitAfter, SplitAfterN, SplitN, Title, ToLower, ToLowerSpecial, ToTitle,
    ToTitleSpecial, ToUpper, ToUpperSpecial, ToValidUTF8, Trim, TrimFunc, TrimLeft, TrimLeftFunc,
    TrimPrefix, TrimRight, TrimRightFunc, TrimSpace, TrimSuffix,
};

#[path = "replace.rs"]
mod replace;
pub use replace::{NewReplacer, Replacer};

// ─── Replacer (slim port of strings/replace.go) ──────────────────────

// go: none — goish idiom: fill the `#[goish::interface]` downcast
// registries for the types this package declares. See AGENTS.md §9b.
/// Register `strings`'s concrete types into the `io` interface
/// registries. Idempotent; called from `goish::init()`.
pub fn register_strings_impls() {
    use crate::io::{
        __goish_register_ReaderAt_impl, __goish_register_Reader_impl, __goish_register_Seeker_impl,
        __goish_register_WriterTo_impl, __goish_register_Writer_impl,
    };
    __goish_register_Writer_impl::<Builder>();
    __goish_register_Reader_impl::<Reader>();
    __goish_register_ReaderAt_impl::<Reader>();
    __goish_register_Seeker_impl::<Reader>();
    __goish_register_WriterTo_impl::<Reader>();
}
