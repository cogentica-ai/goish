// go: package text/tabwriter
//
// text/tabwriter — a write filter that translates tabbed columns in
// input into properly aligned text, using the Elastic Tabstops
// algorithm described at
// http://nickgravgaard.com/elastictabstops/index.html.
//
// One Rust file per Go file, so each carries its own provenance
// anchors (GOISH015):
//
//   tabwriter.rs    tabwriter.go    — the whole package
//
// This file is a module root, so it carries no `// go:` anchors.

#![allow(non_snake_case, non_camel_case_types, non_upper_case_globals)]

pub mod tabwriter;

pub use tabwriter::{
    AlignRight, Debug, DiscardEmptyColumns, Escape, FilterHTML, NewWriter, StripEscape, TabIndent,
    Writer,
};
