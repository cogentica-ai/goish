// go: package path
//
// path — Go's slash-only `path` package, ported.
//
// Module root only: one `.rs` per Go `.go`, and the `pub use` surface.
//
//   path.rs   path/path.go  — Clean, Split, Join, Ext, Base, IsAbs, Dir
//   match.rs  path/match.go — Match
//
// Use this for forward-slash paths like URLs. For OS file paths use
// the [filepath] sibling. Linux-only goish makes the two behaviorally
// identical, but we keep the split because Go does — and any user that
// reaches for `path` is signaling "URL-shaped", not "filesystem-shaped".
//
// Public API mirrors Go:
//
//   path::Clean(p)                   path.Clean(p)
//   path::Split(p) -> (dir, file)    dir, file := path.Split(p)
//   path::Join(elem)                 path.Join(elem...)
//   path::Ext(p)                     path.Ext(p)
//   path::Base(p)                    path.Base(p)
//   path::IsAbs(p)                   path.IsAbs(p)
//   path::Dir(p)                     path.Dir(p)
//   path::Match(pat, name)           ok, err := path.Match(...)
//
// What v1 omits: nothing — every function in path.go and match.go is here.

#![allow(non_snake_case)]

extern crate alloc;

#[path = "path.rs"]
mod path_go;
pub use path_go::*;

#[path = "match.rs"]
mod match_go;
pub use match_go::*;

// ─── filepath subpackage ──────────────────────────────────────────────

pub mod filepath;
