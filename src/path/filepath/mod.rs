// go: package path/filepath
//
// path/filepath — Go's OS-aware path manipulation, ported.
//
// Module root only: one `.rs` per Go `.go`, and the `pub use` surface.
//
//   path.rs       path/filepath/path.go      — ToSlash, FromSlash,
//                                               VolumeName, Abs, Rel,
//                                               Walk, WalkDir, SkipDir,
//                                               SkipAll
//   path_unix.rs  path/filepath/path_unix.go — IsLocal, Localize,
//                                               SplitList
//   match.rs      path/filepath/match.go     — Glob and its helpers
//   symlink.rs    path/filepath/symlink.go   — EvalSymlinks
//
// goish v1 is Linux-only, so Separator == '/' and most operations are
// identical to the slash-only `path` package. We keep the split because
// Go does and because user code that imports `path/filepath` is signaling
// "filesystem-shaped" intent — even if today the lexical behavior matches.
//
// Public API mirrors Go:
//
//   filepath::Separator                  filepath.Separator
//   filepath::ListSeparator              filepath.ListSeparator
//   filepath::Clean(p)                   filepath.Clean(p)
//   filepath::IsAbs(p)                   filepath.IsAbs(p)
//   filepath::IsLocal(p)                 filepath.IsLocal(p)
//   filepath::Localize(p)                filepath.Localize(p) (string, error)
//   filepath::ToSlash(p)                 filepath.ToSlash(p)
//   filepath::FromSlash(p)               filepath.FromSlash(p)
//   filepath::VolumeName(p)              filepath.VolumeName(p)
//   filepath::SplitList(p)               filepath.SplitList(p)
//   filepath::Split(p) -> (dir, file)    dir, file := filepath.Split(p)
//   filepath::Join(elem)                 filepath.Join(elem...)
//   filepath::Ext(p)                     filepath.Ext(p)
//   filepath::Base(p)                    filepath.Base(p)
//   filepath::Dir(p)                     filepath.Dir(p)
//   filepath::Rel(base, targ)            filepath.Rel(base, targ) (string, error)
//   filepath::Match(pat, name)           filepath.Match(pat, name) (bool, error)
//

#![allow(non_snake_case)]
#![allow(non_upper_case_globals)]

extern crate alloc;

use crate::types::byte;

/// `filepath.Separator` — '/' on Unix.
pub const Separator: byte = b'/';

/// `filepath.ListSeparator` — ':' on Unix.
pub const ListSeparator: byte = b':';

// On Linux, Clean / Split / Join / Ext / Base / IsAbs / Dir / Match are
// byte-identical to the slash-only sibling. Re-export instead of
// duplicating: same function, same semantics, same type signatures.
//
// Go declares them separately because Windows needs volume names and a
// backslash separator; `internal/filepathlite` holds the OS-specific
// bodies and `path/filepath` re-exports those. On a Linux-only goish
// the two coincide exactly, and duplicating them would be two copies
// to keep in step rather than one.
//
// User-visible names land at `goish::path::filepath::Clean` etc.,
// exactly like Go's `path/filepath.Clean`.
pub use super::{Base, Clean, Dir, ErrBadPattern, Ext, IsAbs, Join, Match, Split};

#[path = "path.rs"]
mod path_go;
pub use path_go::*;

#[path = "path_unix.rs"]
mod path_unix;
pub use path_unix::*;

#[path = "match.rs"]
mod match_go;
pub use match_go::*;

// symlink.go declares nothing exported — `walkSymlinks` is
// package-internal and `EvalSymlinks`, its only caller, is declared in
// path.go. So this is a crate-visible re-export, not a `pub` one.
#[path = "symlink.rs"]
mod symlink;
use symlink::walk_symlinks;
