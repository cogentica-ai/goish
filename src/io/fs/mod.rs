// go: package io/fs
//
// io/fs — Go's `io/fs` package, ported.
//
// Source: go1.25.5/src/io/fs/
//
// Note on `io/fs` vs `os`: Go's canonical home for the `FileInfo`,
// `DirEntry`, and `FileMode` types is `io/fs`. The `os` package does
// not define its own — `os.FileInfo`, `os.DirEntry`, `os.FileMode`
// are exact type aliases for the `fs` versions. goish mirrors this:
// this module owns the `#[goish::interface]` traits + the `FileMode`
// newtype, and `os` re-exports them via `pub use`.
//
// Module root only: one `.rs` per Go `.go`, and the `pub use` surface.
//
//   fs.rs        io/fs/fs.go        — FS, File, FileInfo, DirEntry,
//                                     ReadDirFile, FileMode, ValidPath,
//                                     PathError, the sentinel errors
//   readdir.rs   io/fs/readdir.go   — ReadDirFS, ReadDir, dirInfo,
//                                     FileInfoToDirEntry
//   stat.rs      io/fs/stat.go      — StatFS, Stat
//   readfile.rs  io/fs/readfile.go  — ReadFileFS, ReadFile
//   readlink.rs  io/fs/readlink.go  — ReadLinkFS, ReadLink, Lstat
//   walk.rs      io/fs/walk.go      — SkipDir, SkipAll, WalkDirFunc, WalkDir
//   sub.rs       io/fs/sub.go       — SubFS, Sub, subFS
//   glob.rs      io/fs/glob.go      — GlobFS, Glob and its helpers
//   format.rs    io/fs/format.go    — FormatFileInfo, FormatDirEntry

#![allow(non_snake_case, non_camel_case_types)]

extern crate alloc;

#[path = "fs.rs"]
mod fs_go;
pub use fs_go::*;

#[path = "readdir.rs"]
mod readdir;
pub use readdir::*;

#[path = "stat.rs"]
mod stat;
pub use stat::*;

#[path = "readfile.rs"]
mod readfile;
pub use readfile::*;

#[path = "readlink.rs"]
mod readlink;
pub use readlink::*;

#[path = "walk.rs"]
mod walk;
pub use walk::*;

#[path = "sub.rs"]
mod sub;
pub use sub::*;

#[path = "glob.rs"]
mod glob;
pub use glob::*;

#[path = "format.rs"]
mod format;
pub use format::*;
