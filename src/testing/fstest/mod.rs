// go: package testing/fstest
//
// testing/fstest — Go's `testing/fstest` package, ported.
//
// Module root only: one `.rs` per Go `.go`, and the `pub use` surface.
//
//   mapfs.rs   testing/fstest/mapfs.go  — MapFS, an in-memory fs.FS
//   testfs.rs  testing/fstest/testfs.go — the TestFS conformance harness
//   shims.rs   (goish-only)             — test entry points for the
//                                         unexported types
//
//
// Deviations:
//  - `MapFS` is a newtype over `map<string, Arc<MapFile>>` rather than
//    a bare map type (Rust cannot attach methods to a type alias).
//    Entries are `Arc<MapFile>` — Go's `*MapFile`. Callers that would
//    mutate a `*MapFile` in place (e.g. `f.ModTime = t`) instead
//    clone-and-replace the entry; an already-open file keeps its
//    snapshot. Go's docs already forbid concurrent map edits, so no
//    real-world behavior change.
//  - `Sys any` is `Arc<dyn Any + Send + Sync>`; a nil Sys is
//    `Arc::new(())` per the goish FileInfo convention.
//  - Go's MapFS satisfies fs.ReadFileFS, fs.StatFS, fs.ReadDirFS,
//    fs.GlobFS and fs.ReadLinkFS structurally, by having the methods.
//    goish needs each impl written out and the type registered, or the
//    assertion inside the fs helper is a silent miss.

#[path = "mapfs.rs"]
mod mapfs;
pub use mapfs::*;

#[path = "testfs.rs"]
mod testfs;
pub use testfs::*;

#[path = "shims.rs"]
mod shims;
pub use shims::*;
