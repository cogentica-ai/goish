// go: file io/fs/stat.go decls: Stat
//
// stat.go — StatFS and Stat.
extern crate alloc;
use alloc::sync::Arc;

use crate::errors::{self, error};
use crate::gostring::string;

use super::*;

// go: sdk 1.25.5 io/fs/stat.go:8-14 StatFS
/// `fs.StatFS` (stat.go:8) — a file system with a `Stat` method.
/// Embeds [`FS`] in Go.
#[goish::interface] // goishlint:ignore GOISH022 - `goish::interface`, not `goish::int`
pub trait StatFS {
    /// `Open(name)` — open the named file (from embedded [`FS`]).
    fn Open(&self, name: string) -> (Arc<dyn File + Send + Sync>, error);
    /// `Stat(name)` — `FileInfo` describing the named file.
    fn Stat(&self, name: string) -> (Arc<dyn FileInfo + Send + Sync>, error);
}
// ─── Stat (stat.go:20) ───────────────────────────────────────────────

// go: sdk 1.25.5 io/fs/stat.go:20-31 Stat
/// `fs.Stat(fsys, name)` (stat.go:20) — a [`FileInfo`] describing the
/// named file.
///
/// If `fsys` implements [`StatFS`], `Stat` calls `fsys.Stat`. Otherwise
/// it opens the [`File`] to stat it.
pub fn Stat<S: Into<string>>(
    fsys: &(dyn FS + Send + Sync + 'static),
    name: S,
) -> (Arc<dyn FileInfo + Send + Sync>, error) {
    let name: string = name.into();

    // Go: if fsys, ok := fsys.(StatFS); ok { return fsys.Stat(name) }
    let (sfs, ok) = goish::cast!(fsys, StatFS);
    if ok {
        return sfs.Stat(name);
    }

    // Go: file, err := fsys.Open(name); if err != nil { return nil, err }
    let (file, err) = fsys.Open(name);
    if err != errors::nil {
        return (crate::nil.into(), err);
    }
    // Go: defer file.Close(); return file.Stat()
    let info = file.Stat();
    let _ = file.Close();
    return info;
}
