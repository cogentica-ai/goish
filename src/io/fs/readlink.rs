// go: file io/fs/readlink.go decls: ReadLink, Lstat

extern crate alloc;
use alloc::sync::Arc;

use crate::errors::{self, error};
use crate::gostring::string;

use super::*;

// go: sdk 1.25.5 io/fs/readlink.go:9-21 ReadLinkFS
/// `fs.ReadLinkFS` (readlink.go:9) — a file system that can read
/// symbolic links. Embeds [`FS`] in Go, so `Open` is re-declared here
/// for the same reason the other composite interfaces re-declare their
/// inherited methods.
#[goish::interface] // goishlint:ignore GOISH022 - `goish::interface`, not `goish::int`
pub trait ReadLinkFS {
    /// `Open(name)` — open the named file (from embedded [`FS`]).
    fn Open(&self, name: string) -> (Arc<dyn File + Send + Sync>, error);
    /// `ReadLink(name)` — the destination of the named symbolic link.
    /// An error should be a [`PathError`].
    fn ReadLink(&self, name: string) -> (string, error);
    /// `Lstat(name)` — a [`FileInfo`] describing the named file. If the
    /// file is a symbolic link, the result describes the LINK, not its
    /// target: no attempt is made to follow it. An error should be a
    /// [`PathError`].
    fn Lstat(&self, name: string) -> (Arc<dyn FileInfo + Send + Sync>, error);
}

// go: sdk 1.25.5 io/fs/readlink.go:26-32 ReadLink
/// `fs.ReadLink(fsys, name)` (readlink.go:26) — the destination of the
/// named symbolic link.
///
/// A file system that does not implement [`ReadLinkFS`] cannot answer
/// at all, so this is an `ErrInvalid` `PathError` rather than a
/// fallback — unlike [`Lstat`], which has [`Stat`] to fall back on.
pub fn ReadLink<S: Into<string>>(
    fsys: &(dyn FS + Send + Sync + 'static),
    name: S,
) -> (string, error) {
    let name: string = name.into();

    // Go: sym, ok := fsys.(ReadLinkFS)
    let (sym, ok) = goish::cast!(fsys, ReadLinkFS);
    if !ok {
        return (
            string::new(),
            errors::Wrap(PathError {
                Op: string::from_static("readlink"),
                Path: name,
                Err: ErrInvalid.into(),
            }),
        );
    }
    return sym.ReadLink(name);
}

// go: sdk 1.25.5 io/fs/readlink.go:38-44 Lstat
/// `fs.Lstat(fsys, name)` (readlink.go:38) — a [`FileInfo`] describing
/// the named file. If the file is a symbolic link, the result describes
/// the link itself; no attempt is made to follow it.
///
/// A file system that does not implement [`ReadLinkFS`] has no links to
/// speak of, so Go makes this identical to [`Stat`] rather than an
/// error.
pub fn Lstat<S: Into<string>>(
    fsys: &(dyn FS + Send + Sync + 'static),
    name: S,
) -> (Arc<dyn FileInfo + Send + Sync>, error) {
    let name: string = name.into();

    // Go: sym, ok := fsys.(ReadLinkFS); if !ok { return Stat(fsys, name) }
    let (sym, ok) = goish::cast!(fsys, ReadLinkFS);
    if !ok {
        return Stat(fsys, name);
    }
    return sym.Lstat(name);
}
