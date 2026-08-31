// go: file io/fs/readdir.go decls: dirInfo.Name, dirInfo.IsDir, dirInfo.Type, dirInfo.Info, dirInfo.String, FileInfoToDirEntry, ReadDir
//
// readdir.go — ReadDirFS, ReadDir, dirInfo, FileInfoToDirEntry.
extern crate alloc;
use alloc::sync::Arc;

use crate::errors::{self, error};
use crate::goslice::slice;
use crate::gostring::string;

use super::*;

// go: sdk 1.25.5 io/fs/readdir.go:15-21 ReadDirFS
/// `fs.ReadDirFS` (readdir.go:15) — a file system with an optimized
/// `ReadDir` implementation. Embeds [`FS`] in Go.
#[goish::interface] // goishlint:ignore GOISH022 - `goish::interface`, not `goish::int`
pub trait ReadDirFS {
    /// `Open(name)` — open the named file (from embedded [`FS`]).
    fn Open(&self, name: string) -> (Arc<dyn File + Send + Sync>, error);
    /// `ReadDir(name)` — entries of the named directory, sorted by
    /// filename.
    fn ReadDir(&self, name: string) -> (slice<Arc<dyn DirEntry + Send + Sync>>, error);
}
// ─── dirInfo — DirEntry over a FileInfo (readdir.go:52) ──────────────

// Go: `type dirInfo struct { fileInfo FileInfo }`
struct dirInfo {
    fileInfo: Arc<dyn FileInfo + Send + Sync>,
}

impl DirEntry for dirInfo {
    // go: sdk 1.25.5 io/fs/readdir.go:69-71 dirInfo.Name
    // Go: func (di dirInfo) Name() string { return di.fileInfo.Name() }
    fn Name(&self) -> string {
        return self.fileInfo.Name();
    }
    // go: sdk 1.25.5 io/fs/readdir.go:57-59 dirInfo.IsDir
    // Go: func (di dirInfo) IsDir() bool { return di.fileInfo.IsDir() }
    fn IsDir(&self) -> bool {
        return self.fileInfo.IsDir();
    }
    // go: sdk 1.25.5 io/fs/readdir.go:61-63 dirInfo.Type
    // Go: func (di dirInfo) Type() FileMode { return di.fileInfo.Mode().Type() }
    fn Type(&self) -> FileMode {
        return self.fileInfo.Mode().Type();
    }
    // go: sdk 1.25.5 io/fs/readdir.go:65-67 dirInfo.Info
    // Go: func (di dirInfo) Info() (FileInfo, error) { return di.fileInfo, nil }
    fn Info(&self) -> (Arc<dyn FileInfo + Send + Sync>, error) {
        return (self.fileInfo.clone(), errors::nil);
    }
}

impl crate::fmt::Stringer for dirInfo {
    // go: sdk 1.25.5 io/fs/readdir.go:73-75 dirInfo.String
    /// Go: `func (di dirInfo) String() string { return FormatDirEntry(di) }`
    ///
    /// This is what makes a `dirInfo` print as `-rw-r--r-- name` rather
    /// than as its fields, and it was missing — `FormatDirEntry` existed
    /// but nothing reached it from here. Go's is a plain method that
    /// satisfies `fmt.Stringer` structurally; goish names the trait.
    fn String(&self) -> string {
        return FormatDirEntry(self);
    }
}

// go: sdk 1.25.5 io/fs/readdir.go:79-84 FileInfoToDirEntry
/// `fs.FileInfoToDirEntry` (readdir.go:79) — a [`DirEntry`] that
/// reports information from `info`.
pub fn FileInfoToDirEntry(
    info: Arc<dyn FileInfo + Send + Sync>,
) -> Arc<dyn DirEntry + Send + Sync> {
    // Go: if info == nil { return nil }
    if info == crate::nil {
        return crate::nil.into();
    }
    return Arc::new(dirInfo { fileInfo: info });
}

// ─── ReadDir (readdir.go:29) ─────────────────────────────────────────

// go: none — goish idiom: Go sorts with
//     `slices.SortFunc(list, func(a, b DirEntry) int {
//     return strings.Compare(a.Name(), b.Name()) })` inline.
//     goish's sort takes a named comparator, so the closure gets a
//     name. A plain byte-wise lexical compare, as `strings.Compare`
//     is.
fn compare_dirent_name(
    a: &Arc<dyn DirEntry + Send + Sync>,
    b: &Arc<dyn DirEntry + Send + Sync>,
) -> core::cmp::Ordering {
    return a.Name().as_bytes().cmp(b.Name().as_bytes());
}

// go: sdk 1.25.5 io/fs/readdir.go:29-50 ReadDir
/// `fs.ReadDir(fsys, name)` (readdir.go:29) — reads the named directory
/// and returns its entries sorted by filename.
///
/// If `fsys` implements [`ReadDirFS`], `ReadDir` calls `fsys.ReadDir`.
/// Otherwise it opens `name` and uses `ReadDir`/`Close` on the file.
pub fn ReadDir<S: Into<string>>(
    fsys: &(dyn FS + Send + Sync + 'static),
    name: S,
) -> (slice<Arc<dyn DirEntry + Send + Sync>>, error) {
    let name: string = name.into();

    // Go: if fsys, ok := fsys.(ReadDirFS); ok { return fsys.ReadDir(name) }
    let (rdfs, ok) = goish::cast!(fsys, ReadDirFS);
    if ok {
        return rdfs.ReadDir(name);
    }

    // Go: file, err := fsys.Open(name); if err != nil { return nil, err }
    let (file, err) = fsys.Open(name.clone());
    if err != errors::nil {
        return (slice::new(), err);
    }

    // Go: dir, ok := file.(ReadDirFile)
    let (dir, ok) = goish::cast!(&*file, ReadDirFile);
    if !ok {
        let _ = file.Close();
        return (
            slice::new(),
            errors::Wrap(PathError {
                Op: string::from_static("readdir"),
                Path: name,
                Err: errors::New("not implemented"),
            }),
        );
    }

    // Go: list, err := dir.ReadDir(-1)
    let (mut list, err) = dir.ReadDir(-1);
    // Go: defer file.Close()
    let _ = file.Close();
    // Go: slices.SortFunc(list, func(a, b) int { CompareString(...) })
    // `slice<T>` DerefMut's to `&mut [T]`, so `sort_by` applies in place.
    (*list).sort_by(compare_dirent_name);
    return (list, err);
}
