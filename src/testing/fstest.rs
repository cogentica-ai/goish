// testing/fstest — line-by-line port of Go 1.25.5
// testing/fstest/mapfs.go (MapFS only; testfs.go's TestFS conformance
// harness is not ported).
//
// goishlint:ignore GOISH018 errorf, formatEntry, formatInfoEntry, formatInfo, checkDir, checkDirList, checkFile, checkGlob, checkStat, Close, Info, IsDir, lstat, Lstat, Mode, ModTime, Name, Open, openDir, Read, ReadDir, ReadFile, ReadLink, resolveSymlinks, Size, Stat, String, Sub, Sys, testFS, TestFS, Type — MapFS's readers/Stat/ReadDir and the whole TestFS conformance suite are hand-written or not yet ported; only openMapFile.Seek and .ReadAt carry anchors so far.
// goishlint:ignore GOISH021 fsTester, _, fsOnly, fsTester, mapDir, MapFile, mapFileInfo, MapFS, noSub, openMapFile — same.
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
//  - MapFS.Glob / MapFS.Sub / fs.ReadLinkFS are not ported (goish
//    io/fs has no Glob or ReadLinkFS yet); ReadLink/Lstat are ported
//    as inherent methods.
//  - Go hides the optimized ReadDir/Stat/ReadFile methods behind
//    `fsOnly` when delegating to the fs package helpers; goish gets
//    the same effect by NOT registering MapFS for ReadDirFS / StatFS /
//    ReadFileFS, so `fs::ReadDir(&mapfs, ..)` etc. always take the
//    generic Open-based path.

use alloc::string::ToString;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicI64, AtomicUsize, Ordering};

use crate::errors::{self, error};
use crate::gomap::map;
use crate::goslice::slice;
use crate::gostring::string;
use crate::io::fs::{
    self, DirEntry, File, FileInfo, FileMode, ModeDir, ModeSymlink, ReadDirFile,
};
use crate::path;
use crate::strings;
use crate::time;
use crate::types::{byte, int};

// Go: mapfs.go:36 — type MapFile struct
/// A MapFile describes a single file in a [`MapFS`].
#[derive(Clone, Default)]
#[allow(non_snake_case)]
pub struct MapFile {
    /// file content or symlink destination
    pub Data: slice<byte>,
    /// fs.FileInfo.Mode
    pub Mode: FileMode,
    /// fs.FileInfo.ModTime
    pub ModTime: time::Time,
    /// fs.FileInfo.Sys (`None` ⇒ Go's nil `any`)
    pub Sys: Option<Arc<dyn core::any::Any + Send + Sync>>,
}

// Go: mapfs.go:33 — type MapFS map[string]*MapFile
/// A MapFS is a simple in-memory file system for use in tests,
/// represented as a map from path names (arguments to Open) to
/// information about the files, directories, or symbolic links they
/// represent.
///
/// The map need not include parent directories for files contained in
/// the map; those will be synthesized if needed.
#[derive(Clone, Default)]
pub struct MapFS(pub map<string, Arc<MapFile>>);

impl MapFS {
    pub fn new() -> MapFS {
        MapFS(map::new())
    }

    fn get(&self, name: &string) -> Option<Arc<MapFile>> {
        let (v, ok) = self.0.GetRef(name.clone());
        if ok { v.cloned() } else { None }
    }

    // Go: mapfs.go:48 — func (fsys MapFS) Open(name string) (fs.File, error)
    /// Open opens the named file after following any symbolic links.
    pub fn Open<S: Into<string>>(
        &self,
        name: S,
    ) -> (Arc<dyn File + Send + Sync>, error) {
        register_fstest_impls();
        let name: string = name.into();
        // Go: if !fs.ValidPath(name) { return nil, &fs.PathError{...ErrNotExist} }
        if !fs::ValidPath(name.clone()) {
            return (crate::nil.into(), open_not_exist(&name));
        }
        // Go: realName, ok := fsys.resolveSymlinks(name)
        let (real_name, ok) = self.resolveSymlinks(name.clone());
        if !ok {
            return (crate::nil.into(), open_not_exist(&name));
        }

        // Go: file := fsys[realName]
        let file = self.get(&real_name);
        if let Some(f) = &file {
            if f.Mode.0 & ModeDir.0 == 0 {
                // Go: Ordinary file
                return (
                    Arc::new(openMapFile {
                        path: name.clone(),
                        info: mapFileInfo { name: path::Base(name), f: f.clone() },
                        offset: AtomicI64::new(0),
                    }),
                    errors::nil,
                );
            }
        }

        // Go: Directory, possibly synthesized.
        let mut list: Vec<mapFileInfo> = Vec::new();
        let mut need: map<string, bool> = map::new();
        if real_name.as_bytes() == b"." {
            for (fname, f) in self.0.__iter() {
                let i = strings::Index(fname.clone(), "/");
                if i < 0 {
                    if fname.as_bytes() != b"." {
                        list.push(mapFileInfo { name: fname.clone(), f: f.clone() });
                    }
                } else {
                    need.Set(
                        string::from_bytes(&fname.as_bytes()[..i as usize]),
                        true,
                    );
                }
            }
        } else {
            // Go: prefix := realName + "/"
            let mut prefix = real_name.clone().to_string();
            prefix.push('/');
            let prefix_b = prefix.as_bytes();
            for (fname, f) in self.0.__iter() {
                let fb = fname.as_bytes();
                if fb.starts_with(prefix_b) {
                    let felem = &fb[prefix_b.len()..];
                    match felem.iter().position(|&c| c == b'/') {
                        None => list.push(mapFileInfo {
                            name: string::from_bytes(felem),
                            f: f.clone(),
                        }),
                        Some(i) => need.Set(string::from_bytes(&felem[..i]), true),
                    }
                }
            }
            // Go: if file == nil && list == nil && len(need) == 0 { ErrNotExist }
            if file.is_none() && list.is_empty() && need.Len() == 0 {
                return (crate::nil.into(), open_not_exist(&name));
            }
        }
        // Go: for _, fi := range list { delete(need, fi.name) }
        for fi in &list {
            need.Delete(fi.name.clone());
        }
        // Go: for name := range need { list = append(list, {name, &MapFile{Mode: ModeDir|0555}}) }
        for n in need.Keys().as_ref() {
            list.push(mapFileInfo { name: n.clone(), f: synth_dir() });
        }
        // Go: slices.SortFunc(list, ... strings.Compare(a.name, b.name))
        list.sort_by(|a, b| a.name.as_bytes().cmp(b.name.as_bytes()));

        // Go: if file == nil { file = &MapFile{Mode: ModeDir | 0555} }
        let file = file.unwrap_or_else(synth_dir);
        // Go: elem = "." or name[strings.LastIndex(name, "/")+1:]
        let elem = if name.as_bytes() == b"." {
            string::from_static(".")
        } else {
            let nb = name.as_bytes();
            let i = nb.iter().rposition(|&c| c == b'/').map(|i| i as i64).unwrap_or(-1);
            string::from_bytes(&nb[(i + 1) as usize..])
        };
        (
            Arc::new(mapDir {
                path: name,
                info: mapFileInfo { name: elem, f: file },
                entry: list,
                offset: AtomicUsize::new(0),
            }),
            errors::nil,
        )
    }

    // Go: mapfs.go:122 — func (fsys MapFS) resolveSymlinks(name string) (string, bool)
    #[allow(non_snake_case)]
    fn resolveSymlinks(&self, name: string) -> (string, bool) {
        // Go: Fast path: if a symlink is in the map, resolve it.
        if let Some(file) = self.get(&name) {
            if file.Mode.Type().0 == ModeSymlink.0 {
                let target = string::from_bytes(file.Data.as_ref());
                if path::IsAbs(target.clone()) {
                    return (string::new(), false);
                }
                return self.resolveSymlinks(path::Join(slice::__from_vec(
                    alloc::vec![path::Dir(name), target],
                )));
            }
        }

        // Go: Check if each parent directory (starting at root) is a symlink.
        let nb_len = name.as_bytes().len();
        let mut i: usize = 0;
        while i < nb_len {
            let nb = name.as_bytes();
            let j = nb[i..].iter().position(|&c| c == b'/');
            let dir: string;
            match j {
                None => {
                    dir = name.clone();
                    i = nb_len;
                }
                Some(j) => {
                    dir = string::from_bytes(&nb[..i + j]);
                    i += j;
                }
            }
            if let Some(file) = self.get(&dir) {
                if file.Mode.Type().0 == ModeSymlink.0 {
                    let target = string::from_bytes(file.Data.as_ref());
                    if path::IsAbs(target.clone()) {
                        return (string::new(), false);
                    }
                    let joined = path::Join(slice::__from_vec(alloc::vec![
                        path::Dir(dir),
                        target,
                    ]));
                    let mut rejoined = joined.to_string();
                    rejoined.push_str(
                        core::str::from_utf8(&name.as_bytes()[i..]).unwrap_or(""),
                    );
                    return self.resolveSymlinks(string::from(rejoined.as_str()));
                }
            }
            i += 1; // Go: i += len("/")
        }
        let ok = fs::ValidPath(name.clone());
        (name, ok)
    }

    // Go: mapfs.go:157 — func (fsys MapFS) ReadLink(name string) (string, error)
    /// ReadLink returns the destination of the named symbolic link.
    pub fn ReadLink<S: Into<string>>(&self, name: S) -> (string, error) {
        let name: string = name.into();
        let (info, err) = self.lstat(&name);
        let Some(info) = info else {
            return (string::new(), path_err("readlink", &name, err));
        };
        if info.f.Mode.Type().0 != ModeSymlink.0 {
            return (
                string::new(),
                path_err("readlink", &name, fs::ErrInvalid.clone().into()),
            );
        }
        (string::from_bytes(info.f.Data.as_ref()), errors::nil)
    }

    // Go: mapfs.go:171 — func (fsys MapFS) Lstat(name string) (fs.FileInfo, error)
    /// Lstat returns a FileInfo describing the named file without
    /// following symbolic links.
    pub fn Lstat<S: Into<string>>(
        &self,
        name: S,
    ) -> (Arc<dyn FileInfo + Send + Sync>, error) {
        register_fstest_impls();
        let name: string = name.into();
        let (info, err) = self.lstat(&name);
        match info {
            Some(i) => (Arc::new(i), errors::nil),
            None => (crate::nil.into(), path_err("lstat", &name, err)),
        }
    }

    // Go: mapfs.go:179 — func (fsys MapFS) lstat(name string) (*mapFileInfo, error)
    fn lstat(&self, name: &string) -> (Option<mapFileInfo>, error) {
        if !fs::ValidPath(name.clone()) {
            return (None, fs::ErrNotExist.clone().into());
        }
        let (real_dir, ok) = self.resolveSymlinks(path::Dir(name.clone()));
        if !ok {
            return (None, fs::ErrNotExist.clone().into());
        }
        let elem = path::Base(name.clone());
        let real_name =
            path::Join(slice::__from_vec(alloc::vec![real_dir, elem.clone()]));

        if let Some(file) = self.get(&real_name) {
            return (Some(mapFileInfo { name: elem, f: file }), errors::nil);
        }

        if real_name.as_bytes() == b"." {
            return (Some(mapFileInfo { name: elem, f: synth_dir() }), errors::nil);
        }
        // Go: Maybe a directory.
        let mut prefix = real_name.to_string();
        prefix.push('/');
        for (fname, _) in self.0.__iter() {
            if fname.as_bytes().starts_with(prefix.as_bytes()) {
                return (Some(mapFileInfo { name: elem, f: synth_dir() }), errors::nil);
            }
        }
        (None, fs::ErrNotExist.clone().into())
    }

    // Go: mapfs.go:218 — func (fsys MapFS) ReadFile(name string) ([]byte, error)
    pub fn ReadFile<S: Into<string>>(&self, name: S) -> (slice<byte>, error) {
        // Go routes through fsOnly{fsys}; here the un-registered
        // optimized interfaces give the same generic path.
        fs::ReadFile(self, name)
    }

    // Go: mapfs.go:222 — func (fsys MapFS) Stat(name string) (fs.FileInfo, error)
    pub fn Stat<S: Into<string>>(
        &self,
        name: S,
    ) -> (Arc<dyn FileInfo + Send + Sync>, error) {
        fs::Stat(self, name)
    }

    // Go: mapfs.go:226 — func (fsys MapFS) ReadDir(name string) ([]fs.DirEntry, error)
    pub fn ReadDir<S: Into<string>>(
        &self,
        name: S,
    ) -> (slice<Arc<dyn DirEntry + Send + Sync>>, error) {
        fs::ReadDir(self, name)
    }
}

// Go: var _ fs.FS = MapFS(nil)
impl fs::FS for MapFS {
    fn Open(&self, name: string) -> (Arc<dyn File + Send + Sync>, error) {
        MapFS::Open(self, name)
    }
    fn __goish_as_dyn_any(&self) -> Option<&(dyn core::any::Any + Send + Sync)> {
        Some(self)
    }
}

fn open_not_exist(name: &string) -> error {
    path_err("open", name, fs::ErrNotExist.clone().into())
}

fn path_err(op: &'static str, name: &string, err: error) -> error {
    // Go: &fs.PathError{Op: op, Path: name, Err: err}
    errors::Wrap(fs::PathError {
        Op: string::from_static(op),
        Path: name.clone(),
        Err: err,
    })
}

// Go: &MapFile{Mode: fs.ModeDir | 0555}
fn synth_dir() -> Arc<MapFile> {
    Arc::new(MapFile {
        Data: slice::new(),
        Mode: FileMode(ModeDir.0 | 0o555),
        ModTime: time::Time::default(),
        Sys: None,
    })
}

/// Register the fstest `#[goish::interface]` impls in the per-trait
/// downcast registries. Idempotent; called from `Open` / `Lstat`.
/// Deliberately does NOT register MapFS for ReadDirFS / StatFS /
/// ReadFileFS (Go's `fsOnly` semantics — see module header).
fn register_fstest_impls() {
    fs::__goish_register_FS_impl::<MapFS>();
    fs::__goish_register_FileInfo_impl::<mapFileInfo>();
    fs::__goish_register_DirEntry_impl::<mapFileInfo>();
    fs::__goish_register_File_impl::<openMapFile>();
    fs::__goish_register_File_impl::<mapDir>();
    fs::__goish_register_ReadDirFile_impl::<mapDir>();
}

// Go: mapfs.go:249 — type mapFileInfo struct { name string; f *MapFile }
/// A mapFileInfo implements fs.FileInfo and fs.DirEntry for a given
/// map file.
#[derive(Clone)]
#[allow(non_camel_case_types)]
struct mapFileInfo {
    name: string,
    f: Arc<MapFile>,
}

impl FileInfo for mapFileInfo {
    // Go: func (i *mapFileInfo) Name() string { return path.Base(i.name) }
    fn Name(&self) -> string {
        path::Base(self.name.clone())
    }
    // Go: func (i *mapFileInfo) Size() int64 { return int64(len(i.f.Data)) }
    fn Size(&self) -> int {
        self.f.Data.as_ref().len() as int
    }
    // Go: func (i *mapFileInfo) Mode() fs.FileMode { return i.f.Mode }
    fn Mode(&self) -> FileMode {
        self.f.Mode
    }
    // Go: func (i *mapFileInfo) ModTime() time.Time { return i.f.ModTime }
    fn ModTime(&self) -> time::Time {
        self.f.ModTime
    }
    // Go: func (i *mapFileInfo) IsDir() bool { return i.f.Mode&fs.ModeDir != 0 }
    fn IsDir(&self) -> bool {
        self.f.Mode.0 & ModeDir.0 != 0
    }
    // Go: func (i *mapFileInfo) Sys() any { return i.f.Sys }
    fn Sys(&self) -> Arc<dyn core::any::Any + Send + Sync> {
        match &self.f.Sys {
            Some(s) => s.clone(),
            None => Arc::new(()),
        }
    }
    fn __goish_as_dyn_any(&self) -> Option<&(dyn core::any::Any + Send + Sync)> {
        Some(self)
    }
}

impl DirEntry for mapFileInfo {
    fn Name(&self) -> string {
        path::Base(self.name.clone())
    }
    fn IsDir(&self) -> bool {
        self.f.Mode.0 & ModeDir.0 != 0
    }
    // Go: func (i *mapFileInfo) Type() fs.FileMode { return i.f.Mode.Type() }
    fn Type(&self) -> FileMode {
        self.f.Mode.Type()
    }
    // Go: func (i *mapFileInfo) Info() (fs.FileInfo, error) { return i, nil }
    fn Info(&self) -> (Arc<dyn FileInfo + Send + Sync>, error) {
        (Arc::new(self.clone()), errors::nil)
    }
    fn __goish_as_dyn_any(&self) -> Option<&(dyn core::any::Any + Send + Sync)> {
        Some(self)
    }
}

// Go: mapfs.go:270 — type openMapFile struct
/// An openMapFile is a regular (non-directory) fs.File open for
/// reading. (`offset` is atomic — Go mutates through the `*File`;
/// goish `File` methods take `&self`.)
#[allow(non_camel_case_types)]
struct openMapFile {
    path: string,
    info: mapFileInfo,
    offset: AtomicI64,
}

impl File for openMapFile {
    // Go: func (f *openMapFile) Stat() (fs.FileInfo, error) { return &f.mapFileInfo, nil }
    fn Stat(&self) -> (Arc<dyn FileInfo + Send + Sync>, error) {
        (Arc::new(self.info.clone()), errors::nil)
    }
    // Go: mapfs.go:280 — func (f *openMapFile) Read(b []byte) (int, error)
    fn Read(&self, b: &mut slice<byte>) -> (int, error) {
        let data = self.info.f.Data.as_ref();
        let offset = self.offset.load(Ordering::Acquire);
        if offset >= data.len() as i64 {
            return (0, crate::io::EOF.into());
        }
        if offset < 0 {
            return (0, path_err("read", &self.path, fs::ErrInvalid.clone().into()));
        }
        // Go: n := copy(b, f.f.Data[f.offset:])
        let src = &data[offset as usize..];
        let dst = b.as_mut();
        let n = core::cmp::min(dst.len(), src.len());
        dst[..n].copy_from_slice(&src[..n]);
        self.offset.store(offset + n as i64, Ordering::Release);
        (n as int, errors::nil)
    }
    // Go: func (f *openMapFile) Close() error { return nil }
    fn Close(&self) -> error {
        errors::nil
    }
    fn __goish_as_dyn_any(&self) -> Option<&(dyn core::any::Any + Send + Sync)> {
        Some(self)
    }
}

impl openMapFile {
    // go: sdk 1.25.5 testing/fstest/mapfs.go:286-300 openMapFile.Seek
    /// Go: `io.Seeker` over the in-memory file. `whence` is 0 (start),
    /// 1 (current) or 2 (end), and an offset outside the data is an
    /// `fs.ErrInvalid` PathError rather than a clamp.
    ///
    /// Deviation: Go mutates `f.offset` on `*openMapFile`; goish holds
    /// it in an `AtomicI64` because `File` hands out `&self`, so the
    /// store replaces Go's assignment.
    pub fn Seek(&self, offset: crate::types::int64, whence: int) -> (crate::types::int64, error) {
        let data = self.info.f.Data.as_ref();
        let mut offset = offset;
        // Go: switch whence { case 0: /* offset += 0 */
        //     case 1: offset += f.offset
        //     case 2: offset += int64(len(f.f.Data)) }
        match whence {
            0 => {}
            1 => {
                offset += self.offset.load(Ordering::Acquire);
            }
            2 => {
                offset += crate::int64(data.len());
            }
            _ => {}
        }
        // Go: if offset < 0 || offset > int64(len(f.f.Data)) {
        //         return 0, &fs.PathError{Op: "seek", ...ErrInvalid} }
        if offset < 0 || offset > crate::int64(data.len()) {
            return (
                0,
                path_err("seek", &self.path, fs::ErrInvalid.clone().into()),
            );
        }
        self.offset.store(offset, Ordering::Release);
        return (offset, errors::nil);
    }

    // go: sdk 1.25.5 testing/fstest/mapfs.go:302-311 openMapFile.ReadAt
    /// Go: `io.ReaderAt` — read at an absolute offset without moving
    /// the file position, and report `io.EOF` on a short read.
    ///
    /// Note this does *not* touch `f.offset`, which is what separates
    /// ReadAt from Read; a ReaderAt is required to be safe for
    /// concurrent use for exactly that reason.
    pub fn ReadAt(&self, b: &mut slice<byte>, offset: crate::types::int64) -> (int, error) {
        let data = self.info.f.Data.as_ref();
        // Go: if offset < 0 || offset > int64(len(f.f.Data)) {
        //         return 0, &fs.PathError{Op: "read", ...ErrInvalid} }
        if offset < 0 || offset > crate::int64(data.len()) {
            return (
                0,
                path_err("read", &self.path, fs::ErrInvalid.clone().into()),
            );
        }
        // Go: n := copy(b, f.f.Data[offset:])
        let src = &data[offset as usize..];
        let dst = b.as_mut();
        let n = core::cmp::min(dst.len(), src.len());
        dst[..n].copy_from_slice(&src[..n]);
        // Go: if n < len(b) { return n, io.EOF }
        if n < dst.len() {
            return (crate::int(n), crate::io::EOF.into());
        }
        return (crate::int(n), errors::nil);
    }
}

// Go: mapfs.go:316 — type mapDir struct
/// A mapDir is a directory fs.File (so also an fs.ReadDirFile) open
/// for reading.
#[allow(non_camel_case_types)]
struct mapDir {
    path: string,
    info: mapFileInfo,
    entry: Vec<mapFileInfo>,
    offset: AtomicUsize,
}

impl mapDir {
    fn read_dir(&self, count: int) -> (slice<Arc<dyn DirEntry + Send + Sync>>, error) {
        // Go: mapfs.go:329 — func (d *mapDir) ReadDir(count int) ([]fs.DirEntry, error)
        let offset = self.offset.load(Ordering::Acquire);
        let mut n = self.entry.len() - offset;
        if n == 0 && count > 0 {
            return (slice::new(), crate::io::EOF.into());
        }
        if count > 0 && n > count as usize {
            n = count as usize;
        }
        let mut list: Vec<Arc<dyn DirEntry + Send + Sync>> = Vec::with_capacity(n);
        for i in 0..n {
            list.push(Arc::new(self.entry[offset + i].clone()));
        }
        self.offset.store(offset + n, Ordering::Release);
        (slice::__from_vec(list), errors::nil)
    }
}

impl File for mapDir {
    fn Stat(&self) -> (Arc<dyn FileInfo + Send + Sync>, error) {
        (Arc::new(self.info.clone()), errors::nil)
    }
    // Go: func (d *mapDir) Read(b []byte) (int, error) — always ErrInvalid
    fn Read(&self, _b: &mut slice<byte>) -> (int, error) {
        (0, path_err("read", &self.path, fs::ErrInvalid.clone().into()))
    }
    fn Close(&self) -> error {
        errors::nil
    }
    fn __goish_as_dyn_any(&self) -> Option<&(dyn core::any::Any + Send + Sync)> {
        Some(self)
    }
}

impl ReadDirFile for mapDir {
    fn Stat(&self) -> (Arc<dyn FileInfo + Send + Sync>, error) {
        File::Stat(self)
    }
    fn Read(&self, b: &mut slice<byte>) -> (int, error) {
        File::Read(self, b)
    }
    fn Close(&self) -> error {
        File::Close(self)
    }
    fn ReadDir(&self, n: int) -> (slice<Arc<dyn DirEntry + Send + Sync>>, error) {
        self.read_dir(n)
    }
    fn __goish_as_dyn_any(&self) -> Option<&(dyn core::any::Any + Send + Sync)> {
        Some(self)
    }
}

// ─── test shims ──────────────────────────────────────────────────────────────
//
// `openMapFile` is unexported in Go and stays unexported here, so its
// `Seek`/`ReadAt` cannot be reached from an example (a separate crate).
// These shims give the smoke test a way in without widening the real
// API, following the pattern used elsewhere in the tree for testing
// unexported Go declarations.

// go: none — goish-only: test shim for the unexported openMapFile.Seek.
#[doc(hidden)]
pub fn __shim_open_seek(
    fsys: &MapFS,
    path: impl Into<string>,
    offset: crate::types::int64,
    whence: int,
) -> (crate::types::int64, error) {
    let (f, err) = fs::FS::Open(fsys, path.into());
    if err != errors::nil {
        return (0, err);
    }
    let any = match f.__goish_as_dyn_any() {
        Some(a) => a,
        None => return (0, errors::New(string::from_static("not an openMapFile"))),
    };
    return match any.downcast_ref::<openMapFile>() {
        Some(o) => o.Seek(offset, whence),
        None => (0, errors::New(string::from_static("not an openMapFile"))),
    };
}

// go: none — goish-only: two seeks on ONE handle, so `whence == 1`
// (seek relative to the current position) can actually be observed.
// A shim that reopens per call always starts at offset 0 and would
// make the relative case indistinguishable from an absolute one.
#[doc(hidden)]
pub fn __shim_open_seek2(
    fsys: &MapFS,
    path: impl Into<string>,
    off1: crate::types::int64,
    whence1: int,
    off2: crate::types::int64,
    whence2: int,
) -> (crate::types::int64, crate::types::int64, error) {
    let (f, err) = fs::FS::Open(fsys, path.into());
    if err != errors::nil {
        return (0, 0, err);
    }
    let any = match f.__goish_as_dyn_any() {
        Some(a) => a,
        None => return (0, 0, errors::New(string::from_static("not an openMapFile"))),
    };
    let o = match any.downcast_ref::<openMapFile>() {
        Some(o) => o,
        None => return (0, 0, errors::New(string::from_static("not an openMapFile"))),
    };
    let (a, e1) = o.Seek(off1, whence1);
    if e1 != errors::nil {
        return (a, 0, e1);
    }
    let (b, e2) = o.Seek(off2, whence2);
    return (a, b, e2);
}

// go: none — goish-only: test shim for the unexported openMapFile.ReadAt.
#[doc(hidden)]
pub fn __shim_open_read_at(
    fsys: &MapFS,
    path: impl Into<string>,
    b: &mut slice<byte>,
    offset: crate::types::int64,
) -> (int, error) {
    let (f, err) = fs::FS::Open(fsys, path.into());
    if err != errors::nil {
        return (0, err);
    }
    let any = match f.__goish_as_dyn_any() {
        Some(a) => a,
        None => return (0, errors::New(string::from_static("not an openMapFile"))),
    };
    return match any.downcast_ref::<openMapFile>() {
        Some(o) => o.ReadAt(b, offset),
        None => (0, errors::New(string::from_static("not an openMapFile"))),
    };
}

impl MapFS {
    // go: sdk 1.25.5 testing/fstest/mapfs.go:230-232 MapFS.Glob
    /// Go: `return fs.Glob(fsOnly{fsys}, pattern)`.
    ///
    /// Deviation: Go wraps the receiver in `fsOnly` so that `fs.Glob`
    /// sees only the `Open` method and cannot recurse back into this
    /// one through the `GlobFS` check. goish's `fs::Glob` has no
    /// `GlobFS` fast path at all, so there is nothing to recurse into
    /// and the wrapper has no work to do.
    pub fn Glob<S: Into<string>>(&self, pattern: S) -> (slice<string>, error) {
        return crate::io::fs::Glob(self, pattern.into());
    }
}

// ─── testfs.go — the TestFS conformance harness ──────────────────────
//
// Partially ported: the error accumulator and the three formatters that
// render a mismatch. The checks themselves (checkDir, checkFile,
// checkGlob, checkStat, checkBadPath) and TestFS/testFS that
// drive them still need `fs.Glob`, `fs.Sub`, `fs.WalkDir` and
// `fs.ReadDirFile` reached through interface downcasts, which goish's
// io/fs does not fully provide yet.

// goishlint:ignore GOISH019 fsTester — Go's `fsys fs.FS` field is held
// by the driver (`testFS`), which is not ported; carrying a filesystem
// this struct never reads would imply a walk that does not exist here.
// goishlint:ignore GOISH020 checkOpen, checkBadPath, checkFileRead, checkDirList, checkStat — Go
// reads `t.fsys` off the receiver; goish's fsTester does not carry a
// filesystem (see GOISH019 above), so these take it, or the opener
// built from it, as a parameter instead. Same inputs, one hop
// explicit.
// goishlint:ignore GOISH020 errorf — Go's signature is
// `(format string, args ...any)`; goish takes the already-formatted
// string, matching how Logf/Skipf are handled in src/testing/testing.rs.
// go: sdk 1.25.5 testing/fstest/testfs.go:96-101 fsTester
/// Go: "An fsTester holds state for running the test."
///
/// Deviation: Go's `fsys fs.FS` field is carried by the driver
/// (`testFS`), which is not ported; this holds only the accumulated
/// state the formatters and `errorf` touch.
#[derive(Default)]
pub struct fsTester {
    errors: alloc::vec::Vec<error>,
    dirs: alloc::vec::Vec<string>,
    files: alloc::vec::Vec<string>,
}

impl fsTester {
    // go: sdk 1.25.5 testing/fstest/testfs.go:104-106 fsTester.errorf
    /// Go: "errorf adds an error to the list of errors."
    ///
    /// Deviation: Go is variadic over `...any`; goish takes the already
    /// formatted string, as elsewhere in this port.
    pub fn errorf(&mut self, msg: string) {
        self.errors.push(errors::New(msg));
    }

    // go: none — goish-only: read back what `errorf` accumulated. Go's
    // driver reaches the slice directly because it is in-package; the
    // field stays private here so the invariant "errors only grow via
    // errorf" holds.
    pub fn Errors(&self) -> slice<error> {
        return slice::__from_vec(self.errors.clone());
    }

    // go: none — goish-only: record a directory the walk found.
    pub fn __push_dir(&mut self, p: string) {
        self.dirs.push(p);
    }

    // go: none — goish-only: record a file the walk found.
    pub fn __push_file(&mut self, p: string) {
        self.files.push(p);
    }

    // go: none — goish-only: the walk's results, for a driver to check.
    pub fn Found(&self) -> (slice<string>, slice<string>) {
        return (
            slice::__from_vec(self.dirs.clone()),
            slice::__from_vec(self.files.clone()),
        );
    }
}

// go: sdk 1.25.5 testing/fstest/testfs.go:276-278 formatEntry
/// Go: `fmt.Sprintf("%s IsDir=%v Type=%v", entry.Name(), entry.IsDir(),
/// entry.Type())` — the rendering both sides of a DirEntry comparison
/// go through, so a mismatch prints as two directly comparable lines.
pub fn formatEntry(entry: &dyn DirEntry) -> string {
    return crate::fmt::Sprintf!(
        "%s IsDir=%v Type=%v",
        entry.Name(),
        entry.IsDir(),
        entry.Type().String()
    );
}

// go: sdk 1.25.5 testing/fstest/testfs.go:281-283 formatInfoEntry
/// Go: the same rendering as `formatEntry`, but taken from a FileInfo —
/// which is the point: a DirEntry and the FileInfo its `Info()` returns
/// must format identically, and that is what the conformance check
/// compares.
pub fn formatInfoEntry(info: &dyn FileInfo) -> string {
    return crate::fmt::Sprintf!(
        "%s IsDir=%v Type=%v",
        info.Name(),
        info.IsDir(),
        info.Mode().Type().String()
    );
}

// go: sdk 1.25.5 testing/fstest/testfs.go:286-288 formatInfo
/// Go: `fmt.Sprintf("%s IsDir=%v Mode=%v Size=%d ModTime=%v", ...)` —
/// the fuller rendering, used where the check compares a Stat against
/// an Open().Stat().
pub fn formatInfo(info: &dyn FileInfo) -> string {
    return crate::fmt::Sprintf!(
        "%s IsDir=%v Mode=%v Size=%d ModTime=%v",
        info.Name(),
        info.IsDir(),
        info.Mode().String(),
        info.Size(),
        // Go renders the Time through %v, i.e. Time.String(), which
        // goish's time does not provide. RFC3339Nano is the closest
        // stable rendering and is what matters here: the string is only
        // ever compared against another produced the same way.
        info.ModTime().Format(crate::gostring::string::from_static(crate::time::RFC3339Nano))
    );
}

impl fsTester {
    // go: sdk 1.25.5 testing/fstest/testfs.go:610-640 fsTester.checkBadPath
    /// Go: "checkBadPath checks that various invalid forms of file's name
    /// cannot be opened using t.fsys.Open."
    ///
    /// This is the check that catches an `FS` doing its own path
    /// cleaning. Every spelling below denotes the same file on a Unix
    /// filesystem, and `fs.FS` requires all of them to be *rejected* —
    /// only the canonical unrooted slash-separated form is valid. An
    /// implementation that helpfully normalised `a//b` to `a/b` would
    /// pass every functional test and fail here, which is the point.
    ///
    /// Deviation: Go reaches `t.fsys` through the receiver; goish's
    /// `fsTester` does not carry it (see the struct), so the caller
    /// supplies the opener directly.
    pub fn checkBadPath<F: Fn(string) -> error>(&mut self, file: string, desc: &str, open: F) {
        let f: &str = file.as_ref();
        let mut bad: alloc::vec::Vec<string> = alloc::vec::Vec::new();
        // Go: bad := []string{"/" + file, file + "/."}
        bad.push(crate::fmt::Sprintf!("/%s", file.clone()));
        bad.push(crate::fmt::Sprintf!("%s/.", file.clone()));
        // Go: if file == "." { bad = append(bad, "/") }
        if f == "." {
            bad.push(string::from_static("/"));
        }
        // Go: if i := strings.Index(file, "/"); i >= 0 { ...four forms... }
        if let Some(i) = f.find('/') {
            let (head, tail) = (&f[..i], &f[i + 1..]);
            bad.push(crate::fmt::Sprintf!("%s//%s", s_of(head), s_of(tail)));
            bad.push(crate::fmt::Sprintf!("%s/./%s", s_of(head), s_of(tail)));
            bad.push(crate::fmt::Sprintf!("%s\\%s", s_of(head), s_of(tail)));
            bad.push(crate::fmt::Sprintf!("%s/../%s", s_of(head), file.clone()));
        }
        // Go: if i := strings.LastIndex(file, "/"); i >= 0 { ...four more... }
        if let Some(i) = f.rfind('/') {
            let (head, tail) = (&f[..i], &f[i + 1..]);
            bad.push(crate::fmt::Sprintf!("%s//%s", s_of(head), s_of(tail)));
            bad.push(crate::fmt::Sprintf!("%s/./%s", s_of(head), s_of(tail)));
            bad.push(crate::fmt::Sprintf!("%s\\%s", s_of(head), s_of(tail)));
            bad.push(crate::fmt::Sprintf!("%s/../%s", file.clone(), s_of(tail)));
        }

        for b in bad.iter() {
            // Go: if err := open(b); err == nil {
            //         t.errorf("%s: %s(%s) succeeded, want error", ...) }
            if open(b.clone()) == errors::nil {
                self.errorf(crate::fmt::Sprintf!(
                    "%s: %s(%s) succeeded, want error",
                    file.clone(),
                    s_of(desc),
                    b.clone()
                ));
            }
        }
    }

    // go: sdk 1.25.5 testing/fstest/testfs.go:591-596 fsTester.checkFileRead
    /// Go: report when two reads of the same file returned different
    /// bytes — e.g. `ReadFile` disagreeing with `Open`+`ReadAll`.
    pub fn checkFileRead(
        &mut self,
        file: string,
        desc: &str,
        data1: slice<byte>,
        data2: slice<byte>,
    ) {
        if string::from_bytes(data1.as_ref()) != string::from_bytes(data2.as_ref()) {
            self.errorf(crate::fmt::Sprintf!(
                "%s: %s: different data returned\n\t%q\n\t%q",
                file.clone(),
                s_of(desc),
                string::from_bytes(data1.as_ref()),
                string::from_bytes(data2.as_ref())
            ));
        }
    }

    // go: sdk 1.25.5 testing/fstest/testfs.go:599-607 fsTester.checkOpen
    /// Go: "checkOpen validates file opening behavior by attempting to
    /// open and then close the given file path."
    ///
    /// Deviation: as `checkBadPath` — the filesystem arrives as a
    /// parameter rather than through the receiver.
    pub fn checkOpen(&mut self, fsys: &(dyn fs::FS + Send + Sync + 'static), file: string) {
        self.checkBadPath(file, "Open", |name| {
            let (f, err) = fs::FS::Open(fsys, name);
            // Go: if err == nil { f.Close() }
            if err == errors::nil {
                f.Close();
            }
            return err;
        });
    }
}

// go: none — goish idiom: `&str` to `string` for the Sprintf! call
// sites above, which take owned goish strings.
fn s_of(x: &str) -> string {
    return string::from_bytes(x.as_bytes());
}

impl fsTester {
    // go: sdk 1.25.5 testing/fstest/testfs.go:472-518 fsTester.checkDirList
    /// Go: "checkDirList checks that two directory lists contain the
    /// same files and file info."
    ///
    /// Two independent things happen here, and both matter:
    ///
    /// 1. `checkMode` asserts `entry.IsDir()` agrees with
    ///    `entry.Type() & ModeDir`. A DirEntry that says it is a
    ///    directory through one accessor and not the other is
    ///    internally inconsistent, and every caller picks one — so half
    ///    of them would be wrong with no way to tell which.
    /// 2. The two listings are diffed by name, and every surviving
    ///    difference is rendered as a +/- line. The diff is sorted by
    ///    name and then with `+` before `-`, so a rename reads as an
    ///    adjacent pair rather than two entries scattered apart.
    ///
    /// Deviation: Go compares `entry1 == nil` against a map lookup;
    /// goish's map returns `(value, ok)` so the presence flag is
    /// explicit rather than a nil interface.
    pub fn checkDirList(
        &mut self,
        dir: string,
        desc: &str,
        list1: &slice<Arc<dyn DirEntry + Send + Sync>>,
        list2: &slice<Arc<dyn DirEntry + Send + Sync>>,
    ) {
        // Go's `checkMode` closure, hoisted: it borrows `t` mutably and
        // the loops below also need `self`, which a closure capturing
        // `&mut self` would forbid.
        let mut mode_errs: alloc::vec::Vec<string> = alloc::vec::Vec::new();
        let mut check_mode = |entry: &(dyn DirEntry + Send + Sync)| {
            // Go: if entry.IsDir() != (entry.Type()&fs.ModeDir != 0)
            if entry.IsDir() != ((entry.Type().0 & fs::ModeDir.0) != 0) {
                if entry.IsDir() {
                    mode_errs.push(crate::fmt::Sprintf!(
                        "%s: ReadDir returned %s with IsDir() = true, Type() & ModeDir = 0",
                        dir.clone(),
                        entry.Name()
                    ));
                } else {
                    mode_errs.push(crate::fmt::Sprintf!(
                        "%s: ReadDir returned %s with IsDir() = false, Type() & ModeDir = ModeDir",
                        dir.clone(),
                        entry.Name()
                    ));
                }
            }
        };

        // Go keys this map by name to the DirEntry itself. goish's
        // `map` needs `Default` on the value to return a zero, which a
        // `dyn` trait object cannot supply — so it holds the entry's
        // index in `list1` instead. Same lookups, same deletions.
        let mut old: crate::map<string, int> = crate::map::new();
        for i in 0..list1.Len() {
            let e = list1[i].clone();
            old.Set(e.Name(), i);
            check_mode(e.as_ref());
        }

        let mut diffs: alloc::vec::Vec<string> = alloc::vec::Vec::new();
        for i in 0..list2.Len() {
            let e2 = list2[i].clone();
            let (i1, ok) = old.Get(e2.Name());
            if !ok {
                check_mode(e2.as_ref());
                diffs.push(crate::fmt::Sprintf!("+ %s", formatEntry(e2.as_ref())));
                continue;
            }
            let e1 = list1[i1].clone();
            if formatEntry(e1.as_ref()) != formatEntry(e2.as_ref()) {
                diffs.push(crate::fmt::Sprintf!("- %s", formatEntry(e1.as_ref())));
                diffs.push(crate::fmt::Sprintf!("+ %s", formatEntry(e2.as_ref())));
            }
            old.Delete(e2.Name());
        }
        // Go: for _, entry1 := range old { diffs = append(diffs, "- "+...) }
        // Go's map iteration order is randomised, but the sort below
        // makes the result deterministic either way.
        let leftover = old.Keys();
        for i in 0..leftover.Len() {
            let (i1, ok) = old.Get(leftover[i].clone());
            if ok {
                let e1 = list1[i1].clone();
                diffs.push(crate::fmt::Sprintf!("- %s", formatEntry(e1.as_ref())));
            }
        }

        drop(check_mode);
        for m in mode_errs.into_iter() {
            self.errorf(m);
        }

        if diffs.len() == 0 {
            return;
        }

        // Go: sort by name (i < j) and then +/- (j < i, because + < -).
        // The comparison key is deliberately asymmetric — it splices
        // the *other* line's sign in — so that for a given name the
        // '+' line sorts first.
        diffs.sort_by(|a, b| {
            let fa = crate::strings::Fields(a.clone());
            let fb = crate::strings::Fields(b.clone());
            if fa.Len() < 2 || fb.Len() < 2 {
                let x: &str = a.as_ref();
                let y: &str = b.as_ref();
                return x.cmp(y);
            }
            let left = crate::fmt::Sprintf!("%s %s", fa[1].clone(), fb[0].clone());
            let right = crate::fmt::Sprintf!("%s %s", fb[1].clone(), fa[0].clone());
            let c = crate::strings::Compare(left, right);
            return c.cmp(&0);
        });

        self.errorf(crate::fmt::Sprintf!(
            "%s: diff %s:\n\t%s",
            dir.clone(),
            s_of(desc),
            crate::strings::Join(
                slice::__from_vec(diffs),
                string::from_static("\n\t")
            )
        ));
    }
}

impl fsTester {
    // go: sdk 1.25.5 testing/fstest/testfs.go:390-468 fsTester.checkStat
    /// Go: "checkStat checks that the file's stat matches the directory
    /// entry."
    ///
    /// Four renderings of the same file have to agree, and the check
    /// exists because they are produced by four different code paths:
    /// the DirEntry from ReadDir, `entry.Info()`, `Open().Stat()`, and
    /// the free `fs.Stat`. A filesystem that assembles any one of them
    /// separately — a common shortcut — drifts here first.
    ///
    /// Symlinks are the exception threaded through the whole function:
    /// `Open` dereferences a symlink, so `file.Stat()` legitimately
    /// describes the *target* while the entry describes the link. Go
    /// therefore compares only the entry-shaped fields in that case,
    /// and this port keeps the same branch even though goish's MapFS
    /// has no symlink support yet — the logic is what is being ported.
    ///
    /// Deviation: Go's two optional-interface blocks (`fs.StatFS` and
    /// `fs.ReadLinkFS`) are absent. goish's io/fs declares neither
    /// trait, so there is nothing to type-assert to; when they arrive,
    /// so do those blocks.
    pub fn checkStat(
        &mut self,
        fsys: &(dyn fs::FS + Send + Sync + 'static),
        path: string,
        entry: &(dyn DirEntry + Send + Sync),
    ) {
        let (file, err) = fs::FS::Open(fsys, path.clone());
        if err != errors::nil {
            self.errorf(crate::fmt::Sprintf!("%s: Open: %v", path.clone(), err.Error()));
            return;
        }
        let (info, serr) = file.Stat();
        file.Close();
        if serr != errors::nil {
            self.errorf(crate::fmt::Sprintf!("%s: Stat: %v", path.clone(), serr.Error()));
            return;
        }

        let fentry = formatEntry(entry);
        let fientry = formatInfoEntry(info.as_ref());
        // Go: "Note: mismatch here is OK for symlink, because Open
        // dereferences symlink."
        let is_symlink = (entry.Type().0 & fs::ModeSymlink.0) != 0;
        if fentry != fientry && !is_symlink {
            self.errorf(crate::fmt::Sprintf!(
                "%s: mismatch:\n\tentry = %s\n\tfile.Stat() = %s",
                path.clone(),
                fentry.clone(),
                fientry.clone()
            ));
        }

        let (einfo, ierr) = entry.Info();
        if ierr != errors::nil {
            self.errorf(crate::fmt::Sprintf!(
                "%s: entry.Info: %v",
                path.clone(),
                ierr.Error()
            ));
            return;
        }
        let finfo = formatInfo(info.as_ref());
        if is_symlink {
            // Go: "For symlink, just check that entry.Info matches
            // entry on common fields. Open dereferences symlink, so
            // info itself may differ."
            let feentry = formatInfoEntry(einfo.as_ref());
            if fentry != feentry {
                self.errorf(crate::fmt::Sprintf!(
                    "%s: mismatch\n\tentry = %s\n\tentry.Info() = %s\n",
                    path.clone(),
                    fentry.clone(),
                    feentry
                ));
            }
        } else {
            let feinfo = formatInfo(einfo.as_ref());
            if feinfo != finfo {
                self.errorf(crate::fmt::Sprintf!(
                    "%s: mismatch:\n\tentry.Info() = %s\n\tfile.Stat() = %s\n",
                    path.clone(),
                    feinfo,
                    finfo.clone()
                ));
            }
        }

        // Go: "Stat should be the same as Open+Stat, even for symlinks."
        let (info2, s2err) = fs::Stat(fsys, path.clone());
        if s2err != errors::nil {
            self.errorf(crate::fmt::Sprintf!(
                "%s: fs.Stat: %v",
                path.clone(),
                s2err.Error()
            ));
            return;
        }
        let finfo2 = formatInfo(info2.as_ref());
        if finfo2 != finfo {
            self.errorf(crate::fmt::Sprintf!(
                "%s: fs.Stat(...) = %s\n\twant %s",
                path.clone(),
                finfo2,
                finfo
            ));
        }
    }
}
