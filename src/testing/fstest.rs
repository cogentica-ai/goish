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
use crate::io::fs::{self, DirEntry, File, FileInfo, FileMode, ModeDir, ModeSymlink, ReadDirFile};
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
        if ok {
            v.cloned()
        } else {
            None
        }
    }

    // Go: mapfs.go:48 — func (fsys MapFS) Open(name string) (fs.File, error)
    /// Open opens the named file after following any symbolic links.
    pub fn Open<S: Into<string>>(&self, name: S) -> (Arc<dyn File + Send + Sync>, error) {
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
                        info: mapFileInfo {
                            name: path::Base(name),
                            f: f.clone(),
                        },
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
                        list.push(mapFileInfo {
                            name: fname.clone(),
                            f: f.clone(),
                        });
                    }
                } else {
                    need.Set(string::from_bytes(&fname.as_bytes()[..i as usize]), true);
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
            list.push(mapFileInfo {
                name: n.clone(),
                f: synth_dir(),
            });
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
            let i = nb
                .iter()
                .rposition(|&c| c == b'/')
                .map(|i| i as i64)
                .unwrap_or(-1);
            string::from_bytes(&nb[(i + 1) as usize..])
        };
        (
            Arc::new(mapDir {
                path: name,
                info: mapFileInfo {
                    name: elem,
                    f: file,
                },
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
                return self.resolveSymlinks(path::Join(slice::__from_vec(alloc::vec![
                    path::Dir(name),
                    target
                ])));
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
                    let joined =
                        path::Join(slice::__from_vec(alloc::vec![path::Dir(dir), target,]));
                    let mut rejoined = joined.to_string();
                    rejoined.push_str(core::str::from_utf8(&name.as_bytes()[i..]).unwrap_or(""));
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
    pub fn Lstat<S: Into<string>>(&self, name: S) -> (Arc<dyn FileInfo + Send + Sync>, error) {
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
        let real_name = path::Join(slice::__from_vec(alloc::vec![real_dir, elem.clone()]));

        if let Some(file) = self.get(&real_name) {
            return (
                Some(mapFileInfo {
                    name: elem,
                    f: file,
                }),
                errors::nil,
            );
        }

        if real_name.as_bytes() == b"." {
            return (
                Some(mapFileInfo {
                    name: elem,
                    f: synth_dir(),
                }),
                errors::nil,
            );
        }
        // Go: Maybe a directory.
        let mut prefix = real_name.to_string();
        prefix.push('/');
        for (fname, _) in self.0.__iter() {
            if fname.as_bytes().starts_with(prefix.as_bytes()) {
                return (
                    Some(mapFileInfo {
                        name: elem,
                        f: synth_dir(),
                    }),
                    errors::nil,
                );
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
    pub fn Stat<S: Into<string>>(&self, name: S) -> (Arc<dyn FileInfo + Send + Sync>, error) {
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
    // Without this, `goish::cast!(file, SeekableFile)` in net/http's
    // ioFile.Seek is a SILENT miss — the impl alone is not enough.
    fs::__goish_register_SeekableFile_impl::<openMapFile>();
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
            return (
                0,
                path_err("read", &self.path, fs::ErrInvalid.clone().into()),
            );
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

// go: none — goish-only. Go's openMapFile satisfies io.Seeker by
// having a Seek method; goish's io::Seeker takes &mut self, which a
// shared `Arc<dyn fs::File>` cannot give, so the capability is
// declared as fs::SeekableFile and implemented here. This is what
// makes `goish::cast!(file, SeekableFile)` succeed for a MapFS file,
// the analogue of Go's `f.file.(io.Seeker)`.
impl crate::io::fs::SeekableFile for openMapFile {
    // go: none — goish-only capability interface; the body is the
    // anchored inherent Seek below.
    fn Seek(&self, offset: crate::types::int64, whence: int) -> (crate::types::int64, error) {
        return openMapFile::Seek(self, offset, whence);
    }
    // go: none — cast! plumbing.
    fn __goish_as_dyn_any(&self) -> Option<&(dyn core::any::Any + Send + Sync)> {
        return Some(self);
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
        (
            0,
            path_err("read", &self.path, fs::ErrInvalid.clone().into()),
        )
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
// goishlint:ignore GOISH020 checkOpen, checkBadPath, checkFileRead, checkDirList, checkStat, checkGlob, checkFile, openDir, checkDir, testFS, TestFS — Go
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
        info.ModTime().Format(crate::gostring::string::from_static(
            crate::time::RFC3339Nano
        ))
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
            crate::strings::Join(slice::__from_vec(diffs), string::from_static("\n\t"))
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
            self.errorf(crate::fmt::Sprintf!(
                "%s: Open: %v",
                path.clone(),
                err.Error()
            ));
            return;
        }
        let (info, serr) = file.Stat();
        file.Close();
        if serr != errors::nil {
            self.errorf(crate::fmt::Sprintf!(
                "%s: Stat: %v",
                path.clone(),
                serr.Error()
            ));
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

impl fsTester {
    // go: sdk 1.25.5 testing/fstest/testfs.go:291-386 fsTester.checkGlob
    /// Go: "checkGlob checks that various glob patterns work if the file
    /// system implements GlobFS."
    ///
    /// The pattern-mangling loop is the interesting half. For each rune
    /// of the directory name it emits one of five *equivalent* spellings
    /// — bare, `[r]`, `[r-r]`, `[\r]`, `[\r-\r]` — cycling by
    /// `(i+j) % 5`. Every one denotes the same single character, so a
    /// correct glob engine returns identical results for all of them;
    /// an engine that mishandles ranges, escapes-inside-brackets, or
    /// single-element classes diverges on exactly one spelling. That is
    /// far more searching than globbing the plain name would be.
    ///
    /// Deviation: Go opens with `if _, ok := t.fsys.(fs.GlobFS); !ok
    /// { return }` and then type-asserts three more times. goish has no
    /// `GlobFS` trait, so the glob function arrives as a parameter —
    /// which also means this check actually runs here, where in Go it
    /// silently skips any filesystem that does not implement the
    /// interface.
    pub fn checkGlob<G: Fn(string) -> (slice<string>, error)>(
        &mut self,
        dir: string,
        list: &slice<Arc<dyn DirEntry + Send + Sync>>,
        globfn: G,
    ) {
        // Go: "Make a complex glob pattern prefix that only matches dir."
        let mut glob = string::from_static("");
        let d: &str = dir.as_ref();
        if d != "." {
            let elems = crate::strings::Split(dir.clone(), string::from_static("/"));
            let mut out: alloc::vec::Vec<string> = alloc::vec::Vec::new();
            for i in 0..elems.Len() {
                let e: &str = elems[i].as_ref();
                let mut pattern: alloc::vec::Vec<char> = alloc::vec::Vec::new();
                for (j, r) in e.chars().enumerate() {
                    if r == '*' || r == '?' || r == '\\' || r == '[' || r == '-' {
                        pattern.push('\\');
                        pattern.push(r);
                        continue;
                    }
                    match (usize::try_from(i).unwrap_or(0) + j) % 5 {
                        0 => pattern.push(r),
                        1 => {
                            pattern.push('[');
                            pattern.push(r);
                            pattern.push(']');
                        }
                        2 => {
                            pattern.push('[');
                            pattern.push(r);
                            pattern.push('-');
                            pattern.push(r);
                            pattern.push(']');
                        }
                        3 => {
                            pattern.push('[');
                            pattern.push('\\');
                            pattern.push(r);
                            pattern.push(']');
                        }
                        _ => {
                            pattern.push('[');
                            pattern.push('\\');
                            pattern.push(r);
                            pattern.push('-');
                            pattern.push('\\');
                            pattern.push(r);
                            pattern.push(']');
                        }
                    }
                }
                let built: alloc::string::String = pattern.into_iter().collect();
                out.push(s_of(&built));
            }
            glob = crate::fmt::Sprintf!(
                "%s/",
                crate::strings::Join(slice::__from_vec(out), string::from_static("/"))
            );
        }

        // Go: "Test that malformed patterns are detected. The error is
        // likely path.ErrBadPattern but need not be."
        let bad = crate::fmt::Sprintf!("%snonexist/[]", glob.clone());
        let (_, berr) = globfn(bad.clone());
        if berr == errors::nil {
            self.errorf(crate::fmt::Sprintf!(
                "%s: Glob(%q): bad pattern not detected",
                dir.clone(),
                bad
            ));
        }

        // Go: "Try to find a letter that appears in only some of the
        // final names." — so the glob is genuinely selective rather
        // than matching everything or nothing.
        let mut c: char = 'a';
        while c <= 'z' {
            let (mut have, mut have_not) = (false, false);
            for i in 0..list.Len() {
                let n = list[i].Name();
                let ns: &str = n.as_ref();
                if ns.contains(c) {
                    have = true;
                } else {
                    have_not = true;
                }
            }
            if have && have_not {
                break;
            }
            c = char::from_u32(u32::from(c) + 1).unwrap_or('z');
        }
        if c > 'z' {
            c = 'a';
        }
        let mut cbuf = [0u8; 4];
        glob = crate::fmt::Sprintf!("%s*%s*", glob.clone(), s_of(c.encode_utf8(&mut cbuf)));

        let mut want: alloc::vec::Vec<string> = alloc::vec::Vec::new();
        for i in 0..list.Len() {
            let n = list[i].Name();
            let ns: &str = n.as_ref();
            if ns.contains(c) {
                want.push(crate::path::Join(slice::__from_vec(alloc::vec![
                    dir.clone(),
                    n
                ])));
            }
        }

        let (names, gerr) = globfn(glob.clone());
        if gerr != errors::nil {
            self.errorf(crate::fmt::Sprintf!(
                "%s: Glob(%q): %v",
                dir.clone(),
                glob.clone(),
                gerr.Error()
            ));
            return;
        }

        let mut got: alloc::vec::Vec<string> = alloc::vec::Vec::new();
        for i in 0..names.Len() {
            got.push(names[i].clone());
        }
        if got == want {
            return;
        }

        // Go: if !slices.IsSorted(names) { errorf(unsorted); sort }
        let mut sorted = true;
        for i in 1..got.len() {
            let (a, b): (&str, &str) = (got[i - 1].as_ref(), got[i].as_ref());
            if a > b {
                sorted = false;
                break;
            }
        }
        if !sorted {
            self.errorf(crate::fmt::Sprintf!(
                "%s: Glob(%q): unsorted output:\n%s",
                dir.clone(),
                glob.clone(),
                crate::strings::Join(slice::__from_vec(got.clone()), string::from_static("\n"))
            ));
            got.sort_by(|x, y| {
                let (a, b): (&str, &str) = (x.as_ref(), y.as_ref());
                return a.cmp(b);
            });
        }

        // Go's merge walk over the two sorted lists, reporting each
        // side's surplus as missing/extra.
        let mut problems: alloc::vec::Vec<string> = alloc::vec::Vec::new();
        let (mut wi, mut gi) = (0usize, 0usize);
        while wi < want.len() || gi < got.len() {
            if wi < want.len() && gi < got.len() && want[wi] == got[gi] {
                wi += 1;
                gi += 1;
            } else if wi < want.len()
                && (gi >= got.len() || {
                    let (a, b): (&str, &str) = (want[wi].as_ref(), got[gi].as_ref());
                    a < b
                })
            {
                problems.push(crate::fmt::Sprintf!("missing: %s", want[wi].clone()));
                wi += 1;
            } else {
                problems.push(crate::fmt::Sprintf!("extra: %s", got[gi].clone()));
                gi += 1;
            }
        }
        self.errorf(crate::fmt::Sprintf!(
            "%s: Glob(%q): wrong output:\n%s",
            dir.clone(),
            glob,
            crate::strings::Join(slice::__from_vec(problems), string::from_static("\n"))
        ));
    }
}

impl fsTester {
    // go: sdk 1.25.5 testing/fstest/testfs.go:108-121 fsTester.openDir
    /// Go: open `dir` and assert the result is an `fs.ReadDirFile`.
    ///
    /// A directory that opens but cannot be read as one is the failure
    /// this catches — an `FS` whose `Open` returns a plain file handle
    /// for a directory path passes every read test and dies the moment
    /// anything walks it.
    ///
    /// Deviation: Go returns the `fs.ReadDirFile` and nil-checks at the
    /// call site; goish returns `(entries, ok)` because the downcast
    /// goes through `__goish_as_dyn_any` and handing back a borrowed
    /// trait object would outlive the `Arc`.
    pub fn openDir(
        &mut self,
        fsys: &(dyn fs::FS + Send + Sync + 'static),
        dir: string,
    ) -> (slice<Arc<dyn DirEntry + Send + Sync>>, bool) {
        let (f, err) = fs::FS::Open(fsys, dir.clone());
        if err != errors::nil {
            self.errorf(crate::fmt::Sprintf!(
                "%s: Open: %v",
                dir.clone(),
                err.Error()
            ));
            return (slice::new(), false);
        }
        // Go: d, ok := f.(fs.ReadDirFile); if !ok { f.Close(); errorf }
        let any = match f.__goish_as_dyn_any() {
            Some(a) => a,
            None => {
                f.Close();
                self.errorf(crate::fmt::Sprintf!(
                    "%s: Open returned a File that is not a fs.ReadDirFile",
                    dir.clone()
                ));
                return (slice::new(), false);
            }
        };
        if let Some(d) = any.downcast_ref::<mapDir>() {
            let (entries, rerr) = d.read_dir(-1);
            f.Close();
            if rerr != errors::nil {
                self.errorf(crate::fmt::Sprintf!(
                    "%s: ReadDir: %v",
                    dir.clone(),
                    rerr.Error()
                ));
                return (slice::new(), false);
            }
            return (entries, true);
        }
        f.Close();
        self.errorf(crate::fmt::Sprintf!(
            "%s: Open returned a File that is not a fs.ReadDirFile",
            dir.clone()
        ));
        return (slice::new(), false);
    }

    // go: sdk 1.25.5 testing/fstest/testfs.go:521-589 fsTester.checkFile
    /// Go: "checkFile checks that basic file reading works correctly."
    ///
    /// Three things beyond "the bytes come back":
    ///
    ///  * Closing twice must not crash. Go says so explicitly and
    ///    ignores the second return value — an `FS` that panics or
    ///    double-frees on a second Close breaks every `defer f.Close()`
    ///    written next to an explicit one.
    ///  * `fs.ReadFile` must agree with `Open` + read-to-end. Two code
    ///    paths, one answer.
    ///  * Mutating the slice a `ReadFile` returned must not change what
    ///    the next call returns. An implementation handing out its
    ///    internal buffer passes every other check here and corrupts
    ///    the filesystem from the outside.
    ///
    /// Deviations: Go's `fs.ReadFileFS` block is absent — goish's io/fs
    /// has no such trait to assert on — and the closing
    /// `iotest.TestReader` call is absent because `TestReader` is the
    /// one declaration of `testing/iotest` not yet ported (it needs
    /// ReadSeeker/ReaderAt downcasts). The aliasing check that block
    /// would have performed is done here against `fs::ReadFile`
    /// instead, so the property is still covered.
    pub fn checkFile(&mut self, fsys: &(dyn fs::FS + Send + Sync + 'static), file: string) {
        self.__push_file(file.clone());

        // Go: read the entire file through Open.
        let (f, err) = fs::FS::Open(fsys, file.clone());
        if err != errors::nil {
            self.errorf(crate::fmt::Sprintf!(
                "%s: Open: %v",
                file.clone(),
                err.Error()
            ));
            return;
        }
        let (data, rerr) = read_all_file(f.as_ref());
        if rerr != errors::nil {
            f.Close();
            self.errorf(crate::fmt::Sprintf!(
                "%s: Open+ReadAll: %v",
                file.clone(),
                rerr.Error()
            ));
            return;
        }
        let cerr = f.Close();
        if cerr != errors::nil {
            self.errorf(crate::fmt::Sprintf!(
                "%s: Close: %v",
                file.clone(),
                cerr.Error()
            ));
        }
        // Go: "Check that closing twice doesn't crash. The return value
        // doesn't matter."
        f.Close();

        // Go: "Check that fs.ReadFile works with t.fsys."
        let (data2, r2err) = fs::ReadFile(fsys, file.clone());
        if r2err != errors::nil {
            self.errorf(crate::fmt::Sprintf!(
                "%s: fs.ReadFile: %v",
                file.clone(),
                r2err.Error()
            ));
            return;
        }
        self.checkFileRead(
            file.clone(),
            "ReadAll vs fs.ReadFile",
            data.clone(),
            data2.clone(),
        );

        // Go performs this aliasing check inside the ReadFileFS block:
        // "Modify the data and check it again. Modifying the returned
        // byte slice should not affect the next call."
        let mut mutated = data2.clone();
        for i in 0..mutated.Len() {
            mutated[i] = mutated[i].wrapping_add(1);
        }
        let (data3, r3err) = fs::ReadFile(fsys, file.clone());
        if r3err != errors::nil {
            self.errorf(crate::fmt::Sprintf!(
                "%s: second call to fs.ReadFile: %v",
                file.clone(),
                r3err.Error()
            ));
            return;
        }
        self.checkFileRead(file.clone(), "ReadAll vs second fs.ReadFile", data, data3);

        self.checkBadPath(file, "ReadFile", |name| {
            let (_, e) = fs::ReadFile(fsys, name);
            return e;
        });
    }
}

// go: none — goish idiom: Go calls `io.ReadAll(f)` on the `fs.File`
// interface. goish's `fs::File::Read` takes `&self` and a `&mut
// slice<byte>` rather than satisfying `io::Reader`, so the read-to-end
// loop is spelled here.
fn read_all_file(f: &(dyn File + Send + Sync)) -> (slice<byte>, error) {
    let mut out: alloc::vec::Vec<byte> = alloc::vec::Vec::new();
    let mut buf: slice<byte> = crate::make!([]byte, 512);
    return 'read: loop {
        let (n, err) = f.Read(&mut buf);
        if n > 0 {
            for i in 0..n {
                out.push(buf[i]);
            }
        }
        if err != errors::nil {
            // Go: io.ReadAll treats EOF as success.
            let eof: error = crate::io::EOF.clone().into();
            if err == eof {
                break 'read (slice::__from_vec(out), errors::nil);
            }
            break 'read (slice::__from_vec(out), err);
        }
        if n == 0 {
            break 'read (slice::__from_vec(out), errors::nil);
        }
    };
}

// go: none — goish-only: open a directory and hand back the live
// handle, which `checkDir` needs because several of its checks depend
// on ReadDir's *position* persisting across calls (read to EOF, then
// confirm ReadDir(-1) returns nothing and ReadDir(1) returns EOF).
// `openDir` above closes the handle and returns a snapshot, which is
// the right shape for its own caller but loses exactly that state.
fn open_dir_handle(
    fsys: &(dyn fs::FS + Send + Sync + 'static),
    dir: string,
) -> (Option<Arc<dyn File + Send + Sync>>, error) {
    let (f, err) = fs::FS::Open(fsys, dir);
    if err != errors::nil {
        return (None, err);
    }
    return (Some(f), errors::nil);
}

// go: none — goish-only: `ReadDir(n)` on a live handle. The downcast to
// `mapDir` stands in for Go's `f.(fs.ReadDirFile)` type assertion,
// which goish's io/fs cannot express yet.
fn handle_read_dir(
    f: &(dyn File + Send + Sync),
    n: int,
) -> (slice<Arc<dyn DirEntry + Send + Sync>>, error, bool) {
    let any = match f.__goish_as_dyn_any() {
        Some(a) => a,
        None => return (slice::new(), errors::nil, false),
    };
    return match any.downcast_ref::<mapDir>() {
        Some(d) => {
            let (e, err) = d.read_dir(n);
            (e, err, true)
        }
        None => (slice::new(), errors::nil, false),
    };
}

impl fsTester {
    // go: sdk 1.25.5 testing/fstest/testfs.go:125-273 fsTester.checkDir
    /// Go: "checkDir checks the directory dir, which is expected to
    /// exist (it is either the root or was found in a directory
    /// listing with IsDir true)."
    ///
    /// The heart of TestFS, and the only recursive check: it walks the
    /// whole tree, and for each directory reads it four different ways,
    /// requiring all four to agree —
    ///
    ///   1. `Open` + `ReadDir(-1)` (the reference listing)
    ///   2. reopen + `ReadDir(-1)`
    ///   3. reopen + `ReadDir(1)`, `ReadDir(2)`, … in pieces
    ///   4. the free `fs.ReadDir`
    ///
    /// A filesystem that caches a listing on the handle, or whose
    /// piecewise reads lose or duplicate an entry at a chunk boundary,
    /// fails only against the third. It also pins the EOF contract,
    /// which is asymmetric and easy to get wrong: at EOF `ReadDir(-1)`
    /// returns zero entries and **nil**, while `ReadDir(1)` returns
    /// zero entries and **io.EOF**.
    ///
    /// Deviations: Go's `fs.ReadDirFS` block is absent (no such trait
    /// here) — the `fs.ReadDir` block below covers the same ground, and
    /// both sort checks are kept. Symlink children are recorded without
    /// being followed, exactly as Go does, "to avoid potentially
    /// unbounded recursion".
    pub fn checkDir(&mut self, fsys: &(dyn fs::FS + Send + Sync + 'static), dir: string) {
        self.__push_dir(dir.clone());

        let (dh, oerr) = open_dir_handle(fsys, dir.clone());
        let d = match dh {
            Some(d) => d,
            None => {
                self.errorf(crate::fmt::Sprintf!(
                    "%s: Open: %v",
                    dir.clone(),
                    oerr.Error()
                ));
                return;
            }
        };
        let (list, rerr, ok) = handle_read_dir(d.as_ref(), -1);
        if !ok {
            d.Close();
            self.errorf(crate::fmt::Sprintf!(
                "%s: Open returned a File that is not a fs.ReadDirFile",
                dir.clone()
            ));
            return;
        }
        if rerr != errors::nil {
            d.Close();
            self.errorf(crate::fmt::Sprintf!(
                "%s: ReadDir(-1): %v",
                dir.clone(),
                rerr.Error()
            ));
            return;
        }

        // Go: prefix is "" for ".", else dir + "/".
        let ds: &str = dir.as_ref();
        let prefix = if ds == "." {
            string::from_static("")
        } else {
            crate::fmt::Sprintf!("%s/", dir.clone())
        };

        for i in 0..list.Len() {
            let info = list[i].clone();
            let name = info.Name();
            let ns: &str = name.as_ref();
            if ns == "." || ns == ".." || ns.is_empty() {
                self.errorf(crate::fmt::Sprintf!(
                    "%s: ReadDir: child has invalid name: %q",
                    dir.clone(),
                    name
                ));
                continue;
            }
            if ns.contains('/') {
                self.errorf(crate::fmt::Sprintf!(
                    "%s: ReadDir: child name contains slash: %q",
                    dir.clone(),
                    name
                ));
                continue;
            }
            if ns.contains('\\') {
                self.errorf(crate::fmt::Sprintf!(
                    "%s: ReadDir: child name contains backslash: %q",
                    dir.clone(),
                    name
                ));
                continue;
            }
            let path = crate::fmt::Sprintf!("%s%s", prefix.clone(), name);
            self.checkStat(fsys, path.clone(), info.as_ref());
            self.checkOpen(fsys, path.clone());
            let ty = info.Type();
            if ty.0 == fs::ModeDir.0 {
                self.checkDir(fsys, path);
            } else if ty.0 == fs::ModeSymlink.0 {
                // Go: "No further processing. Avoid following symlinks
                // to avoid potentially unbounded recursion."
                self.__push_file(path);
            } else {
                self.checkFile(fsys, path);
            }
        }

        // Go: "Check ReadDir(-1) at EOF." — zero entries and NIL.
        let (l2, e2, _) = handle_read_dir(d.as_ref(), -1);
        if l2.Len() > 0 || e2 != errors::nil {
            d.Close();
            self.errorf(crate::fmt::Sprintf!(
                "%s: ReadDir(-1) at EOF = %d entries, %v, wanted 0 entries, nil",
                dir.clone(),
                l2.Len(),
                e2.Error()
            ));
            return;
        }

        // Go: "Check ReadDir(1) at EOF (different results)." — zero
        // entries and EOF. Note the asymmetry with the case above.
        let eof: error = crate::io::EOF.clone().into();
        let (l3, e3, _) = handle_read_dir(d.as_ref(), 1);
        if l3.Len() > 0 || e3 != eof {
            d.Close();
            self.errorf(crate::fmt::Sprintf!(
                "%s: ReadDir(1) at EOF = %d entries, %v, wanted 0 entries, EOF",
                dir.clone(),
                l3.Len(),
                e3.Error()
            ));
            return;
        }

        let cerr = d.Close();
        if cerr != errors::nil {
            self.errorf(crate::fmt::Sprintf!(
                "%s: Close: %v",
                dir.clone(),
                cerr.Error()
            ));
        }
        // Go: "Check that closing twice doesn't crash."
        d.Close();

        // Go: "Reopen directory, read a second time, make sure contents
        // match."
        let (dh2, _) = open_dir_handle(fsys, dir.clone());
        let d2 = match dh2 {
            Some(x) => x,
            None => return,
        };
        let (second, serr, _) = handle_read_dir(d2.as_ref(), -1);
        if serr != errors::nil {
            d2.Close();
            self.errorf(crate::fmt::Sprintf!(
                "%s: second Open+ReadDir(-1): %v",
                dir.clone(),
                serr.Error()
            ));
            return;
        }
        d2.Close();
        self.checkDirList(
            dir.clone(),
            "first Open+ReadDir(-1) vs second Open+ReadDir(-1)",
            &list,
            &second,
        );

        // Go: "Reopen directory, read a third time in pieces, make sure
        // contents match." The chunk size alternates 1 then 2, so a
        // filesystem that mishandles a boundary shows up here.
        let (dh3, _) = open_dir_handle(fsys, dir.clone());
        let d3 = match dh3 {
            Some(x) => x,
            None => return,
        };
        let mut third: slice<Arc<dyn DirEntry + Send + Sync>> = slice::new();
        loop {
            let n: int = if third.Len() > 0 { 2 } else { 1 };
            let (frag, ferr, _) = handle_read_dir(d3.as_ref(), n);
            if frag.Len() > n {
                d3.Close();
                self.errorf(crate::fmt::Sprintf!(
                    "%s: third Open: ReadDir(%d) after %d: %d entries (too many)",
                    dir.clone(),
                    n,
                    third.Len(),
                    frag.Len()
                ));
                return;
            }
            for k in 0..frag.Len() {
                third = crate::append!(third, frag[k].clone());
            }
            if ferr == eof {
                break;
            }
            if ferr != errors::nil {
                d3.Close();
                self.errorf(crate::fmt::Sprintf!(
                    "%s: third Open: ReadDir(%d) after %d: %v",
                    dir.clone(),
                    n,
                    third.Len(),
                    ferr.Error()
                ));
                return;
            }
            if frag.Len() == 0 {
                d3.Close();
                self.errorf(crate::fmt::Sprintf!(
                    "%s: third Open: ReadDir(%d) after %d: 0 entries but nil error",
                    dir.clone(),
                    n,
                    third.Len()
                ));
                return;
            }
        }
        d3.Close();
        self.checkDirList(
            dir.clone(),
            "first Open+ReadDir(-1) vs third Open+ReadDir(1,2) loop",
            &list,
            &third,
        );

        // Go: "Check fs.ReadDir as well."
        let (fourth, r4err) = fs::ReadDir(fsys, dir.clone());
        if r4err != errors::nil {
            self.errorf(crate::fmt::Sprintf!(
                "%s: fs.ReadDir: %v",
                dir.clone(),
                r4err.Error()
            ));
            return;
        }
        self.checkDirList(
            dir.clone(),
            "first Open+ReadDir(-1) vs fs.ReadDir",
            &list,
            &fourth,
        );

        for i in 0..(fourth.Len() - 1).max(0) {
            if fourth[i].Name() >= fourth[i + 1].Name() {
                self.errorf(crate::fmt::Sprintf!(
                    "%s: fs.ReadDir: list not sorted: %s before %s",
                    dir.clone(),
                    fourth[i].Name(),
                    fourth[i + 1].Name()
                ));
            }
        }

        self.checkGlob(dir, &fourth, |pat| {
            return fs::Glob(fsys, pat);
        });
    }
}

// go: sdk 1.25.5 testing/fstest/testfs.go:65-93 testFS
/// Go: walk `fsys` from the root, run every check, and report the
/// accumulated errors as one.
///
/// The `expected` list is checked both ways: everything named must be
/// found, AND — when the list is empty — nothing may be found. That
/// second direction is what makes `TestFS(fsys)` with no arguments a
/// meaningful assertion that a filesystem is empty, rather than a
/// no-op.
///
/// Go's 15-entry truncation of the "expected empty" list is kept, as is
/// `errors.Join` — so the returned error unwraps to the individual
/// failures rather than flattening to a single string.
pub fn testFS(fsys: &(dyn fs::FS + Send + Sync + 'static), expected: &slice<string>) -> error {
    let mut t = fsTester::default();
    t.checkDir(fsys, string::from_static("."));
    t.checkOpen(fsys, string::from_static("."));

    let (dirs, files) = t.Found();
    let mut found: crate::map<string, bool> = crate::map::new();
    for i in 0..dirs.Len() {
        found.Set(dirs[i].clone(), true);
    }
    for i in 0..files.Len() {
        found.Set(files[i].clone(), true);
    }
    found.Delete(string::from_static("."));

    if expected.Len() == 0 && found.Len() > 0 {
        let keys = found.Keys();
        let mut list: alloc::vec::Vec<string> = alloc::vec::Vec::new();
        for i in 0..keys.Len() {
            list.push(keys[i].clone());
        }
        list.sort_by(|a, b| {
            let (x, y): (&str, &str) = (a.as_ref(), b.as_ref());
            return x.cmp(y);
        });
        // Go: if len(list) > 15 { list = append(list[:10], "...") }
        if list.len() > 15 {
            list.truncate(10);
            list.push(string::from_static("..."));
        }
        t.errorf(crate::fmt::Sprintf!(
            "expected empty file system but found files:\n%s",
            crate::strings::Join(slice::__from_vec(list), string::from_static("\n"))
        ));
    }

    for i in 0..expected.Len() {
        let name = expected[i].clone();
        let (ok, present) = found.Get(name.clone());
        if !present || !ok {
            t.errorf(crate::fmt::Sprintf!("expected but not found: %s", name));
        }
    }

    let errs = t.Errors();
    if errs.Len() == 0 {
        return errors::nil;
    }
    // Go: fmt.Errorf("TestFS found errors:\n%w", errors.Join(t.errors...))
    return crate::fmt::Errorf!("TestFS found errors:\n%w", errors::Join(errs));
}

// go: sdk 1.25.5 testing/fstest/testfs.go:39-63 TestFS
/// Go: "TestFS tests a file system implementation. It walks the entire
/// tree of files in fsys, opening and checking that each file behaves
/// correctly. It also checks that the file system contains at least the
/// expected files. As a special case, if no expected files are listed,
/// fsys must be empty. Otherwise, fsys must contain at least the listed
/// files; it can also contain others. The contents of fsys must not
/// change concurrently with TestFS.
///
/// If TestFS finds any misbehaviors, it returns either the first error
/// or a list of errors."
///
/// After the top-level walk it picks the first expected name containing
/// a slash, takes `fs.Sub` of that directory, and runs the whole suite
/// again against the subtree — so a `SubFS` that rewrites paths
/// incorrectly is caught. Go stops after one such subtest ("one
/// sub-test is enough") and so does this.
pub fn TestFS(fsys: Arc<dyn fs::FS + Send + Sync>, expected: &slice<string>) -> error {
    let err = testFS(fsys.as_ref(), expected);
    if err != errors::nil {
        return err;
    }
    for i in 0..expected.Len() {
        let name = expected[i].clone();
        let ns: &str = name.as_ref();
        if let Some(idx) = ns.find('/') {
            let dir = s_of(&ns[..idx]);
            let dir_slash = s_of(&ns[..idx + 1]);
            let mut sub_expected: alloc::vec::Vec<string> = alloc::vec::Vec::new();
            for j in 0..expected.Len() {
                let other = expected[j].clone();
                let os_: &str = other.as_ref();
                let dslash: &str = dir_slash.as_ref();
                if os_.starts_with(dslash) {
                    sub_expected.push(s_of(&os_[dslash.len()..]));
                }
            }
            let (sub, serr) = fs::Sub(fsys.clone(), dir.clone());
            if serr != errors::nil {
                return serr;
            }
            let suberr = testFS(sub.as_ref(), &slice::__from_vec(sub_expected));
            if suberr != errors::nil {
                return errors::New(crate::fmt::Sprintf!(
                    "testing fs.Sub(fsys, %s): %v",
                    dir,
                    suberr.Error()
                ));
            }
            // Go: "one sub-test is enough"
            break;
        }
    }
    return errors::nil;
}

impl mapFileInfo {
    // go: sdk 1.25.5 testing/fstest/mapfs.go:259-261 mapFileInfo.String
    /// Go: `return fs.FormatFileInfo(i)` — the human-readable rendering
    /// `%v` on a FileInfo produces.
    pub fn String(&self) -> string {
        return crate::io::fs::FormatFileInfo(self);
    }
}

impl MapFS {
    // go: sdk 1.25.5 testing/fstest/mapfs.go:240-242 MapFS.Sub
    /// Go: `return fs.Sub(noSub{fsys}, dir)`.
    ///
    /// Deviation, and the same shape as `Glob` above: Go wraps the
    /// receiver in `noSub` — a struct embedding MapFS whose own `Sub()`
    /// has a deliberately wrong signature — purely so `fs.Sub` cannot
    /// see a `SubFS` and recurse straight back here. goish's `fs::Sub`
    /// has no `SubFS` fast path, so there is nothing to hide from and
    /// the wrapper has no work to do.
    pub fn Sub<S: Into<string>>(
        self: &Arc<Self>,
        dir: S,
    ) -> (Arc<dyn fs::FS + Send + Sync>, error) {
        let me: Arc<dyn fs::FS + Send + Sync> = self.clone();
        return crate::io::fs::Sub(me, dir.into());
    }
}

// go: none — goish-only: test shim for the unexported
// `mapFileInfo.String`. Go's is reachable through `%v` on the
// fs.FileInfo interface; goish's FileInfo trait has no Stringer bridge,
// so an example cannot get at it any other way. Builds the info the
// same way `MapFS.Stat` does.
#[doc(hidden)]
pub fn __shim_map_file_info_string(fsys: &MapFS, name: impl Into<string>) -> (string, bool) {
    let name: string = name.into();
    let (f, ok) = fsys.0.Get(name.clone());
    if !ok {
        return (string::from_static(""), false);
    }
    let info = mapFileInfo { name: name, f: f };
    return (info.String(), true);
}
