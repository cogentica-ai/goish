// go: file testing/fstest/mapfs.go decls: MapFS.Open, MapFS.resolveSymlinks, MapFS.ReadLink, MapFS.Lstat, MapFS.lstat, MapFS.ReadFile, MapFS.Stat, MapFS.ReadDir, mapFileInfo.Name, mapFileInfo.Size, mapFileInfo.Mode, mapFileInfo.ModTime, mapFileInfo.IsDir, mapFileInfo.Sys, mapFileInfo.Type, mapFileInfo.Info, openMapFile.Stat, openMapFile.Read, openMapFile.Close, openMapFile.Seek, openMapFile.ReadAt, mapDir.ReadDir, mapDir.Stat, mapDir.Read, mapDir.Close, mapFileInfo.String, MapFS.Sub, MapFS.Glob
//
// mapfs.go — MapFS, an in-memory fs.FS built from a map.

use alloc::string::ToString;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicI64, AtomicUsize, Ordering};

use crate::convert::{int as toint, int64 as toint64};
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
    // go: none — goish idiom: Go's `MapFS` is a map type, so a caller
    //     writes `fstest.MapFS{}` and the zero value is usable. goish's
    //     is a newtype over `map`, which needs a constructor.
    pub fn new() -> MapFS {
        return MapFS(map::new());
    }

    // go: none — goish idiom: Go indexes the map directly —
    //     `fsys[name]` yields `(*MapFile, bool)` at every use site.
    //     goish's `map::Get` returns a tuple; this narrows it to an
    //     `Option` so the callers read the way Go's do.
    fn get(&self, name: &string) -> Option<Arc<MapFile>> {
        let (v, ok) = self.0.GetRef(name.clone());
        return if ok { v.cloned() } else { None };
    }

    // go: sdk 1.25.5 testing/fstest/mapfs.go:48-120 MapFS.Open
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
                .map(|i| toint64(i))
                .unwrap_or(-1);
            string::from_bytes(&nb[(i + 1) as usize..])
        };
        return (
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
        );
    }

    // go: sdk 1.25.5 testing/fstest/mapfs.go:122-153 MapFS.resolveSymlinks
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
                    return self.resolveSymlinks(string::from(AsRef::<str>::as_ref(&rejoined)));
                }
            }
            i += 1; // Go: i += len("/")
        }
        let ok = fs::ValidPath(name.clone());
        return (name, ok);
    }

    // go: sdk 1.25.5 testing/fstest/mapfs.go:156-165 MapFS.ReadLink
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
        return (string::from_bytes(info.f.Data.as_ref()), errors::nil);
    }

    // go: sdk 1.25.5 testing/fstest/mapfs.go:170-176 MapFS.Lstat
    // Go: mapfs.go:171 — func (fsys MapFS) Lstat(name string) (fs.FileInfo, error)
    /// Lstat returns a FileInfo describing the named file without
    /// following symbolic links.
    pub fn Lstat<S: Into<string>>(&self, name: S) -> (Arc<dyn FileInfo + Send + Sync>, error) {
        register_fstest_impls();
        let name: string = name.into();
        let (info, err) = self.lstat(&name);
        return match info {
            Some(i) => (Arc::new(i), errors::nil),
            None => (crate::nil.into(), path_err("lstat", &name, err)),
        };
    }

    // go: sdk 1.25.5 testing/fstest/mapfs.go:178-208 MapFS.lstat
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
        return (None, fs::ErrNotExist.clone().into());
    }

    // go: sdk 1.25.5 testing/fstest/mapfs.go:218-220 MapFS.ReadFile
    /// Go: `return fs.ReadFile(fsOnly{fsys}, name)`.
    pub fn ReadFile<S: Into<string>>(&self, name: S) -> (slice<byte>, error) {
        return fs::ReadFile(&fsOnly::of(self), name);
    }

    // go: sdk 1.25.5 testing/fstest/mapfs.go:222-224 MapFS.Stat
    /// Go: `return fs.Stat(fsOnly{fsys}, name)`.
    pub fn Stat<S: Into<string>>(&self, name: S) -> (Arc<dyn FileInfo + Send + Sync>, error) {
        return fs::Stat(&fsOnly::of(self), name);
    }

    // go: sdk 1.25.5 testing/fstest/mapfs.go:226-228 MapFS.ReadDir
    /// Go: `return fs.ReadDir(fsOnly{fsys}, name)`.
    pub fn ReadDir<S: Into<string>>(
        &self,
        name: S,
    ) -> (slice<Arc<dyn DirEntry + Send + Sync>>, error) {
        return fs::ReadDir(&fsOnly::of(self), name);
    }
}

// go: sdk 1.25.5 testing/fstest/mapfs.go:216-216 fsOnly
/// A wrapper that hides all but the `fs.FS` methods, so that a method
/// implemented in terms of the `fs` helpers cannot recurse back into
/// itself through those helpers' fast-path type assertions.
///
/// This is not optional decoration. `MapFS::ReadFile` is written as
/// `fs::ReadFile(…)`, and `fs::ReadFile` asks whether its argument is a
/// `ReadFileFS`. Handed the `MapFS` itself, the answer is yes and the
/// call comes straight back here, forever. Go's `fsOnly` struct embeds
/// only `fs.FS`, so the assertion misses; goish's holds the filesystem
/// as a plain field and implements exactly one trait, which misses for
/// the same reason.
///
/// Go's wrapper copies a map header. goish's `map` is a real table, so
/// this clones it — keys plus `Arc` pointers, on a path Go's own
/// comment describes as existing to exercise more code paths in tests
/// rather than because it is needed.
struct fsOnly(MapFS);

impl fsOnly {
    // go: none — goish idiom: Go writes the wrapper inline as
    //     `fsOnly{fsys}`; a Rust tuple struct over a borrowed receiver
    //     needs the clone spelled somewhere, so it is spelled once here.
    fn of(fsys: &MapFS) -> fsOnly {
        return fsOnly(fsys.clone());
    }
}

impl fs::FS for fsOnly {
    // go: none — goish idiom: Go embeds `fs.FS`, which promotes `Open`.
    //     Rust has no embedding, so the forward is written out.
    fn Open(&self, name: string) -> (Arc<dyn File + Send + Sync>, error) {
        return MapFS::Open(&self.0, name);
    }
    // go: none — goish idiom: the hidden Any-view hook every
    //     `#[goish::interface]` concrete impl overrides. Deliberately
    //     the ONLY interface `fsOnly` answers to.
    // go: none — goish idiom: the hidden Any-view hook every
    //     `#[goish::interface]` concrete impl overrides so a type
    //     assertion can reach this type. Go's itabs make it
    //     unnecessary.
    fn __goish_as_dyn_any(&self) -> Option<&(dyn core::any::Any + Send + Sync)> {
        return Some(self);
    }
}

// go: sdk 1.25.5 testing/fstest/mapfs.go:234-236 noSub
/// `fsOnly`'s twin for `Sub`. Go gives it a `Sub()` method with a
/// deliberately wrong signature so that `fs.Sub` cannot see a `SubFS`;
/// goish just does not implement `SubFS` for it, which is the same
/// statement without the trick.
struct noSub(Arc<MapFS>);

impl fs::FS for noSub {
    // go: none — goish idiom: see `fsOnly`'s `Open`.
    fn Open(&self, name: string) -> (Arc<dyn File + Send + Sync>, error) {
        return MapFS::Open(&self.0, name);
    }
    // go: none — goish idiom: see `fsOnly`'s hook.
    // go: none — goish idiom: the hidden Any-view hook every
    //     `#[goish::interface]` concrete impl overrides so a type
    //     assertion can reach this type. Go's itabs make it
    //     unnecessary.
    fn __goish_as_dyn_any(&self) -> Option<&(dyn core::any::Any + Send + Sync)> {
        return Some(self);
    }
}

// Go: var _ fs.FS = MapFS(nil)
impl fs::FS for MapFS {
    // go: sdk 1.25.5 testing/fstest/mapfs.go:48-120 MapFS.Open
    fn Open(&self, name: string) -> (Arc<dyn File + Send + Sync>, error) {
        return MapFS::Open(self, name);
    }
    // go: none — goish idiom: the hidden Any-view hook every
    //     `#[goish::interface]` concrete impl overrides so a type
    //     assertion can reach this type. Go's itabs make it
    //     unnecessary.
    fn __goish_as_dyn_any(&self) -> Option<&(dyn core::any::Any + Send + Sync)> {
        return Some(self);
    }
}

// go: none — goish idiom: Go writes `&fs.PathError{Op: "open", Path:
//     name, Err: fs.ErrNotExist}` inline at each of the several places
//     that need it. Named once here.
fn open_not_exist(name: &string) -> error {
    return path_err("open", name, fs::ErrNotExist.clone().into());
}

// go: none — goish idiom: the `&fs.PathError{...}` composite literal
//     Go writes inline, spelled once. goish's `error` is a handle, so
//     the wrap is a call rather than a `&`.
fn path_err(op: &'static str, name: &string, err: error) -> error {
    // Go: &fs.PathError{Op: op, Path: name, Err: err}
    return errors::Wrap(fs::PathError {
        Op: string::from_static(op),
        Path: name.clone(),
        Err: err,
    });
}

// go: none — goish idiom: Go writes `&MapFile{Mode: fs.ModeDir | 0555}`
//     inline where a parent directory has to be synthesized. Named once
//     here because goish needs the `Arc` as well.
fn synth_dir() -> Arc<MapFile> {
    return Arc::new(MapFile {
        Data: slice::new(),
        Mode: FileMode(ModeDir.0 | 0o555),
        ModTime: time::Time::default(),
        Sys: None,
    });
}

// go: sdk 1.25.5 testing/fstest/mapfs.go:218-220 MapFS.ReadFile
/// Register the fstest `#[goish::interface]` impls in the per-trait
/// downcast registries. Idempotent; called from `Open` / `Lstat`.
/// Deliberately does NOT register MapFS for ReadDirFS / StatFS /
/// ReadFileFS (Go's `fsOnly` semantics — see module header).
impl fs::ReadFileFS for MapFS {
    // go: none — goish idiom: `#[goish::interface]` does not model Go's
    //     interface embedding, so every composite interface re-declares
    //     the inherited method and the concrete type forwards it.
    fn Open(&self, name: string) -> (Arc<dyn File + Send + Sync>, error) {
        return MapFS::Open(self, name);
    }
    // go: none — goish idiom: Go's `MapFS` satisfies `fs.ReadFileFS`
    //     structurally, by having the method. goish needs the impl
    //     written out and the type registered, or the assertion inside
    //     `fs::ReadFile` is a SILENT miss and every caller quietly takes
    //     the generic Open-based path instead.
    fn ReadFile(&self, name: string) -> (slice<byte>, error) {
        return MapFS::ReadFile(self, name);
    }
    // go: none — goish idiom: the hidden Any-view hook every
    //     `#[goish::interface]` concrete impl overrides.
    // go: none — goish idiom: the hidden Any-view hook every
    //     `#[goish::interface]` concrete impl overrides so a type
    //     assertion can reach this type. Go's itabs make it
    //     unnecessary.
    fn __goish_as_dyn_any(&self) -> Option<&(dyn core::any::Any + Send + Sync)> {
        return Some(self);
    }
}

// go: sdk 1.25.5 testing/fstest/mapfs.go:222-224 MapFS.Stat
impl fs::StatFS for MapFS {
    // go: none — goish idiom: see `ReadFileFS::Open`.
    fn Open(&self, name: string) -> (Arc<dyn File + Send + Sync>, error) {
        return MapFS::Open(self, name);
    }
    // go: none — goish idiom: see `ReadFileFS::ReadFile`.
    fn Stat(&self, name: string) -> (Arc<dyn FileInfo + Send + Sync>, error) {
        return MapFS::Stat(self, name);
    }
    // go: none — goish idiom: the hidden Any-view hook.
    // go: none — goish idiom: the hidden Any-view hook every
    //     `#[goish::interface]` concrete impl overrides so a type
    //     assertion can reach this type. Go's itabs make it
    //     unnecessary.
    fn __goish_as_dyn_any(&self) -> Option<&(dyn core::any::Any + Send + Sync)> {
        return Some(self);
    }
}

// go: sdk 1.25.5 testing/fstest/mapfs.go:226-228 MapFS.ReadDir
impl fs::ReadDirFS for MapFS {
    // go: none — goish idiom: see `ReadFileFS::Open`.
    fn Open(&self, name: string) -> (Arc<dyn File + Send + Sync>, error) {
        return MapFS::Open(self, name);
    }
    // go: none — goish idiom: see `ReadFileFS::ReadFile`.
    fn ReadDir(&self, name: string) -> (slice<Arc<dyn DirEntry + Send + Sync>>, error) {
        return MapFS::ReadDir(self, name);
    }
    // go: none — goish idiom: the hidden Any-view hook.
    // go: none — goish idiom: the hidden Any-view hook every
    //     `#[goish::interface]` concrete impl overrides so a type
    //     assertion can reach this type. Go's itabs make it
    //     unnecessary.
    fn __goish_as_dyn_any(&self) -> Option<&(dyn core::any::Any + Send + Sync)> {
        return Some(self);
    }
}

// go: sdk 1.25.5 testing/fstest/mapfs.go:230-232 MapFS.Glob
impl fs::GlobFS for MapFS {
    // go: none — goish idiom: see `ReadFileFS::Open`.
    fn Open(&self, name: string) -> (Arc<dyn File + Send + Sync>, error) {
        return MapFS::Open(self, name);
    }
    // go: none — goish idiom: see `ReadFileFS::ReadFile`.
    fn Glob(&self, pattern: string) -> (slice<string>, error) {
        return MapFS::Glob(self, pattern);
    }
    // go: none — goish idiom: the hidden Any-view hook.
    // go: none — goish idiom: the hidden Any-view hook every
    //     `#[goish::interface]` concrete impl overrides so a type
    //     assertion can reach this type. Go's itabs make it
    //     unnecessary.
    fn __goish_as_dyn_any(&self) -> Option<&(dyn core::any::Any + Send + Sync)> {
        return Some(self);
    }
}

// go: sdk 1.25.5 testing/fstest/mapfs.go:156-168 MapFS.ReadLink
impl fs::ReadLinkFS for MapFS {
    // go: none — goish idiom: see `ReadFileFS::Open`.
    fn Open(&self, name: string) -> (Arc<dyn File + Send + Sync>, error) {
        return MapFS::Open(self, name);
    }
    // go: none — goish idiom: see `ReadFileFS::ReadFile`. Until io/fs
    //     grew `ReadLinkFS`, these two were inherent methods that
    //     nothing holding an `fs.FS` could reach at all.
    fn ReadLink(&self, name: string) -> (string, error) {
        return MapFS::ReadLink(self, name);
    }
    // go: sdk 1.25.5 testing/fstest/mapfs.go:170-176 MapFS.Lstat
    fn Lstat(&self, name: string) -> (Arc<dyn FileInfo + Send + Sync>, error) {
        return MapFS::Lstat(self, name);
    }
    // go: none — goish idiom: the hidden Any-view hook.
    // go: none — goish idiom: the hidden Any-view hook every
    //     `#[goish::interface]` concrete impl overrides so a type
    //     assertion can reach this type. Go's itabs make it
    //     unnecessary.
    fn __goish_as_dyn_any(&self) -> Option<&(dyn core::any::Any + Send + Sync)> {
        return Some(self);
    }
}

// go: none — goish idiom: fill the `#[goish::interface]` downcast
//     registries for the types this package declares. Go's linker
//     builds the equivalent itabs. See AGENTS.md §9b.
pub fn register_fstest_impls() {
    fs::__goish_register_FS_impl::<MapFS>();
    fs::__goish_register_ReadFileFS_impl::<MapFS>();
    fs::__goish_register_StatFS_impl::<MapFS>();
    fs::__goish_register_ReadDirFS_impl::<MapFS>();
    fs::__goish_register_GlobFS_impl::<MapFS>();
    fs::__goish_register_ReadLinkFS_impl::<MapFS>();
    fs::__goish_register_FS_impl::<fsOnly>();
    fs::__goish_register_FS_impl::<noSub>();
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
pub(super) struct mapFileInfo {
    pub(super) name: string,
    pub(super) f: Arc<MapFile>,
}

impl FileInfo for mapFileInfo {
    // go: sdk 1.25.5 testing/fstest/mapfs.go:250-250 mapFileInfo.Name
    // Go: func (i *mapFileInfo) Name() string { return path.Base(i.name) }
    fn Name(&self) -> string {
        return path::Base(self.name.clone());
    }
    // go: sdk 1.25.5 testing/fstest/mapfs.go:251-251 mapFileInfo.Size
    // Go: func (i *mapFileInfo) Size() int64 { return int64(len(i.f.Data)) }
    fn Size(&self) -> int {
        return toint(self.f.Data.as_ref().len());
    }
    // go: sdk 1.25.5 testing/fstest/mapfs.go:252-252 mapFileInfo.Mode
    // Go: func (i *mapFileInfo) Mode() fs.FileMode { return i.f.Mode }
    fn Mode(&self) -> FileMode {
        return self.f.Mode;
    }
    // go: sdk 1.25.5 testing/fstest/mapfs.go:254-254 mapFileInfo.ModTime
    // Go: func (i *mapFileInfo) ModTime() time.Time { return i.f.ModTime }
    fn ModTime(&self) -> time::Time {
        return self.f.ModTime;
    }
    // go: sdk 1.25.5 testing/fstest/mapfs.go:255-255 mapFileInfo.IsDir
    // Go: func (i *mapFileInfo) IsDir() bool { return i.f.Mode&fs.ModeDir != 0 }
    fn IsDir(&self) -> bool {
        return self.f.Mode.0 & ModeDir.0 != 0;
    }
    // go: sdk 1.25.5 testing/fstest/mapfs.go:256-256 mapFileInfo.Sys
    // Go: func (i *mapFileInfo) Sys() any { return i.f.Sys }
    fn Sys(&self) -> Arc<dyn core::any::Any + Send + Sync> {
        return match &self.f.Sys {
            Some(s) => s.clone(),
            None => Arc::new(()),
        };
    }
    // go: none — goish idiom: the hidden Any-view hook every
    //     `#[goish::interface]` concrete impl overrides so a type
    //     assertion can reach this type. Go's itabs make it
    //     unnecessary.
    fn __goish_as_dyn_any(&self) -> Option<&(dyn core::any::Any + Send + Sync)> {
        return Some(self);
    }
}

impl DirEntry for mapFileInfo {
    // go: sdk 1.25.5 testing/fstest/mapfs.go:250-250 mapFileInfo.Name
    fn Name(&self) -> string {
        return path::Base(self.name.clone());
    }
    // go: sdk 1.25.5 testing/fstest/mapfs.go:255-255 mapFileInfo.IsDir
    fn IsDir(&self) -> bool {
        return self.f.Mode.0 & ModeDir.0 != 0;
    }
    // go: sdk 1.25.5 testing/fstest/mapfs.go:253-253 mapFileInfo.Type
    // Go: func (i *mapFileInfo) Type() fs.FileMode { return i.f.Mode.Type() }
    fn Type(&self) -> FileMode {
        return self.f.Mode.Type();
    }
    // go: sdk 1.25.5 testing/fstest/mapfs.go:257-257 mapFileInfo.Info
    // Go: func (i *mapFileInfo) Info() (fs.FileInfo, error) { return i, nil }
    fn Info(&self) -> (Arc<dyn FileInfo + Send + Sync>, error) {
        return (Arc::new(self.clone()), errors::nil);
    }
    // go: none — goish idiom: the hidden Any-view hook every
    //     `#[goish::interface]` concrete impl overrides so a type
    //     assertion can reach this type. Go's itabs make it
    //     unnecessary.
    fn __goish_as_dyn_any(&self) -> Option<&(dyn core::any::Any + Send + Sync)> {
        return Some(self);
    }
}

// Go: mapfs.go:270 — type openMapFile struct
/// An openMapFile is a regular (non-directory) fs.File open for
/// reading. (`offset` is atomic — Go mutates through the `*File`;
/// goish `File` methods take `&self`.)
#[allow(non_camel_case_types)]
pub(super) struct openMapFile {
    path: string,
    info: mapFileInfo,
    offset: AtomicI64,
}

impl File for openMapFile {
    // go: sdk 1.25.5 testing/fstest/mapfs.go:270-270 openMapFile.Stat
    // Go: func (f *openMapFile) Stat() (fs.FileInfo, error) { return &f.mapFileInfo, nil }
    fn Stat(&self) -> (Arc<dyn FileInfo + Send + Sync>, error) {
        return (Arc::new(self.info.clone()), errors::nil);
    }
    // go: sdk 1.25.5 testing/fstest/mapfs.go:274-284 openMapFile.Read
    // Go: mapfs.go:280 — func (f *openMapFile) Read(b []byte) (int, error)
    fn Read(&self, b: &mut slice<byte>) -> (int, error) {
        let data = self.info.f.Data.as_ref();
        let offset = self.offset.load(Ordering::Acquire);
        if offset >= toint64(data.len()) {
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
        self.offset.store(offset + toint64(n), Ordering::Release);
        return (toint(n), errors::nil);
    }
    // go: sdk 1.25.5 testing/fstest/mapfs.go:272-272 openMapFile.Close
    // Go: func (f *openMapFile) Close() error { return nil }
    fn Close(&self) -> error {
        return errors::nil;
    }
    // go: none — goish idiom: the hidden Any-view hook every
    //     `#[goish::interface]` concrete impl overrides so a type
    //     assertion can reach this type. Go's itabs make it
    //     unnecessary.
    fn __goish_as_dyn_any(&self) -> Option<&(dyn core::any::Any + Send + Sync)> {
        return Some(self);
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
    // go: none — goish idiom: the hidden Any-view hook every
    //     `#[goish::interface]` concrete impl overrides so a type
    //     assertion can reach this type. Go's itabs make it
    //     unnecessary.
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
pub(super) struct mapDir {
    path: string,
    info: mapFileInfo,
    entry: Vec<mapFileInfo>,
    offset: AtomicUsize,
}

impl mapDir {
    // go: sdk 1.25.5 testing/fstest/mapfs.go:327-341 mapDir.ReadDir
    pub(super) fn read_dir(&self, count: int) -> (slice<Arc<dyn DirEntry + Send + Sync>>, error) {
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
        return (slice::__from_vec(list), errors::nil);
    }
}

impl File for mapDir {
    // go: sdk 1.25.5 testing/fstest/mapfs.go:321-321 mapDir.Stat
    fn Stat(&self) -> (Arc<dyn FileInfo + Send + Sync>, error) {
        return (Arc::new(self.info.clone()), errors::nil);
    }
    // go: sdk 1.25.5 testing/fstest/mapfs.go:323-325 mapDir.Read
    // Go: func (d *mapDir) Read(b []byte) (int, error) — always ErrInvalid
    fn Read(&self, _b: &mut slice<byte>) -> (int, error) {
        return (
            0,
            path_err("read", &self.path, fs::ErrInvalid.clone().into()),
        );
    }
    // go: sdk 1.25.5 testing/fstest/mapfs.go:322-322 mapDir.Close
    fn Close(&self) -> error {
        return errors::nil;
    }
    // go: none — goish idiom: the hidden Any-view hook every
    //     `#[goish::interface]` concrete impl overrides so a type
    //     assertion can reach this type. Go's itabs make it
    //     unnecessary.
    fn __goish_as_dyn_any(&self) -> Option<&(dyn core::any::Any + Send + Sync)> {
        return Some(self);
    }
}

impl ReadDirFile for mapDir {
    // go: sdk 1.25.5 testing/fstest/mapfs.go:321-321 mapDir.Stat
    fn Stat(&self) -> (Arc<dyn FileInfo + Send + Sync>, error) {
        return File::Stat(self);
    }
    // go: sdk 1.25.5 testing/fstest/mapfs.go:323-325 mapDir.Read
    fn Read(&self, b: &mut slice<byte>) -> (int, error) {
        return File::Read(self, b);
    }
    // go: sdk 1.25.5 testing/fstest/mapfs.go:322-322 mapDir.Close
    fn Close(&self) -> error {
        return File::Close(self);
    }
    // go: sdk 1.25.5 testing/fstest/mapfs.go:327-341 mapDir.ReadDir
    fn ReadDir(&self, n: int) -> (slice<Arc<dyn DirEntry + Send + Sync>>, error) {
        return self.read_dir(n);
    }
    // go: none — goish idiom: the hidden Any-view hook every
    //     `#[goish::interface]` concrete impl overrides so a type
    //     assertion can reach this type. Go's itabs make it
    //     unnecessary.
    fn __goish_as_dyn_any(&self) -> Option<&(dyn core::any::Any + Send + Sync)> {
        return Some(self);
    }
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
    /// Same shape as `Glob` above, and load-bearing for the same
    /// reason: `fs::Sub` asserts `SubFS`, so the receiver has to reach
    /// it wearing something that is not one.
    pub fn Sub<S: Into<string>>(
        self: &Arc<Self>,
        dir: S,
    ) -> (Arc<dyn fs::FS + Send + Sync>, error) {
        let me: Arc<dyn fs::FS + Send + Sync> = Arc::new(noSub(self.clone()));
        return crate::io::fs::Sub(me, dir.into());
    }
}

impl MapFS {
    // go: sdk 1.25.5 testing/fstest/mapfs.go:230-232 MapFS.Glob
    /// Go: `return fs.Glob(fsOnly{fsys}, pattern)`.
    ///
    /// The wrapper is load-bearing now that `fs::Glob` asserts `GlobFS`:
    /// without it this calls `fs::Glob`, which finds a `GlobFS` and
    /// calls this, forever.
    pub fn Glob<S: Into<string>>(&self, pattern: S) -> (slice<string>, error) {
        return crate::io::fs::Glob(&fsOnly::of(self), pattern.into());
    }
}
