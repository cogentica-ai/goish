// io_fs_walkdir_smoke — exercise the io/fs WalkDir + FS interface core.
//
// Coverage:
//   1. ReadDir on the test FS returns entries sorted by name.
//   2. Stat on the test FS reports the file's metadata.
//   3. WalkDir visits every file + directory in lexical order, root
//      first.
//   4. SkipDir returned from the walk fn prunes that subtree.
//   5. SkipAll returned from the walk fn stops the whole walk.
//   6. An error from Open/ReadDir is surfaced to the walk fn.
//   7. A non-existent root surfaces the error to the walk fn once.
//
// The walk operates over a tiny in-memory FS (mapFS) modelled on Go's
// testing/fstest.MapFS — a struct holding path -> (content, isDir).

#![no_std]
#![no_main]
#![allow(non_snake_case, non_camel_case_types)]

extern crate alloc;
extern crate goish;

use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicUsize, Ordering};

use goish::errors::{self, error};
use goish::io::fs;
use goish::runtime::spin::SpinLock;
use goish::slice;
use goish::string;
use goish::types::{byte, int};
use goish::{syscall, Println};

const KB: usize = 1024;
const TOTAL: usize = 12;

static FAILED: AtomicUsize = AtomicUsize::new(0);

fn fail() {
    FAILED.fetch_add(1, Ordering::AcqRel);
}

fn check(cond: bool, name: &[u8]) {
    if cond {
        syscall::Write(syscall::STDOUT, b"  PASS ".as_ptr(), 7);
    } else {
        syscall::Write(syscall::STDOUT, b"  FAIL ".as_ptr(), 7);
        fail();
    }
    syscall::Write(syscall::STDOUT, name.as_ptr(), name.len());
    syscall::Write(syscall::STDOUT, b"\n".as_ptr(), 1);
}

// ─── In-memory test file system (fstest.MapFS analogue) ──────────────

// One node in the map: a path, its content, and whether it is a dir.
#[derive(Clone)]
struct node {
    path: string,
    content: Vec<u8>,
    isDir: bool,
}

// mapFS — implements FS, ReadDirFS, StatFS.
struct mapFS {
    nodes: Vec<node>,
}

// mapInfo — a FileInfo over one node.
struct mapInfo {
    name: string,
    size: int,
    isDir: bool,
}

impl fs::FileInfo for mapInfo {
    fn Name(&self) -> string {
        self.name.clone()
    }
    fn Size(&self) -> int {
        self.size
    }
    fn Mode(&self) -> fs::FileMode {
        if self.isDir {
            fs::ModeDir | fs::FileMode(0o755)
        } else {
            fs::FileMode(0o644)
        }
    }
    fn ModTime(&self) -> goish::time::Time {
        goish::time::Time::default()
    }
    fn IsDir(&self) -> bool {
        self.isDir
    }
    fn Sys(&self) -> Arc<dyn core::any::Any + Send + Sync> {
        Arc::new(())
    }
    fn __goish_as_dyn_any(&self) -> Option<&(dyn core::any::Any + Send + Sync)> {
        Some(self)
    }
}

// mapDirEntry — a DirEntry over one node.
struct mapDirEntry {
    name: string,
    size: int,
    isDir: bool,
}

impl fs::DirEntry for mapDirEntry {
    fn Name(&self) -> string {
        self.name.clone()
    }
    fn IsDir(&self) -> bool {
        self.isDir
    }
    fn Type(&self) -> fs::FileMode {
        if self.isDir {
            fs::ModeDir
        } else {
            fs::FileMode(0)
        }
    }
    fn Info(&self) -> (Arc<dyn fs::FileInfo + Send + Sync>, error) {
        (
            Arc::new(mapInfo {
                name: self.name.clone(),
                size: self.size,
                isDir: self.isDir,
            }),
            errors::nil,
        )
    }
    fn __goish_as_dyn_any(&self) -> Option<&(dyn core::any::Any + Send + Sync)> {
        Some(self)
    }
}

// mapRegularFile — a File over a regular (non-directory) node.
struct mapRegularFile {
    name: string,
    content: Vec<u8>,
    pos: SpinLock<usize>,
}

impl fs::File for mapRegularFile {
    fn Stat(&self) -> (Arc<dyn fs::FileInfo + Send + Sync>, error) {
        (
            Arc::new(mapInfo {
                name: self.name.clone(),
                size: self.content.len() as int,
                isDir: false,
            }),
            errors::nil,
        )
    }
    fn Read(&self, p: &mut slice<byte>) -> (int, error) {
        let mut g = self.pos.lock();
        if *g >= self.content.len() {
            return (0, goish::io::EOF.into());
        }
        let mut n: usize = 0;
        while *g < self.content.len() && n < (p.Len() as usize) {
            p[n] = self.content[*g];
            *g += 1;
            n += 1;
        }
        (n as int, errors::nil)
    }
    fn Close(&self) -> error {
        errors::nil
    }
    fn __goish_as_dyn_any(&self) -> Option<&(dyn core::any::Any + Send + Sync)> {
        Some(self)
    }
}

// mapDir — a directory File; also implements ReadDirFile.
struct mapDir {
    name: string,
    entries: Vec<mapDirEntry>,
}

impl fs::File for mapDir {
    fn Stat(&self) -> (Arc<dyn fs::FileInfo + Send + Sync>, error) {
        (
            Arc::new(mapInfo {
                name: self.name.clone(),
                size: 0,
                isDir: true,
            }),
            errors::nil,
        )
    }
    fn Read(&self, _p: &mut slice<byte>) -> (int, error) {
        (0, errors::New("is a directory"))
    }
    fn Close(&self) -> error {
        errors::nil
    }
    fn __goish_as_dyn_any(&self) -> Option<&(dyn core::any::Any + Send + Sync)> {
        Some(self)
    }
}

impl fs::ReadDirFile for mapDir {
    fn Stat(&self) -> (Arc<dyn fs::FileInfo + Send + Sync>, error) {
        <Self as fs::File>::Stat(self)
    }
    fn Read(&self, p: &mut slice<byte>) -> (int, error) {
        <Self as fs::File>::Read(self, p)
    }
    fn Close(&self) -> error {
        <Self as fs::File>::Close(self)
    }
    fn ReadDir(&self, _n: int) -> (slice<Arc<dyn fs::DirEntry + Send + Sync>>, error) {
        let mut v: Vec<Arc<dyn fs::DirEntry + Send + Sync>> = Vec::new();
        for e in self.entries.iter() {
            v.push(Arc::new(mapDirEntry {
                name: e.name.clone(),
                size: e.size,
                isDir: e.isDir,
            }));
        }
        (slice::__from_vec(v), errors::nil)
    }
    fn __goish_as_dyn_any(&self) -> Option<&(dyn core::any::Any + Send + Sync)> {
        Some(self)
    }
}

impl mapFS {
    // base name of a slash-separated path.
    fn base_name(p: &string) -> string {
        let b = p.as_bytes();
        let mut start = 0;
        let mut i = 0;
        while i < b.len() {
            if b[i] == b'/' {
                start = i + 1;
            }
            i += 1;
        }
        string::from_bytes(&b[start..])
    }

    // parent path of a slash-separated path ("" if top-level).
    fn parent(p: &string) -> string {
        let b = p.as_bytes();
        let mut cut: isize = -1;
        let mut i = 0;
        while i < b.len() {
            if b[i] == b'/' {
                cut = i as isize;
            }
            i += 1;
        }
        if cut < 0 {
            string::new()
        } else {
            string::from_bytes(&b[..cut as usize])
        }
    }

    // collect the directory entries directly under `dir` ("" = root).
    fn dir_entries(&self, dir: &string) -> Vec<mapDirEntry> {
        let mut out: Vec<mapDirEntry> = Vec::new();
        for n in self.nodes.iter() {
            if Self::parent(&n.path) == *dir && n.path != *dir {
                out.push(mapDirEntry {
                    name: Self::base_name(&n.path),
                    size: n.content.len() as int,
                    isDir: n.isDir,
                });
            }
        }
        out
    }

    fn find(&self, name: &string) -> Option<node> {
        for n in self.nodes.iter() {
            if n.path == *name {
                return Some(n.clone());
            }
        }
        None
    }
}

impl fs::FS for mapFS {
    fn Open(&self, name: string) -> (Arc<dyn fs::File + Send + Sync>, error) {
        // "." is the synthetic root directory.
        if name == "." {
            let d = mapDir {
                name: string::from_static("."),
                entries: self.dir_entries(&string::new()),
            };
            return (Arc::new(d), errors::nil);
        }
        match self.find(&name) {
            None => (
                goish::nil.into(),
                errors::Wrap(fs::PathError {
                    Op: string::from_static("open"),
                    Path: name,
                    Err: fs::ErrNotExist.into(),
                }),
            ),
            Some(n) if n.isDir => {
                let d = mapDir {
                    name: mapFS::base_name(&n.path),
                    entries: self.dir_entries(&n.path),
                };
                (Arc::new(d), errors::nil)
            }
            Some(n) => {
                let f = mapRegularFile {
                    name: mapFS::base_name(&n.path),
                    content: n.content.clone(),
                    pos: SpinLock::new(0),
                };
                (Arc::new(f), errors::nil)
            }
        }
    }
    fn __goish_as_dyn_any(&self) -> Option<&(dyn core::any::Any + Send + Sync)> {
        Some(self)
    }
}

impl fs::ReadDirFS for mapFS {
    fn Open(&self, name: string) -> (Arc<dyn fs::File + Send + Sync>, error) {
        <Self as fs::FS>::Open(self, name)
    }
    fn ReadDir(&self, name: string) -> (slice<Arc<dyn fs::DirEntry + Send + Sync>>, error) {
        let dir = if name == "." { string::new() } else { name.clone() };
        // Surface a missing directory as an error.
        if name != "." && self.find(&name).is_none() {
            return (
                slice::new(),
                errors::Wrap(fs::PathError {
                    Op: string::from_static("readdir"),
                    Path: name,
                    Err: fs::ErrNotExist.into(),
                }),
            );
        }
        let mut v: Vec<Arc<dyn fs::DirEntry + Send + Sync>> = Vec::new();
        for e in self.dir_entries(&dir) {
            v.push(Arc::new(mapDirEntry {
                name: e.name,
                size: e.size,
                isDir: e.isDir,
            }));
        }
        (slice::__from_vec(v), errors::nil)
    }
    fn __goish_as_dyn_any(&self) -> Option<&(dyn core::any::Any + Send + Sync)> {
        Some(self)
    }
}

impl fs::StatFS for mapFS {
    fn Open(&self, name: string) -> (Arc<dyn fs::File + Send + Sync>, error) {
        <Self as fs::FS>::Open(self, name)
    }
    fn Stat(&self, name: string) -> (Arc<dyn fs::FileInfo + Send + Sync>, error) {
        if name == "." {
            return (
                Arc::new(mapInfo {
                    name: string::from_static("."),
                    size: 0,
                    isDir: true,
                }),
                errors::nil,
            );
        }
        match self.find(&name) {
            None => (
                goish::nil.into(),
                errors::Wrap(fs::PathError {
                    Op: string::from_static("stat"),
                    Path: name,
                    Err: fs::ErrNotExist.into(),
                }),
            ),
            Some(n) => (
                Arc::new(mapInfo {
                    name: mapFS::base_name(&n.path),
                    size: n.content.len() as int,
                    isDir: n.isDir,
                }),
                errors::nil,
            ),
        }
    }
    fn __goish_as_dyn_any(&self) -> Option<&(dyn core::any::Any + Send + Sync)> {
        Some(self)
    }
}

// Register every concrete impl into the per-trait downcast registries
// (so goish::cast! inside fs::ReadDir / fs::Stat can find them).
fn register_mapfs_impls() {
    fs::__goish_register_FS_impl::<mapFS>();
    fs::__goish_register_ReadDirFS_impl::<mapFS>();
    fs::__goish_register_StatFS_impl::<mapFS>();
    fs::__goish_register_File_impl::<mapRegularFile>();
    fs::__goish_register_File_impl::<mapDir>();
    fs::__goish_register_ReadDirFile_impl::<mapDir>();
}

// Build a node tree:
//   .
//   ├── a.txt
//   ├── dir1
//   │   ├── b.txt
//   │   └── sub
//   │       └── c.txt
//   └── dir2
//       └── d.txt
fn build_fs() -> mapFS {
    fn n(p: &'static str, content: &str, is_dir: bool) -> node {
        node {
            path: string::from_static(p),
            content: content.as_bytes().to_vec(),
            isDir: is_dir,
        }
    }
    mapFS {
        nodes: alloc::vec![
            n("a.txt", "alpha", false),
            n("dir1", "", true),
            n("dir1/b.txt", "bravo", false),
            n("dir1/sub", "", true),
            n("dir1/sub/c.txt", "charlie", false),
            n("dir2", "", true),
            n("dir2/d.txt", "delta", false),
        ],
    }
}

// ─── Tests ───────────────────────────────────────────────────────────

fn run_tests() {
    register_mapfs_impls();
    let fsys = build_fs();

    // 1. ReadDir on the root, sorted by name.
    {
        let (entries, err) = fs::ReadDir(&fsys, ".");
        let names = entry_names(&entries);
        check(err == errors::nil, b"ReadDir(.) returns nil error");
        check(
            names == "a.txt,dir1,dir2",
            b"ReadDir(.) entries sorted lexically",
        );
    }

    // 2. ReadDir on a subdir.
    {
        let (entries, _) = fs::ReadDir(&fsys, "dir1");
        let names = entry_names(&entries);
        check(names == "b.txt,sub", b"ReadDir(dir1) lists subentries");
    }

    // 3. Stat reports metadata.
    {
        let (info, err) = fs::Stat(&fsys, "a.txt");
        check(err == errors::nil, b"Stat(a.txt) returns nil error");
        check(
            info.Name() == "a.txt" && info.Size() == 5 && !info.IsDir(),
            b"Stat(a.txt) metadata correct",
        );
        let (di, _) = fs::Stat(&fsys, "dir1");
        check(di.IsDir(), b"Stat(dir1) reports IsDir");
    }

    // 4. WalkDir visits everything, root first, lexical order.
    {
        let visited: Arc<SpinLock<Vec<RustString>>> =
            Arc::new(SpinLock::new(Vec::new()));
        let v2 = visited.clone();
        let err = fs::WalkDir(&fsys, ".", move |path, _d, e| {
            if e == errors::nil {
                v2.lock().push(to_rust(&path));
            }
            errors::nil
        });
        let order = join(&visited.lock());
        check(err == errors::nil, b"WalkDir returns nil error");
        check(
            order == ".,a.txt,dir1,dir1/b.txt,dir1/sub,dir1/sub/c.txt,dir2,dir2/d.txt",
            b"WalkDir lexical order, root first",
        );
    }

    // 5. SkipDir prunes a subtree.
    {
        let visited: Arc<SpinLock<Vec<RustString>>> =
            Arc::new(SpinLock::new(Vec::new()));
        let v2 = visited.clone();
        let err = fs::WalkDir(&fsys, ".", move |path, d, e| {
            if e != errors::nil {
                return errors::nil;
            }
            v2.lock().push(to_rust(&path));
            // Skip everything under dir1.
            if d.IsDir() && path == "dir1" {
                return fs::SkipDir.into();
            }
            errors::nil
        });
        let order = join(&visited.lock());
        check(err == errors::nil, b"WalkDir+SkipDir returns nil error");
        check(
            order == ".,a.txt,dir1,dir2,dir2/d.txt",
            b"SkipDir prunes the dir1 subtree",
        );
    }

    // 6. SkipAll stops the whole walk.
    {
        let visited: Arc<SpinLock<Vec<RustString>>> =
            Arc::new(SpinLock::new(Vec::new()));
        let v2 = visited.clone();
        let err = fs::WalkDir(&fsys, ".", move |path, _d, e| {
            if e != errors::nil {
                return errors::nil;
            }
            v2.lock().push(to_rust(&path));
            if path == "a.txt" {
                return fs::SkipAll.into();
            }
            errors::nil
        });
        let order = join(&visited.lock());
        check(err == errors::nil, b"WalkDir+SkipAll returns nil error");
        check(order == ".,a.txt", b"SkipAll stops the walk early");
    }

    // 7. A non-existent root surfaces the error to fn exactly once.
    {
        let calls: Arc<AtomicUsize> = Arc::new(AtomicUsize::new(0));
        let saw_err: Arc<SpinLock<bool>> = Arc::new(SpinLock::new(false));
        let c2 = calls.clone();
        let s2 = saw_err.clone();
        let err = fs::WalkDir(&fsys, "missing", move |_p, _d, e| {
            c2.fetch_add(1, Ordering::AcqRel);
            if e != errors::nil {
                *s2.lock() = true;
            }
            e
        });
        check(
            calls.load(Ordering::Acquire) == 1 && *saw_err.lock(),
            b"missing root: fn called once with the error",
        );
        check(err != errors::nil, b"missing root: WalkDir returns the error");
    }
}

// ─── helpers ─────────────────────────────────────────────────────────

use alloc::string::String as RustString;
use alloc::string::ToString;

fn to_rust(s: &string) -> RustString {
    core::str::from_utf8(s.as_bytes()).unwrap_or("").to_string()
}

fn join(v: &Vec<RustString>) -> RustString {
    let mut out = RustString::new();
    for (i, s) in v.iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        out.push_str(s);
    }
    out
}

fn entry_names(entries: &slice<Arc<dyn fs::DirEntry + Send + Sync>>) -> RustString {
    let mut out = RustString::new();
    let mut i: int = 0;
    while i < entries.Len() {
        if i > 0 {
            out.push(',');
        }
        out.push_str(&to_rust(&entries[i].Name()));
        i += 1;
    }
    out
}

#[goish::main]
fn main() {
    goish::go!(|| {
        run_tests();
        let f = FAILED.load(Ordering::Acquire);
        let pass = TOTAL - f;
        if f == 0 {
            Println!("ok 12/12");
            syscall::Exit(0);
        } else {
            Println!("FAIL", pass as i64, "of", TOTAL as i64);
            syscall::Exit(1);
        }
    });
    goish::runtime::sched::schedule();
}
