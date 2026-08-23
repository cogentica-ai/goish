// embed — access to files embedded in the running program, ported
// from Go's embed package (go1.25.5 src/embed/embed.go).
//
// Go's `//go:embed` compiler directive becomes the `goish::embed!`
// proc-macro (goish-macros). The declaration mirrors the Go source
// shape — an attribute naming the patterns above each variable:
//
//   //go:embed hello.txt              goish::embed! {
//   var s string                          #[embed("hello.txt")]
//                                         static s: string;
//   //go:embed image/* html/index.html
//   var content embed.FS                  #[embed("image/*", "html/index.html")]
//                                         static content: embed::FS;
//                                     }
//
// Pattern semantics follow Go: interpreted relative to the directory
// of the source file containing the declaration; `/`-separated; no
// `.`, `..`, empty elements, or leading/trailing slashes; a pattern
// naming a directory embeds its whole subtree excluding `.`/`_`-
// prefixed names unless the pattern has the `all:` prefix; `string` /
// `slice<byte>` variables take exactly one pattern matching exactly
// one file; every pattern must match — violations are compile errors.
// Glob elements support `*` and `?` (Go's path.Match character
// classes are not implemented — a compile error tells you so).
//
// FS implements io/fs's FS, ReadDirFS, and ReadFileFS, so it works
// with fs::ReadFile, fs::WalkDir, fs::Sub, etc. As in Go, the file
// list is stored sorted; directories are synthesized entries; ModTime
// is the zero time; regular files have mode 0444, directories
// ModeDir|0555.
//
// Validated behaviorally against real Go (see embed_smoke): the same
// fixture tree embedded by both runtimes produces identical WalkDir
// listings, ReadDir orderings, file contents, mode/size metadata, and
// not-exist / not-a-directory error identities.

use crate::errors::{self, error};
use crate::goslice::slice;
use crate::gostring::string;
use crate::io::fs;
use crate::types::{byte, int};

use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicUsize, Ordering};

/// One embedded entry. Public only so the `goish::embed!` macro
/// expansion can construct the static table; user code never touches
/// it.
#[doc(hidden)]
pub struct __File {
    /// Slash-separated path relative to the embedding source file's
    /// directory. Directories carry a trailing `/` (Go's convention).
    pub name: &'static str,
    pub data: &'static [u8],
}

impl __File {
    fn is_dir(&self) -> bool {
        self.name.ends_with('/')
    }
    // Path without the directory marker slash.
    fn path(&self) -> &'static str {
        self.name.strip_suffix('/').unwrap_or(self.name)
    }
    fn base(&self) -> &'static str {
        match self.path().rfind('/') {
            Some(i) => &self.path()[i + 1..],
            None => self.path(),
        }
    }
}

// "read <path>: <what>" without alloc::format! (its formatting
// machinery drags unwinding symbols into no_std binaries).
fn read_err_msg(path: &str, what: &str) -> string {
    let mut m = alloc::string::String::from("read ");
    m.push_str(path);
    m.push_str(": ");
    m.push_str(what);
    string::from_bytes(m.as_bytes())
}

/// An FS is a read-only collection of files, usually initialized with
/// `goish::embed!`. Mirrors Go's embed.FS.
#[derive(Clone, Copy)]
pub struct FS {
    files: &'static [__File],
}

// Lazy per-trait downcast registration so `goish::cast!` (used by
// fs::ReadFile / fs::WalkDir / fs::Sub fast paths) can find the embed
// impls. Mirrors fs.rs register_subfs_impls / os register_os_fs_impls.
fn register_embed_impls() {
    use crate::sync::Once;
    static ONCE: Once = Once::new();
    ONCE.Do(|| {
        fs::__goish_register_ReadDirFS_impl::<FS>();
        fs::__goish_register_ReadFileFS_impl::<FS>();
        fs::__goish_register_ReadDirFile_impl::<OpenDir>();
        fs::__goish_register_FileInfo_impl::<Info>();
        fs::__goish_register_DirEntry_impl::<Entry>();
    });
}

impl FS {
    #[doc(hidden)]
    pub const fn __new(files: &'static [__File]) -> FS {
        FS { files }
    }

    fn lookup(&self, name: &str) -> Option<&'static __File> {
        if !fs::ValidPath(name) {
            return None;
        }
        if name == "." {
            // Synthesized root directory.
            static ROOT: __File = __File {
                name: "./",
                data: b"",
            };
            return Some(&ROOT);
        }
        self.files.iter().find(|f| f.path() == name)
    }

    // Entries directly under `dir` ("." = root), in stored (sorted)
    // order.
    fn children(&self, dir: &str) -> Vec<&'static __File> {
        let prefix_owned;
        let prefix: &str = if dir == "." {
            ""
        } else {
            let mut p = alloc::string::String::from(dir);
            p.push('/');
            prefix_owned = p;
            &prefix_owned
        };
        let mut out = Vec::new();
        for f in self.files {
            let p = f.path();
            if let Some(rest) = p.strip_prefix(prefix) {
                if !rest.is_empty() && !rest.contains('/') {
                    out.push(f);
                }
            }
        }
        out
    }

    /// Open opens the named file for reading and returns it as an
    /// fs.File. Directories open as ReadDir-able files.
    pub fn Open<S: Into<string>>(&self, name: S) -> (Arc<dyn fs::File + Send + Sync>, error) {
        register_embed_impls();
        let name = name.into();
        let n: &str = name.as_ref();
        let Some(file) = self.lookup(n) else {
            let err = fs::PathError {
                Op: "open".into(),
                Path: name.clone(),
                Err: fs::ErrNotExist.into(),
            };
            return (crate::nil.into(), errors::Wrap(err));
        };
        if file.is_dir() || n == "." {
            let files = self.children(if n == "." { "." } else { file.path() });
            return (
                Arc::new(OpenDir {
                    file,
                    files,
                    offset: AtomicUsize::new(0),
                }),
                errors::nil,
            );
        }
        (
            Arc::new(OpenFile {
                file,
                offset: AtomicUsize::new(0),
            }),
            errors::nil,
        )
    }

    /// ReadDir reads and returns the entire named directory.
    pub fn ReadDir<S: Into<string>>(
        &self,
        name: S,
    ) -> (slice<Arc<dyn fs::DirEntry + Send + Sync>>, error) {
        register_embed_impls();
        let name = name.into();
        let n: &str = name.as_ref();
        let Some(file) = self.lookup(n) else {
            let err = fs::PathError {
                Op: "open".into(),
                Path: name.clone(),
                Err: fs::ErrNotExist.into(),
            };
            return (slice::new(), errors::Wrap(err));
        };
        if !file.is_dir() && n != "." {
            return (
                slice::new(),
                errors::New(read_err_msg(n, "not a directory")),
            );
        }
        let children = self.children(if n == "." { "." } else { file.path() });
        let mut out: Vec<Arc<dyn fs::DirEntry + Send + Sync>> = Vec::with_capacity(children.len());
        for c in children {
            out.push(Arc::new(Entry { file: c }));
        }
        (slice::__from_vec(out), errors::nil)
    }

    /// ReadFile reads and returns the content of the named file.
    pub fn ReadFile<S: Into<string>>(&self, name: S) -> (slice<byte>, error) {
        register_embed_impls();
        let name = name.into();
        let n: &str = name.as_ref();
        let Some(file) = self.lookup(n) else {
            let err = fs::PathError {
                Op: "open".into(),
                Path: name.clone(),
                Err: fs::ErrNotExist.into(),
            };
            return (slice::new(), errors::Wrap(err));
        };
        if file.is_dir() {
            return (slice::new(), errors::New(read_err_msg(n, "is a directory")));
        }
        (slice::__from_vec(file.data.to_vec()), errors::nil)
    }
}

// ─── FileInfo / DirEntry ────────────────────────────────────────────

struct Info {
    file: &'static __File,
}

impl fs::FileInfo for Info {
    fn __goish_as_dyn_any(&self) -> Option<&(dyn core::any::Any + Send + Sync)> {
        Some(self)
    }
    fn Name(&self) -> string {
        self.file.base().into()
    }
    fn Size(&self) -> int {
        self.file.data.len() as int
    }
    fn Mode(&self) -> fs::FileMode {
        if self.file.is_dir() {
            fs::FileMode(fs::ModeDir.0 | 0o555)
        } else {
            fs::FileMode(0o444)
        }
    }
    fn ModTime(&self) -> crate::time::Time {
        crate::time::Time::default()
    }
    fn IsDir(&self) -> bool {
        self.file.is_dir()
    }
    fn Sys(&self) -> Arc<dyn core::any::Any + Send + Sync> {
        Arc::new(crate::nilval::Nil)
    }
}

struct Entry {
    file: &'static __File,
}

impl fs::DirEntry for Entry {
    fn __goish_as_dyn_any(&self) -> Option<&(dyn core::any::Any + Send + Sync)> {
        Some(self)
    }
    fn Name(&self) -> string {
        self.file.base().into()
    }
    fn IsDir(&self) -> bool {
        self.file.is_dir()
    }
    fn Type(&self) -> fs::FileMode {
        if self.file.is_dir() {
            fs::ModeDir
        } else {
            fs::FileMode(0)
        }
    }
    fn Info(&self) -> (Arc<dyn fs::FileInfo + Send + Sync>, error) {
        (Arc::new(Info { file: self.file }), errors::nil)
    }
}

// ─── open files ─────────────────────────────────────────────────────

struct OpenFile {
    file: &'static __File,
    offset: AtomicUsize,
}

impl fs::File for OpenFile {
    fn __goish_as_dyn_any(&self) -> Option<&(dyn core::any::Any + Send + Sync)> {
        Some(self)
    }
    fn Stat(&self) -> (Arc<dyn fs::FileInfo + Send + Sync>, error) {
        (Arc::new(Info { file: self.file }), errors::nil)
    }
    fn Read(&self, p: &mut slice<byte>) -> (int, error) {
        let off = self.offset.load(Ordering::Acquire);
        if off >= self.file.data.len() {
            return (0, crate::io::EOF.into());
        }
        let n = core::cmp::min(p.as_ref().len(), self.file.data.len() - off);
        p.as_mut()[..n].copy_from_slice(&self.file.data[off..off + n]);
        self.offset.store(off + n, Ordering::Release);
        (n as int, errors::nil)
    }
    fn Close(&self) -> error {
        errors::nil
    }
}

struct OpenDir {
    file: &'static __File,
    files: Vec<&'static __File>,
    offset: AtomicUsize,
}

impl fs::File for OpenDir {
    fn __goish_as_dyn_any(&self) -> Option<&(dyn core::any::Any + Send + Sync)> {
        Some(self)
    }
    fn Stat(&self) -> (Arc<dyn fs::FileInfo + Send + Sync>, error) {
        (Arc::new(Info { file: self.file }), errors::nil)
    }
    fn Read(&self, _p: &mut slice<byte>) -> (int, error) {
        (
            0,
            errors::New(read_err_msg(self.file.path(), "is a directory")),
        )
    }
    fn Close(&self) -> error {
        errors::nil
    }
}

impl fs::ReadDirFile for OpenDir {
    fn __goish_as_dyn_any(&self) -> Option<&(dyn core::any::Any + Send + Sync)> {
        Some(self)
    }
    fn Stat(&self) -> (Arc<dyn fs::FileInfo + Send + Sync>, error) {
        (Arc::new(Info { file: self.file }), errors::nil)
    }
    fn Read(&self, p: &mut slice<byte>) -> (int, error) {
        <OpenDir as fs::File>::Read(self, p)
    }
    fn Close(&self) -> error {
        errors::nil
    }
    fn ReadDir(&self, n: int) -> (slice<Arc<dyn fs::DirEntry + Send + Sync>>, error) {
        let off = self.offset.load(Ordering::Acquire);
        let remaining = self.files.len().saturating_sub(off);
        let count = if n <= 0 {
            remaining
        } else {
            core::cmp::min(n as usize, remaining)
        };
        if count == 0 && n > 0 {
            return (slice::new(), crate::io::EOF.into());
        }
        let mut out: Vec<Arc<dyn fs::DirEntry + Send + Sync>> = Vec::with_capacity(count);
        for f in &self.files[off..off + count] {
            out.push(Arc::new(Entry { file: f }));
        }
        self.offset.store(off + count, Ordering::Release);
        (slice::__from_vec(out), errors::nil)
    }
}

// ─── io/fs interface impls ──────────────────────────────────────────

impl fs::FS for FS {
    fn __goish_as_dyn_any(&self) -> Option<&(dyn core::any::Any + Send + Sync)> {
        Some(self)
    }
    fn Open(&self, name: string) -> (Arc<dyn fs::File + Send + Sync>, error) {
        FS::Open(self, name)
    }
}

impl fs::ReadDirFS for FS {
    fn __goish_as_dyn_any(&self) -> Option<&(dyn core::any::Any + Send + Sync)> {
        Some(self)
    }
    fn Open(&self, name: string) -> (Arc<dyn fs::File + Send + Sync>, error) {
        FS::Open(self, name)
    }
    fn ReadDir(&self, name: string) -> (slice<Arc<dyn fs::DirEntry + Send + Sync>>, error) {
        FS::ReadDir(self, name)
    }
}

impl fs::ReadFileFS for FS {
    fn __goish_as_dyn_any(&self) -> Option<&(dyn core::any::Any + Send + Sync)> {
        Some(self)
    }
    fn Open(&self, name: string) -> (Arc<dyn fs::File + Send + Sync>, error) {
        FS::Open(self, name)
    }
    fn ReadFile(&self, name: string) -> (slice<byte>, error) {
        FS::ReadFile(self, name)
    }
}
