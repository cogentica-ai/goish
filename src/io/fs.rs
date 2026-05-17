// io/fs — port of Go 1.25 io/fs (fs.go / readdir.go / stat.go / walk.go).
//
// Source: /nix/store/60z37432vmgkg54krwr1z057bqwp7583-go-1.25.5/share/go/src/io/fs/
//
// What this port covers:
//   * `FileMode` newtype + all bits + String/IsDir/IsRegular/Perm/Type
//   * `ValidPath`
//   * `PathError` + Error/Unwrap
//   * Sentinel errors: ErrInvalid, ErrPermission, ErrExist, ErrNotExist, ErrClosed
//   * Interfaces: `FS`, `File`, `FileInfo`, `DirEntry`, `ReadDirFile`,
//     `ReadDirFS`, `StatFS` — `#[goish::interface]` traits.
//   * `ReadDir`, `Stat`, `FileInfoToDirEntry`
//   * `SkipDir` / `SkipAll`, `WalkDirFunc`, `WalkDir`
//
// Note on `io/fs` vs `os` duplication: goish's `os` module separately
// defines its own concrete `os::FileInfo` *trait* and `os::DirEntry`
// *struct*. Those are NOT the interfaces defined here. Go's canonical
// home for these interfaces is `io/fs`, so this module owns the
// `#[goish::interface]` versions; unifying `os`'s shapes with these is
// out of scope (a future cleanup, once a second FS impl lands).

#![allow(non_snake_case, non_camel_case_types)]

extern crate alloc;
use alloc::string::String as RustString;
use alloc::sync::Arc;
use alloc::vec::Vec;

use crate::errors::{self, error, ErrorTrait};
use crate::goslice::slice;
use crate::gostring::string;
use crate::types::{byte, int, rune};
use crate::unicode::utf8;

// Go: fs.go:172
//   type FileMode uint32
//
// Slim: a newtype wrapper around u32 so we can hang methods off it.
// The numeric layout matches Go exactly so a FileMode round-trips
// across the os boundary unchanged: `FileMode(os_mode)` and
// `fm.Bits()` both work.
#[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Default)]
pub struct FileMode(pub u32);

impl FileMode {
    pub const fn Bits(&self) -> u32 {
        self.0
    }
}

// Bit operators — Go writes `mode | os.ModeDir`, `mode & os.ModePerm`,
// `flag &^ os.O_TRUNC` (Go's bit-clear). Mirror that ergonomically on
// the newtype so ports keep their idioms without `.0` unwrapping.
impl core::ops::BitOr for FileMode {
    type Output = FileMode;
    fn bitor(self, rhs: FileMode) -> FileMode { FileMode(self.0 | rhs.0) }
}
impl core::ops::BitAnd for FileMode {
    type Output = FileMode;
    fn bitand(self, rhs: FileMode) -> FileMode { FileMode(self.0 & rhs.0) }
}
// Mask against a bare integer literal — Go writes `fi.Mode() & 0o777`
// and the untyped constant coerces to `os.FileMode`. Rust needs the
// literal pinned: a single `BitAnd<u32>` impl lets `& 0o777` infer the
// literal as `u32` unambiguously.
impl core::ops::BitAnd<u32> for FileMode {
    type Output = FileMode;
    fn bitand(self, rhs: u32) -> FileMode { FileMode(self.0 & rhs) }
}
impl core::ops::BitXor for FileMode {
    type Output = FileMode;
    fn bitxor(self, rhs: FileMode) -> FileMode { FileMode(self.0 ^ rhs.0) }
}
impl core::ops::BitOrAssign for FileMode {
    fn bitor_assign(&mut self, rhs: FileMode) { self.0 |= rhs.0; }
}
impl core::ops::BitAndAssign for FileMode {
    fn bitand_assign(&mut self, rhs: FileMode) { self.0 &= rhs.0; }
}
impl core::ops::Not for FileMode {
    type Output = FileMode;
    fn not(self) -> FileMode { FileMode(!self.0) }
}

// Integer-literal coercions. Go writes `os.OpenFile(name, flag, 0666)`
// and the compiler accepts 0666 as `os.FileMode` because Go has
// untyped constants. Rust doesn't, so accept the common literal widths
// via `From` and `impl Into<FileMode>` on call sites that take perm.
impl From<u32> for FileMode { fn from(v: u32) -> FileMode { FileMode(v) } }
impl From<i32> for FileMode { fn from(v: i32) -> FileMode { FileMode(v as u32) } }
impl From<i64> for FileMode { fn from(v: i64) -> FileMode { FileMode(v as u32) } }
impl From<u64> for FileMode { fn from(v: u64) -> FileMode { FileMode(v as u32) } }
impl From<u16> for FileMode { fn from(v: u16) -> FileMode { FileMode(v as u32) } }
impl From<crate::nilval::Nil> for FileMode {
    fn from(_: crate::nilval::Nil) -> FileMode { FileMode(0) }
}

// Comparison against bare integer 0 — Go's `if perm == 0 { … }`.
impl PartialEq<i32> for FileMode {
    fn eq(&self, other: &i32) -> bool { self.0 == *other as u32 }
}
impl PartialEq<u32> for FileMode {
    fn eq(&self, other: &u32) -> bool { self.0 == *other }
}

// Go: fs.go:179-200 — FileMode constants. The single letters match the
// abbreviations used by FileMode.String. Bit positions counted from
// MSB so they stay disjoint from the 9 perm bits.
pub const ModeDir: FileMode = FileMode(1 << 31);          // d
pub const ModeAppend: FileMode = FileMode(1 << 30);       // a
pub const ModeExclusive: FileMode = FileMode(1 << 29);    // l
pub const ModeTemporary: FileMode = FileMode(1 << 28);    // T
pub const ModeSymlink: FileMode = FileMode(1 << 27);      // L
pub const ModeDevice: FileMode = FileMode(1 << 26);       // D
pub const ModeNamedPipe: FileMode = FileMode(1 << 25);    // p
pub const ModeSocket: FileMode = FileMode(1 << 24);       // S
pub const ModeSetuid: FileMode = FileMode(1 << 23);       // u
pub const ModeSetgid: FileMode = FileMode(1 << 22);       // g
pub const ModeCharDevice: FileMode = FileMode(1 << 21);   // c
pub const ModeSticky: FileMode = FileMode(1 << 20);       // t
pub const ModeIrregular: FileMode = FileMode(1 << 19);    // ?

// Go: fs.go:197 — mask for the type bits.
pub const ModeType: FileMode = FileMode(
    ModeDir.0
        | ModeSymlink.0
        | ModeNamedPipe.0
        | ModeSocket.0
        | ModeDevice.0
        | ModeCharDevice.0
        | ModeIrregular.0,
);

// Go: fs.go:199
//   ModePerm FileMode = 0777
pub const ModePerm: FileMode = FileMode(0o777);

impl FileMode {
    // Go: fs.go:202-226
    //   func (m FileMode) String() string
    pub fn String(&self) -> string {
        // Go: const str = "dalTLDpSugct?"
        const STR: &[byte] = b"dalTLDpSugct?";
        // Go: var buf [32]byte
        let mut buf: [byte; 32] = [0; 32];
        let mut w: usize = 0;
        // Go: for i, c := range str {
        //         if m&(1<<uint(32-1-i)) != 0 {
        //             buf[w] = byte(c); w++
        //         }
        //     }
        for i in 0..STR.len() {
            let bit: u32 = 1u32 << (32 - 1 - i as u32);
            if self.0 & bit != 0 {
                buf[w] = STR[i];
                w += 1;
            }
        }
        if w == 0 {
            buf[w] = b'-';
            w += 1;
        }
        // Go: const rwx = "rwxrwxrwx"
        const RWX: &[byte] = b"rwxrwxrwx";
        for i in 0..RWX.len() {
            let bit: u32 = 1u32 << (9 - 1 - i as u32);
            if self.0 & bit != 0 {
                buf[w] = RWX[i];
            } else {
                buf[w] = b'-';
            }
            w += 1;
        }
        string::from_bytes(&buf[..w])
    }

    // Go: fs.go:230-232
    //   func (m FileMode) IsDir() bool { return m&ModeDir != 0 }
    pub fn IsDir(&self) -> bool {
        self.0 & ModeDir.0 != 0
    }

    // Go: fs.go:236-238
    //   func (m FileMode) IsRegular() bool { return m&ModeType == 0 }
    pub fn IsRegular(&self) -> bool {
        self.0 & ModeType.0 == 0
    }

    // Go: fs.go:241-243
    //   func (m FileMode) Perm() FileMode { return m & ModePerm }
    pub fn Perm(&self) -> FileMode {
        FileMode(self.0 & ModePerm.0)
    }

    // Go: fs.go:246-248
    //   func (m FileMode) Type() FileMode { return m & ModeType }
    pub fn Type(&self) -> FileMode {
        FileMode(self.0 & ModeType.0)
    }
}

// Go: fs.go:54-79
//   func ValidPath(name string) bool
pub fn ValidPath<S: Into<string>>(name: S) -> bool {
    let name = name.into();
    // Go: if !utf8.ValidString(name) { return false }
    if !utf8::ValidString(&name) {
        return false;
    }

    // Go: if name == "." { return true }
    if name == string::from_static(".") {
        return true;
    }

    // Iterate over elements separated by '/'.
    let bytes = name.clone();
    let raw: &[byte] = bytes.as_bytes();
    let mut start: usize = 0;
    loop {
        // Go: i := 0; for i < len(name) && name[i] != '/' { i++ }
        let mut i: usize = start;
        while i < raw.len() && raw[i] != b'/' {
            i += 1;
        }
        // Go: elem := name[:i]
        let elem = &raw[start..i];
        // Go: if elem == "" || elem == "." || elem == ".." { return false }
        if elem.is_empty() || elem == b"." || elem == b".." {
            return false;
        }
        // Go: if i == len(name) { return true }
        if i == raw.len() {
            return true;
        }
        // Go: name = name[i+1:]
        start = i + 1;
    }
}

// Go: fs.go:251-265
//   type PathError struct {
//       Op   string
//       Path string
//       Err  error
//   }
//
//   func (e *PathError) Error() string { return e.Op + " " + e.Path + ": " + e.Err.Error() }
//   func (e *PathError) Unwrap() error { return e.Err }
#[derive(Clone)]
pub struct PathError {
    pub Op: string,
    pub Path: string,
    pub Err: error,
}

impl ErrorTrait for PathError {
    fn Error(&self) -> string {
        // Go: e.Op + " " + e.Path + ": " + e.Err.Error()
        let inner = if self.Err == errors::nil {
            string::from_static("")
        } else {
            self.Err.Error()
        };
        let mut out = RustString::new();
        out.push_str(core::str::from_utf8(self.Op.as_bytes()).unwrap_or(""));
        out.push(' ');
        out.push_str(core::str::from_utf8(self.Path.as_bytes()).unwrap_or(""));
        out.push_str(": ");
        out.push_str(core::str::from_utf8(inner.as_bytes()).unwrap_or(""));
        string::from_bytes(out.as_bytes())
    }

    fn Unwrap(&self) -> error {
        self.Err.clone()
    }
}

// Go: fs.go:143-155
//   var (
//       ErrInvalid    = errInvalid()    // "invalid argument"
//       ErrPermission = errPermission() // "permission denied"
//       ErrExist      = errExist()      // "file already exists"
//       ErrNotExist   = errNotExist()   // "file does not exist"
//       ErrClosed     = errClosed()     // "file already closed"
//   )
//
// Each is a cached singleton: Arc::ptr_eq across calls so
// `errors::Is(e, fs::ErrNotExist)` works.
crate::var! {
    pub ErrInvalid: error    = "invalid argument";
    pub ErrPermission: error = "permission denied";
    pub ErrExist: error      = "file already exists";
    pub ErrNotExist: error   = "file does not exist";
    pub ErrClosed: error     = "file already closed";
}

// ─── Interfaces (fs.go / readdir.go / stat.go) ───────────────────────
//
// Go interfaces are modelled with `#[goish::interface]`. Every method
// takes `&self`: a concrete file-system value carries interior
// mutability, mirroring Go's interface values (which are pointers —
// all operations flow through them without an exclusive borrow). This
// is what lets `WalkDir` hold `&dyn FS` and `Arc<dyn File>`.

/// `fs.FileInfo` (fs.go:158) — describes a file, returned by [`Stat`].
#[goish::interface]
pub trait FileInfo {
    /// Base name of the file.
    fn Name(&self) -> string;
    /// Length in bytes for regular files; system-dependent for others.
    fn Size(&self) -> i64;
    /// File mode bits.
    fn Mode(&self) -> FileMode;
    /// Modification time.
    fn ModTime(&self) -> crate::time::Time;
    /// Abbreviation for `Mode().IsDir()`.
    fn IsDir(&self) -> bool;
    /// Underlying data source (can return nil).
    fn Sys(&self) -> Arc<dyn core::any::Any + Send + Sync>;
}

/// `fs.DirEntry` (fs.go:93) — an entry read from a directory.
#[goish::interface]
pub trait DirEntry {
    /// Final path element (base name) of the file or subdirectory.
    fn Name(&self) -> string;
    /// Reports whether the entry describes a directory.
    fn IsDir(&self) -> bool;
    /// Type bits for the entry (a subset of [`FileMode`]).
    fn Type(&self) -> FileMode;
    /// `FileInfo` for the file or subdirectory described by the entry.
    fn Info(&self) -> (Arc<dyn FileInfo + Send + Sync>, error);
}

/// `fs.File` (fs.go:85) — access to a single file.
#[goish::interface]
pub trait File {
    /// `Stat()` — file metadata.
    fn Stat(&self) -> (Arc<dyn FileInfo + Send + Sync>, error);
    /// `Read(p)` — read bytes into `p`. (`&self`: the concrete file
    /// owns its cursor behind interior mutability.)
    fn Read(&self, p: slice<byte>) -> (int, error);
    /// `Close()` — release associated resources.
    fn Close(&self) -> error;
}

/// `fs.FS` (fs.go:27) — access to a hierarchical file system.
#[goish::interface]
pub trait FS {
    /// `Open(name)` — open the named file. On error, the result
    /// should be a `*PathError`.
    fn Open(&self, name: string) -> (Arc<dyn File + Send + Sync>, error);
}

// Go embeds interfaces (`type ReadDirFile interface { File; ReadDir }`).
// goish's `#[goish::interface]` macro does not model embedding — each
// interface gets its own nil sentinel + downcast registry, and a Rust
// supertrait would collide on the macro's hidden `__is_nil_iface` /
// `__goish_as_dyn_any` helpers. So the composite interfaces below
// RE-DECLARE the inherited methods as independent interfaces. A
// concrete type that implements e.g. `File` + `ReadDirFile` just
// `impl`s both traits; `goish::cast!(file, ReadDirFile)` still works
// because each interface has its own per-trait registry.

/// `fs.ReadDirFile` (fs.go:119) — a directory file whose entries can
/// be read with `ReadDir`. Embeds [`File`] in Go.
#[goish::interface]
pub trait ReadDirFile {
    /// `Stat()` — file metadata (from embedded [`File`]).
    fn Stat(&self) -> (Arc<dyn FileInfo + Send + Sync>, error);
    /// `Read(p)` — read bytes into `p` (from embedded [`File`]).
    fn Read(&self, p: slice<byte>) -> (int, error);
    /// `Close()` — release resources (from embedded [`File`]).
    fn Close(&self) -> error;
    /// `ReadDir(n)` — up to `n` entries in directory order; `n <= 0`
    /// returns all remaining entries. At end-of-directory the error
    /// is `io::EOF`.
    fn ReadDir(&self, n: int) -> (slice<Arc<dyn DirEntry + Send + Sync>>, error);
}

/// `fs.ReadDirFS` (readdir.go:15) — a file system with an optimized
/// `ReadDir` implementation. Embeds [`FS`] in Go.
#[goish::interface]
pub trait ReadDirFS {
    /// `Open(name)` — open the named file (from embedded [`FS`]).
    fn Open(&self, name: string) -> (Arc<dyn File + Send + Sync>, error);
    /// `ReadDir(name)` — entries of the named directory, sorted by
    /// filename.
    fn ReadDir(&self, name: string) -> (slice<Arc<dyn DirEntry + Send + Sync>>, error);
}

/// `fs.StatFS` (stat.go:8) — a file system with a `Stat` method.
/// Embeds [`FS`] in Go.
#[goish::interface]
pub trait StatFS {
    /// `Open(name)` — open the named file (from embedded [`FS`]).
    fn Open(&self, name: string) -> (Arc<dyn File + Send + Sync>, error);
    /// `Stat(name)` — `FileInfo` describing the named file.
    fn Stat(&self, name: string) -> (Arc<dyn FileInfo + Send + Sync>, error);
}

// ─── dirInfo — DirEntry over a FileInfo (readdir.go:52) ──────────────

// Go: `type dirInfo struct { fileInfo FileInfo }`
struct dirInfo {
    fileInfo: Arc<dyn FileInfo + Send + Sync>,
}

impl DirEntry for dirInfo {
    // Go: func (di dirInfo) Name() string { return di.fileInfo.Name() }
    fn Name(&self) -> string {
        self.fileInfo.Name()
    }
    // Go: func (di dirInfo) IsDir() bool { return di.fileInfo.IsDir() }
    fn IsDir(&self) -> bool {
        self.fileInfo.IsDir()
    }
    // Go: func (di dirInfo) Type() FileMode { return di.fileInfo.Mode().Type() }
    fn Type(&self) -> FileMode {
        self.fileInfo.Mode().Type()
    }
    // Go: func (di dirInfo) Info() (FileInfo, error) { return di.fileInfo, nil }
    fn Info(&self) -> (Arc<dyn FileInfo + Send + Sync>, error) {
        (self.fileInfo.clone(), errors::nil)
    }
}

/// `fs.FileInfoToDirEntry` (readdir.go:79) — a [`DirEntry`] that
/// reports information from `info`.
pub fn FileInfoToDirEntry(
    info: Arc<dyn FileInfo + Send + Sync>,
) -> Arc<dyn DirEntry + Send + Sync> {
    // Go: if info == nil { return nil }
    if info == crate::nil {
        return crate::nil.into();
    }
    Arc::new(dirInfo { fileInfo: info })
}

// ─── ReadDir (readdir.go:29) ─────────────────────────────────────────

// Lexical-order comparison of two DirEntry names, matching Go's
// `bytealg.CompareString` (a plain byte-wise lexical compare).
fn compare_dirent_name(
    a: &Arc<dyn DirEntry + Send + Sync>,
    b: &Arc<dyn DirEntry + Send + Sync>,
) -> core::cmp::Ordering {
    a.Name().as_bytes().cmp(b.Name().as_bytes())
}

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
    (list, err)
}

// ─── Stat (stat.go:20) ───────────────────────────────────────────────

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
    info
}

// ─── WalkDir (walk.go) ───────────────────────────────────────────────

// Go: var SkipDir = errors.New("skip this directory")
// Go: var SkipAll = errors.New("skip everything and stop the walk")
//
// Used only as return values from a `WalkDirFunc`; never returned as an
// error by any function. Emitted via `goish::var!` so a bare-symbol
// comparison (`err == SkipDir`) works without `.into()`.
crate::var! {
    // SkipDir — returned from a WalkDirFunc to skip the named directory.
    pub SkipDir: error = "skip this directory";
    // SkipAll — returned from a WalkDirFunc to skip everything and stop.
    pub SkipAll: error = "skip everything and stop the walk";
}

/// `fs.WalkDirFunc` (walk.go:69) — the function called by [`WalkDir`]
/// to visit each file or directory.
///
/// Go: `type WalkDirFunc func(path string, d DirEntry, err error) error`.
/// goish spells the `DirEntry` argument as an interface-borrow
/// (`&(dyn DirEntry + Send + Sync + 'static)`); when [`WalkDir`] has no
/// entry (the failed-`Stat`-on-root case) it passes a nil-interface
/// sentinel, so `d == crate::nil` is the Go `d == nil` test.
pub trait WalkDirFunc:
    Fn(string, &(dyn DirEntry + Send + Sync + 'static), error) -> error
{
}
impl<F> WalkDirFunc for F where
    F: Fn(string, &(dyn DirEntry + Send + Sync + 'static), error) -> error
{
}

// Go: walkDir — recursively descends `name`, calling `walkDirFn`.
fn walkDir<F: WalkDirFunc>(
    fsys: &(dyn FS + Send + Sync + 'static),
    name: string,
    d: &Arc<dyn DirEntry + Send + Sync>,
    walkDirFn: &F,
) -> error {
    // Go: if err := walkDirFn(name, d, nil); err != nil || !d.IsDir() {
    let err = walkDirFn(name.clone(), &**d, errors::nil.into());
    if err != errors::nil || !d.IsDir() {
        // Go: if err == SkipDir && d.IsDir() { err = nil }
        if err == SkipDir && d.IsDir() {
            return errors::nil;
        }
        return err;
    }

    // Go: dirs, err := ReadDir(fsys, name)
    let (dirs, err) = ReadDir(fsys, name.clone());
    if err != errors::nil {
        // Go: second call, to report the ReadDir error.
        let err = walkDirFn(name.clone(), &**d, err);
        if err != errors::nil {
            // Go: if err == SkipDir && d.IsDir() { err = nil }
            if err == SkipDir && d.IsDir() {
                return errors::nil;
            }
            return err;
        }
    }

    // Go: for _, d1 := range dirs {
    for (_, d1) in crate::range!(&dirs) {
        // Go: name1 := path.Join(name, d1.Name())
        let name1 = crate::path::Join(slice::__from_vec(alloc::vec![
            name.clone(),
            d1.Name()
        ]));
        // Go: if err := walkDir(fsys, name1, d1, walkDirFn); err != nil {
        let err = walkDir(fsys, name1, d1, walkDirFn);
        if err != errors::nil {
            // Go: if err == SkipDir { break }
            if err == SkipDir {
                break;
            }
            return err;
        }
    }
    errors::nil
}

/// `fs.WalkDir(fsys, root, fn)` (walk.go:117) — walks the file tree
/// rooted at `root`, calling `fn` for each file or directory in the
/// tree, including `root`.
///
/// Files are walked in lexical order. See [`WalkDirFunc`] for how the
/// `fn` return value (including [`SkipDir`] / [`SkipAll`]) controls the
/// walk.
pub fn WalkDir<S: Into<string>, F: WalkDirFunc>(
    fsys: &(dyn FS + Send + Sync + 'static),
    root: S,
    fn_: F,
) -> error {
    let root: string = root.into();
    // Go: info, err := Stat(fsys, root)
    let (info, err) = Stat(fsys, root.clone());
    let err = if err != errors::nil {
        // Go: err = fn(root, nil, err)
        let nil_d: Arc<dyn DirEntry + Send + Sync> = crate::nil.into();
        fn_(root.clone(), &*nil_d, err)
    } else {
        // Go: err = walkDir(fsys, root, FileInfoToDirEntry(info), fn)
        let d = FileInfoToDirEntry(info);
        walkDir(fsys, root, &d, &fn_)
    };
    // Go: if err == SkipDir || err == SkipAll { return nil }
    if err == SkipDir || err == SkipAll {
        return errors::nil;
    }
    err
}

// Suppress unused-import warnings for items pulled in for completeness.
#[allow(dead_code)]
fn _unused_imports() {
    let _: int = 0;
    let _: rune = 'a' as rune;
    let _v: Vec<u8> = Vec::new();
    let _s: slice<byte> = slice::__from_vec(_v);
}
