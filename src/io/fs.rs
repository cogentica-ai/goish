// io/fs — port of Go 1.25 io/fs (fs.go / readdir.go / stat.go / walk.go).
//
// Source: go1.25.5/src/io/fs/
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
// Note on `io/fs` vs `os`: Go's canonical home for the `FileInfo`,
// `DirEntry`, and `FileMode` types is `io/fs`. The `os` package does
// not define its own — `os.FileInfo`, `os.DirEntry`, `os.FileMode`
// are exact type aliases for the `fs` versions. goish mirrors this:
// this module owns the `#[goish::interface]` traits + the `FileMode`
// newtype, and `os` re-exports them via `pub use`.

#![allow(non_snake_case, non_camel_case_types)]

extern crate alloc;
use alloc::string::String as RustString;
use alloc::sync::Arc;
use alloc::vec::Vec;

use crate::errors::{self, error, ErrorTrait};
use crate::goslice::slice;
use crate::gostring::string;
use crate::types::{byte, int, int64, rune};
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
    fn bitor(self, rhs: FileMode) -> FileMode {
        FileMode(self.0 | rhs.0)
    }
}
impl core::ops::BitAnd for FileMode {
    type Output = FileMode;
    fn bitand(self, rhs: FileMode) -> FileMode {
        FileMode(self.0 & rhs.0)
    }
}
// Mask against a bare integer literal — Go writes `fi.Mode() & 0o777`
// and the untyped constant coerces to `os.FileMode`. Rust needs the
// literal pinned: a single `BitAnd<u32>` impl lets `& 0o777` infer the
// literal as `u32` unambiguously.
impl core::ops::BitAnd<u32> for FileMode {
    type Output = FileMode;
    fn bitand(self, rhs: u32) -> FileMode {
        FileMode(self.0 & rhs)
    }
}
impl core::ops::BitXor for FileMode {
    type Output = FileMode;
    fn bitxor(self, rhs: FileMode) -> FileMode {
        FileMode(self.0 ^ rhs.0)
    }
}
impl core::ops::BitOrAssign for FileMode {
    fn bitor_assign(&mut self, rhs: FileMode) {
        self.0 |= rhs.0;
    }
}
impl core::ops::BitAndAssign for FileMode {
    fn bitand_assign(&mut self, rhs: FileMode) {
        self.0 &= rhs.0;
    }
}
impl core::ops::Not for FileMode {
    type Output = FileMode;
    fn not(self) -> FileMode {
        FileMode(!self.0)
    }
}

// Integer-literal coercions. Go writes `os.OpenFile(name, flag, 0666)`
// and the compiler accepts 0666 as `os.FileMode` because Go has
// untyped constants. Rust doesn't, so accept the common literal widths
// via `From` and `impl Into<FileMode>` on call sites that take perm.
impl From<u32> for FileMode {
    fn from(v: u32) -> FileMode {
        FileMode(v)
    }
}
impl From<i32> for FileMode {
    fn from(v: i32) -> FileMode {
        FileMode(v as u32)
    }
}
impl From<i64> for FileMode {
    fn from(v: i64) -> FileMode {
        FileMode(v as u32)
    }
}
impl From<u64> for FileMode {
    fn from(v: u64) -> FileMode {
        FileMode(v as u32)
    }
}
impl From<u16> for FileMode {
    fn from(v: u16) -> FileMode {
        FileMode(v as u32)
    }
}
impl From<crate::nilval::Nil> for FileMode {
    fn from(_: crate::nilval::Nil) -> FileMode {
        FileMode(0)
    }
}

// Comparison against bare integer 0 — Go's `if perm == 0 { … }`.
impl PartialEq<i32> for FileMode {
    fn eq(&self, other: &i32) -> bool {
        self.0 == *other as u32
    }
}
impl PartialEq<u32> for FileMode {
    fn eq(&self, other: &u32) -> bool {
        self.0 == *other
    }
}

// Go: fs.go:179-200 — FileMode constants. The single letters match the
// abbreviations used by FileMode.String. Bit positions counted from
// MSB so they stay disjoint from the 9 perm bits.
pub const ModeDir: FileMode = FileMode(1 << 31); // d
pub const ModeAppend: FileMode = FileMode(1 << 30); // a
pub const ModeExclusive: FileMode = FileMode(1 << 29); // l
pub const ModeTemporary: FileMode = FileMode(1 << 28); // T
pub const ModeSymlink: FileMode = FileMode(1 << 27); // L
pub const ModeDevice: FileMode = FileMode(1 << 26); // D
pub const ModeNamedPipe: FileMode = FileMode(1 << 25); // p
pub const ModeSocket: FileMode = FileMode(1 << 24); // S
pub const ModeSetuid: FileMode = FileMode(1 << 23); // u
pub const ModeSetgid: FileMode = FileMode(1 << 22); // g
pub const ModeCharDevice: FileMode = FileMode(1 << 21); // c
pub const ModeSticky: FileMode = FileMode(1 << 20); // t
pub const ModeIrregular: FileMode = FileMode(1 << 19); // ?

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
    fn Size(&self) -> int;
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
    /// owns its cursor behind interior mutability.) `p` is taken by
    /// `&mut` so the caller observes the bytes written, matching
    /// `io::Reader::Read`.
    fn Read(&self, p: &mut slice<byte>) -> (int, error);
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

// go: none — goish-only capability interface, no Go counterpart.
//
// Go's `net/http.ioFile.Seek` asserts `f.file.(io.Seeker)`. goish's
// `io::Seeker` takes `&mut self` — a seek moves a cursor — but a file
// obtained from `FS::Open` is an `Arc<dyn File>`, which yields no
// `&mut`, so that assertion can never succeed and every such file
// would report "missing Seek method".
//
// This declares the same capability with the `&self` receiver the
// rest of this module already uses: `File::Read` is `&self` too,
// because a concrete file owns its cursor behind interior mutability.
// Implement it beside `File` on any type whose bytes are seekable;
// `goish::cast!(file, SeekableFile)` is then the analogue of Go's
// `f.file.(io.Seeker)`.
#[goish::interface] // goishlint:ignore GOISH022 — the macro expands to `goish::int` internally; the declaration below already uses bare `int`.
pub trait SeekableFile {
    /// `Seek(offset, whence)` — as `io::Seeker`, but on a shared
    /// handle. `whence` is [`crate::io::SeekStart`],
    /// [`crate::io::SeekCurrent`] or [`crate::io::SeekEnd`].
    fn Seek(&self, offset: int64, whence: int) -> (int64, error);
}

/// `fs.ReadDirFile` (fs.go:119) — a directory file whose entries can
/// be read with `ReadDir`. Embeds [`File`] in Go.
#[goish::interface]
pub trait ReadDirFile {
    /// `Stat()` — file metadata (from embedded [`File`]).
    fn Stat(&self) -> (Arc<dyn FileInfo + Send + Sync>, error);
    /// `Read(p)` — read bytes into `p` (from embedded [`File`]).
    fn Read(&self, p: &mut slice<byte>) -> (int, error);
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
pub trait WalkDirFunc: Fn(string, &(dyn DirEntry + Send + Sync + 'static), error) -> error {}
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
        let name1 = crate::path::Join(slice::__from_vec(alloc::vec![name.clone(), d1.Name()]));
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

// ─── ReadFile (readfile.go) ──────────────────────────────────────────

/// `fs.ReadFileFS` (readfile.go:14) — a file system with an optimized
/// `ReadFile` implementation. Embeds [`FS`] in Go (re-declared here;
/// see the interface-embedding note above).
#[goish::interface]
pub trait ReadFileFS {
    /// `Open(name)` — open the named file (from embedded [`FS`]).
    fn Open(&self, name: string) -> (Arc<dyn File + Send + Sync>, error);
    /// `ReadFile(name)` — the full contents of the named file. A
    /// successful call returns a nil error, not `io::EOF`.
    fn ReadFile(&self, name: string) -> (slice<byte>, error);
}

/// `fs.ReadFile(fsys, name)` (readfile.go:24) — read the named file
/// and return its contents. A successful call returns a nil error,
/// not `io::EOF` (reads the whole file).
///
/// If `fsys` implements [`ReadFileFS`], `ReadFile` calls its
/// `ReadFile`. Otherwise it opens the file and reads until EOF.
pub fn ReadFile<S: Into<string>>(
    fsys: &(dyn FS + Send + Sync + 'static),
    name: S,
) -> (slice<byte>, error) {
    let name: string = name.into();

    // Go: if fsys, ok := fsys.(ReadFileFS); ok { return fsys.ReadFile(name) }
    let (rffs, ok) = goish::cast!(fsys, ReadFileFS);
    if ok {
        return rffs.ReadFile(name);
    }

    // Go: file, err := fsys.Open(name); if err != nil { return nil, err }
    let (file, err) = fsys.Open(name);
    if err != errors::nil {
        return (slice::new(), err);
    }
    // Go: defer file.Close(); read until error/EOF.
    let mut out: Vec<u8> = Vec::new();
    let mut chunk: slice<byte> = slice::__from_vec(alloc::vec![0u8; 4096]);
    loop {
        let (n, err) = file.Read(&mut chunk);
        if n > 0 {
            out.extend_from_slice(&chunk.as_ref()[..n as usize]);
        }
        if err != errors::nil {
            let _ = file.Close();
            if err == crate::io::EOF {
                return (slice::__from_vec(out), errors::nil);
            }
            return (slice::__from_vec(out), err);
        }
        if n == 0 {
            // A zero-byte, nil-error Read from a well-behaved File
            // only happens at EOF; stop rather than spin.
            let _ = file.Close();
            return (slice::__from_vec(out), errors::nil);
        }
    }
}

// ─── Sub (sub.go) ────────────────────────────────────────────────────

/// `fs.SubFS` (sub.go:12) — a file system with an optimized `Sub`
/// implementation. Embeds [`FS`] in Go (re-declared; see note above).
#[goish::interface]
pub trait SubFS {
    /// `Open(name)` — open the named file (from embedded [`FS`]).
    fn Open(&self, name: string) -> (Arc<dyn File + Send + Sync>, error);
    /// `Sub(dir)` — an FS corresponding to the subtree rooted at dir.
    fn Sub(&self, dir: string) -> (Arc<dyn FS + Send + Sync>, error);
}

/// `fs.Sub(fsys, dir)` (sub.go:25) — an FS corresponding to the
/// subtree rooted at `fsys`'s `dir`.
///
/// If `dir` is `.`, `Sub` returns `fsys` unchanged. If `fsys`
/// implements [`SubFS`], `Sub` calls its `Sub`. Otherwise it returns
/// a wrapper that translates paths (the wrapper forwards optimized
/// `ReadDir` / `ReadFile` / `Stat` through the free functions; Go's
/// error-path shortening inside the wrapper is not replicated).
pub fn Sub<S: Into<string>>(
    fsys: Arc<dyn FS + Send + Sync>,
    dir: S,
) -> (Arc<dyn FS + Send + Sync>, error) {
    let dir: string = dir.into();
    // Go: if !ValidPath(dir) { return nil, &PathError{...} }
    if !ValidPath(dir.clone()) {
        return (
            crate::nil.into(),
            errors::Wrap(PathError {
                Op: string::from_static("sub"),
                Path: dir,
                Err: errors::New("invalid name"),
            }),
        );
    }
    // Go: if dir == "." { return fsys, nil }
    if dir.as_bytes() == b"." {
        return (fsys, errors::nil);
    }
    // Go: if fsys, ok := fsys.(SubFS); ok { return fsys.Sub(dir) }
    let (sfs, ok) = goish::cast!(&*fsys, SubFS);
    if ok {
        return sfs.Sub(dir);
    }
    register_subfs_impls();
    (Arc::new(subFS { fsys, dir }), errors::nil)
}

// Go: `type subFS struct { fsys FS; dir string }` (sub.go:53)
struct subFS {
    fsys: Arc<dyn FS + Send + Sync>,
    dir: string,
}

impl subFS {
    // Go: subFS.fullName (sub.go:59) — maps name to the fully
    // qualified name dir/name.
    fn full_name(&self, op: &'static str, name: &string) -> (string, error) {
        if !ValidPath(name.clone()) {
            return (
                string::new(),
                errors::Wrap(PathError {
                    Op: string::from_static(op),
                    Path: name.clone(),
                    Err: errors::New("invalid name"),
                }),
            );
        }
        // Go routes through path.Join, which cleans "." away; the
        // common case is special-cased here instead.
        if name.as_bytes() == b"." {
            return (self.dir.clone(), errors::nil);
        }
        let mut joined: Vec<u8> = Vec::new();
        joined.extend_from_slice(self.dir.as_bytes());
        joined.push(b'/');
        joined.extend_from_slice(name.as_bytes());
        (string::from_bytes(&joined), errors::nil)
    }
}

impl FS for subFS {
    fn Open(&self, name: string) -> (Arc<dyn File + Send + Sync>, error) {
        let (full, err) = self.full_name("open", &name);
        if err != errors::nil {
            return (crate::nil.into(), err);
        }
        self.fsys.Open(full)
    }
    fn __goish_as_dyn_any(&self) -> Option<&(dyn core::any::Any + Send + Sync)> {
        Some(self)
    }
}

impl ReadDirFS for subFS {
    fn Open(&self, name: string) -> (Arc<dyn File + Send + Sync>, error) {
        FS::Open(self, name)
    }
    fn ReadDir(&self, name: string) -> (slice<Arc<dyn DirEntry + Send + Sync>>, error) {
        let (full, err) = self.full_name("readdir", &name);
        if err != errors::nil {
            return (slice::new(), err);
        }
        ReadDir(&*self.fsys, full)
    }
    fn __goish_as_dyn_any(&self) -> Option<&(dyn core::any::Any + Send + Sync)> {
        Some(self)
    }
}

impl ReadFileFS for subFS {
    fn Open(&self, name: string) -> (Arc<dyn File + Send + Sync>, error) {
        FS::Open(self, name)
    }
    fn ReadFile(&self, name: string) -> (slice<byte>, error) {
        let (full, err) = self.full_name("readfile", &name);
        if err != errors::nil {
            return (slice::new(), err);
        }
        ReadFile(&*self.fsys, full)
    }
    fn __goish_as_dyn_any(&self) -> Option<&(dyn core::any::Any + Send + Sync)> {
        Some(self)
    }
}

impl StatFS for subFS {
    fn Open(&self, name: string) -> (Arc<dyn File + Send + Sync>, error) {
        FS::Open(self, name)
    }
    fn Stat(&self, name: string) -> (Arc<dyn FileInfo + Send + Sync>, error) {
        let (full, err) = self.full_name("stat", &name);
        if err != errors::nil {
            return (crate::nil.into(), err);
        }
        Stat(&*self.fsys, full)
    }
    fn __goish_as_dyn_any(&self) -> Option<&(dyn core::any::Any + Send + Sync)> {
        Some(self)
    }
}

fn register_subfs_impls() {
    __goish_register_ReadDirFS_impl::<subFS>();
    __goish_register_ReadFileFS_impl::<subFS>();
    __goish_register_StatFS_impl::<subFS>();
}

// Suppress unused-import warnings for items pulled in for completeness.
#[allow(dead_code)]
fn _unused_imports() {
    let _: int = 0;
    let _: rune = 'a' as rune;
    let _v: Vec<u8> = Vec::new();
    let _s: slice<byte> = slice::__from_vec(_v);
}

// goishlint:ignore GOISH021 GlobFS — Go's optional fast-path interface,
// which `Glob` type-asserts on so a filesystem can answer directly.
// goish has no such trait, so `Glob` always takes the ReadDir
// traversal; adding an interface nothing implements would be a
// declaration with no behaviour behind it.
// ─── glob.go ─────────────────────────────────────────────────────────

// go: sdk 1.25.5 io/fs/glob.go:33-35 Glob
/// Go: "Glob returns the names of all files matching pattern or nil if
/// there is no matching file. The syntax of patterns is the same as in
/// path.Match. The pattern may describe hierarchical names such as
/// usr/*/bin/ed.
///
/// Glob ignores file system errors such as I/O errors reading
/// directories. The only possible returned error is path.ErrBadPattern,
/// reporting that the pattern is malformed."
///
/// Deviation: Go first checks whether `fsys` implements `GlobFS` and
/// delegates. goish has no `GlobFS` trait yet, so it always takes the
/// ReadDir traversal — the same results, without a filesystem's chance
/// to answer faster.
pub fn Glob<S: Into<string>>(
    fsys: &(dyn FS + Send + Sync + 'static),
    pattern: S,
) -> (slice<string>, error) {
    return globWithLimit(fsys, pattern.into(), 0);
}

// go: sdk 1.25.5 io/fs/glob.go:37-83 globWithLimit
/// Go: the recursive worker behind `Glob`.
///
/// The depth limit is not decoration: Go added it for CVE-2022-30630,
/// where a pattern with enough separators drove `globWithLimit` deep
/// enough to exhaust the stack. goish's goroutine stacks are smaller
/// than Go's grow-on-demand ones, so if anything it matters more here.
fn globWithLimit(
    fsys: &(dyn FS + Send + Sync + 'static),
    pattern: string,
    depth: int,
) -> (slice<string>, error) {
    // Go: "This limit is added to prevent stack exhaustion issues. See
    // CVE-2022-30630."
    const pathSeparatorsLimit: int = 10000;
    if depth > pathSeparatorsLimit {
        return (slice::new(), crate::path::ErrBadPattern.clone().into());
    }

    // Go: check pattern is well-formed.
    let (_, err) = crate::path::Match(pattern.clone(), string::from_static(""));
    if err != errors::nil {
        return (slice::new(), err);
    }

    if !hasMeta(pattern.clone()) {
        // Go: if _, err = Stat(fsys, pattern); err != nil {
        //         return nil, nil }
        //     return []string{pattern}, nil
        //
        // Note the discarded error: a pattern with no metacharacters
        // that names nothing is "no matches", not a failure.
        let (_, serr) = Stat(fsys, pattern.clone());
        if serr != errors::nil {
            return (slice::new(), errors::nil);
        }
        return (slice::__from_vec(alloc::vec![pattern]), errors::nil);
    }

    let (dir, file) = crate::path::Split(pattern.clone());
    let dir = cleanGlobPath(dir);

    if !hasMeta(dir.clone()) {
        return glob(fsys, dir, file, slice::new());
    }

    // Go: "Prevent infinite recursion. See issue 15879."
    if dir == pattern {
        return (slice::new(), crate::path::ErrBadPattern.clone().into());
    }

    let (m, err) = globWithLimit(fsys, dir, depth + 1);
    if err != errors::nil {
        return (slice::new(), err);
    }
    let mut matches: slice<string> = slice::new();
    for i in 0..m.Len() {
        let (next, gerr) = glob(fsys, m[i].clone(), file.clone(), matches);
        if gerr != errors::nil {
            return (next, gerr);
        }
        matches = next;
    }
    return (matches, errors::nil);
}

// go: sdk 1.25.5 io/fs/glob.go:86-93 cleanGlobPath
/// Go: "cleanGlobPath prepares path for glob matching."
fn cleanGlobPath(p: string) -> string {
    // Go: case "": return "."
    //     default: return path[0 : len(path)-1]  // chop off trailing separator
    if p.Len() == 0 {
        return string::from_static(".");
    }
    let b = p.as_bytes();
    return string::from_bytes(&b[..b.len() - 1]);
}

// go: sdk 1.25.5 io/fs/glob.go:99-117 glob
/// Go: "glob searches for files matching pattern in the directory dir
/// and appends them to matches, returning the updated slice. If the
/// directory cannot be opened, glob returns the existing matches. New
/// matches are added in lexicographical order."
fn glob(
    fsys: &(dyn FS + Send + Sync + 'static),
    dir: string,
    pattern: string,
    matches: slice<string>,
) -> (slice<string>, error) {
    let mut m = matches;
    let (infos, err) = ReadDir(fsys, dir.clone());
    if err != errors::nil {
        // Go: return  // ignore I/O error
        return (m, errors::nil);
    }

    for i in 0..infos.Len() {
        let n = infos[i].Name();
        let (matched, merr) = crate::path::Match(pattern.clone(), n.clone());
        if merr != errors::nil {
            return (m, merr);
        }
        if matched {
            m = crate::append!(
                m,
                crate::path::Join(slice::__from_vec(alloc::vec![dir.clone(), n]))
            );
        }
    }
    return (m, errors::nil);
}

// go: sdk 1.25.5 io/fs/glob.go:121-129 hasMeta
/// Go: "hasMeta reports whether path contains any of the magic
/// characters recognized by path.Match."
fn hasMeta(p: string) -> bool {
    let b = p.as_bytes();
    for i in 0..b.len() {
        match b[i] {
            b'*' | b'?' | b'[' | b'\\' => {
                return true;
            }
            _ => {}
        }
    }
    return false;
}

// go: sdk 1.25.5 io/fs/format.go:17-52 FormatFileInfo
/// Go: "FormatFileInfo returns a formatted version of info for human
/// readability. Implementations of FileInfo can call this from a String
/// method. The output for a file named "hello.go", 100 bytes, mode
/// 0o644, created January 1, 1970 at noon is
///
///	-rw-r--r-- 100 1970-01-01 12:00:00 hello.go"
///
/// **Known divergence, inherited from `time`.** Go's zero `time.Time`
/// is 0001-01-01T00:00:00Z; goish's `Time` stores `sec` as *Unix*
/// seconds, so its zero is 1970-01-01T00:00:00Z. A FileInfo with no
/// ModTime therefore formats as `1970-01-01 00:00:00` here and
/// `0001-01-01 00:00:00` in Go. Every other field matches byte for
/// byte. This is a `time` representation choice, not something this
/// function can correct — see examples/io_fs_format_smoke.rs.
///
/// The size is rendered by hand rather than through strconv, and Go
/// keeps a leading `-` for a negative size instead of refusing it —
/// FileInfo.Size() is system-dependent for non-regular files, so a
/// formatter that panicked on one would be useless exactly where it is
/// most needed.
pub fn FormatFileInfo(info: &(dyn FileInfo + Send + Sync)) -> string {
    let name = info.Name();
    let mut b: alloc::vec::Vec<byte> = alloc::vec::Vec::new();
    b.extend_from_slice(info.Mode().String().as_bytes());
    b.push(b' ');

    // Go: if size >= 0 { usize = uint64(size) }
    //     else { b = append(b, '-'); usize = uint64(-size) }
    let size = info.Size();
    let mut usize_: u64;
    if size >= 0 {
        usize_ = crate::uint64(size);
    } else {
        b.push(b'-');
        usize_ = crate::uint64(-size);
    }
    let mut buf = [0u8; 20];
    let mut i = buf.len() - 1;
    while usize_ >= 10 {
        let q = usize_ / 10;
        buf[i] = b'0' + u8::try_from(usize_ - q * 10).unwrap_or(0);
        i -= 1;
        usize_ = q;
    }
    buf[i] = b'0' + u8::try_from(usize_).unwrap_or(0);
    b.extend_from_slice(&buf[i..]);
    b.push(b' ');

    b.extend_from_slice(
        info.ModTime()
            .Format(string::from_static(crate::time::DateTime))
            .as_bytes(),
    );
    b.push(b' ');

    b.extend_from_slice(name.as_bytes());
    if info.IsDir() {
        b.push(b'/');
    }

    return string::from_bytes(&b);
}

// go: sdk 1.25.5 io/fs/format.go:60-76 FormatDirEntry
/// Go: "FormatDirEntry returns a formatted version of dir for human
/// readability. Implementations of DirEntry can call this from a String
/// method. The outputs for a directory named subdir and a file named
/// hello.go are:
///
///	d subdir/
///	- hello.go"
///
/// Note the mode is truncated by exactly nine characters. `Type()`
/// returns only the type bits, so its `String()` still renders the nine
/// permission positions as dashes; Go strips them rather than printing
/// `d--------- subdir/`.
pub fn FormatDirEntry(dir: &(dyn DirEntry + Send + Sync)) -> string {
    let name = dir.Name();
    let mut b: alloc::vec::Vec<byte> = alloc::vec::Vec::new();

    // Go: "The Type method does not return any permission bits, so
    // strip them from the string."
    let mode = dir.Type().String();
    let mb = mode.as_bytes();
    let keep = if mb.len() >= 9 { mb.len() - 9 } else { 0 };
    b.extend_from_slice(&mb[..keep]);
    b.push(b' ');
    b.extend_from_slice(name.as_bytes());
    if dir.IsDir() {
        b.push(b'/');
    }
    return string::from_bytes(&b);
}
