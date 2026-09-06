// os — Go's `os` package, ported.
//
// ─── What has been diffed against Go, 2026-09-05 ─────────────────────
//
// 61 of this file's exported functions carry no provenance anchor, so
// no coverage, anchor or body-diff tier compares them to Go. A sample
// was read by hand against os/file.go, os/file_unix.go and
// os/file_posix.go. One defect, five confirmed:
//
//   FIXED  the FileMode -> syscall conversion dropped setuid, setgid
//          and sticky. Four call sites shared the bug; `syscallMode`
//          is now ported and all four use it. See the note there and
//          examples/os_filemode_bits_smoke.rs.
//
//   clean  WriteFile opens O_WRONLY|O_CREATE|O_TRUNC and Create
//          O_RDWR|O_CREATE|O_TRUNC, so neither leaves a tail of an
//          older, longer file behind.
//   clean  Readlink grows its buffer from 128 and returns only when
//          `n < len`, so a long target is not silently truncated.
//   clean  Remove tries unlink then rmdir and picks the error Go picks,
//          ENOTDIR subtlety included.
//   clean  Chown passes -1 through as "leave unchanged" rather than
//          converting it to 0; verified against a running Go, where
//          the no-op succeeds and chowning to root is refused.
//
// ─── Continued 2026-09-06 ────────────────────────────────────────────
//
//   FIXED  ReadFile sized its buffer to Stat().Size() and read exactly
//          that many bytes. Go treats the stat size as a CAPACITY HINT
//          and reads to EOF — `statOrZero` returns 0 when Stat fails
//          rather than erroring. So every file whose stat size is 0 but
//          which yields data came back EMPTY: all of /proc and /sys.
//          Go's own comment names the case. It also truncated any file
//          that grew between the stat and the read. Now anchored, with
//          Go's minBuf growth, and pinned by
//          examples/os_readfile_ref_smoke.rs — the probe is
//          /proc/sys/kernel/ostype, which stats as 0 and reads back
//          "Linux\n" on every Linux, so the row is machine-independent.
//
//   FIXED  Rename answered "file exists" for Rename(missing, dir). Go
//          re-stats oldname when newname is an existing directory and
//          reports THAT error first. The doc note called the omission a
//          case-sensitivity simplification, which covered the SameFile
//          half and hid the priority half. Pinned by a new
//          rename/missingoverdir row in os_link_ref_smoke.
//   FIXED  Chtimes rejected any pre-1970 time with a fractional part.
//          NsecToTimespec's negative-remainder correction was missing,
//          so tv_nsec went negative and utimensat returned EINVAL. A
//          whole-second pre-1970 time has remainder 0 and always
//          worked, which is why it took the fractional case to surface.
//          Pinned by examples/os_chtimes_ref_smoke.rs.
//
//   FIXED  dirFS.join, the DirFS sandbox boundary, was missing both of
//          Go's checks. An EMPTY root produced "/" + name — an absolute
//          path from the filesystem root — so DirFS("") read anything
//          the process could. And the name was validated with
//          fs::ValidPath alone, where Go uses Localize = ValidPath PLUS
//          a NUL rejection: ValidPath checks path ELEMENTS, not bytes,
//          so "f\0junk" passed and the kernel truncated it at the C
//          string boundary. Measured: a request naming "f\0ignored"
//          returned the contents of "f" — the file opened was not the
//          file validated. All four entry points (Open, Stat, ReadFile,
//          ReadDir) route through this one join, checked by reading
//          every call site. Pinned by examples/os_dirfs_ref_smoke.rs.
//
//   clean  ReadDir sorts by name in Go's byte order.
//   clean  Symlink and Link both build a *LinkError carrying both paths.
//   clean  OpenFile sets O_CLOEXEC on every open, as Go does.
//   clean  UserHomeDir, UserCacheDir and UserConfigDir match Go's env
//          precedence, its "neither $X nor $HOME are defined" text and
//          its "path in $X is relative" absoluteness check.
//   clean  Executable trims the " (deleted)" suffix procfs appends.
//   clean  Pipe uses pipe2 with O_CLOEXEC and keeps the errno.
//   clean  TempDir honours TMPDIR and falls back to /tmp.
//
//   NOTE   Hostname calls uname and stops there. Go tries uname first
//          and falls back to reading /proc/sys/kernel/hostname when the
//          name is absent or 64 bytes (possibly truncated, since
//          Nodename is 65). Unreachable on Linux in practice — uname
//          does not fail here and HOST_NAME_MAX is 64, so the fallback
//          would return the same bytes — but the error path also
//          returns a bare "uname failed" rather than the errno.
//
// The rest of the 61 have NOT been read. This note records where the
// sample stopped, not that the file is clear.
//
//   Go                                   goish
//   ──────────────────────────────────   ──────────────────────────────────
//   var Stdin, Stdout, Stderr *File      pub fn Stdin/Stdout/Stderr() -> File
//   var Args []string                    pub fn Args() -> slice<string>
//   func Exit(code int)                  pub fn Exit(code: int) -> !
//   type File struct { ... }             pub struct File { fd: i32, name: string }
//
// `File` wraps a raw fd. It implements `io::Reader` and `io::Writer`,
// so the standard streams flow into `fmt::Fprintln`, `io::Copy`, etc.
//
// Stdin/Stdout/Stderr are *not* globals (Rust's strict static-init
// semantics make immortal-fd File constants awkward). Instead they're
// factory functions that construct fresh `File` values each call —
// since `File` is just `{fd, name}`, the cost is two atomic ops on the
// name's Arc clone. Callers can store the result in a `let` once.
//
// Drop semantics: `File::Close` is explicit; `Drop` is *not*
// implemented for v1 — fds aren't auto-closed on scope exit. This
// matches Go's "must call Close" expectation; finalizer-driven close
// (Go's GC pattern) is out of scope without a GC equivalent.

#![allow(non_snake_case)]

mod dir;
pub use dir::CopyFS;

pub mod exec;
pub mod exec_posix;
pub mod signal;
pub mod user;

use crate::error;
use crate::gonilable::nilable;
use crate::goslice::slice;
// `crate::string` resolves both the type (gostring) and the function
// (convert) — different namespaces, both re-exported at root.
use crate::errors::{self, nil};
use crate::io;
use crate::runtime;
use crate::string;
use crate::syscall;
use crate::types::{byte, int};

extern crate alloc;
use alloc::vec::Vec;

// ─── FileMode ──────────────────────────────────────────────────────────

/// `os.FileMode` (os/types.go:34) — file mode bits. Goish slim: just
/// the high-level flag bits; permission bits in the low 9.
///
/// Re-exports the `io/fs.FileMode` newtype so `os.FileMode` and
/// `fs.FileMode` refer to the same Rust type (matching Go where
/// `os.FileMode` is a type alias for `fs.FileMode`). The unification
/// is required by ports that pass FileMode values across the
/// `os`/`io/fs` boundary (lockedfile, renameio, walkdir) and ensures
/// FileMode methods (`IsDir`, `IsRegular`, `Perm`, `Type`, `String`)
/// resolve identically regardless of import path.
pub use crate::io::fs::FileMode;
// Go: os/types.go:35-53 re-declares ALL of io/fs's mode bits as
// `os.ModeX = fs.ModeX`. goish re-exported four of the fifteen, so
// `os::ModeNamedPipe` and `os::ModeCharDevice` — among others — did not
// exist under the name Go gives them.
pub use crate::io::fs::{
    ModeAppend, ModeCharDevice, ModeDevice, ModeDir, ModeExclusive, ModeIrregular, ModeNamedPipe,
    ModePerm, ModeSetgid, ModeSetuid, ModeSocket, ModeSticky, ModeSymlink, ModeTemporary, ModeType,
};

// Go: os/types.go declares these as untyped int. Goish ships them
// as `int` (= i64) so port-side `var flag int = os.O_RDWR | os.O_TRUNC`
// arithmetic stays width-uniform without per-callsite `as i32` casts.
pub const O_RDONLY: int = syscall::O_RDONLY as int;
pub const O_WRONLY: int = 0o1;
pub const O_RDWR: int = 0o2;
pub const O_CREATE: int = 0o100;
pub const O_TRUNC: int = 0o1000;
pub const O_APPEND: int = 0o2000;
pub const O_EXCL: int = 0o200;
pub const O_SYNC: int = 0o4010000;

pub const PathSeparator: u8 = b'/';
pub const PathListSeparator: u8 = b':';

/// `os.IsPathSeparator(c)` (path_unix.go:14) — reports whether `c` is
/// the OS's path separator. Linux-pinned in goish v1, so just `c == '/'`.
#[inline]
pub fn IsPathSeparator(c: u8) -> bool {
    return c == PathSeparator;
}

// os/error.go — the error sentinels, the PathError alias, SyscallError
// and the historical Is* predicates.
#[path = "error.rs"]
mod error_go;
pub use error_go::*;

// go: sdk 1.25.5 os/file.go:103-108 LinkError
/// Go: "LinkError records an error during a link or symlink or rename
/// system call and the paths that caused it."
///
/// goish had no such type: `Link`, `Symlink` and `Rename` all returned
/// `errors.New("link failed")` and friends, naming neither path. Go's
/// `underlyingError` has a `case *LinkError` arm precisely so that
/// `os.IsExist` on a failed rename can see the EEXIST underneath.
#[derive(Clone, Default)]
pub struct LinkError {
    pub Op: string,
    pub Old: string,
    pub New: string,
    pub Err: error,
}

impl errors::ErrorTrait for LinkError {
    // go: sdk 1.25.5 os/file.go:110-112 LinkError.Error
    fn Error(&self) -> string {
        // Go: e.Op + " " + e.Old + " " + e.New + ": " + e.Err.Error()
        let mut out: Vec<u8> = Vec::new();
        out.extend_from_slice(self.Op.as_bytes());
        out.push(b' ');
        out.extend_from_slice(self.Old.as_bytes());
        out.push(b' ');
        out.extend_from_slice(self.New.as_bytes());
        out.extend_from_slice(b": ");
        out.extend_from_slice(self.Err.Error().as_bytes());
        return string::from_bytes(&out);
    }

    // go: sdk 1.25.5 os/file.go:114-116 LinkError.Unwrap
    fn Unwrap(&self) -> error {
        return self.Err.clone();
    }
}

// go: none — goish idiom: Go writes `&PathError{Op: …, Path: name, Err:
//     e}` inline at each call site because `e` is already an `error`
//     there. goish holds a negative kernel return code instead, so the
//     errno has to be rebuilt; doing that in one place keeps the
//     fifteen call sites from each inventing their own text, which is
//     how they came to say "chmod failed" in the first place.
fn pathErr(op: &'static str, path: string, rc: i32) -> error {
    return errors::Wrap(PathError {
        Op: string::from_static(op),
        Path: path,
        Err: syscall::Errno(-rc).into(),
    });
}

// go: none — goish idiom: goish's syscall wrappers return the raw
//     kernel value, and its width varies with the call — `i32` from
//     `Chdir`, `i64` from `Getdents64`, `isize` from `Read`. A negative
//     one is `-errno`. This narrows whichever it is to the `i32` that
//     `syscall::Errno` is declared over, in one place, so the twelve
//     `fdErr` call sites do not each write a cast. Go has no
//     counterpart: its syscall layer hands the caller an `error`.
trait KernelRC {
    fn rc(self) -> i32;
}

impl KernelRC for i32 {
    // go: none — goish idiom: see the trait above.
    fn rc(self) -> i32 {
        return self;
    }
}
impl KernelRC for i64 {
    // go: none — goish idiom: see the trait above.
    fn rc(self) -> i32 {
        return self as i32; // goishlint:ignore GOISH005 - a kernel return code, not a Go value.
    }
}
impl KernelRC for isize {
    // go: none — goish idiom: see the trait above.
    fn rc(self) -> i32 {
        return self as i32; // goishlint:ignore GOISH005 - a kernel return code, not a Go value.
    }
}

// go: none — goish idiom: the two-path form of `pathErr` above.
fn linkErr(op: &'static str, old: string, new: string, rc: i32) -> error {
    return errors::Wrap(LinkError {
        Op: string::from_static(op),
        Old: old,
        New: new,
        Err: syscall::Errno(-rc).into(),
    });
}

// ─── FileInfo (alias + concrete) ──────────────────────────────────────
//
// Go: `os.FileInfo` is an exact type alias for `fs.FileInfo`
// (os/types.go:18). goish mirrors this — `io/fs` owns the
// `#[goish::interface]` trait, `os` re-exports it. The concrete
// `FileInfoData` carries the fields cached by stat(2) / fstat(2) and
// implements that interface; ports receive a trait object via
// `dyn fs::FileInfo + Send + Sync` and can downcast through `Any`.

/// `os.FileInfo` (os/types.go:18) — type alias for [`io::fs::FileInfo`].
pub use crate::io::fs::FileInfo;

/// Concrete `FileInfo` impl carrying the fields cached by stat(2).
/// `os::Stat` and `(*File).Stat()` return this type; ports that
/// receive a trait object via Goish's `dyn FileInfo + Send + Sync`
/// can downcast through `core::any::Any` if they need the data form.
#[derive(Clone, Default)]
pub struct FileInfoData {
    name: string,
    size: int,
    mode: FileMode,
    mod_time: crate::time::Time,
    is_dir: bool,
    /// Go's `fileStat.sys` — the raw `syscall.Stat_t` that `Sys()`
    /// hands back and that `SameFile` compares.
    ///
    /// This kept only `(dev, ino)`, the pair `SameFile` needs, on the
    /// grounds that "the rest of the struct is already unpacked into
    /// the fields above". It is not: `st_uid`, `st_gid`, `st_rdev` and
    /// the atime/ctime pairs have no field here, and `Sys()` is the
    /// only way Go exposes them. `archive/tar`'s `statUnix` reads
    /// exactly those to fill a header's Uid, Gid, Uname, Gname,
    /// AccessTime and ChangeTime, all of which came back zero.
    sys: Option<syscall::Stat_t>,
}

// Polymorphic-nil per priority #5. Go's `os.FileInfo` is an interface
// — callers pass `nil` for "no info"; in goish we materialise that as
// a zero-valued FileInfoData (Name() == "", Size() == 0, IsDir() == false).
impl From<crate::nilval::Nil> for FileInfoData {
    fn from(_: crate::nilval::Nil) -> Self {
        Self::default()
    }
}
impl PartialEq<crate::nilval::Nil> for FileInfoData {
    fn eq(&self, _: &crate::nilval::Nil) -> bool {
        self.name == "" && self.size == 0
    }
}
impl PartialEq<FileInfoData> for crate::nilval::Nil {
    fn eq(&self, other: &FileInfoData) -> bool {
        other == self
    }
}

// `io/fs::FileInfo` is a `#[goish::interface]` trait, so the concrete
// impl carries the boilerplate the transpiler emits for hand-written
// interface impls: `__goish_as_dyn_any` returns `Some(self)` so a
// trait-borrow can downcast back to `FileInfoData`. Registration into
// the per-trait downcast registry happens lazily — see `register_os_fs_impls`.
impl FileInfo for FileInfoData {
    fn Name(&self) -> string {
        self.name.clone()
    }
    fn Size(&self) -> int {
        self.size
    }
    fn Mode(&self) -> FileMode {
        self.mode
    }
    fn ModTime(&self) -> crate::time::Time {
        self.mod_time
    }
    fn IsDir(&self) -> bool {
        self.is_dir
    }
    fn Sys(&self) -> alloc::sync::Arc<dyn core::any::Any + Send + Sync> {
        // Forward. This used to return `Arc::new(())` of its own while
        // the inherent `Sys` below returned the real stat — so the
        // answer depended on whether the caller held a `FileInfoData`
        // or an `fs::FileInfo`, and Go's own callers hold the
        // interface. `archive/tar`'s statUnix is one: it reads the
        // owner and the atime/ctime through `fi.Sys()` and got an
        // empty tuple every time.
        return FileInfoData::Sys(self);
    }
    fn __goish_as_dyn_any(&self) -> Option<&(dyn core::any::Any + Send + Sync)> {
        Some(self)
    }
}

// Field-access inherent methods so callers that already hold the
// concrete `FileInfoData` value (the common case via os::Stat) keep
// using Go-style call syntax `info.Name()` without an explicit
// `.as_dyn_FileInfo()` step.
impl FileInfoData {
    /// Construct a FileInfoData from raw parts (for in-memory filesystem implementations).
    pub fn new(
        name: string,
        size: int,
        mode: FileMode,
        mod_time: crate::time::Time,
        is_dir: bool,
    ) -> FileInfoData {
        FileInfoData {
            name,
            size,
            mode,
            mod_time,
            is_dir,
            // An in-memory FileInfo has no kernel identity, so it is
            // never the same file as anything — including itself, which
            // is what Go's type assertion in SameFile also produces for
            // a non-*fileStat.
            sys: None,
        }
    }

    pub fn Name(&self) -> string {
        self.name.clone()
    }
    pub fn Size(&self) -> int {
        self.size
    }
    pub fn Mode(&self) -> FileMode {
        self.mode
    }
    pub fn ModTime(&self) -> crate::time::Time {
        self.mod_time
    }
    pub fn IsDir(&self) -> bool {
        self.is_dir
    }
    // go: sdk 1.25.5 os/types_unix.go:26-26 fileStat.Sys
    /// Go: "Sys returns the underlying data source (can return nil)."
    /// On Unix that is the `*syscall.Stat_t`; goish hands back the
    /// identifying `(dev, ino)` pair it keeps, and `None` — Go's nil —
    /// for a FileInfo that never came from a stat.
    pub fn Sys(&self) -> alloc::sync::Arc<dyn core::any::Any + Send + Sync> {
        match self.sys {
            Some(st) => return alloc::sync::Arc::new(st),
            None => return alloc::sync::Arc::new(()),
        }
    }
}

// go: sdk 1.25.5 os/types.go:69-76 SameFile
/// Go: "SameFile reports whether fi1 and fi2 describe the same file.
/// For example, on Unix this means that the device and inode fields of
/// the two underlying structures are identical; on other systems the
/// decision may be based on the path names. SameFile only applies to
/// results returned by this package's Stat. It returns false in other
/// cases."
///
/// That last sentence is the load-bearing one: Go type-asserts both
/// arguments to `*fileStat` and returns false if either is not one. A
/// FileInfo from an in-memory filesystem is never the same file as
/// anything, INCLUDING ITSELF — which is why goish keeps `sys: None`
/// for those and answers false rather than comparing the paths.
pub fn SameFile(fi1: &FileInfoData, fi2: &FileInfoData) -> bool {
    // Go compares the whole `*syscall.Stat_t` pair through
    // `sameFile`, which on Unix is exactly dev+ino — the two fields
    // that identify a file. The rest of the struct (size, times) can
    // differ between two stats of the same file, so comparing it all
    // would be wrong.
    match (fi1.sys, fi2.sys) {
        (Some(a), Some(b)) => return a.st_dev == b.st_dev && a.st_ino == b.st_ino,
        _ => return false,
    }
}

fn fileinfo_from_stat(name: string, st: &syscall::Stat_t) -> FileInfoData {
    let kind = st.st_mode & syscall::S_IFMT;
    let is_dir = kind == syscall::S_IFDIR;
    let mut mode: FileMode = FileMode((st.st_mode & 0o777) as u32);
    // Go: switch fs.sys.Mode & syscall.S_IFMT { … } — all seven arms.
    // goish had two, so `Stat` on a fifo, a socket or a device
    // reported a regular file: `prw-r--r--` came back as `-rw-r--r--`.
    // This is the same gap `direntType` had, in the other of the two
    // places a mode is built.
    if kind == syscall::S_IFBLK {
        mode |= ModeDevice;
    }
    if kind == syscall::S_IFCHR {
        mode |= ModeDevice;
        mode |= ModeCharDevice;
    }
    if is_dir {
        mode |= ModeDir;
    }
    if kind == syscall::S_IFIFO_M {
        mode |= ModeNamedPipe;
    }
    if kind == syscall::S_IFLNK {
        mode |= ModeSymlink;
    }
    if kind == syscall::S_IFSOCK_M {
        mode |= ModeSocket;
    }
    // Go: the three bits above the permission triplets.
    if st.st_mode & syscall::S_ISGID != 0 {
        mode |= ModeSetgid;
    }
    if st.st_mode & syscall::S_ISUID != 0 {
        mode |= ModeSetuid;
    }
    if st.st_mode & syscall::S_ISVTX != 0 {
        mode |= ModeSticky;
    }
    FileInfoData {
        name,
        size: st.st_size,
        mode,
        mod_time: crate::time::Unix(st.st_mtime, st.st_mtime_nsec as int),
        is_dir,
        sys: Some(*st),
    }
}

// ─── Open / Stat / Create ──────────────────────────────────────────────

/// `os.Open(name)` (os/file.go:386) — open `name` read-only.
///
/// Go's signature is `func Open(name string) (*File, error)`. Goish
/// returns `(nilable<File>, error)` end-to-end so transpiled call
/// sites read identically: `let (f, err) = os::Open(name);`.
pub fn Open<N: Into<string>>(name: N) -> (nilable<File>, error) {
    let name: string = name.into();
    OpenFile(name, O_RDONLY, FileMode(0))
}

/// `os.Create(name)` (os/file.go:402) — create or truncate `name`.
pub fn Create<N: Into<string>>(name: N) -> (nilable<File>, error) {
    let name: string = name.into();
    OpenFile(name, O_RDWR | O_CREATE | O_TRUNC, FileMode(0o666))
}

/// `os.OpenFile(name, flag, perm)` (os/file.go:412).
///
/// `perm: impl Into<FileMode>` so ports that pass a bare `0666` /
/// `0` integer literal (Go's untyped-int convenience) compile without
/// per-callsite `FileMode(…)` wrapping. FileMode-typed call sites
/// (e.g. `lockedfile.OpenFile(name, flag, perm)`) flow through the
/// identity `From<FileMode> for FileMode`.
pub fn OpenFile<N: Into<string>, M: Into<FileMode>>(
    name: N,
    flag: int,
    perm: M,
) -> (nilable<File>, error) {
    let name: string = name.into();
    let perm: FileMode = perm.into();
    // Build a NUL-terminated path for the kernel.
    let mut buf: Vec<u8> = Vec::with_capacity(name.Len() as usize + 1);
    let nb = bytes_of(&name);
    buf.extend_from_slice(nb);
    buf.push(0);
    let fd = syscall::Open(
        buf.as_ptr(),
        (flag as i32) | syscall::O_CLOEXEC,
        syscallMode(perm) as i32,
    );
    if fd < 0 {
        // Go: return nil, &PathError{Op: "open", Path: name, Err: e}.
        //
        // goish translated two errnos into the portable sentinels and
        // called everything else "open failed", so the message named
        // neither the file nor the reason — `open /etc/shadow:
        // permission denied` came back as "open failed" — and the two
        // it did translate lost the errno. The sentinels are reachable
        // from the PathError through `IsNotExist`/`errors::Is`, which
        // is how Go makes both answers available at once.
        return (
            crate::nilval::nil.into(),
            errors::Wrap(PathError {
                Op: string::from("open"),
                Path: name,
                Err: syscall::Errno(-fd).into(),
            }),
        );
    }
    (
        nilable::new(File {
            fd,
            name: name.clone(),
            dirinfo: None,
        }),
        nil,
    )
}

/// `os.Stat(name)` (os/stat.go:14) — stat a path, following symlinks.
pub fn Stat<N: Into<string>>(name: N) -> (FileInfoData, error) {
    let name: string = name.into();
    let mut buf: Vec<u8> = Vec::with_capacity(name.Len() as usize + 1);
    let nb = bytes_of(&name);
    buf.extend_from_slice(nb);
    buf.push(0);
    let mut st = syscall::Stat_t::default();
    let rc = syscall::Stat(buf.as_ptr(), &mut st);
    if rc < 0 {
        // Go: return nil, &PathError{Op: "stat", Path: name, Err: e}.
        let err: error = errors::Wrap(PathError {
            Op: string::from("stat"),
            Path: name.clone(),
            Err: syscall::Errno(-rc).into(),
        });
        return (
            FileInfoData {
                name: name.clone(),
                size: 0,
                mode: FileMode(0),
                mod_time: crate::time::Time::default(),
                is_dir: false,
                sys: None,
            },
            err,
        );
    }
    let base = base_name(&name);
    (fileinfo_from_stat(base, &st), nil)
}

/// Line-by-line port of `os.Lstat(name)` (file.go:417 → stat_unix.go).
/// Like Stat but does not follow a final-component symlink, so
/// FileInfo.Mode() reports ModeSymlink for a link target.
pub fn Lstat<N: Into<string>>(name: N) -> (FileInfoData, error) {
    let name: string = name.into();
    // Go: return statNolog(name) with AT_SYMLINK_NOFOLLOW.
    let mut buf: Vec<u8> = Vec::with_capacity(name.Len() as usize + 1);
    let nb = bytes_of(&name);
    buf.extend_from_slice(nb);
    buf.push(0);
    let mut st = syscall::Stat_t::default();
    let rc = syscall::Lstat(buf.as_ptr(), &mut st);
    if rc < 0 {
        return (
            FileInfoData {
                name: name.clone(),
                size: 0,
                mode: FileMode(0),
                mod_time: crate::time::Time::default(),
                is_dir: false,
                sys: None,
            },
            // Go: &PathError{Op: "lstat", Path: name, Err: e}. goish
            // returned one flat "lstat failed" for every errno, so
            // `IsNotExist` on a missing path was false here even
            // though it was true for the same path through `Stat`.
            errors::Wrap(PathError {
                Op: string::from("lstat"),
                Path: name.clone(),
                Err: syscall::Errno(-rc).into(),
            }),
        );
    }
    let base = base_name(&name);
    (fileinfo_from_stat(base, &st), nil)
}

impl File {
    // go: sdk 1.25.5 os/file.go:469-479 File.wrapErr
    /// Go: every `*File` method routes its error through here, so the
    /// caller gets `read /etc/passwd: bad file descriptor` and not a
    /// bare errno. goish's methods returned `errors.New("read failed")`
    /// and the bare `ErrClosed` sentinel — no path, no errno, nothing
    /// `errors::As` could inspect.
    ///
    /// Go's `poll.ErrFileClosing → ErrClosed` remap has no counterpart
    /// here: goish has no poller, and a closed `File` is `fd < 0`,
    /// which [`fdErr`](File::fdErr) turns into `ErrClosed` directly.
    fn wrapErr(&self, op: &'static str, err: error) -> error {
        // Go: if err == nil || err == io.EOF { return err }
        if err.IsNil() || err == io::EOF {
            return err;
        }
        return errors::Wrap(PathError {
            Op: string::from_static(op),
            Path: self.name.clone(),
            Err: err,
        });
    }

    // go: none — goish idiom: Go's `*File` methods get their error from
    //     `internal/poll`, which reports a closed descriptor as
    //     `ErrFileClosing` and everything else as an errno. goish calls
    //     the kernel directly and marks a closed file with `fd < 0`, so
    //     the same two cases are decided here.
    fn fdErr<R: KernelRC>(&self, op: &'static str, rc: R) -> error {
        if self.fd < 0 {
            return self.wrapErr(op, ErrClosed.into());
        }
        return self.wrapErr(op, syscall::Errno(-rc.rc()).into());
    }

    /// `(*File).Stat()` (os/file.go:432) — fstat the open fd.
    pub fn Stat(&self) -> (FileInfoData, error) {
        let mut st = syscall::Stat_t::default();
        let rc = syscall::Fstat(self.fd, &mut st);
        if rc < 0 {
            return (
                FileInfoData {
                    name: self.name.clone(),
                    size: 0,
                    mode: FileMode(0),
                    mod_time: crate::time::Time::default(),
                    is_dir: false,
                    sys: None,
                },
                self.fdErr("stat", rc),
            );
        }
        let base = base_name(&self.name);
        (fileinfo_from_stat(base, &st), nil)
    }

    /// `(*File).Readdirnames(n)` (os/dir.go:46).
    /// Returns up to `n` directory entry names from the directory
    /// the receiver is open on. `n <= 0` reads all entries. Mirrors
    /// the Go shape `([]string, error)`. Names are unsorted (Go's
    /// contract).
    pub fn Readdirnames(&mut self, n: int) -> (slice<string>, error) {
        let mut names: Vec<string> = Vec::new();
        // Go's readdirent path builds its `*PathError` directly rather
        // than through `wrapErr`, so the `poll.ErrFileClosing →
        // ErrClosed` remap does NOT happen here: a closed directory
        // reads "use of closed file", not "file already closed". That
        // is a real difference in Go and it is reproduced, not tidied.
        if self.fd < 0 {
            return (
                slice::<string>::new(),
                self.wrapErr("readdirent", crate::internal::poll::ErrFileClosing.into()),
            );
        }
        // Go: "if this file has no dirInfo, create one."
        if self.dirinfo.is_none() {
            self.dirinfo = Some(dirInfo {
                buf: alloc::vec![0u8; 8192],
                nbuf: 0,
                bufp: 0,
            });
        }
        // Go: "Change the meaning of n for the implementation below …
        // we use only negative to mean looping until the end and
        // positive to mean bounded, with positive terminating at 0."
        let mut left: int = if n == 0 { -1 } else { n };
        let mut errored = nil;
        loop {
            if left == 0 {
                break;
            }
            let d = match self.dirinfo.as_mut() {
                Some(d) => d,
                None => break,
            };
            // Go: refill the buffer if necessary.
            if d.bufp >= d.nbuf {
                d.bufp = 0;
                let got = syscall::Getdents64(self.fd, d.buf.as_mut_ptr(), d.buf.len());
                if got < 0 {
                    // Go: &PathError{Op: "readdirent", Path: f.name, Err: errno}
                    errored = self.fdErr("readdirent", got);
                    break;
                }
                // Go: `d.nbuf, errno = f.pfd.ReadDirent(*d.buf)` assigns
                // FIRST and tests `d.nbuf <= 0` after. Assigning only on
                // a non-empty read leaves `nbuf` at the previous length
                // while `bufp` has just been reset to 0, so the next
                // call re-drains the buffer it already returned.
                d.nbuf = got as usize;
                if d.nbuf == 0 {
                    // Go: break // EOF
                    break;
                }
            }
            // Go: drain the buffer, one linux_dirent64 at a time.
            //   0  d_ino     u64
            //   8  d_off     i64
            //  16  d_reclen  u16
            //  18  d_type    u8
            //  19  d_name…   NUL-terminated
            let pos = d.bufp;
            let reclen = u16::from_ne_bytes([d.buf[pos + 16], d.buf[pos + 17]]) as usize;
            if reclen == 0 || pos + reclen > d.nbuf {
                break;
            }
            d.bufp += reclen;
            let name_start = pos + 19;
            let mut name_end = name_start;
            while name_end < pos + reclen && d.buf[name_end] != 0 {
                name_end += 1;
            }
            let raw = &d.buf[name_start..name_end];
            // Go: if string(name) == "." || string(name) == ".." { continue }
            // — and note the `continue` does NOT spend one of the n.
            if raw == b"." || raw == b".." {
                continue;
            }
            names.push(string::from_bytes(raw));
            left -= 1;
        }
        if !errored.IsNil() {
            return (slice::<string>::__from_vec(names), errored);
        }
        // Go: if n > 0 && len(names)+len(dirents)+len(infos) == 0 {
        //         return nil, nil, nil, io.EOF }
        //
        // goish returned nil here, so a caller draining a directory in
        // fixed-size batches — the reason the bounded form exists — had
        // no way to tell "no more entries" from "none this time".
        if n > 0 && names.is_empty() {
            return (slice::<string>::new(), io::EOF.into());
        }
        (slice::<string>::__from_vec(names), nil)
    }

    /// `(*File).Seek(offset, whence)` (os/file.go:286).
    pub fn Seek(&self, offset: int, whence: int) -> (int, error) {
        let rc = syscall::Lseek(self.fd, offset, whence as i32);
        if rc < 0 {
            return (0, self.fdErr("seek", rc));
        }
        (rc as int, nil)
    }
}

/// Pull the file path's bytes via the pub(crate) accessor.
fn bytes_of(s: &string) -> &[u8] {
    crate::gostring::__crate_as_bytes(s)
}

// go: sdk 1.25.5 os/file.go:867-875 ReadFile
// goishlint:ignore GOISH018 readFileContents, statOrZero — Go's two
//     helpers (os/file.go:889-928 and 877-882) are inlined into the
//     body below; `statOrZero`'s whole contract is "a failed Stat is
//     size 0, not an error", which is the `else 0` arm here.
/// `os.ReadFile(name)` — read the entire named file
/// and return its contents. Closes the file before returning.
pub fn ReadFile<N: Into<string>>(name: N) -> (slice<byte>, error) {
    let name: string = name.into();
    use crate::io::Reader;
    let (mut f, err) = Open(name);
    if !err.IsNil() {
        return (slice::<byte>::__from_vec(Vec::new()), err);
    }
    // err is nil ⇒ Open returned a non-nil File. Narrow.
    let f = f.MustMut();
    // Go: readFileContents(statOrZero(f), f.Read).
    //
    // The stat size is a CAPACITY HINT, not a limit: `statOrZero`
    // returns 0 when Stat fails rather than erroring, and the loop runs
    // until EOF. Sizing a buffer to Stat().Size() and reading exactly
    // that much — as this used to — returns EMPTY for every file whose
    // stat size is 0 but which yields data, which is all of /proc and
    // /sys. Go's own comment says so: "files in Linux's /proc claim
    // size 0 but then do not work right if read in small pieces". It
    // also truncated any file that grew between the stat and the read.
    let stat_size: int = {
        let (fi, ferr) = f.Stat();
        if ferr.IsNil() {
            fi.Size()
        } else {
            0
        }
    };
    let zero_size = stat_size == 0;
    // Go: const minBuf = 512
    let min_buf: usize = 512;
    // Go: size = int(statSize); size++ // one byte for final read at EOF
    let mut size = (stat_size as usize).saturating_add(1);
    if size < min_buf {
        size = min_buf;
    }
    let mut data: Vec<byte> = Vec::with_capacity(size);
    loop {
        // Go: read(data[len(data):cap(data)])
        let room = data.capacity() - data.len();
        let mut chunk = slice::<byte>::__from_vec(alloc::vec![0u8; room]);
        let (n, rerr) = f.Read(&mut chunk);
        let mut i: int = 0;
        while i < n {
            data.push(chunk[i]);
            i += 1;
        }
        if !rerr.IsNil() {
            let _ = f.Close();
            // Go: if err == io.EOF { err = nil }
            if crate::errors::Is(rerr.clone(), crate::io::EOF) {
                return (slice::<byte>::__from_vec(data), nil);
            }
            return (slice::<byte>::__from_vec(data), rerr);
        }
        // Go loops until an error, so a Reader returning (0, nil)
        // forever would hang there too. goish stops instead: the
        // io.Reader contract discourages that return, and a hung
        // example is a 15-second e2e timeout with no other signal.
        if n == 0 {
            let _ = f.Close();
            return (slice::<byte>::__from_vec(data), nil);
        }
        // Go: grow if out of capacity, or if a /proc-like zero-sized
        // file left less than minBuf — issue 72080 wants reads on those
        // issued with a non-tiny buffer.
        let cap_remain = data.capacity() - data.len();
        if cap_remain == 0 || (zero_size && cap_remain < min_buf) {
            data.reserve(min_buf);
        }
    }
}

// ─── Env ────────────────────────────────────────────────────────────
//
// os/env.go lives in env.rs — GOISH015 forbids anchored code in a
// module root.

#[path = "env.rs"]
mod env;
pub use env::*;

/// `os.TempDir()` (file.go:490) — TMPDIR if set, else "/tmp".
pub fn TempDir() -> string {
    let (v, ok) = LookupEnv(string("TMPDIR"));
    if ok && v.Len() > 0 {
        return v;
    }
    string("/tmp")
}

/// `os.UserHomeDir()` (os/file.go:608) — return the current user's home
/// directory.
///
/// Slim: Linux/Unix only — reads `$HOME`. If unset, returns
/// `("", "$HOME is not defined")`. The Windows / Plan 9 / Android / iOS
/// branches in upstream Go are not reached by this port (no GOOS).
pub fn UserHomeDir() -> (string, error) {
    // Go: env, enverr := "HOME", "$HOME"
    let env = string("HOME");
    let enverr = string("$HOME");
    // Go: if v := Getenv(env); v != "" { return v, nil }
    let v = Getenv(env);
    if v.Len() != 0 {
        return (v, nil);
    }
    // Go: return "", errors.New(enverr + " is not defined")
    let mut b = crate::strings::Builder::new();
    b.Grow(enverr.Len() + 16);
    let _ = b.WriteString(enverr);
    let _ = b.WriteString(string(" is not defined"));
    (string::new(), errors::New(b.String()))
}

/// Line-by-line port of `os.UserCacheDir()` (file.go:507) — return the
/// default root directory for user-specific cached data.
///
/// Slim: Linux/Unix only. Returns `$XDG_CACHE_HOME` if set and absolute,
/// otherwise `$HOME/.cache`. Errors if neither is defined or
/// `$XDG_CACHE_HOME` is relative.
pub fn UserCacheDir() -> (string, error) {
    // Go: dir = Getenv("XDG_CACHE_HOME")
    let dir = Getenv(string("XDG_CACHE_HOME"));
    // Go: if dir == "" { dir = Getenv("HOME"); if dir == "" { return "", errors.New(...) }; dir += "/.cache" }
    if dir.Len() == 0 {
        let home = Getenv(string("HOME"));
        if home.Len() == 0 {
            return (
                string::new(),
                errors::New(string("neither $XDG_CACHE_HOME nor $HOME are defined")),
            );
        }
        let mut b = crate::strings::Builder::new();
        b.Grow(home.Len() + 7);
        let _ = b.WriteString(home);
        let _ = b.WriteString(string("/.cache"));
        return (b.String(), nil);
    }
    // Go: else if !filepathlite.IsAbs(dir) { return "", errors.New("path in $XDG_CACHE_HOME is relative") }
    if !crate::path::filepath::IsAbs(dir.clone()) {
        return (
            string::new(),
            errors::New(string("path in $XDG_CACHE_HOME is relative")),
        );
    }
    (dir, nil)
}

/// Line-by-line port of `os.UserConfigDir()` (file.go:560) — return the
/// default root directory for user-specific configuration data.
///
/// Slim: Linux/Unix only. Returns `$XDG_CONFIG_HOME` if set and absolute,
/// otherwise `$HOME/.config`. Errors if neither is defined or
/// `$XDG_CONFIG_HOME` is relative.
pub fn UserConfigDir() -> (string, error) {
    // Go: dir = Getenv("XDG_CONFIG_HOME")
    let dir = Getenv(string("XDG_CONFIG_HOME"));
    // Go: if dir == "" { dir = Getenv("HOME"); if dir == "" { return "", errors.New(...) }; dir += "/.config" }
    if dir.Len() == 0 {
        let home = Getenv(string("HOME"));
        if home.Len() == 0 {
            return (
                string::new(),
                errors::New(string("neither $XDG_CONFIG_HOME nor $HOME are defined")),
            );
        }
        let mut b = crate::strings::Builder::new();
        b.Grow(home.Len() + 8);
        let _ = b.WriteString(home);
        let _ = b.WriteString(string("/.config"));
        return (b.String(), nil);
    }
    // Go: else if !filepathlite.IsAbs(dir) { return "", errors.New("path in $XDG_CONFIG_HOME is relative") }
    if !crate::path::filepath::IsAbs(dir.clone()) {
        return (
            string::new(),
            errors::New(string("path in $XDG_CONFIG_HOME is relative")),
        );
    }
    (dir, nil)
}

// go: sdk 1.25.5 os/getwd.go:26-149 Getwd
/// `os.Getwd()` — the current working directory. Go documents the
/// behaviour this way: "On Unix platforms, if the environment variable
/// PWD provides an absolute name, and it is a name of the current
/// directory, it is returned."
///
/// goish went straight to `getcwd(2)` and never looked at $PWD, so a
/// process whose cwd was reached THROUGH A SYMLINK got the physical
/// path where Go gives the symlinked one. Measured against Go 1.25.5
/// with the cwd inside `wd/link -> wd/real`:
///
///   $PWD names the cwd (via the symlink)   Go wd/link   goish wd/real
///   $PWD set but names another directory   Go wd/real   goish wd/real
///   $PWD unset                             Go wd/real   goish wd/real
///
/// Only the first diverged, and it is the common case: `cd` through a
/// symlink is how deploy layouts (`releases/current`), home
/// directories and container mounts are usually arranged, and the
/// shell exports $PWD as the logical path.
///
/// Go calls this "a clumsy but widespread kludge". It is load-bearing:
/// a program that prints its cwd, or joins it onto a relative path it
/// then shows a user, is expected to stay in the namespace the user
/// typed.
///
/// The check is dev+ino equality, via `SameFile` — not string
/// comparison — so a $PWD that merely LOOKS plausible does not win.
///
/// Not ported: Go's `getwdCache` fallback, which re-applies the same
/// kludge to a cached directory when `syscall.Getwd` fails with
/// ENAMETOOLONG. goish's loop grows its buffer on ERANGE up to 4 KiB
/// instead of failing, so that branch has nothing to recover from.
pub fn Getwd() -> (string, error) {
    // Go: dir = Getenv("PWD"); if len(dir) > 0 && dir[0] == '/' { ... }
    let dir = crate::os::env::Getenv(string("PWD"));
    if dir.Len() > 0 && bytes_of(&dir)[0] == b'/' {
        // Go: dot, err = statNolog("."); if err != nil { return "", err }
        let (dot, err) = Stat(string("."));
        if err.IsNil() {
            // Go: d, err := statNolog(dir)
            //     if err == nil && SameFile(dot, d) { return dir, nil }
            let (d, err2) = Stat(dir.clone());
            if err2.IsNil() && SameFile(&dot, &d) {
                return (dir, nil);
            }
        }
        // Go falls through to the syscall on any error here, including
        // a stat of "." that failed, and so do we.
    }

    // Go: var buf [128]byte; for { n, err := syscall.Getcwd(buf[:]); ... }
    let mut size: usize = 128;
    while size <= 4096 {
        let mut buf: Vec<u8> = Vec::with_capacity(size);
        buf.resize(size, 0);
        // Go: n, err := syscall.Getcwd(buf)
        let n = syscall::Getcwd(buf.as_mut_ptr(), size);
        // Go: if err == nil { return string(buf[:n-1]), nil } — strip trailing NUL.
        if n > 0 {
            // Linux returns total length including NUL — drop it.
            let len = (n as usize).saturating_sub(1);
            return (string::from_bytes(&buf[..len]), nil);
        }
        // Go: if err != ERANGE { return "", err } — bigger buffer otherwise.
        // Slim: -ERANGE is -34 on Linux. Anything else is fatal.
        if n != -34 {
            return (string::new(), errors::New(string("getwd failed")));
        }
        size *= 2;
    }
    (
        string::new(),
        errors::New(string("getwd: cwd path too long")),
    )
}

/// Line-by-line port of `os.Chdir(name)` (file.go) — change the
/// current working directory to `name`. Returns `nil` on success.
pub fn Chdir<N: Into<string>>(name: N) -> error {
    let name: string = name.into();
    // Go: if e := syscall.Chdir(name); e != nil { return &PathError{...} }
    let mut buf: Vec<u8> = Vec::with_capacity(name.Len() as usize + 1);
    buf.extend_from_slice(bytes_of(&name));
    buf.push(0);
    let rc = syscall::Chdir(buf.as_ptr());
    if rc < 0 {
        return pathErr("chdir", name, rc);
    }
    nil
}

/// Line-by-line port of `os.Chmod(name, mode)` (file.go:647 →
/// file_posix.go:76 chmod). Slim: no PathError wrapping, no EINTR
/// retry loop (chmod(2) is not interruptible on Linux in practice).
///
/// `mode: impl Into<FileMode>` so ports passing a bare integer
/// literal (Go's untyped-int) flow through `From<i32>`/`From<u32>`.
// go: sdk 1.25.5 os/file_posix.go:60-73 syscallMode
/// Convert a `FileMode` to the bits a `chmod`/`open`/`mkdir` syscall
/// wants.
///
/// The permission bits are the low nine and pass straight through. The
/// other three do NOT: Go's `FileMode` keeps setuid at 1<<23, setgid at
/// 1<<22 and sticky at 1<<20, while the kernel wants them at 0o4000,
/// 0o2000 and 0o1000. Masking the FileMode with 0o7777 — which is what
/// this file did, under a comment saying the conversion "collapses to
/// perm bits only" — keeps nine meaningful bits and three meaningless
/// ones, and silently drops all three special bits.
///
/// Measured before the fix: `Chmod(dir, 0o777|ModeSticky)` produced
/// 0777 with no sticky bit and a nil error. On a shared directory that
/// is the difference between "only the owner may delete their files"
/// and "anyone may delete anyone's".
fn syscallMode(i: FileMode) -> u32 {
    let mut o: u32 = i.Perm().0;
    if (i & ModeSetuid) != FileMode(0) {
        o |= syscall::S_ISUID;
    }
    if (i & ModeSetgid) != FileMode(0) {
        o |= syscall::S_ISGID;
    }
    if (i & ModeSticky) != FileMode(0) {
        o |= syscall::S_ISVTX;
    }
    // Go: "No mapping for Go's ModeTemporary (plan9 only)."
    return o;
}

// go: sdk 1.25.5 os/file.go:647-647 Chmod
/// `os.Chmod(name, mode)` — change a named file's mode. The three
/// special bits go through `syscallMode` above; passing the FileMode
/// straight to the syscall drops them.
pub fn Chmod<N: Into<string>, M: Into<FileMode>>(name: N, mode: M) -> error {
    let name: string = name.into();
    let mode: FileMode = mode.into();
    // Go: longName := fixLongPath(name) — Linux no-op.
    // Go: e := ignoringEINTR(func() error { return syscall.Chmod(longName, syscallMode(mode)) })
    let mut buf: Vec<u8> = Vec::with_capacity(name.Len() as usize + 1);
    buf.extend_from_slice(bytes_of(&name));
    buf.push(0);
    let rc = syscall::Chmod(buf.as_ptr(), syscallMode(mode));
    if rc < 0 {
        // Go: return &PathError{Op: "chmod", Path: name, Err: e}
        return pathErr("chmod", name, rc);
    }
    nil
}

/// Line-by-line port of `os.Symlink(oldname, newname)` (file_unix.go:417).
/// Slim: no LinkError wrapping, no EINTR retry.
pub fn Symlink<O: Into<string>, N: Into<string>>(oldname: O, newname: N) -> error {
    let oldname: string = oldname.into();
    let newname: string = newname.into();
    // Go: e := ignoringEINTR(func() error { return syscall.Symlink(oldname, newname) })
    let mut old_buf: Vec<u8> = Vec::with_capacity(oldname.Len() as usize + 1);
    old_buf.extend_from_slice(bytes_of(&oldname));
    old_buf.push(0);
    let mut new_buf: Vec<u8> = Vec::with_capacity(newname.Len() as usize + 1);
    new_buf.extend_from_slice(bytes_of(&newname));
    new_buf.push(0);
    let rc = syscall::Symlink(old_buf.as_ptr(), new_buf.as_ptr());
    if rc < 0 {
        // Go: return &LinkError{"symlink", oldname, newname, e}
        return linkErr("symlink", oldname, newname, rc);
    }
    nil
}

/// Line-by-line port of `os.Readlink(name)` (file.go:449 →
/// file_unix.go:427 readlink) — read the target of a symbolic link.
/// Doubles the buffer until the result fits, mirroring Go's growth
/// retry loop.
pub fn Readlink<N: Into<string>>(name: N) -> (string, error) {
    let name: string = name.into();
    // Go: for len := 128; ; len *= 2 { ... }
    let mut buf: Vec<u8> = Vec::with_capacity(name.Len() as usize + 1);
    buf.extend_from_slice(bytes_of(&name));
    buf.push(0);
    let mut len_: usize = 128;
    loop {
        // Go: b := make([]byte, len)
        let mut b: Vec<u8> = Vec::with_capacity(len_);
        b.resize(len_, 0);
        // Go: n, err := fixCount(syscall.Readlink(name, b))
        let n = syscall::Readlink(buf.as_ptr(), b.as_mut_ptr(), len_);
        if n < 0 {
            // Go: return "", &PathError{Op: "readlink", Path: name, Err: e}
            // `n` is the raw kernel return, negated into an errno.
            let e = n as i32; // goishlint:ignore GOISH005 - a kernel return code, not a Go value.
            return (string::new(), pathErr("readlink", name, e));
        }
        let nu = n as usize;
        // Go: if n < len { return string(b[0:n]), nil }
        if nu < len_ {
            return (string::from_bytes(&b[..nu]), nil);
        }
        // Go: len *= 2
        len_ *= 2;
        // Hard cap to prevent runaway: 1 MiB is more than any realistic symlink.
        if len_ > 1 << 20 {
            return (
                string::new(),
                errors::New(string("readlink: target too long")),
            );
        }
    }
}

/// `os.Executable()` (executable.go:19 → executable_procfs.go:15) —
/// path name for the executable that started the current process, via
/// `Readlink("/proc/self/exe")`. When the executable has been deleted,
/// Readlink returns a path appended with " (deleted)"; trimmed here as
/// in Go.
pub fn Executable() -> (string, error) {
    // Go: path, err := Readlink("/proc/self/exe")
    let (path, err) = Readlink("/proc/self/exe");
    // Go: return stringslite.TrimSuffix(path, " (deleted)"), err
    let b = bytes_of(&path);
    if b.ends_with(b" (deleted)") {
        return (string::from_bytes(&b[..b.len() - b" (deleted)".len()]), err);
    }
    (path, err)
}

// go: sdk 1.25.5 os/file_posix.go:179-185 Chtimes
// goishlint:ignore GOISH018 chtimesUtimes — Go's per-time helper
//     (os/file_posix.go:187-199) is the closure below; its only
//     substance is the zero-Time -> UTIME_OMIT branch and the
//     NsecToTimespec negative-remainder correction, both here.
/// `os.Chtimes(name, atime, mtime)` (file_posix.go:179) — change the
/// access and modification times of the named file. A zero time.Time
/// leaves the corresponding timestamp unchanged (UTIME_OMIT), as in Go.
pub fn Chtimes<N: Into<string>>(
    name: N,
    atime: crate::time::Time,
    mtime: crate::time::Time,
) -> error {
    let name: string = name.into();
    // Go: utimes := chtimesUtimes(atime, mtime) (file_posix.go:187)
    let set = |t: crate::time::Time| -> syscall::Timespec {
        if t.IsZero() {
            // Go: utimes[i] = syscall.Timespec{Sec: _UTIME_OMIT, Nsec: _UTIME_OMIT}
            syscall::Timespec {
                tv_sec: syscall::UTIME_OMIT,
                tv_nsec: syscall::UTIME_OMIT,
            }
        } else {
            // Go: utimes[i] = syscall.NsecToTimespec(t.UnixNano())
            //
            // The correction is the whole point of that helper
            // (syscall/timestruct.go:13-21):
            //
            //     sec := nsec / 1e9
            //     nsec = nsec % 1e9
            //     if nsec < 0 { nsec += 1e9; sec-- }
            //
            // Rust's `%`, like Go's, truncates toward zero, so a
            // pre-1970 time with a fractional part leaves tv_nsec
            // NEGATIVE. utimensat rejects a tv_nsec outside
            // [0, 999999999] with EINVAL, so Chtimes failed outright on
            // a timestamp Go writes without complaint — what an archive
            // extractor hits restoring old mtimes. A whole-second
            // pre-1970 time has remainder 0 and always worked, which is
            // why this needed the fractional case to surface.
            let ns = t.UnixNano() as i64;
            let mut sec = ns / 1_000_000_000;
            let mut nsec = ns % 1_000_000_000;
            if nsec < 0 {
                nsec += 1_000_000_000;
                sec -= 1;
            }
            syscall::Timespec {
                tv_sec: sec,
                tv_nsec: nsec,
            }
        }
    };
    let utimes = [set(atime), set(mtime)];
    let mut buf: Vec<u8> = Vec::with_capacity(name.Len() as usize + 1);
    buf.extend_from_slice(bytes_of(&name));
    buf.push(0);
    // Go: if e := syscall.UtimesNano(name, utimes[0:]); e != nil {
    //         return &PathError{Op: "chtimes", Path: name, Err: e} }
    let r = syscall::Utimensat(syscall::AT_FDCWD, buf.as_ptr(), utimes.as_ptr(), 0);
    if r < 0 {
        return pathErr("chtimes", name, r);
    }
    nil
}

// go: sdk 1.25.5 os/file.go:440-442 Rename
// goishlint:ignore GOISH018 rename — Go's Rename is a one-line
//     forward to the platform `rename` (os/file_unix.go:26-53),
//     whose body is inlined below: the Lstat-of-newname check, the
//     oldname-error priority, the SameFile fall-through for a
//     case-only rename, and the LinkError wrap.
/// Line-by-line port of `os.Rename(oldpath, newpath)`.
///
/// This note used to read "Slim: drops the SameFile case-only-rename
/// gymnastics (Linux is always case-sensitive)". That reasoning covers
/// the SameFile comparison, but the block it dropped also held Go's
/// oldname-error PRIORITY, which is not about case at all — so
/// `Rename(missing, existingDir)` answered "file exists" where Go
/// answers "no such file or directory", and the note made the omission
/// read as a deliberate trade-off. Both are implemented now, and the
/// case-only fall-through matters on a case-insensitive mount even
/// though ext4 is not one.
pub fn Rename<O: Into<string>, N: Into<string>>(oldpath: O, newpath: N) -> error {
    let oldpath: string = oldpath.into();
    let newpath: string = newpath.into();
    // Go: fi, err := Lstat(newname); if err == nil && fi.IsDir() { ... }
    let (fi, e) = Lstat(newpath.clone());
    if e.IsNil() && fi.IsDir() {
        // Two independent errors are possible here — a bad oldname and a
        // bad newname — and Go PRIORITISES the oldname one: "prioritize
        // returning the oldname error because that's what we did
        // historically" (os/file_unix.go). Returning EEXIST as soon as a
        // directory is seen at newname gets the common case right and
        // `Rename(missing, existingDir)` wrong, reporting "file exists"
        // where Go reports "no such file or directory".
        let (ofi, oerr) = Lstat(oldpath.clone());
        if !oerr.IsNil() {
            // Go: if pe, ok := err.(*PathError); ok { err = pe.Err } —
            // the LinkError already carries both paths, so the inner
            // error is unwrapped to the bare errno rather than nesting a
            // PathError's path inside it.
            let inner = match errors::As::<PathError>(oerr.clone()) {
                Some(pe) => pe.Err.clone(),
                None => oerr,
            };
            return errors::Wrap(LinkError {
                Op: string::from_static("rename"),
                Old: oldpath,
                New: newpath,
                Err: inner,
            });
        }
        // Go: else if newname == oldname || !SameFile(fi, ofi) { EEXIST }
        //
        // Falling through when they ARE the same file is deliberate in
        // Go: it is the case-only rename on a case-insensitive
        // filesystem, which must be allowed to reach the syscall.
        if newpath == oldpath || !SameFile(&fi, &ofi) {
            return errors::Wrap(LinkError {
                Op: string::from_static("rename"),
                Old: oldpath,
                New: newpath,
                Err: syscall::EEXIST.into(),
            });
        }
    }
    // Go: err = ignoringEINTR(func() error { return syscall.Rename(oldname, newname) })
    let mut old_buf: Vec<u8> = Vec::with_capacity(oldpath.Len() as usize + 1);
    old_buf.extend_from_slice(bytes_of(&oldpath));
    old_buf.push(0);
    let mut new_buf: Vec<u8> = Vec::with_capacity(newpath.Len() as usize + 1);
    new_buf.extend_from_slice(bytes_of(&newpath));
    new_buf.push(0);
    let rc = syscall::Rename(old_buf.as_ptr(), new_buf.as_ptr());
    if rc < 0 {
        return linkErr("rename", oldpath, newpath, rc);
    }
    nil
}

/// Line-by-line port of `os.Link(oldname, newname)` (file_unix.go:403)
/// — create `newname` as a hard link to `oldname`.
pub fn Link<O: Into<string>, N: Into<string>>(oldname: O, newname: N) -> error {
    let oldname: string = oldname.into();
    let newname: string = newname.into();
    // Go: e := ignoringEINTR(func() error { return syscall.Link(oldname, newname) })
    let mut old_buf: Vec<u8> = Vec::with_capacity(oldname.Len() as usize + 1);
    old_buf.extend_from_slice(bytes_of(&oldname));
    old_buf.push(0);
    let mut new_buf: Vec<u8> = Vec::with_capacity(newname.Len() as usize + 1);
    new_buf.extend_from_slice(bytes_of(&newname));
    new_buf.push(0);
    let rc = syscall::Link(old_buf.as_ptr(), new_buf.as_ptr());
    if rc < 0 {
        return linkErr("link", oldname, newname, rc);
    }
    nil
}

/// Line-by-line port of `os.Truncate(name, size)` (file_unix.go:344)
/// — change the size of the named file. Follows symlinks (per Go).
pub fn Truncate<N: Into<string>>(name: N, size: int) -> error {
    let name: string = name.into();
    // Go: e := ignoringEINTR(func() error { return syscall.Truncate(name, size) })
    let mut buf: Vec<u8> = Vec::with_capacity(name.Len() as usize + 1);
    buf.extend_from_slice(bytes_of(&name));
    buf.push(0);
    let rc = syscall::Truncate(buf.as_ptr(), size);
    if rc < 0 {
        return pathErr("truncate", name, rc);
    }
    nil
}

/// Line-by-line port of `os.Chown(name, uid, gid)` (file_posix.go:105).
/// uid or gid of -1 leaves that field unchanged. Follows symlinks
/// (per Go).
pub fn Chown<N: Into<string>>(name: N, uid: int, gid: int) -> error {
    let name: string = name.into();
    // Go: e := ignoringEINTR(func() error { return syscall.Chown(name, uid, gid) })
    let mut buf: Vec<u8> = Vec::with_capacity(name.Len() as usize + 1);
    buf.extend_from_slice(bytes_of(&name));
    buf.push(0);
    let rc = syscall::Chown(buf.as_ptr(), uid as i32, gid as i32);
    if rc < 0 {
        return pathErr("chown", name, rc);
    }
    nil
}

/// Line-by-line port of `os.Lchown(name, uid, gid)` (file_posix.go:121)
/// — does not follow a final-component symlink.
pub fn Lchown<N: Into<string>>(name: N, uid: int, gid: int) -> error {
    let name: string = name.into();
    // Go: e := ignoringEINTR(func() error { return syscall.Lchown(name, uid, gid) })
    let mut buf: Vec<u8> = Vec::with_capacity(name.Len() as usize + 1);
    buf.extend_from_slice(bytes_of(&name));
    buf.push(0);
    let rc = syscall::Lchown(buf.as_ptr(), uid as i32, gid as i32);
    if rc < 0 {
        return pathErr("lchown", name, rc);
    }
    nil
}

/// `os.Getuid()` (proc.go:31) — caller's real user id.
pub fn Getuid() -> int {
    syscall::Getuid() as int
}

/// `os.Geteuid()` (proc.go:36) — caller's effective user id.
pub fn Geteuid() -> int {
    syscall::Geteuid() as int
}

/// `os.Getgid()` (proc.go:41) — caller's real group id.
pub fn Getgid() -> int {
    syscall::Getgid() as int
}

/// `os.Getegid()` (proc.go:46) — caller's effective group id.
pub fn Getegid() -> int {
    syscall::Getegid() as int
}

/// `os.Getpid()` (proc.go:50) — caller's process id.
pub fn Getpid() -> int {
    syscall::Getpid() as int
}

/// `os.Getppid()` (proc.go:55) — caller's parent process id.
pub fn Getppid() -> int {
    syscall::Getppid() as int
}

/// `os.Getgroups()` (proc.go:51) — list of the numeric IDs of the
/// supplementary groups for the calling process.
///
/// Line-by-line port of:
///   - os/proc.go:51-58       (the public wrapper)
///   - syscall/syscall_linux.go (the two-step Getgroups dance)
pub fn Getgroups() -> (slice<int>, error) {
    use alloc::vec::Vec;

    // Go: n, err := getgroups(0, nil)
    let n = syscall::Getgroups(0, core::ptr::null_mut());
    // Go: if err != nil { return nil, err }
    if n < 0 {
        return (
            slice::<int>::__from_vec(Vec::new()),
            errors::New(string("getgroups failed")),
        );
    }
    // Go: if n == 0 { return nil, nil }
    if n == 0 {
        return (slice::<int>::__from_vec(Vec::new()), errors::nil);
    }

    // Go: a := make([]_Gid_t, n)
    //     n, err = getgroups(n, &a[0])
    // _Gid_t on Linux x86_64 is u32. Allocate exact-size buffer; the
    // second syscall fills `n` entries.
    let count = n as usize;
    let mut a: Vec<u32> = alloc::vec::from_elem(0u32, count);
    let n2 = syscall::Getgroups(count as i32, a.as_mut_ptr());
    if n2 < 0 {
        return (
            slice::<int>::__from_vec(Vec::new()),
            errors::New(string("getgroups failed")),
        );
    }

    // Go: gids = make([]int, n); for i, v := range a[:n] { gids[i] = int(v) }
    let real = n2 as usize;
    let mut gids: Vec<int> = Vec::with_capacity(real);
    for i in 0..real {
        gids.push(a[i] as int);
    }
    (slice::<int>::__from_vec(gids), errors::nil)
}

/// Line-by-line port of `os.Pipe()` (pipe2_unix.go:13) — create a
/// connected pair of Files; reads from `r` return bytes written to
/// `w`. Both ends are O_CLOEXEC by default, mirroring upstream.
pub fn Pipe() -> (File, File, error) {
    // Go: var p [2]int; e := syscall.Pipe2(p[:], syscall.O_CLOEXEC)
    let mut p: [i32; 2] = [-1, -1];
    let rc = syscall::Pipe2(&mut p, syscall::O_CLOEXEC);
    // Go: if e != nil { return nil, nil, NewSyscallError("pipe2", e) }
    // goish returned `errors.New("pipe2 failed")`, which named the call
    // but threw the errno away — so a caller could not tell EMFILE
    // (back off and retry) from ENFILE (the machine is out).
    if rc < 0 {
        return (
            File::NewFile(-1, string::new()),
            File::NewFile(-1, string::new()),
            NewSyscallError("pipe2", syscall::Errno(-rc).into()),
        );
    }
    // Go: return newFile(p[0], "|0", kindPipe, false), newFile(p[1], "|1", kindPipe, false), nil
    (
        File::NewFile(p[0] as int, string("|0")),
        File::NewFile(p[1] as int, string("|1")),
        nil,
    )
}

/// `os.Hostname()` (sys.go:8) — return the kernel's nodename via
/// uname(2).
pub fn Hostname() -> (string, error) {
    let mut u = syscall::Utsname::default();
    let rc = syscall::Uname(&mut u);
    if rc < 0 {
        return (string::new(), errors::New(string("uname failed")));
    }
    let mut n: usize = 0;
    while n < u.nodename.len() && u.nodename[n] != 0 {
        n += 1;
    }
    (string::from_bytes(&u.nodename[..n]), nil)
}

// ─── Mkdir / Remove ──────────────────────────────────────────────────

/// `os.Mkdir(name, perm)` (os/file.go) — create a single directory.
pub fn Mkdir<N: Into<string>, M: Into<FileMode>>(name: N, perm: M) -> error {
    let name: string = name.into();
    let perm: FileMode = perm.into();
    let mut buf: Vec<u8> = Vec::with_capacity(name.Len() as usize + 1);
    buf.extend_from_slice(bytes_of(&name));
    buf.push(0);
    // Go: syscall.Mkdir(longName, syscallMode(perm))
    let rc = syscall::Mkdir(buf.as_ptr(), syscallMode(perm));
    if rc < 0 {
        // Go: &PathError{Op: "mkdir", Path: name, Err: e}. goish
        // returned a bare `errors.New("mkdir failed")`, which names
        // neither the path nor the reason and is not a *PathError, so
        // `errors::As` and `IsExist`/`IsNotExist` could not see through
        // it.
        return errors::Wrap(PathError {
            Op: string::from("mkdir"),
            Path: name,
            Err: syscall::Errno(-rc).into(),
        });
    }
    nil
}

#[path = "path.rs"]
mod path;
pub use path::*;

/// `os.Remove(name)` (os/file_unix.go). Removes a file or empty
/// directory. First tries unlink; falls back to rmdir on EISDIR.
pub fn Remove<N: Into<string>>(name: N) -> error {
    let name: string = name.into();
    let mut buf: Vec<u8> = Vec::with_capacity(name.Len() as usize + 1);
    buf.extend_from_slice(bytes_of(&name));
    buf.push(0);
    // Go tries both calls rather than stat-ing first: it is cheaper on
    // average. Which error it reports is deliberate — the rmdir error
    // wins unless it is ENOTDIR, in which case the name was not a
    // directory and unlink's error is the true one.
    let e = syscall::Unlink(buf.as_ptr());
    if e == 0 {
        return nil;
    }
    let e1 = syscall::Rmdir(buf.as_ptr());
    if e1 == 0 {
        return nil;
    }
    let mut errno = -e;
    if syscall::Errno(-e1) != syscall::ENOTDIR {
        errno = -e1;
    }
    errors::Wrap(PathError {
        Op: string::from("remove"),
        Path: name,
        Err: syscall::Errno(errno).into(),
    })
}

// ─── DirEntry / ReadDir ──────────────────────────────────────────────

/// `os.DirEntry` (os/dir.go:91) — type alias for [`io::fs::DirEntry`].
///
/// Go's `os.DirEntry` is an exact alias for the `fs.DirEntry`
/// interface; the concrete OS-filesystem implementation is the
/// unexported [`unixDirent`].
pub use crate::io::fs::DirEntry;

/// `os.unixDirent` (file_unix.go:446) — concrete `fs.DirEntry` over a
/// `getdents64` record. Carries the parent directory path so `Info()`
/// can `lstat` the entry on demand (Go's `unixDirent.Info`).
#[allow(non_camel_case_types)]
struct unixDirent {
    /// Parent directory path (so `Info()` can build `parent + "/" + name`).
    parent: string,
    /// Base name of the entry.
    name: string,
    /// Type bits from the directory's `d_type`.
    typ: FileMode,
    /// Go: `info FileInfo` — set only when the entry had to be lstat'd
    /// because `d_type` was `DT_UNKNOWN`, so `Info()` reuses it.
    info: Option<alloc::sync::Arc<FileInfoData>>,
}

// `io/fs::DirEntry` is a `#[goish::interface]` trait — the concrete
// impl carries the transpiler-emitted boilerplate (`__goish_as_dyn_any`
// returns `Some(self)`); registration is lazy via `register_os_fs_impls`.
impl DirEntry for unixDirent {
    // Go: func (d *unixDirent) Name() string { return d.name }
    fn Name(&self) -> string {
        self.name.clone()
    }
    // Go: func (d *unixDirent) IsDir() bool { return d.typ.IsDir() }
    fn IsDir(&self) -> bool {
        self.typ.IsDir()
    }
    // Go: func (d *unixDirent) Type() FileMode { return d.typ }
    fn Type(&self) -> FileMode {
        self.typ
    }
    // Go: func (d *unixDirent) Info() (FileInfo, error) {
    //         return lstat(d.parent + "/" + d.name)
    //     }
    fn Info(&self) -> (alloc::sync::Arc<dyn FileInfo + Send + Sync>, error) {
        // Go: if d.info != nil { return d.info, nil }
        if let Some(i) = self.info.as_ref() {
            return (i.clone(), nil);
        }
        let mut full = self.parent.clone();
        full = full + string::from_static("/");
        full = full + self.name.clone();
        let (info, err) = Lstat(full);
        if !err.IsNil() {
            return (crate::nil.into(), err);
        }
        (alloc::sync::Arc::new(info), nil)
    }
    fn __goish_as_dyn_any(&self) -> Option<&(dyn core::any::Any + Send + Sync)> {
        Some(self)
    }
}

/// Register the `os` concrete `#[goish::interface]` impls into their
/// per-trait downcast registries (so `goish::cast!` can find them).
/// Idempotent and cheap; called at the head of `ReadDir`.
fn register_os_fs_impls() {
    crate::io::fs::__goish_register_FileInfo_impl::<FileInfoData>();
    crate::io::fs::__goish_register_DirEntry_impl::<unixDirent>();
}

/// `os.ReadDir(name)` (os/dir.go:114) — read directory entries from
/// `name`, returning them sorted by filename. Slim port: relies on
/// the Linux `getdents64(2)` syscall. Like Go, the return type is a
/// slice of the `fs.DirEntry` interface.
pub fn ReadDir<N: Into<string>>(
    name: N,
) -> (slice<alloc::sync::Arc<dyn DirEntry + Send + Sync>>, error) {
    register_os_fs_impls();
    let name: string = name.into();
    let (mut f, err) = Open(name.clone());
    if !err.IsNil() {
        return (slice::new(), err);
    }
    // err is nil ⇒ Open returned a non-nil File. Narrow.
    let f = f.MustMut();
    let mut entries: Vec<alloc::sync::Arc<dyn DirEntry + Send + Sync>> = Vec::new();
    // 4 KiB buffer matches the kernel's per-call output size sweet spot.
    let mut buf: alloc::vec::Vec<u8> = alloc::vec![0u8; 4096];
    loop {
        let n = syscall::Getdents64(f.fd, buf.as_mut_ptr(), buf.len());
        if n < 0 {
            let _ = f.Close();
            // Go: &PathError{Op: "readdirent", Path: f.name, Err: errno}
            return (slice::__from_vec(entries), f.fdErr("readdirent", n));
        }
        if n == 0 {
            // EOD
            break;
        }
        // Walk the populated buffer, parsing one linux_dirent64 at a time.
        let mut pos: usize = 0;
        let n = n as usize;
        while pos < n {
            // Header layout (offsets within the record):
            //   0  d_ino   u64
            //   8  d_off   i64
            //  16  d_reclen u16
            //  18  d_type  u8
            //  19  d_name  NUL-terminated, runs through end of record.
            let p = unsafe { buf.as_ptr().add(pos) };
            let reclen = unsafe { core::ptr::read_unaligned(p.add(16) as *const u16) } as usize;
            let dtype = unsafe { core::ptr::read(p.add(18)) };
            let name_start = pos + 19;
            // Find NUL terminator within the record.
            let mut name_end = name_start;
            while name_end < pos + reclen && buf[name_end] != 0 {
                name_end += 1;
            }
            let name_bytes = &buf[name_start..name_end];
            // Skip "." and ".." per Go's behavior.
            if name_bytes != b"." && name_bytes != b".." {
                // Go: de, err := newUnixDirent(dirname, string(name), direntType(rec))
                let (de, derr) = newUnixDirent(
                    name.clone(),
                    string::from_bytes(name_bytes),
                    direntType(dtype),
                );
                // Go: if IsNotExist(err) { continue } — an entry that
                // vanished between the getdents and the lstat is not an
                // error, it is a directory that changed underneath.
                if !derr.IsNil() {
                    if IsNotExist(derr.clone()) {
                        pos += reclen;
                        continue;
                    }
                    let _ = f.Close();
                    return (slice::__from_vec(entries), derr);
                }
                let ent: alloc::sync::Arc<dyn DirEntry + Send + Sync> = alloc::sync::Arc::new(de);
                entries.push(ent);
            }
            if reclen == 0 {
                break;
            }
            pos += reclen;
        }
    }
    let _ = f.Close();
    // Sort by name (Go uses slices.SortFunc on Name).
    entries.sort_by(|a, b| a.Name().as_bytes().cmp(b.Name().as_bytes()));
    (slice::__from_vec(entries), nil)
}

// go: sdk 1.25.5 os/dirent_linux.go:28-51 direntType
/// Map a `getdents64` `d_type` byte onto FileMode type bits.
///
/// goish mapped two of the seven and returned `FileMode(0)` for the
/// rest, so a fifo, a socket and a device all read as regular files.
/// Worse, `DT_UNKNOWN` — which is not a type at all but the kernel
/// saying "stat it yourself" — also read as a regular file, and it is
/// what several filesystems return for EVERY entry. On one of those,
/// `IsDir()` was false for every directory.
///
/// Go's sentinel for unknown is `^FileMode(0)`, an all-ones value that
/// is not a valid mode; [`newUnixDirent`] is where it turns into an
/// lstat.
fn direntType(dt: u8) -> FileMode {
    // Go: switch typ { case syscall.DT_BLK: return ModeDevice; … }
    if dt == syscall::DT_BLK {
        return ModeDevice;
    }
    if dt == syscall::DT_CHR {
        return FileMode(ModeDevice.0 | ModeCharDevice.0);
    }
    if dt == syscall::DT_DIR {
        return ModeDir;
    }
    if dt == syscall::DT_FIFO {
        return ModeNamedPipe;
    }
    if dt == syscall::DT_LNK {
        return ModeSymlink;
    }
    if dt == syscall::DT_REG {
        return FileMode(0);
    }
    if dt == syscall::DT_SOCK {
        return ModeSocket;
    }
    // Go: return ^FileMode(0) // unknown
    return FileMode(!0);
}

// go: sdk 1.25.5 os/file_unix.go:468-486 newUnixDirent
/// Go: build a `unixDirent`, and when `d_type` was `DT_UNKNOWN`, lstat
/// the entry to find out what it really is — caching the result so
/// `Info()` does not stat it a second time.
///
/// goish had no counterpart at all: it built the entry inline from the
/// unmapped type byte and never looked further.
fn newUnixDirent(parent: string, name: string, typ: FileMode) -> (unixDirent, error) {
    let mut ude = unixDirent {
        parent: parent.clone(),
        name: name.clone(),
        typ,
        info: None,
    };
    // Go: if typ != ^FileMode(0) { return ude, nil }
    if typ.0 != !0 {
        return (ude, nil);
    }
    let (info, err) = Lstat(parent + string::from_static("/") + name);
    if !err.IsNil() {
        return (ude, err);
    }
    // Go: ude.typ = info.Mode().Type(); ude.info = info
    ude.typ = info.Mode().Type();
    ude.info = Some(alloc::sync::Arc::new(info));
    return (ude, nil);
}

/// `os.WriteFile(name, data, perm)` (os/file.go:763) — write `data`
/// to the named file, creating or truncating it.
pub fn WriteFile<N: Into<string>, D: AsRef<[byte]>, M: Into<FileMode>>(
    name: N,
    data: D,
    perm: M,
) -> error {
    let name: string = name.into();
    let perm: FileMode = perm.into();
    use crate::io::Writer;
    let (mut f, err) = OpenFile(name, O_WRONLY | O_CREATE | O_TRUNC, perm);
    if !err.IsNil() {
        return err;
    }
    // err is nil ⇒ OpenFile returned a non-nil File. Narrow.
    let f = f.MustMut();
    let (_, werr) = f.Write(slice::__from_vec(data.as_ref().to_vec()));
    let cerr = f.Close();
    if !werr.IsNil() {
        return werr;
    }
    cerr
}

// ─── MkdirTemp / CreateTemp (Go 1.16+) ──────────────────────────────────

#[path = "tempfile.rs"]
mod tempfile;
pub use tempfile::*;

/// Compute the base-name (last path component).
fn base_name(p: &string) -> string {
    let bs = bytes_of(p);
    let mut end = bs.len();
    while end > 0 && bs[end - 1] == b'/' {
        end -= 1;
    }
    let mut start = end;
    while start > 0 && bs[start - 1] != b'/' {
        start -= 1;
    }
    string::from_bytes(&bs[start..end])
}

// ─── File ──────────────────────────────────────────────────────────────

/// Wraps an open file descriptor. `Stdin/Stdout/Stderr` return prebuilt
/// `File`s for fd 0/1/2; future `Open`/`Create` will return Files for
/// real filesystem opens.
///
/// Default + Clone are provided so `var f *os.File` in Go (lowered to
/// `nilable<File>` / `File` slots in Goish) get sensible defaults
/// without explicit handling. A default File is fd=-1 (a sentinel
/// invalid fd matching `os.NewFile(-1, "")`); Clone shares the fd
/// (POSIX dup2 semantics aren't enforced — Go's behavior is that
/// two File values pointing at the same fd interact through OS-level
/// locks).
#[derive(Clone)]
pub struct File {
    fd: i32,
    name: string,
    /// Go: `dirinfo atomic.Pointer[dirInfo]` — the partially-drained
    /// getdents buffer that makes a bounded `Readdirnames(n)` resumable.
    /// Go guards it with a mutex because a `*File` is shared; goish's
    /// `File` is a value and `Readdirnames` takes `&mut self`, so the
    /// borrow checker is the guard.
    dirinfo: Option<dirInfo>,
}

// go: sdk 1.25.5 os/dir_unix.go:20-25 dirInfo
/// Go: "buffer for directory I/O", the count returned by the last
/// getdents, and the offset of the next record in it.
///
/// goish had none: `Readdirnames(n)` asked the kernel for a fresh 4 KiB
/// of entries on every call and kept only the first `n` it wanted,
/// DISCARDING the rest of the batch. A directory of four entries read
/// three at a time gave 3, then 0 — the fourth was gone, silently, and
/// the caller saw a short directory rather than an error.
#[derive(Clone, Default)]
struct dirInfo {
    /// Go: `buf *[]byte`.
    buf: alloc::vec::Vec<u8>,
    /// Go: `nbuf int` — bytes the last getdents actually returned.
    nbuf: usize,
    /// Go: `bufp int` — offset of the next record in `buf`.
    bufp: usize,
}

impl Default for File {
    fn default() -> Self {
        File {
            fd: -1,
            name: string::from_static(""),
            dirinfo: None,
        }
    }
}

impl File {
    /// `os.NewFile(fd, name)` — wrap an existing fd. Public so user code
    /// can construct from raw fds (rare; mostly used by stdio factories
    /// and future Pipe/Open functions).
    pub fn NewFile<N: Into<string>>(fd: int, name: N) -> File {
        let name: string = name.into();
        File {
            fd: fd as i32,
            name,
            dirinfo: None,
        }
    }

    /// `f.Fd()` (os/file_unix.go:50) — raw fd as `uintptr`, matching
    /// Go's signature. Cast to `int` at call sites that need the
    /// signed-integer form (`syscall::Flock(int(f.Fd()), …)`).
    pub fn Fd(&self) -> crate::types::uintptr {
        self.fd as crate::types::uintptr
    }

    /// `f.Name()` — the name passed to NewFile (or "/dev/stdout" for stdio).
    pub fn Name(&self) -> string {
        self.name.clone()
    }

    /// `f.Close()` — close the underlying fd. Subsequent Reads/Writes
    /// will return errors. Closing fd < 0 is a no-op (matches "already
    /// closed" calls).
    pub fn Close(&mut self) -> error {
        if self.fd < 0 {
            // Go: a second Close is `&PathError{Op:"close", …,
            // Err: ErrClosed}` — "close NAME: file already closed" —
            // not nil. The distinction is what tells a caller it
            // double-closed rather than that the close succeeded, and
            // it is the same shape net's TCPConn.Close reports.
            return self.wrapErr("close", ErrClosed.into());
        }
        let rc = unsafe { syscall::syscall1(syscall::SYS_CLOSE, self.fd as usize) };
        let old_fd = self.fd;
        self.fd = -1;
        if rc < 0 {
            self.fdErr("close", rc)
        } else {
            let _ = old_fd;
            nil
        }
    }

    /// `f.Sync()` — flush any buffered data to disk. Returns an error
    /// if the underlying fsync syscall fails.
    pub fn Sync(&mut self) -> error {
        if self.fd < 0 {
            return self.wrapErr("sync", ErrClosed.into());
        }
        let rc = unsafe { syscall::syscall1(syscall::SYS_FSYNC, self.fd as usize) };
        if rc < 0 {
            self.fdErr("sync", rc)
        } else {
            nil
        }
    }

    /// `f.ReadAt(buf, off)` — read from file at given offset.
    /// Does not change the current file offset.
    pub fn ReadAt(&mut self, p: &mut slice<byte>, off: i64) -> (int, error) {
        if self.fd < 0 {
            return (0, self.wrapErr("read", ErrClosed.into()));
        }
        // Go: a NEGATIVE offset is its own error, not a syscall
        // failure (os/file.go:157-159).
        if off < 0 {
            return (
                0,
                errors::Wrap(PathError {
                    Op: crate::gostring::string::from_static("readat"),
                    Path: self.name.clone(),
                    Err: errors::New(crate::gostring::string::from_static("negative offset")),
                }),
            );
        }
        // Go LOOPS until the buffer is full or an error stops it
        // (os/file.go:161-170), so a SHORT read reports the error that
        // ended it — io.EOF when the file ran out — alongside the
        // bytes it did get. Returning nil there, which this did, tells
        // a caller looping on `n < len(p)` that the buffer is full
        // when it is not: io.ReaderAt's contract is explicit that
        // "ReadAt returns a non-nil error when n < len(p)".
        let total = p.len();
        let mut n: usize = 0;
        let mut err = nil;
        while n < total {
            let ptr = unsafe { p.as_mut_ptr().add(n) };
            let at = off + i64::try_from(n).unwrap_or(0);
            let got = syscall::Pread64(self.fd, ptr, total - n, at);
            if got < 0 {
                err = self.fdErr("read", got);
                break;
            }
            if got == 0 {
                err = io::EOF.into();
                break;
            }
            n += got as usize;
        }
        return (n as int, err);
    }

    /// `f.WriteAt(buf, off)` — write to file at given offset.
    /// Does not change the current file offset.
    pub fn WriteAt(&mut self, p: slice<byte>, off: i64) -> (int, error) {
        if self.fd < 0 {
            return (0, self.wrapErr("write", ErrClosed.into()));
        }
        let n = syscall::Pwrite64(self.fd, p.as_ptr(), p.len(), off);
        if n < 0 {
            (0, self.fdErr("write", n))
        } else {
            (n as int, nil)
        }
    }

    /// `f.Truncate(size)` — truncate file to given size.
    pub fn Truncate(&mut self, size: int) -> error {
        if self.fd < 0 {
            return self.wrapErr("truncate", ErrClosed.into());
        }
        let rc = syscall::Ftruncate(self.fd, size as i64);
        if rc < 0 {
            self.fdErr("truncate", rc)
        } else {
            nil
        }
    }

    /// `(*File).Chmod(mode)` (os/file_posix.go:106) — change the mode of
    /// the underlying file. Inherent so callers don't need to import
    /// any extra trait; the call shape matches Go exactly:
    /// `f.Chmod(0o644)` or `f.Chmod(mode)` where mode is a FileMode.
    ///
    /// Takes `&self` rather than `&mut self` so transpiled call sites
    /// that hold a `nilable<File>` via `t.Must()` (the immutable-cell
    /// reach-in) work without requiring a `MustMut()` rewrite. The fd
    /// is unchanged by `fchmod(2)`; no mutation is required to model
    /// the syscall faithfully.
    pub fn Chmod<M: Into<FileMode>>(&self, mode: M) -> error {
        if self.fd < 0 {
            return self.wrapErr("chmod", ErrClosed.into());
        }
        let mode: FileMode = mode.into();
        let rc = syscall::Fchmod(self.fd, syscallMode(mode));
        if rc < 0 {
            self.fdErr("chmod", rc)
        } else {
            nil
        }
    }

    /// `(*File).Write(p)` (os/file.go:188) — inherent forwarder so
    /// `f.Write(data)` works without `use goish::io::Writer;` at the
    /// call site. Mirrors Go where `(*os.File).Write` is a concrete
    /// method on the type (the io.Writer interface is satisfied
    /// structurally, not by trait-method dispatch).
    ///
    /// Takes `&self` for the same reason as `Chmod`: lets transpiled
    /// callers reach in through `t.Must().File.Write(data)` (immutable
    /// cell access). The underlying syscall doesn't mutate the `File`
    /// struct itself — only the kernel's file-offset table.
    // go: sdk 1.25.5 os/file.go:319-322 File.WriteString
    /// Go: "WriteString is like Write, but writes the contents of
    /// string s rather than a slice of bytes."
    ///
    /// Go reaches the bytes without copying, through
    /// `unsafe.Slice(unsafe.StringData(s), len(s))`; goish's `string`
    /// already lends its bytes, so the copy Go avoids does not arise.
    pub fn WriteString<S: Into<string>>(&self, s: S) -> (int, error) {
        let s: string = s.into();
        return self.Write(slice::__from_vec(s.as_bytes().to_vec()));
    }

    pub fn Write(&self, p: slice<byte>) -> (int, error) {
        // Go's `poll.FD.Write` LOOPS until every byte is written or a
        // syscall fails, which is what lets os.File satisfy io.Writer:
        // "Write must return a non-nil error if it returns n < len(p)".
        // A single write(2) does not — a pipe or socket-backed File
        // takes what fits and reports success, and the caller loses
        // the rest silently.
        let total = p.len();
        let mut n: usize = 0;
        while n < total {
            let ptr = unsafe { p.as_ptr().add(n) };
            let got = syscall::Write(self.fd, ptr, total - n);
            if got < 0 {
                return (n as int, self.fdErr("write", got));
            }
            if got == 0 {
                // Linux write(2) returning 0 for a non-empty buffer is
                // not expected; treat it as a stall rather than spin.
                return (n as int, self.fdErr("write", -5i64));
            }
            n += got as usize;
        }
        return (n as int, nil);
    }

    /// `(*File).Read(p)` (os/file.go:118) — inherent forwarder, see
    /// the rationale on `Write` above.
    pub fn Read(&self, p: &mut slice<byte>) -> (int, error) {
        let len = p.len();
        let ptr = p.as_mut_ptr();
        let n = syscall::Read(self.fd, ptr, len);
        if n < 0 {
            (0, self.fdErr("read", n))
        } else if n == 0 {
            (0, io::EOF.into())
        } else {
            (n as int, nil)
        }
    }
}

impl io::Writer for File {
    // go: none — goish idiom: Go's *File IS an io.Writer, so there is
    // one implementation. Rust needs the trait impl separately, and
    // this one used to be a SECOND implementation that called write(2)
    // itself and reported `errors.New("write failed")` — no path, no
    // errno, no closed-file detection.
    //
    // Everything generic goes through here: io::Copy, fmt::Fprintf,
    // any `dyn io::Writer`. So `io.Copy(f, r)` onto a full disk said
    // "write failed" while `f.Write(…)` on the same file said
    // "write /path: no space left on device". It forwards now, and
    // there is one implementation again.
    fn Write(&mut self, p: slice<byte>) -> (int, error) {
        return File::Write(self, p);
    }
}

impl io::Reader for File {
    // go: none — goish idiom: see the note on the Writer impl. This
    // reported `errors.New("read failed")` for every failure.
    fn Read(&mut self, p: &mut slice<byte>) -> (int, error) {
        return File::Read(self, p);
    }
}

impl io::Closer for File {
    fn Close(&mut self) -> error {
        File::Close(self)
    }
}

// ─── Standard streams ──────────────────────────────────────────────────

/// `os.Stdin` — returns a fresh `File` view of fd 0.
pub fn Stdin() -> File {
    File::NewFile(syscall::STDIN as int, string("/dev/stdin"))
}

/// `os.Stdout` — returns a fresh `File` view of fd 1.
pub fn Stdout() -> File {
    File::NewFile(syscall::STDOUT as int, string("/dev/stdout"))
}

/// `os.Stderr` — returns a fresh `File` view of fd 2.
pub fn Stderr() -> File {
    File::NewFile(syscall::STDERR as int, string("/dev/stderr"))
}

// ─── os.Args ───────────────────────────────────────────────────────────

/// `os.Args` — command-line arguments. `Args()[0]` is the program name.
///
/// Decodes the kernel-supplied argv on first call, caches the result.
/// Each subsequent call returns a clone of the cached slice (Arc-cheap).
pub fn Args() -> slice<string> {
    use crate::runtime::spin::SpinLock;
    static CACHE: SpinLock<Option<slice<string>>> = SpinLock::new(None);
    let mut g = CACHE.lock();
    if g.is_none() {
        *g = Some(decode_argv());
    }
    g.as_ref().unwrap().clone()
}

fn decode_argv() -> slice<string> {
    let raw = match runtime::args::get() {
        Some(r) => r,
        None => return slice::__from_vec(Vec::new()),
    };
    let mut v: Vec<string> = Vec::with_capacity(raw.argc as usize);
    for i in 0..raw.argc {
        unsafe {
            let cstr = *raw.argv.add(i as usize);
            if cstr.is_null() {
                break;
            }
            let n = cstrlen(cstr);
            let bytes = core::slice::from_raw_parts(cstr, n);
            v.push(string::from_bytes(bytes));
        }
    }
    slice::__from_vec(v)
}

/// Internal C-string length (we don't have libc's strlen).
unsafe fn cstrlen(p: *const u8) -> usize {
    let mut n: usize = 0;
    while *p.add(n) != 0 {
        n += 1;
    }
    n
}

// ─── os.Exit ───────────────────────────────────────────────────────────

/// `os.Exit(code)` — terminate the process. Mirrors `syscall::Exit`,
/// re-exported here under the Go-shaped path.
pub fn Exit(code: int) -> ! {
    syscall::Exit(code as i32);
}

// ─── os.DirFS (os/file.go:717) ─────────────────────────────────────────

// os::File as an `fs::File` interface value. The fs trait takes
// `&self` everywhere (Go interface values), while os::File's Close
// needs `&mut` — so the adapter owns the File behind a lock and
// Close takes it out. Reads hold the lock across the read(2); a
// single fs::File handle is never shared hot, so a spinlock is fine.
#[allow(non_camel_case_types)] // Go name (os/file.go)
struct dirFSFile {
    inner: runtime::spin::SpinLock<Option<File>>,
}

impl crate::io::fs::File for dirFSFile {
    fn Stat(&self) -> (alloc::sync::Arc<dyn FileInfo + Send + Sync>, error) {
        let g = self.inner.lock();
        match g.as_ref() {
            Some(f) => {
                let (info, err) = f.Stat();
                if !err.IsNil() {
                    return (crate::nil.into(), err);
                }
                (alloc::sync::Arc::new(info), nil)
            }
            None => (crate::nil.into(), ErrClosed.into()),
        }
    }
    fn Read(&self, p: &mut slice<byte>) -> (int, error) {
        let g = self.inner.lock();
        match g.as_ref() {
            Some(f) => f.Read(p),
            None => (0, ErrClosed.into()),
        }
    }
    fn Close(&self) -> error {
        match self.inner.lock().take() {
            Some(mut f) => f.Close(),
            None => ErrClosed.into(),
        }
    }
    fn __goish_as_dyn_any(&self) -> Option<&(dyn core::any::Any + Send + Sync)> {
        Some(self)
    }
}

// go: sdk 1.25.5 os/file.go:755 dirFS
#[allow(non_camel_case_types)] // Go name
struct dirFS {
    dir: string,
}

impl dirFS {
    // go: sdk 1.25.5 os/file.go:849-861 dirFS.join
    /// `dir/name`, with the empty-root and Localize checks that make
    /// this a boundary rather than a string concatenation.
    fn join(&self, op: &'static str, name: &string) -> (string, error) {
        // Go: if dir == "" { return "", errors.New("os: DirFS with empty root") }
        //
        // First, before the name is looked at, as Go orders it. Without
        // this the join below produces "/" + name — an absolute path
        // from the FILESYSTEM ROOT rather than a contained one — so
        // DirFS("") reads anything the process can.
        if self.dir.Len() == 0 {
            return (
                string::new(),
                errors::Wrap(crate::io::fs::PathError {
                    Op: string::from_static(op),
                    Path: name.clone(),
                    Err: errors::New(string::from_static(
                        "os: DirFS with empty root",
                    )),
                }),
            );
        }
        // Go: name, err := filepathlite.Localize(name); if err != nil { ErrInvalid }
        //
        // Localize is fs.ValidPath AND a rejection of any embedded NUL
        // (internal/filepathlite/path_unix.go:27-32). ValidPath alone
        // is not enough: it checks path ELEMENTS, not bytes, so "f\0junk"
        // passes it and is then truncated at the C string boundary by
        // the kernel — the file OPENED is not the file VALIDATED. That
        // was measured: this returned the contents of "f" for a request
        // naming "f\0ignored".
        if !crate::io::fs::ValidPath(name.clone())
            || name.as_bytes().contains(&0u8)
        {
            return (
                string::new(),
                errors::Wrap(crate::io::fs::PathError {
                    Op: string::from_static(op),
                    Path: name.clone(),
                    Err: ErrInvalid.into(),
                }),
            );
        }
        // Go routes through filepath, cleaning "." away; the common
        // case is special-cased here instead.
        if name.as_bytes() == b"." {
            return (self.dir.clone(), nil);
        }
        let mut joined: Vec<u8> = Vec::new();
        joined.extend_from_slice(self.dir.as_bytes());
        if !self.dir.as_bytes().ends_with(b"/") {
            joined.push(b'/');
        }
        joined.extend_from_slice(name.as_bytes());
        (string::from_bytes(&joined), nil)
    }
}

impl crate::io::fs::FS for dirFS {
    // go: sdk 1.25.5 os/file.go:757-772 dirFS.Open
    fn Open(
        &self,
        name: string,
    ) -> (
        alloc::sync::Arc<dyn crate::io::fs::File + Send + Sync>,
        error,
    ) {
        let (full, err) = self.join("open", &name);
        if !err.IsNil() {
            return (crate::nil.into(), err);
        }
        let (f, err) = Open(full);
        if !err.IsNil() {
            return (crate::nil.into(), err);
        }
        (
            alloc::sync::Arc::new(dirFSFile {
                inner: runtime::spin::SpinLock::new(Some(f.MustTake())),
            }),
            nil,
        )
    }
    fn __goish_as_dyn_any(&self) -> Option<&(dyn core::any::Any + Send + Sync)> {
        Some(self)
    }
}

impl crate::io::fs::StatFS for dirFS {
    fn Open(
        &self,
        name: string,
    ) -> (
        alloc::sync::Arc<dyn crate::io::fs::File + Send + Sync>,
        error,
    ) {
        crate::io::fs::FS::Open(self, name)
    }
    // Go: dirFS.Stat (os/file.go:806).
    fn Stat(&self, name: string) -> (alloc::sync::Arc<dyn FileInfo + Send + Sync>, error) {
        let (full, err) = self.join("stat", &name);
        if !err.IsNil() {
            return (crate::nil.into(), err);
        }
        let (info, err) = Stat(full);
        if !err.IsNil() {
            return (crate::nil.into(), err);
        }
        (alloc::sync::Arc::new(info), nil)
    }
    fn __goish_as_dyn_any(&self) -> Option<&(dyn core::any::Any + Send + Sync)> {
        Some(self)
    }
}

impl crate::io::fs::ReadFileFS for dirFS {
    fn Open(
        &self,
        name: string,
    ) -> (
        alloc::sync::Arc<dyn crate::io::fs::File + Send + Sync>,
        error,
    ) {
        crate::io::fs::FS::Open(self, name)
    }
    // Go: dirFS.ReadFile (os/file.go:782).
    fn ReadFile(&self, name: string) -> (slice<byte>, error) {
        let (full, err) = self.join("readfile", &name);
        if !err.IsNil() {
            return (slice::new(), err);
        }
        ReadFile(full)
    }
    fn __goish_as_dyn_any(&self) -> Option<&(dyn core::any::Any + Send + Sync)> {
        Some(self)
    }
}

impl crate::io::fs::ReadDirFS for dirFS {
    fn Open(
        &self,
        name: string,
    ) -> (
        alloc::sync::Arc<dyn crate::io::fs::File + Send + Sync>,
        error,
    ) {
        crate::io::fs::FS::Open(self, name)
    }
    // Go: dirFS.ReadDir (os/file.go:794).
    fn ReadDir(
        &self,
        name: string,
    ) -> (slice<alloc::sync::Arc<dyn DirEntry + Send + Sync>>, error) {
        let (full, err) = self.join("readdir", &name);
        if !err.IsNil() {
            return (slice::new(), err);
        }
        ReadDir(full)
    }
    fn __goish_as_dyn_any(&self) -> Option<&(dyn core::any::Any + Send + Sync)> {
        Some(self)
    }
}

fn register_dirfs_impls() {
    crate::io::fs::__goish_register_StatFS_impl::<dirFS>();
    crate::io::fs::__goish_register_ReadFileFS_impl::<dirFS>();
    crate::io::fs::__goish_register_ReadDirFS_impl::<dirFS>();
    crate::io::fs::__goish_register_File_impl::<dirFSFile>();
}

/// `os.DirFS(dir)` (os/file.go:717) — an `fs::FS` for the tree of
/// files rooted at the directory `dir`. Implements the optimized
/// `StatFS` / `ReadFileFS` / `ReadDirFS` paths, so `fs::Stat`,
/// `fs::ReadFile`, `fs::ReadDir`, and `fs::WalkDir` all route through
/// the direct os calls.
pub fn DirFS<S: Into<string>>(dir: S) -> alloc::sync::Arc<dyn crate::io::fs::FS + Send + Sync> {
    register_os_fs_impls();
    register_dirfs_impls();
    alloc::sync::Arc::new(dirFS { dir: dir.into() })
}

// go: none — goish idiom: fill the `#[goish::interface]` downcast
// registries for the types this package declares. See AGENTS.md §9b.
/// Register `os::File` into the `io` interface registries. Idempotent;
/// called from `goish::init()`.
pub fn register_os_impls() {
    use crate::io::{
        __goish_register_Closer_impl, __goish_register_Reader_impl, __goish_register_Writer_impl,
    };
    __goish_register_Reader_impl::<File>();
    __goish_register_Writer_impl::<File>();
    __goish_register_Closer_impl::<File>();
}
