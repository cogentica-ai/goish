// go: file io/fs/fs.go decls: FileMode.String, FileMode.IsDir, FileMode.IsRegular, FileMode.Perm, FileMode.Type, ValidPath, PathError.Error, PathError.Unwrap, PathError.Timeout
//
// fs.go — FS, File, FileInfo, DirEntry, ReadDirFile, FileMode,
// ValidPath, PathError and the sentinel errors.
extern crate alloc;
use alloc::sync::Arc;
use alloc::vec::Vec;

use crate::convert::uint32 as touint32;
use crate::errors::{self, error, ErrorTrait};
use crate::goslice::slice;
use crate::gostring::string;
use crate::types::{byte, int, int64};
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
    // go: none — goish idiom: Go's `FileMode` is a defined `uint32`, so
    //     the language gives it `|`, `&`, `^`, `&^`, `^x` and untyped-
    //     constant conversion for free. Rust gives a newtype none of
    //     that, so each one is written out. No Go counterpart because in
    //     Go there is nothing to write.
    pub const fn Bits(&self) -> u32 {
        return self.0;
    }
}

// Bit operators — Go writes `mode | os.ModeDir`, `mode & os.ModePerm`,
// `flag &^ os.O_TRUNC` (Go's bit-clear). Mirror that ergonomically on
// the newtype so ports keep their idioms without `.0` unwrapping.
// go: none — goish idiom: Go's `fmt` finds `FileMode.String` by
// structural assertion, so `%s` and `%v` on a mode just work. goish's
// printer dispatches on the `Format` trait, which a type reaches
// through `Stringer` — and nothing implemented it here, so a
// `FileMode` could not be printed at all.
//
// It implements `Format` DIRECTLY rather than `Stringer`, because the
// `impl<T: Stringer> Format for T` blanket sends every verb through
// the string. Go does not: `handleMethods` consults a Stringer only
// for %v, %s, %q, %x and %X, and formats the underlying value for the
// numeric verbs. A mode is a uint32, so Go prints
//
//     %v -rw-r-----   %o 640   %04o 0640   %d 416
//
// and goish printed `-rw-r-----` for all four — which makes
// `Printf("%o", mode)`, the ordinary way to log a file mode, produce
// a symbolic string with no digits in it.
//
// %x stays the hex of the STRING, not of the number: that is Go's
// behaviour too, because %x is one of the verbs a Stringer serves.
impl crate::fmt::Format for FileMode {
    // go: none — goish idiom: see the note above this impl.
    fn fmt(&self, verb: crate::types::byte, f: &mut crate::fmt::FmtBuf) {
        match verb {
            b'd' | b'b' | b'o' | b'O' | b'c' | b'U' => {
                crate::fmt::Format::fmt(&self.0, verb, f);
            }
            _ => {
                let s = FileMode::String(self);
                crate::fmt::Format::fmt(&s, verb, f);
            }
        }
    }
}

impl core::ops::BitOr for FileMode {
    type Output = FileMode;
    // go: none — goish idiom: Go's `FileMode` is a defined `uint32`, so
    //     the language gives it `|`, `&`, `^`, `&^`, `^x` and untyped-
    //     constant conversion for free. Rust gives a newtype none of
    //     that, so each one is written out. No Go counterpart because in
    //     Go there is nothing to write.
    fn bitor(self, rhs: FileMode) -> FileMode {
        return FileMode(self.0 | rhs.0);
    }
}
impl core::ops::BitAnd for FileMode {
    type Output = FileMode;
    // go: none — goish idiom: Go's `FileMode` is a defined `uint32`, so
    //     the language gives it `|`, `&`, `^`, `&^`, `^x` and untyped-
    //     constant conversion for free. Rust gives a newtype none of
    //     that, so each one is written out. No Go counterpart because in
    //     Go there is nothing to write.
    fn bitand(self, rhs: FileMode) -> FileMode {
        return FileMode(self.0 & rhs.0);
    }
}
// Mask against a bare integer literal — Go writes `fi.Mode() & 0o777`
// and the untyped constant coerces to `os.FileMode`. Rust needs the
// literal pinned: a single `BitAnd<u32>` impl lets `& 0o777` infer the
// literal as `u32` unambiguously.
impl core::ops::BitAnd<u32> for FileMode {
    type Output = FileMode;
    // go: none — goish idiom: Go's `FileMode` is a defined `uint32`, so
    //     the language gives it `|`, `&`, `^`, `&^`, `^x` and untyped-
    //     constant conversion for free. Rust gives a newtype none of
    //     that, so each one is written out. No Go counterpart because in
    //     Go there is nothing to write.
    fn bitand(self, rhs: u32) -> FileMode {
        return FileMode(self.0 & rhs);
    }
}
impl core::ops::BitXor for FileMode {
    type Output = FileMode;
    // go: none — goish idiom: Go's `FileMode` is a defined `uint32`, so
    //     the language gives it `|`, `&`, `^`, `&^`, `^x` and untyped-
    //     constant conversion for free. Rust gives a newtype none of
    //     that, so each one is written out. No Go counterpart because in
    //     Go there is nothing to write.
    fn bitxor(self, rhs: FileMode) -> FileMode {
        return FileMode(self.0 ^ rhs.0);
    }
}
impl core::ops::BitOrAssign for FileMode {
    // go: none — goish idiom: Go's `FileMode` is a defined `uint32`, so
    //     the language gives it `|`, `&`, `^`, `&^`, `^x` and untyped-
    //     constant conversion for free. Rust gives a newtype none of
    //     that, so each one is written out. No Go counterpart because in
    //     Go there is nothing to write.
    fn bitor_assign(&mut self, rhs: FileMode) {
        self.0 |= rhs.0;
    }
}
impl core::ops::BitAndAssign for FileMode {
    // go: none — goish idiom: Go's `FileMode` is a defined `uint32`, so
    //     the language gives it `|`, `&`, `^`, `&^`, `^x` and untyped-
    //     constant conversion for free. Rust gives a newtype none of
    //     that, so each one is written out. No Go counterpart because in
    //     Go there is nothing to write.
    fn bitand_assign(&mut self, rhs: FileMode) {
        self.0 &= rhs.0;
    }
}
impl core::ops::Not for FileMode {
    type Output = FileMode;
    // go: none — goish idiom: Go's `FileMode` is a defined `uint32`, so
    //     the language gives it `|`, `&`, `^`, `&^`, `^x` and untyped-
    //     constant conversion for free. Rust gives a newtype none of
    //     that, so each one is written out. No Go counterpart because in
    //     Go there is nothing to write.
    fn not(self) -> FileMode {
        return FileMode(!self.0);
    }
}

// Integer-literal coercions. Go writes `os.OpenFile(name, flag, 0666)`
// and the compiler accepts 0666 as `os.FileMode` because Go has
// untyped constants. Rust doesn't, so accept the common literal widths
// via `From` and `impl Into<FileMode>` on call sites that take perm.
impl From<u32> for FileMode {
    // go: none — goish idiom: Go's `FileMode` is a defined `uint32`, so
    //     the language gives it `|`, `&`, `^`, `&^`, `^x` and untyped-
    //     constant conversion for free. Rust gives a newtype none of
    //     that, so each one is written out. No Go counterpart because in
    //     Go there is nothing to write.
    fn from(v: u32) -> FileMode {
        return FileMode(v);
    }
}
impl From<i32> for FileMode {
    // go: none — goish idiom: Go's `FileMode` is a defined `uint32`, so
    //     the language gives it `|`, `&`, `^`, `&^`, `^x` and untyped-
    //     constant conversion for free. Rust gives a newtype none of
    //     that, so each one is written out. No Go counterpart because in
    //     Go there is nothing to write.
    fn from(v: i32) -> FileMode {
        return FileMode(touint32(v));
    }
}
impl From<i64> for FileMode {
    // go: none — goish idiom: Go's `FileMode` is a defined `uint32`, so
    //     the language gives it `|`, `&`, `^`, `&^`, `^x` and untyped-
    //     constant conversion for free. Rust gives a newtype none of
    //     that, so each one is written out. No Go counterpart because in
    //     Go there is nothing to write.
    fn from(v: i64) -> FileMode {
        return FileMode(touint32(v));
    }
}
impl From<u64> for FileMode {
    // go: none — goish idiom: Go's `FileMode` is a defined `uint32`, so
    //     the language gives it `|`, `&`, `^`, `&^`, `^x` and untyped-
    //     constant conversion for free. Rust gives a newtype none of
    //     that, so each one is written out. No Go counterpart because in
    //     Go there is nothing to write.
    fn from(v: u64) -> FileMode {
        return FileMode(touint32(v));
    }
}
impl From<u16> for FileMode {
    // go: none — goish idiom: Go's `FileMode` is a defined `uint32`, so
    //     the language gives it `|`, `&`, `^`, `&^`, `^x` and untyped-
    //     constant conversion for free. Rust gives a newtype none of
    //     that, so each one is written out. No Go counterpart because in
    //     Go there is nothing to write.
    fn from(v: u16) -> FileMode {
        return FileMode(touint32(v));
    }
}
impl From<crate::nilval::Nil> for FileMode {
    // go: none — goish idiom: Go's `FileMode` is a defined `uint32`, so
    //     the language gives it `|`, `&`, `^`, `&^`, `^x` and untyped-
    //     constant conversion for free. Rust gives a newtype none of
    //     that, so each one is written out. No Go counterpart because in
    //     Go there is nothing to write.
    fn from(_: crate::nilval::Nil) -> FileMode {
        return FileMode(0);
    }
}

// Comparison against bare integer 0 — Go's `if perm == 0 { … }`.
impl PartialEq<i32> for FileMode {
    // go: none — goish idiom: Go's `FileMode` is a defined `uint32`, so
    //     the language gives it `|`, `&`, `^`, `&^`, `^x` and untyped-
    //     constant conversion for free. Rust gives a newtype none of
    //     that, so each one is written out. No Go counterpart because in
    //     Go there is nothing to write.
    fn eq(&self, other: &i32) -> bool {
        return self.0 == touint32(*other);
    }
}
impl PartialEq<u32> for FileMode {
    // go: none — goish idiom: Go's `FileMode` is a defined `uint32`, so
    //     the language gives it `|`, `&`, `^`, `&^`, `^x` and untyped-
    //     constant conversion for free. Rust gives a newtype none of
    //     that, so each one is written out. No Go counterpart because in
    //     Go there is nothing to write.
    fn eq(&self, other: &u32) -> bool {
        return self.0 == *other;
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
    // go: sdk 1.25.5 io/fs/fs.go:202-226 FileMode.String
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
            let bit: u32 = 1u32 << (32 - 1 - touint32(i));
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
            let bit: u32 = 1u32 << (9 - 1 - touint32(i));
            if self.0 & bit != 0 {
                buf[w] = RWX[i];
            } else {
                buf[w] = b'-';
            }
            w += 1;
        }
        return string::from_bytes(&buf[..w]);
    }

    // go: sdk 1.25.5 io/fs/fs.go:230-232 FileMode.IsDir
    // Go: fs.go:230-232
    //   func (m FileMode) IsDir() bool { return m&ModeDir != 0 }
    pub fn IsDir(&self) -> bool {
        return self.0 & ModeDir.0 != 0;
    }

    // go: sdk 1.25.5 io/fs/fs.go:236-238 FileMode.IsRegular
    // Go: fs.go:236-238
    //   func (m FileMode) IsRegular() bool { return m&ModeType == 0 }
    pub fn IsRegular(&self) -> bool {
        return self.0 & ModeType.0 == 0;
    }

    // go: sdk 1.25.5 io/fs/fs.go:241-243 FileMode.Perm
    // Go: fs.go:241-243
    //   func (m FileMode) Perm() FileMode { return m & ModePerm }
    pub fn Perm(&self) -> FileMode {
        return FileMode(self.0 & ModePerm.0);
    }

    // go: sdk 1.25.5 io/fs/fs.go:246-248 FileMode.Type
    // Go: fs.go:246-248
    //   func (m FileMode) Type() FileMode { return m & ModeType }
    pub fn Type(&self) -> FileMode {
        return FileMode(self.0 & ModeType.0);
    }
}

// go: sdk 1.25.5 io/fs/fs.go:54-79 ValidPath
// Go: fs.go:54-79
//   func ValidPath(name string) bool
// goishlint:ignore GOISH023 — the body ends in an infinite `loop` whose
//     every exit is a `return` from inside it, so there is no tail
//     expression to make explicit. Go writes the same shape: `for { … }`
//     with returns in the body.
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
    // go: sdk 1.25.5 io/fs/fs.go:257-257 PathError.Error
    fn Error(&self) -> string {
        // Go: e.Op + " " + e.Path + ": " + e.Err.Error()
        let inner = if self.Err == errors::nil {
            string::from_static("")
        } else {
            self.Err.Error()
        };
        // Go: e.Op + " " + e.Path + ": " + e.Err.Error(). These are
        // byte strings, not Rust `str`s — building through `RustString`
        // meant a `from_utf8` at every step, and an invalid byte in a
        // path silently became "".
        let mut out: Vec<byte> = Vec::new();
        out.extend_from_slice(self.Op.as_bytes());
        out.push(b' ');
        out.extend_from_slice(self.Path.as_bytes());
        out.extend_from_slice(b": ");
        out.extend_from_slice(inner.as_bytes());
        return string::from_bytes(&out);
    }

    // go: sdk 1.25.5 io/fs/fs.go:259-259 PathError.Unwrap
    fn Unwrap(&self) -> error {
        return self.Err.clone();
    }
}

impl PathError {
    // go: sdk 1.25.5 io/fs/fs.go:262-265 PathError.Timeout
    /// Reports whether this error represents a timeout.
    ///
    /// Go asserts the anonymous `interface{ Timeout() bool }` on the
    /// wrapped error; goish's named equivalent is `net::timeout`, which
    /// is the same one-method interface with a name attached.
    pub fn Timeout(&self) -> bool {
        // `cast!` on an `error` downcasts the HANDLE, not what it
        // wraps, so it never hits. `errors::AsIface` is the assertion
        // Go writes.
        let (t, ok) = crate::errors::AsIface::<crate::d!(crate::net::net::timeout)>(&self.Err);
        return ok && t.Timeout();
    }
}

// goishlint:ignore GOISH018 errInvalid, errPermission, errExist, errNotExist, errClosed - Go declares five one-line accessors because the values live in `internal/oserror` and `io/fs` only re-exports them. goish declares them here, in the `var!` block below, so the accessors would be five functions returning a constant that is already in scope.

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

// go: sdk 1.25.5 io/fs/fs.go:158-165 FileInfo
/// `fs.FileInfo` (fs.go:158) — describes a file, returned by [`Stat`].
#[goish::interface] // goishlint:ignore GOISH022 - `goish::interface`, not `goish::int`
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

// go: sdk 1.25.5 io/fs/fs.go:93-113 DirEntry
/// `fs.DirEntry` (fs.go:93) — an entry read from a directory.
#[goish::interface] // goishlint:ignore GOISH022 - `goish::interface`, not `goish::int`
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

// go: sdk 1.25.5 io/fs/fs.go:85-89 File
/// `fs.File` (fs.go:85) — access to a single file.
#[goish::interface] // goishlint:ignore GOISH022 - `goish::interface`, not `goish::int`
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

// go: sdk 1.25.5 io/fs/fs.go:27-39 FS
/// `fs.FS` (fs.go:27) — access to a hierarchical file system.
#[goish::interface] // goishlint:ignore GOISH022 - `goish::interface`, not `goish::int`
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

// go: sdk 1.25.5 io/fs/fs.go:119-138 ReadDirFile
/// `fs.ReadDirFile` (fs.go:119) — a directory file whose entries can
/// be read with `ReadDir`. Embeds [`File`] in Go.
#[goish::interface] // goishlint:ignore GOISH022 - `goish::interface`, not `goish::int`
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
