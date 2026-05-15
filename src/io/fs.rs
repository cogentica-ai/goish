// io/fs — line-by-line port of Go 1.25 io/fs/fs.go (slim).
//
// Source: /nix/store/60z37432vmgkg54krwr1z057bqwp7583-go-1.25.5/share/go/src/io/fs/fs.go
//
// What this slim port covers:
//   * `FileMode` newtype + all bits + String/IsDir/IsRegular/Perm/Type
//   * `ValidPath`
//   * `PathError` + Error/Unwrap
//   * Sentinel errors: ErrInvalid, ErrPermission, ErrExist, ErrNotExist, ErrClosed
//
// What it doesn't cover (deferred):
//   * `FS`, `File`, `ReadDirFile`, `FileInfo`, `DirEntry` traits — `os`
//     already exposes concrete `os::FileInfo` / `os::DirEntry`. Adding
//     traits here would require refactoring callers to be generic over
//     filesystem type. That's a separate task once a second FS impl
//     (testing/fstest, embed) gets ported.
//   * `WalkDir`, `ReadFile`, `Stat`, `Sub`, `Glob`, `ReadDir` package
//     functions — they all take an `FS` arg, so they wait for the
//     trait port above.

#![allow(non_snake_case)]

extern crate alloc;
use alloc::string::String as RustString;
use alloc::vec::Vec;

use crate::errors::{self, error, ErrorTrait};
use crate::goslice::slice;
use crate::gostring::string;
use crate::types::{byte, int, rune};
use crate::unicode::utf8;

// Go's `io/fs` re-exports `FileInfo` (defined in fs.go:130) as the
// canonical interface — `os.FileInfo` is the same type. Mirror that
// here so call sites can write `fs::FileInfo` interchangeably with
// `os::FileInfo`. Goish's representation: trait `FileInfo`
// (`os::FileInfo`) + concrete `FileInfoData` (`os::FileInfoData`)
// that implements the trait.
pub use crate::os::{FileInfo, FileInfoData};

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

// Suppress unused-import warnings for items pulled in for completeness.
#[allow(dead_code)]
fn _unused_imports() {
    let _: int = 0;
    let _: rune = 'a' as rune;
    let _v: Vec<u8> = Vec::new();
    let _s: slice<byte> = slice::__from_vec(_v);
}
