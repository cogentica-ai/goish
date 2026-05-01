// os — Go's `os` package, ported.
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

pub mod signal;

use crate::errors::error;
use crate::goslice::slice;
// `crate::string` resolves both the type (gostring) and the function
// (convert) — different namespaces, both re-exported at root.
use crate::string;
use crate::io;
use crate::runtime;
use crate::syscall;
use crate::types::{byte, int};
use crate::{errors, nil};

extern crate alloc;
use alloc::vec::Vec;

// ─── FileMode ──────────────────────────────────────────────────────────

/// `os.FileMode` (os/types.go:34) — file mode bits. Goish slim: just
/// the high-level flag bits; permission bits in the low 9.
pub type FileMode = u32;

pub const ModeDir: FileMode = 1 << 31;
pub const ModeSymlink: FileMode = 1 << 30;
pub const ModePerm: FileMode = 0o777;

/// `os.Open` flag aliases (os/file.go).
pub const O_RDONLY: i32 = syscall::O_RDONLY;
pub const O_WRONLY: i32 = 0o1;
pub const O_RDWR: i32 = 0o2;
pub const O_CREATE: i32 = 0o100;
pub const O_TRUNC: i32 = 0o1000;
pub const O_APPEND: i32 = 0o2000;
pub const O_EXCL: i32 = 0o200;

// ─── FileInfo ──────────────────────────────────────────────────────────

/// `os.FileInfo` (io/fs.FileInfo) — slim port. Carries the fields
/// most callers (FileServer, ServeFile, http.ServeContent) need.
#[derive(Clone)]
pub struct FileInfo {
    name: string,
    size: int,
    mode: FileMode,
    mod_time: crate::time::Time,
    is_dir: bool,
}

impl FileInfo {
    /// `f.Name()` — base name of the file (no directory component).
    pub fn Name(&self) -> string {
        self.name.clone()
    }
    /// `f.Size()` — size in bytes for regular files.
    pub fn Size(&self) -> int {
        self.size
    }
    /// `f.Mode()` — permission + type bits.
    pub fn Mode(&self) -> FileMode {
        self.mode
    }
    /// `f.ModTime()` — last modification time.
    pub fn ModTime(&self) -> crate::time::Time {
        self.mod_time
    }
    /// `f.IsDir()` — convenience for `mode & ModeDir != 0`.
    pub fn IsDir(&self) -> bool {
        self.is_dir
    }
}

fn fileinfo_from_stat(name: string, st: &syscall::Stat_t) -> FileInfo {
    let kind = st.st_mode & syscall::S_IFMT;
    let is_dir = kind == syscall::S_IFDIR;
    let mut mode: FileMode = (st.st_mode & 0o777) as FileMode;
    if is_dir {
        mode |= ModeDir;
    }
    if kind == syscall::S_IFLNK {
        mode |= ModeSymlink;
    }
    FileInfo {
        name,
        size: st.st_size,
        mode,
        mod_time: crate::time::Unix(st.st_mtime, st.st_mtime_nsec as int),
        is_dir,
    }
}

// ─── Open / Stat / Create ──────────────────────────────────────────────

/// `os.Open(name)` (os/file.go:386) — open `name` read-only.
pub fn Open(name: string) -> (File, error) {
    OpenFile(name, O_RDONLY, 0)
}

/// `os.Create(name)` (os/file.go:402) — create or truncate `name`.
pub fn Create(name: string) -> (File, error) {
    OpenFile(name, O_RDWR | O_CREATE | O_TRUNC, 0o666)
}

/// `os.OpenFile(name, flag, perm)` (os/file.go:412).
pub fn OpenFile(name: string, flag: i32, perm: u32) -> (File, error) {
    // Build a NUL-terminated path for the kernel.
    let mut buf: Vec<u8> = Vec::with_capacity(name.Len() as usize + 1);
    let nb = bytes_of(&name);
    buf.extend_from_slice(nb);
    buf.push(0);
    let fd = syscall::Open(buf.as_ptr(), flag | syscall::O_CLOEXEC, perm as i32);
    if fd < 0 {
        return (
            File {
                fd: -1,
                name: name.clone(),
            },
            errors::New(string("open failed")),
        );
    }
    (
        File {
            fd,
            name: name.clone(),
        },
        nil,
    )
}

/// `os.Stat(name)` (os/stat.go:14) — stat a path, following symlinks.
pub fn Stat(name: string) -> (FileInfo, error) {
    let mut buf: Vec<u8> = Vec::with_capacity(name.Len() as usize + 1);
    let nb = bytes_of(&name);
    buf.extend_from_slice(nb);
    buf.push(0);
    let mut st = syscall::Stat_t::default();
    let rc = syscall::Stat(buf.as_ptr(), &mut st);
    if rc < 0 {
        return (
            FileInfo {
                name: name.clone(),
                size: 0,
                mode: 0,
                mod_time: crate::time::Time::default(),
                is_dir: false,
            },
            errors::New(string("stat failed")),
        );
    }
    let base = base_name(&name);
    (fileinfo_from_stat(base, &st), nil)
}

/// `(*File).Stat()` (os/file.go:432) — fstat the open fd.
impl File {
    pub fn Stat(&self) -> (FileInfo, error) {
        let mut st = syscall::Stat_t::default();
        let rc = syscall::Fstat(self.fd, &mut st);
        if rc < 0 {
            return (
                FileInfo {
                    name: self.name.clone(),
                    size: 0,
                    mode: 0,
                    mod_time: crate::time::Time::default(),
                    is_dir: false,
                },
                errors::New(string("fstat failed")),
            );
        }
        let base = base_name(&self.name);
        (fileinfo_from_stat(base, &st), nil)
    }

    /// `(*File).Seek(offset, whence)` (os/file.go:286).
    pub fn Seek(&self, offset: int, whence: int) -> (int, error) {
        let rc = syscall::Lseek(self.fd, offset, whence as i32);
        if rc < 0 {
            return (0, errors::New(string("seek failed")));
        }
        (rc as int, nil)
    }
}

/// Pull the file path's bytes via the pub(crate) accessor.
fn bytes_of(s: &string) -> &[u8] {
    crate::gostring::__crate_as_bytes(s)
}

/// `os.ReadFile(name)` (os/file.go:735) — read the entire named file
/// and return its contents. Closes the file before returning.
pub fn ReadFile(name: string) -> (slice<byte>, error) {
    use crate::io::Reader;
    let (mut f, err) = Open(name);
    if !err.IsNil() {
        return (slice::<byte>::__from_vec(Vec::new()), err);
    }
    let (fi, ferr) = f.Stat();
    if !ferr.IsNil() {
        let _ = f.Close();
        return (slice::<byte>::__from_vec(Vec::new()), ferr);
    }
    let want = fi.Size();
    let mut body = slice::<byte>::__from_vec(alloc::vec![0u8; want as usize]);
    let mut got: int = 0;
    while got < want {
        let mut chunk =
            slice::<byte>::__from_vec(alloc::vec![0u8; (want - got) as usize]);
        let (n, rerr) = f.Read(&mut chunk);
        if n > 0 {
            for i in 0..n {
                body[got + i] = chunk[i];
            }
            got += n;
        }
        if !rerr.IsNil() {
            if crate::errors::Is(rerr.clone(), crate::io::EOF()) {
                break;
            }
            let _ = f.Close();
            return (body, rerr);
        }
        if n == 0 {
            break;
        }
    }
    let _ = f.Close();
    if got < want {
        body = body.slice(0, got);
    }
    (body, nil)
}

/// `os.WriteFile(name, data, perm)` (os/file.go:763) — write `data`
/// to the named file, creating or truncating it.
pub fn WriteFile(name: string, data: slice<byte>, perm: u32) -> error {
    use crate::io::Writer;
    let (mut f, err) = OpenFile(name, O_WRONLY | O_CREATE | O_TRUNC, perm);
    if !err.IsNil() {
        return err;
    }
    let (_, werr) = f.Write(data);
    let cerr = f.Close();
    if !werr.IsNil() {
        return werr;
    }
    cerr
}

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
pub struct File {
    fd: i32,
    name: string,
}

impl File {
    /// `os.NewFile(fd, name)` — wrap an existing fd. Public so user code
    /// can construct from raw fds (rare; mostly used by stdio factories
    /// and future Pipe/Open functions).
    pub fn NewFile(fd: int, name: string) -> File {
        File {
            fd: fd as i32,
            name,
        }
    }

    /// `f.Fd()` — raw fd as int.
    pub fn Fd(&self) -> int {
        self.fd as int
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
            return nil;
        }
        let rc = unsafe { syscall::syscall1(syscall::SYS_CLOSE, self.fd as usize) };
        let old_fd = self.fd;
        self.fd = -1;
        if rc < 0 {
            errors::New("close failed")
        } else {
            let _ = old_fd;
            nil
        }
    }
}

impl io::Writer for File {
    fn Write(&mut self, p: slice<byte>) -> (int, error) {
        let n = syscall::Write(self.fd, p.as_ptr(), p.len());
        if n < 0 {
            (0, errors::New("write failed"))
        } else {
            (n as int, nil)
        }
    }
}

impl io::Reader for File {
    fn Read(&mut self, p: &mut slice<byte>) -> (int, error) {
        // p.len() is from Deref<[T]>. p.as_mut_ptr() needs DerefMut → [T].
        let len = p.len();
        let ptr = p.as_mut_ptr();
        let n = syscall::Read(self.fd, ptr, len);
        if n < 0 {
            (0, errors::New("read failed"))
        } else if n == 0 {
            // Convention: Read returns (0, EOF) on end-of-input.
            (0, io::EOF())
        } else {
            (n as int, nil)
        }
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
