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

pub mod exec;
pub mod signal;
pub mod user;

use crate::error;
use crate::goslice::slice;
// `crate::string` resolves both the type (gostring) and the function
// (convert) — different namespaces, both re-exported at root.
use crate::string;
use crate::io;
use crate::runtime;
use crate::syscall;
use crate::types::{byte, int};
use crate::errors::{self, nil};

extern crate alloc;
use alloc::vec::Vec;

// ─── FileMode ──────────────────────────────────────────────────────────

/// `os.FileMode` (os/types.go:34) — file mode bits. Goish slim: just
/// the high-level flag bits; permission bits in the low 9.
pub type FileMode = u32;

pub const ModeDir: FileMode = 1 << 31;
pub const ModeSymlink: FileMode = 1 << 30;
pub const ModePerm: FileMode = 0o777;

pub const O_RDONLY: i32 = syscall::O_RDONLY;
pub const O_WRONLY: i32 = 0o1;
pub const O_RDWR: i32 = 0o2;
pub const O_CREATE: i32 = 0o100;
pub const O_TRUNC: i32 = 0o1000;

pub const PathSeparator: u8 = b'/';
pub const PathListSeparator: u8 = b':';

/// `os.IsPathSeparator(c)` (path_unix.go:14) — reports whether `c` is
/// the OS's path separator. Linux-pinned in goish v1, so just `c == '/'`.
#[inline]
pub fn IsPathSeparator(c: u8) -> bool {
    c == PathSeparator
}

// os sentinels — Doctrine 2 marker form. Identity-stable, so
// `errors::Is(err, os::ErrNotExist)` works across the program.
// (Previous fn-form returned a fresh errors::New() each call — the
// Is() check could spuriously fail for sentinels stored at module
// boundary.)
crate::var! {
    /// `os.ErrInvalid` (os/error.go:19) — "invalid argument".
    pub ErrInvalid: error    = "invalid argument";

    /// `os.ErrPermission` (os/error.go:21) — "permission denied".
    pub ErrPermission: error = "permission denied";

    /// `os.ErrExist` (os/error.go:22) — "file already exists".
    pub ErrExist: error      = "file already exists";

    /// `os.ErrNotExist` (os/error.go:23) — "file does not exist".
    pub ErrNotExist: error   = "file does not exist";

    /// `os.ErrClosed` (os/error.go:24) — "file already closed".
    pub ErrClosed: error     = "file already closed";
}

/// `os.IsNotExist(err)` (os/error.go:91) — reports whether `err` is known
/// to report that a file or directory does not exist.
pub fn IsNotExist(err: error) -> bool {
    err == ErrNotExist
}

/// `os.IsExist(err)` (os/error.go:80) — reports whether `err` is known to
/// report that a file or directory already exists.
pub fn IsExist(err: error) -> bool {
    err == ErrExist
}

/// `os.IsPermission(err)` (os/error.go:100) — reports whether `err` is
/// known to report that permission is denied.
pub fn IsPermission(err: error) -> bool {
    err == ErrPermission
}

/// `os.PathError` (os/error.go:46) — records an error and the operation
/// and file path that caused it.
#[derive(Clone)]
pub struct PathError {
    pub Op: string,
    pub Path: string,
    pub Err: error,
}

impl crate::errors::ErrorTrait for PathError {
    fn Error(&self) -> string {
        self.Op.clone() + " " + self.Path.clone() + ": " + self.Err.Error()
    }
    fn Unwrap(&self) -> error {
        self.Err.clone()
    }
}

impl From<PathError> for crate::error {
    fn from(p: PathError) -> Self {
        crate::errors::Wrap(p)
    }
}

// ─── FileInfo ──────────────────────────────────────────────────────────

/// `os.FileInfo` (io/fs.FileInfo) — slim port. Carries the fields
/// most callers (FileServer, ServeFile, http.ServeContent) need.
#[derive(Clone, Default)]
pub struct FileInfo {
    name: string,
    size: int,
    mode: FileMode,
    mod_time: crate::time::Time,
    is_dir: bool,
}

// Polymorphic-nil per priority #5. Go's `os.FileInfo` is an interface
// — callers pass `nil` for "no info"; in goish we materialise that as
// a zero-valued FileInfo (Name() == "", Size() == 0, IsDir() == false).
impl From<crate::nilval::Nil> for FileInfo {
    fn from(_: crate::nilval::Nil) -> Self {
        Self::default()
    }
}
impl PartialEq<crate::nilval::Nil> for FileInfo {
    fn eq(&self, _: &crate::nilval::Nil) -> bool {
        self.name == "" && self.size == 0
    }
}
impl PartialEq<FileInfo> for crate::nilval::Nil {
    fn eq(&self, other: &FileInfo) -> bool {
        other == self
    }
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
pub fn Open<N: Into<string>>(name: N) -> (File, error) {
    let name: string = name.into();
    OpenFile(name, O_RDONLY, 0)
}

/// `os.Create(name)` (os/file.go:402) — create or truncate `name`.
pub fn Create<N: Into<string>>(name: N) -> (File, error) {
    let name: string = name.into();
    OpenFile(name, O_RDWR | O_CREATE | O_TRUNC, 0o666)
}

/// `os.OpenFile(name, flag, perm)` (os/file.go:412).
pub fn OpenFile<N: Into<string>>(name: N, flag: i32, perm: u32) -> (File, error) {
    let name: string = name.into();
    // Build a NUL-terminated path for the kernel.
    let mut buf: Vec<u8> = Vec::with_capacity(name.Len() as usize + 1);
    let nb = bytes_of(&name);
    buf.extend_from_slice(nb);
    buf.push(0);
    let fd = syscall::Open(buf.as_ptr(), flag | syscall::O_CLOEXEC, perm as i32);
    if fd < 0 {
        let err: error = if -fd == syscall::ENOENT {
            ErrNotExist.into()
        } else if -fd == syscall::EEXIST {
            ErrExist.into()
        } else {
            errors::New(string("open failed"))
        };
        return (File { fd: -1, name: name.clone() }, err);
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
pub fn Stat<N: Into<string>>(name: N) -> (FileInfo, error) {
    let name: string = name.into();
    let mut buf: Vec<u8> = Vec::with_capacity(name.Len() as usize + 1);
    let nb = bytes_of(&name);
    buf.extend_from_slice(nb);
    buf.push(0);
    let mut st = syscall::Stat_t::default();
    let rc = syscall::Stat(buf.as_ptr(), &mut st);
    if rc < 0 {
        let err: error = if -rc == syscall::ENOENT {
            ErrNotExist.into()
        } else {
            errors::New(string("stat failed"))
        };
        return (
            FileInfo {
                name: name.clone(),
                size: 0,
                mode: 0,
                mod_time: crate::time::Time::default(),
                is_dir: false,
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
pub fn Lstat<N: Into<string>>(name: N) -> (FileInfo, error) {
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
            FileInfo {
                name: name.clone(),
                size: 0,
                mode: 0,
                mod_time: crate::time::Time::default(),
                is_dir: false,
            },
            errors::New(string("lstat failed")),
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

    /// `(*File).Readdirnames(n)` (os/dir.go:46).
    /// Returns up to `n` directory entry names from the directory
    /// the receiver is open on. `n <= 0` reads all entries. Mirrors
    /// the Go shape `([]string, error)`. Names are unsorted (Go's
    /// contract).
    pub fn Readdirnames(&mut self, n: int) -> (slice<string>, error) {
        let mut names: Vec<string> = Vec::new();
        let mut buf: alloc::vec::Vec<u8> = alloc::vec![0u8; 4096];
        let want_all = n <= 0;
        let want = if want_all { usize::MAX } else { n as usize };
        loop {
            if names.len() >= want {
                break;
            }
            let got = syscall::Getdents64(self.fd, buf.as_mut_ptr(), buf.len());
            if got < 0 {
                return (
                    slice::<string>::__from_vec(names),
                    errors::New(string("readdir failed")),
                );
            }
            if got == 0 {
                break;
            }
            let total = got as usize;
            let mut pos: usize = 0;
            while pos < total && names.len() < want {
                // linux_dirent64 layout:
                //   0  d_ino     u64
                //   8  d_off     i64
                //  16  d_reclen  u16
                //  18  d_type    u8
                //  19  d_name…   NUL-terminated
                let reclen = u16::from_ne_bytes([buf[pos + 16], buf[pos + 17]]) as usize;
                let name_start = pos + 19;
                let mut name_end = name_start;
                while name_end < pos + reclen && buf[name_end] != 0 {
                    name_end += 1;
                }
                let raw = &buf[name_start..name_end];
                // Filter `.` and `..` to match Go's Readdirnames.
                if !(raw == b"." || raw == b"..") {
                    names.push(string::from_bytes(raw));
                }
                pos += reclen;
            }
        }
        (slice::<string>::__from_vec(names), nil.into())
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
pub fn ReadFile<N: Into<string>>(name: N) -> (slice<byte>, error) {
    let name: string = name.into();
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
            if crate::errors::Is(rerr.clone(), crate::io::EOF) {
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

// ─── Env / Hostname / TempDir ───────────────────────────────────────

/// `os.LookupEnv(key)` (env.go:112) — return `(value, true)` if `key`
/// is set in the process environment, `("", false)` otherwise.
pub fn LookupEnv<K: Into<string>>(key: K) -> (string, bool) {
    let key: string = key.into();
    let bytes_key = bytes_of(&key);
    let val_bytes = unsafe { runtime::args::envp_lookup(bytes_key) };
    match val_bytes {
        Some(b) => (string::from_bytes(b), true),
        None => (string::new(), false),
    }
}

/// `os.Getenv(key)` (env.go:101) — return the value of `key` in the
/// process environment, or "" if not present.
pub fn Getenv<K: Into<string>>(key: K) -> string {
    let key: string = key.into();
    let (v, _) = LookupEnv(key);
    v
}

/// Line-by-line port of `os.Setenv(key, value)` (env.go:119) — set the
/// value of the environment variable named `key`. Goish slim: writes
/// to a process-wide overlay rather than the kernel envp, so child
/// processes won't inherit the change (no exec support yet).
pub fn Setenv<K: Into<string>, V: Into<string>>(key: K, value: V) -> error {
    let key: string = key.into();
    let value: string = value.into();
    // Go: err := syscall.Setenv(key, value); ... return NewSyscallError("setenv", err)
    let kb = bytes_of(&key);
    if kb.is_empty() {
        return errors::New(string("setenv: key is empty"));
    }
    for &c in kb {
        if c == b'=' || c == 0 {
            return errors::New(string("setenv: invalid argument"));
        }
    }
    let vb = bytes_of(&value);
    for &c in vb {
        if c == 0 {
            return errors::New(string("setenv: invalid argument"));
        }
    }
    runtime::args::envp_set(kb, vb);
    nil
}

/// Line-by-line port of `os.Unsetenv(key)` (env.go:128) — unset the
/// environment variable named `key`. Goish slim: writes a tombstone
/// to the overlay rather than mutating kernel envp.
pub fn Unsetenv<K: Into<string>>(key: K) -> error {
    let key: string = key.into();
    // Go: return syscall.Unsetenv(key)
    let kb = bytes_of(&key);
    if kb.is_empty() {
        return errors::New(string("unsetenv: key is empty"));
    }
    for &c in kb {
        if c == b'=' || c == 0 {
            return errors::New(string("unsetenv: invalid argument"));
        }
    }
    runtime::args::envp_unset(kb);
    nil
}

/// Line-by-line port of `os.Environ()` (env.go:139) — return a copy of
/// the entire visible environment as a slice of `KEY=VALUE` strings.
/// Goish merges kernel envp with the Setenv/Unsetenv overlay; tombstoned
/// keys are omitted, and Setenv'd keys appear after the kernel entries.
pub fn Environ() -> slice<string> {
    // Go: copyenv(); a := make([]string, 0, len(envs)); for _, env := range envs { ... }; return a
    let bufs = unsafe { runtime::args::envp_environ() };
    let mut out: Vec<string> = Vec::with_capacity(bufs.len());
    for b in bufs.iter() {
        out.push(string::from_bytes(b));
    }
    slice::__from_vec(out)
}

/// Line-by-line port of `os.Clearenv()` (env.go:134) — delete every
/// environment variable visible to this process. Goish slim: installs
/// a tombstone for every kernel-envp key and drops overlay sets, since
/// kernel envp is read-only.
pub fn Clearenv() {
    // Go: syscall.Clearenv()
    unsafe { runtime::args::envp_clear() };
}

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
                errors::New(string(
                    "neither $XDG_CACHE_HOME nor $HOME are defined",
                )),
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
                errors::New(string(
                    "neither $XDG_CONFIG_HOME nor $HOME are defined",
                )),
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

/// Line-by-line port of `os.Getwd()` (file.go ~ getwd) — return the
/// current working directory via `getcwd(2)`. The buffer doubles up
/// to a 4 KiB cap, mirroring Go's exponential growth retry loop.
pub fn Getwd() -> (string, error) {
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
    (string::new(), errors::New(string("getwd: cwd path too long")))
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
        return errors::New(string("chdir failed"));
    }
    nil
}

/// Line-by-line port of `os.Chmod(name, mode)` (file.go:647 →
/// file_posix.go:76 chmod). Slim: no PathError wrapping, no EINTR
/// retry loop (chmod(2) is not interruptible on Linux in practice).
pub fn Chmod<N: Into<string>>(name: N, mode: FileMode) -> error {
    let name: string = name.into();
    // Go: longName := fixLongPath(name) — Linux no-op.
    // Go: e := ignoringEINTR(func() error { return syscall.Chmod(longName, syscallMode(mode)) })
    let mut buf: Vec<u8> = Vec::with_capacity(name.Len() as usize + 1);
    buf.extend_from_slice(bytes_of(&name));
    buf.push(0);
    // syscallMode(mode) for slim FileMode collapses to perm bits only.
    let rc = syscall::Chmod(buf.as_ptr(), mode & 0o7777);
    if rc < 0 {
        // Go: return &PathError{Op: "chmod", Path: name, Err: e}
        return errors::New(string("chmod failed"));
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
        return errors::New(string("symlink failed"));
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
            return (string::new(), errors::New(string("readlink failed")));
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
            return (string::new(), errors::New(string("readlink: target too long")));
        }
    }
}

/// Line-by-line port of `os.Rename(oldpath, newpath)` (file.go:440 →
/// file_unix.go:26 rename). Slim: drops the SameFile case-only-rename
/// gymnastics (Linux is always case-sensitive) but preserves the
/// "newname is a directory" prelude check so `Rename(file, dir)` errors
/// before clobbering anything.
pub fn Rename<O: Into<string>, N: Into<string>>(oldpath: O, newpath: N) -> error {
    let oldpath: string = oldpath.into();
    let newpath: string = newpath.into();
    // Go: fi, err := Lstat(newname); if err == nil && fi.IsDir() { return &LinkError{...EEXIST} }
    let (fi, e) = Lstat(newpath.clone());
    if e.IsNil() && fi.IsDir() {
        return errors::New(string("rename: newname is a directory"));
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
        return errors::New(string("rename failed"));
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
        return errors::New(string("link failed"));
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
        return errors::New(string("truncate failed"));
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
        return errors::New(string("chown failed"));
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
        return errors::New(string("lchown failed"));
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
    if rc < 0 {
        return (
            File::NewFile(-1, string::new()),
            File::NewFile(-1, string::new()),
            errors::New(string("pipe2 failed")),
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
pub fn Mkdir<N: Into<string>>(name: N, perm: u32) -> error {
    let name: string = name.into();
    let mut buf: Vec<u8> = Vec::with_capacity(name.Len() as usize + 1);
    buf.extend_from_slice(bytes_of(&name));
    buf.push(0);
    let rc = syscall::Mkdir(buf.as_ptr(), perm);
    if rc < 0 {
        return errors::New(string("mkdir failed"));
    }
    nil
}

/// `os.MkdirAll(path, perm)` (os/path.go:19) — create `path` and any
/// missing parent directories. If `path` is already a directory,
/// returns nil.
pub fn MkdirAll<P: Into<string>>(path: P, perm: u32) -> error {
    let path: string = path.into();
    // Go: dir, err := Stat(path); if err == nil { if dir.IsDir() { return nil }; return ... }
    let (dir, err) = Stat(path.clone());
    if err.IsNil() {
        if dir.IsDir() {
            return nil;
        }
        return errors::New(string("mkdir: path exists and is not a directory"));
    }

    // Go: scan back for parent.
    let bs = bytes_of(&path);
    let mut i: int = bs.len() as int - 1;
    while i >= 0 && bs[i as usize] == b'/' {
        i -= 1;
    }
    while i >= 0 && bs[i as usize] != b'/' {
        i -= 1;
    }
    if i < 0 {
        i = 0;
    }
    // Go: if parent := path[:i]; len(parent) > 0 { MkdirAll(parent, perm) }
    if i > 0 {
        let parent = string::from_bytes(&bs[..i as usize]);
        let perr = MkdirAll(parent, perm);
        if !perr.IsNil() {
            return perr;
        }
    }
    // Go: Mkdir(path, perm); on failure double-check.
    let merr = Mkdir(path.clone(), perm);
    if !merr.IsNil() {
        let (d2, err2) = Stat(path);
        if err2.IsNil() && d2.IsDir() {
            return nil;
        }
        return merr;
    }
    nil
}

/// `os.RemoveAll(path)` (os/path.go:73) — recursively delete `path`
/// and everything beneath. Missing paths return nil.
pub fn RemoveAll<P: Into<string>>(path: P) -> error {
    let path: string = path.into();
    // Stat to learn if it's a dir.
    let (fi, err) = Stat(path.clone());
    if !err.IsNil() {
        // Treat any stat failure as "doesn't exist" — matches Go's
        // os.IsNotExist short-circuit.
        return nil;
    }
    if !fi.IsDir() {
        return Remove(path);
    }
    // Recurse into children.
    let (entries, derr) = ReadDir(path.clone());
    if !derr.IsNil() {
        return derr;
    }
    for i in 0..entries.Len() {
        let e = entries[i].clone();
        let mut child = crate::strings::Builder::new();
        let _ = child.WriteString(path.clone());
        let _ = child.WriteByte(b'/');
        let _ = child.WriteString(e.Name());
        let cerr = RemoveAll(child.String());
        if !cerr.IsNil() {
            return cerr;
        }
    }
    Remove(path)
}

/// `os.Remove(name)` (os/file_unix.go). Removes a file or empty
/// directory. First tries unlink; falls back to rmdir on EISDIR.
pub fn Remove<N: Into<string>>(name: N) -> error {
    let name: string = name.into();
    let mut buf: Vec<u8> = Vec::with_capacity(name.Len() as usize + 1);
    buf.extend_from_slice(bytes_of(&name));
    buf.push(0);
    let rc = syscall::Unlink(buf.as_ptr());
    if rc == 0 {
        return nil;
    }
    // EISDIR (-21) or EPERM (-1) on dirs → try rmdir.
    let rc2 = syscall::Rmdir(buf.as_ptr());
    if rc2 == 0 {
        return nil;
    }
    errors::New(string("remove failed"))
}

// ─── DirEntry / ReadDir ──────────────────────────────────────────────

/// `os.DirEntry` (Go 1.16, os/dir.go:85). Slim subset: just name +
/// type bits. `Type()` returns the FileMode portion populated from the
/// directory's `d_type` (see `getdents64(2)`).
#[derive(Clone)]
pub struct DirEntry {
    pub Name_: string,
    pub Type_: FileMode,
}

impl DirEntry {
    /// `e.Name()` (fs/fs.go) — base name of the directory entry.
    pub fn Name(&self) -> string {
        self.Name_.clone()
    }
    /// `e.IsDir()` — convenience for `Type().IsDir()`.
    pub fn IsDir(&self) -> bool {
        (self.Type_ & ModeDir) != 0
    }
    /// `e.Type()` — entry mode bits (directory / symlink / etc.).
    pub fn Type(&self) -> FileMode {
        self.Type_
    }
}

/// `os.ReadDir(name)` (os/dir.go:114) — read directory entries from
/// `name`, returning them sorted by filename. Slim port: relies on
/// the Linux `getdents64(2)` syscall and returns `(slice<DirEntry>,
/// error)` per goish convention.
pub fn ReadDir<N: Into<string>>(name: N) -> (slice<DirEntry>, error) {
    let name: string = name.into();
    let (mut f, err) = Open(name);
    if !err.IsNil() {
        return (slice::<DirEntry>::__from_vec(Vec::new()), err);
    }
    let mut entries: Vec<DirEntry> = Vec::new();
    // 4 KiB buffer matches the kernel's per-call output size sweet spot.
    let mut buf: alloc::vec::Vec<u8> = alloc::vec![0u8; 4096];
    loop {
        let n = syscall::Getdents64(f.fd, buf.as_mut_ptr(), buf.len());
        if n < 0 {
            let _ = f.Close();
            return (
                slice::<DirEntry>::__from_vec(entries),
                errors::New(string("readdir failed")),
            );
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
                let mode = mode_from_dtype(dtype);
                entries.push(DirEntry {
                    Name_: string::from_bytes(name_bytes),
                    Type_: mode,
                });
            }
            if reclen == 0 {
                break;
            }
            pos += reclen;
        }
    }
    let _ = f.Close();
    // Sort by name (Go uses slices.SortFunc on Name).
    entries.sort_by(|a, b| {
        let ab = bytes_of(&a.Name_);
        let bb = bytes_of(&b.Name_);
        ab.cmp(bb)
    });
    (slice::<DirEntry>::__from_vec(entries), nil)
}

/// Map a `getdents64` `d_type` byte into the goish FileMode bits.
fn mode_from_dtype(dt: u8) -> FileMode {
    match dt {
        x if x == syscall::DT_DIR => ModeDir,
        x if x == syscall::DT_LNK => ModeSymlink,
        _ => 0,
    }
}

/// `os.WriteFile(name, data, perm)` (os/file.go:763) — write `data`
/// to the named file, creating or truncating it.
pub fn WriteFile<N: Into<string>>(name: N, data: slice<byte>, perm: u32) -> error {
    let name: string = name.into();
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
    pub fn NewFile<N: Into<string>>(fd: int, name: N) -> File {
        let name: string = name.into();
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

    /// `f.Sync()` — flush any buffered data to disk. Returns an error
    /// if the underlying fsync syscall fails.
    pub fn Sync(&mut self) -> error {
        if self.fd < 0 {
            return errors::New("file already closed")
        }
        let rc = unsafe { syscall::syscall1(syscall::SYS_FSYNC, self.fd as usize) };
        if rc < 0 {
            errors::New("fsync failed")
        } else {
            nil
        }
    }

    /// `f.ReadAt(buf, off)` — read from file at given offset.
    /// Does not change the current file offset.
    pub fn ReadAt(&mut self, p: &mut slice<byte>, off: i64) -> (int, error) {
        if self.fd < 0 {
            return (0, ErrClosed.into());
        }
        let len = p.len();
        let ptr = p.as_mut_ptr();
        let n = syscall::Pread64(self.fd, ptr, len, off);
        if n < 0 {
            (0, errors::New("read failed"))
        } else if n == 0 {
            (0, io::EOF.into())
        } else {
            (n as int, nil)
        }
    }

    /// `f.WriteAt(buf, off)` — write to file at given offset.
    /// Does not change the current file offset.
    pub fn WriteAt(&mut self, p: slice<byte>, off: i64) -> (int, error) {
        if self.fd < 0 {
            return (0, ErrClosed.into());
        }
        let n = syscall::Pwrite64(self.fd, p.as_ptr(), p.len(), off);
        if n < 0 {
            (0, errors::New("write failed"))
        } else {
            (n as int, nil)
        }
    }

    /// `f.Truncate(size)` — truncate file to given size.
    pub fn Truncate(&mut self, size: int) -> error {
        if self.fd < 0 {
            return ErrClosed.into();
        }
        let rc = syscall::Ftruncate(self.fd, size as i64);
        if rc < 0 {
            errors::New("truncate failed")
        } else {
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
            (0, io::EOF.into())
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
