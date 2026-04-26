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
