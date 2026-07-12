// os/exec — minimal Linux fork+exec port of Go's `os/exec`.
//
// Surface (v2 — stdin pipe wired):
//
//   var ErrNotFound = errors.New("executable file not found in $PATH")
//   func LookPath(file string) (string, error)
//   func Command(name string, args ...string) *Cmd
//   type Cmd struct {
//       Path   string
//       Args   []string
//       Env    []string                 // KEY=VALUE; nil means inherit
//       Dir    string                   // not yet honored (v2: cwd inherited)
//       Stdin  io.Reader                // honored: piped to child fd 0
//       Stdout io.Writer                // captured via pipe + drained synchronously
//       Stderr io.Writer                // captured via pipe + drained synchronously
//   }
//   func (c *Cmd) SetStdin(r io.Reader)
//   func (c *Cmd) StdinPipe() (io.WriteCloser, error)
//   func (c *Cmd) Run() error
//   func (c *Cmd) Start() error
//   func (c *Cmd) Wait() error
//
// Process model (stdin path):
//   1. Pipe2 for stdin (read_end → child fd 0, write_end → parent).
//      Pipe2 for stdout/stderr as before.
//   2. Fork. Child wires fd 0/1/2, closes all parent ends, Execve.
//   3. Parent closes child ends.
//      - If Stdin reader present: goroutine does io::Copy(write_end, reader)
//        then closes write_end.
//      - If StdinPipe was called: write_end was already returned to the caller;
//        parent just holds the read_end state (nothing to close yet).
//   4. Drains stdout/stderr, then Wait4.
//
// Slim deviations from Go:
//   * `Cmd.Dir` is parsed but not honored.
//   * `Cmd.SysProcAttr`, `Cmd.ExtraFiles`, `Cmd.Env` (when nil →
//     inherit), `ProcessState` all elided.
//   * `StdinPipe()` must be called before `Start()` / `Run()`.
//   * `Start()` + `Wait()` split is now supported.

#![allow(non_snake_case)]

extern crate alloc;

use alloc::sync::Arc;
use alloc::vec::Vec;

use crate::errors;
use crate::error;
use crate::goslice::slice;
use crate::gostring::string;
use crate::io;
use crate::io::Closer as _;
use crate::syscall;
use crate::types::{byte, int};

// ─── FdWriter / FdReader ───────────────────────────────────────────────
//
// Thin wrappers around a raw fd that implement io::Writer / io::Reader /
// io::Closer. Used as the writable half of a stdin pipe returned by
// StdinPipe(), and internally for feeding stdin from a goroutine.
//
// Both types are `Send` because they hold no thread-local state —
// all I/O is done via kernel syscalls.

/// Writable end of a raw OS pipe (or any fd open for writing).
/// Returned by `Cmd::StdinPipe()` to the caller.
pub struct FdWriter {
    fd: i32,
}

impl FdWriter {
    /// Wrap a raw file descriptor. Takes ownership: `Close()` will
    /// call `syscall::Close(fd)`.
    pub fn from_raw(fd: i32) -> Self {
        FdWriter { fd }
    }
    /// Expose the underlying raw fd (for child-side dup3 use).
    pub fn as_raw_fd(&self) -> i32 {
        self.fd
    }
}

impl io::Writer for FdWriter {
    fn Write(&mut self, p: slice<byte>) -> (int, error) {
        if self.fd < 0 {
            return (0, errors::New("write on closed FdWriter"));
        }
        let n = syscall::Write(self.fd, p.as_ptr(), p.Len() as usize);
        if n < 0 {
            (0, errors::New("write failed"))
        } else {
            (n as int, crate::nilval::nil.into())
        }
    }
}

impl io::Closer for FdWriter {
    fn Close(&mut self) -> error {
        if self.fd < 0 {
            return crate::nilval::nil.into();
        }
        syscall::Close(self.fd);
        self.fd = -1;
        crate::nilval::nil.into()
    }
}

// SAFETY: FdWriter contains only an i32 fd, which is a kernel handle.
// We never expose a raw pointer to shared state. Sync is sound for the same
// reason (an fd integer); concurrent use is the caller's responsibility, as in Go.
unsafe impl Send for FdWriter {}
unsafe impl Sync for FdWriter {}

/// Readable end of a raw OS pipe. Returned by `Cmd::StdoutPipe()` /
/// `Cmd::StderrPipe()`; the caller reads the child's output from it while the
/// child runs and closes it after `Wait()`.
pub struct FdReader {
    fd: i32,
}

impl FdReader {
    /// Wrap a raw file descriptor. Takes ownership: `Close()` will
    /// call `syscall::Close(fd)`.
    pub fn from_raw(fd: i32) -> Self {
        FdReader { fd }
    }
    /// Expose the underlying raw fd.
    pub fn as_raw_fd(&self) -> i32 {
        self.fd
    }
}

impl io::Reader for FdReader {
    fn Read(&mut self, p: &mut slice<byte>) -> (int, error) {
        if self.fd < 0 {
            return (0, io::EOF.into());
        }
        let cap = p.Len() as usize;
        let n = syscall::Read(self.fd, p.as_mut_ptr(), cap);
        if n == 0 {
            (0, io::EOF.into())
        } else if n < 0 {
            (0, errors::New("read failed"))
        } else {
            (n as int, crate::nilval::nil.into())
        }
    }
}

impl io::Closer for FdReader {
    fn Close(&mut self) -> error {
        if self.fd < 0 {
            return crate::nilval::nil.into();
        }
        syscall::Close(self.fd);
        self.fd = -1;
        crate::nilval::nil.into()
    }
}

unsafe impl Send for FdReader {}
unsafe impl Sync for FdReader {}

// Sentinel returned by `LookPath` when no matching executable is on
// `$PATH`. Mirrors `exec.ErrNotFound`.
crate::var! {
    pub ErrNotFound: error = "executable file not found in $PATH";
}

/// `exec.Cmd` — a one-shot subprocess. Build via `Command(name, args)`.
pub struct Cmd {
    /// Absolute path to the binary. Set by `Command` via `LookPath`.
    pub Path: string,
    /// Argv passed to the child (Args[0] is conventionally `Path`'s
    /// basename).
    pub Args: slice<string>,
    /// Optional explicit environment. `nil`-equivalent (empty) means
    /// inherit the current process's environment.
    pub Env: slice<string>,
    /// Optional working directory. Currently parsed but not honored.
    pub Dir: string,
    /// Optional stdin source. If set, a pipe is created and a goroutine
    /// copies from this reader to the child's stdin.
    pub Stdin: Option<Arc<crate::sync::Mutex<core::cell::UnsafeCell<alloc::boxed::Box<dyn io::Reader + Send>>>>>,
    /// Where to copy the child's stdout. None ≡ inherit (v2: discard
    /// captured bytes).
    pub Stdout: Option<Arc<crate::sync::Mutex<core::cell::UnsafeCell<alloc::boxed::Box<dyn io::Writer + Send>>>>>,
    /// Where to copy the child's stderr. None ≡ inherit (v2: discard).
    pub Stderr: Option<Arc<crate::sync::Mutex<core::cell::UnsafeCell<alloc::boxed::Box<dyn io::Writer + Send>>>>>,
    /// PID of the running child; set by Start(), cleared by Wait().
    /// -1 means "not started" or "already waited".
    pid: i32,
    /// If StdinPipe() was called, this holds the read end of the stdin
    /// pipe so Run/Start can dup it onto fd 0 in the child. -1 otherwise.
    stdin_pipe_read_fd: i32,
    /// Read-end fds of the stdout/stderr capture pipes, cached between
    /// Start() and Wait() so Wait() can drain them.  -1 when not used.
    cached_out_fd: i32,
    cached_err_fd: i32,
    /// If StdoutPipe()/StderrPipe() was called, the write end of the pipe to
    /// dup onto the child's fd 1 / fd 2. The caller holds the read end (an
    /// FdReader) and reads it directly — not drained by Wait(). -1 otherwise.
    stdout_pipe_write_fd: i32,
    stderr_pipe_write_fd: i32,
}

impl Cmd {
    /// Wire `Stdout` from a typed Writer. The Go API just assigns
    /// `cmd.Stdout = &buf`; in goish we offer a convenience that takes
    /// a goish-style Writer and stashes it under the lock+UnsafeCell
    /// dance the field expects.
    pub fn SetStdout<W: io::Writer + Send + 'static>(&mut self, w: W) {
        self.Stdout = Some(Arc::new(crate::sync::Mutex::new(
            core::cell::UnsafeCell::new(alloc::boxed::Box::new(w))
        )));
    }
    pub fn SetStderr<W: io::Writer + Send + 'static>(&mut self, w: W) {
        self.Stderr = Some(Arc::new(crate::sync::Mutex::new(
            core::cell::UnsafeCell::new(alloc::boxed::Box::new(w))
        )));
    }

    /// Wire `Stdin` from a typed Reader. Before fork, a pipe is created;
    /// in the child the read end is dup'd onto fd 0. In the parent a
    /// goroutine copies from this reader to the write end.
    ///
    /// Mirrors Go's `cmd.Stdin = reader` assignment.
    pub fn SetStdin<R: io::Reader + Send + 'static>(&mut self, r: R) {
        self.Stdin = Some(Arc::new(crate::sync::Mutex::new(
            core::cell::UnsafeCell::new(alloc::boxed::Box::new(r))
        )));
    }

    /// `(*Cmd).StdinPipe()` — return an `FdWriter` whose read end will
    /// become the child's stdin. The caller writes to the returned writer
    /// (before or after `Start()`); the child reads from its fd 0.
    ///
    /// Must be called before `Start()` or `Run()`.
    /// The caller is responsible for closing the returned writer;
    /// the child's stdin reaches EOF when the write end is closed.
    ///
    /// Mirrors Go's `(*Cmd).StdinPipe() (io.WriteCloser, error)`.
    pub fn StdinPipe(&mut self) -> (FdWriter, error) {
        if self.stdin_pipe_read_fd >= 0 {
            return (FdWriter::from_raw(-1),
                    errors::New("os/exec: StdinPipe already called"));
        }
        if self.pid >= 0 {
            return (FdWriter::from_raw(-1),
                    errors::New("os/exec: StdinPipe called after Start"));
        }
        let mut pipe_fds = [-1i32; 2];
        let r = syscall::Pipe2(&mut pipe_fds, syscall::O_CLOEXEC);
        if r < 0 {
            return (FdWriter::from_raw(-1),
                    errors::New("os/exec: StdinPipe pipe2 failed"));
        }
        // pipe_fds[0] = read end (child will inherit via dup3)
        // pipe_fds[1] = write end (returned to caller)
        self.stdin_pipe_read_fd = pipe_fds[0];
        // Clear O_CLOEXEC on the write end so we can close it ourselves
        // after Start without racing the child.
        // (The read end will be dup'd onto fd 0 in the child, so
        //  O_CLOEXEC on it is fine — dup3 without O_CLOEXEC clears it.)
        (FdWriter::from_raw(pipe_fds[1]), crate::nilval::nil.into())
    }

    /// `(*Cmd).StdoutPipe()` — return an `FdReader` connected to the child's
    /// stdout (fd 1). The caller reads the child's output from it while the
    /// child runs, and should read to EOF before calling `Wait()`.
    ///
    /// Must be called before `Start()` or `Run()`.
    /// Mirrors Go's `(*Cmd).StdoutPipe() (io.ReadCloser, error)`.
    pub fn StdoutPipe(&mut self) -> (FdReader, error) {
        if self.stdout_pipe_write_fd >= 0 || self.Stdout.is_some() {
            return (FdReader::from_raw(-1),
                    errors::New("os/exec: Stdout already set"));
        }
        if self.pid >= 0 {
            return (FdReader::from_raw(-1),
                    errors::New("os/exec: StdoutPipe called after Start"));
        }
        let mut pipe_fds = [-1i32; 2];
        let r = syscall::Pipe2(&mut pipe_fds, syscall::O_CLOEXEC);
        if r < 0 {
            return (FdReader::from_raw(-1),
                    errors::New("os/exec: StdoutPipe pipe2 failed"));
        }
        // pipe_fds[0] = read end (returned to caller)
        // pipe_fds[1] = write end (child's fd 1 via dup3 in Start)
        self.stdout_pipe_write_fd = pipe_fds[1];
        (FdReader::from_raw(pipe_fds[0]), crate::nilval::nil.into())
    }

    /// `(*Cmd).StderrPipe()` — return an `FdReader` connected to the child's
    /// stderr (fd 2). Symmetric to `StdoutPipe()`.
    ///
    /// Must be called before `Start()` or `Run()`.
    /// Mirrors Go's `(*Cmd).StderrPipe() (io.ReadCloser, error)`.
    pub fn StderrPipe(&mut self) -> (FdReader, error) {
        if self.stderr_pipe_write_fd >= 0 || self.Stderr.is_some() {
            return (FdReader::from_raw(-1),
                    errors::New("os/exec: Stderr already set"));
        }
        if self.pid >= 0 {
            return (FdReader::from_raw(-1),
                    errors::New("os/exec: StderrPipe called after Start"));
        }
        let mut pipe_fds = [-1i32; 2];
        let r = syscall::Pipe2(&mut pipe_fds, syscall::O_CLOEXEC);
        if r < 0 {
            return (FdReader::from_raw(-1),
                    errors::New("os/exec: StderrPipe pipe2 failed"));
        }
        self.stderr_pipe_write_fd = pipe_fds[1];
        (FdReader::from_raw(pipe_fds[0]), crate::nilval::nil.into())
    }
}

/// `exec.Command(name, args...)`. The first arg is the program name —
/// run through `LookPath` if it has no `/` separator. Args[0] is set
/// to `name` itself (matching Go's `cmd.Args[0] = cmd.Path` only if
/// the lookup succeeded — Go preserves the original name on failure
/// so callers see the typo'd argv[0] in error messages).
pub fn Command<S: Into<string>>(name: S, args: slice<string>) -> Cmd {
    let name = name.into();
    let path = if name_has_slash(&name) {
        name.clone()
    } else {
        let (p, err) = LookPath(name.clone());
        if err == crate::nilval::nil { p } else { name.clone() }
    };
    let mut full = crate::make!([]string, 0, crate::len(&args) + 1);
    full = crate::append!(full, name);
    let argc = crate::len(&args);
    let mut i: int = 0;
    while i < argc {
        full = crate::append!(full, args[i].clone());
        i += 1;
    }
    Cmd {
        Path: path,
        Args: full,
        Env: crate::make!([]string, 0),
        Dir: string::new(),
        Stdin: None,
        Stdout: None,
        Stderr: None,
        pid: -1,
        stdin_pipe_read_fd: -1,
        cached_out_fd: -1,
        cached_err_fd: -1,
        stdout_pipe_write_fd: -1,
        stderr_pipe_write_fd: -1,
    }
}

/// `exec.LookPath(file)` — find an executable on `$PATH`. Returns the
/// absolute path, or `ErrNotFound`. `file` containing `/` is returned
/// as-is (Go semantics: the lookup is skipped, but the file's
/// existence isn't verified — same here).
pub fn LookPath<S: Into<string>>(file: S) -> (string, error) {
    let file = file.into();
    if name_has_slash(&file) {
        return (file, crate::nilval::nil.into());
    }
    let path = crate::os::Getenv("PATH");
    if path.Len() == 0 {
        return (string::new(), ErrNotFound.into());
    }
    let dirs = crate::strings::Split(path, ":");
    let n = crate::len(&dirs);
    let mut i: int = 0;
    while i < n {
        let dir = dirs[i].clone();
        i += 1;
        if dir.Len() == 0 { continue; }
        let candidate = dir + string::from_static("/") + file.clone();
        if file_is_accessible(&candidate) {
            return (candidate, crate::nilval::nil.into());
        }
    }
    (string::new(), ErrNotFound.into())
}

fn name_has_slash(s: &string) -> bool {
    use crate::builtin::Len;
    let n = s.__len();
    let mut i: int = 0;
    while i < n {
        if s[i] == b'/' { return true; }
        i += 1;
    }
    false
}

fn file_is_accessible(path: &string) -> bool {
    // Use stat(2) to check existence + executable bit. faccessat(2)
    // would be more honest about X_OK + UID/GID resolution but isn't
    // wired in goish::syscall yet. For v1 a regular-file existence
    // check is enough: $PATH lookups by definition target executables.
    let mut buf: Vec<u8> = Vec::with_capacity(path.Len() as usize + 1);
    for &b in path.as_bytes() { buf.push(b); }
    buf.push(0);
    let mut st: syscall::Stat_t = Default::default();
    let r = unsafe {
        syscall::syscall4(
            syscall::SYS_NEWFSTATAT,
            syscall::AT_FDCWD as usize,
            buf.as_ptr() as usize,
            (&mut st as *mut syscall::Stat_t) as usize,
            0,
        )
    };
    r == 0 && (st.st_mode & syscall::S_IFMT) == syscall::S_IFREG
}

impl Cmd {
    /// `(*Cmd).Start()` — fork and exec the child, wiring all configured
    /// pipes. Returns immediately (without waiting). Call `Wait()` after
    /// all I/O is complete to collect the exit status.
    ///
    /// If `Stdin` was set via `SetStdin`, a goroutine is spawned that
    /// copies from the reader to the child's stdin; the goroutine closes
    /// the write end when the reader reaches EOF.
    ///
    /// If `StdinPipe()` was called, the read end is wired to fd 0 in the
    /// child and then closed in the parent; the caller holds the write end
    /// and is responsible for closing it.
    pub fn Start(&mut self) -> error {
        if self.Path.Len() == 0 {
            return ErrNotFound.into();
        }
        if self.pid >= 0 {
            return errors::New("os/exec: already started");
        }

        // ── Build C-string argv ──────────────────────────────────────
        let mut argv_bufs: Vec<Vec<u8>> = Vec::with_capacity(crate::len(&self.Args) as usize);
        for_each_arg(&self.Args, |s| {
            let mut b = Vec::with_capacity(s.Len() as usize + 1);
            for &x in s.as_bytes() { b.push(x); }
            b.push(0);
            argv_bufs.push(b);
        });
        let mut argv_ptrs: Vec<*const u8> = argv_bufs.iter().map(|b| b.as_ptr()).collect();
        argv_ptrs.push(core::ptr::null());

        // ── Path NUL-buffer ─────────────────────────────────────────
        let mut path_buf = Vec::with_capacity(self.Path.Len() as usize + 1);
        for &x in self.Path.as_bytes() { path_buf.push(x); }
        path_buf.push(0);

        // ── Build envp ──────────────────────────────────────────────
        let env_strings: slice<string> = if crate::len(&self.Env) > 0 {
            self.Env.clone()
        } else {
            crate::os::Environ()
        };
        let mut envp_bufs: Vec<Vec<u8>> = Vec::with_capacity(crate::len(&env_strings) as usize);
        for_each_arg(&env_strings, |s| {
            let mut b = Vec::with_capacity(s.Len() as usize + 1);
            for &x in s.as_bytes() { b.push(x); }
            b.push(0);
            envp_bufs.push(b);
        });
        let mut envp_ptrs: Vec<*const u8> = envp_bufs.iter().map(|b| b.as_ptr()).collect();
        envp_ptrs.push(core::ptr::null());

        // ── Stdin pipe ──────────────────────────────────────────────
        // Three cases:
        //   A) Stdin reader set via SetStdin → create pipe, goroutine feeds it.
        //   B) StdinPipe() was called → self.stdin_pipe_read_fd is already set.
        //   C) Neither → child inherits parent's fd 0.
        let mut in_pipe = [-1i32; 2]; // [read_end, write_end]
        let mut in_write_fd_for_goroutine: i32 = -1; // write end to hand to goroutine
        let want_in_reader = self.Stdin.is_some();
        let want_in_pipe   = self.stdin_pipe_read_fd >= 0;

        if want_in_reader {
            let r = syscall::Pipe2(&mut in_pipe, syscall::O_CLOEXEC);
            if r < 0 {
                return errors::New("os/exec: pipe2 failed for stdin");
            }
            in_write_fd_for_goroutine = in_pipe[1];
        } else if want_in_pipe {
            // StdinPipe() already opened the pipe; the read end is stored.
            in_pipe[0] = self.stdin_pipe_read_fd;
            // in_pipe[1] is with the caller; we don't own it here.
        }

        // ── Stdout/Stderr pipes ──────────────────────────────────────
        // Two cases each, mirroring stdin:
        //   • SetStdout/SetStderr → Stdout/Stderr writer set → create a capture
        //     pipe; the parent caches the read end and Wait() drains it.
        //   • StdoutPipe()/StderrPipe() → the pipe was already created; the write
        //     end is stored here and the caller already holds the read end (it
        //     reads concurrently with the running child). Not drained by Wait().
        let mut out_pipe = [-1i32; 2];
        let mut err_pipe = [-1i32; 2];
        let want_out = self.Stdout.is_some();
        let want_err = self.Stderr.is_some();
        let want_out_pipe = self.stdout_pipe_write_fd >= 0;
        let want_err_pipe = self.stderr_pipe_write_fd >= 0;
        if want_out {
            let r = syscall::Pipe2(&mut out_pipe, syscall::O_CLOEXEC);
            if r < 0 {
                if want_in_reader { syscall::Close(in_pipe[0]); syscall::Close(in_pipe[1]); }
                return errors::New("os/exec: pipe2 failed for stdout");
            }
        } else if want_out_pipe {
            // out_pipe[0] (read end) is with the caller; we only hold the write end.
            out_pipe[1] = self.stdout_pipe_write_fd;
        }
        if want_err {
            let r = syscall::Pipe2(&mut err_pipe, syscall::O_CLOEXEC);
            if r < 0 {
                if want_in_reader { syscall::Close(in_pipe[0]); syscall::Close(in_pipe[1]); }
                if want_out { syscall::Close(out_pipe[0]); syscall::Close(out_pipe[1]); }
                return errors::New("os/exec: pipe2 failed for stderr");
            }
        } else if want_err_pipe {
            err_pipe[1] = self.stderr_pipe_write_fd;
        }

        // ── Fork ─────────────────────────────────────────────────────
        let pid = syscall::Fork();
        if pid < 0 {
            if want_in_reader { syscall::Close(in_pipe[0]); syscall::Close(in_pipe[1]); }
            if want_out { syscall::Close(out_pipe[0]); syscall::Close(out_pipe[1]); }
            if want_err { syscall::Close(err_pipe[0]); syscall::Close(err_pipe[1]); }
            // For the StdoutPipe/StderrPipe cases we own only the write end; the
            // caller holds the read end and will see EOF once it is closed.
            if want_out_pipe { syscall::Close(out_pipe[1]); self.stdout_pipe_write_fd = -1; }
            if want_err_pipe { syscall::Close(err_pipe[1]); self.stderr_pipe_write_fd = -1; }
            return errors::New("os/exec: fork failed");
        }

        if pid == 0 {
            // ── CHILD ───────────────────────────────────────────────
            // After fork only async-signal-safe ops are guaranteed.
            // All buffers were prepared before the fork.

            // Wire stdin (fd 0).
            if want_in_reader || want_in_pipe {
                // Close the write end (child doesn't need it).
                if want_in_reader && in_pipe[1] >= 0 {
                    syscall::Close(in_pipe[1]);
                }
                // Dup read end onto fd 0 (flags=0 clears O_CLOEXEC).
                if syscall::Dup3(in_pipe[0], 0, 0) < 0 {
                    child_die(127);
                }
                syscall::Close(in_pipe[0]);
            }

            // Wire stdout (fd 1). Covers both SetStdout (capture) and StdoutPipe.
            if want_out || want_out_pipe {
                if out_pipe[0] >= 0 { syscall::Close(out_pipe[0]); }
                if syscall::Dup3(out_pipe[1], 1, 0) < 0 { child_die(127); }
                syscall::Close(out_pipe[1]);
            }
            // Wire stderr (fd 2). Covers both SetStderr (capture) and StderrPipe.
            if want_err || want_err_pipe {
                if err_pipe[0] >= 0 { syscall::Close(err_pipe[0]); }
                if syscall::Dup3(err_pipe[1], 2, 0) < 0 { child_die(127); }
                syscall::Close(err_pipe[1]);
            }

            let _ = syscall::Execve(
                path_buf.as_ptr(),
                argv_ptrs.as_ptr(),
                envp_ptrs.as_ptr(),
            );
            child_die(127);
        }

        // ── PARENT ───────────────────────────────────────────────────
        self.pid = pid;

        // Close the child's end of the stdin pipe in the parent.
        if (want_in_reader || want_in_pipe) && in_pipe[0] >= 0 {
            syscall::Close(in_pipe[0]);
            if want_in_pipe {
                // Clear the stored fd so we don't double-close.
                self.stdin_pipe_read_fd = -1;
            }
        }

        // Close write ends of stdout/stderr (they belong to the child).
        if want_out { syscall::Close(out_pipe[1]); }
        if want_err { syscall::Close(err_pipe[1]); }
        // StdoutPipe/StderrPipe: the write end now lives in the child; close the
        // parent's copy so the caller's reader sees EOF when the child exits.
        // The caller keeps and closes the read end itself.
        if want_out_pipe { syscall::Close(out_pipe[1]); self.stdout_pipe_write_fd = -1; }
        if want_err_pipe { syscall::Close(err_pipe[1]); self.stderr_pipe_write_fd = -1; }

        // ── Feed stdin from reader via goroutine ─────────────────────
        // If Stdin was set, spawn a goroutine that copies from the reader
        // to the write end of the stdin pipe, then closes the write end.
        // This mirrors Go's Cmd.stdin goroutine (exec.go:468).
        if want_in_reader {
            let stdin_arc = self.Stdin.take().unwrap();
            let write_fd = in_write_fd_for_goroutine;
            // io::Copy uses a 32 KiB internal buffer; give the goroutine
            // at least 64 KiB stack so the allocation succeeds without
            // stack-growth overhead.
            crate::go!(64 * crate::KB, move || {
                let g = stdin_arc.Lock();
                let reader: &mut alloc::boxed::Box<dyn io::Reader + Send> =
                    unsafe { &mut *g.get() };
                let mut writer = FdWriter::from_raw(write_fd);
                let _ = io::Copy(&mut writer, reader.as_mut());
                let _ = writer.Close();
                drop(g);
            });
        }

        // ── Store output pipe read ends for Run/Wait to drain ────────
        // We stash them in a temporary way: reuse the fields that
        // Run() will read. Since Start() owns the fd lifetime, we store
        // them back into the pipe arrays by embedding in the closure
        // that Wait() will call.
        //
        // Simpler: Run() calls Start() then wait_internal() directly.
        // We expose the raw pipe fds via a second parallel approach:
        // store them in extra fields on Cmd.
        // For this implementation, Run() is the only path that uses
        // these; Start()+Wait() leave stdout/stderr uncaptured until
        // Wait() is called.
        //
        // We'll handle this by storing the open pipe read-fds in a
        // new pair of fields that Wait() will drain.
        // For now: stash them back in out_pipe/err_pipe by caching in Cmd.
        self.cached_out_fd = out_pipe[0];
        self.cached_err_fd = err_pipe[0];

        crate::nilval::nil.into()
    }

    /// `(*Cmd).Wait()` — wait for the child started with `Start()` to
    /// exit. Drains any configured stdout/stderr pipes before returning.
    /// Returns the exit-status error (nil on exit code 0).
    pub fn Wait(&mut self) -> error {
        if self.pid < 0 {
            return errors::New("os/exec: Wait called before Start");
        }
        let pid = self.pid;
        self.pid = -1;

        // Drain captured pipes before blocking on wait4 to avoid
        // the deadlock: child blocks on write because pipe buffer full,
        // parent blocks on wait4 because child hasn't exited.
        if self.cached_out_fd >= 0 {
            let w = self.Stdout.as_ref().unwrap().clone();
            drain_into(self.cached_out_fd, w);
            syscall::Close(self.cached_out_fd);
            self.cached_out_fd = -1;
        }
        if self.cached_err_fd >= 0 {
            let w = self.Stderr.as_ref().unwrap().clone();
            drain_into(self.cached_err_fd, w);
            syscall::Close(self.cached_err_fd);
            self.cached_err_fd = -1;
        }

        let mut status: i32 = 0;
        let r = syscall::Wait4(pid, &mut status as *mut i32, 0, core::ptr::null_mut());
        if r < 0 {
            return errors::New("os/exec: wait4 failed");
        }
        decode_wait_status(status)
    }

    /// `(*Cmd).Run()` — fork, exec, drain captured pipes, wait, return
    /// the child's status as an error (or nil on exit code 0).
    /// Unchanged API: callers that only need Run() continue to work as before.
    pub fn Run(&mut self) -> error {
        let err = self.Start();
        if err != crate::nilval::nil {
            return err;
        }
        self.Wait()
    }
}

fn for_each_arg<F: FnMut(&string)>(args: &slice<string>, mut f: F) {
    let n = crate::len(args);
    let mut i: int = 0;
    while i < n {
        f(&args[i]);
        i += 1;
    }
}

#[inline]
fn child_die(code: i32) -> ! {
    unsafe { syscall::syscall1(syscall::SYS_EXIT, code as usize); }
    loop { core::hint::spin_loop(); }
}

/// Decode the raw `wait4(2)` status word into a goish `error`.
/// Returns nil on clean exit 0, otherwise a descriptive error.
fn decode_wait_status(status: i32) -> error {
    if status == 0 {
        return crate::nilval::nil.into();
    }
    if status & 0x7f == 0 {
        let code = (status >> 8) & 0xff;
        return errors::New(crate::fmt::Sprintf!("exit status %d", code));
    }
    let sig = status & 0x7f;
    errors::New(crate::fmt::Sprintf!("signal: %d", sig))
}

/// Read everything from `fd` into the goish writer. Buffers are 4 KiB.
/// Loop terminates on EOF (read returns 0) or any read error.
fn drain_into(
    fd: i32,
    writer: Arc<crate::sync::Mutex<core::cell::UnsafeCell<alloc::boxed::Box<dyn io::Writer + Send>>>>,
) {
    let mut buf = [0u8; 4096];
    loop {
        let n = syscall::Read(fd, buf.as_mut_ptr(), buf.len());
        if n <= 0 { break; }
        let bytes_slice: slice<byte> = slice::__from_vec(buf[..n as usize].to_vec());
        let g = writer.Lock();
        // SAFETY: the Mutex guard serialises access to the inner Box.
        let w: &mut alloc::boxed::Box<dyn io::Writer + Send> =
            unsafe { &mut *g.get() };
        let _ = w.Write(bytes_slice);
        drop(g);
    }
}
