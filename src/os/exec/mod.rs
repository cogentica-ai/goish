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

use crate::error;
use crate::errors;
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

// go: none — goish idiom: Go declares this in exec.go as
// `ErrDot = errors.New("cannot run executable found relative to current directory")`.
//
// It was MISSING, and it is the newest of LookPath's rules and the one
// with a CVE behind it. Go 1.19 made a name that resolves through a
// RELATIVE PATH entry — including the EMPTY entry, which Unix shells
// read as "." — return this error alongside the path it found, because
// running whatever happens to sit in the current directory is how a
// build tool becomes an arbitrary-code-execution vector. The path is
// still returned, so a caller that has genuinely decided this is fine
// can proceed; one that checks the error does not.
crate::var! {
    pub ErrDot: error = "cannot run executable found relative to current directory";
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
    /// Optional working directory. The child chdir()s here between
    /// fork and exec, so a relative `Path` resolves against it exactly
    /// as Go's `Cmd.Dir` describes.
    pub Dir: string,
    /// Optional stdin source. If set, a pipe is created and a goroutine
    /// copies from this reader to the child's stdin.
    pub Stdin: Option<
        Arc<crate::sync::Mutex<core::cell::UnsafeCell<alloc::boxed::Box<dyn io::Reader + Send>>>>,
    >,
    /// Where to copy the child's stdout. None ≡ inherit (v2: discard
    /// captured bytes).
    pub Stdout: Option<
        Arc<crate::sync::Mutex<core::cell::UnsafeCell<alloc::boxed::Box<dyn io::Writer + Send>>>>,
    >,
    /// Where to copy the child's stderr. None ≡ inherit (v2: discard).
    pub Stderr: Option<
        Arc<crate::sync::Mutex<core::cell::UnsafeCell<alloc::boxed::Box<dyn io::Writer + Send>>>>,
    >,

    // go: none — goish-only placement: Go's `Cmd.Process` is
    // os/exec/exec.go:189. See the note on ExitError for why the
    // citation is prose.
    /// Go: "Process is the underlying process, once started." It is
    /// None before Start and stays set after Wait, so `Kill` on a
    /// finished process reports ErrProcessDone rather than panicking.
    pub Process: Option<crate::os::exec_posix::Process>,
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
            core::cell::UnsafeCell::new(alloc::boxed::Box::new(w)),
        )));
    }
    pub fn SetStderr<W: io::Writer + Send + 'static>(&mut self, w: W) {
        self.Stderr = Some(Arc::new(crate::sync::Mutex::new(
            core::cell::UnsafeCell::new(alloc::boxed::Box::new(w)),
        )));
    }

    /// Wire `Stdin` from a typed Reader. Before fork, a pipe is created;
    /// in the child the read end is dup'd onto fd 0. In the parent a
    /// goroutine copies from this reader to the write end.
    ///
    /// Mirrors Go's `cmd.Stdin = reader` assignment.
    pub fn SetStdin<R: io::Reader + Send + 'static>(&mut self, r: R) {
        self.Stdin = Some(Arc::new(crate::sync::Mutex::new(
            core::cell::UnsafeCell::new(alloc::boxed::Box::new(r)),
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
            return (
                FdWriter::from_raw(-1),
                errors::New("os/exec: StdinPipe already called"),
            );
        }
        if self.pid >= 0 {
            return (
                FdWriter::from_raw(-1),
                errors::New("os/exec: StdinPipe called after Start"),
            );
        }
        let mut pipe_fds = [-1i32; 2];
        let r = syscall::Pipe2(&mut pipe_fds, syscall::O_CLOEXEC);
        if r < 0 {
            return (
                FdWriter::from_raw(-1),
                errors::New("os/exec: StdinPipe pipe2 failed"),
            );
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
            return (
                FdReader::from_raw(-1),
                errors::New("os/exec: Stdout already set"),
            );
        }
        if self.pid >= 0 {
            return (
                FdReader::from_raw(-1),
                errors::New("os/exec: StdoutPipe called after Start"),
            );
        }
        let mut pipe_fds = [-1i32; 2];
        let r = syscall::Pipe2(&mut pipe_fds, syscall::O_CLOEXEC);
        if r < 0 {
            return (
                FdReader::from_raw(-1),
                errors::New("os/exec: StdoutPipe pipe2 failed"),
            );
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
            return (
                FdReader::from_raw(-1),
                errors::New("os/exec: Stderr already set"),
            );
        }
        if self.pid >= 0 {
            return (
                FdReader::from_raw(-1),
                errors::New("os/exec: StderrPipe called after Start"),
            );
        }
        let mut pipe_fds = [-1i32; 2];
        let r = syscall::Pipe2(&mut pipe_fds, syscall::O_CLOEXEC);
        if r < 0 {
            return (
                FdReader::from_raw(-1),
                errors::New("os/exec: StderrPipe pipe2 failed"),
            );
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
        if err == crate::nilval::nil {
            p
        } else {
            name.clone()
        }
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
        Process: None,
    }
}

// go: none — goish-only placement: Go declares `ExitError` in
// os/exec/exec.go:877-895. goish's os/exec is a module root with the
// whole package in it and no per-file split yet, so anchoring this to
// exec.go would make goishlint audit all 34 of that file's
// declarations against mod.rs. Splitting os/exec the way net/dial and
// net/tcpsock were split is worth doing and is its own commit; the
// citation is prose until then. The port is verbatim.
/// Go: "An ExitError reports an unsuccessful exit by a command."
///
/// It embeds `*os.ProcessState`, which is what makes
/// `err.(*exec.ExitError).ExitCode()` the way a caller reads a
/// command's exit code. goish returned an untyped
/// `errors.New("exit status 1")`, so the only way to get the number
/// back was to parse the message.
///
/// Go's `Stderr` field — a captured prefix of the child's stderr,
/// filled in only by `Cmd.Output` — is not carried: goish has no
/// Output method yet, and an always-empty field would read as
/// "the child printed nothing".
#[derive(Clone)]
pub struct ExitError {
    pub ProcessState: crate::os::exec_posix::ProcessState,
}

impl crate::errors::ErrorTrait for ExitError {
    // go: none — goish-only placement: Go's `ExitError.Error` is
    // os/exec/exec.go:893-895. See the note on the struct.
    /// Go: `return e.ProcessState.String()`.
    fn Error(&self) -> string {
        return self.ProcessState.String();
    }
}

impl ExitError {
    // go: none — goish-only: Go reaches this through the embedded
    // *os.ProcessState. Rust has no embedding, so it forwards.
    /// The exit code, or -1 if a signal ended the process.
    pub fn ExitCode(&self) -> int {
        return self.ProcessState.ExitCode();
    }

    // go: none — goish-only: see ExitCode.
    /// Whether the process ran to completion.
    pub fn Exited(&self) -> bool {
        return self.ProcessState.Exited();
    }

    // go: none — goish-only: see ExitCode.
    /// Whether it exited with status 0.
    pub fn Success(&self) -> bool {
        return self.ProcessState.Success();
    }

    // go: none — goish-only: see ExitCode.
    /// The pid that was waited on.
    pub fn Pid(&self) -> int {
        return self.ProcessState.Pid();
    }
}

// go: none — goish idiom: Go's `exec.Error` is a struct with `Name` and
// `Err` whose Error() is `"exec: " + strconv.Quote(e.Name) + ": " +
// e.Err.Error()`. Every LookPath failure is wrapped in one, and the
// quoted name is how a caller tells WHICH lookup failed when several
// are in flight. goish returned the bare sentinel, so every message
// differed from Go's and the name was lost.
#[derive(Clone, PartialEq)]
pub struct Error {
    pub Name: string,
    pub Err: error,
}

impl crate::errors::ErrorTrait for Error {
    // go: none — goish idiom: see the note above the struct.
    fn Error(&self) -> string {
        return crate::fmt::Sprintf!("exec: %q: %s", self.Name.clone(), self.Err.Error());
    }

    // go: none — goish idiom: `errors.Is`/`As` unwrap through this,
    // which is what makes `errors.Is(err, exec.ErrDot)` work on a
    // wrapped value.
    fn Unwrap(&self) -> error {
        return self.Err.clone();
    }
}

/// `exec.LookPath(file)` — find an executable on `$PATH`. Returns the
/// absolute path, or `ErrNotFound`. `file` containing `/` is returned
/// as-is (Go semantics: the lookup is skipped, but the file's
/// existence isn't verified — same here).
pub fn LookPath<S: Into<string>>(file: S) -> (string, error) {
    let file = file.into();
    // Go: if strings.Contains(file, "/") { err := findExecutable(file);
    //         if err == nil { return file, nil }
    //         return "", &Error{file, err} }
    //
    // goish used to return the name unchanged WITHOUT checking it, on
    // the reasoning that the lookup is skipped. Go skips the SEARCH,
    // not the check: a name with a slash is tested where it stands, so
    // "/nonexistent/xyz" is an error rather than a path. A caller that
    // reads a successful LookPath as "this is runnable" was wrong for
    // every such name.
    if name_has_slash(&file) {
        if file_is_accessible(&file) {
            return (file, crate::nilval::nil.into());
        }
        return (string::new(), lookErr(&file, statErrFor(&file)));
    }
    let path = crate::os::Getenv("PATH");
    // Go: filepath.SplitList(path). goish used strings.Split, which
    // yields ONE EMPTY element for an empty PATH where SplitList
    // yields none — so with PATH unset the loop ran once against "."
    // and could find a binary in the current directory.
    let dirs = crate::path::filepath::SplitList(path);
    let n = crate::len(&dirs);
    let mut i: int = 0;
    while i < n {
        let mut dir = dirs[i].clone();
        i += 1;
        // Go: "Unix shell semantics: path element "" means "."". goish
        // used to SKIP an empty element, which is safer but not Go —
        // and quietly so, since the difference only shows when a
        // binary of that name exists in the current directory.
        if dir.Len() == 0 {
            dir = string::from_static(".");
        }
        let candidate =
            crate::path::filepath::Join(crate::goslice::slice::__from_vec(alloc::vec![
                dir,
                file.clone()
            ]));
        if file_is_accessible(&candidate) {
            // Go: if !filepath.IsAbs(path) { return path, &Error{file, ErrDot} }
            //
            // The path IS returned with the error. That is deliberate:
            // the caller is told what was found and left to decide.
            if !crate::path::filepath::IsAbs(candidate.clone()) {
                return (candidate, lookErr(&file, ErrDot.into()));
            }
            return (candidate, crate::nilval::nil.into());
        }
    }
    (string::new(), lookErr(&file, ErrNotFound.into()))
}

// go: none — goish idiom: Go writes `&Error{file, err}` inline; this
// names it once.
fn lookErr(name: &string, err: error) -> error {
    return errors::Wrap(Error {
        Name: name.clone(),
        Err: err,
    });
}

// go: none — goish idiom: Go's findExecutable distinguishes a failed
// stat from a directory from a missing execute bit; goish's
// `file_is_accessible` answers one bool, so the message is rebuilt
// from a second stat here. Only the "no such file" shape is
// reachable from LookPath's slash branch in practice.
fn statErrFor(path: &string) -> error {
    return crate::fmt::Errorf!("stat %s: no such file or directory", path.clone());
}

fn name_has_slash(s: &string) -> bool {
    use crate::builtin::Len;
    let n = s.__len();
    let mut i: int = 0;
    while i < n {
        if s[i] == b'/' {
            return true;
        }
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
    for &b in path.as_bytes() {
        buf.push(b);
    }
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
    if r != 0 || (st.st_mode & syscall::S_IFMT) != syscall::S_IFREG {
        return false;
    }
    // Go's findExecutable checks the EXECUTE permission, not merely
    // that a regular file is there. This used to stop at the file
    // check, with a comment reasoning that "$PATH lookups by
    // definition target executables" — which is the assumption the
    // check exists to test.
    //
    // It is not a cosmetic difference. A non-executable file EARLIER
    // on $PATH shadowed the real binary later on it: LookPath returned
    // the unusable one and the exec failed, where Go walks past it and
    // finds the executable. The lookup selected the wrong file.
    //
    // Go asks the kernel through Eaccess(X_OK), which resolves the
    // owner/group/other question against the real uid. goish's syscall
    // surface has no faccessat, so the mode bits are read directly and
    // matched against the caller's identity — the same three-way
    // choice the kernel makes, minus the supplementary-group and
    // capability cases, where this is stricter than Go rather than
    // looser.
    return has_exec_permission(&st);
}

// go: none — goish-only: the owner/group/other arm of what Go gets
// from Eaccess(X_OK). See the note in `file_is_accessible`.
fn has_exec_permission(st: &syscall::Stat_t) -> bool {
    let mode = st.st_mode;
    let uid = crate::uint32(syscall::Getuid());
    if uid == 0 {
        // root: any execute bit is enough, as for the kernel.
        return (mode & 0o111) != 0;
    }
    if st.st_uid == uid {
        return (mode & 0o100) != 0;
    }
    let gid = crate::uint32(syscall::Getgid());
    if st.st_gid == gid {
        return (mode & 0o010) != 0;
    }
    return (mode & 0o001) != 0;
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
            for &x in s.as_bytes() {
                b.push(x);
            }
            b.push(0);
            argv_bufs.push(b);
        });
        let mut argv_ptrs: Vec<*const u8> = argv_bufs.iter().map(|b| b.as_ptr()).collect();
        argv_ptrs.push(core::ptr::null());

        // ── Path NUL-buffer ─────────────────────────────────────────
        let mut path_buf = Vec::with_capacity(self.Path.Len() as usize + 1);
        for &x in self.Path.as_bytes() {
            path_buf.push(x);
        }
        path_buf.push(0);

        // ── Dir NUL-buffer ──────────────────────────────────────────
        // Prepared BEFORE the fork: allocation after fork is not
        // async-signal-safe, and this is the same rule every other
        // buffer here follows.
        let mut dir_buf: Vec<u8> = Vec::new();
        if self.Dir.Len() > 0 {
            dir_buf.reserve(self.Dir.Len() as usize + 1);
            for &x in self.Dir.as_bytes() {
                dir_buf.push(x);
            }
            dir_buf.push(0);
        }

        // ── Build envp ──────────────────────────────────────────────
        let env_strings: slice<string> = if crate::len(&self.Env) > 0 {
            self.Env.clone()
        } else {
            crate::os::Environ()
        };
        let mut envp_bufs: Vec<Vec<u8>> = Vec::with_capacity(crate::len(&env_strings) as usize);
        for_each_arg(&env_strings, |s| {
            let mut b = Vec::with_capacity(s.Len() as usize + 1);
            for &x in s.as_bytes() {
                b.push(x);
            }
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
        let want_in_pipe = self.stdin_pipe_read_fd >= 0;

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
                if want_in_reader {
                    syscall::Close(in_pipe[0]);
                    syscall::Close(in_pipe[1]);
                }
                return errors::New("os/exec: pipe2 failed for stdout");
            }
        } else if want_out_pipe {
            // out_pipe[0] (read end) is with the caller; we only hold the write end.
            out_pipe[1] = self.stdout_pipe_write_fd;
        }
        if want_err {
            let r = syscall::Pipe2(&mut err_pipe, syscall::O_CLOEXEC);
            if r < 0 {
                if want_in_reader {
                    syscall::Close(in_pipe[0]);
                    syscall::Close(in_pipe[1]);
                }
                if want_out {
                    syscall::Close(out_pipe[0]);
                    syscall::Close(out_pipe[1]);
                }
                return errors::New("os/exec: pipe2 failed for stderr");
            }
        } else if want_err_pipe {
            err_pipe[1] = self.stderr_pipe_write_fd;
        }

        // ── The exec-status pipe ─────────────────────────────────────
        //
        // Go's forkExec carries the child's failure back to the parent
        // through a CLOEXEC pipe: a successful execve closes the write
        // end and the parent reads EOF, while a failure writes the
        // errno first. Without it the child can only signal failure by
        // EXITING, and an exit code is indistinguishable from one the
        // program itself chose — goish reported a missing binary as
        // "exit status 127", which is also what `sh -c 'exit 127'`
        // reports.
        let mut exec_pipe: [i32; 2] = [-1, -1];
        if syscall::Pipe2(&mut exec_pipe, syscall::O_CLOEXEC) < 0 {
            return errors::New("os/exec: pipe2 failed for exec status");
        }

        // ── Fork ─────────────────────────────────────────────────────
        let pid = syscall::Fork();
        if pid < 0 {
            if want_in_reader {
                syscall::Close(in_pipe[0]);
                syscall::Close(in_pipe[1]);
            }
            if want_out {
                syscall::Close(out_pipe[0]);
                syscall::Close(out_pipe[1]);
            }
            if want_err {
                syscall::Close(err_pipe[0]);
                syscall::Close(err_pipe[1]);
            }
            // For the StdoutPipe/StderrPipe cases we own only the write end; the
            // caller holds the read end and will see EOF once it is closed.
            if want_out_pipe {
                syscall::Close(out_pipe[1]);
                self.stdout_pipe_write_fd = -1;
            }
            if want_err_pipe {
                syscall::Close(err_pipe[1]);
                self.stderr_pipe_write_fd = -1;
            }
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
                if out_pipe[0] >= 0 {
                    syscall::Close(out_pipe[0]);
                }
                if syscall::Dup3(out_pipe[1], 1, 0) < 0 {
                    child_die(127);
                }
                syscall::Close(out_pipe[1]);
            }
            // Wire stderr (fd 2). Covers both SetStderr (capture) and StderrPipe.
            if want_err || want_err_pipe {
                if err_pipe[0] >= 0 {
                    syscall::Close(err_pipe[0]);
                }
                if syscall::Dup3(err_pipe[1], 2, 0) < 0 {
                    child_die(127);
                }
                syscall::Close(err_pipe[1]);
            }

            // Go: "Dir specifies the working directory of the command.
            // If Dir is the empty string, Run runs the command in the
            // calling process's current directory." The chdir belongs
            // between fork and exec so the parent's cwd is untouched —
            // doing it in the parent would race every other goroutine.
            if !dir_buf.is_empty() && syscall::Chdir(dir_buf.as_ptr()) < 0 {
                child_die(127);
            }

            let rc = syscall::Execve(path_buf.as_ptr(), argv_ptrs.as_ptr(), envp_ptrs.as_ptr());
            child_report(exec_pipe[1], rc);
            child_die(127);
        }

        // ── PARENT ───────────────────────────────────────────────────
        self.pid = pid;

        // Read the exec-status pipe first. A successful execve closed
        // the write end (O_CLOEXEC), so this reads 0 bytes; a failure
        // wrote the errno. Reap the child either way before reporting,
        // so a failed start does not leave a zombie.
        syscall::Close(exec_pipe[1]);
        {
            let mut errbuf = [0u8; 4];
            let n = syscall::Read(exec_pipe[0], errbuf.as_mut_ptr(), errbuf.len());
            syscall::Close(exec_pipe[0]);
            if n == 4 {
                let errno = i32::from_ne_bytes(errbuf);
                let mut status: i32 = 0;
                let _ = syscall::Wait4(pid, &mut status as *mut i32, 0, core::ptr::null_mut());
                self.pid = -1;
                // Go: &PathError{Op: "fork/exec", Path: name, Err: errno}
                return errors::Wrap(crate::os::PathError {
                    Op: string::from_static("fork/exec"),
                    Path: self.Path.clone(),
                    Err: errors::Wrap(syscall::Errno(errno as _)),
                });
            }
        }

        // The child is running: publish it, as Go's Start does, so a
        // caller can Kill or Signal it while another goroutine Waits.
        self.Process = Some(crate::os::exec_posix::Process::__new(int::from(i64::from(
            pid,
        ))));

        // Close the child's end of the stdin pipe in the parent.
        if (want_in_reader || want_in_pipe) && in_pipe[0] >= 0 {
            syscall::Close(in_pipe[0]);
            if want_in_pipe {
                // Clear the stored fd so we don't double-close.
                self.stdin_pipe_read_fd = -1;
            }
        }

        // Close write ends of stdout/stderr (they belong to the child).
        if want_out {
            syscall::Close(out_pipe[1]);
        }
        if want_err {
            syscall::Close(err_pipe[1]);
        }
        // StdoutPipe/StderrPipe: the write end now lives in the child; close the
        // parent's copy so the caller's reader sees EOF when the child exits.
        // The caller keeps and closes the read end itself.
        if want_out_pipe {
            syscall::Close(out_pipe[1]);
            self.stdout_pipe_write_fd = -1;
        }
        if want_err_pipe {
            syscall::Close(err_pipe[1]);
            self.stderr_pipe_write_fd = -1;
        }

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

    // go: none — goish-only: Go writes `cmd.Process.Kill()`, where
    // `Process` is an `*os.Process` handle Start publishes. goish has
    // no `os.Process`, so the kill lives on the Cmd that owns the pid.
    /// Send SIGKILL to a child started with `Start()`. A no-op once
    /// `Wait()` has reaped it — the pid is cleared there, and killing
    /// a reaped pid could hit an unrelated process that inherited the
    /// number.
    pub fn Kill(&self) -> error {
        if self.pid <= 0 {
            return errors::New("os/exec: process already finished");
        }
        // SIGKILL
        if crate::syscall::Kill(self.pid, 9) < 0 {
            return errors::New("os/exec: kill failed");
        }
        return crate::nilval::nil.into();
    }

    /// `(*Cmd).Wait()` — wait for the child started with `Start()` to
    /// exit. Drains any configured stdout/stderr pipes before returning.
    /// Returns the exit-status error (nil on exit code 0).
    pub fn Wait(&mut self) -> error {
        if self.pid < 0 {
            // Go distinguishes the two: a Wait before Start is
            // "exec: not started", a second Wait is "exec: Wait was
            // already called". goish said "Wait called before Start"
            // for both, which is wrong for the far more common one.
            if self.Process.is_some() {
                return errors::New("exec: Wait was already called");
            }
            return errors::New("exec: not started");
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
        // The process is reaped either way: a later Kill must report
        // ErrProcessDone rather than signalling a recycled pid.
        if let Some(p) = &self.Process {
            p.__set_done();
        }
        if r < 0 {
            return errors::New("os/exec: wait4 failed");
        }
        decode_wait_status(int::from(i64::from(pid)), status)
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
// go: none — goish-only: the child half of Go's forkExec status pipe
// (syscall/exec_unix.go). Go writes the errno from the child through
// a CLOEXEC pipe and the parent turns it back into an error; this is
// the write.
/// Report a failed syscall to the parent, as a 4-byte errno.
///
/// `rc` is goish's negative-errno convention. Nothing can be done if
/// the write fails — the parent then sees EOF and reports the exit
/// status, which is the behaviour this replaces.
fn child_report(fd: i32, rc: i32) {
    if fd < 0 {
        return;
    }
    let errno: i32 = if rc < 0 { -rc } else { 0 };
    let bytes = errno.to_ne_bytes();
    let _ = syscall::Write(fd, bytes.as_ptr(), bytes.len());
}

fn child_die(code: i32) -> ! {
    unsafe {
        syscall::syscall1(syscall::SYS_EXIT, code as usize);
    }
    loop {
        core::hint::spin_loop();
    }
}

/// Decode the raw `wait4(2)` status word into a goish `error`.
/// Returns nil on clean exit 0, otherwise a descriptive error.
fn decode_wait_status(pid: int, status: i32) -> error {
    let st = crate::os::exec_posix::ProcessState::__new(pid, status);
    if st.Success() {
        return crate::nilval::nil.into();
    }
    // Go: Cmd.Wait returns `&ExitError{ProcessState: ps}` for any
    // non-zero state, and the message is ProcessState.String() — so
    // a signal renders by NAME ("signal: killed"), not by number.
    return errors::Wrap(ExitError { ProcessState: st });
}

/// Read everything from `fd` into the goish writer. Buffers are 4 KiB.
/// Loop terminates on EOF (read returns 0) or any read error.
fn drain_into(
    fd: i32,
    writer: Arc<
        crate::sync::Mutex<core::cell::UnsafeCell<alloc::boxed::Box<dyn io::Writer + Send>>>,
    >,
) {
    let mut buf = [0u8; 4096];
    loop {
        let n = syscall::Read(fd, buf.as_mut_ptr(), buf.len());
        if n <= 0 {
            break;
        }
        let bytes_slice: slice<byte> = slice::__from_vec(buf[..n as usize].to_vec());
        let g = writer.Lock();
        // SAFETY: the Mutex guard serialises access to the inner Box.
        let w: &mut alloc::boxed::Box<dyn io::Writer + Send> = unsafe { &mut *g.get() };
        let _ = w.Write(bytes_slice);
        drop(g);
    }
}

// go: none — goish idiom: fill the `#[goish::interface]` downcast
// registries for the types this package declares. See AGENTS.md §9b.
/// Register `os/exec`'s pipe endpoints into the `io` registries.
/// Idempotent; called from `goish::init()`.
pub fn register_exec_impls() {
    use crate::io::{
        __goish_register_Closer_impl, __goish_register_Reader_impl, __goish_register_Writer_impl,
    };
    __goish_register_Reader_impl::<FdReader>();
    __goish_register_Closer_impl::<FdReader>();
    __goish_register_Writer_impl::<FdWriter>();
    __goish_register_Closer_impl::<FdWriter>();
}
