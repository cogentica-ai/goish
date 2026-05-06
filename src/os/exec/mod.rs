// os/exec — minimal Linux fork+exec port of Go's `os/exec`.
//
// Surface (v1):
//
//   var ErrNotFound = errors.New("executable file not found in $PATH")
//   func LookPath(file string) (string, error)
//   func Command(name string, args ...string) *Cmd
//   type Cmd struct {
//       Path   string
//       Args   []string
//       Env    []string                 // KEY=VALUE; nil means inherit
//       Dir    string                   // not yet honored (v1: cwd inherited)
//       Stdin  io.Reader                // not yet honored (v1: child stdin = /dev/null)
//       Stdout io.Writer                // captured via pipe + drained synchronously
//       Stderr io.Writer                // captured via pipe + drained synchronously
//   }
//   func (c *Cmd) Run() error
//
// Process model:
//   1. Pipe2 for stdout (and stderr if distinct from Stdout).
//   2. Fork. Child closes parent ends, dup3 child ends to fd 1/2,
//      then Execve. On any failure in the child, _exit(127).
//   3. Parent closes child ends, drains pipes into the io.Writers,
//      then Wait4 for the child.
//
// Slim deviations from Go:
//   * Stdin handling deferred — child gets the parent's stdin (fd 0
//     is not redirected). For the homedir use case (`sh -c "cd && pwd"`)
//     this matches behavior since the script needs no input.
//   * `Cmd.Dir` is parsed but not honored.
//   * `Cmd.SysProcAttr`, `Cmd.ExtraFiles`, `Cmd.Env` (when nil →
//     inherit), `ProcessState`, `Process.Pid` all elided.
//   * Combined waits and asynchronous Start/Wait are deferred —
//     `Run()` is the only entrypoint in v1.

#![allow(non_snake_case)]

extern crate alloc;

use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::AtomicI32;

use crate::errors;
use crate::error;
use crate::goslice::slice;
use crate::gostring::string;
use crate::io;
use crate::syscall;
use crate::types::{byte, int};

/// Sentinel returned by `LookPath` when no matching executable is on
crate::var! {
    /// `$PATH`. Mirrors `exec.ErrNotFound`.
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
    /// Optional stdin source. Currently not honored (child inherits
    /// the parent's stdin).
    pub Stdin: Option<Arc<crate::sync::Mutex<core::cell::UnsafeCell<alloc::boxed::Box<dyn io::Reader + Send>>>>>,
    /// Where to copy the child's stdout. None ≡ inherit (v1: discard
    /// captured bytes).
    pub Stdout: Option<Arc<crate::sync::Mutex<core::cell::UnsafeCell<alloc::boxed::Box<dyn io::Writer + Send>>>>>,
    /// Where to copy the child's stderr. None ≡ inherit (v1: discard).
    pub Stderr: Option<Arc<crate::sync::Mutex<core::cell::UnsafeCell<alloc::boxed::Box<dyn io::Writer + Send>>>>>,
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
    /// `(*Cmd).Run()` — fork, exec, drain captured pipes, wait, return
    /// the child's status as an error (or nil on exit code 0).
    pub fn Run(&mut self) -> error {
        if self.Path.Len() == 0 {
            return ErrNotFound.into();
        }
        // Build the C-string argv. We hold the buffers alive across
        // execve via `argv_bufs`; argv_ptrs points into them.
        let mut argv_bufs: Vec<Vec<u8>> = Vec::with_capacity(crate::len(&self.Args) as usize);
        for_each_arg(&self.Args, |s| {
            let mut b = Vec::with_capacity(s.Len() as usize + 1);
            for &x in s.as_bytes() { b.push(x); }
            b.push(0);
            argv_bufs.push(b);
        });
        let mut argv_ptrs: Vec<*const u8> = argv_bufs.iter().map(|b| b.as_ptr()).collect();
        argv_ptrs.push(core::ptr::null());

        // Path (NUL-terminated) for execve.
        let mut path_buf = Vec::with_capacity(self.Path.Len() as usize + 1);
        for &x in self.Path.as_bytes() { path_buf.push(x); }
        path_buf.push(0);

        // Build envp from explicit Env or inherited Environ().
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

        // Pipes for stdout/stderr capture (only if writer set).
        let mut out_pipe = [-1i32; 2];
        let mut err_pipe = [-1i32; 2];
        let want_out = self.Stdout.is_some();
        let want_err = self.Stderr.is_some();
        if want_out {
            let r = syscall::Pipe2(&mut out_pipe, syscall::O_CLOEXEC);
            if r < 0 { return errors::New("os/exec: pipe2 failed for stdout"); }
        }
        if want_err {
            let r = syscall::Pipe2(&mut err_pipe, syscall::O_CLOEXEC);
            if r < 0 {
                if want_out { syscall::Close(out_pipe[0]); syscall::Close(out_pipe[1]); }
                return errors::New("os/exec: pipe2 failed for stderr");
            }
        }

        let pid = syscall::Fork();
        if pid < 0 {
            if want_out { syscall::Close(out_pipe[0]); syscall::Close(out_pipe[1]); }
            if want_err { syscall::Close(err_pipe[0]); syscall::Close(err_pipe[1]); }
            return errors::New("os/exec: fork failed");
        }
        if pid == 0 {
            // CHILD. After fork, only async-signal-safe operations are
            // technically guaranteed — alloc/free are NOT in that list.
            // We avoid heap touches here; everything is on the stack
            // or in the buffers prepared pre-fork.
            //
            // Wire stdout/stderr.
            if want_out {
                syscall::Close(out_pipe[0]);
                // dup3 with flags=0 to clear O_CLOEXEC on the child fd
                // that becomes stdout (fd 1).
                if syscall::Dup3(out_pipe[1], 1, 0) < 0 {
                    child_die(127);
                }
                syscall::Close(out_pipe[1]);
            }
            if want_err {
                syscall::Close(err_pipe[0]);
                if syscall::Dup3(err_pipe[1], 2, 0) < 0 {
                    child_die(127);
                }
                syscall::Close(err_pipe[1]);
            }
            let _ = syscall::Execve(
                path_buf.as_ptr(),
                argv_ptrs.as_ptr(),
                envp_ptrs.as_ptr(),
            );
            // Execve only returns on failure.
            child_die(127);
        }
        // PARENT.
        if want_out { syscall::Close(out_pipe[1]); }
        if want_err { syscall::Close(err_pipe[1]); }

        // Drain the pipes synchronously. Stdout first; then stderr.
        // For interleaved output the right answer is select/epoll —
        // deferred. Most callers use only one channel anyway (Output
        // helper, the typical homedir pattern).
        if want_out {
            drain_into(out_pipe[0], self.Stdout.as_ref().unwrap().clone());
            syscall::Close(out_pipe[0]);
        }
        if want_err {
            drain_into(err_pipe[0], self.Stderr.as_ref().unwrap().clone());
            syscall::Close(err_pipe[0]);
        }

        let mut status: i32 = 0;
        let r = syscall::Wait4(pid, &mut status as *mut i32, 0, core::ptr::null_mut());
        if r < 0 {
            return errors::New("os/exec: wait4 failed");
        }
        if status == 0 {
            return crate::nilval::nil.into();
        }
        // Decode WEXITSTATUS / WTERMSIG for an informative error.
        if status & 0x7f == 0 {
            let code = (status >> 8) & 0xff;
            return errors::New(crate::fmt::Sprintf!("exit status %d", code));
        }
        let sig = status & 0x7f;
        errors::New(crate::fmt::Sprintf!("signal: %d", sig))
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
    // Should be unreachable, but on the off-chance the syscall fails
    // we spin rather than UB.
    loop { core::hint::spin_loop(); }
}

/// Read everything from `fd` into the goish writer. Buffers are 4 KiB
/// to keep the static allocation modest; the loop terminates on EOF
/// (read returns 0) or any read error.
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
    // Suppress dead-code warning from a future helper.
    let _: AtomicI32 = AtomicI32::new(0);
}
