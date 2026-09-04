// os/exec_posix — Go 1.25.5 src/os/exec_posix.go.
//
// One `.rs` per `.go` (§33). ProcessState and how it renders, which is
// what a caller reads after a command fails.

#![allow(non_snake_case)]

extern crate alloc;

use crate::gostring::string;
use crate::types::int;

// go: none — goish-only placement: Go's table is
// `syscall/zerrors_linux_amd64.go:1491-1523`. goish has no .rs for
// that file — anchoring it here would make goishlint audit the whole
// of zerrors against this one, which is why the citation is prose.
// The entries are verbatim.
/// Go's signal-name table, indexed by signal number.
///
/// Rendering a signal by NAME is not cosmetic: "signal: killed" and
/// "signal: 9" are the difference between an error a person can read
/// and one they have to look up. goish printed the number.
const signals: [&str; 32] = [
    "",
    "hangup",
    "interrupt",
    "quit",
    "illegal instruction",
    "trace/breakpoint trap",
    "aborted",
    "bus error",
    "floating point exception",
    "killed",
    "user defined signal 1",
    "segmentation fault",
    "user defined signal 2",
    "broken pipe",
    "alarm clock",
    "terminated",
    "stack fault",
    "child exited",
    "continued",
    "stopped (signal)",
    "stopped",
    "stopped (tty input)",
    "stopped (tty output)",
    "urgent I/O condition",
    "CPU time limit exceeded",
    "file size limit exceeded",
    "virtual timer expired",
    "profiling timer expired",
    "window changed",
    "I/O possible",
    "power failure",
    "bad system call",
];

// go: none — goish-only placement: Go's is `Signal.String`
// (syscall/syscall_unix.go:172-180), a method on a `Signal` type goish
// does not have yet, so this is a free function over the number. Same
// reason as the table above for the prose citation.
/// Go: the table entry when there is one, else "signal N".
pub fn SignalString(sig: int) -> string {
    if sig >= 0 && (sig as usize) < signals.len() {
        let s = signals[sig as usize];
        if !s.is_empty() {
            return string::from_static(s);
        }
    }
    return string::from_static("signal ") + crate::strconv::Itoa(i64::from(sig));
}

// go: none — goish-only shape: Go declares `ProcessState` in
// os/exec.go:207-211 holding a pid and a `syscall.WaitStatus`, and
// reaches the bits through `Sys()`. goish has no WaitStatus type, so
// the raw status is a field. The METHODS below are ports and carry
// their own anchors.
/// Go: "ProcessState stores information about a process, as reported
/// by Wait."
///
/// goish carries the raw wait(2) status and the pid, which is what
/// every accessor below is derived from — Go stores the same two
/// behind `Sys()`.
#[derive(Clone, Copy)]
pub struct ProcessState {
    pub(crate) pid: int,
    pub(crate) status: i32,
}

impl ProcessState {
    // go: none — goish-only: Go's caller builds a ProcessState from
    // the values wait4 filled in; this names that construction.
    /// Build a state from a raw wait(2) status.
    pub fn __new(pid: int, status: i32) -> Self {
        return ProcessState { pid, status };
    }

    // go: none — goish-only placement: Go's `ProcessState.Pid` is
    // os/exec.go:214-216. goish has no .rs for os/exec.go — the name
    // collides with the os/exec DIRECTORY — so the citation is prose.
    /// Go: "Pid returns the process id of the exited process."
    pub fn Pid(&self) -> int {
        return self.pid;
    }

    // go: none — goish-only: Go declares this on a `syscall.WaitStatus`
    // type (syscall/syscall_linux.go:469-469) that `ProcessState.Sys()`
    // hands back. goish's ProcessState holds the raw status and tests
    // it directly, so the method lives here instead.
    /// True when the process ran to completion and returned a status.
    pub fn Exited(&self) -> bool {
        return (self.status & 0x7f) == 0;
    }

    // go: none — goish-only: Go declares this on a `syscall.WaitStatus`
    // type (syscall/syscall_linux.go:471-471) that `ProcessState.Sys()`
    // hands back. goish's ProcessState holds the raw status and tests
    // it directly, so the method lives here instead.
    /// True when a signal ended the process.
    ///
    /// The test is Go's: a low byte that is neither 0 (exited) nor
    /// 0x7f (stopped). Writing it as "not exited" would call a
    /// STOPPED process signalled.
    pub fn Signaled(&self) -> bool {
        let low = self.status & 0x7f;
        return low != 0 && low != 0x7f;
    }

    // go: none — goish-only: Go declares this on a `syscall.WaitStatus`
    // type (syscall/syscall_linux.go:477-477) that `ProcessState.Sys()`
    // hands back. goish's ProcessState holds the raw status and tests
    // it directly, so the method lives here instead.
    /// True when the kernel wrote a core file, which Go appends to
    /// the rendering as " (core dumped)".
    pub fn CoreDump(&self) -> bool {
        return self.Signaled() && (self.status & 0x80) != 0;
    }

    // go: none — goish-only: Go declares this on a `syscall.WaitStatus`
    // type (syscall/syscall_linux.go:486-490) that `ProcessState.Sys()`
    // hands back. goish's ProcessState holds the raw status and tests
    // it directly, so the method lives here instead.
    /// The signal that ended the process, or -1.
    pub fn Signal(&self) -> int {
        if !self.Signaled() {
            return int::from(-1);
        }
        return int::from(i64::from(self.status & 0x7f));
    }

    // go: sdk 1.25.5 os/exec_posix.go:140-146 ProcessState.ExitCode
    /// Go: "returns the exit code of the exited process, or -1 if the
    /// process hasn't exited or was terminated by a signal."
    pub fn ExitCode(&self) -> int {
        if !self.Exited() {
            return int::from(-1);
        }
        return int::from(i64::from((self.status >> 8) & 0xff));
    }

    // go: none — goish-only placement: Go's `ProcessState.Success` is
    // os/exec.go:368-370, not exec_posix.go. Same reason as Pid above
    // for the prose citation.
    /// Go: "reports whether the program exited successfully, such as
    /// with exit status 0 on Unix."
    pub fn Success(&self) -> bool {
        return self.Exited() && self.ExitCode() == 0;
    }

    // go: sdk 1.25.5 os/exec_posix.go:108-136 ProcessState.String
    /// Go's rendering, which is also what `*exec.ExitError` prints:
    /// "exit status N", "signal: NAME", or "stop signal: NAME", with
    /// " (core dumped)" appended when the kernel wrote one.
    pub fn String(&self) -> string {
        let mut res = if self.Exited() {
            string::from_static("exit status ") + crate::strconv::Itoa(i64::from(self.ExitCode()))
        } else if self.Signaled() {
            string::from_static("signal: ") + SignalString(self.Signal())
        } else if (self.status & 0xff) == 0x7f {
            // Stopped: the signal is in the high byte.
            string::from_static("stop signal: ")
                + SignalString(int::from(i64::from((self.status >> 8) & 0xff)))
        } else if self.status == 0xffff {
            string::from_static("continued")
        } else {
            string::from_static("")
        };
        if self.CoreDump() {
            res = res + string::from_static(" (core dumped)");
        }
        return res;
    }
}

// go: none — goish-only placement: Go declares `ErrProcessDone` in
// os/exec.go:18, whose name collides with the os/exec DIRECTORY, so
// there is no .rs to anchor it to. See the note on ProcessState.
/// Go: "ErrProcessDone indicates a Process has finished."
pub fn ErrProcessDone() -> crate::errors::error {
    return crate::errors::New(string::from_static("os: process already finished"));
}

// go: none — goish-only placement: Go declares `Process` in
// os/exec.go:23-40 with a handle, a pid and a status word behind a
// mutex, because it supports pidfd. goish signals by pid and tracks
// only whether the process has been reaped.
/// Go: "Process stores the information about a process created by
/// StartProcess."
///
/// Cloneable, and every clone shares the done flag: that is what lets
/// one goroutine `Kill` a child while another sits in `Wait`, which is
/// the whole point of the type.
#[derive(Clone)]
pub struct Process {
    pub Pid: int,
    done: alloc::sync::Arc<core::sync::atomic::AtomicBool>,
}

impl Process {
    // go: none — goish-only: Go's Process is built by startProcess or
    // FindProcess; this names the construction for both.
    /// A Process for a pid that is believed live.
    pub fn __new(pid: int) -> Self {
        return Process {
            Pid: pid,
            done: alloc::sync::Arc::new(core::sync::atomic::AtomicBool::new(false)),
        };
    }

    // go: none — goish-only: Go sets the status word under sigMu when
    // Wait reaps. goish's flag is the same signal, shared by clones.
    /// Mark the process reaped, so later signals report ErrProcessDone.
    pub fn __set_done(&self) {
        self.done.store(true, core::sync::atomic::Ordering::Release);
    }

    // go: none — goish-only placement: Go's is `Process.pidSignal`
    // (os/exec_unix.go:93-111) plus `convertESRCH` (:113-118). goish
    // has no .rs for exec_unix.go, and anchoring across it would make
    // goishlint audit that whole file against this one — the same
    // reason the citations above are prose.
    /// Go: send a signal, answering ErrProcessDone when the process
    /// has already been reaped.
    ///
    /// The ESRCH translation is Go's `convertESRCH`
    /// (os/exec_unix.go:113-118): a pid that no longer exists is
    /// reported as finished, not as a raw errno. Without it a caller
    /// racing Wait would see "no such process" — an error about the
    /// implementation rather than about the process.
    pub fn Signal(&self, sig: int) -> crate::errors::error {
        if self.done.load(core::sync::atomic::Ordering::Acquire) {
            return ErrProcessDone();
        }
        let pid32 = self.Pid as i32; // goishlint:ignore GOISH005 - a pid for kill(2), a C ABI int
        let sig32 = sig as i32; // goishlint:ignore GOISH005 - a signal number for kill(2), a C ABI int
        let r = crate::syscall::Kill(pid32, sig32);
        if r == 0 {
            return crate::errors::nil;
        }
        // ESRCH is 3 on Linux.
        if -r == 3 {
            return ErrProcessDone();
        }
        return crate::errors::Wrap(crate::syscall::Errno((-r) as _));
    }

    // go: none — goish-only placement: Go's `Process.Kill` is
    // os/exec.go:325-331; see the note on ProcessState.
    /// Go: "Kill causes the Process to exit immediately. Kill does not
    /// wait until the Process has actually exited."
    pub fn Kill(&self) -> crate::errors::error {
        // SIGKILL is 9.
        return self.Signal(int::from(9));
    }
}

// go: none — goish-only placement: Go's `FindProcess` is
// os/exec.go:247-252; see the note on ProcessState.
/// Go: "On Unix systems, FindProcess always succeeds and returns a
/// Process for the given pid, regardless of whether the process
/// exists. To test whether the process actually exists, see whether
/// p.Signal(syscall.Signal(0)) reports an error."
pub fn FindProcess(pid: int) -> (Process, crate::errors::error) {
    return (Process::__new(pid), crate::errors::nil);
}
