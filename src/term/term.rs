// go: file cmd/vendor/golang.org/x/term/term.go decls: IsTerminal, MakeRaw, GetState, Restore, GetSize
// goishlint:ignore GOISH018 ReadPassword — term.go's sixth wrapper. Go
//     delegates it to readPassword in term_unix.go, which is the
//     line-editing loop over a raw terminal; it is deferred here and
//     the deviation list below says so. Nothing in goish calls it.
//
// term — port of golang.org/x/term (term.go + term_unix.go +
// term_unix_linux.go), the terminal-control package every TUI sits on.
//
//   Go                                       goish
//   ──────────────────────────────────────   ──────────────────────────────
//   term.IsTerminal(fd)                      term::IsTerminal(fd)
//   old, err := term.MakeRaw(fd)             let (old, err) = term::MakeRaw(fd);
//   term.Restore(fd, old)                    term::Restore(fd, &old);
//   st, err := term.GetState(fd)             let (st, err) = term::GetState(fd);
//   w, h, err := term.GetSize(fd)            let (w, h, err) = term::GetSize(fd);
//
// The bodies come from term_unix.go, whose lowercase impls Go's
// term.go wrappers delegate to; each is inlined under the exported
// name here. On Linux `ioctlReadTermios` is TCGETS and
// `ioctlWriteTermios` is TCSETS, per term_unix_linux.go.
//
// **Deviations from Go (v1):**
//   * `MakeRaw` / `GetState` return `(State, error)` where Go returns
//     `(*State, error)` — goish's value-plus-error shape; the zero
//     State accompanies a non-nil error.
//   * `ReadPassword` is deferred (needs the line-editing loop from
//     terminal.go; QuCode's input layer supersedes it).

#![allow(non_snake_case)]

use crate::errors::{self, error};
use crate::syscall;
use crate::types::int;

/// `term.State` — the state of a terminal, as captured by `GetState` /
/// `MakeRaw` and reapplied by `Restore`. Opaque, like Go's unexported
/// `state` embed.
#[derive(Copy, Clone, Default)]
pub struct State {
    termios: syscall::Termios,
}

// go: none — goish helper. Go calls unix.IoctlGetTermios inline in
// each of the five bodies; hoisting it keeps them one-liners.
/// `unix.IoctlGetTermios(fd, TCGETS)` — TCGETS into a fresh Termios.
fn ioctl_get_termios(fd: i32) -> (syscall::Termios, isize) {
    let mut t = syscall::Termios::default();
    let rc = syscall::Ioctl(
        fd,
        syscall::TCGETS,
        &mut t as *mut syscall::Termios as usize,
    );
    return (t, rc);
}

// go: none — goish helper. Go's bodies return the unix.Ioctl error
// directly; goish's syscalls return a negative errno, so the two-line
// conversion is hoisted rather than repeated five times.
/// Map a negative ioctl rc onto a goish `error` (Errno-typed).
fn errno_err(rc: isize) -> error {
    return syscall::Errno(-rc as i32).into(); // goishlint:ignore GOISH005 - an errno for Errno(), a C ABI int
}

// go: sdk 1.25.5 cmd/vendor/golang.org/x/term/term.go:25-27 IsTerminal
/// `term.IsTerminal(fd)` — whether the file descriptor is a terminal.
/// Go's wrapper is `return isTerminal(fd)`; that body, at term_unix.go
/// line 17, is `_, err := unix.IoctlGetTermios(fd, ioctlReadTermios);
/// return err == nil`, and is inlined here.
pub fn IsTerminal(fd: int) -> bool {
    let fd32 = fd as i32; // goishlint:ignore GOISH005 - an fd for ioctl(2), a C ABI int
    let (_, rc) = ioctl_get_termios(fd32);
    return rc == 0;
}

// go: sdk 1.25.5 cmd/vendor/golang.org/x/term/term.go:38-40 GetState
/// `term.GetState(fd)` — capture the current terminal state, useful
/// to restore after a signal. Body inlined from getState, at
/// term_unix.go line 46.
pub fn GetState(fd: int) -> (State, error) {
    let fd32 = fd as i32; // goishlint:ignore GOISH005 - an fd for ioctl(2), a C ABI int
    let (termios, rc) = ioctl_get_termios(fd32);
    if rc != 0 {
        return (State::default(), errno_err(rc));
    }
    return (State { termios }, errors::nil);
}

// go: sdk 1.25.5 cmd/vendor/golang.org/x/term/term.go:32-34 MakeRaw
/// `term.MakeRaw(fd)` — put the terminal into raw mode and return the
/// previous state. Line-by-line from makeRaw, at term_unix.go line 22,
/// which replicates the behaviour documented for `cfmakeraw` in
/// termios(3).
pub fn MakeRaw(fd: int) -> (State, error) {
    let fd = fd as i32; // goishlint:ignore GOISH005 - an fd for ioctl(2), a C ABI int
    let (mut termios, rc) = ioctl_get_termios(fd);
    if rc != 0 {
        return (State::default(), errno_err(rc));
    }

    let oldState = State { termios };

    // Go: termios.Iflag &^= IGNBRK | BRKINT | PARMRK | ISTRIP | INLCR | IGNCR | ICRNL | IXON
    termios.Iflag &= !(syscall::IGNBRK
        | syscall::BRKINT
        | syscall::PARMRK
        | syscall::ISTRIP
        | syscall::INLCR
        | syscall::IGNCR
        | syscall::ICRNL
        | syscall::IXON);
    // Go: termios.Oflag &^= OPOST
    termios.Oflag &= !syscall::OPOST;
    // Go: termios.Lflag &^= ECHO | ECHONL | ICANON | ISIG | IEXTEN
    termios.Lflag &=
        !(syscall::ECHO | syscall::ECHONL | syscall::ICANON | syscall::ISIG | syscall::IEXTEN);
    // Go: termios.Cflag &^= CSIZE | PARENB; termios.Cflag |= CS8
    termios.Cflag &= !(syscall::CSIZE | syscall::PARENB);
    termios.Cflag |= syscall::CS8;
    // Go: termios.Cc[VMIN] = 1; termios.Cc[VTIME] = 0
    termios.Cc[syscall::VMIN] = 1;
    termios.Cc[syscall::VTIME] = 0;

    let rc = syscall::Ioctl(
        fd,
        syscall::TCSETS,
        &mut termios as *mut syscall::Termios as usize,
    );
    if rc != 0 {
        return (State::default(), errno_err(rc));
    }

    return (oldState, errors::nil);
}

// go: sdk 1.25.5 cmd/vendor/golang.org/x/term/term.go:44-46 Restore
/// `term.Restore(fd, oldState)` — reapply a previously captured state.
/// Body inlined from restore, at term_unix.go line 55.
pub fn Restore(fd: int, oldState: &State) -> error {
    let mut termios = oldState.termios;
    let fd32 = fd as i32; // goishlint:ignore GOISH005 - an fd for ioctl(2), a C ABI int
    let rc = syscall::Ioctl(
        fd32,
        syscall::TCSETS,
        &mut termios as *mut syscall::Termios as usize,
    );
    if rc != 0 {
        return errno_err(rc);
    }
    return errors::nil;
}

// go: sdk 1.25.5 cmd/vendor/golang.org/x/term/term.go:51-53 GetSize
/// `term.GetSize(fd)` — visible terminal dimensions as
/// `(width, height, error)`. Body inlined from getSize, at
/// term_unix.go line 59.
pub fn GetSize(fd: int) -> (int, int, error) {
    let mut ws = syscall::Winsize::default();
    let fd32 = fd as i32; // goishlint:ignore GOISH005 - an fd for ioctl(2), a C ABI int
    let rc = syscall::Ioctl(
        fd32,
        syscall::TIOCGWINSZ,
        &mut ws as *mut syscall::Winsize as usize,
    );
    if rc != 0 {
        return (0, 0, errno_err(rc));
    }
    let (w, h) = (ws.Col as int, ws.Row as int); // goishlint:ignore GOISH005 - Winsize.Col/Row are C ABI ushorts
    return (w, h, errors::nil);
}
