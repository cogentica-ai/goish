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
// Reference: go/src/cmd/vendor/golang.org/x/term/term_unix.go. On
// Linux `ioctlReadTermios` is `TCGETS` and `ioctlWriteTermios` is
// `TCSETS` (term_unix_linux.go).
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

/// `unix.IoctlGetTermios(fd, TCGETS)` — TCGETS into a fresh Termios.
fn ioctl_get_termios(fd: i32) -> (syscall::Termios, isize) {
    let mut t = syscall::Termios::default();
    let rc = syscall::Ioctl(
        fd,
        syscall::TCGETS,
        &mut t as *mut syscall::Termios as usize,
    );
    (t, rc)
}

/// Map a negative ioctl rc onto a goish `error` (Errno-typed).
fn errno_err(rc: isize) -> error {
    syscall::Errno(-rc as i32).into()
}

/// `term.IsTerminal(fd)` — whether the file descriptor is a terminal.
/// Go: `_, err := unix.IoctlGetTermios(fd, ioctlReadTermios); return
/// err == nil` (term_unix.go:17).
pub fn IsTerminal(fd: int) -> bool {
    let (_, rc) = ioctl_get_termios(fd as i32);
    rc == 0
}

/// `term.GetState(fd)` — capture the current terminal state, useful
/// to restore after a signal (term_unix.go:46).
pub fn GetState(fd: int) -> (State, error) {
    let (termios, rc) = ioctl_get_termios(fd as i32);
    if rc != 0 {
        return (State::default(), errno_err(rc));
    }
    (State { termios }, errors::nil)
}

/// `term.MakeRaw(fd)` — put the terminal into raw mode and return the
/// previous state. Line-by-line from term_unix.go:22, which replicates
/// the behaviour documented for `cfmakeraw` in termios(3).
pub fn MakeRaw(fd: int) -> (State, error) {
    let fd = fd as i32;
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

    (oldState, errors::nil)
}

/// `term.Restore(fd, oldState)` — reapply a previously captured state
/// (term_unix.go:55).
pub fn Restore(fd: int, oldState: &State) -> error {
    let mut termios = oldState.termios;
    let rc = syscall::Ioctl(
        fd as i32,
        syscall::TCSETS,
        &mut termios as *mut syscall::Termios as usize,
    );
    if rc != 0 {
        return errno_err(rc);
    }
    errors::nil
}

/// `term.GetSize(fd)` — visible terminal dimensions as
/// `(width, height, error)` (term_unix.go:59).
pub fn GetSize(fd: int) -> (int, int, error) {
    let mut ws = syscall::Winsize::default();
    let rc = syscall::Ioctl(
        fd as i32,
        syscall::TIOCGWINSZ,
        &mut ws as *mut syscall::Winsize as usize,
    );
    if rc != 0 {
        return (0, 0, errno_err(rc));
    }
    (ws.Col as int, ws.Row as int, errors::nil)
}
