// os/signal — Go's `os/signal` package.
//
// Reference: /share/go/src/os/signal/signal.go.
//
// Public API:
//
//   signal::Notify(&c, &[syscall::SIGINT, syscall::SIGTERM]);
//   let (sig, _) = c.Recv();   // blocks until a signal arrives
//   match sig {
//       syscall::SIGINT  => ...,  // Ctrl+C
//       syscall::SIGTERM => ...,  // kill
//       _ => ...,
//   }
//   signal::Stop(&c);
//
// Goish v1 uses `chan<i32>` (the signal number) where Go uses
// `chan<- os.Signal`. Go's `os.Signal` is just an interface with
// `String()` and `Signal()` methods over what is, internally, a
// `syscall.Signal` (an int wrapped). The integer-as-signal form
// is more direct and avoids the interface overhead.
//
// What v1 omits:
//   - `signal.Reset(sigs ...)` (restore default handler).
//   - `signal.Ignore(sigs ...)` (set SIG_IGN).
//   - `signal.Ignored(sig) bool`.
//   - SIGINFO siginfo_t / context-aware handlers.

#![allow(non_snake_case)]

use crate::gochan::chan;

/// `signal.Notify(c, sigs...)` — register `c` to receive
/// notifications when any of the given signals fires. Multiple
/// calls accumulate (different signal sets). Mirrors `Notify`
/// (signal.go in Go's stdlib).
///
/// Sends are non-blocking: if `c`'s buffer is full when the
/// signal arrives, the delivery is dropped (matches Go).
pub fn Notify(c: &chan<i32>, sigs: &[i32]) {
    crate::runtime::signal::register(c, sigs);
}

/// `signal.Stop(c)` — stop relaying signals to `c`. Subsequent
/// signals will not be sent. Does not close `c`.
pub fn Stop(c: &chan<i32>) {
    crate::runtime::signal::unregister(c);
}
