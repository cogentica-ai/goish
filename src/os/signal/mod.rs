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

extern crate alloc;

use alloc::boxed::Box;
use alloc::sync::Arc;

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

/// `signal.NotifyContext(parent, sigs...)` (signal.go:278) — a copy
/// of `parent` marked done when one of `sigs` arrives, when the
/// returned stop function is called, or when the parent is done —
/// whichever comes first. The blessed shape for SIGTERM-triggered
/// graceful shutdown:
///
/// ```ignore
/// let (ctx, stop) = signal::NotifyContext(
///     context::Background(), &[syscall::SIGTERM, syscall::SIGINT]);
/// let _ = (ctx.Done()).Recv();   // park until signal
/// let _ = srv.Shutdown(time::Second * 10);
/// stop();
/// ```
pub fn NotifyContext(
    parent: Arc<dyn crate::context::Context>,
    sigs: &[i32],
) -> (Arc<dyn crate::context::Context>, crate::context::CancelFunc) {
    let (ctx, cancel) = crate::context::WithCancel(parent);
    let cancel = Arc::new(cancel);
    let ch = chan::<i32>::new_buffered(1);
    Notify(&ch, sigs);
    if ctx.Err().IsNil() {
        // Watcher goroutine (signal.go:288): first of {signal, done}
        // wins — a signal cancels the ctx, parent-done just exits.
        let wctx = ctx.clone();
        let wch = ch.clone();
        let wcancel = cancel.clone();
        crate::go!(move || {
            crate::select! {
                let _ = (wch).Recv() => { (wcancel)(); },
                let _ = (wctx.Done()).Recv() => {},
            };
        });
    }
    let stop_ch = ch;
    let stop: crate::context::CancelFunc = Box::new(move || {
        (cancel)();
        Stop(&stop_ch);
    });
    (ctx, stop)
}
