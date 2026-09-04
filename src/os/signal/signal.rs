// os/signal/signal — Go 1.25.5 src/os/signal/signal.go.
//
// Public API:
//
//   signal::Notify(&c, &[syscall::SIGINT, syscall::SIGTERM]);
//   let (sig, _) = c.Recv();   // blocks until a signal arrives
//   signal::Stop(&c);
//
// What is still missing is what goishlint reports: the handler map's
// internals, `signum`, the `watchSignalLoop` plumbing. The public
// surface below is complete.

#![allow(non_snake_case)]

extern crate alloc;

use alloc::boxed::Box;
use alloc::sync::Arc;

use crate::gochan::chan;

// go: sdk 1.25.5 os/signal/signal.go:122-169 Notify
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

// go: sdk 1.25.5 os/signal/signal.go:181-227 Stop
/// `signal.Stop(c)` — stop relaying signals to `c`. Subsequent
/// signals will not be sent. Does not close `c`.
pub fn Stop(c: &chan<i32>) {
    crate::runtime::signal::unregister(c);
}

// go: sdk 1.25.5 os/signal/signal.go:278-296 NotifyContext
/// `signal.NotifyContext(parent, sigs...)` — a copy
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
    return (ctx, stop);
}

// go: sdk 1.25.5 os/signal/signal.go:87-89 Ignore
/// Go: "Ignore causes the
/// provided signals to be ignored. If they are received by the
/// program, nothing will happen. Ignore undoes the effect of any
/// prior calls to Notify for the provided signals. If no signals are
/// provided, all incoming signals will be ignored."
///
/// Both halves matter and both are measured: the registry entry is
/// dropped AND the kernel disposition becomes SIG_IGN.
pub fn Ignore(sigs: &[i32]) {
    crate::runtime::signal::unregister_sigs(sigs);
    if sigs.is_empty() {
        for s in 1..64i32 {
            crate::runtime::signal::ignore_signal(s);
        }
        return;
    }
    for &s in sigs {
        crate::runtime::signal::ignore_signal(s);
    }
}

// go: sdk 1.25.5 os/signal/signal.go:92-95 Ignored
/// Go: "Ignored reports
/// whether sig is currently ignored."
///
/// It reports the DISPOSITION, not goish's registry. That is why
/// `Ignored` stays true after `Reset` — see the note there.
pub fn Ignored(sig: i32) -> bool {
    return crate::runtime::signal::is_ignored(sig);
}

// go: sdk 1.25.5 os/signal/signal.go:174-176 Reset
/// Go: "Reset undoes the
/// effect of any prior calls to Notify for the provided signals. If
/// no signals are provided, all signal handlers will be reset."
///
/// Reset drops the registrations and NOTHING ELSE. Measured against
/// Go: after `Ignore(SIGUSR1)` then `Reset(SIGUSR1)`,
/// `Ignored(SIGUSR1)` is still TRUE. Go's `cancel(sig,
/// disableSignal)` stops the runtime WANTING the signal; the
/// disposition Ignore installed survives, and only a later `Notify`
/// — which reinstalls the handler — clears it.
///
/// This is the one line of nine that contradicted intuition when the
/// reference was generated, which is why it is spelled out here.
pub fn Reset(sigs: &[i32]) {
    crate::runtime::signal::unregister_sigs(sigs);
}
