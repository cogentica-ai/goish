// Smoke test: SIGWINCH (terminal resize) delivery through os/signal.
//
// A TUI's resize path is `signal.Notify(c, syscall.SIGWINCH)` + a
// re-render on each delivery. Headless, we can't resize a real
// terminal, but the kernel treats a self-sent SIGWINCH identically
// to one raised by a TIOCSWINSZ ioctl — what's under test is the
// constant + the runtime's dynamic handler install for signal 28.
//
// Verifies: Notify a chan for SIGWINCH, self-kill twice (coalescing
// allowed, at least one delivery required), recv it, then Stop.

#![no_std]
#![no_main]

use core::sync::atomic::{AtomicI64, AtomicUsize, Ordering};

use goish::os::signal as ossig;
use goish::runtime::sched::schedule;
use goish::time::{Milliseconds, Sleep};
use goish::{go, make, syscall};

fn die(msg: &[u8]) -> ! {
    syscall::Write(syscall::STDERR, msg.as_ptr(), msg.len());
    syscall::Exit(1);
}

fn check(cond: bool, msg: &[u8]) {
    if !cond {
        die(msg);
    }
}

#[goish::main]
fn main() {
    static GOT_SIG: AtomicI64 = AtomicI64::new(-1);
    static DONE: AtomicUsize = AtomicUsize::new(0);

    // Buffered cap=1 so the dispatcher's non-blocking send won't drop
    // (further deliveries while full coalesce, matching Go).
    let c = make!(chan i32, 1);
    ossig::Notify(&c, &[syscall::SIGWINCH]);

    // Receiver goroutine (see signal_smoke.rs for the stack notes).
    {
        let c = c.clone();
        go!(move || {
            let (sig, _) = c.Recv();
            GOT_SIG.store(sig as i64, Ordering::Release);
            DONE.store(1, Ordering::Release);
        });
    }

    // Sender: let the receiver park, then self-deliver SIGWINCH
    // twice — the second may coalesce into the full buffer, which
    // is exactly Go's contract for resize storms.
    go!(|| {
        Sleep(Milliseconds(10));
        let pid = syscall::Getpid();
        let r = syscall::Kill(pid, syscall::SIGWINCH);
        if r != 0 {
            die(b"signal_winch: Kill returned nonzero\n");
        }
        let _ = syscall::Kill(pid, syscall::SIGWINCH);
    });

    schedule();

    check(
        DONE.load(Ordering::Acquire) == 1,
        b"winch: receiver didn't fire\n",
    );
    check(
        GOT_SIG.load(Ordering::Acquire) == syscall::SIGWINCH as i64,
        b"winch: wrong signal received\n",
    );
    ossig::Stop(&c);

    const OK: &[u8] = b"signal_winch_smoke: ok\n";
    syscall::Write(syscall::STDOUT, OK.as_ptr(), OK.len());
}
