// Smoke test: M23 — os/signal.
//
// Sends SIGUSR1 to ourselves, verifies it's received on a chan
// registered via os::signal::Notify. Then unregisters via Stop
// and verifies subsequent SIGUSR1 deliveries do NOT arrive.

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
    test_notify_then_recv();
    test_stop_drops_signals();

    const OK: &[u8] = b"signal_smoke: ok\n";
    syscall::Write(syscall::STDOUT, OK.as_ptr(), OK.len());
}

// ── Test 1: Notify a chan, send SIGUSR1, recv it ─────────────────

fn test_notify_then_recv() {
    static GOT_SIG: AtomicI64 = AtomicI64::new(-1);
    static DONE: AtomicUsize = AtomicUsize::new(0);

    // Buffered cap=1 so the dispatcher's non-blocking send won't drop.
    let c = make!(chan i32, 1);
    ossig::Notify(&c, &[syscall::SIGUSR1]);

    // Receiver goroutine. Recv parks via gopark which carries
    // a deeper Rust-debug-build call stack than the 2 KiB default
    // (chan_park → mcall_setup → swap_context, plus alloc paths
    // when the chan's recvq grows). 64 KiB matches the chan_micro
    // examples and keeps the same headroom margin.
    {
        let c = c.clone();
        go!(move || {
            let (sig, _) = c.Recv();
            GOT_SIG.store(sig as i64, Ordering::Release);
            DONE.store(1, Ordering::Release);
        });
    }

    // Sender: small delay to let the receiver park, then self-kill.
    // Sleep → sysmon::timer_park → BinaryHeap::push → mheap alloc
    // is ~24 frames deep in debug builds; default 2 KiB stack
    // overflows into the next mmap region and SEGV-s in
    // PallocBits::summarize.
    go!(|| {
        Sleep(Milliseconds(10));
        let pid = syscall::Getpid();
        let r = syscall::Kill(pid, syscall::SIGUSR1);
        if r != 0 {
            die(b"signal_smoke: Kill returned nonzero\n");
        }
    });

    schedule();

    check(DONE.load(Ordering::Acquire) == 1, b"notify-recv: receiver didn't fire\n");
    check(
        GOT_SIG.load(Ordering::Acquire) == syscall::SIGUSR1 as i64,
        b"notify-recv: wrong signal received\n",
    );

    // Clean up registration so test 2 starts fresh.
    ossig::Stop(&c);
}

// ── Test 2: Stop unregisters; subsequent signals are not delivered.

fn test_stop_drops_signals() {
    static FIRED: AtomicUsize = AtomicUsize::new(0);

    let c = make!(chan i32, 4);
    ossig::Notify(&c, &[syscall::SIGUSR2]);
    ossig::Stop(&c);

    // Spawn a goroutine that uses select with default to drain
    // anything in the chan during a 30ms window. Without a Stop
    // bug, nothing should arrive. 64 KiB stack as for test 1 —
    // Sleep's call chain through sysmon::timer_park overflows
    // the default 2 KiB.
    {
        let c = c.clone();
        go!(move || {
            for _ in 0..3 {
                Sleep(Milliseconds(10));
                // Try non-blocking recv via __try_recv-equivalent:
                // peek at the chan's Len. If anything arrived after
                // Stop, Len > 0.
                if c.Len() > 0 {
                    FIRED.fetch_add(1, Ordering::Relaxed);
                }
            }
        });
    }

    // Self-kill SIGUSR2 while the goroutine watches.
    go!(|| {
        Sleep(Milliseconds(5));
        let pid = syscall::Getpid();
        let _ = syscall::Kill(pid, syscall::SIGUSR2);
        let _ = syscall::Kill(pid, syscall::SIGUSR2);
    });

    schedule();

    check(
        FIRED.load(Ordering::Relaxed) == 0,
        b"stop: signals delivered after Stop\n",
    );
}
