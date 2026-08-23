// Smoke test: M16d — unbuffered channels.
//
// Exercises the four critical paths of an unbuffered channel:
//
//   1. Sender arrives first, parks; receiver picks up the value.
//   2. Receiver arrives first, parks; sender hands off directly.
//   3. Multiple producers + multiple consumers handing off through
//      one channel — verifies FIFO of waiters and that every
//      message arrives exactly once.
//   4. Close semantics: parked receivers get (zero, false); future
//      receives also get (zero, false).
//
// All examples run cooperatively via the M16b scheduler, so the
// interleavings are deterministic on a single OS thread.

#![no_std]
#![no_main]

use core::sync::atomic::{AtomicI64, AtomicUsize, Ordering};

use goish::runtime::sched::schedule;
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
    test_send_first_then_recv();
    test_recv_first_then_send();
    test_many_producers_consumers();
    test_close_drains_parked_recvs();

    const OK: &[u8] = b"chan_unbuffered: ok\n";
    syscall::Write(syscall::STDOUT, OK.as_ptr(), OK.len());
}

// ─── Test 1: sender parks first, receiver picks up ──────────────────

fn test_send_first_then_recv() {
    let ch = make!(chan i64);
    static GOT: AtomicI64 = AtomicI64::new(0);

    {
        let ch = ch.clone();
        go!(move || {
            ch.Send(0xCAFE);
        });
    }
    {
        let ch = ch.clone();
        go!(move || {
            let (v, ok) = ch.Recv();
            check(ok, b"send-first: not ok\n");
            GOT.store(v, Ordering::Relaxed);
        });
    }

    schedule();
    check(
        GOT.load(Ordering::Relaxed) == 0xCAFE,
        b"send-first: wrong value\n",
    );
}

// ─── Test 2: receiver parks first, sender hands off ─────────────────

fn test_recv_first_then_send() {
    let ch = make!(chan i64);
    static GOT: AtomicI64 = AtomicI64::new(0);

    {
        let ch = ch.clone();
        go!(move || {
            // Recv goroutine starts first in FIFO order, parks
            // because no sender exists yet.
            let (v, ok) = ch.Recv();
            check(ok, b"recv-first: not ok\n");
            GOT.store(v, Ordering::Relaxed);
        });
    }
    {
        let ch = ch.clone();
        go!(move || {
            ch.Send(0xBEEF);
        });
    }

    schedule();
    check(
        GOT.load(Ordering::Relaxed) == 0xBEEF,
        b"recv-first: wrong value\n",
    );
}

// ─── Test 3: many producers + consumers, all messages delivered ────

fn test_many_producers_consumers() {
    let ch = make!(chan i64);
    static SUM: AtomicI64 = AtomicI64::new(0);
    static MSGS: AtomicUsize = AtomicUsize::new(0);

    const N: i64 = 100;

    // Spawn N producers, each sending its index.
    for i in 0..N {
        let ch = ch.clone();
        go!(move || {
            ch.Send(i);
        });
    }
    // Spawn N consumers, each receiving one message and adding it
    // to SUM.
    for _ in 0..N {
        let ch = ch.clone();
        go!(move || {
            let (v, ok) = ch.Recv();
            check(ok, b"many: not ok\n");
            SUM.fetch_add(v, Ordering::Relaxed);
            MSGS.fetch_add(1, Ordering::Relaxed);
        });
    }

    schedule();

    let expected_sum: i64 = (0..N).sum();
    check(
        SUM.load(Ordering::Relaxed) == expected_sum,
        b"many: sum wrong\n",
    );
    check(
        MSGS.load(Ordering::Relaxed) == N as usize,
        b"many: msg count wrong\n",
    );
}

// ─── Test 4: close wakes parked receivers with (zero, false) ────────

fn test_close_drains_parked_recvs() {
    let ch = make!(chan i64);
    static OK_FLAGS: AtomicUsize = AtomicUsize::new(0); // bitmask
    static ZEROS: AtomicI64 = AtomicI64::new(0); // sum of values (should be 0)

    // Three receivers all park (no senders).
    for i in 0..3usize {
        let ch = ch.clone();
        go!(move || {
            let (v, ok) = ch.Recv();
            // After close: ok=false, v=0 (default i64).
            ZEROS.fetch_add(v, Ordering::Relaxed);
            // Mark this receiver finished, with ok bit reflected.
            let bit = if ok { 1usize << (i + 16) } else { 1usize << i };
            OK_FLAGS.fetch_or(bit, Ordering::Relaxed);
        });
    }

    // After receivers park, a closer goroutine closes the channel.
    let close_ch = ch.clone();
    go!(move || {
        close_ch.Close();
    });

    schedule();

    // All three receivers should have observed ok=false (bits 0..2)
    // and zero values.
    let flags = OK_FLAGS.load(Ordering::Relaxed);
    check(flags & 0b111 == 0b111, b"close: not all 3 saw ok=false\n");
    check(
        flags & 0b1110000_0000_0000_0000 == 0,
        b"close: some saw ok=true\n",
    );
    check(
        ZEROS.load(Ordering::Relaxed) == 0,
        b"close: nonzero default\n",
    );

    // A subsequent Recv on the closed channel should also return
    // (0, false) immediately, not block.
    let post_ch = ch.clone();
    static POST_OK: AtomicUsize = AtomicUsize::new(99);
    go!(move || {
        let (v, ok) = post_ch.Recv();
        let _ = v;
        POST_OK.store(if ok { 1 } else { 0 }, Ordering::Relaxed);
    });
    schedule();
    check(
        POST_OK.load(Ordering::Relaxed) == 0,
        b"close: post-close Recv didn't return false\n",
    );
}
