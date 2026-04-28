// Smoke test: M16e — buffered channels.
//
// Exercises the additional fast paths and edge cases that buffered
// channels introduce on top of M16d's unbuffered semantics:
//
//   1. Send-into-empty-buffer doesn't block — fills slots until cap.
//   2. Send blocks once buffer is full.
//   3. Recv-from-non-empty-buffer doesn't block.
//   4. Recv when buffer is full + sender parked rotates correctly:
//      receiver gets the head value AND the sender's value lands
//      at the tail (preserves FIFO).
//   5. Close on a buffered channel: existing buffered values still
//      drain on Recv before subsequent Recvs return (zero, false).
//   6. Len() / Cap() reflect the runtime state.

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
    test_send_fills_buffer_without_blocking();
    test_send_blocks_when_full();
    test_buffered_fifo_under_contention();
    test_close_drains_buffer_then_returns_false();
    test_len_cap();

    const OK: &[u8] = b"chan_buffered: ok\n";
    syscall::Write(syscall::STDOUT, OK.as_ptr(), OK.len());
}

// ─── Test 1: send N into a cap-N buffer without parking ────────────

fn test_send_fills_buffer_without_blocking() {
    let ch = make!(chan i64, 4);

    static SENT_COUNT: AtomicUsize = AtomicUsize::new(0);

    {
        let ch = ch.clone();
        go!(move || {
            for i in 0..4i64 {
                ch.Send(i);
                SENT_COUNT.fetch_add(1, Ordering::Relaxed);
            }
        });
    }

    schedule();
    check(
        SENT_COUNT.load(Ordering::Relaxed) == 4,
        b"send-fills: didn't push all 4\n",
    );
    check(ch.Len() == 4, b"send-fills: Len mismatch\n");

    // Drain.
    for i in 0..4i64 {
        let (v, ok) = (|| {
            // We're outside any goroutine; spawn one to recv.
            let ch = ch.clone();
            static GOT: AtomicI64 = AtomicI64::new(-1);
            static OK_FLAG: AtomicUsize = AtomicUsize::new(99);
            go!(move || {
                let (v, ok) = ch.Recv();
                GOT.store(v, Ordering::Relaxed);
                OK_FLAG.store(if ok { 1 } else { 0 }, Ordering::Relaxed);
            });
            schedule();
            (
                GOT.load(Ordering::Relaxed),
                OK_FLAG.load(Ordering::Relaxed) == 1,
            )
        })();
        check(ok, b"send-fills: drain not ok\n");
        check(v == i, b"send-fills: drain wrong value\n");
    }
    check(ch.Len() == 0, b"send-fills: drained Len != 0\n");
}

// ─── Test 2: 5th send on a cap-4 buffer blocks ──────────────────────

fn test_send_blocks_when_full() {
    let ch = make!(chan i64, 4);
    static SENDS_DONE: AtomicUsize = AtomicUsize::new(0);
    static RECVD: AtomicI64 = AtomicI64::new(0);

    // Producer pushes 5 items; the 5th will park.
    {
        let ch = ch.clone();
        go!(move || {
            for i in 0..5i64 {
                ch.Send(i);
                SENDS_DONE.fetch_add(1, Ordering::Relaxed);
            }
        });
    }

    // Consumer arrives later (after the producer parks on the 5th
    // send) and pulls all 5 values.
    {
        let ch = ch.clone();
        go!(move || {
            for _ in 0..5 {
                let (v, _) = ch.Recv();
                RECVD.fetch_add(v, Ordering::Relaxed);
            }
        });
    }

    schedule();
    check(
        SENDS_DONE.load(Ordering::Relaxed) == 5,
        b"send-blocks: producer didn't finish\n",
    );
    check(
        RECVD.load(Ordering::Relaxed) == 0 + 1 + 2 + 3 + 4,
        b"send-blocks: consumer didn't receive all\n",
    );
}

// ─── Test 3: many producers + many consumers preserve FIFO under
// buffered contention. With cap=8 and 100 producers + 100 consumers,
// the buffer rotation path (recv with parked sender) gets exercised
// many times. We just verify every value arrives once (sum match).

fn test_buffered_fifo_under_contention() {
    let ch = make!(chan i64, 8);
    static SUM: AtomicI64 = AtomicI64::new(0);
    static MSGS: AtomicUsize = AtomicUsize::new(0);
    const N: i64 = 100;

    for i in 0..N {
        let ch = ch.clone();
        go!(move || {
            ch.Send(i);
        });
    }
    for _ in 0..N {
        let ch = ch.clone();
        go!(move || {
            let (v, ok) = ch.Recv();
            check(ok, b"contention: recv not ok\n");
            SUM.fetch_add(v, Ordering::Relaxed);
            MSGS.fetch_add(1, Ordering::Relaxed);
        });
    }

    schedule();

    let expected: i64 = (0..N).sum();
    check(
        SUM.load(Ordering::Relaxed) == expected,
        b"contention: sum wrong\n",
    );
    check(
        MSGS.load(Ordering::Relaxed) == N as usize,
        b"contention: count wrong\n",
    );
}

// ─── Test 4: close-then-drain — buffered values survive close ──────

fn test_close_drains_buffer_then_returns_false() {
    let ch = make!(chan i64, 3);
    // Pre-fill the buffer.
    {
        let ch = ch.clone();
        go!(move || {
            ch.Send(10);
            ch.Send(20);
            ch.Send(30);
        });
    }
    schedule();
    check(ch.Len() == 3, b"close-drain: pre-fill Len != 3\n");

    // Close.
    ch.Close();

    // Drain via 5 Recv calls — first 3 should yield (10, true),
    // (20, true), (30, true) in FIFO order; calls 4 and 5 should
    // yield (0, false).
    static SEQ: [AtomicI64; 5] = [
        AtomicI64::new(-1),
        AtomicI64::new(-1),
        AtomicI64::new(-1),
        AtomicI64::new(-1),
        AtomicI64::new(-1),
    ];
    static OKS: [AtomicUsize; 5] = [
        AtomicUsize::new(99),
        AtomicUsize::new(99),
        AtomicUsize::new(99),
        AtomicUsize::new(99),
        AtomicUsize::new(99),
    ];

    for i in 0..5usize {
        let ch = ch.clone();
        go!(move || {
            let (v, ok) = ch.Recv();
            SEQ[i].store(v, Ordering::Relaxed);
            OKS[i].store(if ok { 1 } else { 0 }, Ordering::Relaxed);
        });
    }
    schedule();

    // The *channel buffer* drains in FIFO (10, 20, 30 in that
    // order — the property under test), but the *consumer
    // goroutines* are not guaranteed to run in spawn order. Go's
    // own runtime documents this at proc.go:7042-7050:
    //
    //   "To shake out latent assumptions about scheduling order,
    //    we introduce some randomness into scheduling decisions
    //    when running with the race detector. … breaking many
    //    poorly-written tests."
    //
    // Once M17b-γ work-stealing distributes Gs across worker Ms,
    // consumer i=k may execute its `Recv()` before consumer i=0,
    // so SEQ[i] does not necessarily hold the i-th buffered
    // value. The invariant we assert is the multi-set: three of
    // the five recv calls return one each of {10, 20, 30} (in
    // some order), and two return (0, !ok) from the
    // closed-and-empty path.
    let mut got_buf: [i64; 3] = [0; 3];
    let mut got_buf_n: usize = 0;
    let mut closed_count: usize = 0;
    for i in 0..5usize {
        let v = SEQ[i].load(Ordering::Relaxed);
        let ok = OKS[i].load(Ordering::Relaxed);
        if ok == 1 {
            check(got_buf_n < 3, b"drain: too many ok=true recvs\n");
            got_buf[got_buf_n] = v;
            got_buf_n += 1;
        } else if ok == 0 {
            check(v == 0, b"drain: !ok recv with non-zero value\n");
            closed_count += 1;
        } else {
            die(b"drain: consumer never wrote OKS slot\n");
        }
    }
    check(got_buf_n == 3, b"drain: buffered recv count != 3\n");
    check(closed_count == 2, b"drain: closed-recv count != 2\n");
    if got_buf[0] > got_buf[1] {
        got_buf.swap(0, 1);
    }
    if got_buf[1] > got_buf[2] {
        got_buf.swap(1, 2);
    }
    if got_buf[0] > got_buf[1] {
        got_buf.swap(0, 1);
    }
    check(
        got_buf[0] == 10 && got_buf[1] == 20 && got_buf[2] == 30,
        b"drain: recv'd values != {10,20,30}\n",
    );
}

// ─── Test 5: Len() / Cap() reflect runtime state ────────────────────

fn test_len_cap() {
    let ch = make!(chan i64, 5);
    check(ch.Cap() == 5, b"len-cap: Cap mismatch\n");
    check(ch.Len() == 0, b"len-cap: initial Len\n");

    // Push 3 items via a goroutine; channel is buffered enough for
    // these to not park.
    {
        let ch = ch.clone();
        go!(move || {
            ch.Send(1);
            ch.Send(2);
            ch.Send(3);
        });
    }
    schedule();
    check(ch.Len() == 3, b"len-cap: after 3 sends\n");
    check(ch.Cap() == 5, b"len-cap: cap shouldn't change\n");

    // Drain one.
    {
        let ch = ch.clone();
        go!(move || {
            let _ = ch.Recv();
        });
    }
    schedule();
    check(ch.Len() == 2, b"len-cap: after one Recv\n");
}
