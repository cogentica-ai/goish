// Step 2 in the M17b-δ bug-hunting ladder.
//
// Same shape as `chan_select_stress` but with `select!` removed:
//   - 4 chans (2 unbuffered, 2 buffered cap=2/3) — same as the
//     full stress test.
//   - 4 plain senders, 4 plain receivers — no select goroutines.
//   - No `Close`.
//
// If this passes 0/200 like `chan_micro_send_recv`, the bug is
// in the `select!` machinery. If it fails at the
// `chan_select_stress` rate (~2%), the bug is in plain
// chan/scheduler interaction at scale (multi-M, multi-chan,
// multi-goroutine), not in select.
//
// N kept at the full 1e5 to match `chan_select_stress`.

#![no_std]
#![no_main]

use core::sync::atomic::{AtomicI64, AtomicUsize, Ordering};

use goish::gochan::chan;
use goish::runtime::sched::schedule;
use goish::{go, make, syscall, KB};

fn die(msg: &[u8]) -> ! {
    syscall::Write(syscall::STDERR, msg.as_ptr(), msg.len());
    syscall::Exit(1);
}

fn check(cond: bool, msg: &[u8]) {
    if !cond {
        die(msg);
    }
}

const N: i64 = 100_000;

#[goish::main]
fn main() {
    let c: [chan<i64>; 4] = [
        make!(chan i64),
        make!(chan i64),
        make!(chan i64, 2),
        make!(chan i64, 3),
    ];

    static SEND_TOTAL: AtomicI64 = AtomicI64::new(0);
    static RECV_TOTAL: AtomicI64 = AtomicI64::new(0);
    static GS_DONE: AtomicUsize = AtomicUsize::new(0);

    for k in 0..4usize {
        {
            let ck = c[k].clone();
            go!(stack(64 * KB), move || {
                for _ in 0..N {
                    ck.Send(0);
                    SEND_TOTAL.fetch_add(1, Ordering::Relaxed);
                }
                GS_DONE.fetch_add(1, Ordering::Relaxed);
            });
        }
        {
            let ck = c[k].clone();
            go!(stack(64 * KB), move || {
                for _ in 0..N {
                    let _ = ck.Recv();
                    RECV_TOTAL.fetch_add(1, Ordering::Relaxed);
                }
                GS_DONE.fetch_add(1, Ordering::Relaxed);
            });
        }
    }

    schedule();

    check(
        GS_DONE.load(Ordering::Relaxed) == 8,
        b"chan_micro_no_select: not all 8 Gs done\n",
    );
    check(
        SEND_TOTAL.load(Ordering::Relaxed) == 4 * N,
        b"chan_micro_no_select: send total wrong\n",
    );
    check(
        RECV_TOTAL.load(Ordering::Relaxed) == 4 * N,
        b"chan_micro_no_select: recv total wrong\n",
    );

    const OK: &[u8] = b"chan_micro_no_select: ok\n";
    syscall::Write(syscall::STDOUT, OK.as_ptr(), OK.len());
}
