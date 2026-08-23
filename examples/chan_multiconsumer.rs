// Smoke test: M17a-ε — multi-consumer with closer (port of Go
// runtime/chan_test.go:546 TestMultiConsumer).
//
// Topology:
//   feeder ──q──> [N workers] ──r──> consumer
//                  ↓              ↓
//                close(q)      close(r)
//
//   - feeder: sends NITER values into q, then closes q.
//   - workers: drain q via Recv-loop until closed; for each value,
//     forward to r. When all workers see q closed, the last one
//     closes r (we coordinate via WORKERS_REMAINING).
//   - consumer: drains r via Recv-loop until closed; sums values.
//
// Verifies that close-during-recv-storm is correct under multi-M:
// every queued value is delivered exactly once, count and sum
// match feeder's expectations, no deadlock.
//
// Stack size: workers are opted up to 64 KiB to avoid 2 KiB overflow
// under the close-storm path (Recv frame + sudog + gopark + signal-
// stack interaction crowds the cap on real hardware at ~0.2% rate;
// see project_stack_grow_3tier_design.md for the long-term fix).

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

const NWORK: usize = 8;
const QCAP: i64 = 24; // NWORK * 3
const NITER: i64 = 5_000;
const PRIMES: [i64; 10] = [2, 3, 7, 11, 13, 17, 19, 23, 27, 31];

static EXPECT: AtomicI64 = AtomicI64::new(0);
static GOT_SUM: AtomicI64 = AtomicI64::new(0);
static GOT_N: AtomicI64 = AtomicI64::new(0);
static WORKERS_REMAINING: AtomicUsize = AtomicUsize::new(NWORK);
static CONSUMER_DONE: AtomicUsize = AtomicUsize::new(0);
static FEEDER_DONE: AtomicUsize = AtomicUsize::new(0);

#[goish::main]
fn main() {
    let q = make!(chan i64, QCAP);
    let r = make!(chan i64, QCAP);

    // Workers: consume from q, forward to r. Last one closes r.
    for _ in 0..NWORK {
        let q = q.clone();
        let r = r.clone();
        go!(move || {
            loop {
                let (v, ok) = q.Recv();
                if !ok {
                    break;
                }
                r.Send(v);
            }
            // q is closed. If we're the last worker, close r.
            if WORKERS_REMAINING.fetch_sub(1, Ordering::AcqRel) == 1 {
                r.Close();
            }
        });
    }

    // Feeder: produce NITER values, then close q.
    {
        let q = q.clone();
        go!(move || {
            let mut expect: i64 = 0;
            for i in 0..NITER {
                let v = PRIMES[(i as usize) % PRIMES.len()];
                expect += v;
                q.Send(v);
            }
            EXPECT.store(expect, Ordering::Release);
            q.Close();
            FEEDER_DONE.store(1, Ordering::Release);
        });
    }

    // Consumer: drain r and sum.
    {
        let r = r.clone();
        go!(move || {
            let mut n: i64 = 0;
            let mut s: i64 = 0;
            loop {
                let (v, ok) = r.Recv();
                if !ok {
                    break;
                }
                n += 1;
                s += v;
            }
            GOT_N.store(n, Ordering::Release);
            GOT_SUM.store(s, Ordering::Release);
            CONSUMER_DONE.store(1, Ordering::Release);
        });
    }

    schedule();

    check(
        FEEDER_DONE.load(Ordering::Acquire) == 1,
        b"multiconsumer: feeder didn't finish\n",
    );
    check(
        CONSUMER_DONE.load(Ordering::Acquire) == 1,
        b"multiconsumer: consumer didn't finish\n",
    );
    check(
        WORKERS_REMAINING.load(Ordering::Acquire) == 0,
        b"multiconsumer: workers leaked\n",
    );
    let expect = EXPECT.load(Ordering::Acquire);
    let got_n = GOT_N.load(Ordering::Acquire);
    let got_s = GOT_SUM.load(Ordering::Acquire);
    check(got_n == NITER, b"multiconsumer: count wrong\n");
    check(got_s == expect, b"multiconsumer: sum wrong\n");

    const OK: &[u8] = b"chan_multiconsumer: ok\n";
    syscall::Write(syscall::STDOUT, OK.as_ptr(), OK.len());
}
