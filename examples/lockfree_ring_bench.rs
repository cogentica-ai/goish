// Quick benchmark: chan<T> vs LockFreeRing<T>
// Same workload (push N values, drain N values), apples-to-apples
// where possible. Reports total wall time in ms and ns/op.
//
// The two paths differ in their blocking behavior:
//   - chan<T>::Send/Recv park automatically when buf full / empty.
//   - LockFreeRing has try_send/try_recv only; user calls Gosched
//     on Err/None.
// We size cap >> active producers so neither path needs to park
// in steady state — the comparison reflects raw enqueue/dequeue
// cost, not park/unpark.

#![no_std]
#![no_main]

extern crate alloc;

use alloc::boxed::Box;
use core::sync::atomic::{AtomicI64, AtomicUsize, Ordering};

use goish::gochan::chan;
use goish::runtime::lockfree_ring::LockFreeRing;
use goish::runtime::sched::{schedule, Gosched};
use goish::sync::WaitGroup;
use goish::time::{Now, Since};
use goish::{go, make, syscall, KB};

fn print(s: &[u8]) {
    syscall::Write(syscall::STDOUT, s.as_ptr(), s.len());
}

fn print_dec(n: i64) {
    let mut buf = [0u8; 24];
    let mut i = buf.len();
    let mut neg = false;
    let mut x = if n < 0 {
        neg = true;
        (-(n as i128)) as u128
    } else {
        n as u128
    };
    if x == 0 {
        i -= 1;
        buf[i] = b'0';
    } else {
        while x > 0 {
            i -= 1;
            buf[i] = b'0' + (x % 10) as u8;
            x /= 10;
        }
    }
    if neg {
        i -= 1;
        buf[i] = b'-';
    }
    syscall::Write(syscall::STDOUT, buf[i..].as_ptr(), buf.len() - i);
}

const N_SPSC: i64 = 200_000;
const N_MPMC_PER_PRODUCER: i64 = 50_000;
const N_PRODUCERS_MPMC: i64 = 4;
const CAP: usize = 1024;

#[goish::main]
fn main() {
    go!(|| {
        bench_chan_spsc();
        bench_ring_spsc();
        bench_chan_mpmc();
        bench_ring_mpmc();
    });
    schedule();
}

// ── chan SPSC ───────────────────────────────────────────────────────

fn bench_chan_spsc() {
    let c: chan<i64> = make!(chan i64, CAP as i64);
    let cs = c.clone();
    let cr = c.clone();
    let wg = WaitGroup::new();

    let t0 = Now();
    wg.GoStack(8 * KB, move || {
        for i in 0..N_SPSC {
            cs.Send(i);
        }
    });
    wg.GoStack(8 * KB, move || {
        for _ in 0..N_SPSC {
            let _ = cr.Recv();
        }
    });
    wg.Wait();
    let dt = Since(t0).Nanoseconds();

    print(b"chan  SPSC  N=");
    print_dec(N_SPSC);
    print(b"  total=");
    print_dec(dt / 1_000_000);
    print(b"ms  ns/op=");
    print_dec(dt / N_SPSC);
    print(b"\n");
}

// ── ring SPSC ───────────────────────────────────────────────────────

fn bench_ring_spsc() {
    let r: &'static LockFreeRing<i64> = Box::leak(Box::new(LockFreeRing::new(CAP)));
    let wg = WaitGroup::new();

    let t0 = Now();
    wg.GoStack(8 * KB, move || {
        let mut i: i64 = 0;
        while i < N_SPSC {
            if r.try_send(i).is_ok() {
                i += 1;
            } else {
                Gosched();
            }
        }
    });
    wg.GoStack(8 * KB, move || {
        let mut got: i64 = 0;
        while got < N_SPSC {
            if r.try_recv().is_some() {
                got += 1;
            } else {
                Gosched();
            }
        }
    });
    wg.Wait();
    let dt = Since(t0).Nanoseconds();

    print(b"ring  SPSC  N=");
    print_dec(N_SPSC);
    print(b"  total=");
    print_dec(dt / 1_000_000);
    print(b"ms  ns/op=");
    print_dec(dt / N_SPSC);
    print(b"\n");
}

// ── chan MPMC 4P × 4C ───────────────────────────────────────────────

fn bench_chan_mpmc() {
    let total = N_PRODUCERS_MPMC * N_MPMC_PER_PRODUCER;
    let c: chan<i64> = make!(chan i64, CAP as i64);
    let wg = WaitGroup::new();

    static RECEIVED: AtomicI64 = AtomicI64::new(0);
    RECEIVED.store(0, Ordering::Relaxed);

    let t0 = Now();
    for pid in 0..N_PRODUCERS_MPMC {
        let cs = c.clone();
        wg.GoStack(8 * KB, move || {
            let lo = pid * N_MPMC_PER_PRODUCER;
            let hi = lo + N_MPMC_PER_PRODUCER;
            for i in lo..hi {
                cs.Send(i);
            }
        });
    }
    for _ in 0..N_PRODUCERS_MPMC {
        let cr = c.clone();
        wg.GoStack(8 * KB, move || loop {
            if RECEIVED.load(Ordering::Acquire) >= total {
                return;
            }
            let (_, ok) = cr.Recv();
            if !ok {
                return;
            }
            RECEIVED.fetch_add(1, Ordering::AcqRel);
        });
    }
    // Producers all done → drain remaining + signal close so consumers exit.
    // For this bench we just spin until RECEIVED == total, then close.
    while RECEIVED.load(Ordering::Acquire) < total {
        Gosched();
    }
    let dt = Since(t0).Nanoseconds();
    goish::close!(c); // wakes any consumers still parked on Recv
    wg.Wait();

    print(b"chan  MPMC  N=");
    print_dec(total);
    print(b"  total=");
    print_dec(dt / 1_000_000);
    print(b"ms  ns/op=");
    print_dec(dt / total);
    print(b"\n");
}

// ── ring MPMC 4P × 4C ───────────────────────────────────────────────

fn bench_ring_mpmc() {
    let total = N_PRODUCERS_MPMC * N_MPMC_PER_PRODUCER;
    let r: &'static LockFreeRing<i64> = Box::leak(Box::new(LockFreeRing::new(CAP)));
    let wg = WaitGroup::new();

    static RECEIVED: AtomicI64 = AtomicI64::new(0);
    static DONE: AtomicUsize = AtomicUsize::new(0);
    RECEIVED.store(0, Ordering::Relaxed);
    DONE.store(0, Ordering::Relaxed);

    let t0 = Now();
    for pid in 0..N_PRODUCERS_MPMC {
        wg.GoStack(8 * KB, move || {
            let lo = pid * N_MPMC_PER_PRODUCER;
            let hi = lo + N_MPMC_PER_PRODUCER;
            let mut i = lo;
            while i < hi {
                if r.try_send(i).is_ok() {
                    i += 1;
                } else {
                    Gosched();
                }
            }
        });
    }
    for _ in 0..N_PRODUCERS_MPMC {
        wg.GoStack(8 * KB, || loop {
            if RECEIVED.load(Ordering::Acquire) >= total {
                DONE.fetch_add(1, Ordering::AcqRel);
                return;
            }
            if r.try_recv().is_some() {
                RECEIVED.fetch_add(1, Ordering::AcqRel);
            } else {
                Gosched();
            }
        });
    }
    wg.Wait();
    let dt = Since(t0).Nanoseconds();

    print(b"ring  MPMC  N=");
    print_dec(total);
    print(b"  total=");
    print_dec(dt / 1_000_000);
    print(b"ms  ns/op=");
    print_dec(dt / total);
    print(b"\n");
}
