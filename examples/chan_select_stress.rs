// Smoke test: M17a-ε — verbatim port of Go runtime/chan_test.go:342
// TestSelectStress (Go 1.25.5).
//
// Reproduced from Go SDK for line-by-line equivalence:
//
//   func TestSelectStress(t *testing.T) {
//       defer runtime.GOMAXPROCS(runtime.GOMAXPROCS(10))
//       var c [4]chan int
//       c[0] = make(chan int)
//       c[1] = make(chan int)
//       c[2] = make(chan int, 2)
//       c[3] = make(chan int, 3)
//       N := int(1e5)
//       if testing.Short() { N /= 10 }
//       var wg sync.WaitGroup
//       wg.Add(10)
//       for k := 0; k < 4; k++ {
//           k := k
//           go func() { for i := 0; i < N; i++ { c[k] <- 0 }; wg.Done() }()
//           go func() { for i := 0; i < N; i++ { <-c[k]   }; wg.Done() }()
//       }
//       go func() {
//           var n [4]int
//           c1 := c
//           for i := 0; i < 4*N; i++ {
//               select {
//               case c1[3] <- 0: n[3]++; if n[3]==N { c1[3] = nil }
//               case c1[2] <- 0: n[2]++; if n[2]==N { c1[2] = nil }
//               case c1[0] <- 0: n[0]++; if n[0]==N { c1[0] = nil }
//               case c1[1] <- 0: n[1]++; if n[1]==N { c1[1] = nil }
//               }
//           }
//           wg.Done()
//       }()
//       go func() {
//           var n [4]int
//           c1 := c
//           for i := 0; i < 4*N; i++ {
//               select {
//               case <-c1[0]: n[0]++; if n[0]==N { c1[0] = nil }
//               case <-c1[1]: n[1]++; if n[1]==N { c1[1] = nil }
//               case <-c1[2]: n[2]++; if n[2]==N { c1[2] = nil }
//               case <-c1[3]: n[3]++; if n[3]==N { c1[3] = nil }
//               }
//           }
//           wg.Done()
//       }()
//       wg.Wait()
//   }
//
// We use Go's "short" N (1e4) so the test fits in a multi-run stress
// loop. Goish doesn't expose GOMAXPROCS — workers come up via
// sched_getaffinity() on bootstrap. WaitGroup is GS_DONE atomic.

#![no_std]
#![no_main]

use core::sync::atomic::{AtomicI64, AtomicUsize, Ordering};

use goish::gochan::chan;
use goish::runtime::sched::schedule;
use goish::{go, make, select, syscall, KB};

fn die(msg: &[u8]) -> ! {
    syscall::Write(syscall::STDERR, msg.as_ptr(), msg.len());
    syscall::Exit(1);
}

fn check(cond: bool, msg: &[u8]) {
    if !cond {
        die(msg);
    }
}

const N: i64 = 100_000; // Go's full N := int(1e5)

#[goish::main]
fn main() {
    // var c [4]chan int
    // c[0] = make(chan int)        c[1] = make(chan int)
    // c[2] = make(chan int, 2)     c[3] = make(chan int, 3)
    let c: [chan<i64>; 4] = [
        make!(chan i64),
        make!(chan i64),
        make!(chan i64, 2),
        make!(chan i64, 3),
    ];

    static SEND_TOTAL: AtomicI64 = AtomicI64::new(0);
    static RECV_TOTAL: AtomicI64 = AtomicI64::new(0);
    static GS_DONE: AtomicUsize = AtomicUsize::new(0);

    // for k := 0; k < 4; k++ { 4 senders + 4 receivers }
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

    // go func() { ... select-sender ... }()
    {
        let c1_init: [chan<i64>; 4] = [c[0].clone(), c[1].clone(), c[2].clone(), c[3].clone()];
        go!(stack(64 * KB), move || {
            let mut c1 = c1_init;
            let mut n = [0i64; 4];
            for _ in 0..(4 * N) {
                // case order verbatim from Go: 3, 2, 0, 1
                select! {
                    (c1[3]).Send(0) => {
                        n[3] += 1;
                        if n[3] == N { c1[3] = chan::nil(); }
                    },
                    (c1[2]).Send(0) => {
                        n[2] += 1;
                        if n[2] == N { c1[2] = chan::nil(); }
                    },
                    (c1[0]).Send(0) => {
                        n[0] += 1;
                        if n[0] == N { c1[0] = chan::nil(); }
                    },
                    (c1[1]).Send(0) => {
                        n[1] += 1;
                        if n[1] == N { c1[1] = chan::nil(); }
                    },
                }
                SEND_TOTAL.fetch_add(1, Ordering::Relaxed);
            }
            GS_DONE.fetch_add(1, Ordering::Relaxed);
        });
    }

    // go func() { ... select-receiver ... }()
    {
        let c1_init: [chan<i64>; 4] = [c[0].clone(), c[1].clone(), c[2].clone(), c[3].clone()];
        go!(stack(64 * KB), move || {
            let mut c1 = c1_init;
            let mut n = [0i64; 4];
            for _ in 0..(4 * N) {
                // case order verbatim from Go: 0, 1, 2, 3
                select! {
                    let _ = (c1[0]).Recv() => {
                        n[0] += 1;
                        if n[0] == N { c1[0] = chan::nil(); }
                    },
                    let _ = (c1[1]).Recv() => {
                        n[1] += 1;
                        if n[1] == N { c1[1] = chan::nil(); }
                    },
                    let _ = (c1[2]).Recv() => {
                        n[2] += 1;
                        if n[2] == N { c1[2] = chan::nil(); }
                    },
                    let _ = (c1[3]).Recv() => {
                        n[3] += 1;
                        if n[3] == N { c1[3] = chan::nil(); }
                    },
                }
                RECV_TOTAL.fetch_add(1, Ordering::Relaxed);
            }
            GS_DONE.fetch_add(1, Ordering::Relaxed);
        });
    }

    // wg.Wait()
    schedule();

    check(GS_DONE.load(Ordering::Relaxed) == 10, b"select_stress: not all 10 Gs done\n");
    check(SEND_TOTAL.load(Ordering::Relaxed) == 8 * N, b"select_stress: send total wrong\n");
    check(RECV_TOTAL.load(Ordering::Relaxed) == 8 * N, b"select_stress: recv total wrong\n");

    const OK: &[u8] = b"chan_select_stress: ok\n";
    syscall::Write(syscall::STDOUT, OK.as_ptr(), OK.len());
}
