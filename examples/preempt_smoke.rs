// Smoke test: M18b-α phase C — full async preempt via SIGURG.
//
// Validates that:
//   1. The SIGURG handler fires (`invocations() > 0`).
//   2. The handler injects at least once when SIGURG arrives on a
//      worker M running a CPU-bound goroutine (`injections() > 0`).
//   3. Each preempted goroutine resumes at the correct PC with its
//      register state bit-identical — verified by checking that
//      every spinner's accumulated sum equals
//      `(0..ITERS).fold(0, |a,k| a.wrapping_add(k))` exactly. Any
//      drift means register corruption (the trampoline mis-restored
//      a GPR/XMM across the swap-and-yield cycle) or PC corruption
//      (the trampoline jumped to the wrong location).
//
// Setup:
//   - Spawn N CPU-spinner goroutines that increment a per-G atomic
//     counter ITERS times each.
//   - Spawn one signaler goroutine that loops calling
//     `Kill(getpid, SIGURG)` with a tiny `time.Sleep` between bursts.
//     Linux's `kill(2)` typically delivers to the calling thread
//     when eligible, so when the signaler runs on a worker M the
//     SIGURG handler runs on that worker — which has `curg = Some`
//     and `status = Running` (the signaler itself, or whatever
//     spinner the M was running before the signaler resumed).
//     Sending from a goroutine routes signals to workers; sending
//     from main would route to the supervisor thread (curg = None,
//     handler skips).
//   - WaitGroup for the spinners; assert each finished.
//   - Print and verify counters.

#![no_std]
#![no_main]

use core::sync::atomic::{AtomicU64, Ordering};

use goish::runtime::preempt;
use goish::sync::WaitGroup;
use goish::time;
use goish::{go, syscall};

const N_SPINNERS: usize = 4;
const ITERS: u64 = 50_000_000;
const SIGURG_BURST: usize = 500;
const SIGURG_INTERVAL_MS: i64 = 1;

static SPINNER_RESULTS: [AtomicU64; N_SPINNERS] = [
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
];

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
    static WG: WaitGroup = WaitGroup::new();
    WG.Add(N_SPINNERS as i64);

    for i in 0..N_SPINNERS {
        go!(move || {
            // Tight CPU loop — no chan/sync/syscall ops, so m.locks
            // stays 0 throughout. Goroutine body runs entirely in
            // user code, the only place phase B should bump
            // PREEMPT_DECISIONS.
            let mut s: u64 = 0;
            for k in 0..ITERS {
                s = s.wrapping_add(k);
                core::hint::black_box(&s);
            }
            SPINNER_RESULTS[i].store(s, Ordering::Release);
            WG.Done();
        });
    }

    // Fire SIGURG bursts from a signaler GOROUTINE (not from main).
    // This way the signal-emitting thread is one of the worker Ms,
    // not the supervisor — when the kernel routes the signal back to
    // the calling thread, the handler runs on a worker M whose
    // `curg` is Some(...).
    static SIGNAL_DONE: AtomicU64 = AtomicU64::new(0);
    go!(|| {
        let pid = syscall::Getpid();
        for _ in 0..SIGURG_BURST {
            syscall::Kill(pid, syscall::SIGURG);
            time::Sleep(time::Millisecond * (SIGURG_INTERVAL_MS as i64));
        }
        SIGNAL_DONE.store(1, Ordering::Release);
    });

    // Wait for spinners to finish from the main M as a goroutine,
    // because main M itself is not a goroutine and Wait would
    // deadlock if called from non-G context (gopark requires
    // current_g != None).
    static DONE: AtomicU64 = AtomicU64::new(0);
    go!(|| {
        WG.Wait();
        DONE.store(1, Ordering::Release);
    });
    goish::runtime::sched::schedule();
    check(
        DONE.load(Ordering::Acquire) == 1,
        b"preempt_smoke: WG.Wait didn't return\n",
    );
    check(
        SIGNAL_DONE.load(Ordering::Acquire) == 1,
        b"preempt_smoke: signaler didn't finish\n",
    );

    // Verify spinners produced correct results — phase C must
    // preserve register state bit-exactly across each preempt event.
    // Any wrong sum means the trampoline corrupted GPR/XMM/RFLAGS.
    let expected: u64 = (0..ITERS).fold(0u64, |a, k| a.wrapping_add(k));
    for i in 0..N_SPINNERS {
        let got = SPINNER_RESULTS[i].load(Ordering::Acquire);
        check(
            got == expected,
            b"preempt_smoke: spinner result wrong (register corruption)\n",
        );
    }

    // Verify the handler fired and actually injected at least once.
    let inv = preempt::invocations();
    let inj = preempt::injections();
    let (l, t, p, n, r, sp) = preempt::skip_breakdown();

    print_diag(b"invocations=", inv);
    print_diag(b" injections=", inj);
    print_diag(b" skip_locks=", l);
    print_diag(b" skip_trampoline=", t);
    print_diag(b" skip_parking=", p);
    print_diag(b" skip_no_curg=", n);
    print_diag(b" skip_not_running=", r);
    print_diag(b" skip_sp_range=", sp);
    syscall::Write(syscall::STDOUT, b"\n".as_ptr(), 1);

    check(inv > 0, b"preempt_smoke: handler never fired\n");
    check(
        inj > 0,
        b"preempt_smoke: handler never injected (no async preempt observed)\n",
    );

    const OK: &[u8] = b"preempt_smoke: ok\n";
    syscall::Write(syscall::STDOUT, OK.as_ptr(), OK.len());
}

/// Tiny u64-to-decimal formatter for diagnostic output.
fn print_diag(label: &[u8], n: u64) {
    syscall::Write(syscall::STDOUT, label.as_ptr(), label.len());
    let mut buf = [0u8; 24];
    let mut i = buf.len();
    if n == 0 {
        i -= 1;
        buf[i] = b'0';
    } else {
        let mut x = n;
        while x > 0 {
            i -= 1;
            buf[i] = b'0' + ((x % 10) as u8);
            x /= 10;
        }
    }
    syscall::Write(syscall::STDOUT, buf[i..].as_ptr(), buf.len() - i);
}
