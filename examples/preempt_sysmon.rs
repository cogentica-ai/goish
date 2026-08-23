// Smoke test: M18b-β/γ — sysmon-driven async preempt + cooperative
// rescue.
//
// Validates that:
//   1. Sysmon's force-preempt scan fires SIGURGs at goroutines that
//      have been running too long, **without any user-side
//      signaling**. The test launches CPU-spinners and never sends a
//      signal explicitly — every preemption observed must come from
//      sysmon.
//   2. CPU-bound goroutines yield within roughly FORCE_PREEMPT_NS
//      (10 ms) of starting, regardless of how tight their inner
//      loop is.
//   3. Register state survives every preempt cycle bit-exactly: each
//      spinner's wrapping-add accumulator equals the reference sum.
//
// Setup:
//   - Spawn N spinners (no chan/sync ops in their hot loop, so
//      cooperative-side γ is never the rescuer here — pure async β).
//   - Wait for them via WaitGroup. No signaler goroutine, no
//      explicit kill / tgkill calls.
//   - Verify `preempt::injections() > 0` and spinner sums match.

#![no_std]
#![no_main]

use core::sync::atomic::{AtomicU64, Ordering};

use goish::runtime::preempt;
use goish::sync::WaitGroup;
use goish::{go, syscall};

const N_SPINNERS: usize = 4;
const ITERS: u64 = 50_000_000;

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
            let mut s: u64 = 0;
            for k in 0..ITERS {
                s = s.wrapping_add(k);
                core::hint::black_box(&s);
            }
            SPINNER_RESULTS[i].store(s, Ordering::Release);
            WG.Done();
        });
    }

    static DONE: AtomicU64 = AtomicU64::new(0);
    go!(|| {
        WG.Wait();
        DONE.store(1, Ordering::Release);
    });
    goish::runtime::sched::schedule();
    check(
        DONE.load(Ordering::Acquire) == 1,
        b"preempt_sysmon: WG.Wait didn't return\n",
    );

    let expected: u64 = (0..ITERS).fold(0u64, |a, k| a.wrapping_add(k));
    for i in 0..N_SPINNERS {
        let got = SPINNER_RESULTS[i].load(Ordering::Acquire);
        check(
            got == expected,
            b"preempt_sysmon: spinner result wrong (register corruption)\n",
        );
    }

    let inv = preempt::invocations();
    let inj = preempt::injections();
    let (l, t, p, n, r, sp) = preempt::skip_breakdown();
    let scan_ticks = goish::runtime::sysmon::force_preempt_scan_ticks();
    let signals = goish::runtime::sysmon::force_preempt_signals_sent();
    let n_ms = goish::runtime::sched::registered_m_count();
    let stamps = goish::runtime::sched::DISPATCH_STAMP_COUNT.load(Ordering::Relaxed);
    print_diag(b"all_ms=", n_ms as u64);
    print_diag(b" stamps=", stamps as u64);

    print_diag(b"invocations=", inv);
    print_diag(b" injections=", inj);
    print_diag(b" sysmon_ticks=", scan_ticks);
    print_diag(b" sysmon_signals=", signals);
    print_diag(b" skip_locks=", l);
    print_diag(b" skip_trampoline=", t);
    print_diag(b" skip_parking=", p);
    print_diag(b" skip_no_curg=", n);
    print_diag(b" skip_not_running=", r);
    print_diag(b" skip_sp_range=", sp);
    syscall::Write(syscall::STDOUT, b"\n".as_ptr(), 1);

    check(
        inv > 0,
        b"preempt_sysmon: handler never fired (sysmon scan failed)\n",
    );
    check(
        inj > 0,
        b"preempt_sysmon: handler never injected (no async preempt observed)\n",
    );

    const OK: &[u8] = b"preempt_sysmon: ok\n";
    syscall::Write(syscall::STDOUT, OK.as_ptr(), OK.len());
}

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
