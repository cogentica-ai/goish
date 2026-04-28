// Smoke test: M17b-γ — work-stealing across Ps.
//
// Verifies that goroutines spawned exclusively from the main M (and
// thus all queued onto P[0]'s runq) get distributed across worker
// Ms via the steal pass in `find_runnable`.
//
// Setup:
//   - Spawn N short CPU-bound goroutines from main M (all land on
//     P[0]'s local runq).
//   - Each goroutine bumps a per-M counter (indexed by `m.id`).
//   - With γ wired into `find_runnable`, idle worker Ms scan all
//     other Ps via `runqsteal` and pull half-batches until the work
//     drains.
//
// Assertions:
//   1. Total counter == N (no Gs lost).
//   2. With > 1 P, at least 2 different Ms ran goroutines (work
//      crossed P boundaries via steal).
//   3. With > 1 P, STEAL_HITS > 0 (the steal path actually fired).

#![no_std]
#![no_main]

extern crate alloc;

use core::sync::atomic::{AtomicU32, Ordering};

use goish::runtime::sched::{
    current_m, num_ps, schedule, MAX_PS, STEAL_HITS, STEAL_PASSES,
};
use goish::{go, syscall};

fn die(msg: &[u8]) -> ! {
    syscall::Write(syscall::STDERR, msg.as_ptr(), msg.len());
    syscall::Exit(1);
}

fn check(cond: bool, msg: &[u8]) {
    if !cond {
        die(msg);
    }
}

// Pick N below LOCAL_RUNQ_SIZE (256) so the spawn loop fills only
// P[0]'s local runq — never overflowing to global. Forces workers
// to actually *steal* rather than pulling from a global drain that
// `find_runnable` would prefer to the steal pass.
const N_GOROUTINES: u32 = 200;

// Per-M execution counts. Sized to MAX_PS+8 since `m.id` is bounded
// by the worker count (≤ num_ps + sysmon).
const SLOTS: usize = MAX_PS + 8;
static PER_M: [AtomicU32; SLOTS] = {
    const Z: AtomicU32 = AtomicU32::new(0);
    [Z; SLOTS]
};

#[goish::main]
fn main() {
    for _ in 0..N_GOROUTINES {
        go!(move || {
            let my_m_id = current_m().lock().id as usize;
            let slot = if my_m_id < SLOTS { my_m_id } else { 0 };
            PER_M[slot].fetch_add(1, Ordering::Relaxed);

            // CPU spin sized to give workers wall time to wake from
            // futex park and enter the steal pass before main M
            // drains its own runq. Without this the main M is too
            // fast and dispatches every G itself.
            let mut acc: u64 = 0;
            for k in 0..200_000u64 {
                acc = acc.wrapping_add(k);
                core::hint::black_box(&acc);
            }
        });
    }
    schedule();

    let mut total: u32 = 0;
    let mut ms_with_work: u32 = 0;
    for slot in 0..SLOTS {
        let n = PER_M[slot].load(Ordering::Relaxed);
        total += n;
        if n > 0 {
            ms_with_work += 1;
        }
    }
    let nps = num_ps() as u32;
    let hits = STEAL_HITS.load(Ordering::Relaxed);
    let passes = STEAL_PASSES.load(Ordering::Relaxed);

    print_diag(b"num_ps=", nps as u64);
    print_diag(b" total=", total as u64);
    print_diag(b" ms_with_work=", ms_with_work as u64);
    print_diag(b" steal_hits=", hits as u64);
    print_diag(b" steal_passes=", passes as u64);
    syscall::Write(syscall::STDOUT, b"\n".as_ptr(), 1);

    check(total == N_GOROUTINES, b"gamma: total != N\n");

    if nps > 1 {
        check(
            ms_with_work >= 2,
            b"gamma: only one M ran any Gs (steal didn't distribute)\n",
        );
        check(hits > 0, b"gamma: STEAL_HITS == 0 with > 1 P\n");
        check(passes > 0, b"gamma: STEAL_PASSES == 0\n");
    }

    const OK: &[u8] = b"sched_p_gamma: ok\n";
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
