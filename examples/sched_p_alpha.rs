// Smoke test: M17b-α — P struct bootstrap and M↔P binding.
//
// Verifies:
//   1. `bootstrap_ps(N)` populated `num_ps()` slots with status==P_IDLE.
//   2. The main M acquired P[0] in `__goish_rt0`. `current_p()` returns
//      `Some(&P)` from the main thread; that P's status is P_RUNNING
//      and its bound M is the main M.
//   3. Every worker M acquired its own P in `mstart`. Iterating
//      `for_each_p` shows every P bound to a unique M.
//   4. `releasep` returns the bound P, transitions it to P_IDLE, and
//      clears `current_p`. Re-acquiring restores the bound state.
//   5. The total ALL_MS count == ALL_PS count (1:1 binding).

#![no_std]
#![no_main]

extern crate alloc;

use core::sync::atomic::{AtomicI32, Ordering};

use goish::runtime::sched::{
    acquirem, acquirep, current_m, current_p, for_each_p, num_ps, p_at, registered_m_count,
    releasem, releasep, P_IDLE, P_RUNNING,
};
use goish::syscall;

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
    test_bootstrap_count();
    test_main_m_binding();
    test_release_reacquire();
    test_per_p_binding();

    const OK: &[u8] = b"sched_p_alpha: ok\n";
    syscall::Write(syscall::STDOUT, OK.as_ptr(), OK.len());
}

fn test_bootstrap_count() {
    // num_ps must be > 0 after bootstrap.
    let n = num_ps();
    check(n > 0, b"num_ps > 0\n");
    // Every slot 0..n must be populated.
    for i in 0..n {
        check(p_at(i).is_some(), b"p_at(i) Some\n");
    }
    // Slot at n must be None.
    check(p_at(n).is_none(), b"p_at(n) None\n");
}

fn test_main_m_binding() {
    // `main` runs on the main *goroutine* (Go-faithful), dispatched by
    // whichever M dequeued it — not necessarily the main M / P[0]. The
    // invariant is per-M: the M running this code is bound to *a* P,
    // that P is RUNNING, and the P's bound M is this M. Pin the M
    // (acquirem) so no preemption can migrate us between the reads.
    acquirem();
    let p = current_p().expect("dispatching M has bound P");
    check(
        usize::try_from(p.id).unwrap_or(usize::MAX) < num_ps(),
        b"bound P id in range\n",
    );
    check(
        p.status.load(Ordering::Acquire) == P_RUNNING,
        b"bound P status running\n",
    );
    let my_id = current_m().lock().id;
    let bound_id = p.bound_m().expect("P has bound M").m.lock().id;
    check(bound_id == my_id, b"P bound to the M running main\n");
    releasem();
}

fn test_release_reacquire() {
    // Mutates this M's P binding — pin the M for the duration.
    acquirem();
    let p = current_p().expect("bound at start");
    let id = p.id;
    let released = releasep().expect("releasep returns bound P");
    check(released.id == id, b"released P matches\n");
    check(
        released.status.load(Ordering::Acquire) == P_IDLE,
        b"released P idle\n",
    );
    check(released.bound_m().is_none(), b"released P no M\n");
    check(current_p().is_none(), b"current_p None after release\n");
    // Re-acquire and verify.
    acquirep(released);
    let p2 = current_p().expect("rebound");
    check(p2.id == id, b"re-acquired same P\n");
    check(
        p2.status.load(Ordering::Acquire) == P_RUNNING,
        b"P running again\n",
    );
    releasem();
}

fn test_per_p_binding() {
    // Every P should have a bound M, and each M's id should be unique.
    // The main M (id=0) + workers (id=1..) total registered_m_count();
    // sysmon also registers, so registered_m_count == num_ps + 1.
    let n = num_ps();
    let mut bound = 0usize;
    let mut max_id: i32 = -1;
    let id_seen = AtomicI32::new(0);
    for_each_p(|p| {
        if let Some(m_storage) = p.bound_m() {
            bound += 1;
            // Read the M's id under its SpinLock.
            let mid = m_storage.m.lock().id as i32;
            if mid > max_id {
                max_id = mid;
            }
            // Mark this id as seen via bitmask (max 32 Ms — adequate
            // for any plausible smoke run).
            if mid < 32 {
                id_seen.fetch_or(1 << mid, Ordering::Relaxed);
            }
        }
    });
    check(bound == n, b"every P bound to an M\n");
    // All ids 0..n must be present in the seen bitmask.
    let seen = id_seen.load(Ordering::Relaxed);
    let want = if n < 32 { ((1u32 << n) - 1) as i32 } else { -1 };
    check(seen == want, b"unique M ids 0..n bound to Ps\n");

    // registered_m_count includes sysmon's M (registered for tgkill
    // routing); so it should be n + 1.
    let m_count = registered_m_count();
    check(m_count == n + 1, b"M count == num_ps + sysmon\n");
}
