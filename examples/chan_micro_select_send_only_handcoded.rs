// Hand-coded equivalent of chan_micro_select_send_only — same workload
// (1 sender selecting on 3 send-cases + 3 plain receivers), but the
// 3-send select is open-coded against the runtime helpers instead of
// being emitted by the `select!` macro.
//
// **Why**: isolates whether the residual ~4% failure rate of
// chan_micro_select_send_only lives in the macro's expansion or in the
// underlying chan / scheduler / preempt layer. If this version shows
// the same rate, the macro is innocent; if substantially lower, the
// macro emits something subtle.
//
// The protocol mirrors what `src/select_macro.rs:507-700` expands to:
// lock all chan atoms (sorted, deduped) → pass-1 try_send_locked in
// random poll order → pass-2 register sudogs under held locks →
// populate G.select_wait → gopark(selparkcommit) (which releases the
// locks during the park transition) → pass-3 cancel sudogs to
// identify the winner. Nil chans are filtered before the lock-order
// pass, matching the macro's nil handling.

#![no_std]
#![no_main]

use core::ptr::NonNull;
use core::sync::atomic::{AtomicBool, AtomicI64, AtomicUsize, Ordering};

use goish::gochan::{chan, RegisterStatus, SelectCoord, Sudog};
use goish::runtime::rand::cheaprandn;
use goish::runtime::sched::{
    current_g, gopark, schedule, selparkcommit, SELECT_WAIT_MAX,
};
use goish::runtime::spin::raw_lock;
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

const N: i64 = 100_000;

/// Hand-coded 3-send select. Returns the index of the case that
/// fired (0, 1, or 2). Sends `val` on whichever non-nil chan wins.
///
/// Nil chans contribute no sudog and never fire — matching Go's
/// `case (nil_chan).Send(v)` semantics.
///
/// This is the post-β protocol: locks released by `selparkcommit`
/// during the park transition (not by the parker pre-park), so a
/// remote-M waker sees a consistent (sudog published, lock held)
/// frame at the linearization point.
fn select_3send(
    c0: &chan<i64>,
    c1: &chan<i64>,
    c2: &chan<i64>,
    val: i64,
) -> usize {
    // ── Phase 1a: collect non-nil case data ──
    //
    // Mirrors the macro's per-case `if !chan.is_nil() { … }` filter.
    let chans: [&chan<i64>; 3] = [c0, c1, c2];
    let mut active_idx = [0u8; 3];
    let mut active_atoms: [*const AtomicBool; 3] = [core::ptr::null(); 3];
    let mut active_n: usize = 0;
    for i in 0..3 {
        if !chans[i].is_nil() {
            active_idx[active_n] = i as u8;
            active_atoms[active_n] = chans[i].__lock_atom();
            active_n += 1;
        }
    }
    if active_n == 0 {
        // All-nil select: would block forever per Go semantics. Not
        // expected in this test (one of the chans is always non-nil
        // until the entire 3*N iteration completes).
        die(b"select_3send: all-nil select\n");
    }

    // ── Phase 1b: sort atoms by address, dedup. ──
    //
    // Matches the macro's `__sel_atoms` setup. With ≤3 entries a
    // simple insertion sort is fine.
    let mut sorted_atoms: [*const AtomicBool; 3] = [core::ptr::null(); 3];
    sorted_atoms[..active_n].copy_from_slice(&active_atoms[..active_n]);
    for i in 1..active_n {
        let mut j = i;
        while j > 0 && (sorted_atoms[j - 1] as usize) > (sorted_atoms[j] as usize) {
            sorted_atoms.swap(j - 1, j);
            j -= 1;
        }
    }
    let mut unique_atoms: [*const AtomicBool; 3] = [core::ptr::null(); 3];
    let mut unique_n: usize = 0;
    for i in 0..active_n {
        if i == 0 || sorted_atoms[i] != sorted_atoms[i - 1] {
            unique_atoms[unique_n] = sorted_atoms[i];
            unique_n += 1;
        }
    }
    for i in 0..unique_n {
        unsafe {
            raw_lock(unique_atoms[i]);
        }
    }

    // ── Phase 2: random poll order, pass-1 try_send_locked. ──
    let mut order: [u8; 3] = [0, 1, 2];
    for i in 0..active_n {
        let j = cheaprandn((i as u32) + 1) as usize;
        order[i] = order[j];
        order[j] = i as u8;
    }

    let mut send_holder: Option<i64> = Some(val);
    for k in 0..active_n {
        let case_pos = order[k] as usize;
        let case_idx = active_idx[case_pos] as usize;
        let v = send_holder.take().expect("send_holder empty in pass-1");
        let s = unsafe { chans[case_idx].__state_unchecked() };
        match chan::<i64>::__try_send_locked(s, v) {
            Ok(()) => {
                // Pass-1 hit: release all locks and return.
                for i in 0..unique_n {
                    unsafe {
                        goish::runtime::spin::raw_unlock(unique_atoms[i]);
                    }
                }
                return case_idx;
            }
            Err(returned) => {
                send_holder = Some(returned);
            }
        }
    }

    // ── Phase 3: pass-2 register sudogs under held locks. ──
    let coord = SelectCoord::new();
    let coord_ptr = NonNull::from(&coord);
    let g = current_g().expect("select_3send: no current G");
    let send_v = send_holder
        .take()
        .expect("send_holder empty entering pass-2");

    // Stack-allocated sudogs, one per active case. We need them
    // live across gopark + pass-3, so they live on this fn's frame.
    let mut sd0 = Sudog::<i64>::new_send_select(g, send_v, coord_ptr);
    let mut sd1 = Sudog::<i64>::new_send_select(g, send_v, coord_ptr);
    let mut sd2 = Sudog::<i64>::new_send_select(g, send_v, coord_ptr);

    {
        let mut k: usize = 0;
        while k < active_n {
            let case_idx = active_idx[k] as usize;
            let s = unsafe { chans[case_idx].__state_unchecked() };
            let sg: &mut Sudog<i64> = match case_idx {
                0 => &mut sd0,
                1 => &mut sd1,
                2 => &mut sd2,
                _ => unreachable!(),
            };
            let st = chan::<i64>::__register_send_locked(s, sg);
            check(
                matches!(st, RegisterStatus::Registered),
                b"select_3send: __register_send_locked unexpected status\n",
            );
            k += 1;
        }
    }

    // ── Phase 4: populate G.select_wait, gopark via selparkcommit. ──
    //
    // selparkcommit walks G.select_wait (deduped+sorted atoms) and
    // releases each lock during the park transition. This is the
    // load-bearing step that differs from `select_handcoded.rs`'s
    // older "release-before-park" variant — under M17b multi-M,
    // releasing pre-park opens a window where a waker can claim the
    // sudog before the parker's gobuf is committed.
    unsafe {
        let g_mut = &mut *g.as_ptr();
        let take_n = if unique_n > SELECT_WAIT_MAX {
            SELECT_WAIT_MAX
        } else {
            unique_n
        };
        for i in 0..take_n {
            g_mut.select_wait[i] = unique_atoms[i];
        }
        g_mut.select_wait_len = take_n as u8;
    }

    gopark(selparkcommit, core::ptr::null());

    // ── Phase 5: pass-3 — cancel each sudog; the one not removed is
    // the winner.
    let mut winners: [bool; 3] = [false; 3];
    {
        let mut k: usize = 0;
        while k < active_n {
            let case_idx = active_idx[k] as usize;
            let sg_ptr: NonNull<Sudog<i64>> = match case_idx {
                0 => NonNull::from(&sd0),
                1 => NonNull::from(&sd1),
                2 => NonNull::from(&sd2),
                _ => unreachable!(),
            };
            // __cancel_send returns true if the sudog WAS removed
            // (loser). false → already removed by the waker = winner.
            let was_loser = chans[case_idx].__cancel_send(sg_ptr);
            winners[case_idx] = !was_loser;
            k += 1;
        }
    }

    // Exactly one winner expected.
    let mut winner: i32 = -1;
    let mut wcount = 0;
    for i in 0..3 {
        if winners[i] {
            winner = i as i32;
            wcount += 1;
        }
    }
    if wcount != 1 {
        die(b"select_3send: pass-3 winner count != 1\n");
    }
    let widx = winner as usize;
    // For send winner, success is propagated via the sudog. We
    // ignore the value (sender-only).
    let win_success = match widx {
        0 => sd0.success,
        1 => sd1.success,
        2 => sd2.success,
        _ => unreachable!(),
    };
    check(win_success, b"select_3send: winner !success\n");
    widx
}

#[goish::main]
fn main() {
    let c: [chan<i64>; 3] = [make!(chan i64), make!(chan i64), make!(chan i64)];

    static SEND_TOTAL: AtomicI64 = AtomicI64::new(0);
    static RECV_TOTAL: AtomicI64 = AtomicI64::new(0);
    static GS_DONE: AtomicUsize = AtomicUsize::new(0);

    {
        let c1_init: [chan<i64>; 3] = [c[0].clone(), c[1].clone(), c[2].clone()];
        go!(move || {
            let mut c1 = c1_init;
            let mut n = [0i64; 3];
            for _ in 0..(3 * N) {
                let widx = select_3send(&c1[0], &c1[1], &c1[2], 0);
                n[widx] += 1;
                if n[widx] == N {
                    c1[widx] = chan::nil();
                }
                SEND_TOTAL.fetch_add(1, Ordering::Relaxed);
            }
            GS_DONE.fetch_add(1, Ordering::Relaxed);
        });
    }

    for k in 0..3 {
        let ck = c[k].clone();
        go!(move || {
            for _ in 0..N {
                let _ = ck.Recv();
                RECV_TOTAL.fetch_add(1, Ordering::Relaxed);
            }
            GS_DONE.fetch_add(1, Ordering::Relaxed);
        });
    }

    schedule();

    check(
        GS_DONE.load(Ordering::Relaxed) == 4,
        b"chan_micro_select_send_only_handcoded: not all done\n",
    );
    check(
        SEND_TOTAL.load(Ordering::Relaxed) == 3 * N,
        b"chan_micro_select_send_only_handcoded: send total wrong\n",
    );
    check(
        RECV_TOTAL.load(Ordering::Relaxed) == 3 * N,
        b"chan_micro_select_send_only_handcoded: recv total wrong\n",
    );

    const OK: &[u8] = b"chan_micro_select_send_only_handcoded: ok\n";
    syscall::Write(syscall::STDOUT, OK.as_ptr(), OK.len());
}
