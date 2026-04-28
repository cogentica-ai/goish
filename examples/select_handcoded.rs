// Smoke test: M16f-α step 4a — hand-coded select equivalent.
//
// Validates that the runtime helpers (__try_send / __try_recv /
// __register_send / __register_recv / __cancel_send / __cancel_recv,
// SelectCoord, Sudog<T>::new_*_select, cheaprandn, gopark) compose
// into a working select before any macro complexity stacks on top.
//
// Each test goroutine here writes the exact code that the upcoming
// `select!` macro will emit, so the macro becomes a mechanical
// translation rather than a leap of faith.
//
// Two cases per select:  case 0 = recv from ch_recv,
//                        case 1 = send 42 on ch_send.
//
//   1. Pass-1 hit on recv: ch_recv pre-buffered → case 0 fires
//      immediately, never parks.
//   2. Pass-1 hit on send: ch_send empty (cap=1) → case 1 fires
//      immediately.
//   3. Both cases blocked → select parks; a later goroutine
//      satisfies one case; pass-3 cancels the loser, dispatches.

#![no_std]
#![no_main]

use core::ptr::NonNull;
use core::sync::atomic::{AtomicI64, AtomicUsize, Ordering};

use goish::gochan::{chan, RegisterStatus, SelectCoord, Sudog};
use goish::runtime::rand::cheaprandn;
use goish::runtime::sched::{current_g, gopark, schedule, selparkcommit};
use goish::runtime::spin::{raw_lock, raw_unlock};
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

/// Outcome the select communicates back to the goroutine body.
#[derive(Copy, Clone)]
enum Outcome {
    /// Case 0 fired (recv); carries `(value, ok)`.
    Recv(i64, bool),
    /// Case 1 fired (send) — value already delivered.
    Send,
}

/// Hand-coded 2-case select:
///   case 0: let (v, ok) = ch_recv.Recv()
///   case 1: ch_send.Send(send_val)
///
/// Returns which case fired and (for recv) the received value/ok.
///
/// Mirrors the codegen the `select!` macro produces, including the
/// **multi-M-correct lock-order protocol** added in M16f-β
/// (cf. Go's `runtime/select.go:206-240`): all chan locks are
/// sorted by atom address and acquired up-front; pass-1 try and
/// pass-2 register both run under the held locks. Without this,
/// under M17b-γ work-stealing a counterpart G running on a worker
/// M can interleave between the selector's per-chan lock cycles —
/// publishing a sudog *after* pass-1 saw an empty queue but
/// *before* pass-2 registers — leaving both Gs parked on each
/// other.
///
/// The pre-γ revision of this file was annotated "Single-M
/// handcoded test", written for the M16f-α single-M scheduler;
/// M16f-β fixed the macro itself but the demo wasn't updated.
/// This rewrite catches the test up to the post-β macro shape so
/// it remains a faithful "what does the macro emit?" reference.
fn handcoded_select(ch_recv: &chan<i64>, ch_send: &chan<i64>, send_val: i64) -> Outcome {
    let mut send_val_holder: Option<i64> = Some(send_val);

    // Phase 1a: collect chan lock atoms, sort, dedup. Mirrors
    // `__sel_atoms` setup in src/select_macro.rs:350-380.
    let mut atoms: [*const core::sync::atomic::AtomicBool; 2] =
        [ch_recv.__lock_atom(), ch_send.__lock_atom()];
    if (atoms[0] as usize) > (atoms[1] as usize) {
        atoms.swap(0, 1);
    }
    let mut unique: usize = 1;
    if atoms[0] != atoms[1] {
        unique = 2;
    }
    for i in 0..unique {
        unsafe {
            raw_lock(atoms[i]);
        }
    }

    // Phase 1b: random poll order under held locks (matches Go's
    // runtime/select.go:191-194).
    const N: usize = 2;
    let mut order: [u8; N] = [0u8; N];
    for i in 0..N {
        let j = cheaprandn((i as u32) + 1) as usize;
        order[i] = order[j];
        order[j] = i as u8;
    }

    // Phase 2: pass-1 try under the held locks. Use *_locked
    // variants so we don't recursively re-lock.
    for k in 0..N {
        match order[k] {
            0 => {
                let s = unsafe { ch_recv.__state_unchecked() };
                if let Some((v, ok)) = chan::<i64>::__try_recv_locked(s) {
                    for i in 0..unique {
                        unsafe {
                            raw_unlock(atoms[i]);
                        }
                    }
                    return Outcome::Recv(v, ok);
                }
            }
            1 => {
                let v = send_val_holder.take().expect("send_val empty in pass-1");
                let s = unsafe { ch_send.__state_unchecked() };
                match chan::<i64>::__try_send_locked(s, v) {
                    Ok(()) => {
                        for i in 0..unique {
                            unsafe {
                                raw_unlock(atoms[i]);
                            }
                        }
                        return Outcome::Send;
                    }
                    Err(returned) => {
                        send_val_holder = Some(returned);
                    }
                }
            }
            _ => unreachable!(),
        }
    }

    // Phase 3: pass-2 register under the held locks, then release.
    let coord = SelectCoord::new();
    let coord_ptr = NonNull::from(&coord);
    let g = current_g().expect("handcoded_select: no current G");
    let send_v = send_val_holder
        .take()
        .expect("send_val_holder empty entering pass-2");
    let mut sd_recv = Sudog::<i64>::new_recv_select(g, coord_ptr);
    let mut sd_send = Sudog::<i64>::new_send_select(g, send_v, coord_ptr);

    {
        let s = unsafe { ch_recv.__state_unchecked() };
        let st = chan::<i64>::__register_recv_locked(s, &mut sd_recv);
        check(
            matches!(st, RegisterStatus::Registered),
            b"handcoded: __register_recv_locked unexpected status\n",
        );
    }
    {
        let s = unsafe { ch_send.__state_unchecked() };
        let st = chan::<i64>::__register_send_locked(s, &mut sd_send);
        check(
            matches!(st, RegisterStatus::Registered),
            b"handcoded: __register_send_locked unexpected status\n",
        );
    }

    // Release all chan locks before parking. The macro hands the
    // lock array to `selparkcommit` via M.waitlock so locks are
    // released *after* the G is detached from the runq. Until that
    // plumbing is in the public API, we release here — sudogs are
    // already published, so the wake-side counterpart finds them;
    // the wake's `goready` race with our own `gopark` is closed by
    // the standard sudog-claim CAS at the channel layer
    // (`try_claim_sudog`).
    for i in 0..unique {
        unsafe {
            raw_unlock(atoms[i]);
        }
    }
    gopark(selparkcommit, core::ptr::null());

    // Phase 4: pass-3 cleanup. Cancel each sudog; the one whose
    // cancel returns `false` (no longer queued) is the winner.
    let recv_was_loser = ch_recv.__cancel_recv(NonNull::from(&sd_recv));
    let send_was_loser = ch_send.__cancel_send(NonNull::from(&sd_send));

    match (recv_was_loser, send_was_loser) {
        (false, true) => {
            let v = sd_recv.value.take().unwrap_or(0);
            Outcome::Recv(v, sd_recv.success)
        }
        (true, false) => {
            check(sd_send.success, b"handcoded: send winner !success\n");
            Outcome::Send
        }
        other => {
            let _ = other;
            die(b"handcoded: pass-3 found 0 or 2 winners\n")
        }
    }
}

#[goish::main]
fn main() {
    test_pass1_recv_ready();
    test_pass1_send_ready();
    test_pass2_park_until_recv();
    test_pass2_park_until_send();
    test_many_iterations();

    const OK: &[u8] = b"select_handcoded: ok\n";
    syscall::Write(syscall::STDOUT, OK.as_ptr(), OK.len());
}

// ─── Test 1: pass-1 hit on recv (ch_recv pre-buffered) ────────────

fn test_pass1_recv_ready() {
    let ch_recv = make!(chan i64, 1);
    let ch_send = make!(chan i64, 0); // unbuffered; would-block on send

    static GOT: AtomicI64 = AtomicI64::new(-1);

    // Pre-fill ch_recv so pass-1 succeeds without parking.
    {
        let ch = ch_recv.clone();
        go!(move || {
            ch.Send(0xCAFE);
        });
    }
    {
        let cr = ch_recv.clone();
        let cs = ch_send.clone();
        go!(move || {
            match handcoded_select(&cr, &cs, 99) {
                Outcome::Recv(v, ok) => {
                    check(ok, b"test1: !ok\n");
                    GOT.store(v, Ordering::Relaxed);
                }
                Outcome::Send => die(b"test1: wrong case fired (Send)\n"),
            }
        });
    }
    schedule();
    check(GOT.load(Ordering::Relaxed) == 0xCAFE, b"test1: wrong recv value\n");
}

// ─── Test 2: pass-1 hit on send (ch_send buffered, has slot) ──────

fn test_pass1_send_ready() {
    let ch_recv = make!(chan i64, 0); // empty unbuffered → recv blocks
    let ch_send = make!(chan i64, 1); // buffered cap=1, has slot → send fits

    static FIRED: AtomicUsize = AtomicUsize::new(0);

    {
        let cr = ch_recv.clone();
        let cs = ch_send.clone();
        go!(move || {
            match handcoded_select(&cr, &cs, 7) {
                Outcome::Send => FIRED.store(1, Ordering::Relaxed),
                Outcome::Recv(_, _) => die(b"test2: wrong case fired (Recv)\n"),
            }
        });
    }
    schedule();
    check(FIRED.load(Ordering::Relaxed) == 1, b"test2: send didn't fire\n");
    // Confirm the value did land in the buffer.
    check(ch_send.Len() == 1, b"test2: send didn't deposit\n");
}

// ─── Test 3: park until a receiver arrives (case 1 fires) ─────────

fn test_pass2_park_until_send() {
    let ch_recv = make!(chan i64, 0); // empty
    let ch_send = make!(chan i64, 0); // unbuffered

    static FIRED: AtomicUsize = AtomicUsize::new(0);
    static SEND_GOT: AtomicI64 = AtomicI64::new(0);

    // Selector parks first; nothing is ready.
    {
        let cr = ch_recv.clone();
        let cs = ch_send.clone();
        go!(move || {
            match handcoded_select(&cr, &cs, 11) {
                Outcome::Send => FIRED.store(1, Ordering::Relaxed),
                Outcome::Recv(_, _) => FIRED.store(2, Ordering::Relaxed),
            }
        });
    }
    // Counterpart for case 1 (Send): a receiver on ch_send.
    {
        let ch = ch_send.clone();
        go!(move || {
            let (v, _) = ch.Recv();
            SEND_GOT.store(v, Ordering::Relaxed);
        });
    }
    schedule();
    check(FIRED.load(Ordering::Relaxed) == 1, b"test3: wrong case fired\n");
    check(SEND_GOT.load(Ordering::Relaxed) == 11, b"test3: recv missed value\n");
}

// ─── Test 4: park until a sender arrives (case 0 fires) ───────────

fn test_pass2_park_until_recv() {
    let ch_recv = make!(chan i64, 0);
    let ch_send = make!(chan i64, 0);

    static FIRED: AtomicUsize = AtomicUsize::new(0);
    static GOT: AtomicI64 = AtomicI64::new(0);

    {
        let cr = ch_recv.clone();
        let cs = ch_send.clone();
        go!(move || {
            match handcoded_select(&cr, &cs, 22) {
                Outcome::Recv(v, ok) => {
                    check(ok, b"test4: !ok\n");
                    GOT.store(v, Ordering::Relaxed);
                    FIRED.store(1, Ordering::Relaxed);
                }
                Outcome::Send => FIRED.store(2, Ordering::Relaxed),
            }
        });
    }
    // Counterpart for case 0 (Recv): a sender on ch_recv.
    {
        let ch = ch_recv.clone();
        go!(move || {
            ch.Send(0xBEEF);
        });
    }
    schedule();
    check(FIRED.load(Ordering::Relaxed) == 1, b"test4: wrong case fired\n");
    check(GOT.load(Ordering::Relaxed) == 0xBEEF, b"test4: wrong recv value\n");
}

// ─── Test 5: many iterations — both cases fire across runs ────────
//
// Spawns 100 selectors; for each, also spawns one counterpart that
// resolves either case 0 or case 1 (alternating). Verifies every
// selector resolves to the expected case and that the value flow
// is correct in both directions.

fn test_many_iterations() {
    const N: usize = 100;
    let ch_recv = make!(chan i64, 0);
    let ch_send = make!(chan i64, 0);

    static RECV_FIRES: AtomicUsize = AtomicUsize::new(0);
    static SEND_FIRES: AtomicUsize = AtomicUsize::new(0);
    static SEND_SUM: AtomicI64 = AtomicI64::new(0);
    static RECV_SUM: AtomicI64 = AtomicI64::new(0);

    for i in 0..N {
        let cr = ch_recv.clone();
        let cs = ch_send.clone();
        go!(move || {
            match handcoded_select(&cr, &cs, i as i64) {
                Outcome::Recv(v, _) => {
                    RECV_FIRES.fetch_add(1, Ordering::Relaxed);
                    RECV_SUM.fetch_add(v, Ordering::Relaxed);
                }
                Outcome::Send => {
                    SEND_FIRES.fetch_add(1, Ordering::Relaxed);
                }
            }
        });
        // Alternate: even i → resolve via send-counterpart (recv on
        // ch_send) so the selector's case 1 fires; odd i → resolve
        // via recv-counterpart (send on ch_recv) so case 0 fires.
        if i % 2 == 0 {
            let ch = ch_send.clone();
            go!(move || {
                let (v, _) = ch.Recv();
                SEND_SUM.fetch_add(v, Ordering::Relaxed);
            });
        } else {
            let ch = ch_recv.clone();
            let val = i as i64 + 1000;
            go!(move || {
                ch.Send(val);
            });
        }
    }
    schedule();

    let recv_fires = RECV_FIRES.load(Ordering::Relaxed);
    let send_fires = SEND_FIRES.load(Ordering::Relaxed);
    check(recv_fires + send_fires == N, b"test5: case-fire count mismatch\n");
    // Even count of N=100 → 50 sends + 50 recvs satisfied.
    check(send_fires == 50, b"test5: send_fires != 50\n");
    check(recv_fires == 50, b"test5: recv_fires != 50\n");

    // RECV_SUM is deterministic: 50 cr-senders deliver 50 distinct
    // odd-i values (1001..1099), each picked up by exactly one
    // selector's recv branch.
    let expected_recv: i64 = (0..N as i64).filter(|i| i % 2 == 1).map(|i| i + 1000).sum();
    check(
        RECV_SUM.load(Ordering::Relaxed) == expected_recv,
        b"test5: recv sum mismatch\n",
    );
    // SEND_SUM is NOT deterministic under M17b-γ work-stealing.
    // 100 selectors run in parallel across worker Ms; any 50 can
    // win their send branch depending on race timing. The original
    // `expected_send = 0+2+…+98 = 2450` assertion silently assumed
    // selectors i=0,2,…,98 fire send, which only held under the
    // single-M pre-γ scheduler. Go's runtime documents this at
    // proc.go:7042-7050:
    //
    //   "we introduce some randomness into scheduling decisions
    //    when running with the race detector. … breaking many
    //    poorly-written tests."
    //
    // The invariant we assert is the bound:
    // SEND_SUM ∈ [0, sum(0..N)] = [0, 4950].
    let send_sum = SEND_SUM.load(Ordering::Relaxed);
    let upper: i64 = (0..N as i64).sum();
    check(
        send_sum >= 0 && send_sum <= upper,
        b"test5: send sum out of range\n",
    );
}
