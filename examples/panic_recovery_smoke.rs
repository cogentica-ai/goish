// panic_recovery_smoke — verify that a RECOVERED panic in a goroutine
// doesn't kill the process. Spawns N goroutines via WaitGroup; one
// panics and recovers, the rest complete normally; the program exits 0.
//
// The `recover!()` is load-bearing. An UNRECOVERED panic ends the
// process with status 2, as it ends a Go program (issue #6) — this
// smoke is about the scheduler reclaiming a panicked G and the others
// carrying on, not about surviving an unhandled panic.
// panic_fatal_ref_smoke covers the unrecovered case, in subprocesses
// where an exit status can actually be asserted.
//
// What this proves:
//   - `g_entry` installs the panic_recover gobuf
//   - `#[panic_handler]` detects user-G panic and `gogo`s to recovery
//   - `on_g_panic_aborted` chains to `goexit` so the G is reclaimed
//   - the panicked G still cannot resume its abandoned Rust stack, so
//     SURVIVOR_COUNT — not the WG counter — is what says "did we
//     complete". `WaitGroup::Go` defers its `Done()` the way Go writes
//     it, so the counter balances on both paths and no compensating
//     `Done()` is needed (one would now be a decrement too many).
//   - G_PANIC_COUNT is exactly 1 after the run

#![no_std]
#![no_main]

extern crate goish;

use core::sync::atomic::{AtomicI64, Ordering};

use goish::runtime::sched;
use goish::sync::WaitGroup;
use goish::{defer, go, recover, syscall, KB};

fn print(s: &[u8]) {
    syscall::Write(syscall::STDOUT, s.as_ptr(), s.len());
}

fn print_dec(mut n: u64) {
    let mut buf = [0u8; 24];
    let mut i = buf.len();
    if n == 0 {
        i -= 1;
        buf[i] = b'0';
    } else {
        while n > 0 {
            i -= 1;
            buf[i] = b'0' + (n % 10) as u8;
            n /= 10;
        }
    }
    syscall::Write(syscall::STDOUT, buf[i..].as_ptr(), buf.len() - i);
}

const N_GOROUTINES: i64 = 10;

#[goish::main]
fn main() {
    static SURVIVOR_COUNT: AtomicI64 = AtomicI64::new(0);

    go!(|| {
        let wg = WaitGroup::new();

        for i in 0..N_GOROUTINES {
            wg.GoStack(32 * KB, move || {
                if i == 4 {
                    // One specific goroutine panics. The others
                    // should still complete and increment SURVIVOR_COUNT.
                    //
                    // It recovers explicitly: an unrecovered panic is
                    // fatal now (issue #6), and what this smoke is
                    // about is the scheduler continuing, which only a
                    // recovered panic entitles it to do.
                    defer! { let _ = recover!(); }
                    panic!("intentional panic from goroutine #4");
                }
                SURVIVOR_COUNT.fetch_add(1, Ordering::AcqRel);
            });
        }

        // Wait for everyone — including the panicked one. Its Done()
        // runs on the panic cleanup walk, because `WaitGroup::Go`
        // defers it exactly as Go does (sync/waitgroup.go:238). The
        // manual compensating `wg.Done()` that used to sit here would
        // now be a third decrement against two Adds.
        wg.Wait();

        // wg.Wait() unblocks once the WG counter hits 0, which can
        // happen *before* the panicked G's `on_g_panic_aborted`
        // finishes incrementing G_PANIC_COUNT (the panic-recovery
        // path runs in parallel on its M). Spin until the counter
        // reaches 1.
        //
        // The bound used to be 10_000, which is plenty on an idle
        // machine and not enough on a loaded CI runner: the recovery
        // path is doing real work on another M, and this loop only
        // yields. When it ran out the smoke printed panics=0 and
        // exited 1, so a scheduling race read as a broken runtime. The
        // bound is now large enough that exhausting it means the
        // counter is never coming, which is the failure worth
        // reporting — and the loop still terminates rather than
        // hanging, so that failure is a FAIL and not a timeout.
        for _ in 0..20_000_000 {
            if sched::G_PANIC_COUNT.load(Ordering::Acquire) >= 1 {
                break;
            }
            sched::Gosched();
        }

        let survivors = SURVIVOR_COUNT.load(Ordering::Acquire);
        let panics = sched::G_PANIC_COUNT.load(Ordering::Acquire);

        print(b"survivors=");
        print_dec(survivors as u64);
        print(b" panics=");
        print_dec(panics);
        print(b"\n");

        if survivors == N_GOROUTINES - 1 && panics == 1 {
            print(b"PASS\n");
        } else {
            print(b"FAIL\n");
            syscall::Exit(1);
        }
    });

    sched::schedule();
}
