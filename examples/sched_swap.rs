// Smoke test: M16a — gobuf + asm context switch.
//
// Sets up two coroutines that ping-pong control with the main thread
// via `swap_context`. Each ping increments a shared counter; after
// the loop we verify the counter equals the number of round-trips.
// This exercises:
//
//   - First-time entry into a fresh coroutine (`make_context` setup
//     of the initial frame on a freshly mmap'd stack)
//   - Repeated symmetric swaps between contexts (each direction
//     restores the saved register set and resumes at the saved PC)
//   - Independence of the two coroutines' stacks
//
// No scheduler yet — main loop drives the swaps directly. M16b will
// hide this behind `go!()` and a run queue.

#![no_std]
#![no_main]

use core::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

use goish::runtime::sched::{make_context, swap_context, Gobuf, Stack};
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

// Shared counters — coroutines bump these to prove they ran.
static COUNTER_A: AtomicUsize = AtomicUsize::new(0);
static COUNTER_B: AtomicUsize = AtomicUsize::new(0);
static MAIN_RESUMES: AtomicUsize = AtomicUsize::new(0);

// Context handles. Set by main before swapping in.
static MAIN_CTX: AtomicU64 = AtomicU64::new(0);
static A_CTX: AtomicU64 = AtomicU64::new(0);
static B_CTX: AtomicU64 = AtomicU64::new(0);

const ROUNDS: usize = 1000;

extern "C" fn coroutine_a() -> ! {
    loop {
        COUNTER_A.fetch_add(1, Ordering::Relaxed);
        // Yield back to main.
        unsafe {
            swap_context(
                A_CTX.load(Ordering::Relaxed) as *mut Gobuf,
                MAIN_CTX.load(Ordering::Relaxed) as *const Gobuf,
            );
        }
    }
}

extern "C" fn coroutine_b() -> ! {
    loop {
        COUNTER_B.fetch_add(1, Ordering::Relaxed);
        unsafe {
            swap_context(
                B_CTX.load(Ordering::Relaxed) as *mut Gobuf,
                MAIN_CTX.load(Ordering::Relaxed) as *const Gobuf,
            );
        }
    }
}

#[goish::main]
fn main() {
    // ─── Allocate stacks for each coroutine ─────────────────────────
    let stack_a = Stack::new();
    let stack_b = Stack::new();
    check(stack_a.top() % 16 == 0, b"stack_a not 16-aligned\n");
    check(stack_b.top() % 16 == 0, b"stack_b not 16-aligned\n");

    // ─── Build per-coroutine Gobufs ─────────────────────────────────
    let mut main_buf = Gobuf::new();
    let mut a_buf = Gobuf::new();
    let mut b_buf = Gobuf::new();

    unsafe {
        make_context(&mut a_buf, stack_a.top(), coroutine_a);
        make_context(&mut b_buf, stack_b.top(), coroutine_b);
    }

    // Publish handles so the coroutines can swap back to us.
    MAIN_CTX.store(&mut main_buf as *mut _ as u64, Ordering::Relaxed);
    A_CTX.store(&mut a_buf as *mut _ as u64, Ordering::Relaxed);
    B_CTX.store(&mut b_buf as *mut _ as u64, Ordering::Relaxed);

    // ─── Single-shot swap into A, then back, then into B ───────────
    //
    // Verifies the very first context entry works for both
    // coroutines independently.
    unsafe {
        swap_context(&mut main_buf, &a_buf);
    }
    check(COUNTER_A.load(Ordering::Relaxed) == 1, b"A first entry\n");
    check(COUNTER_B.load(Ordering::Relaxed) == 0, b"B should not have run\n");

    unsafe {
        swap_context(&mut main_buf, &b_buf);
    }
    check(COUNTER_A.load(Ordering::Relaxed) == 1, b"A should not advance\n");
    check(COUNTER_B.load(Ordering::Relaxed) == 1, b"B first entry\n");

    // ─── Many rounds of ping-pong ──────────────────────────────────
    //
    // Each iteration: swap to A (which yields back), then to B
    // (which yields back). After ROUNDS iterations both counters
    // should equal 1 + ROUNDS (one for the first-entry above + one
    // per round here).
    for _ in 0..ROUNDS {
        unsafe {
            swap_context(&mut main_buf, &a_buf);
        }
        unsafe {
            swap_context(&mut main_buf, &b_buf);
        }
        MAIN_RESUMES.fetch_add(2, Ordering::Relaxed);
    }

    check(
        COUNTER_A.load(Ordering::Relaxed) == 1 + ROUNDS,
        b"A counter mismatch\n",
    );
    check(
        COUNTER_B.load(Ordering::Relaxed) == 1 + ROUNDS,
        b"B counter mismatch\n",
    );
    check(
        MAIN_RESUMES.load(Ordering::Relaxed) == 2 * ROUNDS,
        b"main resumes mismatch\n",
    );

    // ─── Stress the call/return path: many tight rounds ────────────
    //
    // 100k rounds — confirms the swap is fast enough to be useful
    // and stable over a long sequence. At 14 mov + ret per swap on
    // amd64 we expect ~10 ns/swap → 1 ms total. (We don't time it
    // here; just verify no corruption.)
    let before_a = COUNTER_A.load(Ordering::Relaxed);
    let before_b = COUNTER_B.load(Ordering::Relaxed);
    for _ in 0..100_000 {
        unsafe {
            swap_context(&mut main_buf, &a_buf);
            swap_context(&mut main_buf, &b_buf);
        }
    }
    check(
        COUNTER_A.load(Ordering::Relaxed) == before_a + 100_000,
        b"stress A counter\n",
    );
    check(
        COUNTER_B.load(Ordering::Relaxed) == before_b + 100_000,
        b"stress B counter\n",
    );

    const OK: &[u8] = b"sched_swap: ok\n";
    syscall::Write(syscall::STDOUT, OK.as_ptr(), OK.len());
}
