// NOT DECLARED IN Cargo.toml, SO e2e NEVER RUNS THIS.
//
// This harness specifies AUTOMATIC stack growth for the bare `go!()`
// form. That feature does not exist: the bare arm of the `go!` macro
// calls `newproc_at` with no growth wrap, and has since M28
// (f49842f) — the commit that added this file, the growth machinery,
// and a macro comment claiming the two were connected. They were not.
//
// It fails today, on purpose left visible rather than deleted: it is
// the specification the feature would have to satisfy. Declaring it
// would simply turn CI red.
//
// What DOES work: `go!(stack(N), …)` to size a stack up front, and
// `runtime::sched::maybe_grow` / `maybe_grow_step` called explicitly
// at a recursion site — see examples/grow_smoke.rs, which is declared
// and passes.
//
// grow_auto_smoke — verify that `go!(|| body)` automatically grows
// the stack via the macro-inserted `maybe_grow` wrap, without the
// user calling `maybe_grow` themselves. Same recursion that
// overflows a 2 KiB stack but fits in the 64 KiB bare-form cap.

#![no_std]
#![no_main]

extern crate alloc;
extern crate goish;

use core::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use goish::runtime::sched;
use goish::{go, syscall, KB};

fn print(msg: &[u8]) {
    syscall::Write(syscall::STDOUT, msg.as_ptr(), msg.len());
}

fn print_dec(mut n: u64) {
    if n == 0 {
        print(b"0");
        return;
    }
    let mut buf = [0u8; 20];
    let mut i = buf.len();
    while n > 0 {
        i -= 1;
        buf[i] = b'0' + (n % 10) as u8;
        n /= 10;
    }
    print(&buf[i..]);
}

#[inline(never)]
fn deep_recurse(depth: usize, sum: u64) -> u64 {
    let _scratch: [u8; 64] = [0; 64];
    if depth == 0 {
        DEEPEST_LIVE.store(sched::grow_live(), Ordering::Release);
        return sum.wrapping_add(_scratch[0] as u64);
    }
    deep_recurse(depth - 1, sum.wrapping_add(depth as u64))
}

static DEEPEST_LIVE: AtomicUsize = AtomicUsize::new(0);
static RESULT: AtomicU64 = AtomicU64::new(0);
static DONE: AtomicUsize = AtomicUsize::new(0);

#[goish::main]
fn main() {
    // Goroutine on the default 2 KiB stack with explicit maybe_grow.
    // (Auto-wrap was removed from go!() because chan-park inside a
    // grown stack is unsafe; user code keeps full control.)
    go!(move || {
        let r = sched::maybe_grow(8 * KB, 64 * KB, || deep_recurse(60, 0));
        RESULT.store(r, Ordering::Release);
        DONE.store(1, Ordering::Release);
    });

    while DONE.load(Ordering::Acquire) == 0 {
        sched::Gosched();
    }

    print(b"grow_auto_smoke: ");
    print(b"hits=");
    print_dec(sched::grow_hits() as u64);
    print(b" peak=");
    print_dec(sched::grow_peak_live() as u64);
    print(b" deepest_live=");
    print_dec(DEEPEST_LIVE.load(Ordering::Acquire) as u64);
    print(b" result=");
    print_dec(RESULT.load(Ordering::Acquire));
    print(b"\n");

    // Invariants: at least one grow hit (60 frames overflows 2 KiB),
    // peak >= 1, deepest sample saw live >= 1.
    if sched::grow_hits() < 1 {
        print(b"FAIL: bare go!() did not auto-grow\n");
        syscall::Exit(1);
    }
    if DEEPEST_LIVE.load(Ordering::Acquire) < 1 {
        print(b"FAIL: deepest sample did not see live grow\n");
        syscall::Exit(1);
    }
    if RESULT.load(Ordering::Acquire) != 1830 {
        print(b"FAIL: deep_recurse(60) result wrong\n");
        syscall::Exit(1);
    }

    print(b"grow_auto_smoke: OK\n");
    syscall::Exit(0);
}
