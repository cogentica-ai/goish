// grow_smoke — exercise runtime::sched::maybe_grow and surface the
// monitoring counters. Demonstrates:
//
//   1. A goroutine on the default 2 KiB stack runs deep recursion
//      INSIDE maybe_grow without overflowing.
//   2. Counters reflect the lifecycle:
//        before grow:  live=0
//        during grow:  live>=1, peak>=1, bytes>0
//        after grow:   live=0  (returned home), peak preserved.
//   3. The same recursion called WITHOUT maybe_grow on a 2 KiB stack
//      would crash. We don't run that path — but the comparison is
//      what motivates the API.

#![no_std]
#![no_main]

extern crate alloc;
extern crate goish;

use core::sync::atomic::{AtomicUsize, Ordering};
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

fn print_snapshot(label: &[u8]) {
    print(label);
    print(b"  calls=");
    print_dec(sched::grow_calls() as u64);
    print(b" hits=");
    print_dec(sched::grow_hits() as u64);
    print(b" live=");
    print_dec(sched::grow_live() as u64);
    print(b" peak=");
    print_dec(sched::grow_peak_live() as u64);
    print(b" bytes_live=");
    print_dec(sched::grow_bytes_live() as u64);
    print(b"\n");
}

// Recursion that consumes meaningful stack per frame. Each frame
// holds a 64-byte buffer plus SysV frame overhead. In debug builds
// frames are fat (no local coalescing), so 60 frames easily exceed
// the 2 KiB goroutine stack while comfortably fitting in the 256 KiB
// growth region.
#[inline(never)]
fn deep_recurse(depth: usize, sum: u64) -> u64 {
    let _scratch: [u8; 64] = [0; 64];
    if depth == 0 {
        // Sample the counters from the deepest frame so we observe
        // live>=1 from inside the grown region.
        DEEPEST_LIVE.store(sched::grow_live(), Ordering::Release);
        DEEPEST_BYTES.store(sched::grow_bytes_live(), Ordering::Release);
        return sum.wrapping_add(_scratch[0] as u64);
    }
    deep_recurse(depth - 1, sum.wrapping_add(depth as u64))
}

static DEEPEST_LIVE: AtomicUsize = AtomicUsize::new(0);
static DEEPEST_BYTES: AtomicUsize = AtomicUsize::new(0);
static RESULT: AtomicUsize = AtomicUsize::new(0);
static DONE: AtomicUsize = AtomicUsize::new(0);

#[goish::main]
fn main() {
    print_snapshot(b"[before]");

    // Run on the default 2 KiB stack. Growth is mandatory or we'd
    // overflow.
    go!(stack(2 * KB), move || {
        let r = sched::maybe_grow(8 * KB, 256 * KB, || deep_recurse(60, 0));
        RESULT.store(r as usize, Ordering::Release);
        DONE.store(1, Ordering::Release);
    });

    // Yield until the goroutine completes.
    while DONE.load(Ordering::Acquire) == 0 {
        sched::Gosched();
    }

    print_snapshot(b"[after] ");

    print(b"deepest_live=");
    print_dec(DEEPEST_LIVE.load(Ordering::Acquire) as u64);
    print(b" deepest_bytes=");
    print_dec(DEEPEST_BYTES.load(Ordering::Acquire) as u64);
    print(b" result=");
    print_dec(RESULT.load(Ordering::Acquire) as u64);
    print(b"\n");

    // Hard invariants:
    //   - At least one grow occurred (depth=200 with 256B buffers
    //     can't fit in 2 KiB).
    //   - Live count is 0 again — the region was freed.
    //   - Peak live >= 1.
    if sched::grow_hits() < 1 {
        print(b"FAIL: expected at least one grow_hits\n");
        syscall::Exit(1);
    }
    if sched::grow_live() != 0 {
        print(b"FAIL: grow_live did not return to 0\n");
        syscall::Exit(1);
    }
    if sched::grow_peak_live() < 1 {
        print(b"FAIL: grow_peak_live should be >= 1\n");
        syscall::Exit(1);
    }
    if DEEPEST_LIVE.load(Ordering::Acquire) < 1 {
        print(b"FAIL: live count from inside grown region < 1\n");
        syscall::Exit(1);
    }

    print(b"grow_smoke: OK\n");
    syscall::Exit(0);
}
