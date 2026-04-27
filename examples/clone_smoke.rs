// Smoke test: M17a-α — Clone syscall + child trampoline.
//
// Spawns one child OS thread via raw clone(2), the child runs a Rust
// `extern "C" fn() -> !` entry on its own mmap'd stack, increments a
// shared AtomicUsize (visible because CLONE_VM shares the address
// space), writes its tid to stdout, and exits the THREAD only (not
// the process — uses syscall::ExitThread, not Exit).
//
// Parent busy-waits on the shared counter, prints OK, exits. We have
// no futex/joins yet; busy-wait is fine for a smoke test that the
// thread actually ran. M17c will replace the busy-wait with futex
// park.
//
// Verifies:
//   1. Clone returns a positive tid (>0) to parent.
//   2. Child runs to completion (counter incremented to 1).
//   3. Child's tid is distinct from parent's (gettid before/after).
//   4. Process exits cleanly with the parent's exit code (no zombie
//      from the thread — CLONE_THREAD makes them part of the same
//      tgid, so kernel cleans up).

#![no_std]
#![no_main]

use core::sync::atomic::{AtomicI32, AtomicUsize, Ordering};

use goish::syscall;

static CHILD_RAN: AtomicUsize = AtomicUsize::new(0);
static CHILD_TID: AtomicI32 = AtomicI32::new(0);
// For test 2: count of children that ran their entry function. Each
// of 4 children increments this; main verifies count == 4.
static MULTI_RAN: AtomicUsize = AtomicUsize::new(0);

extern "C" fn child_entry() -> ! {
    // Read our tid (different from parent's because each thread has
    // its own kernel tid, even though they share the tgid).
    let tid = syscall::Gettid();
    CHILD_TID.store(tid, Ordering::Release);
    CHILD_RAN.store(1, Ordering::Release);
    syscall::ExitThread(0);
}

extern "C" fn multi_child_entry() -> ! {
    MULTI_RAN.fetch_add(1, Ordering::AcqRel);
    syscall::ExitThread(0);
}

fn die(msg: &[u8]) -> ! {
    syscall::Write(syscall::STDERR, msg.as_ptr(), msg.len());
    syscall::Exit(1);
}

fn check(cond: bool, msg: &[u8]) {
    if !cond {
        die(msg);
    }
}

const STACK_SIZE: usize = 64 * 1024;

#[goish::main]
fn main() {
    let parent_tid = syscall::Gettid();
    check(parent_tid > 0, b"parent tid invalid\n");

    // mmap a 64 KiB stack for the child.
    let stack = syscall::Mmap(
        core::ptr::null_mut(),
        STACK_SIZE,
        syscall::PROT_READ | syscall::PROT_WRITE,
        syscall::MAP_PRIVATE | syscall::MAP_ANONYMOUS,
        -1,
        0,
    );
    check(stack != syscall::MAP_FAILED, b"mmap child stack failed\n");

    // Clone needs the stack TOP. Stack grows downward.
    let stack_top = unsafe { stack.add(STACK_SIZE) };

    let child_tid = unsafe { syscall::Clone(syscall::CLONE_THREAD_FLAGS, stack_top, child_entry, 0) };
    check(child_tid > 0, b"clone returned non-positive tid\n");
    check(child_tid as i32 != parent_tid, b"child tid == parent tid\n");

    // Busy-wait for the child to publish CHILD_RAN. Bounded by a
    // generous spin count — under any sane scheduler the child runs
    // within microseconds. If we hit the limit we fail the test.
    let mut spins: u64 = 0;
    while CHILD_RAN.load(Ordering::Acquire) == 0 {
        core::hint::spin_loop();
        spins += 1;
        if spins > 100_000_000 {
            die(b"child never ran (timed out)\n");
        }
    }

    let observed_child_tid = CHILD_TID.load(Ordering::Acquire);
    check(
        observed_child_tid == child_tid as i32,
        b"child tid mismatch: clone return vs gettid()\n",
    );

    // Don't munmap — the child may still be in the kernel's exit
    // path on its stack. With CLONE_THREAD the kernel cleans up
    // automatically when the thread group exits. Leak the stack;
    // process exit reclaims it.

    // ─── Test 2: spawn 4 children in sequence ────────────────────
    //
    // Verifies the clone path is robust under repeat: each child gets
    // its own stack, runs to completion, increments the shared count.
    const N: usize = 4;
    for _ in 0..N {
        let s = syscall::Mmap(
            core::ptr::null_mut(),
            STACK_SIZE,
            syscall::PROT_READ | syscall::PROT_WRITE,
            syscall::MAP_PRIVATE | syscall::MAP_ANONYMOUS,
            -1,
            0,
        );
        check(s != syscall::MAP_FAILED, b"multi: mmap failed\n");
        let top = unsafe { s.add(STACK_SIZE) };
        let tid = unsafe { syscall::Clone(syscall::CLONE_THREAD_FLAGS, top, multi_child_entry, 0) };
        check(tid > 0, b"multi: clone failed\n");
    }
    // Wait for all 4 to publish.
    let mut spins: u64 = 0;
    while MULTI_RAN.load(Ordering::Acquire) < N {
        core::hint::spin_loop();
        spins += 1;
        if spins > 1_000_000_000 {
            die(b"multi: not all children ran (timed out)\n");
        }
    }

    const OK: &[u8] = b"clone_smoke: ok\n";
    syscall::Write(syscall::STDOUT, OK.as_ptr(), OK.len());
}
