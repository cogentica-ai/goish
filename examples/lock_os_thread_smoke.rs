// lock_os_thread_smoke — runtime.LockOSThread survives yield and park/wake.

#![no_std]
#![no_main]
#![allow(non_snake_case)]

use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use goish::runtime;
use goish::runtime::sched::{current_g, Gosched};
use goish::syscall;
use goish::time;

const COMPETITORS: usize = 8;
static STOP: AtomicBool = AtomicBool::new(false);
static DONE: AtomicUsize = AtomicUsize::new(0);

fn fail(message: &[u8]) -> ! {
    syscall::Write(syscall::STDERR, message.as_ptr(), message.len());
    syscall::Exit(1);
}

fn check(condition: bool, message: &[u8]) {
    if !condition {
        fail(message);
    }
}

fn assertThread(want: i32) {
    check(syscall::Gettid() == want, b"locked goroutine migrated\n");
}

#[goish::main]
fn main() {
    for _ in 0..COMPETITORS {
        goish::go!(move || {
            while !STOP.load(Ordering::Acquire) {
                Gosched();
            }
            DONE.fetch_add(1, Ordering::AcqRel);
        });
    }

    let goroutine = current_g().unwrap_or_else(|| fail(b"missing current goroutine\n"));
    let originalThread = syscall::Gettid();

    runtime::LockOSThread();
    runtime::LockOSThread();
    unsafe {
        check(
            (*goroutine.as_ptr()).locked_m.load(Ordering::Acquire) != 0,
            b"LockOSThread did not publish an owner\n",
        );
        check(
            (*goroutine.as_ptr()).locked_m_count.load(Ordering::Acquire) == 2,
            b"nested LockOSThread count is wrong\n",
        );
    }

    // Voluntary yields republish the locked G. Other Ms must reject it and the
    // owner must recover it from the global queue.
    for _ in 0..256 {
        Gosched();
        assertThread(originalThread);
    }

    // Sleep parks the G and makes the timer/sysmon path wake it remotely. This
    // is the same park/wake shape used by Cogi's dedicated CUDA call lane.
    for _ in 0..8 {
        time::Sleep(time::Millisecond);
        assertThread(originalThread);
    }

    runtime::UnlockOSThread();
    unsafe {
        check(
            (*goroutine.as_ptr()).locked_m_count.load(Ordering::Acquire) == 1,
            b"first UnlockOSThread released a nested pin\n",
        );
        check(
            (*goroutine.as_ptr()).locked_m.load(Ordering::Acquire) != 0,
            b"first UnlockOSThread cleared the owner\n",
        );
    }
    for _ in 0..64 {
        Gosched();
        assertThread(originalThread);
    }

    runtime::UnlockOSThread();
    unsafe {
        check(
            (*goroutine.as_ptr()).locked_m_count.load(Ordering::Acquire) == 0,
            b"final UnlockOSThread left a nested count\n",
        );
        check(
            (*goroutine.as_ptr()).locked_m.load(Ordering::Acquire) == 0,
            b"final UnlockOSThread left an owner\n",
        );
    }

    // An unmatched unlock remains a no-op.
    runtime::UnlockOSThread();
    unsafe {
        check(
            (*goroutine.as_ptr()).locked_m_count.load(Ordering::Acquire) == 0
                && (*goroutine.as_ptr()).locked_m.load(Ordering::Acquire) == 0,
            b"unmatched UnlockOSThread changed state\n",
        );
    }

    STOP.store(true, Ordering::Release);
    while DONE.load(Ordering::Acquire) != COMPETITORS {
        Gosched();
    }
    syscall::Write(
        syscall::STDOUT,
        b"lock_os_thread_smoke: ok\n".as_ptr(),
        b"lock_os_thread_smoke: ok\n".len(),
    );
}
