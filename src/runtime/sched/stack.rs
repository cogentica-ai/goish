// runtime::sched::stack — per-goroutine stack allocation.
//
// Each goroutine needs its own stack — context-switching to a
// coroutine means setting RSP to that coroutine's stack region. We
// allocate stacks via raw `mmap` rather than going through mheap,
// for two reasons:
//
//   - **Independence.** mheap's arena is shared with user
//     allocations; carving stacks out of the same pool would
//     conflate two very different lifetime patterns. Each goroutine
//     stack is born with the goroutine and lives until it exits;
//     mheap allocations come and go on a different timeline.
//
//   - **Optional guard pages.** A separately-mmap'd stack lets us
//     leave a `PROT_NONE` guard page below it later (M18b) so stack
//     overflow faults rather than silently corrupts adjacent memory.
//     For M16a we don't add the guard page — a missing guard makes
//     overflows hard to diagnose, but adding it is purely additive
//     code.
//
// Stack size: fixed 64 KiB per stack, no growth. Go uses 2 KiB
// initial + segmented stack growth (`morestack`); we don't have the
// compiler hooks for that yet, so we go static. 64 KiB comfortably
// holds the call depths smoke tests will reach without bloating
// memory for the common case.

use crate::syscall;

/// Per-G stack size in bytes. 64 KiB = 16 pages.
pub const STACK_SIZE: usize = 64 * 1024;

/// A goroutine stack. Owns its mmap region and unmaps on drop.
pub struct Stack {
    base: *mut u8,
    size: usize,
}

unsafe impl Send for Stack {}

impl Stack {
    /// Allocate a fresh stack. Returns a `Stack` whose `top()` is
    /// page-aligned (and therefore 16-byte aligned, suitable for
    /// `make_context`).
    pub fn new() -> Self {
        let p = syscall::Mmap(
            core::ptr::null_mut(),
            STACK_SIZE,
            syscall::PROT_READ | syscall::PROT_WRITE,
            syscall::MAP_PRIVATE | syscall::MAP_ANONYMOUS,
            -1,
            0,
        );
        if p == syscall::MAP_FAILED {
            const MSG: &[u8] = b"goish: sched: stack mmap failed\n";
            syscall::Write(syscall::STDERR, MSG.as_ptr(), MSG.len());
            syscall::Exit(2);
        }
        Stack {
            base: p,
            size: STACK_SIZE,
        }
    }

    /// Address one byte past the end of the stack. The stack grows
    /// down from this point. `make_context` writes its initial
    /// frame at `top() - 16`.
    pub fn top(&self) -> usize {
        (self.base as usize) + self.size
    }

    /// Address of the lowest byte of the stack (where overflow would
    /// land if it happens — useful for adding a guard page later).
    pub fn base(&self) -> usize {
        self.base as usize
    }
}

impl Drop for Stack {
    fn drop(&mut self) {
        syscall::Munmap(self.base, self.size);
    }
}
