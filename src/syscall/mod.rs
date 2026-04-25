// syscall — Go's `syscall` package, ported. Raw Linux x86-64 syscalls
// via inline assembly. No libc.
//
//   Go                                   goish
//   ──────────────────────────────────   ──────────────────────────────────
//   syscall.Write(fd, buf)               syscall::Write(fd, buf.as_ptr(), buf.len())
//   syscall.Exit(0)                      syscall::Exit(0)
//
// Calling convention (SysV / Linux x86-64 syscall):
//   rax = syscall number
//   rdi, rsi, rdx, r10, r8, r9 = args 1..6
//   rax = return (negative = -errno)
//   clobbers: rcx, r11, plus memory.

use core::arch::asm;

// ─── syscall numbers (asm-generic / x86_64) ────────────────────────────
pub const SYS_READ: usize = 0;
pub const SYS_WRITE: usize = 1;
pub const SYS_OPEN: usize = 2;
pub const SYS_CLOSE: usize = 3;
pub const SYS_MMAP: usize = 9;
pub const SYS_MUNMAP: usize = 11;
pub const SYS_EXIT_GROUP: usize = 231;

// ─── standard fds ──────────────────────────────────────────────────────
pub const STDIN: i32 = 0;
pub const STDOUT: i32 = 1;
pub const STDERR: i32 = 2;

// ─── mmap flags / prot bits ────────────────────────────────────────────
pub const PROT_NONE: i32 = 0;
pub const PROT_READ: i32 = 1;
pub const PROT_WRITE: i32 = 2;
pub const PROT_EXEC: i32 = 4;

pub const MAP_PRIVATE: i32 = 0x02;
pub const MAP_ANONYMOUS: i32 = 0x20;

/// Sentinel returned by `mmap(2)` on failure (`(void*) -1`).
pub const MAP_FAILED: *mut u8 = !0usize as *mut u8;

// ─── raw syscall wrappers (x86-64) ─────────────────────────────────────

/// 1-argument syscall.
#[inline]
pub unsafe fn syscall1(n: usize, a1: usize) -> isize {
    let ret: isize;
    asm!(
        "syscall",
        inlateout("rax") n => ret,
        in("rdi") a1,
        out("rcx") _,
        out("r11") _,
        options(nostack, preserves_flags),
    );
    ret
}

/// 3-argument syscall (write, read, open).
#[inline]
pub unsafe fn syscall3(n: usize, a1: usize, a2: usize, a3: usize) -> isize {
    let ret: isize;
    asm!(
        "syscall",
        inlateout("rax") n => ret,
        in("rdi") a1,
        in("rsi") a2,
        in("rdx") a3,
        out("rcx") _,
        out("r11") _,
        options(nostack, preserves_flags),
    );
    ret
}

/// 6-argument syscall (mmap).
#[inline]
pub unsafe fn syscall6(
    n: usize,
    a1: usize,
    a2: usize,
    a3: usize,
    a4: usize,
    a5: usize,
    a6: usize,
) -> isize {
    let ret: isize;
    asm!(
        "syscall",
        inlateout("rax") n => ret,
        in("rdi") a1,
        in("rsi") a2,
        in("rdx") a3,
        in("r10") a4,
        in("r8")  a5,
        in("r9")  a6,
        out("rcx") _,
        out("r11") _,
        options(nostack, preserves_flags),
    );
    ret
}

// ─── Go-shaped public API ──────────────────────────────────────────────

/// Write up to `n` bytes from `p` to file descriptor `fd`.
/// Returns the raw syscall result: number of bytes written on success,
/// or a negative `-errno` on error (matching Go's `syscall.Syscall`).
#[allow(non_snake_case)]
pub fn Write(fd: i32, p: *const u8, n: usize) -> isize {
    unsafe { syscall3(SYS_WRITE, fd as usize, p as usize, n) }
}

/// Read up to `n` bytes from `fd` into `p`.
#[allow(non_snake_case)]
pub fn Read(fd: i32, p: *mut u8, n: usize) -> isize {
    unsafe { syscall3(SYS_READ, fd as usize, p as usize, n) }
}

/// Terminate the entire process. Mirrors `syscall.Exit` in Go (which
/// invokes `exit_group` on Linux).
#[allow(non_snake_case)]
pub fn Exit(code: i32) -> ! {
    unsafe {
        syscall1(SYS_EXIT_GROUP, code as usize);
        // exit_group never returns; tell the optimizer.
        core::hint::unreachable_unchecked()
    }
}

/// `mmap(2)` — map anonymous memory pages. Returns `MAP_FAILED` on error.
///
/// Goish uses this as the sole source of heap memory: `runtime::alloc`
/// hands out chunks of mmap'd regions, never calling into libc malloc.
#[allow(non_snake_case)]
pub fn Mmap(addr: *mut u8, length: usize, prot: i32, flags: i32, fd: i32, offset: i64) -> *mut u8 {
    let ret = unsafe {
        syscall6(
            SYS_MMAP,
            addr as usize,
            length,
            prot as usize,
            flags as usize,
            fd as usize,        // -1 for anonymous; kernel ignores
            offset as usize,
        )
    };
    // Return is either the address (positive) or -errno (negative). Cast
    // back to a pointer; callers compare against MAP_FAILED.
    ret as *mut u8
}

/// `munmap(2)` — release a previously mapped region.
#[allow(non_snake_case)]
pub fn Munmap(addr: *mut u8, length: usize) -> isize {
    unsafe { syscall3(SYS_MUNMAP, addr as usize, length, 0) }
}
