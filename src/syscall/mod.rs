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
pub const SYS_CLONE: usize = 56;
pub const SYS_EXIT: usize = 60; // per-thread exit (vs SYS_EXIT_GROUP)
pub const SYS_SCHED_YIELD: usize = 24;
pub const SYS_NANOSLEEP: usize = 35;
pub const SYS_ARCH_PRCTL: usize = 158;
pub const SYS_GETTID: usize = 186;
pub const SYS_CLOCK_GETTIME: usize = 228;
pub const SYS_EXIT_GROUP: usize = 231;
pub const SYS_SCHED_GETAFFINITY: usize = 204;
pub const SYS_FUTEX: usize = 202;
pub const SYS_RT_SIGACTION: usize = 13;
pub const SYS_RT_SIGRETURN: usize = 15;
pub const SYS_GETPID: usize = 39;
pub const SYS_KILL: usize = 62;
pub const SYS_TGKILL: usize = 234;
pub const SYS_SIGALTSTACK: usize = 131;

// Signal numbers (Linux). Mirror /usr/include/asm-generic/signal.h.
pub const SIGHUP: i32 = 1;
pub const SIGINT: i32 = 2;
pub const SIGQUIT: i32 = 3;
pub const SIGILL: i32 = 4;
pub const SIGTRAP: i32 = 5;
pub const SIGABRT: i32 = 6;
pub const SIGFPE: i32 = 8;
pub const SIGKILL: i32 = 9;
pub const SIGUSR1: i32 = 10;
pub const SIGSEGV: i32 = 11;
pub const SIGUSR2: i32 = 12;
pub const SIGPIPE: i32 = 13;
pub const SIGALRM: i32 = 14;
pub const SIGTERM: i32 = 15;
pub const SIGCHLD: i32 = 17;
pub const SIGURG: i32 = 23;
pub const SIGXCPU: i32 = 24;
pub const SIGXFSZ: i32 = 25;

// sigaction flags. SA_RESTORER tells the kernel to use the
// userspace-provided sigreturn trampoline (mandatory on amd64
// since glibc's removal — without it, signal handler return
// crashes with "default action" because the kernel has no stub).
pub const SA_RESTORER: u64 = 0x04000000;
pub const SA_SIGINFO: u64 = 0x00000004;
pub const SA_RESTART: u64 = 0x10000000;
/// `SA_ONSTACK` — handler runs on the alt stack registered via
/// `sigaltstack(2)`. Mirrors the role of Go's signal-handler flag at
/// runtime/signal_unix.go (where `setSignalstackSP` + `signalstack`
/// + SA_ONSTACK ensure the handler's frame and the kernel's
/// rt_sigframe live on the per-M `gsignal` stack rather than the
/// user goroutine's stack).
pub const SA_ONSTACK: u64 = 0x08000000;

// futex(2) ops. PRIVATE flag (128) is set when only intra-process
// threads share the address — Linux can use a faster wait-list.
// Mirrors Go runtime/os_linux.go:55-58.
pub const FUTEX_PRIVATE_FLAG: i32 = 128;
pub const FUTEX_WAIT_PRIVATE: i32 = 0 | FUTEX_PRIVATE_FLAG;
pub const FUTEX_WAKE_PRIVATE: i32 = 1 | FUTEX_PRIVATE_FLAG;

// ─── arch_prctl(2) op codes (M17a-β2) ──────────────────────────────────
//
// `arch_prctl(2)` is x86-only; we use it to plant a per-thread fs base
// so `mov %fs:0, _` reads back a pointer to the calling M.
pub const ARCH_SET_FS: i32 = 0x1002;
pub const ARCH_GET_FS: i32 = 0x1003;

// ─── clone(2) flags (M17a) ─────────────────────────────────────────────
//
// Mirrors Go 1.25 runtime/os_linux.go:133-150. We use the same
// composite flags Go uses for `newm`/`newosproc` minus CLONE_SETTLS
// (added by M17a-β when per-M TLS lands).
pub const CLONE_VM: u64 = 0x100;
pub const CLONE_FS: u64 = 0x200;
pub const CLONE_FILES: u64 = 0x400;
pub const CLONE_SIGHAND: u64 = 0x800;
pub const CLONE_THREAD: u64 = 0x10000;
pub const CLONE_SYSVSEM: u64 = 0x40000;
pub const CLONE_SETTLS: u64 = 0x80000;

/// Default flags for spawning a worker M (no TLS yet — α only).
pub const CLONE_THREAD_FLAGS: u64 =
    CLONE_VM | CLONE_FS | CLONE_FILES | CLONE_SIGHAND | CLONE_SYSVSEM | CLONE_THREAD;

// ─── clock_gettime clock IDs ───────────────────────────────────────────
pub const CLOCK_REALTIME: i32 = 0;
pub const CLOCK_MONOTONIC: i32 = 1;

/// `struct timespec` — matches Linux's two-field representation.
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct Timespec {
    pub tv_sec: i64,
    pub tv_nsec: i64,
}

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

/// Open flags. Subset of `<fcntl.h>`.
pub const O_RDONLY: i32 = 0;
pub const O_CLOEXEC: i32 = 0o2_000_000;

/// `open(2)` — open a file. `path` must be a NUL-terminated C string.
/// Returns the new fd on success, or a negative `-errno` on error.
#[allow(non_snake_case)]
pub fn Open(path: *const u8, flags: i32, mode: i32) -> i32 {
    unsafe { syscall3(SYS_OPEN, path as usize, flags as usize, mode as usize) as i32 }
}

/// `close(2)` — close a file descriptor.
#[allow(non_snake_case)]
pub fn Close(fd: i32) -> i32 {
    unsafe { syscall1(SYS_CLOSE, fd as usize) as i32 }
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

/// `clock_gettime(2)` — read the value of `clk` into `tp`. Returns 0 on
/// success or `-errno`.
#[allow(non_snake_case)]
pub fn ClockGettime(clk: i32, tp: *mut Timespec) -> isize {
    unsafe { syscall2(SYS_CLOCK_GETTIME, clk as usize, tp as usize) }
}

/// `nanosleep(2)` — sleep for the requested duration. `rem` may be null.
/// Does not retry on `EINTR` for v1; callers needing precise sleep over
/// signal interruptions should re-call manually.
#[allow(non_snake_case)]
pub fn Nanosleep(req: *const Timespec, rem: *mut Timespec) -> isize {
    unsafe { syscall2(SYS_NANOSLEEP, req as usize, rem as usize) }
}

/// 2-argument syscall — used by `clock_gettime` / `nanosleep`.
#[inline]
pub unsafe fn syscall2(n: usize, a1: usize, a2: usize) -> isize {
    let ret: isize;
    asm!(
        "syscall",
        inlateout("rax") n => ret,
        in("rdi") a1,
        in("rsi") a2,
        out("rcx") _,
        out("r11") _,
        options(nostack, preserves_flags),
    );
    ret
}

/// `gettid(2)` — kernel thread id. Linux makes each clone(2)'d thread
/// have its own tid (vs the shared tgid). Used as the M's identity
/// (`m.procid`) in M17a-β.
#[allow(non_snake_case)]
pub fn Gettid() -> i32 {
    unsafe { syscall1(SYS_GETTID, 0) as i32 }
}

/// `getpid(2)` — process id (tgid).
#[allow(non_snake_case)]
pub fn Getpid() -> i32 {
    unsafe { syscall1(SYS_GETPID, 0) as i32 }
}

/// `kill(2)` — send a signal to a process. Use `Getpid()` for the
/// target to send a signal to ourselves (the test pattern).
#[allow(non_snake_case)]
pub fn Kill(pid: i32, sig: i32) -> isize {
    unsafe { syscall2(SYS_KILL, pid as usize, sig as usize) }
}

/// `tgkill(2)` — send a signal to a specific thread.
#[allow(non_snake_case)]
pub fn Tgkill(tgid: i32, tid: i32, sig: i32) -> isize {
    unsafe { syscall3(SYS_TGKILL, tgid as usize, tid as usize, sig as usize) }
}

/// Linux kernel `struct sigaction` layout (amd64). Note: this is
/// the **kernel** layout, not glibc's — they differ. Kernel layout:
///
///   sa_handler   (8 bytes)  — handler fn pointer
///   sa_flags     (8 bytes)
///   sa_restorer  (8 bytes)  — trampoline that issues rt_sigreturn
///   sa_mask      (8 bytes)  — kernel sigset_t (single u64)
///
/// Mirrors Go runtime/defs_linux_amd64.go:`type sigactiont`.
#[repr(C)]
#[derive(Copy, Clone, Default)]
pub struct Sigaction {
    pub sa_handler: usize,
    pub sa_flags: u64,
    pub sa_restorer: usize,
    pub sa_mask: u64,
}

/// `rt_sigaction(2)` — install or query a signal handler. The
/// last argument is `sizeof(sa_mask)` which the kernel uses to
/// distinguish 32-bit from 64-bit sigsets; for amd64 this is 8.
///
/// **Safety**: `new` and `old` must point to valid `Sigaction`s
/// or be null. The handler in `new.sa_handler` must be an
/// `extern "C" fn(i32)` for the simple case (no SA_SIGINFO).
#[allow(non_snake_case)]
pub unsafe fn RtSigaction(
    sig: i32,
    new: *const Sigaction,
    old: *mut Sigaction,
) -> isize {
    syscall6(
        SYS_RT_SIGACTION,
        sig as usize,
        new as usize,
        old as usize,
        8, // sizeof(kernel sigset_t) on amd64
        0,
        0,
    )
}

/// Linux kernel `stack_t` layout (amd64). Used as the argument to
/// `sigaltstack(2)`. Mirrors `runtime/defs_linux_amd64.go:type stackt`.
///
///   ss_sp     (8 bytes)  — base of the alt stack (lowest address).
///   ss_flags  (4 bytes)  — 0, SS_DISABLE (2), or SS_ONSTACK (1).
///   _pad      (4 bytes)
///   ss_size   (8 bytes)  — size of the alt stack in bytes.
#[repr(C)]
#[derive(Copy, Clone, Default)]
pub struct SigaltstackT {
    pub ss_sp: usize,
    pub ss_flags: i32,
    pub _pad0: i32,
    pub ss_size: usize,
}

/// `sigaltstack(2)` — register/inspect the calling thread's alt
/// signal stack. With `SA_ONSTACK` set on a sigaction, the kernel
/// switches RSP to the alt stack before delivering the signal,
/// so the rt_sigframe and handler frame live there rather than on
/// the user goroutine's stack. Goish uses this so the M18b-δ.3
/// handler can write a resume-PC slot directly to the user G stack
/// at `[ucontext.RSP - 144]` without colliding with the kernel's
/// sigframe.
///
/// **Safety**: `new` and `old` must point to valid `SigaltstackT`s
/// or be null. The alt stack memory must remain mapped and writable
/// for as long as it is the registered alt stack.
#[allow(non_snake_case)]
pub unsafe fn Sigaltstack(new: *const SigaltstackT, old: *mut SigaltstackT) -> isize {
    syscall2(SYS_SIGALTSTACK, new as usize, old as usize)
}

/// Sigreturn trampoline. The kernel jumps here when a signal
/// handler returns; this issues `rt_sigreturn(2)` which restores
/// the pre-signal context. Mandatory on amd64 (kernel has no
/// default stub since glibc dropped libgcc-style restorers).
///
/// Naked asm: just two instructions, no prologue/epilogue.
/// Mirrors Go runtime `sigreturn__sigaction`
/// (sys_linux_amd64.s:470).
#[unsafe(naked)]
#[allow(non_snake_case)]
pub unsafe extern "C" fn SigreturnTrampoline() {
    core::arch::naked_asm!(
        "movq $15, %rax",   // SYS_rt_sigreturn
        "syscall",
        // Should never return; if it does, INT3.
        "int3",
        options(att_syntax),
    )
}

/// `sched_yield(2)` — voluntary yield to other runnable threads.
/// Used by idle Ms after a bounded spin when their run queue is
/// empty (M17a-γ). M17c will replace this with a futex wait.
#[allow(non_snake_case)]
pub fn SchedYield() -> isize {
    unsafe { syscall1(SYS_SCHED_YIELD, 0) }
}

/// `futex(2)` — Linux address-based wait/wake primitive.
///
/// `op = FUTEX_WAIT_PRIVATE`: if `*addr == val`, sleep until woken
/// (or `ts` elapses; `ts == null` means forever). Returns 0 on
/// wake, `-EAGAIN` if `*addr != val`, `-ETIMEDOUT` on timeout.
///
/// `op = FUTEX_WAKE_PRIVATE`: wake up to `val` threads sleeping on
/// `addr`. Returns the number woken (0 if none).
///
/// Mirrors Go's `runtime.futex` (os_linux.go:44, asm at
/// sys_linux_amd64.s for SYS_FUTEX = 202). `addr2` and `val3` are
/// only used by REQUEUE/CMP_REQUEUE; we always pass null/0.
#[allow(non_snake_case)]
pub fn Futex(
    addr: *const u32,
    op: i32,
    val: u32,
    ts: *const Timespec,
) -> isize {
    unsafe {
        syscall6(
            SYS_FUTEX,
            addr as usize,
            op as usize,
            val as usize,
            ts as usize,
            0, // addr2
            0, // val3
        )
    }
}

/// `sched_getaffinity(2)` — fetch the calling thread's CPU affinity
/// mask. `pid = 0` means "this thread". `mask` points at a buffer of
/// at least `cpusetsize` bytes (must be a multiple of `sizeof(long)`,
/// i.e. 8 on amd64); on success the kernel returns the number of
/// bytes written, on failure a negative `-errno`.
///
/// Used by `runtime::sched::num_cpus()` to size the worker M pool —
/// the GOMAXPROCS default. Mirrors Go's `sched_getaffinity` (asm
/// definition at runtime/sys_linux_amd64.s:658) used by
/// `runtime.getCPUCount` (os_linux.go:104).
#[allow(non_snake_case)]
pub fn SchedGetaffinity(pid: i32, cpusetsize: usize, mask: *mut u8) -> isize {
    unsafe { syscall3(SYS_SCHED_GETAFFINITY, pid as usize, cpusetsize, mask as usize) }
}

/// `arch_prctl(code, addr)` — amd64-specific thread-state op. We use
/// `code = ARCH_SET_FS` with `addr = &m.tls_self` to plant the fs
/// segment base; subsequent `mov %fs:0, _` reads back the pointer
/// stored at that address (the M's address in goish's TLS layout).
///
/// Returns 0 on success, `-errno` on failure.
#[allow(non_snake_case)]
pub fn ArchPrctl(code: i32, addr: usize) -> isize {
    unsafe { syscall2(SYS_ARCH_PRCTL, code as usize, addr) }
}

/// `exit(2)` — per-thread exit. Different from `Exit`/`exit_group`
/// which kills the whole process. Used by worker M shutdown paths
/// where the main thread shouldn't terminate.
#[allow(non_snake_case)]
pub fn ExitThread(code: i32) -> ! {
    unsafe {
        syscall1(SYS_EXIT, code as usize);
        core::hint::unreachable_unchecked()
    }
}

/// `clone(2)` — spawn a new OS thread sharing the parent's address
/// space. The child begins execution at `child_entry` on a fresh
/// stack pointed at by `child_stack` (which must point at the **top**
/// of an mmap'd region of at least 64 KiB). `child_entry` must be
/// `extern "C"` and never return; it should call `ExitThread` when
/// done.
///
/// `tls`: if nonzero, the kernel sets the child's `fs` segment base
/// to this address (CLONE_SETTLS is OR'd into flags by the trampoline).
/// Pass 0 to inherit the parent's fs (matches M17a-α behavior).
///
/// Returns the child TID on the parent path. Never returns directly
/// in the child — the child immediately tail-jumps to `child_entry`.
///
/// **ABI** (matches Go runtime/sys_linux_amd64.s:561-619):
///   rdi = flags (typically `CLONE_THREAD_FLAGS`)
///   rsi = child_stack (top — kernel decrements as child uses)
///   rdx = child_entry (saved on the new stack before the syscall
///                       so we can jmp to it after the syscall
///                       clobbers our scratch regs)
///   rcx = tls (4th SysV arg; trampoline moves to r8 = clone's newtls)
///
/// **Safety**: caller must keep `child_stack` and (if `tls != 0`) the
/// memory it points at alive for the lifetime of the child thread;
/// passing stale pointers will SIGSEGV the child.
#[allow(non_snake_case)]
#[unsafe(naked)]
pub unsafe extern "C" fn Clone(
    _flags: u64,
    _child_stack: *mut u8,
    _child_entry: extern "C" fn() -> !,
    _tls: u64,
) -> i64 {
    core::arch::naked_asm!(
        // SysV register-passed args at function entry:
        //   rdi = flags, rsi = child_stack, rdx = child_entry, rcx = tls
        //
        // Step 1: stash child_entry on the new stack (so we can
        // recover it after rdx is clobbered for ptid).
        "subq $8, %rsi",
        "movq %rdx, (%rsi)",
        // Step 2: move tls (rcx, our 4th SysV arg) → r8 (clone's
        // newtls register). rcx will be clobbered by the syscall
        // anyway; we don't need it again.
        "movq %rcx, %r8",
        // Step 3: if tls != 0, OR CLONE_SETTLS (0x80000) into flags
        // so the kernel sets the child's fs base from r8.
        "testq %r8, %r8",
        "jz 3f",
        "orq $0x80000, %rdi",
        "3:",
        // Step 4: clone(2) syscall.
        "movq $56, %rax",          // SYS_clone
        "xorq %rdx, %rdx",         // ptid = 0
        "xorq %r10, %r10",         // ctid = 0
        "syscall",
        // Both threads continue here. Parent: rax > 0; child: rax = 0
        // and rsp = child_stack-8 (kernel set rsp from rsi).
        "testq %rax, %rax",
        "jnz 2f",
        // CHILD: load child_entry off the stack (without popping —
        // we want rsp at stack_top-8 when entry runs, so that
        // rsp+8 is 16-aligned, matching SysV's "after-CALL"
        // convention. Go's clone trampoline does this implicitly
        // by using `CALL R12` instead of JMP. fs is already set by
        // CLONE_SETTLS, so the entry function can call
        // current_m() immediately.
        "movq (%rsp), %rax",
        "jmpq *%rax",
        // PARENT: rax holds child_pid; just return.
        "2:",
        "retq",
        options(att_syntax),
    )
}
