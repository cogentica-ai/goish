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
// Socket family (M27a — net/http port).
pub const SYS_SOCKET: usize = 41;
pub const SYS_CONNECT: usize = 42;
pub const SYS_ACCEPT: usize = 43;
pub const SYS_SENDTO: usize = 44;
pub const SYS_RECVFROM: usize = 45;
pub const SYS_SHUTDOWN: usize = 48;
pub const SYS_BIND: usize = 49;
pub const SYS_LISTEN: usize = 50;
pub const SYS_GETSOCKNAME: usize = 51;
pub const SYS_GETPEERNAME: usize = 52;
pub const SYS_SETSOCKOPT: usize = 54;
pub const SYS_GETSOCKOPT: usize = 55;
pub const SYS_FCNTL: usize = 72;
pub const SYS_ACCEPT4: usize = 288;
pub const SYS_EPOLL_CREATE1: usize = 291;
pub const SYS_EPOLL_CTL: usize = 233;
pub const SYS_EPOLL_PWAIT: usize = 281;
pub const SYS_EVENTFD2: usize = 290;

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

/// 4-argument syscall (newfstatat).
#[inline]
pub unsafe fn syscall4(n: usize, a1: usize, a2: usize, a3: usize, a4: usize) -> isize {
    let ret: isize;
    asm!(
        "syscall",
        inlateout("rax") n => ret,
        in("rdi") a1,
        in("rsi") a2,
        in("rdx") a3,
        in("r10") a4,
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

// ─── stat / fstat (Linux x86_64 layout) ──────────────────────────────

pub const SYS_FSTAT: usize = 5;
pub const SYS_NEWFSTATAT: usize = 262;
pub const SYS_LSEEK: usize = 8;

/// File mode bits (from <sys/stat.h>). Used by `Stat_t.st_mode`.
pub const S_IFMT: u32 = 0o170000;
pub const S_IFDIR: u32 = 0o040000;
pub const S_IFREG: u32 = 0o100000;
pub const S_IFLNK: u32 = 0o120000;

/// `seek(2)` whence values.
pub const SEEK_SET: i32 = 0;
pub const SEEK_CUR: i32 = 1;
pub const SEEK_END: i32 = 2;

/// Linux x86_64 `struct stat` (asm-generic/stat.h with x86_64 padding).
/// Layout matches what SYS_FSTAT / SYS_NEWFSTATAT write.
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct Stat_t {
    pub st_dev: u64,
    pub st_ino: u64,
    pub st_nlink: u64,
    pub st_mode: u32,
    pub st_uid: u32,
    pub st_gid: u32,
    pub __pad0: u32,
    pub st_rdev: u64,
    pub st_size: i64,
    pub st_blksize: i64,
    pub st_blocks: i64,
    pub st_atime: i64,
    pub st_atime_nsec: u64,
    pub st_mtime: i64,
    pub st_mtime_nsec: u64,
    pub st_ctime: i64,
    pub st_ctime_nsec: u64,
    pub __unused: [i64; 3],
}

/// `fstat(fd, &stat)` — fill `out` from the kernel. Returns 0 on
/// success or `-errno` on error.
#[allow(non_snake_case)]
pub fn Fstat(fd: i32, out: &mut Stat_t) -> i32 {
    unsafe { syscall2(SYS_FSTAT, fd as usize, out as *mut Stat_t as usize) as i32 }
}

/// `fstatat(AT_FDCWD, path, &stat, 0)` — stat a path relative to CWD,
/// following symlinks. `path` must be NUL-terminated.
pub const AT_FDCWD: i32 = -100;

#[allow(non_snake_case)]
pub fn Stat(path: *const u8, out: &mut Stat_t) -> i32 {
    unsafe {
        syscall4(
            SYS_NEWFSTATAT,
            AT_FDCWD as usize,
            path as usize,
            out as *mut Stat_t as usize,
            0,
        ) as i32
    }
}

/// `lseek(fd, offset, whence)` — reposition file offset.
#[allow(non_snake_case)]
pub fn Lseek(fd: i32, offset: i64, whence: i32) -> i64 {
    unsafe { syscall3(SYS_LSEEK, fd as usize, offset as usize, whence as usize) as i64 }
}

// ─── getdents64 ──────────────────────────────────────────────────────

pub const SYS_GETDENTS64: usize = 217;

/// Linux `struct linux_dirent64` (getdents64(2)). Variable-sized
/// `d_name` field is *not* part of this struct; callers parse it
/// out of the buffer via `d_reclen`.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct LinuxDirent64Header {
    pub d_ino: u64,
    pub d_off: i64,
    pub d_reclen: u16,
    pub d_type: u8,
    // d_name follows here, NUL-terminated, length = d_reclen - 19.
}

/// `d_type` values for getdents64. `DT_UNKNOWN` means caller must stat.
pub const DT_UNKNOWN: u8 = 0;
pub const DT_FIFO: u8 = 1;
pub const DT_CHR: u8 = 2;
pub const DT_DIR: u8 = 4;
pub const DT_BLK: u8 = 6;
pub const DT_REG: u8 = 8;
pub const DT_LNK: u8 = 10;
pub const DT_SOCK: u8 = 12;

/// `getdents64(fd, buf, buflen)` — read raw directory entries into the
/// caller-provided buffer. Returns the number of bytes filled, or
/// `-errno` on error, `0` on EOD.
#[allow(non_snake_case)]
pub fn Getdents64(fd: i32, buf: *mut u8, buflen: usize) -> i64 {
    unsafe { syscall3(SYS_GETDENTS64, fd as usize, buf as usize, buflen) as i64 }
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

// ─── BSD/POSIX sockets — M27a ─────────────────────────────────────────
//
// Linux x86_64 socket calls. Each is a direct syscall (no
// `socketcall(2)` indirection — that's i386). Constants and structs
// mirror /usr/include/{sys/socket.h, netinet/in.h, asm-generic/socket.h}
// and asm-generic/fcntl.h. Goish defines its own repr(C) to stay free
// of libc.

/// `socket(2)` domains.
pub const AF_UNIX: i32 = 1;
pub const AF_INET: i32 = 2;
pub const AF_INET6: i32 = 10;

/// `socket(2)` types.
pub const SOCK_STREAM: i32 = 1;
pub const SOCK_DGRAM: i32 = 2;
/// OR into the type to atomically set close-on-exec on the new fd.
pub const SOCK_CLOEXEC: i32 = 0o2000000;
/// OR into the type to atomically set non-blocking on the new fd.
pub const SOCK_NONBLOCK: i32 = 0o4000;

/// Common protocols.
pub const IPPROTO_TCP: i32 = 6;
pub const IPPROTO_UDP: i32 = 17;

/// `setsockopt(2)` levels.
pub const SOL_SOCKET: i32 = 1;
pub const IPPROTO_IPV6: i32 = 41;

/// SOL_SOCKET option names.
pub const SO_REUSEADDR: i32 = 2;
pub const SO_TYPE: i32 = 3;
pub const SO_ERROR: i32 = 4;
pub const SO_KEEPALIVE: i32 = 9;
pub const SO_LINGER: i32 = 13;
pub const SO_REUSEPORT: i32 = 15;
pub const SO_RCVTIMEO: i32 = 20;
pub const SO_SNDTIMEO: i32 = 21;

/// IPV6_V6ONLY: bind on AF_INET6 should not also accept AF_INET.
pub const IPV6_V6ONLY: i32 = 26;

/// `shutdown(2)` how.
pub const SHUT_RD: i32 = 0;
pub const SHUT_WR: i32 = 1;
pub const SHUT_RDWR: i32 = 2;

/// `fcntl(2)` commands.
pub const F_GETFL: i32 = 3;
pub const F_SETFL: i32 = 4;
/// File status flag — non-blocking I/O.
pub const O_NONBLOCK: i32 = 0o4000;
pub const FD_CLOEXEC: i32 = 1;

/// Special listen-on-any IPv4 address.
pub const INADDR_ANY: u32 = 0;
/// 127.0.0.1 in network-byte-order is computed by `htonl(0x7F000001)`
/// = 0x0100007F. We expose only `INADDR_ANY`; user code uses a
/// helper to build a SockaddrIn.

/// `epoll_ctl(2)` ops.
pub const EPOLL_CTL_ADD: i32 = 1;
pub const EPOLL_CTL_DEL: i32 = 2;
pub const EPOLL_CTL_MOD: i32 = 3;

/// `epoll` event masks.
pub const EPOLLIN: u32 = 0x001;
pub const EPOLLOUT: u32 = 0x004;
pub const EPOLLERR: u32 = 0x008;
pub const EPOLLHUP: u32 = 0x010;
pub const EPOLLRDHUP: u32 = 0x2000;
pub const EPOLLET: u32 = 1u32 << 31;
pub const EPOLLONESHOT: u32 = 1u32 << 30;

/// `eventfd(2)` flags. Mirror the Linux `EFD_*` bits used by
/// `runtime/netpoll_epoll.go`.
pub const EFD_CLOEXEC: i32 = 0x80000;
pub const EFD_NONBLOCK: i32 = 0x800;

/// IPv4 socket address. Layout matches `struct sockaddr_in`:
///   `family: u16`, `port: u16` (BE), `addr: u32` (BE), `_pad: [u8; 8]`.
/// Total 16 bytes — what `bind`/`connect`/`accept` expect via
/// `*const sockaddr` + `socklen_t`.
#[repr(C)]
#[derive(Copy, Clone)]
pub struct SockaddrIn {
    pub sin_family: u16,
    /// Port number in **network byte order** (big-endian). Use
    /// `htons(p)` to convert from host order.
    pub sin_port: u16,
    /// IPv4 address in **network byte order** (big-endian).
    pub sin_addr: u32,
    pub _pad: [u8; 8],
}

impl SockaddrIn {
    /// Build an `AF_INET` sockaddr for `port` on the wildcard
    /// address (binds all interfaces).
    pub const fn any(port: u16) -> Self {
        SockaddrIn {
            sin_family: AF_INET as u16,
            sin_port: htons(port),
            sin_addr: INADDR_ANY,
            _pad: [0; 8],
        }
    }

    /// Build an `AF_INET` sockaddr for `port` on the loopback
    /// address `127.0.0.1`.
    pub const fn loopback(port: u16) -> Self {
        SockaddrIn {
            sin_family: AF_INET as u16,
            sin_port: htons(port),
            sin_addr: htonl(0x7F00_0001),
            _pad: [0; 8],
        }
    }

    /// Build from `(a, b, c, d)` IPv4 octets and host-order port.
    pub const fn ipv4(octets: [u8; 4], port: u16) -> Self {
        let addr = ((octets[0] as u32) << 24)
            | ((octets[1] as u32) << 16)
            | ((octets[2] as u32) << 8)
            | (octets[3] as u32);
        SockaddrIn {
            sin_family: AF_INET as u16,
            sin_port: htons(port),
            sin_addr: htonl(addr),
            _pad: [0; 8],
        }
    }

    /// Extract host-order port.
    pub const fn port_host(&self) -> u16 {
        ntohs(self.sin_port)
    }
}

/// Single `epoll_event` entry. `repr(packed)` to match the
/// kernel's `__attribute__((packed))` ABI on x86_64 — the data
/// payload follows events with no alignment padding.
#[repr(C, packed)]
#[derive(Copy, Clone)]
pub struct EpollEvent {
    pub events: u32,
    pub data: u64,
}

/// Convert host-order u16 to network byte order (big-endian).
#[inline]
pub const fn htons(x: u16) -> u16 {
    x.to_be()
}

/// Convert network-order u16 to host order.
#[inline]
pub const fn ntohs(x: u16) -> u16 {
    u16::from_be(x)
}

/// Convert host-order u32 to network byte order.
#[inline]
pub const fn htonl(x: u32) -> u32 {
    x.to_be()
}

/// Convert network-order u32 to host order.
#[inline]
pub const fn ntohl(x: u32) -> u32 {
    u32::from_be(x)
}

/// `socket(2)` — create an endpoint. Returns the fd on success or
/// `-errno` on failure (mirrors syscall convention).
#[allow(non_snake_case)]
pub fn Socket(domain: i32, type_: i32, protocol: i32) -> i32 {
    unsafe {
        syscall3(
            SYS_SOCKET,
            domain as usize,
            type_ as usize,
            protocol as usize,
        ) as i32
    }
}

/// `bind(2)` — bind a socket to an address. Returns `0` on
/// success, `-errno` on failure.
#[allow(non_snake_case)]
pub fn Bind(fd: i32, addr: *const SockaddrIn, addrlen: u32) -> i32 {
    unsafe {
        syscall3(
            SYS_BIND,
            fd as usize,
            addr as usize,
            addrlen as usize,
        ) as i32
    }
}

/// `listen(2)` — mark a socket as accepting connections. Returns
/// `0` on success, `-errno` on failure.
#[allow(non_snake_case)]
pub fn Listen(fd: i32, backlog: i32) -> i32 {
    unsafe { syscall2(SYS_LISTEN, fd as usize, backlog as usize) as i32 }
}

/// `accept4(2)` — accept a connection, atomically setting flags
/// (`SOCK_NONBLOCK`, `SOCK_CLOEXEC`) on the returned fd. Returns
/// the new fd on success, `-errno` on failure. `addr` may be null
/// when the caller doesn't need the peer address.
#[allow(non_snake_case)]
pub fn Accept4(
    fd: i32,
    addr: *mut SockaddrIn,
    addrlen: *mut u32,
    flags: i32,
) -> i32 {
    unsafe {
        syscall6(
            SYS_ACCEPT4,
            fd as usize,
            addr as usize,
            addrlen as usize,
            flags as usize,
            0,
            0,
        ) as i32
    }
}

/// `connect(2)` — connect a socket to a peer. Returns `0` on
/// success, `-errno` on failure (including `-EINPROGRESS` on
/// non-blocking sockets).
#[allow(non_snake_case)]
pub fn Connect(fd: i32, addr: *const SockaddrIn, addrlen: u32) -> i32 {
    unsafe {
        syscall3(
            SYS_CONNECT,
            fd as usize,
            addr as usize,
            addrlen as usize,
        ) as i32
    }
}

/// `setsockopt(2)`. Returns `0` on success, `-errno` on failure.
#[allow(non_snake_case)]
pub fn Setsockopt(
    fd: i32,
    level: i32,
    name: i32,
    val: *const u8,
    len: u32,
) -> i32 {
    unsafe {
        syscall6(
            SYS_SETSOCKOPT,
            fd as usize,
            level as usize,
            name as usize,
            val as usize,
            len as usize,
            0,
        ) as i32
    }
}

/// `getsockopt(2)`. `len` is in/out. Returns `0` on success.
#[allow(non_snake_case)]
pub fn Getsockopt(
    fd: i32,
    level: i32,
    name: i32,
    val: *mut u8,
    len: *mut u32,
) -> i32 {
    unsafe {
        syscall6(
            SYS_GETSOCKOPT,
            fd as usize,
            level as usize,
            name as usize,
            val as usize,
            len as usize,
            0,
        ) as i32
    }
}

/// `shutdown(2)`. `how` is `SHUT_RD` / `SHUT_WR` / `SHUT_RDWR`.
#[allow(non_snake_case)]
pub fn Shutdown(fd: i32, how: i32) -> i32 {
    unsafe { syscall2(SYS_SHUTDOWN, fd as usize, how as usize) as i32 }
}

/// `fcntl(2)`. The `arg` form (used for `F_SETFL`); for `F_GETFL`
/// pass `0`. Returns the result on success, `-errno` on failure.
#[allow(non_snake_case)]
pub fn Fcntl(fd: i32, cmd: i32, arg: i32) -> i32 {
    unsafe {
        syscall3(
            SYS_FCNTL,
            fd as usize,
            cmd as usize,
            arg as usize,
        ) as i32
    }
}

/// `epoll_create1(2)`. Returns the epoll fd or `-errno`. Pass
/// `O_CLOEXEC` (= 0o2000000) for close-on-exec.
#[allow(non_snake_case)]
pub fn EpollCreate1(flags: i32) -> i32 {
    unsafe { syscall1(SYS_EPOLL_CREATE1, flags as usize) as i32 }
}

/// `epoll_ctl(2)`. `op` is `EPOLL_CTL_{ADD,DEL,MOD}`. `event` may
/// be null for `EPOLL_CTL_DEL`.
#[allow(non_snake_case)]
pub fn EpollCtl(
    epfd: i32,
    op: i32,
    fd: i32,
    event: *mut EpollEvent,
) -> i32 {
    unsafe {
        syscall6(
            SYS_EPOLL_CTL,
            epfd as usize,
            op as usize,
            fd as usize,
            event as usize,
            0,
            0,
        ) as i32
    }
}

/// `eventfd2(2)`. Returns a new eventfd or `-errno`. The netpoller
/// uses one eventfd registered with EPOLLIN as the wakeup source for
/// `netpollBreak` (mirrors `runtime/netpoll_epoll.go:netpollinit`).
#[allow(non_snake_case)]
pub fn Eventfd(initval: u32, flags: i32) -> i32 {
    unsafe { syscall2(SYS_EVENTFD2, initval as usize, flags as usize) as i32 }
}

/// `epoll_pwait(2)`. Returns the number of events filled into
/// `events[..maxevents]`, `0` on timeout, or `-errno`.
/// `timeout_ms` is in milliseconds, `-1` for indefinite.
/// `sigmask` may be null.
#[allow(non_snake_case)]
pub fn EpollPwait(
    epfd: i32,
    events: *mut EpollEvent,
    maxevents: i32,
    timeout_ms: i32,
    sigmask: *const u8,
    sigsetsize: usize,
) -> i32 {
    unsafe {
        syscall6(
            SYS_EPOLL_PWAIT,
            epfd as usize,
            events as usize,
            maxevents as usize,
            timeout_ms as usize,
            sigmask as usize,
            sigsetsize,
        ) as i32
    }
}
