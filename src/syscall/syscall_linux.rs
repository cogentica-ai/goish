// syscall — Go's `syscall` package, ported. Raw Linux x86-64 syscalls
// via inline assembly. No libc.
//
//   Go                                   goish
//   ──────────────────────────────────   ──────────────────────────────────
//   syscall.Write(fd, buf)               syscall::Write(fd, buf.as_ptr(), buf.len())
//   syscall.Exit(0)                      syscall::Exit(0)
//
// WHY THE WRAPPERS HERE CARRY NO `// go: sdk` ANCHOR, checked 2026-09-06.
// Fifty-four of them share a name with a Go declaration — Open, Read,
// Write, Close, Fstat, Wait4 — and an anchor on any of them would
// overclaim, because the contracts differ at every point that matters:
//
//   Go    func Open(path string, mode int, perm uint32) (fd int, err error)
//         calls openat(_AT_FDCWD, ..., mode|O_LARGEFILE, perm)
//   goish pub fn Open(path: *const u8, flags: i32, mode: i32) -> i32
//         issues SYS_OPEN directly and returns the raw -errno
//
// Different signature, different syscall, and an `error` against a
// negative return. `// go: sdk` says "this declaration is a port of that
// range", and anchor_check would happily verify the range while the
// claim itself was false. The layer above — `src/os` — is where the Go
// contract is reconstructed, and that is where the anchors live: `os`
// carries 100 of them, all verified.
//
// This note exists because the unanchored-declaration scan reports
// these 54 every time it is run. They are not a gap. Openat is the exception:
// it was added later with the exact Go-shaped string/(fd,error) contract and
// therefore carries its SDK anchor at the declaration.
//
// Calling convention (SysV / Linux x86-64 syscall):
//   rax = syscall number
//   rdi, rsi, rdx, r10, r8, r9 = args 1..6
//   rax = return (negative = -errno)
//   clobbers: rcx, r11, plus memory.


// ─── syscall numbers (asm-generic / x86_64) ────────────────────────────
// Socket family (M27a — net/http port).
// Terminal control (term port — QuCode T1).
// Process family (os/exec port — M27 follow-up).

// Signal numbers (Linux). Mirror /usr/include/asm-generic/signal.h.
pub const SIGHUP: i32 = 1;
pub const SIGINT: i32 = 2;
pub const SIGQUIT: i32 = 3;
pub const SIGILL: i32 = 4;
pub const SIGTRAP: i32 = 5;
pub const SIGABRT: i32 = 6;
pub const SIGBUS: i32 = 7;
pub const SIGFPE: i32 = 8;
pub const SIGKILL: i32 = 9;
pub const SIGUSR1: i32 = 10;
pub const SIGSEGV: i32 = 11;
pub const SIGUSR2: i32 = 12;
pub const SIGPIPE: i32 = 13;
pub const SIGALRM: i32 = 14;
pub const SIGTERM: i32 = 15;
pub const SIGCHLD: i32 = 17;
pub const SIGCONT: i32 = 18;
pub const SIGSTOP: i32 = 19;
pub const SIGTSTP: i32 = 20;
pub const SIGTTIN: i32 = 21;
pub const SIGTTOU: i32 = 22;
pub const SIGURG: i32 = 23;
pub const SIGXCPU: i32 = 24;
pub const SIGXFSZ: i32 = 25;
pub const SIGVTALRM: i32 = 26;
pub const SIGPROF: i32 = 27;
pub const SIGWINCH: i32 = 28;

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
// `arch_prctl(2)` is x86-only; we use it to plant a per-thread segment
// base so a segment-relative load reads back a pointer to the calling M.
pub const ARCH_SET_GS: i32 = 0x1001;
pub const ARCH_SET_FS: i32 = 0x1002;
pub const ARCH_GET_FS: i32 = 0x1003;
pub const ARCH_GET_GS: i32 = 0x1004;

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

/// `UTIME_OMIT` — sentinel tv_nsec value for `utimensat`: leave the
/// corresponding timestamp unchanged (Go internal/syscall/unix
/// at_sysnum_linux.go:26).
pub const UTIME_OMIT: i64 = 0x3ffffffe;

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
/// Don't reserve swap / commit charge for this mapping — pages are
/// accounted only as they're touched. Used for goroutine stack
/// reservations, where the virtual size (1 MiB+) vastly exceeds
/// typical use.
pub const MAP_NORESERVE: i32 = 0x4000;

/// `madvise(2)` advice: free the pages and reset them to zero-fill on
/// next touch. Drops physical memory immediately (unlike MADV_FREE's
/// lazy reclaim), so RSS reflects reality — same reasoning as Go's
/// default `madvdontneed=1` since 1.16.
pub const MADV_DONTNEED: i32 = 4;

/// Sentinel returned by `mmap(2)` on failure (`(void*) -1`).
pub const MAP_FAILED: *mut u8 = !0usize as *mut u8;

// ─── raw syscall wrappers ──────────────────────────────────────────────
//
// The instruction itself lives in `crate::sys`, one file per target
// (`sys/sys_linux_amd64.rs`, `sys/sys_linux_arm64.rs`). Re-exported here
// so every wrapper below — and every caller of them — keeps the
// `syscall::syscallN` path it has always used.
//
// The contract is unchanged: a non-negative kernel result, or a
// negative `-errno`.
pub use crate::sys::{syscall0, syscall1, syscall2, syscall3, syscall4, syscall6};

// --- system-call numbers ----------------------------------------------
//
// One table per target, mirroring Go's `syscall/zsysnum_linux_*.go`.
// Re-exported so `syscall::SYS_WRITE` resolves as it always has.
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
#[path = "zsysnum_linux_amd64.rs"]
mod zsysnum_linux_amd64;
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
pub use zsysnum_linux_amd64::*;

#[cfg(all(target_os = "linux", target_arch = "aarch64"))]
#[path = "zsysnum_linux_arm64.rs"]
mod zsysnum_linux_arm64;
#[cfg(all(target_os = "linux", target_arch = "aarch64"))]
pub use zsysnum_linux_arm64::*;

// ─── naked-asm entry points ────────────────────────────────────────────
//
// `Clone` and the sigreturn restorer are whole functions written in
// assembly, not wrappers around a syscall instruction, so they live in
// `syscall/asm_linux_*.rs` — mirroring Go's own `syscall/asm_linux_*.s`
// / `runtime/sys_linux_*.s` layout.
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
#[path = "asm_linux_amd64.rs"]
mod asm_linux_amd64;
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
pub use asm_linux_amd64::*;

#[cfg(all(target_os = "linux", target_arch = "aarch64"))]
#[path = "asm_linux_arm64.rs"]
mod asm_linux_arm64;
#[cfg(all(target_os = "linux", target_arch = "aarch64"))]
pub use asm_linux_arm64::*;

// ─── raw syscall wrappers (x86-64) ─────────────────────────────────────

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

/// `ioctl(2)` — device control. `req` selects the operation (TCGETS,
/// TIOCGWINSZ, …); `arg` is usually a pointer to the in/out struct,
/// passed as `usize` like the kernel ABI takes it. Returns the raw
/// syscall result: `0` (or a positive value, request-specific) on
/// success, negative `-errno` on error. Mirrors the
/// `unix.IoctlGetTermios`-family plumbing in golang.org/x/sys.
#[allow(non_snake_case)]
pub fn Ioctl(fd: i32, req: usize, arg: usize) -> isize {
    unsafe { syscall3(SYS_IOCTL, fd as usize, req, arg) }
}

// ─── termios (ztypes_linux_amd64.go) ──────────────────────────────────
//
// Layout is Go's `syscall.Termios` on linux/amd64 — itself the kernel's
// `struct termios` (asm-generic/termbits.h, NCCS=19) padded out to the
// glibc-compatible 32-slot Cc array plus speed fields. TCGETS/TCSETS
// only touch the first 36 bytes; the tail exists for layout fidelity.

/// `syscall.Termios` (ztypes_linux_amd64.go:718).
#[repr(C)]
#[derive(Copy, Clone, Default)]
#[allow(missing_docs)]
pub struct Termios {
    pub Iflag: u32,
    pub Oflag: u32,
    pub Cflag: u32,
    pub Lflag: u32,
    pub Line: u8,
    pub Cc: [u8; 32],
    pub Pad_cgo_0: [u8; 3],
    pub Ispeed: u32,
    pub Ospeed: u32,
}

/// `syscall.Winsize` (ztypes_linux_amd64.go) — the TIOCGWINSZ /
/// TIOCSWINSZ payload.
#[repr(C)]
#[derive(Copy, Clone, Default)]
#[allow(missing_docs)]
pub struct Winsize {
    pub Row: u16,
    pub Col: u16,
    pub Xpixel: u16,
    pub Ypixel: u16,
}

// ioctl request numbers (ztypes_linux_amd64.go / zerrors_linux_amd64.go).
pub const TCGETS: usize = 0x5401;
pub const TCSETS: usize = 0x5402;
pub const TIOCGWINSZ: usize = 0x5413;
pub const TIOCSWINSZ: usize = 0x5414;
pub const TIOCGPTN: usize = 0x80045430;
pub const TIOCSPTLCK: usize = 0x40045431;

// c_iflag bits (ztypes_linux_amd64.go:635).
pub const IGNBRK: u32 = 0x1;
pub const BRKINT: u32 = 0x2;
pub const PARMRK: u32 = 0x8;
pub const ISTRIP: u32 = 0x20;
pub const INLCR: u32 = 0x40;
pub const IGNCR: u32 = 0x80;
pub const ICRNL: u32 = 0x100;
pub const IXON: u32 = 0x400;

// c_oflag bits.
pub const OPOST: u32 = 0x1;

// c_cflag bits.
pub const CSIZE: u32 = 0x30;
pub const CS8: u32 = 0x30;
pub const PARENB: u32 = 0x100;

// c_lflag bits.
pub const ISIG: u32 = 0x1;
pub const ICANON: u32 = 0x2;
pub const ECHO: u32 = 0x8;
pub const ECHONL: u32 = 0x40;
pub const IEXTEN: u32 = 0x8000;

// c_cc indices (ztypes_linux_amd64.go:623). `usize` so `Cc[VMIN]`
// indexes directly, matching Go's untyped-const ergonomics.
pub const VTIME: usize = 0x5;
pub const VMIN: usize = 0x6;

// ─── Errno ────────────────────────────────────────────────────────────
//
// Go: `syscall.Errno` is `type Errno uintptr` (integer) that implements
// the `error` interface (zerrors_linux_*.go:Errno.Error).
//
// Goish v1 ships it as a Copy newtype around i32 so we can:
//   1. Use it as the return type of syscall fns (Go-shape: `error`).
//   2. Compare values directly (`if err == syscall.EINTR { ... }`) since
//      Errno is PartialEq.
//   3. Cross-compare with raw i32 in internal goish-v1 paths that compare
//      against the negated kernel rc (e.g. `if -rc == syscall::ENOENT`).
//
// The wrap-into-error path (`error::from(Errno)`) routes through
// `errors::From<Errno>` so Go-shape returns `(T, error)` continue to
// work — the error binding holds an `Errno`-typed Arc<dyn ErrorTrait>.
#[derive(Copy, Clone, PartialEq, Eq, Hash, Debug, Default)]
#[allow(non_camel_case_types)]
pub struct Errno(pub i32);

impl Errno {
    /// `(e Errno) Error() string` — Linux errno → human name (Go's
    /// `errnoErr` table is large; we ship a short table for the v1
    /// surface and fall through to the numeric form for anything else).
    #[allow(non_snake_case)]
    pub fn Error(&self) -> crate::gostring::string {
        // The nine socket errnos below used to be absent, so every one
        // of them rendered as the bare word "errno": a refused
        // connection, a reset peer, an address already in use and a
        // broken pipe all produced the same useless message. They are
        // the errnos `net` hands back most often, plus every errno a
        // FILE, DIRECTORY or PROCESS operation produces — measured
        // against Go rather than transcribed, because "errno 28" for a
        // full disk is exactly as useless as the bare "errno" this
        // table replaced.
        //
        // The fallback carries the NUMBER, as Go's does — Go renders
        // an unknown errno as "errno 0", not "errno", and without the
        // number two different failures are indistinguishable in a
        // log.
        let msg = match self.0 {
            1 => "operation not permitted",
            2 => "no such file or directory",
            4 => "interrupted system call",
            9 => "bad file descriptor",
            11 => "resource temporarily unavailable",
            12 => "cannot allocate memory",
            13 => "permission denied",
            17 => "file exists",
            20 => "not a directory",
            21 => "is a directory",
            22 => "invalid argument",
            23 => "too many open files in system",
            24 => "too many open files",
            32 => "broken pipe",
            38 => "function not implemented",
            39 => "directory not empty",
            95 => "operation not supported",
            98 => "address already in use",
            99 => "cannot assign requested address",
            103 => "software caused connection abort",
            104 => "connection reset by peer",
            105 => "no buffer space available",
            110 => "connection timed out",
            111 => "connection refused",
            3 => "no such process",
            5 => "input/output error",
            6 => "no such device or address",
            7 => "argument list too long",
            8 => "exec format error",
            10 => "no child processes",
            14 => "bad address",
            16 => "device or resource busy",
            18 => "invalid cross-device link",
            19 => "no such device",
            25 => "inappropriate ioctl for device",
            26 => "text file busy",
            27 => "file too large",
            28 => "no space left on device",
            29 => "illegal seek",
            30 => "read-only file system",
            31 => "too many links",
            33 => "numerical argument out of domain",
            34 => "numerical result out of range",
            36 => "file name too long",
            40 => "too many levels of symbolic links",
            61 => "no data available",
            62 => "timer expired",
            71 => "protocol error",
            75 => "value too large for defined data type",
            84 => "invalid or incomplete multibyte or wide character",
            88 => "socket operation on non-socket",
            89 => "destination address required",
            90 => "message too long",
            91 => "protocol wrong type for socket",
            92 => "protocol not available",
            93 => "protocol not supported",
            94 => "socket type not supported",
            96 => "protocol family not supported",
            97 => "address family not supported by protocol",
            100 => "network is down",
            101 => "network is unreachable",
            102 => "network dropped connection on reset",
            106 => "transport endpoint is already connected",
            107 => "transport endpoint is not connected",
            108 => "cannot send after transport endpoint shutdown",
            109 => "too many references: cannot splice",
            112 => "host is down",
            113 => "no route to host",
            114 => "operation already in progress",
            115 => "operation now in progress",
            116 => "stale file handle",
            122 => "disk quota exceeded",
            125 => "operation canceled",
            _ => "",
        };
        if !msg.is_empty() {
            return crate::gostring::string::from_static(msg);
        }
        return crate::gostring::string::from_static("errno ")
            + crate::strconv::Itoa(self.0 as crate::types::int);
    }

    // go: sdk 1.25.5 syscall/syscall_unix.go:138-140 Errno.Timeout
    /// Go: `func (e Errno) Timeout() bool`. This is what makes a
    /// blocking read that hit its deadline read as a timeout to every
    /// caller that asks the `net.Error` question, EAGAIN included.
    #[allow(non_snake_case)]
    pub fn Timeout(&self) -> bool {
        return *self == EAGAIN || *self == EWOULDBLOCK || *self == ETIMEDOUT;
    }

    // go: sdk 1.25.5 syscall/syscall_unix.go:134-136 Errno.Temporary
    /// Go: `func (e Errno) Temporary() bool`. Every timeout is
    /// temporary, and so are the three "come back later" errnos: an
    /// interrupted call and the two fd-table exhaustions.
    #[allow(non_snake_case)]
    pub fn Temporary(&self) -> bool {
        return *self == EINTR || *self == EMFILE || *self == ENFILE || self.Timeout();
    }
}

// go: sdk 1.25.5 syscall/syscall_unix.go:120-132 Errno.Is
// `func (e Errno) Is(target error) bool` — the hook that makes
// `errors.Is(syscall.ENOENT, fs.ErrNotExist)` true. Without it, every
// portable check against a raw errno is false: the two values are
// unrelated, and `errors.Is` has nothing else to go on.
//
// goish had no such hook at all, so `os.IsNotExist` could only ever be
// an equality test against the sentinel, and an errno arriving from a
// real system call answered false. Go's `switch target` is a shallow
// comparison, and so is this one.
//
// The inherent `Errno::Is(Errno)` this replaces was value-equality
// under a doc comment claiming it mirrored `errors.Is`. It had no
// callers.
impl Errno {
    // go: sdk 1.25.5 syscall/syscall_unix.go:120-132 Errno.Is
    #[allow(non_snake_case)]
    fn __is(&self, target: &crate::errors::error) -> bool {
        if *target == crate::io::fs::ErrPermission {
            return *self == EACCES || *self == EPERM;
        }
        if *target == crate::io::fs::ErrExist {
            return *self == EEXIST || *self == ENOTEMPTY;
        }
        if *target == crate::io::fs::ErrNotExist {
            return *self == ENOENT;
        }
        if *target == crate::errors::ErrUnsupported {
            return *self == ENOSYS || *self == ENOTSUP || *self == EOPNOTSUPP;
        }
        return false;
    }
}

impl crate::errors::ErrorTrait for Errno {
    fn Error(&self) -> crate::gostring::string {
        Self::Error(self)
    }
    fn Is(&self, target: &crate::errors::error) -> bool {
        return self.__is(target);
    }
}

// `From<Errno> for error` flows through the existing
// `impl<E: ErrorTrait> From<E> for error` blanket in errors/mod.rs.
// Errno(0) is the success sentinel (`syscall.Errno(0).Error() ==
// "errno"`, but `errors.Is(syscall.Errno(0), nil)` is true in Go);
// goish callers manage that bridge at the syscall fn body, returning
// `errors::nil` for the zero case instead of `Errno(0).into()`.

// Cross-equality with raw i32 so internal goish-v1 code that compares
// `(-rc as i32) == syscall::ENOENT` keeps compiling without rewrite.
impl PartialEq<i32> for Errno {
    fn eq(&self, other: &i32) -> bool {
        self.0 == *other
    }
}
impl PartialEq<Errno> for i32 {
    fn eq(&self, other: &Errno) -> bool {
        *self == other.0
    }
}

// Cross-equality with goish::error so port code `if err == syscall.EINTR`
// (where err is the trait-object form) compares by underlying Errno
// value. The implementation downcasts through `goish::Any::As` which
// returns the Go-shape `(value, ok)` comma-ok pair.
impl PartialEq<Errno> for crate::errors::error {
    fn eq(&self, other: &Errno) -> bool {
        let (e, ok) = self.As::<Errno>();
        ok && *e == *other
    }
}
impl PartialEq<crate::errors::error> for Errno {
    fn eq(&self, other: &crate::errors::error) -> bool {
        other == self
    }
}

/// Common errno values (Linux, from `<errno.h>`). Match the Go-side
/// `syscall.E*` consts in name; type is `Errno` to match Go shape.
pub const EPERM: Errno = Errno(1);
pub const ENOENT: Errno = Errno(2);
pub const EACCES: Errno = Errno(13);
pub const EEXIST: Errno = Errno(17);
pub const ENOTDIR: Errno = Errno(20);
pub const EISDIR: Errno = Errno(21);
pub const EINVAL: Errno = Errno(22);
pub const ENOTEMPTY: Errno = Errno(39);
pub const EINTR: Errno = Errno(4);
pub const EAGAIN: Errno = Errno(11);
/// Linux gives EAGAIN and EWOULDBLOCK the same value, as Go's
/// `zerrors_linux_amd64.go` does.
pub const EWOULDBLOCK: Errno = Errno(11);
pub const ENFILE: Errno = Errno(23);
pub const EMFILE: Errno = Errno(24);
pub const ETIMEDOUT: Errno = Errno(110);
pub const ENOSYS: Errno = Errno(38);
pub const ENOTSUP: Errno = Errno(95);
pub const EOPNOTSUPP: Errno = Errno(95);

// Every other errno name the Darwin surface declares, so code spelling
// them by name compiles on both. Values from Go's
// `syscall/zerrors_linux_amd64.go` (the generic table; arm64 agrees).
pub const E2BIG: Errno = Errno(7);
pub const EADDRINUSE: Errno = Errno(98);
pub const EADDRNOTAVAIL: Errno = Errno(99);
pub const EAFNOSUPPORT: Errno = Errno(97);
pub const EALREADY: Errno = Errno(114);
pub const EBADF: Errno = Errno(9);
pub const EBADMSG: Errno = Errno(74);
pub const EBUSY: Errno = Errno(16);
pub const ECANCELED: Errno = Errno(125);
pub const ECHILD: Errno = Errno(10);
pub const ECONNABORTED: Errno = Errno(103);
pub const ECONNREFUSED: Errno = Errno(111);
pub const ECONNRESET: Errno = Errno(104);
pub const EDEADLK: Errno = Errno(35);
pub const EDESTADDRREQ: Errno = Errno(89);
pub const EDOM: Errno = Errno(33);
pub const EDQUOT: Errno = Errno(122);
pub const EFAULT: Errno = Errno(14);
pub const EFBIG: Errno = Errno(27);
pub const EHOSTDOWN: Errno = Errno(112);
pub const EHOSTUNREACH: Errno = Errno(113);
pub const EIDRM: Errno = Errno(43);
pub const EILSEQ: Errno = Errno(84);
pub const EINPROGRESS: Errno = Errno(115);
pub const EIO: Errno = Errno(5);
pub const EISCONN: Errno = Errno(106);
pub const ELOOP: Errno = Errno(40);
pub const EMLINK: Errno = Errno(31);
pub const EMSGSIZE: Errno = Errno(90);
pub const EMULTIHOP: Errno = Errno(72);
pub const ENAMETOOLONG: Errno = Errno(36);
pub const ENETDOWN: Errno = Errno(100);
pub const ENETRESET: Errno = Errno(102);
pub const ENETUNREACH: Errno = Errno(101);
pub const ENOBUFS: Errno = Errno(105);
pub const ENODATA: Errno = Errno(61);
pub const ENODEV: Errno = Errno(19);
pub const ENOEXEC: Errno = Errno(8);
pub const ENOLCK: Errno = Errno(37);
pub const ENOLINK: Errno = Errno(67);
pub const ENOMEM: Errno = Errno(12);
pub const ENOMSG: Errno = Errno(42);
pub const ENOPROTOOPT: Errno = Errno(92);
pub const ENOSPC: Errno = Errno(28);
pub const ENOSR: Errno = Errno(63);
pub const ENOSTR: Errno = Errno(60);
pub const ENOTBLK: Errno = Errno(15);
pub const ENOTCONN: Errno = Errno(107);
pub const ENOTRECOVERABLE: Errno = Errno(131);
pub const ENOTSOCK: Errno = Errno(88);
pub const ENOTTY: Errno = Errno(25);
pub const ENXIO: Errno = Errno(6);
pub const EOVERFLOW: Errno = Errno(75);
pub const EOWNERDEAD: Errno = Errno(130);
pub const EPFNOSUPPORT: Errno = Errno(96);
pub const EPIPE: Errno = Errno(32);
pub const EPROTO: Errno = Errno(71);
pub const EPROTONOSUPPORT: Errno = Errno(93);
pub const EPROTOTYPE: Errno = Errno(91);
pub const ERANGE: Errno = Errno(34);
pub const EREMOTE: Errno = Errno(66);
pub const EROFS: Errno = Errno(30);
pub const ESHUTDOWN: Errno = Errno(108);
pub const ESOCKTNOSUPPORT: Errno = Errno(94);
pub const ESPIPE: Errno = Errno(29);
pub const ESRCH: Errno = Errno(3);
pub const ESTALE: Errno = Errno(116);
pub const ETIME: Errno = Errno(62);
pub const ETOOMANYREFS: Errno = Errno(109);
pub const ETXTBSY: Errno = Errno(26);
pub const EUSERS: Errno = Errno(87);
pub const EXDEV: Errno = Errno(18);

/// Open flags. Subset of `<fcntl.h>`.
pub const O_RDONLY: i32 = 0;
// The rest of the open(2) flags `os` re-exports (Go: os/file.go's
// O_* = syscall.O_*). Values from Go's syscall/zerrors_linux_amd64.go;
// arm64 agrees.
pub const O_WRONLY: i32 = 0x1;
pub const O_RDWR: i32 = 0x2;
pub const O_CREAT: i32 = 0x40;
pub const O_EXCL: i32 = 0x80;
pub const O_TRUNC: i32 = 0x200;
pub const O_APPEND: i32 = 0x400;
pub const O_SYNC: i32 = 0x101000;
pub const F_DUPFD_CLOEXEC: i32 = 0x406;
pub const O_CLOEXEC: i32 = 0o2_000_000;
// go: sdk 1.25.5 syscall/zerrors_linux_amd64.go:626 O_DIRECTORY
/// Fail with ENOTDIR unless the target is a directory.
pub const O_DIRECTORY: i32 = 0o200_000;
// go: sdk 1.25.5 syscall/zerrors_linux_amd64.go:633 O_NOCTTY
pub const O_NOCTTY: i32 = 0o400;
// go: sdk 1.25.5 syscall/zerrors_linux_amd64.go:634 O_NOFOLLOW
/// Fail with ELOOP if the final component is a symlink.
///
/// This is the whole basis of `os.Root`: resolving a path one component
/// at a time with openat(2) and O_NOFOLLOW is what makes a symlink
/// unable to carry the walk out of the root, no matter who wrote it.
pub const O_NOFOLLOW: i32 = 0o400_000;
/// `O_PATH` — obtain an fd that references a location without opening
/// the file itself (follows symlinks; needs only search permission).
pub const O_PATH: i32 = 0o10_000_000;

/// `open(2)` — open a file. `path` must be a NUL-terminated C string.
/// Returns the new fd on success, or a negative `-errno` on error.
#[allow(non_snake_case)]
pub fn Open(path: *const u8, flags: i32, mode: i32) -> i32 {
    // Go: `syscall/syscall_linux.go:279-281` routes every Linux arch
    // through the `*at` form with `AT_FDCWD`; arm64 has no legacy call
    // to route to. See `zsysnum_linux_arm64.rs`.
    //
    // Go's line is `openat(_AT_FDCWD, path, mode|O_LARGEFILE, perm)`.
    // The `|O_LARGEFILE` is not carried here because it is a no-op on
    // both of goish's targets: the flag only exists to make 32-bit
    // userspace opt in to >2 GiB files, and the kernel sets it
    // implicitly for 64-bit processes. Go passes it because it also
    // builds for 386 and arm.
    unsafe {
        syscall4(
            SYS_OPENAT,
            AT_FDCWD as usize,
            path as usize,
            flags as usize,
            mode as usize,
        ) as i32
    }
}

// go: sdk 1.25.5 syscall/syscall_linux.go:285-287 Openat
// Go: func Openat(dirfd int, path string, flags int, mode uint32) (fd int, err error)
/// `syscall.Openat(dirfd, path, flags, mode)` — open `path` relative to
/// `dirfd`, or relative to the current directory for `AT_FDCWD`. Absolute
/// paths ignore `dirfd`, as Linux specifies. Kernel failures return
/// `(-1, error)`; an embedded NUL returns `(0, EINVAL)` before the syscall,
/// matching Go's named-result zero value.
#[allow(non_snake_case)]
pub fn Openat<P: Into<crate::string>>(
    dirfd: crate::int,
    path: P,
    flags: crate::int,
    mode: u32,
) -> (crate::int, crate::error) {
    let path = path.into();
    if path.as_bytes().contains(&0) {
        return (0, EINVAL.into());
    }
    let path = __c_path(path);
    let rc = unsafe {
        syscall4(
            SYS_OPENAT,
            dirfd as usize,
            path.as_ptr() as usize,
            flags as usize,
            mode as usize,
        )
    };
    if rc < 0 {
        return (-1, Errno(-crate::int32(rc)).into());
    }
    return (crate::int(rc), crate::errors::nil);
}

/// `close(2)` — close a file descriptor.
#[allow(non_snake_case)]
pub fn Close(fd: i32) -> i32 {
    unsafe { syscall1(SYS_CLOSE, fd as usize) as i32 }
}

/// `fsync(2)`. Returns 0 or `-errno`.
#[allow(non_snake_case)]
pub fn Fsync(fd: i32) -> i32 {
    unsafe { syscall1(SYS_FSYNC, fd as usize) as i32 }
}

// ─── process family (os/exec) ─────────────────────────────────────────

/// `fork(2)` — returns 0 in child, child PID in parent, -errno on
/// error. Expressed as `clone(SIGCHLD, 0)`, which is precisely what the
/// legacy `fork` syscall does: a full address-space copy whose child
/// signals the parent with SIGCHLD on exit, running on the parent's own
/// (copy-on-write) stack because `newsp` is 0.
///
/// Why not the legacy call: arm64 has no `SYS_FORK` at any number, and
/// Go does not use one either — `syscall/exec_linux.go:340-342` goes
/// through `rawVforkSyscall(SYS_CLONE, …)` on every Linux architecture,
/// amd64 included.
///
/// The address-space-*sharing* variants (vfork, clone with CLONE_VM) are
/// still deliberately avoided: they require child-side discipline the
/// simple posix-style `Cmd.Run` path doesn't need.
#[allow(non_snake_case)]
pub fn Fork() -> i32 {
    // clone(flags = SIGCHLD, newsp = 0). The remaining arguments are
    // unused because no CLONE_PARENT_SETTID / CLONE_SETTLS /
    // CLONE_CHILD_CLEARTID flag is set — which is also why the amd64 and
    // arm64 disagreement about the order of slots 4 and 5 (see
    // `asm_linux_arm64.rs`) cannot bite here.
    unsafe { syscall2(SYS_CLONE, SIGCHLD as usize, 0) as i32 }
}

/// `execve(2)` — replace the current process image. `argv` and `envp`
/// are NULL-terminated arrays of NULL-terminated C strings. On
/// success, does not return (so the caller observes the child via
/// wait4 and a non-zero exit). On failure, returns -errno.
#[allow(non_snake_case)]
pub fn Execve(path: *const u8, argv: *const *const u8, envp: *const *const u8) -> i32 {
    unsafe { syscall3(SYS_EXECVE, path as usize, argv as usize, envp as usize) as i32 }
}

/// `wait4(2)` — wait for the given pid and return its raw status word
/// (or -errno). `options` follows Linux's WNOHANG/WUNTRACED/etc.; pass
/// 0 for blocking-wait-for-exit semantics. The decoded exit-code lives
/// in bits 8..16 of the status word for normal exits.
#[allow(non_snake_case)]
pub fn Wait4(pid: i32, status: *mut i32, options: i32, rusage: *mut u8) -> i32 {
    unsafe {
        syscall4(
            SYS_WAIT4,
            pid as usize,
            status as usize,
            options as usize,
            rusage as usize,
        ) as i32
    }
}

/// `dup3(2)` — duplicate `oldfd` to `newfd` with optional flags
/// (typically `O_CLOEXEC`). Used to wire pipes onto stdin/stdout/
/// stderr in the child between Fork and Execve.
#[allow(non_snake_case)]
pub fn Dup3(oldfd: i32, newfd: i32, flags: i32) -> i32 {
    unsafe { syscall3(SYS_DUP3, oldfd as usize, newfd as usize, flags as usize) as i32 }
}

/// Leave a forked child that could not exec. `exit(2)` — the thread
/// exit, which in a freshly forked child is the whole process, since
/// the child has exactly one thread. A wrapper rather than the raw
/// `syscall1(SYS_EXIT, …)` `os::exec` used to write, because Darwin
/// has no raw entry point: its sibling is `_exit(2)` through libSystem.
#[allow(non_snake_case)]
pub fn ForkExit(code: i32) -> ! {
    unsafe {
        syscall1(SYS_EXIT, code as usize);
        core::hint::unreachable_unchecked()
    }
}

// ─── stat / fstat (Linux x86_64 layout) ──────────────────────────────


/// File mode bits (from <sys/stat.h>). Used by `Stat_t.st_mode`.
pub const S_IFMT: u32 = 0o170000;
pub const S_IFDIR: u32 = 0o040000;
pub const S_IFREG: u32 = 0o100000;
pub const S_IFLNK: u32 = 0o120000;
pub const S_IFBLK: u32 = 0o060000;
pub const S_IFCHR: u32 = 0o020000;
pub const S_IFIFO_M: u32 = 0o010000;
pub const S_IFSOCK_M: u32 = 0o140000;
/// setuid / setgid / sticky, the three bits above the permission
/// triplets that `FileMode` carries as u / g / t.
pub const S_ISUID: u32 = 0o4000;
pub const S_ISGID: u32 = 0o2000;
pub const S_ISVTX: u32 = 0o1000;

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

// go: none — goish-only: the raw form of openat(2), for callers that
// already hold a NUL-terminated buffer and want the errno rather than
// an `error`. `Openat` above is the Go-shaped API (Go string in,
// `(fd, error)` out) and is what a port of Go code should call; this
// is the internal one `os::Root`'s walk uses, because that walk runs
// once per path COMPONENT and needs to branch on ELOOP/ENOTDIR
// directly to decide whether to follow a symlink.
/// `openat(dirfd, path, flags, mode)` — open `path` RELATIVE to the
/// directory `dirfd` refers to, rather than to the process cwd.
/// `path` must be NUL-terminated; returns the fd or the raw -errno.
///
/// The relative resolution is the point. A path resolved against a
/// directory fd cannot be redirected by anything that happens to the
/// process cwd, and combined with O_NOFOLLOW it is how `os.Root`
/// refuses a traversal instead of merely detecting one.
#[allow(non_snake_case)]
pub fn __openat_raw(dirfd: i32, path: *const u8, flags: i32, mode: i32) -> i32 {
    let r = unsafe {
        syscall4(
            SYS_OPENAT,
            dirfd as usize,
            path as usize,
            flags as usize,
            mode as usize,
        )
    };
    return r as i32; // goishlint:ignore GOISH005 — syscall ABI returns a machine word.
}

/// `fstatat(AT_FDCWD, path, &stat, 0)` — stat a path relative to CWD,
/// following symlinks. `path` must be NUL-terminated.
pub const AT_FDCWD: i32 = -100;

/// `AT_REMOVEDIR` — make `unlinkat` behave as `rmdir` rather than
/// `unlink`. The only way to remove a directory on an architecture
/// with no `rmdir` syscall.
pub const AT_REMOVEDIR: i32 = 0x200;

/// `AT_SYMLINK_NOFOLLOW` — don't traverse a final-component symlink.
/// Used by Lstat (fstatat with this flag).
pub const AT_SYMLINK_NOFOLLOW: i32 = 0x100;

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

/// `fstatat(AT_FDCWD, path, &stat, AT_SYMLINK_NOFOLLOW)` — stat a path
/// without following a final-component symlink. Mirrors `lstat(2)`.
#[allow(non_snake_case)]
pub fn Lstat(path: *const u8, out: &mut Stat_t) -> i32 {
    unsafe {
        syscall4(
            SYS_NEWFSTATAT,
            AT_FDCWD as usize,
            path as usize,
            out as *mut Stat_t as usize,
            AT_SYMLINK_NOFOLLOW as usize,
        ) as i32
    }
}

/// `lseek(fd, offset, whence)` — reposition file offset.
#[allow(non_snake_case)]
pub fn Lseek(fd: i32, offset: i64, whence: i32) -> i64 {
    unsafe { syscall3(SYS_LSEEK, fd as usize, offset as usize, whence as usize) as i64 }
}

/// `pread64(fd, buf, count, offset)` — read from file at given offset.
#[allow(non_snake_case)]
pub fn Pread64(fd: i32, buf: *mut u8, count: usize, offset: i64) -> isize {
    unsafe {
        syscall4(
            SYS_PREAD64,
            fd as usize,
            buf as usize,
            count,
            offset as usize,
        ) as isize
    }
}

/// `pwrite64(fd, buf, count, offset)` — write to file at given offset.
#[allow(non_snake_case)]
pub fn Pwrite64(fd: i32, buf: *const u8, count: usize, offset: i64) -> isize {
    unsafe {
        syscall4(
            SYS_PWRITE64,
            fd as usize,
            buf as usize,
            count,
            offset as usize,
        ) as isize
    }
}

/// `ftruncate(fd, length)` — truncate file to given length.
#[allow(non_snake_case)]
pub fn Ftruncate(fd: i32, length: i64) -> i32 {
    unsafe { syscall2(SYS_FTRUNCATE, fd as usize, length as usize) as i32 }
}

/// `flock(fd, operation)` — advisory file lock.
/// operation: LOCK_SH (shared), LOCK_EX (exclusive), LOCK_UN (unlock).
///
/// Go: `func Flock(fd int, how int) (err error)` (zsyscall_linux_*.go).
/// Goish mirrors the `int`/`int` arg shape so port-side calls don't
/// need cast preludes. Returns `nil` on success, `Errno(-rc).into()`
/// on failure.
#[allow(non_snake_case)]
pub fn Flock(fd: crate::types::int, operation: crate::types::int) -> crate::errors::error {
    let rc = unsafe { syscall2(SYS_FLOCK, fd as usize, operation as usize) as i32 };
    if rc >= 0 {
        return crate::errors::nil;
    }
    Errno(-rc).into()
}

// flock operations (linux/fcntl.h)
pub const LOCK_SH: i32 = 1;
pub const LOCK_EX: i32 = 2;
pub const LOCK_UN: i32 = 8;
pub const LOCK_NB: i32 = 4;

// ─── mkdir / unlink / rmdir / chmod / symlink / readlink ────────────


/// `mkdir(path, mode)`. Returns 0 on success, -errno on failure.
#[allow(non_snake_case)]
pub fn Mkdir(path: *const u8, mode: u32) -> i32 {
    // Go: `syscall/syscall_linux.go:279-281` routes every Linux arch
    // through the `*at` form with `AT_FDCWD`; arm64 has no legacy call
    // to route to. See `zsysnum_linux_arm64.rs`.
    unsafe { syscall3(SYS_MKDIRAT, AT_FDCWD as usize, path as usize, mode as usize) as i32 }
}

// go: none — goish-only: the `at` form, taking a NUL-terminated
// pointer and returning the raw -errno, for the reason the banner at
// the top of this file gives for every wrapper here.
/// `mkdirat(dirfd, path, mode)` — create a directory RELATIVE to
/// `dirfd`. `os.Root` needs the relative form so the path cannot be
/// redirected by anything that changes the process cwd.
#[allow(non_snake_case)]
pub fn Mkdirat(dirfd: i32, path: *const u8, mode: u32) -> i32 {
    let r = unsafe { syscall3(SYS_MKDIRAT, dirfd as usize, path as usize, mode as usize) };
    return r as i32; // goishlint:ignore GOISH005 — syscall ABI returns a machine word.
}

// go: none — goish-only: see `Mkdirat` above.
/// `unlinkat(dirfd, path, flags)` — remove a name RELATIVE to `dirfd`.
/// With `AT_REMOVEDIR` it removes a directory instead.
///
/// It removes the NAME, never what a symlink points at, which is what
/// makes `Root.Remove("link-pointing-outside")` delete the link and
/// leave the target alone.
#[allow(non_snake_case)]
pub fn Unlinkat(dirfd: i32, path: *const u8, flags: i32) -> i32 {
    let r = unsafe { syscall3(SYS_UNLINKAT, dirfd as usize, path as usize, flags as usize) };
    return r as i32; // goishlint:ignore GOISH005 — syscall ABI returns a machine word.
}

// go: none — goish-only: see `Mkdirat` above.
/// `newfstatat(dirfd, path, &stat, flags)` — stat RELATIVE to `dirfd`.
/// Pass `AT_SYMLINK_NOFOLLOW` for the Lstat form.
#[allow(non_snake_case)]
pub fn Fstatat(dirfd: i32, path: *const u8, out: &mut Stat_t, flags: i32) -> i32 {
    let r = unsafe {
        syscall4(
            SYS_NEWFSTATAT,
            dirfd as usize,
            path as usize,
            out as *mut Stat_t as usize,
            flags as usize,
        )
    };
    return r as i32; // goishlint:ignore GOISH005 — syscall ABI returns a machine word.
}

// go: none — goish-only: see `Mkdirat` above.
/// `renameat(olddirfd, old, newdirfd, new)` — rename RELATIVE to two
/// directory fds. `os.Root` resolves BOTH names through its walk and
/// passes the two parent fds here, which is why an escape in either
/// position is refused.
#[allow(non_snake_case)]
pub fn Renameat(olddirfd: i32, oldpath: *const u8, newdirfd: i32, newpath: *const u8) -> i32 {
    let r = unsafe {
        syscall4(
            SYS_RENAMEAT,
            olddirfd as usize,
            oldpath as usize,
            newdirfd as usize,
            newpath as usize,
        )
    };
    return r as i32; // goishlint:ignore GOISH005 — syscall ABI returns a machine word.
}

// go: none — goish-only: see `Mkdirat` above.
/// `linkat(olddirfd, old, newdirfd, new, flags)` — hard-link RELATIVE
/// to two directory fds. Flags is 0 here: without AT_SYMLINK_FOLLOW a
/// symlink is linked as itself, never resolved.
#[allow(non_snake_case)]
pub fn Linkat(
    olddirfd: i32,
    oldpath: *const u8,
    newdirfd: i32,
    newpath: *const u8,
    flags: i32,
) -> i32 {
    let r = unsafe {
        // syscall6 with a zero sixth argument: linkat takes five, and
        // the kernel ignores the register the sixth would occupy.
        syscall6(
            SYS_LINKAT,
            olddirfd as usize,
            oldpath as usize,
            newdirfd as usize,
            newpath as usize,
            flags as usize,
            0,
        )
    };
    return r as i32; // goishlint:ignore GOISH005 — syscall ABI returns a machine word.
}

// go: none — goish-only: see `Mkdirat` above.
/// `symlinkat(target, newdirfd, linkpath)` — create a symlink RELATIVE
/// to `newdirfd`.
///
/// The TARGET is not resolved and not checked: it is bytes stored in
/// the link. That is why `Root.Symlink("/etc/passwd", …)` succeeds and
/// creates a link the same Root then refuses to follow.
#[allow(non_snake_case)]
pub fn Symlinkat(target: *const u8, newdirfd: i32, linkpath: *const u8) -> i32 {
    let r = unsafe {
        syscall3(
            SYS_SYMLINKAT,
            target as usize,
            newdirfd as usize,
            linkpath as usize,
        )
    };
    return r as i32; // goishlint:ignore GOISH005 — syscall ABI returns a machine word.
}

// go: none — goish-only: see `Mkdirat` above.
/// `fchdir(fd)` — make the directory `fd` refers to the process cwd.
/// Returns 0 or the raw -errno.
#[allow(non_snake_case)]
pub fn Fchdir(fd: i32) -> i32 {
    let r = unsafe { syscall1(SYS_FCHDIR, fd as usize) };
    return r as i32; // goishlint:ignore GOISH005 — syscall ABI returns a machine word.
}

// go: none — goish-only: see `Mkdirat` above.
/// `fchown(fd, uid, gid)` — change the owner of an OPEN file, so the
/// answer cannot be redirected by a rename between the check and the
/// call.
#[allow(non_snake_case)]
pub fn Fchown(fd: i32, uid: u32, gid: u32) -> i32 {
    let r = unsafe { syscall3(SYS_FCHOWN, fd as usize, uid as usize, gid as usize) };
    return r as i32; // goishlint:ignore GOISH005 — syscall ABI returns a machine word.
}

// go: none — goish-only: see `Mkdirat` above.
/// `fchmodat(dirfd, path, mode, flags)` — chmod RELATIVE to `dirfd`.
#[allow(non_snake_case)]
pub fn Fchmodat(dirfd: i32, path: *const u8, mode: u32, flags: i32) -> i32 {
    let r = unsafe {
        syscall4(
            SYS_FCHMODAT,
            dirfd as usize,
            path as usize,
            mode as usize,
            flags as usize,
        )
    };
    return r as i32; // goishlint:ignore GOISH005 — syscall ABI returns a machine word.
}

// go: none — goish-only: see `Mkdirat` above.
/// `fchownat(dirfd, path, uid, gid, flags)` — chown RELATIVE to
/// `dirfd`. `AT_SYMLINK_NOFOLLOW` gives the Lchown form, which changes
/// the LINK rather than what it points at.
#[allow(non_snake_case)]
pub fn Fchownat(dirfd: i32, path: *const u8, uid: u32, gid: u32, flags: i32) -> i32 {
    let r = unsafe {
        // syscall6 with a zero sixth argument; see `Linkat`.
        syscall6(
            SYS_FCHOWNAT,
            dirfd as usize,
            path as usize,
            uid as usize,
            gid as usize,
            flags as usize,
            0,
        )
    };
    return r as i32; // goishlint:ignore GOISH005 — syscall ABI returns a machine word.
}

/// `unlink(path)`. Returns 0 on success, -errno on failure.
#[allow(non_snake_case)]
pub fn Unlink(path: *const u8) -> i32 {
    // Go: `syscall/syscall_linux.go:279-281` routes every Linux arch
    // through the `*at` form with `AT_FDCWD`; arm64 has no legacy call
    // to route to. See `zsysnum_linux_arm64.rs`.
    unsafe { syscall3(SYS_UNLINKAT, AT_FDCWD as usize, path as usize, 0) as i32 }
}

/// `rmdir(path)`. Returns 0 on success, -errno on failure.
#[allow(non_snake_case)]
pub fn Rmdir(path: *const u8) -> i32 {
    // Go: `syscall/syscall_linux.go:279-281` routes every Linux arch
    // through the `*at` form with `AT_FDCWD`; arm64 has no legacy call
    // to route to. See `zsysnum_linux_arm64.rs`.
    // `AT_REMOVEDIR` is what makes `unlinkat` act as `rmdir`.
    unsafe {
        syscall3(
            SYS_UNLINKAT,
            AT_FDCWD as usize,
            path as usize,
            AT_REMOVEDIR as usize,
        ) as i32
    }
}

/// `getcwd(buf, size)`. Linux returns the length of the cwd string
/// (including the terminating NUL), or a negative errno on failure.
#[allow(non_snake_case)]
pub fn Getcwd(buf: *mut u8, size: usize) -> isize {
    unsafe { syscall2(SYS_GETCWD, buf as usize, size) as isize }
}

/// `chdir(path)`. Returns 0 on success, -errno on failure.
#[allow(non_snake_case)]
pub fn Chdir(path: *const u8) -> i32 {
    unsafe { syscall1(SYS_CHDIR, path as usize) as i32 }
}

/// `chmod(path, mode)`. Returns 0 on success, -errno on failure.
#[allow(non_snake_case)]
pub fn Chmod(path: *const u8, mode: u32) -> i32 {
    // Go: `syscall/syscall_linux.go:279-281` routes every Linux arch
    // through the `*at` form with `AT_FDCWD`; arm64 has no legacy call
    // to route to. See `zsysnum_linux_arm64.rs`.
    unsafe { syscall4(SYS_FCHMODAT, AT_FDCWD as usize, path as usize, mode as usize, 0) as i32 }
}

// go: sdk 1.25.5 syscall/zsyscall_linux_amd64.go:914-918 Umask
/// `Umask(mask)` sets the process file-creation mask and returns the previous mask.
#[allow(non_snake_case)]
pub fn Umask(mask: crate::int) -> crate::int {
    return crate::int(unsafe { syscall1(SYS_UMASK, mask as usize) }); // goishlint:ignore GOISH005 — syscall ABI requires a machine word.
}

/// `fchmod(fd, mode)`. Returns 0 on success, -errno on failure.
#[allow(non_snake_case)]
pub fn Fchmod(fd: i32, mode: u32) -> i32 {
    unsafe { syscall2(SYS_FCHMOD, fd as usize, mode as usize) as i32 }
}

/// `symlink(oldname, newname)`. Returns 0 on success, -errno on failure.
#[allow(non_snake_case)]
pub fn Symlink(oldname: *const u8, newname: *const u8) -> i32 {
    // Go: `syscall/syscall_linux.go:279-281` routes every Linux arch
    // through the `*at` form with `AT_FDCWD`; arm64 has no legacy call
    // to route to. See `zsysnum_linux_arm64.rs`.
    unsafe {
        syscall3(SYS_SYMLINKAT, oldname as usize, AT_FDCWD as usize, newname as usize) as i32
    }
}

/// File-type bits for `mknod(2)`'s mode argument (`<sys/stat.h>`).
/// Only the two a process can create without CAP_MKNOD are listed;
/// S_IFCHR and S_IFBLK need privilege.
pub const S_IFIFO: i32 = 0o010000;
pub const S_IFSOCK: i32 = 0o140000;

// go: sdk 1.25.5 syscall/syscall_linux.go:275-277 Mknod
/// `mknod(path, mode, dev)`. With `S_IFIFO` in `mode` this is `mkfifo`,
/// which is the one node type an unprivileged process may create.
/// Returns 0 or a negative errno.
#[allow(non_snake_case)]
pub fn Mknod(path: *const u8, mode: i32, dev: u64) -> i32 {
    // `mknodat(AT_FDCWD, …)`, as Go spells it — arm64 has no `mknod`.
    let rc = unsafe {
        syscall4(SYS_MKNODAT, AT_FDCWD as usize, path as usize, mode as usize, dev as usize)
    };
    return rc as i32; // goishlint:ignore GOISH005 - a raw kernel return code, not a Go value.
}

/// `readlink(path, buf, bufsiz)`. Returns the number of bytes placed in
/// buf (without NUL) on success, or a negative errno on failure.
#[allow(non_snake_case)]
pub fn Readlink(path: *const u8, buf: *mut u8, bufsiz: usize) -> isize {
    // Go: `syscall/syscall_linux.go:279-281` routes every Linux arch
    // through the `*at` form with `AT_FDCWD`; arm64 has no legacy call
    // to route to. See `zsysnum_linux_arm64.rs`.
    unsafe {
        syscall4(SYS_READLINKAT, AT_FDCWD as usize, path as usize, buf as usize, bufsiz) as isize
    }
}

// go: none — goish-only: Go's `unix.Readlinkat` takes a Go string and
// returns `(int, error)`; this takes a NUL-terminated pointer and
// returns the raw -errno, for the reason the banner at the top of this
// file gives for every wrapper here.
/// `readlinkat(dirfd, path, buf, bufsiz)` — read a symlink target
/// RELATIVE to `dirfd`. `os.Root` needs the relative form for the same
/// reason it needs openat: the answer must not depend on the process
/// cwd, which anything else in the program can change underneath it.
#[allow(non_snake_case)]
pub fn Readlinkat(dirfd: i32, path: *const u8, buf: *mut u8, bufsiz: usize) -> isize {
    return unsafe {
        syscall4(
            SYS_READLINKAT,
            dirfd as usize,
            path as usize,
            buf as usize,
            bufsiz,
        )
    };
}

/// `utimensat(dirfd, path, times, flags)` — set file access/modification
/// times with nanosecond precision. `times` points to `[atime, mtime]`;
/// a `tv_nsec` of [`UTIME_OMIT`] leaves that timestamp unchanged.
/// Returns 0 on success, -errno on failure.
#[allow(non_snake_case)]
pub fn Utimensat(dirfd: i32, path: *const u8, times: *const Timespec, flags: i32) -> i32 {
    unsafe {
        syscall4(
            SYS_UTIMENSAT,
            dirfd as usize,
            path as usize,
            times as usize,
            flags as usize,
        ) as i32
    }
}

/// `rename(oldpath, newpath)`. Returns 0 on success, -errno on failure.
#[allow(non_snake_case)]
pub fn Rename(oldpath: *const u8, newpath: *const u8) -> i32 {
    // Go: `syscall/syscall_linux.go:279-281` routes every Linux arch
    // through the `*at` form with `AT_FDCWD`; arm64 has no legacy call
    // to route to. See `zsysnum_linux_arm64.rs`.
    unsafe {
        syscall4(
            SYS_RENAMEAT,
            AT_FDCWD as usize,
            oldpath as usize,
            AT_FDCWD as usize,
            newpath as usize,
        ) as i32
    }
}

/// `link(oldpath, newpath)` — create newpath as a hard link to oldpath.
/// Returns 0 on success, -errno on failure.
#[allow(non_snake_case)]
pub fn Link(oldpath: *const u8, newpath: *const u8) -> i32 {
    // Go: `syscall/syscall_linux.go:279-281` routes every Linux arch
    // through the `*at` form with `AT_FDCWD`; arm64 has no legacy call
    // to route to. See `zsysnum_linux_arm64.rs`.
    // The trailing 0 is `flags`; `AT_SYMLINK_FOLLOW` is not set, matching
    // `link(2)`'s behaviour of not following a symlinked oldpath.
    unsafe {
        syscall6(
            SYS_LINKAT,
            AT_FDCWD as usize,
            oldpath as usize,
            AT_FDCWD as usize,
            newpath as usize,
            0,
            0,
        ) as i32
    }
}

/// `truncate(path, length)`. Returns 0 on success, -errno on failure.
#[allow(non_snake_case)]
pub fn Truncate(path: *const u8, length: i64) -> i32 {
    unsafe { syscall2(SYS_TRUNCATE, path as usize, length as usize) as i32 }
}

/// `pipe2(pipefd[2], flags)` — create a unidirectional pipe; pipefd[0]
/// is the read end, pipefd[1] is the write end. Returns 0 on success
/// or -errno. Pass `O_CLOEXEC` to set close-on-exec on both ends.
#[allow(non_snake_case)]
pub fn Pipe2(pipefd: &mut [i32; 2], flags: i32) -> i32 {
    unsafe { syscall2(SYS_PIPE2, pipefd.as_mut_ptr() as usize, flags as usize) as i32 }
}

/// `chown(path, uid, gid)` — set ownership; -1 leaves the field
/// unchanged. Returns 0 on success or -errno on failure.
#[allow(non_snake_case)]
pub fn Chown(path: *const u8, uid: i32, gid: i32) -> i32 {
    // Go: `syscall/syscall_linux.go:279-281` routes every Linux arch
    // through the `*at` form with `AT_FDCWD`; arm64 has no legacy call
    // to route to. See `zsysnum_linux_arm64.rs`.
    unsafe {
        syscall6(
            SYS_FCHOWNAT,
            AT_FDCWD as usize,
            path as usize,
            uid as usize,
            gid as usize,
            0,
            0,
        ) as i32
    }
}

/// `lchown(path, uid, gid)` — like chown, but does not follow a
/// final-component symlink. Returns 0 on success or -errno.
#[allow(non_snake_case)]
pub fn Lchown(path: *const u8, uid: i32, gid: i32) -> i32 {
    // Go: `syscall/syscall_linux.go:279-281` routes every Linux arch
    // through the `*at` form with `AT_FDCWD`; arm64 has no legacy call
    // to route to. See `zsysnum_linux_arm64.rs`.
    // `AT_SYMLINK_NOFOLLOW` is exactly what distinguishes `lchown` from
    // `chown`.
    unsafe {
        syscall6(
            SYS_FCHOWNAT,
            AT_FDCWD as usize,
            path as usize,
            uid as usize,
            gid as usize,
            AT_SYMLINK_NOFOLLOW as usize,
            0,
        ) as i32
    }
}

// ─── uname ───────────────────────────────────────────────────────────


/// Linux `struct utsname`. Each field is a NUL-padded byte array of
/// fixed length (65 on Linux). `sysname` / `nodename` / `release` /
/// `version` / `machine` / `domainname`.
#[repr(C)]
pub struct Utsname {
    pub sysname: [u8; 65],
    pub nodename: [u8; 65],
    pub release: [u8; 65],
    pub version: [u8; 65],
    pub machine: [u8; 65],
    pub domainname: [u8; 65],
}

impl Default for Utsname {
    fn default() -> Self {
        Utsname {
            sysname: [0; 65],
            nodename: [0; 65],
            release: [0; 65],
            version: [0; 65],
            machine: [0; 65],
            domainname: [0; 65],
        }
    }
}

/// `uname(2)`. Returns 0 on success, -errno on failure.
#[allow(non_snake_case)]
pub fn Uname(buf: &mut Utsname) -> i32 {
    unsafe { syscall1(SYS_UNAME, buf as *mut Utsname as usize) as i32 }
}

// ─── getrandom ───────────────────────────────────────────────────────

pub const GRND_NONBLOCK: u32 = 0x0001;
pub const GRND_RANDOM: u32 = 0x0002;
pub const GRND_INSECURE: u32 = 0x0004;

/// `getrandom(2)` — fill `buf[0..buflen]` with random bytes from the
/// kernel CSPRNG. Returns the number of bytes written, or `-errno` on
/// failure.
#[allow(non_snake_case)]
pub fn Getrandom(buf: *mut u8, buflen: usize, flags: u32) -> i64 {
    unsafe { syscall3(SYS_GETRANDOM, buf as usize, buflen, flags as usize) as i64 }
}

// ─── getdents64 ──────────────────────────────────────────────────────


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
            fd as usize, // -1 for anonymous; kernel ignores
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

/// `mprotect(2)` — change protection on a region. Used to carve
/// `PROT_NONE` guard pages out of goroutine stack reservations.
#[allow(non_snake_case)]
pub fn Mprotect(addr: *mut u8, length: usize, prot: i32) -> isize {
    unsafe { syscall3(SYS_MPROTECT, addr as usize, length, prot as usize) }
}

/// `madvise(2)` — advise the kernel about a region's usage pattern.
/// `MADV_DONTNEED` drops physical pages when a stack reservation is
/// recycled into the reserve pool.
#[allow(non_snake_case)]
pub fn Madvise(addr: *mut u8, length: usize, advice: i32) -> isize {
    unsafe { syscall3(SYS_MADVISE, addr as usize, length, advice as usize) }
}

/// `recv(2)` flag: peek at incoming data without consuming it.
pub const MSG_PEEK: i32 = 0x2;
/// `recv(2)` flag: non-blocking for this call only.
pub const MSG_DONTWAIT: i32 = 0x40;

/// `recvfrom(2)` with null src-addr — i.e. `recv(2)`. Returns the
/// byte count, `0` on orderly peer shutdown, or `-errno`. Used with
/// `MSG_PEEK | MSG_DONTWAIT` by net/http's client-disconnect watcher
/// to probe a socket without consuming pipelined request bytes.
#[allow(non_snake_case)]
pub fn Recvfrom(fd: i32, buf: *mut u8, len: usize, flags: i32) -> isize {
    unsafe {
        syscall6(
            SYS_RECVFROM,
            fd as usize,
            buf as usize,
            len,
            flags as usize,
            0,
            0,
        )
    }
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


/// `getuid(2)` — real user id of the calling process.
#[allow(non_snake_case)]
pub fn Getuid() -> i32 {
    unsafe { syscall1(SYS_GETUID, 0) as i32 }
}

/// `getgid(2)` — real group id of the calling process.
#[allow(non_snake_case)]
pub fn Getgid() -> i32 {
    unsafe { syscall1(SYS_GETGID, 0) as i32 }
}

/// `geteuid(2)` — effective user id.
#[allow(non_snake_case)]
pub fn Geteuid() -> i32 {
    unsafe { syscall1(SYS_GETEUID, 0) as i32 }
}

/// `getegid(2)` — effective group id.
#[allow(non_snake_case)]
pub fn Getegid() -> i32 {
    unsafe { syscall1(SYS_GETEGID, 0) as i32 }
}

/// `getppid(2)` — parent process id.
#[allow(non_snake_case)]
pub fn Getppid() -> i32 {
    unsafe { syscall1(SYS_GETPPID, 0) as i32 }
}

/// `getgroups(2)` — list of supplementary group IDs. Linux signature:
/// `int getgroups(int size, gid_t list[])`. Returns the count on
/// success, -errno on failure. Caller passes `size=0, list=null` to
/// probe the count, then allocates and re-calls with the right size.
#[allow(non_snake_case)]
pub fn Getgroups(size: i32, list: *mut u32) -> isize {
    unsafe { syscall2(SYS_GETGROUPS, size as usize, list as usize) }
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
pub unsafe fn RtSigaction(sig: i32, new: *const Sigaction, old: *mut Sigaction) -> isize {
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
pub fn Futex(addr: *const u32, op: i32, val: u32, ts: *const Timespec) -> isize {
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
    unsafe {
        syscall3(
            SYS_SCHED_GETAFFINITY,
            pid as usize,
            cpusetsize,
            mask as usize,
        )
    }
}

/// `arch_prctl(code, addr)` — amd64-specific thread-state op. We use
/// `code = ARCH_SET_FS` with `addr = &m.tls_self` to plant the fs
/// segment base; subsequent `mov %fs:0, _` reads back the pointer
/// stored at that address (the M's address in goish's TLS layout).
///
/// Returns 0 on success, `-errno` on failure.
///
/// **amd64 only.** arm64 has no `arch_prctl` syscall at all — the thread
/// pointer lives in `TPIDR_EL0`, which is writable at EL0, so the same
/// operation is one `msr` and no kernel entry. Callers go through
/// `runtime::sched::tls::{base, set_base}` rather than calling this
/// directly, which is what keeps the difference from leaking.
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
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

/// IPPROTO_TCP option names (linux/tcp.h).
pub const TCP_NODELAY: i32 = 1;
pub const TCP_KEEPIDLE: i32 = 4;
pub const TCP_KEEPINTVL: i32 = 5;
pub const TCP_KEEPCNT: i32 = 6;

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
        Self::ipv4_host(addr, port)
    }

    /// Build from a host-order IPv4 address and a host-order port.
    ///
    /// The last constructor added, and the one that let `net/parse.rs`
    /// stop writing `SockaddrIn { .. }` literals. That matters beyond
    /// tidiness: BSD sockaddrs carry a leading `sin_len` byte and put
    /// `sin_family` in a `u8` at offset 1, so a struct literal that
    /// compiles here cannot compile on Darwin — and one that did would
    /// be silently malformed. Constructors are the portable surface.
    pub const fn ipv4_host(addr: u32, port: u16) -> Self {
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
    unsafe { syscall3(SYS_BIND, fd as usize, addr as usize, addrlen as usize) as i32 }
}

// go: none — goish-only: Go's `syscall.Sockaddr` is an interface and
// `SockaddrUnix` one of its implementations, chosen at run time by
// `bind`/`connect`. goish's wrappers are typed to `SockaddrIn`, so the
// AF_UNIX address gets its own struct and the raw-pointer entry points
// below. Layout is the kernel's `struct sockaddr_un`.
/// `struct sockaddr_un` — an AF_UNIX address.
///
/// `sun_path` is 108 bytes on Linux and that is a hard kernel limit,
/// not a convention: a longer path cannot be represented at all, which
/// is why `Listen("unix", …)` has to reject one rather than truncate.
#[repr(C)]
#[derive(Clone, Copy)]
#[allow(non_snake_case)]
pub struct SockaddrUn {
    pub sun_family: u16,
    pub sun_path: [u8; 108],
}

impl SockaddrUn {
    // go: none — goish-only: Go builds the same bytes inside
    // `SockaddrUnix.sockaddr()` (syscall/syscall_linux.go), which is a
    // method on the interface implementation goish does not have.
    /// Build an AF_UNIX address for `path`, or None when it does not
    /// fit in `sun_path` with room for the NUL the kernel expects.
    pub fn __for_path(path: &[u8]) -> Option<SockaddrUn> {
        if path.is_empty() || path.len() >= 108 {
            return None;
        }
        let mut sa = SockaddrUn {
            sun_family: crate::convert::uint16(AF_UNIX),
            sun_path: [0u8; 108],
        };
        sa.sun_path[..path.len()].copy_from_slice(path);
        return Some(sa);
    }

    // go: none — goish-only: the second return of Go's
    // `SockaddrUnix.sockaddr()`, split out because goish's callers take
    // the pointer and the length separately.
    /// The length to pass to bind/connect: the family word plus the
    /// path plus its NUL. Passing `size_of::<SockaddrUn>()` also works
    /// on Linux, but this is what Go computes and keeps abstract
    /// sockets representable later.
    pub fn __len(&self) -> u32 {
        let n = self
            .sun_path
            .iter()
            .position(|&b| b == 0)
            .unwrap_or(self.sun_path.len());
        return crate::convert::uint32(2 + n + 1);
    }
}

// go: none — goish-only: the address-family-agnostic forms. The typed
// wrappers above stay as they are; these take the raw pointer the
// syscall actually wants, so an AF_UNIX address can reach it.
/// `bind(2)` with an arbitrary sockaddr.
#[allow(non_snake_case)]
pub fn __bind_raw(fd: i32, addr: *const u8, addrlen: u32) -> i32 {
    let r = unsafe { syscall3(SYS_BIND, fd as usize, addr as usize, addrlen as usize) };
    return r as i32; // goishlint:ignore GOISH005 — syscall ABI returns a machine word.
}

// go: none — goish-only: see `__bind_raw`.
/// `connect(2)` with an arbitrary sockaddr.
#[allow(non_snake_case)]
pub fn __connect_raw(fd: i32, addr: *const u8, addrlen: u32) -> i32 {
    let r = unsafe { syscall3(SYS_CONNECT, fd as usize, addr as usize, addrlen as usize) };
    return r as i32; // goishlint:ignore GOISH005 — syscall ABI returns a machine word.
}

// go: none — goish-only: see `__bind_raw`. A NULL `addr` is legal and
// means "do not report the peer", which is what a Unix listener wants:
// a client that did not bind has no path to report anyway.
/// `accept4(2)` with an arbitrary sockaddr, or NULL.
#[allow(non_snake_case)]
pub fn __accept4_raw(fd: i32, addr: *mut u8, addrlen: *mut u32, flags: i32) -> i32 {
    let r = unsafe {
        syscall4(
            SYS_ACCEPT4,
            fd as usize,
            addr as usize,
            addrlen as usize,
            flags as usize,
        )
    };
    return r as i32; // goishlint:ignore GOISH005 — syscall ABI returns a machine word.
}

/// `getsockname(2)` into a caller buffer. 0 or `-errno`.
#[allow(non_snake_case)]
pub fn Getsockname(fd: i32, addr: *mut u8, addrlen: *mut u32) -> i32 {
    unsafe { syscall3(SYS_GETSOCKNAME, fd as usize, addr as usize, addrlen as usize) as i32 }
}

/// `getpeername(2)` into a caller buffer. 0 or `-errno`.
#[allow(non_snake_case)]
pub fn Getpeername(fd: i32, addr: *mut u8, addrlen: *mut u32) -> i32 {
    unsafe { syscall3(SYS_GETPEERNAME, fd as usize, addr as usize, addrlen as usize) as i32 }
}

/// `sendto(2)`; `addr` may be null for a connected socket. Returns the
/// byte count or `-errno`.
#[allow(non_snake_case)]
pub fn Sendto(fd: i32, buf: *const u8, len: usize, flags: i32, addr: *const u8, addrlen: u32) -> isize {
    unsafe {
        syscall6(
            SYS_SENDTO,
            fd as usize,
            buf as usize,
            len,
            flags as usize,
            addr as usize,
            addrlen as usize,
        )
    }
}

/// `recvfrom(2)` also reporting the sender. Returns the byte count or
/// `-errno`.
#[allow(non_snake_case)]
pub fn RecvfromAddr(fd: i32, buf: *mut u8, len: usize, flags: i32, addr: *mut u8, addrlen: *mut u32) -> isize {
    unsafe {
        syscall6(
            SYS_RECVFROM,
            fd as usize,
            buf as usize,
            len,
            flags as usize,
            addr as usize,
            addrlen as usize,
        )
    }
}

/// `socketpair(2)`. `ty` may carry `SOCK_NONBLOCK | SOCK_CLOEXEC`.
#[allow(non_snake_case)]
pub fn Socketpair(domain: i32, ty: i32, proto: i32, sv: &mut [i32; 2]) -> i32 {
    unsafe {
        syscall4(
            SYS_SOCKETPAIR,
            domain as usize,
            ty as usize,
            proto as usize,
            sv.as_mut_ptr() as usize,
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
pub fn Accept4(fd: i32, addr: *mut SockaddrIn, addrlen: *mut u32, flags: i32) -> i32 {
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
    unsafe { syscall3(SYS_CONNECT, fd as usize, addr as usize, addrlen as usize) as i32 }
}

/// `setsockopt(2)`. Returns `0` on success, `-errno` on failure.
#[allow(non_snake_case)]
pub fn Setsockopt(fd: i32, level: i32, name: i32, val: *const u8, len: u32) -> i32 {
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

/// `syscall.SetsockoptInt(fd, level, opt, value int) error`
/// (syscall/syscall_unix.go) — Go-shape wrapper around the raw
/// `Setsockopt` above: the value is materialised as a 4-byte int32
/// exactly like Go's `var n = int32(value); setsockopt(..., &n, 4)`.
/// Returns `nil` on success, a `syscall.Errno` on failure.
#[allow(non_snake_case)]
pub fn SetsockoptInt(
    fd: crate::int,
    level: crate::int,
    opt: crate::int,
    value: crate::int,
) -> crate::error {
    let n: i32 = value as i32;
    let rc = Setsockopt(
        fd as i32,
        level as i32,
        opt as i32,
        &n as *const i32 as *const u8,
        core::mem::size_of::<i32>() as u32,
    );
    if rc < 0 {
        return Errno(-rc).into();
    }
    crate::errors::nil
}

// ─── RawConn ─────────────────────────────────────────────────────────
//
// Go: `syscall.RawConn` (syscall/net.go:8) is the interface handed to
// `net.ListenConfig.Control` / `net.Dialer.Control` hooks so callers
// can run setsockopt(2) etc. against the raw fd before bind/connect.
//
// Goish v1 ships it as a concrete struct (the only producer is the
// pre-bind Control path in `net.ListenConfig.Listen`, where Go's
// netFD incref bookkeeping — the interface's only failure mode —
// doesn't exist yet). `Read` / `Write` (the "invoke f until it
// reports done, blocking on readiness in between" forms) are
// deferred until a consumer needs them.

/// `syscall.RawConn` (syscall/net.go:8) — raw access to a socket fd
/// inside a `net.ListenConfig.Control` hook. The fd is only
/// guaranteed valid for the duration of the callback, mirroring the
/// Go doc contract.
pub struct RawConn {
    fd: i32,
}

impl RawConn {
    pub(crate) fn __from_fd(fd: i32) -> RawConn {
        RawConn { fd }
    }

    /// `RawConn.Control(f func(fd uintptr)) error` — invoke `f` on
    /// the underlying fd. The concrete v1 carrier has no incref
    /// failure mode, so this always returns `nil`.
    #[allow(non_snake_case)]
    pub fn Control<F: Fn(crate::uintptr)>(&self, f: F) -> crate::error {
        f(self.fd as crate::uintptr);
        crate::errors::nil
    }
}

/// `getsockopt(2)`. `len` is in/out. Returns `0` on success.
#[allow(non_snake_case)]
pub fn Getsockopt(fd: i32, level: i32, name: i32, val: *mut u8, len: *mut u32) -> i32 {
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
    unsafe { syscall3(SYS_FCNTL, fd as usize, cmd as usize, arg as usize) as i32 }
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
pub fn EpollCtl(epfd: i32, op: i32, fd: i32, event: *mut EpollEvent) -> i32 {
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

// ─── inotify / fanotify (fs event notification) ──────────────────────
//
// The syscall surface behind Go's x/sys/unix inotify/fanotify API —
// what a file watcher (typescript-go internal/fswatch shape: fanotify
// preferred, inotify fallback) needs on Linux. Constants and struct
// layouts verified against golang.org/x/sys zerrors_linux*.go /
// ztypes_linux.go; syscall numbers from zsysnum_linux_amd64.go.
//
// Wrappers follow the x/sys signatures (Go-shaped, string paths,
// (value, error) returns); the raw -errno forms stay private.


// inotify flags (zerrors_linux_amd64.go).
pub const IN_CLOEXEC: i32 = 0x80000;
pub const IN_NONBLOCK: i32 = 0x800;

// inotify event masks (zerrors_linux.go).
pub const IN_MODIFY: u32 = 0x2;
pub const IN_MOVED_FROM: u32 = 0x40;
pub const IN_MOVED_TO: u32 = 0x80;
pub const IN_CREATE: u32 = 0x100;
pub const IN_DELETE: u32 = 0x200;
pub const IN_DELETE_SELF: u32 = 0x400;
pub const IN_MOVE_SELF: u32 = 0x800;
pub const IN_Q_OVERFLOW: u32 = 0x4000;
pub const IN_ONLYDIR: u32 = 0x0100_0000;
pub const IN_DONT_FOLLOW: u32 = 0x0200_0000;
pub const IN_EXCL_UNLINK: u32 = 0x0400_0000;
pub const IN_ISDIR: u32 = 0x4000_0000;

/// `unix.InotifyEvent` (ztypes_linux.go:781) — fixed header of each
/// inotify record; `Len` bytes of NUL-padded name follow it.
#[repr(C)]
#[derive(Copy, Clone, Debug, Default)]
pub struct InotifyEvent {
    pub Wd: i32,
    pub Mask: u32,
    pub Cookie: u32,
    pub Len: u32,
}

/// `unix.SizeofInotifyEvent` (ztypes_linux.go:788).
pub const SizeofInotifyEvent: usize = 0x10;

// fanotify_init flags (zerrors_linux.go).
pub const FAN_CLASS_NOTIF: u32 = 0x0;
pub const FAN_CLOEXEC: u32 = 0x1;
pub const FAN_NONBLOCK: u32 = 0x2;
pub const FAN_REPORT_FID: u32 = 0x200;
pub const FAN_REPORT_DIR_FID: u32 = 0x400;
pub const FAN_REPORT_NAME: u32 = 0x800;
pub const FAN_REPORT_DFID_NAME: u32 = 0xc00;

// fanotify event masks (zerrors_linux.go).
pub const FAN_MODIFY: u64 = 0x2;
pub const FAN_MOVED_FROM: u64 = 0x40;
pub const FAN_MOVED_TO: u64 = 0x80;
pub const FAN_CREATE: u64 = 0x100;
pub const FAN_DELETE: u64 = 0x200;
pub const FAN_DELETE_SELF: u64 = 0x400;
pub const FAN_MOVE_SELF: u64 = 0x800;
pub const FAN_Q_OVERFLOW: u64 = 0x20;
pub const FAN_EVENT_ON_CHILD: u64 = 0x0800_0000;
pub const FAN_RENAME: u64 = 0x1000_0000;
pub const FAN_ONDIR: u64 = 0x4000_0000;

// fanotify_mark flags (zerrors_linux.go).
pub const FAN_MARK_ADD: u32 = 0x1;
pub const FAN_MARK_REMOVE: u32 = 0x2;
pub const FAN_MARK_DONT_FOLLOW: u32 = 0x4;
pub const FAN_MARK_ONLYDIR: u32 = 0x8;

// fanotify info-record types (zerrors_linux.go).
pub const FAN_EVENT_INFO_TYPE_FID: u8 = 0x1;
pub const FAN_EVENT_INFO_TYPE_DFID_NAME: u8 = 0x2;
pub const FAN_EVENT_INFO_TYPE_DFID: u8 = 0x3;
pub const FAN_EVENT_INFO_TYPE_OLD_DFID_NAME: u8 = 0xa;
pub const FAN_EVENT_INFO_TYPE_NEW_DFID_NAME: u8 = 0xc;

/// `unix.FANOTIFY_METADATA_VERSION` (zerrors_linux.go).
pub const FANOTIFY_METADATA_VERSION: u8 = 0x3;

/// `unix.FanotifyEventMetadata` (ztypes_linux.go:2496) — fixed
/// header of each fanotify record (`Event_len` covers the trailing
/// info records in FID-reporting modes).
#[repr(C)]
#[derive(Copy, Clone, Debug, Default)]
pub struct FanotifyEventMetadata {
    pub Event_len: u32,
    pub Vers: u8,
    pub Reserved: u8,
    pub Metadata_len: u16,
    pub Mask: u64,
    pub Fd: i32,
    pub Pid: i32,
}

/// `unix.FanotifyEventInfoHeader` (ztypes_linux.go) — header of each
/// variable-length info record following the metadata in
/// FAN_REPORT_* modes.
#[repr(C)]
#[derive(Copy, Clone, Debug, Default)]
pub struct FanotifyEventInfoHeader {
    pub Info_type: u8,
    pub Pad: u8,
    pub Len: u16,
}

// NUL-terminate a goish string for the kernel.
fn __c_path(path: crate::string) -> alloc::vec::Vec<u8> {
    let mut v = alloc::vec::Vec::with_capacity(path.as_bytes().len() + 1);
    v.extend_from_slice(path.as_bytes());
    v.push(0);
    v
}

/// `unix.InotifyInit1(flags)` — create an inotify instance.
pub fn InotifyInit1(flags: crate::int) -> (crate::int, crate::error) {
    let rc = unsafe { syscall1(SYS_INOTIFY_INIT1, flags as usize) };
    if rc < 0 {
        return (-1, Errno(-(rc as i32)).into());
    }
    (rc as crate::int, crate::errors::nil)
}

/// `unix.InotifyAddWatch(fd, pathname, mask)` — add or modify a
/// watch; returns the watch descriptor.
pub fn InotifyAddWatch<P: Into<crate::string>>(
    fd: crate::int,
    pathname: P,
    mask: u32,
) -> (crate::int, crate::error) {
    let p = __c_path(pathname.into());
    let rc = unsafe {
        syscall3(
            SYS_INOTIFY_ADD_WATCH,
            fd as usize,
            p.as_ptr() as usize,
            mask as usize,
        )
    };
    if rc < 0 {
        return (-1, Errno(-(rc as i32)).into());
    }
    (rc as crate::int, crate::errors::nil)
}

/// `unix.InotifyRmWatch(fd, watchdesc)` — remove a watch.
pub fn InotifyRmWatch(fd: crate::int, watchdesc: u32) -> (crate::int, crate::error) {
    let rc = unsafe { syscall2(SYS_INOTIFY_RM_WATCH, fd as usize, watchdesc as usize) };
    if rc < 0 {
        return (-1, Errno(-(rc as i32)).into());
    }
    (rc as crate::int, crate::errors::nil)
}

/// `unix.FanotifyInit(flags, event_f_flags)` — create a fanotify
/// group. Most reporting modes need CAP_SYS_ADMIN; unprivileged
/// callers get EPERM (the watcher's cue to fall back to inotify).
pub fn FanotifyInit(flags: u32, event_f_flags: u32) -> (crate::int, crate::error) {
    let rc = unsafe { syscall2(SYS_FANOTIFY_INIT, flags as usize, event_f_flags as usize) };
    if rc < 0 {
        return (-1, Errno(-(rc as i32)).into());
    }
    (rc as crate::int, crate::errors::nil)
}

/// `unix.FanotifyMark(fd, flags, mask, dirFd, pathname)` — add,
/// remove, or flush marks. An empty `pathname` marks `dirFd` itself
/// (NULL path, as the kernel expects).
pub fn FanotifyMark<P: Into<crate::string>>(
    fd: crate::int,
    flags: u32,
    mask: u64,
    dirFd: crate::int,
    pathname: P,
) -> crate::error {
    let path: crate::string = pathname.into();
    let (pptr, _keep);
    if path.as_bytes().is_empty() {
        pptr = 0usize;
        _keep = alloc::vec::Vec::new();
    } else {
        let v = __c_path(path);
        pptr = v.as_ptr() as usize;
        _keep = v;
    }
    let rc = unsafe {
        syscall6(
            SYS_FANOTIFY_MARK,
            fd as usize,
            flags as usize,
            mask as usize,
            dirFd as usize,
            pptr,
            0,
        )
    };
    if rc < 0 {
        return Errno(-(rc as i32)).into();
    }
    crate::errors::nil
}

// ─── name_to_handle_at (fanotify FID decoding) ───────────────────────

/// Kernel MAX_HANDLE_SZ.
const MAX_HANDLE_SZ: usize = 128;

#[repr(C)]
struct RawFileHandle {
    handle_bytes: u32,
    handle_type: i32,
    f_handle: [u8; MAX_HANDLE_SZ],
}

/// `unix.FileHandle` (syscall_linux.go:2275) — an opaque fs object
/// handle, as produced by [`NameToHandleAt`] and embedded in
/// fanotify FID info records.
#[derive(Clone, Default)]
pub struct FileHandle {
    handle_type: i32,
    bytes: crate::slice<u8>,
}

impl core::fmt::Debug for FileHandle {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "FileHandle{{type: {}, {} bytes}}",
            self.handle_type,
            self.bytes.as_ref().len()
        )
    }
}

impl FileHandle {
    /// `unix.NewFileHandle(handleType, bytes)`.
    pub fn New(handle_type: i32, bytes: crate::slice<u8>) -> FileHandle {
        FileHandle { handle_type, bytes }
    }
    /// `FileHandle.Type()`.
    pub fn Type(&self) -> i32 {
        self.handle_type
    }
    /// `FileHandle.Bytes()`.
    pub fn Bytes(&self) -> crate::slice<u8> {
        self.bytes.clone()
    }
    /// `FileHandle.Size()`.
    pub fn Size(&self) -> crate::int {
        self.bytes.as_ref().len() as crate::int
    }
}

/// `unix.NameToHandleAt(dirfd, path, flags)` (syscall_linux.go:2302)
/// — returns a FileHandle for the object at `path` plus the mount ID
/// it lives on. EOPNOTSUPP on filesystems without export support.
pub fn NameToHandleAt<P: Into<crate::string>>(
    dirfd: crate::int,
    path: P,
    flags: crate::int,
) -> (FileHandle, crate::int, crate::error) {
    let p = __c_path(path.into());
    let mut raw = RawFileHandle {
        handle_bytes: MAX_HANDLE_SZ as u32,
        handle_type: 0,
        f_handle: [0; MAX_HANDLE_SZ],
    };
    let mut mount_id: i32 = 0;
    let rc = unsafe {
        syscall6(
            SYS_NAME_TO_HANDLE_AT,
            dirfd as usize,
            p.as_ptr() as usize,
            &mut raw as *mut RawFileHandle as usize,
            &mut mount_id as *mut i32 as usize,
            flags as usize,
            0,
        )
    };
    if rc < 0 {
        return (FileHandle::default(), 0, Errno(-(rc as i32)).into());
    }
    let n = (raw.handle_bytes as usize).min(MAX_HANDLE_SZ);
    (
        FileHandle {
            handle_type: raw.handle_type,
            bytes: crate::slice::__from_vec(raw.f_handle[..n].to_vec()),
        },
        mount_id as crate::int,
        crate::errors::nil,
    )
}

// ─── poll(2) + statfs(2) (watcher support calls) ─────────────────────

/// `unix.POLLIN`.
pub const POLLIN: i16 = 0x1;
/// `unix.POLLERR`.
pub const POLLERR: i16 = 0x8;
/// `unix.POLLHUP`.
pub const POLLHUP: i16 = 0x10;
/// `unix.POLLNVAL`.
pub const POLLNVAL: i16 = 0x20;

/// `unix.PollFd` — one entry of the poll(2) fd set.
#[repr(C)]
#[derive(Copy, Clone, Debug, Default)]
pub struct PollFd {
    pub Fd: i32,
    pub Events: i16,
    pub Revents: i16,
}

/// `unix.Poll(fds, timeout)` — wait for events on the fd set;
/// `timeout` in milliseconds, negative = infinite. Returns the
/// number of ready fds.
pub fn Poll(fds: &mut [PollFd], timeout: crate::int) -> (crate::int, crate::error) {
    // `ppoll` rather than `poll`: arm64 has no `poll` syscall. The
    // timeout changes shape with it — milliseconds as an `int` become a
    // `Timespec`, and "infinite" becomes a NULL pointer rather than a
    // negative number.
    let ts = Timespec {
        tv_sec: (timeout as i64) / 1000,
        tv_nsec: ((timeout as i64) % 1000) * 1_000_000,
    };
    let tsp = if timeout < 0 {
        core::ptr::null()
    } else {
        &ts as *const Timespec
    };
    let rc = unsafe {
        syscall4(
            SYS_PPOLL,
            fds.as_mut_ptr() as usize,
            fds.len(),
            tsp as usize,
            // sigmask = NULL, so ppoll's signal-mask swap is a no-op and
            // the call is behaviourally identical to poll(2). The 5th
            // argument (sigsetsize) is only read when sigmask is
            // non-NULL, so a 4-argument call is well-formed here.
            0,
        )
    };
    if rc < 0 {
        return (0, Errno(-(rc as i32)).into());
    }
    (rc as crate::int, crate::errors::nil)
}

/// Linux x86-64 `struct statfs` (`unix.Statfs_t`).
#[repr(C)]
#[derive(Copy, Clone, Debug, Default)]
pub struct Statfs_t {
    pub Type: i64,
    pub Bsize: i64,
    pub Blocks: u64,
    pub Bfree: u64,
    pub Bavail: u64,
    pub Files: u64,
    pub Ffree: u64,
    pub Fsid: [i32; 2],
    pub Namelen: i64,
    pub Frsize: i64,
    pub Flags: i64,
    pub Spare: [i64; 4],
}

/// `unix.Statfs(path, buf)` — filesystem statistics for the fs
/// containing `path` (watchers check `buf.Type` for supported
/// filesystems).
pub fn Statfs<P: Into<crate::string>>(path: P, buf: &mut Statfs_t) -> crate::error {
    let p = __c_path(path.into());
    let rc = unsafe {
        syscall2(
            SYS_STATFS,
            p.as_ptr() as usize,
            buf as *mut Statfs_t as usize,
        )
    };
    if rc < 0 {
        return Errno(-(rc as i32)).into();
    }
    crate::errors::nil
}

// ─── interval timers (runtime/pprof CPU sampling) ────────────────────

// go: none — goish-only: the ITIMER_* selectors, which live in the Go
// runtime's own itimer constants rather than package syscall.
/// `ITIMER_REAL` — counts wall-clock time, delivers SIGALRM.
pub const ITIMER_REAL: i32 = 0;
/// `ITIMER_VIRTUAL` — counts CPU time in user mode only, SIGVTALRM.
pub const ITIMER_VIRTUAL: i32 = 1;
/// `ITIMER_PROF` — counts CPU time in user AND system mode, delivering
/// SIGPROF. This is the one a CPU profile uses: a profile that ignored
/// kernel time would attribute nothing to a syscall-heavy function.
pub const ITIMER_PROF: i32 = 2;

// go: none — goish-only: Go's `syscall.Timeval` exists, but
// `setitimer` takes a PAIR of them and Go's runtime uses its own
// `itimerval` rather than exporting one.
/// `struct itimerval` — the reload interval and the time until the
/// next expiry. Setting `it_value` to zero DISARMS the timer, which is
/// how a profile stops.
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct Itimerval {
    pub it_interval: crate::os::exec_posix::Timeval,
    pub it_value: crate::os::exec_posix::Timeval,
}

// go: none — goish-only: Go declares `setitimer` in the RUNTIME
// (runtime/os_linux.go line 437), unexported and //go:noescape, not in
// package syscall — a Go program cannot call it. goish's profiler
// needs it, so it is a syscall wrapper here with the errno convention
// the rest of this file uses.
/// `setitimer(which, new, old)` — arm or disarm an interval timer.
/// Returns 0 or a negative `-errno`.
#[allow(non_snake_case)]
pub fn Setitimer(which: i32, new: *const Itimerval, old: *mut Itimerval) -> i32 {
    let r = unsafe {
        syscall3(
            SYS_SETITIMER,
            which as usize,
            new as usize,
            old as usize,
        )
    };
    return r as i32; // goishlint:ignore GOISH005 — syscall ABI returns a machine word.
}
