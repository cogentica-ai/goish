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
// **Stack size policy (M26 / phase 1).**
//
// Default stack is **2 KiB nominal**, matching Go's `stackMin`
// (`runtime/stack.go:76`). Linux's mmap is page-granular (4 KiB on
// x86_64), so a 2 KiB request actually consumes one page (4 KiB) of
// virtual memory. Physical RSS for an idle/parked goroutine stays at
// ~one page until the stack is actually touched (lazy paging).
//
// Goish does **not** implement Go's `morestack` growth (no compiler
// hooks). The stack you request is the stack you get; overflow
// silently corrupts adjacent memory unless a guard page is added
// (Phase γ — separate work). For deep call chains, the user must
// bump the size explicitly via `go!(stack(N), closure)`.
//
// **Why 2 KiB default**: targeting workloads with ~1M goroutines.
// 1M × 4 KiB virtual = 4 GiB; physical RSS is bounded by actual
// stack usage on touched pages. A larger default (e.g. 64 KiB)
// would push virtual to 64 GiB and touch many more pages on
// goroutines that spawn deep frames.
//
// To approach true 2 KiB density (sub-page), Phase 2 will port Go's
// `stackpool` (`runtime/stack.go:194`) — chunked allocator carving
// 2 K / 4 K / 8 K / 16 K / 32 K stacks from larger mmap'd spans.

use crate::syscall;

/// Default per-G stack size in bytes (M26): 2 KiB nominal.
/// Page-rounded to 4 KiB at mmap time on x86_64.
pub const DEFAULT_STACK_SIZE: usize = 2 * 1024;

/// Legacy alias — pre-M26 every G got exactly 64 KiB. Kept so any
/// out-of-tree callers continue to compile, but new code should use
/// `DEFAULT_STACK_SIZE` or pass an explicit size to `Stack::new_sized`.
#[deprecated(note = "use DEFAULT_STACK_SIZE or Stack::new_sized(N)")]
pub const STACK_SIZE: usize = 64 * 1024;

/// Page granularity (mmap minimum allocation). Used to round
/// caller-requested stack sizes up to a whole page.
pub const PAGE_SIZE: usize = 4096;

/// A goroutine stack. The storage source depends on `owned` and
/// `pool_span_idx`:
///
///   - `owned == false`              → adopted OS-thread stack
///                                     (`g0` only). Drop is a no-op.
///   - `pool_span_idx != 0`          → carved from
///                                     `runtime::sched::stackpool` —
///                                     a sub-page slot inside a
///                                     mmap'd 32 KiB span. Drop
///                                     returns the slot to the pool.
///   - `owned == true && pool_span_idx == 0`
///                                   → direct mmap (large stack >
///                                     32 KiB). Drop munmaps.
pub struct Stack {
    base: *mut u8,
    size: usize,
    owned: bool,
    /// Stackpool span index, or `0` (`stackpool::NIL_SPAN`) for
    /// direct-mmap'd stacks.
    pool_span_idx: u32,
}

unsafe impl Send for Stack {}

impl Stack {
    /// Allocate a fresh stack at the **default size** (2 KiB nominal,
    /// page-rounded to 4 KiB). Returns a `Stack` whose `top()` is
    /// page-aligned (and therefore 16-byte aligned, suitable for
    /// `make_context`).
    pub fn new() -> Self {
        Self::new_sized(DEFAULT_STACK_SIZE)
    }

    /// Allocate a fresh stack of `requested` bytes.
    ///
    /// **M26 phase 2 routing**:
    ///   - `requested ≤ 32 KiB`  → carved from the chunked
    ///     `stackpool` (sub-page slots inside a 32 KiB span).
    ///     A 2 KiB request truly costs 2 KiB.
    ///   - `requested > 32 KiB`  → direct page-aligned mmap (large
    ///     path).
    ///
    /// In both cases the returned `Stack`'s `top()` is 16-byte aligned
    /// (suitable for `make_context`).
    pub fn new_sized(requested: usize) -> Self {
        let bytes = requested.max(1);
        if let Some(order) = super::stackpool::order_for(bytes) {
            // Sub-page chunked path: round up to the nearest stack
            // class, draw from the pool.
            let (base, span_idx, size) = unsafe { super::stackpool::alloc(order) };
            return Stack {
                base,
                size,
                owned: true,
                pool_span_idx: span_idx,
            };
        }
        // Large path: page-aligned direct mmap.
        let size = round_up_to_page(bytes);
        let p = syscall::Mmap(
            core::ptr::null_mut(),
            size,
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
            size,
            owned: true,
            pool_span_idx: super::stackpool::NIL_SPAN,
        }
    }

    /// M17b-ε.α: adopt pre-existing stack bounds without owning them.
    /// Used by `m.g0`: the OS-thread stack (main thread or a cloned
    /// worker thread's mmap) provides the storage, and `g0`'s `Stack`
    /// is just a non-owning view that records `(base, size)` so that
    /// `getg() == m.g0` discrimination via rsp-range works the same
    /// way as it does for user-G stacks.
    ///
    /// Drop on a non-owning Stack is a no-op — the underlying memory
    /// is reclaimed by `exit_group(2)` (worker stacks) or by the
    /// kernel at process exit (main stack).
    ///
    /// Mirrors Go's pattern: `mp.g0.stack.{lo, hi}` is set to the
    /// thread's stack bounds in `mstart0`/`needm` without allocating
    /// a separate mmap region.
    pub fn adopted(base: *mut u8, size: usize) -> Self {
        Stack {
            base,
            size,
            owned: false,
            pool_span_idx: super::stackpool::NIL_SPAN,
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

    /// Allocated stack size in bytes (post page-rounding).
    pub fn size(&self) -> usize {
        self.size
    }
}

/// Round `n` up to the nearest multiple of `PAGE_SIZE`.
#[inline]
const fn round_up_to_page(n: usize) -> usize {
    (n + PAGE_SIZE - 1) & !(PAGE_SIZE - 1)
}

impl Drop for Stack {
    fn drop(&mut self) {
        if !self.owned {
            return;
        }
        if self.pool_span_idx != super::stackpool::NIL_SPAN {
            // Pool-managed: return slot to the stackpool. The pool
            // will munmap the span when fully empty.
            unsafe { super::stackpool::free(self.pool_span_idx, self.base); }
        } else {
            // Direct-mmap'd large stack.
            syscall::Munmap(self.base, self.size);
        }
    }
}

/// M17b-ε.α: parse the main thread's stack bounds from
/// `/proc/self/maps`. Reads the file in 4 KiB chunks looking for the
/// `[stack]` line (kernel marks the *initial* thread's stack with
/// that label). Returns `Some((base, size))` on success.
///
/// Linux gives no easier interface to query the initial thread's
/// stack:
///   - `getrlimit(RLIMIT_STACK)` returns the *limit*, not where the
///     kernel mapped it.
///   - `pthread_getattr_np` is glibc-only.
///   - `auxv` has `AT_PHENT`/`AT_BASE` etc., but no AT_STACK on Linux.
///
/// The mapping is stable for the process's lifetime — the kernel
/// never unmaps the main thread's stack — so a one-shot read at
/// `setup_main_tls` time is sufficient.
///
/// Caller-provided buffer (`buf`) avoids an alloc; 16 KiB is enough
/// to capture the early lines of /proc/self/maps where the [stack]
/// entry typically sits.
pub fn parse_main_stack_bounds(buf: &mut [u8]) -> Option<(*mut u8, usize)> {
    // /proc/self/maps as a NUL-terminated path
    static PATH: &[u8] = b"/proc/self/maps\0";
    let fd = syscall::Open(PATH.as_ptr(), syscall::O_RDONLY | syscall::O_CLOEXEC, 0);
    if fd < 0 {
        return None;
    }
    // Drain into buf (one read; kernel returns whatever fits).
    let mut total = 0usize;
    loop {
        if total >= buf.len() {
            break;
        }
        let n = syscall::Read(
            fd,
            unsafe { buf.as_mut_ptr().add(total) },
            buf.len() - total,
        );
        if n <= 0 {
            break;
        }
        total += n as usize;
    }
    syscall::Close(fd);

    // Scan for "[stack]" line, parse "BASE-TOP " hex pair from line head.
    let data = &buf[..total];
    let needle = b"[stack]";
    let mut i = 0;
    while i + needle.len() <= data.len() {
        if &data[i..i + needle.len()] == needle {
            // Walk back to start of line.
            let mut s = i;
            while s > 0 && data[s - 1] != b'\n' {
                s -= 1;
            }
            // Parse "<base_hex>-<top_hex>" at start of line.
            let mut p = s;
            let base = parse_hex(data, &mut p);
            if p >= data.len() || data[p] != b'-' {
                return None;
            }
            p += 1;
            let top = parse_hex(data, &mut p);
            if base == 0 || top <= base {
                return None;
            }
            return Some((base as *mut u8, top - base));
        }
        i += 1;
    }
    None
}

fn parse_hex(data: &[u8], p: &mut usize) -> usize {
    let mut v = 0usize;
    while *p < data.len() {
        let c = data[*p];
        let nibble = match c {
            b'0'..=b'9' => (c - b'0') as usize,
            b'a'..=b'f' => (c - b'a' + 10) as usize,
            b'A'..=b'F' => (c - b'A' + 10) as usize,
            _ => break,
        };
        v = (v << 4) | nibble;
        *p += 1;
    }
    v
}
