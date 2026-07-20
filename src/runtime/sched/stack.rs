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
//   - **Guard pages.** A separately-mmap'd stack lets us leave a
//     `PROT_NONE` guard page below it so stack overflow faults (and
//     gets a symbolized diagnostic from `runtime::segv`) rather than
//     silently corrupting adjacent memory. Reserved stacks and large
//     direct-mmap stacks carry a guard; sub-page pool carves cannot
//     (several stacks share one physical page).
//
// **Stack size policy (M29 — reserve-big, commit-lazy).**
//
// Goish cannot implement Go's `morestack`: stack copying requires
// relocating every pointer into the stack (Go has GC stack maps;
// Rust code holds raw pointers/references the runtime cannot see),
// and stable Rust offers no compiler hook to insert prologue checks.
// The stacker-style pivot ladder (`runtime::sched::grow`) works but
// only at annotated call sites — it can't make bare `go!()` safe for
// arbitrary code.
//
// What x86-64 Linux *does* give us is cheap virtual address space
// with kernel-side lazy commit: an anonymous private mapping costs
// physical pages only as they're first touched, at 4 KiB
// granularity. So the default goroutine stack is a **large virtual
// reservation** (`BARE_STACK_RESERVE`, 1 MiB) mapped with
// `MAP_NORESERVE` and a `PROT_NONE` guard page at the bottom:
//
//   - Depth is transparent: recursion, big locals, fmt machinery all
//     just touch more pages — no annotations, no `stack(N)` tuning.
//   - Physical cost ≈ pages actually touched (≥ 1 page once the G
//     runs). An idle shallow goroutine costs 4 KiB physical.
//   - Overflow beyond the reservation hits the guard page →
//     `runtime::segv` prints "stack overflow, spawned at file:line".
//
// Dead reservations are recycled through `RESERVE_POOL` (below):
// `MADV_DONTNEED` drops their physical pages, the virtual region is
// reused by the next spawn without mmap/munmap churn.
//
// **Density workloads keep the pool-carve path**: `go!(stack(2*KB))`
// draws a sub-page slot from `runtime::sched::stackpool` (2 KiB
// truly costs 2 KiB, no per-G VMA). That's the opt-in for 1M-G
// workloads, where per-G mmap would exhaust `vm.max_map_count`
// (default 65530, 2 VMAs per reserved stack).

use crate::runtime::spin::SpinLock;
use crate::syscall;

/// Default per-G stack size in bytes (M26): 2 KiB nominal.
/// Page-rounded to 4 KiB at mmap time on x86_64. This is the
/// *pool-carve* default used by explicit small `go!(stack(N))`
/// spawns; bare `go!()` uses `BARE_STACK_RESERVE` instead (M29).
pub const DEFAULT_STACK_SIZE: usize = 2 * 1024;

/// Default virtual reservation for a bare `go!()` goroutine stack
/// (M29). 1 MiB of `MAP_NORESERVE` address space, committed by the
/// kernel one 4 KiB page at a time as the goroutine actually touches
/// it. Matches the old auto-grow ladder's tier-3 cap, so "how deep
/// can a bare goroutine go" is unchanged — it just no longer needs
/// pivot annotations to get there.
///
/// The *live* reservation size is `bare_reserve()` below —
/// `runtime/debug::SetMaxStack` adjusts it at runtime for
/// deep-recursion workloads (compilers, tree walkers). Goroutines
/// needing a one-off size use `go!(stack(N), …)` instead.
pub const BARE_STACK_RESERVE: usize = 1024 * 1024;

/// Live reservation size for bare `go!()` stacks. Reservations are
/// `MAP_NORESERVE` + lazily committed, so raising this costs virtual
/// address space only — a 512 MiB reservation whose goroutine stays
/// shallow still occupies ~one physical page. Read at every bare
/// spawn; written by `set_bare_reserve` (the `runtime/debug::
/// SetMaxStack` backend).
static BARE_RESERVE: core::sync::atomic::AtomicUsize =
    core::sync::atomic::AtomicUsize::new(BARE_STACK_RESERVE);

/// Current bare-`go!()` stack reservation in bytes.
pub fn bare_reserve() -> usize {
    BARE_RESERVE.load(core::sync::atomic::Ordering::Acquire)
}

/// Set the reservation size used for bare `go!()` goroutines spawned
/// from now on (backend of `runtime/debug::SetMaxStack`). Returns the
/// previous value. `bytes` is page-rounded and clamped to at least
/// two pages (one usable page would fault on the first real frame).
///
/// Already-parked recycle-pool entries of the old size are munmapped
/// here so the pool never hands out a stale-size reservation; live
/// goroutines keep the reservation they were born with.
pub fn set_bare_reserve(bytes: usize) -> usize {
    let want = round_up_to_page(bytes.max(2 * PAGE_SIZE));
    let prev = BARE_RESERVE.swap(want, core::sync::atomic::Ordering::AcqRel);
    if prev != want {
        // Flush mismatched pool entries. Collect under the lock,
        // munmap after releasing it (no syscalls while spinning).
        let mut stale: alloc::vec::Vec<(usize, usize)> = alloc::vec::Vec::new();
        {
            let mut pool = RESERVE_POOL.lock();
            let mut i = 0;
            while i < pool.len() {
                if pool[i].1 != want {
                    stale.push(pool.swap_remove(i));
                } else {
                    i += 1;
                }
            }
        }
        for (addr, size) in stale {
            syscall::Munmap((addr - GUARD_SIZE) as *mut u8, size + GUARD_SIZE);
        }
    }
    prev
}

/// Guard region below reserved / large stacks: one `PROT_NONE` page.
/// Overflow lands here and `runtime::segv::classify` (which treats
/// faults within one page below `stack.base()` as home-stack
/// overflow) produces the spawn-site diagnostic.
pub const GUARD_SIZE: usize = PAGE_SIZE;

/// Max recycled reservations parked in `RESERVE_POOL`. Beyond this,
/// Drop munmaps instead. 256 × 1 MiB = 256 MiB of cached *virtual*
/// space (physical is dropped via `MADV_DONTNEED` at recycle time);
/// 512 VMAs — well under the default `vm.max_map_count` of 65530.
const RESERVE_POOL_CAP: usize = 256;

/// Legacy alias — pre-M26 every G got exactly 64 KiB. Kept so any
/// out-of-tree callers continue to compile, but new code should use
/// `DEFAULT_STACK_SIZE` or pass an explicit size to `Stack::new_sized`.
#[deprecated(note = "use DEFAULT_STACK_SIZE or Stack::new_sized(N)")]
pub const STACK_SIZE: usize = 64 * 1024;

/// Page granularity (mmap minimum allocation). Used to round
/// caller-requested stack sizes up to a whole page.
pub const PAGE_SIZE: usize = 4096;

/// A goroutine stack. The storage source depends on `owned`,
/// `pool_span_idx`, and `guarded`:
///
///   - `owned == false`              → adopted OS-thread stack
///                                     (`g0` only). Drop is a no-op.
///   - `pool_span_idx != 0`          → carved from
///                                     `runtime::sched::stackpool` —
///                                     a sub-page slot inside a
///                                     mmap'd 32 KiB span. Drop
///                                     returns the slot to the pool.
///   - `guarded == true`             → mmap of `size + GUARD_SIZE`
///                                     with a `PROT_NONE` page at the
///                                     bottom; `base` points *above*
///                                     the guard. Drop recycles
///                                     `BARE_STACK_RESERVE`-class
///                                     regions into `RESERVE_POOL`,
///                                     munmaps other sizes (guard
///                                     included).
///   - `owned == true`, unguarded,
///     `pool_span_idx == 0`          → legacy direct mmap. Drop
///                                     munmaps exactly `(base, size)`.
///
/// `base` / `size` always describe the *usable* range — guard pages
/// are excluded, so `base()`, `top()`, and `size()` need no
/// per-variant adjustment.
pub struct Stack {
    base: *mut u8,
    size: usize,
    owned: bool,
    /// Stackpool span index, or `0` (`stackpool::NIL_SPAN`) for
    /// direct-mmap'd stacks.
    pool_span_idx: u32,
    /// A `PROT_NONE` guard page sits at `base - GUARD_SIZE`; the
    /// underlying mapping starts there and Drop must account for it.
    guarded: bool,
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
            // class, draw from the pool. No guard page possible —
            // neighbouring slots share the page an overflow would
            // land on.
            let (base, span_idx, size) = unsafe { super::stackpool::alloc(order) };
            return Stack {
                base,
                size,
                owned: true,
                pool_span_idx: span_idx,
                guarded: false,
            };
        }
        // Large path: page-aligned direct mmap with a PROT_NONE guard
        // page below the usable range, so `go!(stack(N))` overflow
        // faults into the segv diagnostic instead of corrupting the
        // neighbouring mapping.
        let size = round_up_to_page(bytes);
        let usable = guarded_mmap(size);
        Stack {
            base: usable,
            size,
            owned: true,
            pool_span_idx: super::stackpool::NIL_SPAN,
            guarded: true,
        }
    }

    /// M29: allocate a bare-`go!()` stack — a `bare_reserve()`-sized
    /// (default 1 MiB, adjustable via `runtime/debug::SetMaxStack`)
    /// virtual reservation with lazy physical commit and a bottom
    /// guard page. Recycled reservations are reused from
    /// `RESERVE_POOL` without any syscalls (their guard page is
    /// already in place and their physical pages were dropped at
    /// recycle time); only same-size entries are eligible, and
    /// `set_bare_reserve` flushes mismatches, so a pooled hit always
    /// has the advertised size.
    pub fn new_reserved() -> Self {
        let want = bare_reserve();
        let recycled = {
            let mut pool = RESERVE_POOL.lock();
            let mut found = None;
            let mut i = pool.len();
            while i > 0 {
                i -= 1;
                if pool[i].1 == want {
                    found = Some(pool.swap_remove(i).0);
                    break;
                }
            }
            found
        };
        let usable = match recycled {
            Some(addr) => addr as *mut u8,
            None => guarded_mmap(want),
        };
        Stack {
            base: usable,
            size: want,
            owned: true,
            pool_span_idx: super::stackpool::NIL_SPAN,
            guarded: true,
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
            guarded: false,
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

// ─── M29: guarded mmap + reserve pool ────────────────────────────────

/// mmap `usable + GUARD_SIZE` bytes of lazily-committed anonymous
/// memory and turn the bottom page into a `PROT_NONE` guard. Returns
/// the usable base (first byte above the guard). Exits the process on
/// failure — a goroutine spawn has no error path to surface this.
fn guarded_mmap(usable: usize) -> *mut u8 {
    let total = usable + GUARD_SIZE;
    let p = syscall::Mmap(
        core::ptr::null_mut(),
        total,
        syscall::PROT_READ | syscall::PROT_WRITE,
        syscall::MAP_PRIVATE | syscall::MAP_ANONYMOUS | syscall::MAP_NORESERVE,
        -1,
        0,
    );
    if p == syscall::MAP_FAILED || (p as isize) < 0 {
        const MSG: &[u8] = b"goish: sched: stack mmap failed\n";
        syscall::Write(syscall::STDERR, MSG.as_ptr(), MSG.len());
        syscall::Exit(2);
    }
    if syscall::Mprotect(p, GUARD_SIZE, syscall::PROT_NONE) < 0 {
        const MSG: &[u8] = b"goish: sched: stack guard mprotect failed\n";
        syscall::Write(syscall::STDERR, MSG.as_ptr(), MSG.len());
        syscall::Exit(2);
    }
    unsafe { p.add(GUARD_SIZE) }
}

/// Recycled bare-`go!()` reservations, stored as `(usable_base,
/// usable_size)` pairs (guard page still protected below each; the
/// size travels with the entry so `set_bare_reserve` transitions
/// never hand out a mislabeled region). Physical pages were dropped
/// with `MADV_DONTNEED` when the entry was pushed, so a parked entry
/// costs virtual space + 2 VMAs only.
static RESERVE_POOL: SpinLock<alloc::vec::Vec<(usize, usize)>> =
    SpinLock::new(alloc::vec::Vec::new());

/// Number of reservations currently parked in the reserve pool.
/// Diagnostic — smoke tests assert recycling actually happens.
pub fn reserve_pool_len() -> usize {
    RESERVE_POOL.lock().len()
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
            return;
        }
        if self.guarded {
            let map_base = unsafe { self.base.sub(GUARD_SIZE) };
            if self.size == bare_reserve() {
                // Recycle: drop physical pages now (so RSS reflects
                // reality while the entry idles in the pool), keep
                // the virtual region + guard for the next spawn.
                // Size-checked against the *current* bare reserve, so
                // stacks born before a SetMaxStack change munmap
                // instead of poisoning the pool.
                syscall::Madvise(self.base, self.size, syscall::MADV_DONTNEED);
                let mut pool = RESERVE_POOL.lock();
                // Re-check under the lock: `set_bare_reserve` swaps
                // the size *before* taking this lock to flush, so a
                // stale push either loses the re-check here or is
                // caught by the flush — never both missed.
                if self.size == bare_reserve() && pool.len() < RESERVE_POOL_CAP {
                    pool.push((self.base as usize, self.size));
                    return;
                }
                drop(pool);
            }
            syscall::Munmap(map_base, self.size + GUARD_SIZE);
            return;
        }
        // Legacy direct-mmap'd stack (no guard).
        syscall::Munmap(self.base, self.size);
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
