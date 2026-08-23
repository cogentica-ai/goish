// runtime::heap — global allocator routing.
//
// Two tiers cooperate (post 2c+2e):
//
//   - **mheap** (Go-style page allocator from runtime::mheap) handles
//     allocations larger than 32 KiB or with alignment requirements
//     beyond what mcentral satisfies. Hands out page-aligned spans
//     of contiguous pages drawn from a fixed-size mmap'd arena.
//
//   - **mcentral** (size-class slabs from runtime::mcentral) handles
//     allocations of 32 KiB or smaller — 67 size classes drawing
//     spans from mheap.
//
// dlmalloc is gone. The bootstrap chicken-and-egg that earlier kept
// dlmalloc around (PageAlloc::new used Vec, which routes through
// GlobalAlloc, which would route to mheap during mheap's own init)
// has been resolved by switching PageAlloc's metadata storage to
// raw mmap'd memory — `super::mmap_zeroed`. With that change, no
// allocation needs to land before mheap is online.
//
// Bootstrap is now: __goish_rt0 calls mheap_init then
// mcentral_init, both of which use raw mmap rather than the global
// allocator. After both, every allocation is served by either
// mheap (large) or mcentral (small).
//
// Concurrency: each tier has its own SpinLock. Single-threaded
// today; per-P mcache (2d) will absorb most small allocations
// without ever touching the central locks once goroutines arrive
// and M16b establishes the P struct.

use crate::runtime::mheap::consts::{PAGE_SIZE, PALLOC_CHUNK_BYTES};
use crate::runtime::mheap::page_alloc::{PageAlloc, ALLOC_FAILED};
use crate::runtime::spin::SpinLock;
use crate::syscall;
use core::alloc::{GlobalAlloc, Layout};
use core::sync::atomic::{AtomicBool, Ordering};

// ─── Tunables ──────────────────────────────────────────────────────────

/// Allocations strictly above this threshold (in bytes) go through
/// mheap. Below or equal go through mcentral. Mirrors Go's
/// `gc.MaxSmallSize` (`internal/runtime/gc/sizeclasses.go:86`).
pub const LARGE_THRESHOLD: usize = 32 * 1024;

/// Initial mheap arena size — number of chunks to map up front.
/// 256 chunks × 4 MiB = 1 GiB virtual; physical RSS only grows with
/// actual usage (anonymous mmap is lazily-paged). Sized to host 1 M
/// goroutines (~450 MB G + closure heap) without re-grow plumbing.
const INITIAL_ARENA_CHUNKS: usize = 256;

/// Maximum mheap arena size — chunks the radix tree's metadata is
/// pre-sized to cover. With 4 MiB chunks, 81920 chunks is a 320 GiB
/// total heap. Demand-paging means metadata RSS scales with usage —
/// the pre-size cost is virtual address space plus ~6 MiB of bitmap
/// metadata (~73 B/chunk), not resident memory.
///
/// Raised from 512 (2 GiB) → 8192 (32 GiB) → 81920 for goish-vllm-port
/// M15: the FULL 93-layer Kimi-K3 checkpoint dequantizes ~203 GiB of
/// non-expert f32 into the heap (census against the real shard
/// headers), and the cap must clear that plus load transients. The
/// arena mapping is MAP_NORESERVE, so the reservation neither commits
/// memory nor trips overcommit accounting on boxes smaller than the
/// cap.
const MAX_ARENA_CHUNKS: usize = 81920;

// ─── mheap ────────────────────────────────────────────────────────────

static MHEAP_READY: AtomicBool = AtomicBool::new(false);
static MHEAP: SpinLock<Option<PageAlloc>> = SpinLock::new(None);

/// Map a chunk-aligned arena of `n_chunks` chunks.
unsafe fn map_arena(n_chunks: usize) -> usize {
    // Over-reserve by one chunk so we can always trim down to a
    // chunk-aligned base.
    let total = n_chunks * PALLOC_CHUNK_BYTES + PALLOC_CHUNK_BYTES;
    // MAP_NORESERVE: this is a demand-paged reservation, not a commit.
    // Without it, a 320 GiB arena mapping is refused at startup by
    // overcommit accounting on any box smaller than the cap.
    let raw = syscall::Mmap(
        core::ptr::null_mut(),
        total,
        syscall::PROT_READ | syscall::PROT_WRITE,
        syscall::MAP_PRIVATE | syscall::MAP_ANONYMOUS | syscall::MAP_NORESERVE,
        -1,
        0,
    );
    if raw == syscall::MAP_FAILED {
        const MSG: &[u8] = b"goish: mheap: mmap arena failed\n";
        syscall::Write(syscall::STDERR, MSG.as_ptr(), MSG.len());
        syscall::Exit(2);
    }
    let base = raw as usize;
    (base + PALLOC_CHUNK_BYTES - 1) & !(PALLOC_CHUNK_BYTES - 1)
}

/// One-time mheap initialization. Called from `__goish_rt0` *before*
/// user main runs.
pub unsafe fn mheap_init() {
    if MHEAP_READY.load(Ordering::Acquire) {
        return;
    }
    // Reserve the FULL max range up front: anonymous mmap is
    // demand-paged, so the cost is virtual address space only, and it
    // guarantees grow() always has contiguous room without MAP_FIXED
    // games.
    let arena_base = map_arena(MAX_ARENA_CHUNKS);
    let pages = PageAlloc::new(arena_base, INITIAL_ARENA_CHUNKS, MAX_ARENA_CHUNKS);
    *MHEAP.lock() = Some(pages);
    MHEAP_READY.store(true, Ordering::Release);
}

/// Returns the virtual base address of the mheap arena. Used by
/// mcentral to translate raw pointers into per-page indices.
pub fn mheap_arena_base() -> usize {
    let g = MHEAP.lock();
    g.as_ref().map(|p| p.arena_base).unwrap_or(0)
}

/// Page-grain mheap alloc. Public so mcentral can draw spans.
///
/// Grows the arena ON DEMAND: `PageAlloc::grow` existed but had no
/// caller, so the heap silently capped at INITIAL_ARENA_CHUNKS (1 GiB)
/// and the first real-checkpoint load died with "arena exhausted".
/// The full MAX range is reserved at init, so growth is just extending
/// the active chunk count over already-mapped, demand-paged memory.
pub unsafe fn mheap_alloc_pages(npages: usize) -> usize {
    let mut g = MHEAP.lock();
    let h = g.as_mut().unwrap_or_else(|| {
        const MSG: &[u8] = b"goish: mheap: alloc before init\n";
        syscall::Write(syscall::STDERR, MSG.as_ptr(), MSG.len());
        syscall::Exit(2);
    });
    let addr = h.alloc(npages);
    if addr != ALLOC_FAILED {
        return addr;
    }
    // Enough chunks for this request (it may not fit even in a fresh
    // region if growth were too small), plus a step to amortize.
    let need = (npages * PAGE_SIZE + PALLOC_CHUNK_BYTES - 1) / PALLOC_CHUNK_BYTES;
    let room = h.capacity_chunks() - h.end_chunk;
    let step = need.max(64).min(room);
    if step < need {
        return ALLOC_FAILED; // truly out: request exceeds MAX
    }
    h.grow(step);
    h.alloc(npages)
}

/// Total page capacity of the arena (`MAX_ARENA_CHUNKS` worth) — what
/// mcentral sizes its page → span map to, so no mheap-backed span can
/// ever be untracked.
pub fn mheap_capacity_pages() -> usize {
    let g = MHEAP.lock();
    match g.as_ref() {
        Some(h) => h.capacity_chunks() * (PALLOC_CHUNK_BYTES / PAGE_SIZE),
        None => 0,
    }
}

/// Page-grain mheap free. Public so mcentral can return empty spans.
pub unsafe fn mheap_free_pages(base: usize, npages: usize) {
    let mut g = MHEAP.lock();
    if let Some(h) = g.as_mut() {
        h.free(base, npages);
    }
}

/// Round `size` (in bytes) up to whole pages.
#[inline]
fn pages_for(size: usize) -> usize {
    (size + PAGE_SIZE - 1) / PAGE_SIZE
}

/// Allocate via mheap, panicking on OOM.
unsafe fn mheap_alloc(layout: Layout) -> *mut u8 {
    let bytes = layout.size().max(layout.align());
    let npages = pages_for(bytes);
    let addr = mheap_alloc_pages(npages);
    if addr == ALLOC_FAILED {
        const MSG: &[u8] = b"goish: mheap: arena exhausted\n";
        syscall::Write(syscall::STDERR, MSG.as_ptr(), MSG.len());
        syscall::Exit(2);
    }
    addr as *mut u8
}

/// Free a span previously returned by `mheap_alloc`.
unsafe fn mheap_free(ptr: *mut u8, layout: Layout) {
    let bytes = layout.size().max(layout.align());
    let npages = pages_for(bytes);
    mheap_free_pages(ptr as usize, npages);
}

/// True if `layout` should be served by mheap directly (large path).
#[inline]
fn route_to_mheap(layout: Layout) -> bool {
    MHEAP_READY.load(Ordering::Acquire) && layout.size() > LARGE_THRESHOLD
}

/// True if `layout` should be served by mcentral (small path).
#[inline]
fn route_to_mcentral(layout: Layout) -> bool {
    crate::runtime::mcentral::ready()
        && layout.size() > 0
        && layout.size() <= LARGE_THRESHOLD
        && layout.align() <= PAGE_SIZE
}

// ─── Go-shaped public API ──────────────────────────────────────────────

/// Allocate `size` bytes at `align` alignment. Returns null on
/// failure. `align` must be a power of two.
///
/// **Routing priority** (M17b-ε.mcache):
///   1. If `size > LARGE_THRESHOLD`: mheap directly (large path).
///   2. If a P is bound to this M and the size fits a class: try
///      `P::mcache_alloc` (per-P cached span — no central scan).
///   3. Else fall back to `mcentral::alloc` (central partial-list scan).
///   4. On all-tier OOM: round to a page and try mheap.
pub unsafe fn alloc(size: usize, align: usize) -> *mut u8 {
    // Preemption mask — same discipline as `GlobalAlloc::alloc`
    // (see the comment there); this free-fn entry is reached by
    // `realloc` and runtime-internal callers.
    crate::runtime::sched::acquirem();
    let p = alloc_masked(size, align);
    crate::runtime::sched::releasem();
    p
}

// go: none — goish-only: bytes the page allocator has handed out, for
// `runtime::MemStats.Sys` / `.HeapSys`. Go's Sys is virtual address
// space reserved from the OS; goish reports the allocated-page total,
// which is the part it actually tracks.
pub fn sys_bytes() -> usize {
    let g = MHEAP.lock();
    return match g.as_ref() {
        Some(p) => p.allocated_pages() * crate::runtime::mheap::consts::PAGE_SIZE,
        None => 0,
    };
}

/// Cumulative allocation counters, feeding `runtime::MemStats`.
///
/// Go's `Mallocs` and `TotalAlloc` are monotonic totals over the life of
/// the process, not live-heap gauges — `testing.B` samples them before
/// and after a run and subtracts, so only the delta matters and they
/// must never decrease. Incremented on the one funnel every allocation
/// passes through, below.
///
/// Relaxed ordering: these are statistics. A benchmark reading them
/// across a park may miss a concurrent allocation from another M by a
/// few counts, which is the same accuracy Go's own sampling gives.
pub(crate) static MALLOCS: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);
pub(crate) static TOTAL_ALLOC: core::sync::atomic::AtomicU64 =
    core::sync::atomic::AtomicU64::new(0);

#[inline]
unsafe fn alloc_masked(size: usize, align: usize) -> *mut u8 {
    MALLOCS.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
    TOTAL_ALLOC.fetch_add(crate::uint64(size), core::sync::atomic::Ordering::Relaxed);
    let layout = Layout::from_size_align_unchecked(size, align);
    if route_to_mheap(layout) {
        return mheap_alloc(layout);
    }
    if route_to_mcentral(layout) {
        // Per-P fast path. `current_p()` is a lock-free TLS read; only
        // valid once the runtime has bound a P to this M (post
        // `acquirep`).
        if let Some(p) = crate::runtime::sched::current_p() {
            let q = p.mcache_alloc(size, align);
            if !q.is_null() {
                return q;
            }
            // mcache miss (e.g., class refill failed). Fall through
            // to the central path which will retry with the same
            // central lock that mcache_alloc just released.
        }
        let p = crate::runtime::mcentral::alloc(size, align);
        if !p.is_null() {
            return p;
        }
        // mcentral couldn't serve (table exhausted, etc.) — fall back
        // to mheap rounding the request up to a page.
        return mheap_alloc(layout);
    }
    // Pre-init only. Round up to a page and use mheap directly.
    // In practice nothing allocates before mheap_init.
    mheap_alloc(layout)
}

/// Reallocate via alloc + memcpy + free. Preempt-masked end to end —
/// `Vec` growth funnels through here, and the copy runs against span
/// state the mask keeps owner-consistent.
pub unsafe fn realloc(ptr: *mut u8, old_size: usize, new_size: usize, align: usize) -> *mut u8 {
    crate::runtime::sched::acquirem();
    let dst = alloc_masked(new_size, align);
    if dst.is_null() {
        crate::runtime::sched::releasem();
        return dst;
    }
    let n = old_size.min(new_size);
    core::ptr::copy_nonoverlapping(ptr, dst, n);
    dealloc_routed(ptr, old_size, align);
    crate::runtime::sched::releasem();
    dst
}

/// Free a previously allocated block. Preempt-masked (see `alloc`).
pub unsafe fn free(ptr: *mut u8, size: usize) {
    crate::runtime::sched::acquirem();
    dealloc_routed(ptr, size, 8);
    crate::runtime::sched::releasem();
}

/// Internal dealloc dispatch consulting mheap then mcentral.
unsafe fn dealloc_routed(ptr: *mut u8, size: usize, align: usize) {
    let layout = Layout::from_size_align_unchecked(size, align);
    if route_to_mheap(layout) {
        mheap_free(ptr, layout);
        return;
    }
    if crate::runtime::mcentral::ready() && crate::runtime::mcentral::free(ptr) {
        return;
    }
    // Pointer wasn't owned by mcentral — must have come from a
    // pre-mcentral mheap-direct alloc.
    mheap_free(ptr, layout);
}

// ─── #[global_allocator] adapter ───────────────────────────────────────

struct GoishAllocator;

unsafe impl GlobalAlloc for GoishAllocator {
    // **Preemption mask (Go parity)**: `mallocgc` opens with
    // `mp := acquirem()` (malloc.go:1018) precisely because the
    // mcache fast path mutates owner-P-private state (`alloc_cache`,
    // `freeindex` — plain UnsafeCell writes under a "only the M
    // bound to this P touches these" discipline). Without the mask,
    // a SIGURG async preempt landing mid-`mcache_alloc` deschedules
    // the G *while it owns the span cursor*; the G resumes on
    // another M and keeps mutating a span that the original P's new
    // occupant is also allocating from. The corrupted span
    // accounting then wedges every allocating M in an
    // uncache/cacheSpan retry storm — an allocator-wide livelock
    // (all Ms at 100%, zero progress; bisected from
    // http_complex_api's per-request goroutine churn).
    // `acquirem` bumps `m.locks`, which both the SIGURG handler and
    // the cooperative-preempt check treat as "do not preempt here".
    #[inline]
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        crate::runtime::sched::acquirem();
        let p = alloc_masked(layout.size(), layout.align());
        crate::runtime::sched::releasem();
        p
    }

    #[inline]
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        crate::runtime::sched::acquirem();
        // dealloc's span mutations (`alloc_bits` clear, central list
        // moves) are lock/CAS-protected, but `mcentral::free`'s
        // last-slot release path re-reads span state across several
        // steps; keep the same non-preemptible discipline as alloc
        // (Go's `mfree` paths run under the same acquirem).
        if route_to_mheap(layout) {
            mheap_free(ptr, layout);
            crate::runtime::sched::releasem();
            return;
        }
        if crate::runtime::mcentral::ready() && crate::runtime::mcentral::free(ptr) {
            crate::runtime::sched::releasem();
            return;
        }
        mheap_free(ptr, layout);
        crate::runtime::sched::releasem();
    }

    #[inline]
    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        realloc(ptr, layout.size(), new_size, layout.align())
    }
}

#[global_allocator]
static GOISH_ALLOCATOR: GoishAllocator = GoishAllocator;
