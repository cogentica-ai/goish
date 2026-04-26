// runtime::heap — global allocator routing.
//
// Two tiers cooperate:
//
//   - **mheap** (Go-style page allocator from runtime::mheap) handles
//     allocations larger than 32 KiB or with alignment requirements
//     beyond what dlmalloc satisfies cheaply. It hands out
//     page-aligned spans of contiguous pages drawn from a fixed-size
//     mmap'd arena.
//
//   - **dlmalloc-rs** continues to serve the small path. mcentral
//     (2c) and mcache (2d) will subsume this; for 2b'-γ dlmalloc
//     stays put.
//
// The threshold mirrors Go's `gc.MaxSmallSize = 32768`. The
// `GlobalAlloc` impl and the lower-level `alloc/free/realloc` API
// share the same routing so every allocation path agrees on which
// tier owns a given block.
//
// Bootstrap (chicken-and-egg): `PageAlloc::new` itself allocates the
// summary `Vec`s through the global allocator. If routing checked
// the size and tried to use mheap before mheap exists, init would
// recurse. We avoid this with `MHEAP_READY: AtomicBool`. Set to
// `false` at startup so every alloc routes to dlmalloc until
// `mheap_init` finishes; flipped to `true` at the very end of init.
//
// Concurrency: single SpinLock around mheap state. Single-threaded
// today; goroutines/Ms will arrive in M16/M17. Per-P mcache (2d)
// will absorb 99% of small allocations without ever touching this
// lock.

use crate::runtime::mheap::consts::{PAGE_SIZE, PALLOC_CHUNK_BYTES};
use crate::runtime::mheap::page_alloc::{PageAlloc, ALLOC_FAILED};
use crate::runtime::spin::SpinLock;
use crate::syscall;
use core::alloc::{GlobalAlloc, Layout};
use core::sync::atomic::{AtomicBool, Ordering};
use dlmalloc::{Allocator, Dlmalloc};

// ─── Tunables ──────────────────────────────────────────────────────────

/// Allocations strictly above this threshold (in bytes) go through
/// mheap. Below or equal go through dlmalloc. Mirrors Go's
/// `gc.MaxSmallSize` (`internal/runtime/gc/sizeclasses.go:86`).
pub const LARGE_THRESHOLD: usize = 32 * 1024;

/// Initial mheap arena size. 64 MiB = 16 chunks. Linux demand-paging
/// means RSS is bounded by actual usage, so an oversized initial
/// arena costs only address space (cheap).
const INITIAL_ARENA_CHUNKS: usize = 16;

// ─── dlmalloc leaf allocator (small path) ──────────────────────────────

struct MmapAllocator;

unsafe impl Allocator for MmapAllocator {
    fn alloc(&self, size: usize) -> (*mut u8, usize, u32) {
        let p = syscall::Mmap(
            core::ptr::null_mut(),
            size,
            syscall::PROT_READ | syscall::PROT_WRITE,
            syscall::MAP_PRIVATE | syscall::MAP_ANONYMOUS,
            -1,
            0,
        );
        if p == syscall::MAP_FAILED {
            (core::ptr::null_mut(), 0, 0)
        } else {
            (p, size, 0)
        }
    }

    fn remap(&self, _ptr: *mut u8, _oldsize: usize, _newsize: usize, _can_move: bool) -> *mut u8 {
        core::ptr::null_mut()
    }

    fn free_part(&self, _ptr: *mut u8, _oldsize: usize, _newsize: usize) -> bool {
        false
    }

    fn free(&self, ptr: *mut u8, size: usize) -> bool {
        syscall::Munmap(ptr, size) == 0
    }

    fn can_release_part(&self, _flags: u32) -> bool {
        false
    }

    fn allocates_zeros(&self) -> bool {
        true
    }

    fn page_size(&self) -> usize {
        4096
    }
}

static SMALL_HEAP: SpinLock<Dlmalloc<MmapAllocator>> =
    SpinLock::new(Dlmalloc::new_with_allocator(MmapAllocator));

// ─── mheap (large path) ───────────────────────────────────────────────

static MHEAP_READY: AtomicBool = AtomicBool::new(false);
static MHEAP: SpinLock<Option<PageAlloc>> = SpinLock::new(None);

/// Map a chunk-aligned arena of `n_chunks` chunks.
unsafe fn map_arena(n_chunks: usize) -> usize {
    // Over-reserve by one chunk so we can always trim down to a
    // chunk-aligned base.
    let total = n_chunks * PALLOC_CHUNK_BYTES + PALLOC_CHUNK_BYTES;
    let raw = syscall::Mmap(
        core::ptr::null_mut(),
        total,
        syscall::PROT_READ | syscall::PROT_WRITE,
        syscall::MAP_PRIVATE | syscall::MAP_ANONYMOUS,
        -1,
        0,
    );
    if raw == syscall::MAP_FAILED {
        // OOM during init — fatal.
        const MSG: &[u8] = b"goish: mheap: mmap arena failed\n";
        syscall::Write(syscall::STDERR, MSG.as_ptr(), MSG.len());
        syscall::Exit(2);
    }
    let base = raw as usize;
    (base + PALLOC_CHUNK_BYTES - 1) & !(PALLOC_CHUNK_BYTES - 1)
}

/// One-time mheap initialization. Called from `__goish_rt0` *before*
/// user main runs. Idempotent — calling twice is a no-op.
///
/// During this function, every allocation routes to dlmalloc because
/// `MHEAP_READY` is still `false`; that breaks the recursion that
/// would otherwise occur when `PageAlloc::new` allocates its summary
/// Vec backing.
pub unsafe fn mheap_init() {
    if MHEAP_READY.load(Ordering::Acquire) {
        return;
    }
    let arena_base = map_arena(INITIAL_ARENA_CHUNKS);
    let pages = PageAlloc::new(arena_base, INITIAL_ARENA_CHUNKS);
    *MHEAP.lock() = Some(pages);
    MHEAP_READY.store(true, Ordering::Release);
}

/// Round `size` (in bytes) up to whole pages.
#[inline]
fn pages_for(size: usize) -> usize {
    (size + PAGE_SIZE - 1) / PAGE_SIZE
}

/// Returns the virtual base address of the mheap arena. Used by
/// mcentral to translate raw pointers into per-page indices for the
/// `page_to_span` reverse map.
pub fn mheap_arena_base() -> usize {
    let g = MHEAP.lock();
    g.as_ref().map(|p| p.arena_base).unwrap_or(0)
}

/// Page-grain mheap alloc. Public so mcentral can draw spans from
/// the same heap. Returns `ALLOC_FAILED` on OOM.
pub unsafe fn mheap_alloc_pages(npages: usize) -> usize {
    let mut g = MHEAP.lock();
    let h = g.as_mut().unwrap_or_else(|| {
        const MSG: &[u8] = b"goish: mheap: alloc before init\n";
        syscall::Write(syscall::STDERR, MSG.as_ptr(), MSG.len());
        syscall::Exit(2);
    });
    h.alloc(npages)
}

/// Page-grain mheap free. Public so mcentral can return empty spans.
pub unsafe fn mheap_free_pages(base: usize, npages: usize) {
    let mut g = MHEAP.lock();
    if let Some(h) = g.as_mut() {
        h.free(base, npages);
    }
}

/// Allocate via mheap. Returns null on OOM.
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

/// Allocate `size` bytes at `align` alignment. Returns a null pointer
/// on failure. `align` must be a power of two.
pub unsafe fn alloc(size: usize, align: usize) -> *mut u8 {
    let layout = Layout::from_size_align_unchecked(size, align);
    if route_to_mheap(layout) {
        mheap_alloc(layout)
    } else if route_to_mcentral(layout) {
        let p = crate::runtime::mcentral::alloc(size, align);
        if !p.is_null() {
            return p;
        }
        // mcentral can't serve (e.g. couldn't get a span); fall back.
        SMALL_HEAP.lock().malloc(size, align)
    } else {
        SMALL_HEAP.lock().malloc(size, align)
    }
}

/// Reallocate, preserving the first `min(old_size, new_size)` bytes.
/// Cross-tier resizes go through alloc + memcpy + free.
pub unsafe fn realloc(ptr: *mut u8, old_size: usize, new_size: usize, align: usize) -> *mut u8 {
    // Fast path: same dlmalloc tier on both ends → use dlmalloc's
    // in-place realloc when possible. Otherwise generic copy.
    let dst = alloc(new_size, align);
    if dst.is_null() {
        return dst;
    }
    let n = old_size.min(new_size);
    core::ptr::copy_nonoverlapping(ptr, dst, n);
    dealloc_routed(ptr, old_size, align);
    dst
}

/// Free a previously allocated block. `size` must match the original
/// allocation.
pub unsafe fn free(ptr: *mut u8, size: usize) {
    dealloc_routed(ptr, size, 8);
}

/// Internal dealloc dispatch consulting all three tiers in order:
/// mheap (large), mcentral (small/owned), dlmalloc (fallback).
unsafe fn dealloc_routed(ptr: *mut u8, size: usize, align: usize) {
    let layout = Layout::from_size_align_unchecked(size, align);
    if route_to_mheap(layout) {
        mheap_free(ptr, layout);
        return;
    }
    // mcentral_free returns true if it owns the pointer (i.e. ptr is
    // inside a tracked span). Otherwise this is a dlmalloc-tier alloc.
    if crate::runtime::mcentral::ready() && crate::runtime::mcentral::free(ptr) {
        return;
    }
    SMALL_HEAP.lock().free(ptr, size, align);
}

// ─── #[global_allocator] adapter ───────────────────────────────────────

struct GoishAllocator;

unsafe impl GlobalAlloc for GoishAllocator {
    #[inline]
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        if route_to_mheap(layout) {
            mheap_alloc(layout)
        } else if route_to_mcentral(layout) {
            let p = crate::runtime::mcentral::alloc(layout.size(), layout.align());
            if !p.is_null() {
                p
            } else {
                SMALL_HEAP.lock().malloc(layout.size(), layout.align())
            }
        } else {
            SMALL_HEAP.lock().malloc(layout.size(), layout.align())
        }
    }

    #[inline]
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        if route_to_mheap(layout) {
            mheap_free(ptr, layout);
            return;
        }
        if crate::runtime::mcentral::ready() && crate::runtime::mcentral::free(ptr) {
            return;
        }
        SMALL_HEAP
            .lock()
            .free(ptr, layout.size(), layout.align());
    }

    #[inline]
    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        // Delegate to the size-passing realloc above.
        realloc(ptr, layout.size(), new_size, layout.align())
    }
}

#[global_allocator]
static GOISH_ALLOCATOR: GoishAllocator = GoishAllocator;
