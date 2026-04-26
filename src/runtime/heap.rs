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
const INITIAL_ARENA_CHUNKS: usize = 16;

/// Maximum mheap arena size — chunks the radix tree's metadata is
/// pre-sized to cover. With 4 MiB chunks, 256 chunks is a 1 GiB
/// total heap. Demand-paging means metadata RSS scales with usage.
const MAX_ARENA_CHUNKS: usize = 256;

// ─── mheap ────────────────────────────────────────────────────────────

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
    let arena_base = map_arena(INITIAL_ARENA_CHUNKS);
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
pub unsafe fn alloc(size: usize, align: usize) -> *mut u8 {
    let layout = Layout::from_size_align_unchecked(size, align);
    if route_to_mheap(layout) {
        mheap_alloc(layout)
    } else if route_to_mcentral(layout) {
        let p = crate::runtime::mcentral::alloc(size, align);
        if !p.is_null() {
            return p;
        }
        // mcentral couldn't serve (table exhausted, etc.) — fall back
        // to mheap rounding the request up to a page.
        mheap_alloc(layout)
    } else {
        // Pre-init only. Round up to a page and use mheap directly.
        // In practice nothing allocates before mheap_init.
        mheap_alloc(layout)
    }
}

/// Reallocate via alloc + memcpy + free.
pub unsafe fn realloc(ptr: *mut u8, old_size: usize, new_size: usize, align: usize) -> *mut u8 {
    let dst = alloc(new_size, align);
    if dst.is_null() {
        return dst;
    }
    let n = old_size.min(new_size);
    core::ptr::copy_nonoverlapping(ptr, dst, n);
    dealloc_routed(ptr, old_size, align);
    dst
}

/// Free a previously allocated block.
pub unsafe fn free(ptr: *mut u8, size: usize) {
    dealloc_routed(ptr, size, 8);
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
    #[inline]
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        if route_to_mheap(layout) {
            mheap_alloc(layout)
        } else if route_to_mcentral(layout) {
            let p = crate::runtime::mcentral::alloc(layout.size(), layout.align());
            if !p.is_null() {
                p
            } else {
                mheap_alloc(layout)
            }
        } else {
            mheap_alloc(layout)
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
        mheap_free(ptr, layout);
    }

    #[inline]
    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        realloc(ptr, layout.size(), new_size, layout.align())
    }
}

#[global_allocator]
static GOISH_ALLOCATOR: GoishAllocator = GoishAllocator;
