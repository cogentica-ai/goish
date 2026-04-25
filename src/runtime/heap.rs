// runtime::heap — leaf allocator: dlmalloc-rs over our mmap.
//
// `alloc`, `realloc`, `free` are the Go-shaped public API (re-exported
// from `runtime`). They delegate to `dlmalloc::Dlmalloc<MmapAllocator>`.
// dlmalloc is a pure-Rust port of Doug Lea's malloc, used by Rust's
// own wasm target in production. We supply our own `Allocator` impl
// backed by `syscall::Mmap` so libc is never touched.
//
// `GoishAllocator` (registered as `#[global_allocator]`) routes
// `Vec`/`String`/`Box` allocations through the same heap.
//
// Concurrency: single SpinLock around the dlmalloc state. Single-
// threaded today, so contention is zero. When goroutines arrive, the
// per-thread tcache (phase 2d) will absorb the hot path and only cold
// fills will touch this lock.

use crate::runtime::spin::SpinLock;
use crate::syscall;
use core::alloc::{GlobalAlloc, Layout};
use dlmalloc::{Allocator, Dlmalloc};

// ─── Allocator (dlmalloc's "system" trait) backed by mmap ──────────────

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

    // We don't expose mremap (no SYS_MREMAP wrapper yet); dlmalloc will
    // fall back to alloc+copy+free, which is fine.
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
        // mmap'd anonymous pages are zero-filled by the kernel.
        true
    }

    fn page_size(&self) -> usize {
        4096
    }
}

// ─── Heap singleton ────────────────────────────────────────────────────

static HEAP: SpinLock<Dlmalloc<MmapAllocator>> =
    SpinLock::new(Dlmalloc::new_with_allocator(MmapAllocator));

// ─── Go-shaped public API ──────────────────────────────────────────────

/// Allocate `size` bytes at `align` alignment. Returns a null pointer
/// on failure. `align` must be a power of two.
pub unsafe fn alloc(size: usize, align: usize) -> *mut u8 {
    HEAP.lock().malloc(size, align)
}

/// Reallocate, preserving the first `min(old_size, new_size)` bytes.
/// dlmalloc may grow in place when possible; otherwise it allocates +
/// copies + frees the old block.
pub unsafe fn realloc(ptr: *mut u8, old_size: usize, new_size: usize, align: usize) -> *mut u8 {
    HEAP.lock().realloc(ptr, old_size, align, new_size)
}

/// Free a previously allocated block. `size` and `align` must match the
/// values originally passed to `alloc`/`realloc`.
pub unsafe fn free(ptr: *mut u8, size: usize) {
    // Alignment isn't tracked by callers; pass dlmalloc's default
    // alignment, which is the same value `malloc(size, 1)` would store.
    HEAP.lock().free(ptr, size, 8)
}

// ─── #[global_allocator] adapter ───────────────────────────────────────
//
// Lets `extern crate alloc;` consumers (Vec, Box, String) draw from the
// same heap. Without this, `Vec::push` either fails to link or — on
// std builds — would call libc malloc, which is exactly what we are
// avoiding.

struct GoishAllocator;

unsafe impl GlobalAlloc for GoishAllocator {
    #[inline]
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        HEAP.lock().malloc(layout.size(), layout.align())
    }
    #[inline]
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        HEAP.lock().free(ptr, layout.size(), layout.align())
    }
    #[inline]
    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        HEAP.lock().realloc(ptr, layout.size(), layout.align(), new_size)
    }
}

#[global_allocator]
static GOISH_ALLOCATOR: GoishAllocator = GoishAllocator;
