// runtime::mheap — Go-style page allocator.
//
// Phase 2b'-α brings the radix tree page allocator online as a
// standalone module with its own mmap'd test arena. It is *not* yet
// wired into the global allocator path (that lands in 2b'-γ); for now
// `runtime::heap` continues to delegate every alloc/free to
// dlmalloc-rs unchanged.
//
// Layered responsibility:
//
//     palloc_sum   packed (start, max, end) summary used by every level
//                  of the radix tree
//
//     palloc_bits  per-chunk page bitmap (512 pages = 8 u64s) with
//                  `find_bit_range_n`, `set_range`, `clear_range`, and
//                  `summarize` to fold the bitmap into a PallocSum
//
//     page_alloc   the radix tree itself: 5-level summary descent,
//                  `alloc(npages)` and `free(base, npages)`,
//                  bottom-up summary maintenance via mergeSummaries
//
// Each piece tracks its Go counterpart line-by-line where reasonable
// to make verification against the upstream source straightforward.

#![allow(dead_code)]

pub mod consts;
pub mod page_alloc;
pub mod palloc_bits;
pub mod palloc_sum;

use crate::syscall;

/// `mmap` an anonymous, zero-filled, read/write region of `bytes`
/// bytes. Used by `PageAlloc::new` to back its summary and chunks
/// metadata directly, bypassing the `GlobalAlloc` trait — that's the
/// crucial detail that lets `PageAlloc::new` run during mheap
/// bootstrap without recursing through the global allocator.
///
/// The kernel guarantees anonymous mmap pages start zero-filled, so
/// returned regions are immediately ready for `PallocSum` /
/// `PallocBits` data (both of which encode "all-zero" as their
/// "empty"/"all-free" sentinel).
///
/// Aborts the process with `Exit(2)` on mmap failure — there's
/// nothing meaningful we can do at this stage.
pub(crate) unsafe fn mmap_zeroed(bytes: usize) -> *mut u8 {
    let p = syscall::Mmap(
        core::ptr::null_mut(),
        bytes,
        syscall::PROT_READ | syscall::PROT_WRITE,
        syscall::MAP_PRIVATE | syscall::MAP_ANONYMOUS,
        -1,
        0,
    );
    if p == syscall::MAP_FAILED {
        const MSG: &[u8] = b"goish: mheap: mmap_zeroed failed\n";
        syscall::Write(syscall::STDERR, MSG.as_ptr(), MSG.len());
        syscall::Exit(2);
    }
    p
}
