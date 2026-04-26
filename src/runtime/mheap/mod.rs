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
