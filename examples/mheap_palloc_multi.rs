// Smoke test: M16 (2b'-β) — multi-chunk arena and `grow()`.
//
// Exercises the cross-chunk code paths in `find` (straddle across
// adjacent leaf summaries), `alloc_range` (bitmap updates spanning
// chunks), `free` (cross-chunk clearing), and `update` (multi-leaf
// summary refresh). Also verifies `grow()` extends the heap
// correctly and treats new pages as free, matching Go's semantics
// in runtime/mpagealloc.go:360-432.

#![no_std]
#![no_main]

use goish::runtime::mheap::consts::{PAGE_SIZE, PALLOC_CHUNK_BYTES, PALLOC_CHUNK_PAGES};
use goish::runtime::mheap::page_alloc::{PageAlloc, ALLOC_FAILED};
use goish::syscall;

fn die(msg: &[u8]) -> ! {
    syscall::Write(syscall::STDERR, msg.as_ptr(), msg.len());
    syscall::Exit(1);
}

fn check(cond: bool, msg: &[u8]) {
    if !cond {
        die(msg);
    }
}

/// Reserve `n_chunks` chunks of mmap'd memory at a chunk-aligned
/// base. Over-reserves by one chunk so we can always trim down to a
/// chunk-aligned region.
fn reserve_arena(n_chunks: usize) -> usize {
    let extra = PALLOC_CHUNK_BYTES; // alignment slack
    let raw = syscall::Mmap(
        core::ptr::null_mut(),
        n_chunks * PALLOC_CHUNK_BYTES + extra,
        syscall::PROT_READ | syscall::PROT_WRITE,
        syscall::MAP_PRIVATE | syscall::MAP_ANONYMOUS,
        -1,
        0,
    );
    check(raw != syscall::MAP_FAILED, b"reserve_arena: mmap failed\n");
    let base = raw as usize;
    (base + PALLOC_CHUNK_BYTES - 1) & !(PALLOC_CHUNK_BYTES - 1)
}

#[goish::main]
fn main() {
    test_multi_chunk_init();
    test_cross_chunk_alloc();
    test_grow_extends_heap();
    test_grow_then_alloc_in_grown_region();

    const OK: &[u8] = b"mheap_palloc_multi: ok\n";
    syscall::Write(syscall::STDOUT, OK.as_ptr(), OK.len());
}

// ─── Test 1: 4-chunk arena initializes consistently ───────────────────

fn test_multi_chunk_init() {
    let arena_base = reserve_arena(4);
    let p = PageAlloc::new(arena_base, 4, 4);
    check(p.allocated_pages() == 0, b"multi-init: nonzero alloc\n");
    // 4 chunks × 512 pages = 2048 free pages.
    let total_pages = 4 * PALLOC_CHUNK_PAGES;
    check(
        p.free_pages() == total_pages,
        b"multi-init: free_pages mismatch\n",
    );
}

// ─── Test 2: cross-chunk allocation + free + recovery ─────────────────
//
// Allocate a span larger than one chunk → forces find() to use the
// straddle path at the leaf level, alloc_range() to update bitmaps
// across chunks, and update() to refresh multiple leaf summaries.

fn test_cross_chunk_alloc() {
    let arena_base = reserve_arena(4);
    let mut p = PageAlloc::new(arena_base, 4, 4);

    // 1000 pages = ~7.8 MiB → spans 2 chunks (chunks 0 and 1).
    let span = 1000;
    let a = p.alloc(span);
    check(a != ALLOC_FAILED, b"cross-alloc: alloc(1000) failed\n");
    check(a == arena_base, b"cross-alloc: not at arena base\n");
    check(
        p.allocated_pages() == span,
        b"cross-alloc: allocated_pages mismatch\n",
    );

    // Write a marker into pages spanning the chunk boundary to
    // confirm we own pages across the boundary.
    let crossing_page_base = arena_base + (PALLOC_CHUNK_PAGES - 2) * PAGE_SIZE;
    for i in 0..4 {
        let pp = (crossing_page_base + i * PAGE_SIZE) as *mut u64;
        unsafe {
            *pp = 0xCAFE_BABE_DEAD_BEEF;
        }
    }
    for i in 0..4 {
        let pp = (crossing_page_base + i * PAGE_SIZE) as *const u64;
        let v = unsafe { *pp };
        check(
            v == 0xCAFE_BABE_DEAD_BEEF,
            b"cross-alloc: cross-boundary marker corrupted\n",
        );
    }

    // Free the cross-chunk allocation. update() should bubble
    // emptiness back up through both affected leaves.
    p.free(a, span);
    check(
        p.allocated_pages() == 0,
        b"cross-free: nonzero after free\n",
    );

    // After full free, the entire 4-chunk heap should be reclaimable
    // as one contiguous span. This proves the bottom-up summary
    // restoration handles cross-chunk coalescing.
    let whole = p.alloc(4 * PALLOC_CHUNK_PAGES);
    check(whole == arena_base, b"post-free: whole-heap span fail\n");
    p.free(whole, 4 * PALLOC_CHUNK_PAGES);
    check(p.allocated_pages() == 0, b"post-free: nonzero post-drain\n");
}

// ─── Test 3: grow() extends the heap and adds free pages ──────────────

fn test_grow_extends_heap() {
    let arena_base = reserve_arena(4);
    let mut p = PageAlloc::new(arena_base, 1, 4);
    check(
        p.free_pages() == PALLOC_CHUNK_PAGES,
        b"grow-pre: free_pages != one chunk\n",
    );

    // Caller is responsible for ensuring the grown range is mmap'd —
    // we already mapped 4 chunks via reserve_arena.
    p.grow(3);
    check(
        p.free_pages() == 4 * PALLOC_CHUNK_PAGES,
        b"grow-post: free_pages != 4 chunks\n",
    );
    check(p.allocated_pages() == 0, b"grow-post: nonzero alloc\n");
}

// ─── Test 4: grow() then allocate spanning into the grown region ─────

fn test_grow_then_alloc_in_grown_region() {
    let arena_base = reserve_arena(4);
    let mut p = PageAlloc::new(arena_base, 2, 4);

    // Pre-fill chunk 0 entirely so the next allocation must use
    // chunks 1+. This exercises the radix-tree's first-fit being
    // address-ordered after `grow`.
    let block_chunk0 = p.alloc(PALLOC_CHUNK_PAGES);
    check(
        block_chunk0 == arena_base,
        b"grow-alloc: pre-fill chunk0 wrong addr\n",
    );

    // Grow to 4 chunks total.
    p.grow(2);

    // Now allocate 1500 pages (just under 3 chunks worth). It must
    // fit in the contiguous range chunks 1..=3 (1536 pages), but
    // can't fit in chunks 1..=2 (1024 pages) alone.
    let span = 1500;
    let a = p.alloc(span);
    check(a != ALLOC_FAILED, b"grow-alloc: alloc(1500) failed\n");
    check(
        a == arena_base + PALLOC_CHUNK_BYTES,
        b"grow-alloc: not at chunk1 base\n",
    );

    // Verify total accounting.
    check(
        p.allocated_pages() == PALLOC_CHUNK_PAGES + span,
        b"grow-alloc: alloc total mismatch\n",
    );

    // Free everything.
    p.free(block_chunk0, PALLOC_CHUNK_PAGES);
    p.free(a, span);
    check(
        p.allocated_pages() == 0,
        b"grow-alloc: post-free nonzero\n",
    );

    // The full 4-chunk heap should be available as one contiguous
    // run, demonstrating the post-grow summary tree is coherent.
    let whole = p.alloc(4 * PALLOC_CHUNK_PAGES);
    check(whole == arena_base, b"grow-alloc: post-free whole-heap fail\n");
}
