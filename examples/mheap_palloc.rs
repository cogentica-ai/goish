// Smoke test: M16 (2b'-α) — radix tree page allocator over a single
// 4 MiB chunk. This is the standalone-module phase; the global
// allocator path is unchanged. We mmap one PALLOC_CHUNK_BYTES region,
// hand it to PageAlloc, and exercise alloc/free patterns.

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

#[goish::main]
fn main() {
    // ─── Reserve one chunk via direct mmap ───────────────────────────
    //
    // PageAlloc itself doesn't allocate user memory — it tracks which
    // pages are free in a region the caller already owns. So we mmap
    // one chunk of writable memory at a chunk-aligned address and
    // hand the base to PageAlloc.

    let raw = syscall::Mmap(
        core::ptr::null_mut(),
        PALLOC_CHUNK_BYTES,
        syscall::PROT_READ | syscall::PROT_WRITE,
        syscall::MAP_PRIVATE | syscall::MAP_ANONYMOUS,
        -1,
        0,
    );
    check(raw != syscall::MAP_FAILED, b"mmap failed\n");

    // mmap returns page-aligned but not necessarily chunk-aligned
    // memory. Round up to the next chunk boundary by reserving a
    // bigger region, then trimming. Simpler: mmap 2 chunks and pick
    // the chunk-aligned subregion.
    let base = raw as usize;
    let aligned = (base + PALLOC_CHUNK_BYTES - 1) & !(PALLOC_CHUNK_BYTES - 1);
    // The kernel always returns at least page-aligned memory (4 KiB);
    // if the kernel happened to give us a chunk-aligned mapping then
    // `aligned == base`. If not we'd need a 2-chunk reservation. The
    // smoke test plays it safe by re-mapping a 2-chunk region.
    if aligned != base {
        // Free the first attempt and re-map 2 chunks.
        syscall::Munmap(raw, PALLOC_CHUNK_BYTES);
        let raw2 = syscall::Mmap(
            core::ptr::null_mut(),
            2 * PALLOC_CHUNK_BYTES,
            syscall::PROT_READ | syscall::PROT_WRITE,
            syscall::MAP_PRIVATE | syscall::MAP_ANONYMOUS,
            -1,
            0,
        );
        check(raw2 != syscall::MAP_FAILED, b"mmap 2-chunk failed\n");
        let base2 = raw2 as usize;
        let aligned2 = (base2 + PALLOC_CHUNK_BYTES - 1) & !(PALLOC_CHUNK_BYTES - 1);
        run_tests(aligned2);
        return;
    }
    run_tests(aligned);
}

fn run_tests(arena_base: usize) {
    let mut p = PageAlloc::new(arena_base, 1);
    check(p.allocated_pages() == 0, b"fresh: nonzero alloc\n");

    // ─── Single-page allocation ─────────────────────────────────────
    let a1 = p.alloc(1);
    check(a1 != ALLOC_FAILED, b"alloc(1) failed\n");
    check(a1 == arena_base, b"alloc(1) wrong addr\n");
    check(p.allocated_pages() == 1, b"allocated_pages != 1\n");

    // Address-ordered first-fit: next 1-page alloc should be at +PAGE_SIZE
    let a2 = p.alloc(1);
    check(a2 == arena_base + PAGE_SIZE, b"alloc(1) #2 not first-fit\n");

    // ─── Larger allocation ──────────────────────────────────────────
    let a8 = p.alloc(8);
    check(a8 != ALLOC_FAILED, b"alloc(8) failed\n");
    check(a8 == arena_base + 2 * PAGE_SIZE, b"alloc(8) wrong addr\n");

    // Total now 1 + 1 + 8 = 10
    check(p.allocated_pages() == 10, b"allocated_pages != 10\n");

    // ─── Free-then-realloc reuses freed space ───────────────────────
    p.free(a8, 8);
    check(p.allocated_pages() == 2, b"after free(8): alloc != 2\n");
    let r8 = p.alloc(8);
    check(r8 == a8, b"realloc(8) didn't reuse freed run\n");

    // ─── Non-overlap: write a marker into each allocation ───────────
    //
    // The write proves the addresses we got back point into our
    // mapped region. Reading after a non-overlapping alloc proves
    // the allocator didn't double-allocate.
    unsafe {
        *(a1 as *mut u64) = 0x1111_1111_1111_1111;
        *(a2 as *mut u64) = 0x2222_2222_2222_2222;
        *(r8 as *mut u64) = 0x8888_8888_8888_8888;
    }
    let v1 = unsafe { *(a1 as *const u64) };
    let v2 = unsafe { *(a2 as *const u64) };
    let v8 = unsafe { *(r8 as *const u64) };
    check(v1 == 0x1111_1111_1111_1111, b"a1 corrupted\n");
    check(v2 == 0x2222_2222_2222_2222, b"a2 corrupted\n");
    check(v8 == 0x8888_8888_8888_8888, b"r8 corrupted\n");

    // ─── Many small allocs + free-all + giant alloc ─────────────────
    p.free(a1, 1);
    p.free(a2, 1);
    p.free(r8, 8);
    check(p.allocated_pages() == 0, b"after triple-free: nonzero alloc\n");

    let mut addrs = [0usize; 64];
    for i in 0..64 {
        let a = p.alloc(3);
        check(a != ALLOC_FAILED, b"alloc(3) batch failed\n");
        addrs[i] = a;
    }
    check(p.allocated_pages() == 64 * 3, b"batch: wrong total\n");

    for i in 0..64 {
        p.free(addrs[i], 3);
    }
    check(p.allocated_pages() == 0, b"batch free: nonzero alloc\n");

    // The full chunk should now be available as one contiguous run.
    let whole = p.alloc(PALLOC_CHUNK_PAGES);
    check(whole == arena_base, b"alloc(whole chunk) wrong addr\n");
    check(p.allocated_pages() == PALLOC_CHUNK_PAGES, b"whole chunk: wrong total\n");

    // ─── Exhaustion ─────────────────────────────────────────────────
    check(p.alloc(1) == ALLOC_FAILED, b"exhausted heap returned non-failure\n");

    // Free the whole chunk; allocator should be empty again.
    p.free(whole, PALLOC_CHUNK_PAGES);
    check(p.allocated_pages() == 0, b"after free-all: nonzero alloc\n");

    const OK: &[u8] = b"mheap_palloc: ok\n";
    syscall::Write(syscall::STDOUT, OK.as_ptr(), OK.len());
}
