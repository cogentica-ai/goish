// Stress test for the radix tree page allocator (2b'-α).
//
// Empirically corroborates the soundness / completeness theorems by
// running thousands of randomized alloc/free pairs and after each
// operation checking the invariants we can observe externally:
//
//   - Every allocation lies inside the arena.
//   - No two live allocations overlap (proved by writing distinct
//     marker bytes into each and reading them back).
//   - `allocated_pages()` equals the sum of live allocation sizes.
//   - After freeing every live block, the allocator is empty and the
//     entire chunk is reclaimable as one contiguous run.

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

// xorshift64* — deterministic, no_std-friendly RNG. Identical seed
// on every run so failures are reproducible.
struct Rng(u64);
impl Rng {
    fn new(seed: u64) -> Self {
        Rng(seed)
    }
    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x
    }
    fn range(&mut self, n: usize) -> usize {
        (self.next() as usize) % n
    }
}

#[goish::main]
fn main() {
    // Reserve 2 chunks of mmap to ensure we can find a chunk-aligned
    // base inside.
    let raw = syscall::Mmap(
        core::ptr::null_mut(),
        2 * PALLOC_CHUNK_BYTES,
        syscall::PROT_READ | syscall::PROT_WRITE,
        syscall::MAP_PRIVATE | syscall::MAP_ANONYMOUS,
        -1,
        0,
    );
    check(raw != syscall::MAP_FAILED, b"stress: mmap failed\n");
    let base = raw as usize;
    let arena_base = (base + PALLOC_CHUNK_BYTES - 1) & !(PALLOC_CHUNK_BYTES - 1);

    let mut p = PageAlloc::new(arena_base, 1);

    // Live allocations: parallel arrays of (base, npages, marker).
    // Cap at 200 — plenty to fragment a 512-page chunk.
    const MAX_LIVE: usize = 200;
    let mut live_base = [0usize; MAX_LIVE];
    let mut live_size = [0usize; MAX_LIVE];
    let mut live_marker = [0u8; MAX_LIVE];
    let mut nlive = 0usize;

    let mut rng = Rng::new(0x_DEAD_BEEF_F00Dusize as u64);

    // Bookkeeping — total pages currently held in `live_*`.
    let mut held_pages = 0usize;

    const ROUNDS: u32 = 5_000;
    for r in 0..ROUNDS {
        // Pick an action. Bias toward alloc when fewer live, toward
        // free when more, so we churn through a wide range of fill
        // levels.
        let do_alloc = if nlive == 0 {
            true
        } else if nlive >= MAX_LIVE {
            false
        } else {
            rng.range(2) == 0
        };

        if do_alloc {
            // Random size 1..=8 most of the time, occasionally larger
            // to hit the find_large_n path.
            let big = rng.range(16) == 0;
            let max_n = if big { 64 } else { 8 };
            let want = 1 + rng.range(max_n);

            let addr = p.alloc(want);
            if addr == ALLOC_FAILED {
                // Ran out of contiguous space — that's a legitimate
                // outcome under fragmentation. Skip and continue.
                continue;
            }

            // Boundary check: allocation must lie within the arena.
            check(addr >= arena_base, b"stress: alloc below arena\n");
            check(
                addr + want * PAGE_SIZE <= arena_base + PALLOC_CHUNK_BYTES,
                b"stress: alloc above arena\n",
            );

            // Pick a marker byte; write it to every page so we can
            // detect overlap with any other live allocation.
            let marker = (rng.next() as u8).wrapping_add(1); // never 0
            for pg in 0..want {
                let pp = (addr + pg * PAGE_SIZE) as *mut u8;
                unsafe {
                    *pp = marker;
                    *pp.add(PAGE_SIZE - 1) = marker;
                }
            }

            live_base[nlive] = addr;
            live_size[nlive] = want;
            live_marker[nlive] = marker;
            nlive += 1;
            held_pages += want;
        } else {
            // Free a random live allocation. First verify its marker
            // is intact (i.e. nobody else allocated into our pages).
            let idx = rng.range(nlive);
            let addr = live_base[idx];
            let want = live_size[idx];
            let marker = live_marker[idx];

            for pg in 0..want {
                let pp = (addr + pg * PAGE_SIZE) as *const u8;
                let v = unsafe { *pp };
                check(v == marker, b"stress: marker corrupted (overlap!)\n");
            }

            p.free(addr, want);
            held_pages -= want;

            // Swap-remove from live arrays.
            nlive -= 1;
            live_base[idx] = live_base[nlive];
            live_size[idx] = live_size[nlive];
            live_marker[idx] = live_marker[nlive];
        }

        // Invariant: held_pages == p.allocated_pages().
        check(
            p.allocated_pages() == held_pages,
            b"stress: allocated_pages() vs held_pages diverged\n",
        );

        // Spot-check a few rounds in the middle: every live marker
        // must still be intact. This is O(nlive * pages) so we only
        // do it occasionally.
        if r % 500 == 0 {
            for idx in 0..nlive {
                let addr = live_base[idx];
                let want = live_size[idx];
                let marker = live_marker[idx];
                for pg in 0..want {
                    let pp = (addr + pg * PAGE_SIZE) as *const u8;
                    let v = unsafe { *pp };
                    check(v == marker, b"stress: full sweep marker mismatch\n");
                }
            }
        }
    }

    // Tear down: free everything still live.
    for idx in 0..nlive {
        p.free(live_base[idx], live_size[idx]);
    }
    check(p.allocated_pages() == 0, b"stress: drain nonzero alloc\n");

    // After full free, the entire chunk should be reclaimable as one
    // contiguous run. This proves the radix tree's bottom-up summary
    // restoration is symmetric with allocation.
    let whole = p.alloc(PALLOC_CHUNK_PAGES);
    check(whole == arena_base, b"stress: post-drain whole-chunk failed\n");
    p.free(whole, PALLOC_CHUNK_PAGES);

    const OK: &[u8] = b"mheap_palloc_stress: ok\n";
    syscall::Write(syscall::STDOUT, OK.as_ptr(), OK.len());
}
