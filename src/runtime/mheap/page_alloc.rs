// runtime::mheap::page_alloc — radix tree page allocator.
//
// Faithful port of `pageAlloc` from runtime/mpagealloc.go. Five-level
// radix tree of `PallocSum` summaries over per-chunk `PallocBits`
// bitmaps. The descent path on alloc and the bottom-up summary update
// path on alloc/free are line-for-line equivalents of Go's
// `(*pageAlloc).find`, `.alloc`, `.free`, and `.update`.
//
// What 2b'-α deliberately does *not* port:
//
//   - lazy summary mmap reserve/commit (kept simple via plain `Vec`)
//   - scavenger / `pallocData.scavenged` bitmap (no madvise yet)
//   - multi-arena `inUse` ranges + `findMappedAddr` (single arena)
//   - `searchAddr` candidate-narrowing optimization (always restart)
//   - `arenaBaseOffset`'s linearization of negative addresses
//
// All of these are correctness-preserving simplifications: removing
// them shrinks the code without changing what allocations succeed or
// where they land. They land in 2b'-β and later.
//
// Rust safety: the radix tree itself is pure safe Rust over
// `Vec<PallocSum>` and `Vec<PallocBits>`. The only `unsafe` is at the
// very bottom, where `Heap::reserve_arena` calls `syscall::Mmap` to
// obtain a fresh 4 MiB region; that boundary will be the same when
// 2b'-γ wires this into the global allocator.

use alloc::vec;
use alloc::vec::Vec;

use super::consts::{
    LEVEL_BITS, LEVEL_LOG_PAGES, LEVEL_SHIFT, PAGE_SHIFT, PAGE_SIZE, PALLOC_CHUNK_BYTES,
    PALLOC_CHUNK_PAGES, SUMMARY_LEVELS,
};
use super::palloc_bits::{PallocBits, NO_INDEX};
use super::palloc_sum::{merge_summaries, PallocSum};

/// Sentinel returned by [`PageAlloc::alloc`] for "out of memory". 0 is
/// not a valid heap address.
pub const ALLOC_FAILED: usize = 0;

/// `pageAlloc` — the radix tree page allocator over a contiguous range
/// of chunks `[start_chunk, end_chunk)` whose virtual base is
/// `arena_base`. Phase 2b'-α only ever populates one chunk; the data
/// shape supports more so 2b'-β can grow without re-architecting.
pub struct PageAlloc {
    /// Per-level summary arrays. `summary[l][i]` is the packed
    /// summary for the i-th block at level l.
    pub summary: [Vec<PallocSum>; SUMMARY_LEVELS],

    /// Per-chunk bitmaps, indexed by `chunk_idx - start_chunk`.
    pub chunks: Vec<PallocBits>,

    /// Virtual base address of the arena. Any pointer `p` returned
    /// to the caller satisfies `arena_base <= p < arena_base + N *
    /// PALLOC_CHUNK_BYTES` where N is the number of chunks.
    pub arena_base: usize,

    /// Chunk index range we know about. Chunks are addressed in
    /// "offset chunk space" so that `start_chunk == 0` for our
    /// arena; this lets summary arrays stay bounded.
    pub start_chunk: usize,
    pub end_chunk: usize,
}

impl PageAlloc {
    /// Initialize a `PageAlloc` over a contiguous arena of `n_chunks`
    /// chunks beginning at virtual address `arena_base` (which must
    /// be `PALLOC_CHUNK_BYTES`-aligned and refer to mapped, writable
    /// memory).
    pub fn new(arena_base: usize, n_chunks: usize) -> Self {
        debug_assert!(arena_base % PALLOC_CHUNK_BYTES == 0);
        debug_assert!(n_chunks >= 1);

        // Each chunk's bitmap starts all-zero (entirely free).
        let chunks: Vec<PallocBits> = (0..n_chunks).map(|_| PallocBits::zero()).collect();

        // Size each summary level. The leaf level has one entry per
        // chunk; non-leaf levels need to cover the L_(l-1)-aligned
        // block containing every chunk index in our arena.
        //
        // For a single-arena setup with `start_chunk == 0`, this is
        // straightforward: each level needs an array large enough
        // that `summary[l][i : i + (1 << LEVEL_BITS[l+1])]` is
        // in-bounds for every `i` we'll touch. The simplest
        // sufficient size is `block-aligned-ceil(n_chunks_at_level)`.
        let mut summary: [Vec<PallocSum>; SUMMARY_LEVELS] = [
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
        ];

        // Compute per-level array sizes top-down.
        // L0 must cover at least one root block (1 << LEVEL_BITS[0]).
        // L1..L4 must cover at least one parent block (1 <<
        // LEVEL_BITS[l]) per parent entry that's in use.
        let l0_block: usize = 1usize << LEVEL_BITS[0];
        summary[0] = vec![PallocSum::empty(); l0_block];

        // For L1..L4: they only need entries covering chunks
        // [start_chunk, end_chunk). Pad up to the parent block
        // boundary so slice operations work.
        for l in 1..SUMMARY_LEVELS {
            // How many entries cover our heap at this level?
            let level_bits_total: u32 = LEVEL_BITS[l..].iter().sum::<u32>();
            let entries_for_heap = ((n_chunks + (1usize << (level_bits_total - LEVEL_BITS[l]))
                - 1)
                >> (level_bits_total - LEVEL_BITS[l]))
                .max(1);
            // Round up to the parent block size (1 << LEVEL_BITS[l]).
            let block = 1usize << LEVEL_BITS[l];
            let n = ((entries_for_heap + block - 1) / block) * block;
            summary[l] = vec![PallocSum::empty(); n];
        }

        let mut p = PageAlloc {
            summary,
            chunks,
            arena_base,
            start_chunk: 0,
            end_chunk: n_chunks,
        };

        // Populate every chunk's leaf summary and bubble up.
        for ci in 0..n_chunks {
            let leaf = p.chunks[ci].summarize();
            p.summary[SUMMARY_LEVELS - 1][ci] = leaf;
        }
        // Walk up.
        for l in (0..SUMMARY_LEVELS - 1).rev() {
            let log_max_pages = LEVEL_LOG_PAGES[l + 1];
            let entries_per_block = 1usize << LEVEL_BITS[l + 1];
            let parent_count = p.summary[l].len();
            for i in 0..parent_count {
                let lo = i << LEVEL_BITS[l + 1];
                let hi = lo + entries_per_block;
                if hi > p.summary[l + 1].len() {
                    break;
                }
                let merged = merge_summaries(&p.summary[l + 1][lo..hi], log_max_pages);
                p.summary[l][i] = merged;
            }
        }

        p
    }

    /// `chunkIndex(p)` — convert a virtual address in our arena into
    /// the chunk index that contains it.
    #[inline]
    pub fn chunk_index(&self, addr: usize) -> usize {
        (addr - self.arena_base) / PALLOC_CHUNK_BYTES
    }

    /// `chunkPageIndex(p)` — the page index within the containing
    /// chunk for `addr`.
    #[inline]
    pub fn chunk_page_index(&self, addr: usize) -> usize {
        (addr % PALLOC_CHUNK_BYTES) / PAGE_SIZE
    }

    /// `chunkBase(ci)` — the virtual base address of the chunk at
    /// index `ci` in our arena.
    #[inline]
    pub fn chunk_base(&self, ci: usize) -> usize {
        self.arena_base + ci * PALLOC_CHUNK_BYTES
    }

    /// `(*pageAlloc).update` — refresh leaf summaries for chunks
    /// touched by `[base, base + npages*PAGE_SIZE)` and bubble those
    /// changes up the radix tree.
    pub fn update(&mut self, base: usize, npages: usize) {
        let limit = base + npages * PAGE_SIZE - 1;
        let sc = self.chunk_index(base);
        let ec = self.chunk_index(limit);

        // Refresh affected leaf summaries.
        for ci in sc..=ec {
            let s = self.chunks[ci].summarize();
            self.summary[SUMMARY_LEVELS - 1][ci] = s;
        }

        // Walk up. At each non-leaf level, recompute the summary for
        // the parent block(s) containing the affected children.
        let mut changed = true;
        let mut l = SUMMARY_LEVELS as isize - 2;
        while l >= 0 && changed {
            changed = false;
            let lu = l as usize;
            let log_entries_per_block = LEVEL_BITS[lu + 1];
            let log_max_pages = LEVEL_LOG_PAGES[lu + 1];
            let entries_per_block = 1usize << log_entries_per_block;

            // Translate (base, limit+1) into [lo, hi) at level l.
            let lo = self.addr_to_level_index(lu, base);
            let hi = self.addr_to_level_index(lu, limit) + 1;

            for i in lo..hi {
                let child_lo = i << log_entries_per_block;
                let child_hi = child_lo + entries_per_block;
                if child_hi > self.summary[lu + 1].len() {
                    // Child block doesn't exist yet (out-of-range);
                    // would only happen with arena holes.
                    continue;
                }
                let merged = merge_summaries(
                    &self.summary[lu + 1][child_lo..child_hi],
                    log_max_pages,
                );
                if self.summary[lu][i] != merged {
                    self.summary[lu][i] = merged;
                    changed = true;
                }
            }
            l -= 1;
        }
    }

    /// Map an address to its index at level `l`. Equivalent to
    /// Go's `offAddrToLevelIndex(l, addr)` after subtracting our
    /// arena base.
    #[inline]
    fn addr_to_level_index(&self, l: usize, addr: usize) -> usize {
        let off = (addr - self.arena_base) >> LEVEL_SHIFT[l];
        off
    }

    /// `(*pageAlloc).allocRange` — mark `[base, base+npages)` as
    /// allocated in the bitmaps and refresh summaries.
    pub fn alloc_range(&mut self, base: usize, npages: usize) {
        let limit = base + npages * PAGE_SIZE - 1;
        let sc = self.chunk_index(base);
        let ec = self.chunk_index(limit);
        let si = self.chunk_page_index(base);
        let ei = self.chunk_page_index(limit);

        if sc == ec {
            self.chunks[sc].alloc_range(si, ei + 1 - si);
        } else {
            self.chunks[sc].alloc_range(si, PALLOC_CHUNK_PAGES - si);
            for c in (sc + 1)..ec {
                self.chunks[c].alloc_range(0, PALLOC_CHUNK_PAGES);
            }
            self.chunks[ec].alloc_range(0, ei + 1);
        }

        self.update(base, npages);
    }

    /// `(*pageAlloc).find` — radix-tree descent to locate the first
    /// `npages`-page contiguous free run. Returns the base address,
    /// or `ALLOC_FAILED` (0) if no such run exists.
    pub fn find(&self, npages: usize) -> usize {
        let mut i: usize = 0;

        // Walk levels 0..SUMMARY_LEVELS-1 picking either:
        //   (a) a single child summary whose `max >= npages` (descend
        //       into it), or
        //   (b) a straddle of consecutive children whose tail+head
        //       free-pages reach `npages` (alloc within this level).
        'level: for l in 0..SUMMARY_LEVELS {
            let entries_per_block = 1usize << LEVEL_BITS[l];
            let log_max_pages = LEVEL_LOG_PAGES[l];

            // For l > 0, scale i by the new fanout.
            i <<= LEVEL_BITS[l];

            let lvl = &self.summary[l];
            // Bound by what's actually present.
            let block_end = (i + entries_per_block).min(lvl.len());

            let mut base: usize = 0;
            let mut size: usize = 0;
            let mut j = i;
            while j < block_end {
                let sum = lvl[j];
                if sum.raw() == 0 {
                    // Fully allocated child — break any straddle.
                    size = 0;
                    j += 1;
                    continue;
                }
                let s = sum.start();
                if size + s >= npages {
                    if size == 0 {
                        base = (j - i) << log_max_pages;
                    }
                    size += s;
                    break;
                }
                if sum.max() >= npages {
                    // Descend into this child.
                    i = j;
                    continue 'level;
                }
                if size == 0 || s < (1usize << log_max_pages) {
                    // Restart straddle from this child's tail.
                    size = sum.end();
                    base = ((j - i + 1) << log_max_pages) - size;
                } else {
                    // Child is entirely free — extend the straddle.
                    size += 1usize << log_max_pages;
                }
                j += 1;
            }

            if size >= npages {
                // We satisfied the request from a straddle at this
                // level. Compute the base address.
                let base_addr = self.arena_base
                    + ((i << LEVEL_SHIFT[l]) >> 0)
                    + (base << PAGE_SHIFT);
                return base_addr;
            }

            if l == 0 {
                // Exhausted the root level → out of memory.
                return ALLOC_FAILED;
            }

            // We told the upper level to descend into us, but we
            // didn't satisfy the alloc here. That should be
            // impossible if summaries are correct — drop through to
            // the next level to look in our children.
        }

        // After the loop, i is a chunk index — use the chunk-level
        // bitmap search.
        let ci = i;
        let (j, _) = self.chunks[ci].find(npages, 0);
        if j == NO_INDEX {
            return ALLOC_FAILED;
        }
        self.chunk_base(ci) + j * PAGE_SIZE
    }

    /// `(*pageAlloc).alloc` — find a run of `npages` free pages and
    /// mark it allocated. Returns the base address or `ALLOC_FAILED`.
    pub fn alloc(&mut self, npages: usize) -> usize {
        let addr = self.find(npages);
        if addr == ALLOC_FAILED {
            return ALLOC_FAILED;
        }
        self.alloc_range(addr, npages);
        addr
    }

    /// `(*pageAlloc).free` — return `npages` pages starting at
    /// `base` to the page heap.
    pub fn free(&mut self, base: usize, npages: usize) {
        let limit = base + npages * PAGE_SIZE - 1;
        if npages == 1 {
            let i = self.chunk_index(base);
            let pi = self.chunk_page_index(base);
            self.chunks[i].free(pi, 1);
        } else {
            let sc = self.chunk_index(base);
            let ec = self.chunk_index(limit);
            let si = self.chunk_page_index(base);
            let ei = self.chunk_page_index(limit);
            if sc == ec {
                self.chunks[sc].free(si, ei + 1 - si);
            } else {
                self.chunks[sc].free(si, PALLOC_CHUNK_PAGES - si);
                for c in (sc + 1)..ec {
                    self.chunks[c].free(0, PALLOC_CHUNK_PAGES);
                }
                self.chunks[ec].free(0, ei + 1);
            }
        }
        self.update(base, npages);
    }

    /// `(*pageAlloc).grow` — extend the heap by `n_more` chunks of
    /// fresh memory contiguous with the existing arena. The caller is
    /// responsible for ensuring the new range is mmap'd and writable.
    /// Phase 2b'-β: contiguous extension only; non-contiguous arenas
    /// (Go's `inUse` ranges) land later if needed.
    ///
    /// Mirrors Go's `(*pageAlloc).grow`: a `grow` is treated as a
    /// `free` operation — newly-mapped pages are added to the page
    /// heap as available.
    pub fn grow(&mut self, n_more: usize) {
        if n_more == 0 {
            return;
        }
        let old_count = self.end_chunk;
        let new_count = old_count + n_more;

        // Extend the per-chunk bitmap storage. New chunks start
        // entirely free (all-zero bitmap).
        self.chunks.reserve(n_more);
        for _ in 0..n_more {
            self.chunks.push(PallocBits::zero());
        }
        self.end_chunk = new_count;

        // Re-size each summary level. summary[0] already covers a
        // full root block (1 << LEVEL_BITS[0] entries), so it never
        // needs to grow in this single-arena setup. Levels 1..4
        // grow to cover the new chunk range, padded up to the
        // parent block size at that level.
        for l in 1..SUMMARY_LEVELS {
            let level_bits_total: u32 = LEVEL_BITS[l..].iter().sum::<u32>();
            let shift = level_bits_total - LEVEL_BITS[l];
            let entries_for_heap = ((new_count + (1usize << shift) - 1) >> shift).max(1);
            let block = 1usize << LEVEL_BITS[l];
            let needed = entries_for_heap.div_ceil(block) * block;
            if self.summary[l].len() < needed {
                self.summary[l].resize(needed, PallocSum::empty());
            }
        }

        // Populate new leaf summaries from the freshly-zeroed bitmaps.
        for ci in old_count..new_count {
            self.summary[SUMMARY_LEVELS - 1][ci] = self.chunks[ci].summarize();
        }

        // Bubble up. The grow only added chunks at the high end,
        // so we need to refresh all parent entries whose children
        // include the new range. For simplicity (and matching Go's
        // approach of `update(base, size, contig=true, alloc=false)`)
        // we re-merge across the affected branches.
        //
        // The leaf-level range affected is `[old_count, new_count)`;
        // at each higher level, the affected parent index range
        // contracts by the level's fanout.
        let mut lo_chunk = old_count;
        let mut hi_chunk = new_count;
        for l in (0..SUMMARY_LEVELS - 1).rev() {
            let log_entries_per_block = LEVEL_BITS[l + 1];
            let log_max_pages = LEVEL_LOG_PAGES[l + 1];
            let entries_per_block = 1usize << log_entries_per_block;
            // Parent index range at this level.
            let parent_lo = lo_chunk >> log_entries_per_block;
            let parent_hi = (hi_chunk + entries_per_block - 1) >> log_entries_per_block;
            for i in parent_lo..parent_hi {
                let child_lo = i << log_entries_per_block;
                let child_hi = child_lo + entries_per_block;
                if child_hi > self.summary[l + 1].len() {
                    continue;
                }
                let merged = merge_summaries(
                    &self.summary[l + 1][child_lo..child_hi],
                    log_max_pages,
                );
                if i < self.summary[l].len() {
                    self.summary[l][i] = merged;
                }
            }
            lo_chunk = parent_lo;
            hi_chunk = parent_hi;
        }
    }

    /// Total free pages in the arena, computed from the root summary.
    /// Useful for tests.
    pub fn free_pages(&self) -> usize {
        // The root-level summary's max gives an upper bound, but to
        // get the exact free count we sum across the leaf level.
        let mut n = 0usize;
        for ci in self.start_chunk..self.end_chunk {
            n += PALLOC_CHUNK_PAGES - self.chunks[ci].0.popcnt_range(0, PALLOC_CHUNK_PAGES);
        }
        n
    }

    /// Total allocated pages in the arena. Inverse of `free_pages`.
    pub fn allocated_pages(&self) -> usize {
        let mut n = 0usize;
        for ci in self.start_chunk..self.end_chunk {
            n += self.chunks[ci].0.popcnt_range(0, PALLOC_CHUNK_PAGES);
        }
        n
    }
}

#[cfg(test)]
mod tests {
    use super::super::consts::PALLOC_CHUNK_BYTES;
    use super::*;

    fn fresh(n_chunks: usize) -> PageAlloc {
        // Use a fake arena base so chunk_index math works without
        // touching real memory.
        PageAlloc::new(0x10_0000_0000usize, n_chunks)
    }

    #[test]
    fn fresh_alloc_one_page() {
        let mut p = fresh(1);
        let addr = p.alloc(1);
        assert!(addr != ALLOC_FAILED);
        assert!(addr >= p.arena_base);
        assert!(addr < p.arena_base + PALLOC_CHUNK_BYTES);
        assert_eq!(p.allocated_pages(), 1);
    }

    #[test]
    fn alloc_then_free_round_trip() {
        let mut p = fresh(1);
        let a = p.alloc(8);
        let b = p.alloc(16);
        let c = p.alloc(32);
        assert!(a != ALLOC_FAILED && b != ALLOC_FAILED && c != ALLOC_FAILED);
        assert_eq!(p.allocated_pages(), 8 + 16 + 32);
        p.free(b, 16);
        assert_eq!(p.allocated_pages(), 8 + 32);
        // The freed run should be reusable.
        let d = p.alloc(16);
        assert_eq!(d, b);
    }

    #[test]
    fn exhaust_chunk() {
        let mut p = fresh(1);
        let _ = p.alloc(PALLOC_CHUNK_PAGES);
        // Out of pages now.
        assert_eq!(p.alloc(1), ALLOC_FAILED);
    }

    #[test]
    fn many_small_then_free_all() {
        let mut p = fresh(1);
        let mut addrs = alloc::vec::Vec::new();
        for _ in 0..100 {
            let a = p.alloc(3);
            assert!(a != ALLOC_FAILED);
            addrs.push(a);
        }
        assert_eq!(p.allocated_pages(), 300);
        for a in &addrs {
            p.free(*a, 3);
        }
        assert_eq!(p.allocated_pages(), 0);
        // After freeing everything, we should be able to alloc the
        // entire chunk in one shot.
        let big = p.alloc(PALLOC_CHUNK_PAGES);
        assert!(big != ALLOC_FAILED);
    }
}
