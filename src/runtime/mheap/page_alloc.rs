// runtime::mheap::page_alloc — radix tree page allocator.
//
// Faithful port of `pageAlloc` from runtime/mpagealloc.go. Five-level
// radix tree of `PallocSum` summaries over per-chunk `PallocBits`
// bitmaps. The descent path on alloc and the bottom-up summary update
// path on alloc/free are line-for-line equivalents of Go's
// `(*pageAlloc).find`, `.alloc`, `.free`, and `.update`.
//
// What this port deliberately omits (compared to upstream Go):
//
//   - lazy summary mmap reserve/commit (we mmap up-front for the
//     declared capacity; demand-paging means RSS still scales with
//     actual heap use)
//   - scavenger / `pallocData.scavenged` bitmap
//   - multi-arena `inUse` ranges + `findMappedAddr`
//   - `searchAddr` candidate-narrowing optimization
//   - `arenaBaseOffset`'s linearization of negative addresses
//
// All of these are correctness-preserving simplifications.
//
// Storage: summary and chunks arrays are backed by raw mmap'd
// memory (via `super::mmap_zeroed`) instead of `Vec`. This is
// load-bearing: `PageAlloc::new` runs during mheap bootstrap, before
// the global allocator is ready. Vec would route through
// GlobalAlloc, which would route to mheap, which is being
// initialized — infinite recursion. Raw mmap bypasses GlobalAlloc
// entirely.
//
// Rust safety: the public radix tree algorithm is pure safe Rust
// over `&[PallocSum]` / `&mut [PallocSum]` slices retrieved through
// the `summary()`/`summary_mut()` accessors. The only `unsafe` lives
// in those accessors (raw pointer + length → slice) and in
// `PageAlloc::new` (mmap setup). The pointer never moves once
// allocated; the slice it represents is always exactly that long.

use core::slice;

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
/// `arena_base`. The allocator is constructed for a `max_chunks`
/// capacity; `grow()` extends the active range up to that ceiling
/// without allocating.
pub struct PageAlloc {
    /// Per-level summary array pointers.
    summary_ptr: [*mut PallocSum; SUMMARY_LEVELS],
    /// Per-level summary array lengths (in entries).
    summary_len: [usize; SUMMARY_LEVELS],

    /// Per-chunk bitmap storage pointer.
    chunks_ptr: *mut PallocBits,
    /// Capacity (entries) of the chunks array — i.e. `max_chunks`.
    chunks_capacity: usize,

    /// Virtual base address of the arena.
    pub arena_base: usize,

    /// Currently-active chunk index range.
    pub start_chunk: usize,
    pub end_chunk: usize,
}

// `PageAlloc` is shared via `SpinLock<Option<PageAlloc>>` in
// `runtime::heap`. The raw pointers are not interior-mutability hot
// spots; access is fully serialized by the lock.
unsafe impl Send for PageAlloc {}

impl PageAlloc {
    /// Initialize a `PageAlloc` over a contiguous arena starting at
    /// `arena_base` (`PALLOC_CHUNK_BYTES`-aligned) with `n_chunks`
    /// initially active out of a `max_chunks` capacity. Metadata is
    /// mmap'd up front for the full `max_chunks`; data pages are
    /// faulted on demand by the kernel.
    pub fn new(arena_base: usize, n_chunks: usize, max_chunks: usize) -> Self {
        debug_assert!(arena_base % PALLOC_CHUNK_BYTES == 0);
        debug_assert!(n_chunks >= 1);
        debug_assert!(max_chunks >= n_chunks);

        // ── Allocate per-chunk bitmap storage ──
        let chunks_bytes = max_chunks * core::mem::size_of::<PallocBits>();
        let chunks_ptr = unsafe { super::mmap_zeroed(chunks_bytes) } as *mut PallocBits;

        // ── Allocate per-level summary storage ──
        let mut summary_ptr = [core::ptr::null_mut(); SUMMARY_LEVELS];
        let mut summary_len = [0usize; SUMMARY_LEVELS];

        // L0 always covers one full root block (256 TiB worth of
        // entries) regardless of `max_chunks`.
        summary_len[0] = 1usize << LEVEL_BITS[0];
        let s0_bytes = summary_len[0] * core::mem::size_of::<PallocSum>();
        summary_ptr[0] = unsafe { super::mmap_zeroed(s0_bytes) } as *mut PallocSum;

        // L1..L4 are sized to cover `max_chunks` worth of leaves,
        // padded up to the parent block size at each level.
        for l in 1..SUMMARY_LEVELS {
            let level_bits_total: u32 = LEVEL_BITS[l..].iter().sum::<u32>();
            let shift = level_bits_total - LEVEL_BITS[l];
            let entries_for_heap = ((max_chunks + (1usize << shift) - 1) >> shift).max(1);
            let block = 1usize << LEVEL_BITS[l];
            let n = entries_for_heap.div_ceil(block) * block;
            summary_len[l] = n;
            let bytes = n * core::mem::size_of::<PallocSum>();
            summary_ptr[l] = unsafe { super::mmap_zeroed(bytes) } as *mut PallocSum;
        }

        let mut p = PageAlloc {
            summary_ptr,
            summary_len,
            chunks_ptr,
            chunks_capacity: max_chunks,
            arena_base,
            start_chunk: 0,
            end_chunk: n_chunks,
        };

        // mmap'd memory is zero-filled. PallocBits all-zero = all
        // pages free, which is exactly the post-init state. We just
        // need to populate the leaf summaries and bubble up.
        for ci in 0..n_chunks {
            let leaf = p.chunks()[ci].summarize();
            p.summary_mut(SUMMARY_LEVELS - 1)[ci] = leaf;
        }
        p.bubble_up_initial();
        p
    }

    /// Compute every parent summary from its children, top of leaf
    /// up to the root. Used at construction.
    fn bubble_up_initial(&mut self) {
        for l in (0..SUMMARY_LEVELS - 1).rev() {
            let log_max_pages = LEVEL_LOG_PAGES[l + 1];
            let entries_per_block = 1usize << LEVEL_BITS[l + 1];
            let parent_count = self.summary_len[l];
            for i in 0..parent_count {
                let lo = i << LEVEL_BITS[l + 1];
                let hi = lo + entries_per_block;
                if hi > self.summary_len[l + 1] {
                    break;
                }
                let merged = merge_summaries(&self.summary(l + 1)[lo..hi], log_max_pages);
                self.summary_mut(l)[i] = merged;
            }
        }
    }

    // ─── Internal accessors ──────────────────────────────────────────

    #[inline]
    fn summary(&self, l: usize) -> &[PallocSum] {
        unsafe { slice::from_raw_parts(self.summary_ptr[l], self.summary_len[l]) }
    }

    #[inline]
    fn summary_mut(&mut self, l: usize) -> &mut [PallocSum] {
        unsafe { slice::from_raw_parts_mut(self.summary_ptr[l], self.summary_len[l]) }
    }

    #[inline]
    fn chunks(&self) -> &[PallocBits] {
        unsafe { slice::from_raw_parts(self.chunks_ptr, self.end_chunk) }
    }

    #[inline]
    fn chunks_mut(&mut self) -> &mut [PallocBits] {
        unsafe { slice::from_raw_parts_mut(self.chunks_ptr, self.end_chunk) }
    }

    // ─── Coordinate translation ──────────────────────────────────────

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

    /// Map an address to its index at level `l`.
    #[inline]
    fn addr_to_level_index(&self, l: usize, addr: usize) -> usize {
        (addr - self.arena_base) >> LEVEL_SHIFT[l]
    }

    // ─── Update / alloc_range / find / alloc / free ──────────────────

    /// `(*pageAlloc).update` — refresh leaf summaries for chunks
    /// touched by `[base, base + npages*PAGE_SIZE)` and bubble those
    /// changes up the radix tree.
    pub fn update(&mut self, base: usize, npages: usize) {
        let limit = base + npages * PAGE_SIZE - 1;
        let sc = self.chunk_index(base);
        let ec = self.chunk_index(limit);

        // Refresh affected leaf summaries.
        for ci in sc..=ec {
            let s = self.chunks()[ci].summarize();
            self.summary_mut(SUMMARY_LEVELS - 1)[ci] = s;
        }

        // Walk up.
        let mut changed = true;
        let mut l = SUMMARY_LEVELS as isize - 2;
        while l >= 0 && changed {
            changed = false;
            let lu = l as usize;
            let log_entries_per_block = LEVEL_BITS[lu + 1];
            let log_max_pages = LEVEL_LOG_PAGES[lu + 1];
            let entries_per_block = 1usize << log_entries_per_block;

            let lo = self.addr_to_level_index(lu, base);
            let hi = self.addr_to_level_index(lu, limit) + 1;

            for i in lo..hi {
                let child_lo = i << log_entries_per_block;
                let child_hi = child_lo + entries_per_block;
                if child_hi > self.summary_len[lu + 1] {
                    continue;
                }
                let merged =
                    merge_summaries(&self.summary(lu + 1)[child_lo..child_hi], log_max_pages);
                if self.summary(lu)[i] != merged {
                    self.summary_mut(lu)[i] = merged;
                    changed = true;
                }
            }
            l -= 1;
        }
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
            self.chunks_mut()[sc].alloc_range(si, ei + 1 - si);
        } else {
            self.chunks_mut()[sc].alloc_range(si, PALLOC_CHUNK_PAGES - si);
            for c in (sc + 1)..ec {
                self.chunks_mut()[c].alloc_range(0, PALLOC_CHUNK_PAGES);
            }
            self.chunks_mut()[ec].alloc_range(0, ei + 1);
        }

        self.update(base, npages);
    }

    /// `(*pageAlloc).find` — radix-tree descent to locate the first
    /// `npages`-page contiguous free run.
    pub fn find(&self, npages: usize) -> usize {
        let mut i: usize = 0;

        'level: for l in 0..SUMMARY_LEVELS {
            let entries_per_block = 1usize << LEVEL_BITS[l];
            let log_max_pages = LEVEL_LOG_PAGES[l];

            i <<= LEVEL_BITS[l];

            let lvl = self.summary(l);
            let block_end = (i + entries_per_block).min(lvl.len());

            let mut base: usize = 0;
            let mut size: usize = 0;
            let mut j = i;
            while j < block_end {
                let sum = lvl[j];
                if sum.raw() == 0 {
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
                    i = j;
                    continue 'level;
                }
                if size == 0 || s < (1usize << log_max_pages) {
                    size = sum.end();
                    base = ((j - i + 1) << log_max_pages) - size;
                } else {
                    size += 1usize << log_max_pages;
                }
                j += 1;
            }

            if size >= npages {
                let base_addr =
                    self.arena_base + (i << LEVEL_SHIFT[l]) + (base << PAGE_SHIFT);
                return base_addr;
            }

            if l == 0 {
                return ALLOC_FAILED;
            }
        }

        let ci = i;
        let (j, _) = self.chunks()[ci].find(npages, 0);
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
            self.chunks_mut()[i].free(pi, 1);
        } else {
            let sc = self.chunk_index(base);
            let ec = self.chunk_index(limit);
            let si = self.chunk_page_index(base);
            let ei = self.chunk_page_index(limit);
            if sc == ec {
                self.chunks_mut()[sc].free(si, ei + 1 - si);
            } else {
                self.chunks_mut()[sc].free(si, PALLOC_CHUNK_PAGES - si);
                for c in (sc + 1)..ec {
                    self.chunks_mut()[c].free(0, PALLOC_CHUNK_PAGES);
                }
                self.chunks_mut()[ec].free(0, ei + 1);
            }
        }
        self.update(base, npages);
    }

    /// Total chunk capacity the metadata was pre-sized for (`max_chunks`).
    pub fn capacity_chunks(&self) -> usize {
        self.chunks_capacity
    }

    /// `(*pageAlloc).grow` — extend the heap by `n_more` chunks of
    /// fresh memory contiguous with the existing arena. The caller is
    /// responsible for ensuring the new range is mmap'd and writable.
    /// Cannot exceed the `max_chunks` capacity passed at construction.
    pub fn grow(&mut self, n_more: usize) {
        if n_more == 0 {
            return;
        }
        let old_count = self.end_chunk;
        let new_count = old_count + n_more;
        debug_assert!(
            new_count <= self.chunks_capacity,
            "PageAlloc::grow: exceeded capacity"
        );
        self.end_chunk = new_count;

        // New chunks' bitmaps are already zeroed (mmap-zero), so they
        // start fully free. Populate their leaf summaries.
        for ci in old_count..new_count {
            self.summary_mut(SUMMARY_LEVELS - 1)[ci] = self.chunks()[ci].summarize();
        }

        // Bubble up over the new chunk range only.
        let mut lo_chunk = old_count;
        let mut hi_chunk = new_count;
        for l in (0..SUMMARY_LEVELS - 1).rev() {
            let log_entries_per_block = LEVEL_BITS[l + 1];
            let log_max_pages = LEVEL_LOG_PAGES[l + 1];
            let entries_per_block = 1usize << log_entries_per_block;
            let parent_lo = lo_chunk >> log_entries_per_block;
            let parent_hi = (hi_chunk + entries_per_block - 1) >> log_entries_per_block;
            for i in parent_lo..parent_hi {
                let child_lo = i << log_entries_per_block;
                let child_hi = child_lo + entries_per_block;
                if child_hi > self.summary_len[l + 1] {
                    continue;
                }
                let merged =
                    merge_summaries(&self.summary(l + 1)[child_lo..child_hi], log_max_pages);
                if i < self.summary_len[l] {
                    self.summary_mut(l)[i] = merged;
                }
            }
            lo_chunk = parent_lo;
            hi_chunk = parent_hi;
        }
    }

    /// Total free pages in the arena, computed from the leaf
    /// bitmaps. Useful for tests.
    pub fn free_pages(&self) -> usize {
        let mut n = 0usize;
        for ci in self.start_chunk..self.end_chunk {
            n += PALLOC_CHUNK_PAGES - self.chunks()[ci].0.popcnt_range(0, PALLOC_CHUNK_PAGES);
        }
        n
    }

    /// Total allocated pages in the arena. Inverse of `free_pages`.
    pub fn allocated_pages(&self) -> usize {
        let mut n = 0usize;
        for ci in self.start_chunk..self.end_chunk {
            n += self.chunks()[ci].0.popcnt_range(0, PALLOC_CHUNK_PAGES);
        }
        n
    }
}

#[cfg(test)]
mod tests {
    // `alloc::vec::Vec` is not in scope in a no_std crate; the harness
    // below builds one, so name it explicitly.
    use alloc::vec::Vec;
    use super::super::consts::PALLOC_CHUNK_BYTES;
    use super::*;

    fn fresh(n_chunks: usize) -> PageAlloc {
        PageAlloc::new(0x10_0000_0000usize, n_chunks, n_chunks)
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
        let d = p.alloc(16);
        assert_eq!(d, b);
    }

    #[test]
    fn exhaust_chunk() {
        let mut p = fresh(1);
        let _ = p.alloc(PALLOC_CHUNK_PAGES);
        assert_eq!(p.alloc(1), ALLOC_FAILED);
    }

    /// Replay the goish-vllm-port full-checkpoint load pattern at the
    /// 81920-chunk (320 GiB) capacity: grow-on-demand in 64-chunk
    /// steps from a 256-chunk start, interleaving multi-GiB tensor
    /// allocations with 1-page metadata allocations, freeing some.
    /// Every live span is checked against every other for overlap and
    /// for containment in the active arena. The real loader corrupted
    /// tensor dims once the heap crossed ~144 GiB — an overlap here is
    /// that bug.
    #[test]
    fn no_overlap_at_full_checkpoint_scale() {
        const MAX_CHUNKS: usize = 81920;
        let mut p = PageAlloc::new(0x10_0000_0000usize, 256, MAX_CHUNKS);
        // (base, npages) of live allocations
        let mut live: Vec<(usize, usize)> = Vec::new();
        // Deterministic xorshift so failures replay
        let mut rng = 0x9e3779b97f4a7c15u64;
        let mut next = move || {
            rng ^= rng << 13;
            rng ^= rng >> 7;
            rng ^= rng << 17;
            rng
        };
        // Sizes drawn from the real load: KDA in_proj f32 = 1.416 GB
        // (~173k pages @8K), attn tensors ~350 MB, norms ~1 page.
        let big_sizes = [173_000usize, 43_000, 10_800, 86_000];
        let mut alloc_like_loader = |p: &mut PageAlloc,
                                     live: &mut Vec<(usize, usize)>,
                                     npages: usize| {
            let mut addr = p.alloc(npages);
            if addr == ALLOC_FAILED {
                // mheap_alloc_pages grow-on-demand replica
                let need = npages.div_ceil(PALLOC_CHUNK_PAGES);
                let room = p.capacity_chunks() - p.end_chunk;
                let step = need.max(64).min(room);
                assert!(step >= need, "arena truly exhausted mid-test");
                p.grow(step);
                addr = p.alloc(npages);
            }
            assert!(addr != ALLOC_FAILED, "alloc failed after grow");
            let end = addr + npages * PAGE_SIZE;
            assert!(addr >= p.arena_base, "span below arena");
            assert!(
                end <= p.arena_base + p.end_chunk * PALLOC_CHUNK_BYTES,
                "span past active arena end (addr {:#x} npages {})",
                addr,
                npages
            );
            for &(b, n) in live.iter() {
                let e = b + n * PAGE_SIZE;
                assert!(
                    end <= b || addr >= e,
                    "OVERLAP: new [{:#x},{:#x}) vs live [{:#x},{:#x})",
                    addr,
                    end,
                    b,
                    e
                );
            }
            live.push((addr, npages));
        };
        // ~93 layers x (1 big in_proj + several mid + ~6 small)
        for _layer in 0..93 {
            alloc_like_loader(&mut p, &mut live, big_sizes[0]);
            for _ in 0..4 {
                let s = big_sizes[1 + (next() as usize % 3)];
                alloc_like_loader(&mut p, &mut live, s);
            }
            for _ in 0..6 {
                alloc_like_loader(&mut p, &mut live, 1);
            }
            // The loader frees cat temporaries: drop ~1 in 3 mid-size
            if live.len() > 8 && next() % 3 == 0 {
                let idx = live.len() - 2;
                let (b, n) = live.swap_remove(idx);
                p.free(b, n);
            }
        }
        // Sanity: we really did cross into high-chunk territory.
        assert!(
            p.end_chunk > 16384,
            "test never left low-chunk range (end_chunk {})",
            p.end_chunk
        );
    }
}
