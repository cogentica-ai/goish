// runtime::mheap::palloc_bits — per-chunk page allocation bitmap.
//
// Faithful port of `pageBits` / `pallocBits` / `findBitRange64` from
// runtime/mpallocbits.go. One `PallocBits` covers exactly one chunk
// (`PALLOC_CHUNK_PAGES = 512` pages = `PALLOC_CHUNK_BYTES = 4 MiB`).
// In the bitmap, **0 = free, 1 = in-use**, matching Go.
//
// Phase 2b'-α uses non-atomic ops because the page allocator runs
// under `mheap.lock` (one SpinLock) in single-threaded form. When
// 2c/2d open the alloc paths to multiple goroutines, the bitmap
// itself remains lock-protected so atomic-per-bit isn't needed; we'd
// only switch to AtomicU64 if we ever wanted lock-free scavenge.
//
// Pure safe Rust — indexing and shifts only. No unsafe, no raw
// pointers. Rust's bounds checks are debug-time guardrails for the
// modulo arithmetic; in release the compiler eliminates them once
// the radix-tree caller's invariants are visible.

use super::consts::{LOG_PALLOC_CHUNK_PAGES, PALLOC_CHUNK_PAGES};
use super::palloc_sum::PallocSum;

/// `mask_low_bits(n)` — `(1 << n) - 1` extended to handle `n == 64`
/// without UB. Go's shift returns 0 for `1 << 64`, so the `(... - 1)`
/// silently produces `^uint64(0)`; Rust's `1u64 << 64` is UB. We
/// replicate Go's semantics explicitly.
#[inline]
const fn mask_low_bits(n: usize) -> u64 {
    if n >= 64 {
        u64::MAX
    } else {
        (1u64 << n) - 1
    }
}

/// Number of u64 words backing one chunk's bitmap.
pub const PAGE_BITS_WORDS: usize = PALLOC_CHUNK_PAGES / 64;

/// `pageBits` — one bit per page in a chunk. 0 means free, 1 means
/// allocated.
#[derive(Clone)]
#[repr(transparent)]
pub struct PageBits(pub [u64; PAGE_BITS_WORDS]);

impl PageBits {
    pub const fn zero() -> Self {
        PageBits([0; PAGE_BITS_WORDS])
    }

    /// `get(i)` — bit value at index `i`.
    #[inline]
    pub fn get(&self, i: usize) -> u64 {
        (self.0[i / 64] >> (i % 64)) & 1
    }

    /// `block64(i)` — the entire 64-bit aligned block of bits
    /// containing the i'th bit.
    #[inline]
    pub fn block64(&self, i: usize) -> u64 {
        self.0[i / 64]
    }

    /// `set(i)` — set the i'th bit to 1.
    #[inline]
    pub fn set(&mut self, i: usize) {
        self.0[i / 64] |= 1u64 << (i % 64);
    }

    /// `setRange(i, n)` — set bits in [i, i+n) to 1.
    pub fn set_range(&mut self, i: usize, n: usize) {
        if n == 1 {
            self.set(i);
            return;
        }
        let j = i + n - 1;
        let iw = i / 64;
        let jw = j / 64;
        if iw == jw {
            self.0[iw] |= mask_low_bits(n) << (i % 64);
            return;
        }
        // Leading partial word.
        self.0[iw] |= u64::MAX << (i % 64);
        // Whole interior words.
        let mut k = iw + 1;
        while k < jw {
            self.0[k] = u64::MAX;
            k += 1;
        }
        // Trailing partial word.
        self.0[jw] |= mask_low_bits((j % 64) + 1);
    }

    /// `setAll()` — set every bit.
    pub fn set_all(&mut self) {
        for w in self.0.iter_mut() {
            *w = u64::MAX;
        }
    }

    /// `setBlock64(i, v)` — OR `v` into the 64-bit aligned block of
    /// bits containing the i'th bit.
    #[inline]
    pub fn set_block64(&mut self, i: usize, v: u64) {
        self.0[i / 64] |= v;
    }

    /// `clear(i)` — clear the i'th bit.
    #[inline]
    pub fn clear(&mut self, i: usize) {
        self.0[i / 64] &= !(1u64 << (i % 64));
    }

    /// `clearRange(i, n)` — clear bits in [i, i+n).
    pub fn clear_range(&mut self, i: usize, n: usize) {
        if n == 1 {
            self.clear(i);
            return;
        }
        let j = i + n - 1;
        let iw = i / 64;
        let jw = j / 64;
        if iw == jw {
            self.0[iw] &= !(mask_low_bits(n) << (i % 64));
            return;
        }
        self.0[iw] &= !(u64::MAX << (i % 64));
        let mut k = iw + 1;
        while k < jw {
            self.0[k] = 0;
            k += 1;
        }
        self.0[jw] &= !mask_low_bits((j % 64) + 1);
    }

    /// `clearAll()` — zero the bitmap.
    pub fn clear_all(&mut self) {
        for w in self.0.iter_mut() {
            *w = 0;
        }
    }

    /// `popcntRange(i, n)` — number of 1-bits in [i, i+n).
    pub fn popcnt_range(&self, i: usize, n: usize) -> usize {
        if n == 1 {
            return ((self.0[i / 64] >> (i % 64)) & 1) as usize;
        }
        let j = i + n - 1;
        let iw = i / 64;
        let jw = j / 64;
        if iw == jw {
            return ((self.0[iw] >> (i % 64)) & mask_low_bits(n)).count_ones() as usize;
        }
        let mut s = (self.0[iw] >> (i % 64)).count_ones() as usize;
        let mut k = iw + 1;
        while k < jw {
            s += self.0[k].count_ones() as usize;
            k += 1;
        }
        s += (self.0[jw] & mask_low_bits((j % 64) + 1)).count_ones() as usize;
        s
    }
}

/// `pallocBits` — newtype around `PageBits` carrying allocation
/// semantics: 0 = free, 1 = allocated. Adds `summarize` and the
/// `find` family for scanning runs of free pages.
#[derive(Clone)]
#[repr(transparent)]
pub struct PallocBits(pub PageBits);

/// Sentinel returned by `find*` to indicate "no run available".
pub const NO_INDEX: usize = usize::MAX;

impl PallocBits {
    pub const fn zero() -> Self {
        PallocBits(PageBits::zero())
    }

    pub fn alloc_range(&mut self, i: usize, n: usize) {
        self.0.set_range(i, n);
    }

    pub fn free(&mut self, i: usize, n: usize) {
        self.0.clear_range(i, n);
    }

    pub fn pages64(&self, i: usize) -> u64 {
        self.0.block64(i)
    }

    pub fn alloc_pages64(&mut self, i: usize, alloc: u64) {
        self.0.set_block64(i, alloc);
    }

    /// `summarize()` — fold the bitmap into a `(start, max, end)`
    /// summary describing free-page runs. Verbatim port of
    /// `(*pallocBits).summarize` from mpallocbits.go:132-221.
    ///
    /// Returns the leaf-level summary that the radix-tree update
    /// path will install at `summary[SUMMARY_LEVELS-1]`.
    pub fn summarize(&self) -> PallocSum {
        let bits = &self.0.0;
        let n_words = bits.len();

        let mut start: usize = NO_INDEX; // sentinel for "not set yet"
        let mut most: usize = 0;
        let mut cur: usize = 0;

        // First pass: count runs of zeros that span 64-bit boundaries.
        for &x in bits.iter() {
            if x == 0 {
                cur += 64;
                continue;
            }
            let t = x.trailing_zeros() as usize;
            let l = x.leading_zeros() as usize;

            // Close out any region that was straddling 64-bit words.
            cur += t;
            if start == NO_INDEX {
                start = cur;
            }
            if cur > most {
                most = cur;
            }
            // The next region starts at the leading zeros of x.
            cur = l;
        }

        if start == NO_INDEX {
            // All bits zero — entire chunk is free.
            let n = 64 * n_words;
            return PallocSum::pack(n, n, n);
        }
        if cur > most {
            most = cur;
        }

        // If most is already 62+, no internal run within a single
        // 64-bit word could beat it.
        if most >= 64 - 2 {
            return PallocSum::pack(start, most, cur);
        }

        // Second pass: look inside each non-zero u64 for runs of zeros
        // that didn't cross a word boundary.
        'outer: for i in 0..n_words {
            let mut x = bits[i];

            // Skip over the trailing zeros — already credited in pass 1.
            x >>= (x.trailing_zeros() as u64) & 63;
            if x & x.wrapping_add(1) == 0 {
                continue;
            }

            // Strategy: shrink every run of zeros (except the topmost,
            // which "leaks" out the top of the word) by `most` places.
            // Any zeros that survive represent a longer run than we
            // currently believe is the maximum.
            let mut p = most;
            let mut k: usize = 1;
            loop {
                while p > 0 {
                    if p <= k {
                        x |= x >> ((p as u64) & 63);
                        if x & x.wrapping_add(1) == 0 {
                            continue 'outer;
                        }
                        break;
                    }
                    x |= x >> ((k as u64) & 63);
                    if x & x.wrapping_add(1) == 0 {
                        continue 'outer;
                    }
                    p -= k;
                    k *= 2;
                }

                // Bottom-most surviving zero-run extends our maximum.
                let j_ones = (!x).trailing_zeros() as u64;
                x >>= j_ones & 63;
                let j_zeros = x.trailing_zeros() as usize;
                x >>= (j_zeros as u64) & 63;
                most += j_zeros;
                if x & x.wrapping_add(1) == 0 {
                    continue 'outer;
                }
                p = j_zeros;
            }
        }

        PallocSum::pack(start, most, cur)
    }

    /// `find(npages, search_idx)` — locate `npages` contiguous free
    /// pages starting at or after page `search_idx`. Returns
    /// `(run_start, new_search_idx)`, or `(NO_INDEX, _)` on failure.
    pub fn find(&self, npages: usize, search_idx: usize) -> (usize, usize) {
        if npages == 1 {
            let addr = self.find1(search_idx);
            return (addr, addr);
        }
        if npages <= 64 {
            return self.find_small_n(npages, search_idx);
        }
        self.find_large_n(npages, search_idx)
    }

    fn find1(&self, search_idx: usize) -> usize {
        let bits = &self.0.0;
        let mut i = search_idx / 64;
        while i < bits.len() {
            let x = bits[i];
            if !x == 0 {
                i += 1;
                continue;
            }
            return i * 64 + (!x).trailing_zeros() as usize;
        }
        NO_INDEX
    }

    fn find_small_n(&self, npages: usize, search_idx: usize) -> (usize, usize) {
        let bits = &self.0.0;
        let mut end: usize = 0;
        let mut new_search_idx: usize = NO_INDEX;
        let mut i = search_idx / 64;
        while i < bits.len() {
            let bi = bits[i];
            if !bi == 0 {
                end = 0;
                i += 1;
                continue;
            }
            if new_search_idx == NO_INDEX {
                new_search_idx = i * 64 + (!bi).trailing_zeros() as usize;
            }
            let start = bi.trailing_zeros() as usize;
            if end + start >= npages {
                return (i * 64 - end, new_search_idx);
            }
            // Look inside this 64-bit chunk for a run of zeros of
            // length `npages`.
            let j = find_bit_range64(!bi, npages);
            if j < 64 {
                return (i * 64 + j, new_search_idx);
            }
            end = bi.leading_zeros() as usize;
            i += 1;
        }
        (NO_INDEX, new_search_idx)
    }

    fn find_large_n(&self, npages: usize, search_idx: usize) -> (usize, usize) {
        let bits = &self.0.0;
        let mut start: usize = NO_INDEX;
        let mut size: usize = 0;
        let mut new_search_idx: usize = NO_INDEX;
        let mut i = search_idx / 64;
        while i < bits.len() {
            let x = bits[i];
            if x == u64::MAX {
                size = 0;
                i += 1;
                continue;
            }
            if new_search_idx == NO_INDEX {
                new_search_idx = i * 64 + (!x).trailing_zeros() as usize;
            }
            if size == 0 {
                size = x.leading_zeros() as usize;
                start = i * 64 + 64 - size;
                i += 1;
                continue;
            }
            let s = x.trailing_zeros() as usize;
            if s + size >= npages {
                return (start, new_search_idx);
            }
            if s < 64 {
                size = x.leading_zeros() as usize;
                start = i * 64 + 64 - size;
                i += 1;
                continue;
            }
            size += 64;
            i += 1;
        }
        if size < npages {
            return (NO_INDEX, new_search_idx);
        }
        (start, new_search_idx)
    }
}

/// `findBitRange64(c, n)` — return the bit index of the first run of
/// `n` consecutive 1-bits in `c`, or any value ≥ 64 if no such run
/// exists. `n` must be > 0.
///
/// Verbatim port of `findBitRange64` from mpallocbits.go:384-410.
pub fn find_bit_range64(mut c: u64, n: usize) -> usize {
    let mut p = n - 1;
    let mut k: usize = 1;
    while p > 0 {
        if p <= k {
            c &= c >> ((p as u64) & 63);
            break;
        }
        c &= c >> ((k as u64) & 63);
        if c == 0 {
            return 64;
        }
        p -= k;
        k *= 2;
    }
    if c == 0 {
        return 64;
    }
    c.trailing_zeros() as usize
}

// Compile-time sanity: 8 words × 64 bits = 512 pages = one chunk.
const _: () = {
    assert!(PAGE_BITS_WORDS * 64 == 1usize << LOG_PALLOC_CHUNK_PAGES);
};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn set_clear_roundtrip() {
        let mut b = PageBits::zero();
        b.set(7);
        assert_eq!(b.get(7), 1);
        b.clear(7);
        assert_eq!(b.get(7), 0);
    }

    #[test]
    fn set_range_within_word() {
        let mut b = PageBits::zero();
        b.set_range(3, 5); // bits 3..=7
        for i in 0..3 {
            assert_eq!(b.get(i), 0);
        }
        for i in 3..8 {
            assert_eq!(b.get(i), 1);
        }
    }

    #[test]
    fn set_range_across_words() {
        let mut b = PageBits::zero();
        b.set_range(60, 10); // spans words 0 and 1
        assert_eq!(b.popcnt_range(60, 10), 10);
    }

    #[test]
    fn summarize_all_free() {
        let b = PallocBits::zero();
        let s = b.summarize();
        assert_eq!(s.unpack(), (512, 512, 512));
    }

    #[test]
    fn summarize_all_allocated() {
        let mut b = PallocBits::zero();
        b.alloc_range(0, 512);
        let s = b.summarize();
        assert_eq!(s.unpack(), (0, 0, 0));
    }

    #[test]
    fn summarize_split() {
        // First 100 free, next 312 used, last 100 free.
        let mut b = PallocBits::zero();
        b.alloc_range(100, 312);
        let s = b.summarize();
        assert_eq!(s.start(), 100);
        assert_eq!(s.end(), 100);
        assert_eq!(s.max(), 100);
    }

    #[test]
    fn find_one() {
        let mut b = PallocBits::zero();
        b.alloc_range(0, 5);
        let (idx, _) = b.find(1, 0);
        assert_eq!(idx, 5);
    }

    #[test]
    fn find_n_within_word() {
        let mut b = PallocBits::zero();
        b.alloc_range(0, 10);
        let (idx, _) = b.find(8, 0);
        assert_eq!(idx, 10);
    }

    #[test]
    fn find_n_spanning_words() {
        let mut b = PallocBits::zero();
        b.alloc_range(60, 4); // bits 60..=63 used → run starts at 64
        let (idx, _) = b.find(128, 0);
        assert_eq!(idx, 64);
    }

    #[test]
    fn find_bit_range64_basic() {
        // 0b0000_1111_0000 → first run of 4 ones starts at bit 4.
        assert_eq!(find_bit_range64(0xF0, 4), 4);
        // No run of 5 ones in 0xF0.
        assert!(find_bit_range64(0xF0, 5) >= 64);
    }
}
