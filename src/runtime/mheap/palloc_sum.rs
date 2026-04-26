// runtime::mheap::palloc_sum — packed `(start, max, end)` summary.
//
// Faithful port of `pallocSum` from runtime/mpagealloc.go, lines
// 988-1075 of Go 1.25's runtime. The summary records, for some
// region of the address space:
//
//   - `start` — number of free pages at the *start* of the region
//   - `max`   — the longest run of contiguous free pages anywhere
//   - `end`   — number of free pages at the *end* of the region
//
// These three are exactly what a parent radix-tree node needs to
// synthesize *its* summary from its children's: a contiguous free run
// can straddle the boundary between two adjacent children, so the
// parent's `max` is `max(child[i].max, child[i].end + child[i+1].start)`
// across all neighbours.
//
// Encoding (LSB → MSB), with `LMV = LOG_MAX_PACKED_VALUE = 21`:
//
//   bits  0..LMV          start
//   bits  LMV..2*LMV      max
//   bits  2*LMV..3*LMV    end
//   bit   63              "all-MAX_PACKED_VALUE" sentinel
//
// Three 21-bit fields fit in 63 bits exactly, leaving bit 63 to encode
// the case where the entire region is free (start = max = end =
// MAX_PACKED_VALUE), since MAX_PACKED_VALUE itself doesn't fit in 21
// bits. This is purely an internal representation choice — callers
// always see the unpacked values via `unpack` / `start` / `max` / `end`.

use super::consts::{LOG_MAX_PACKED_VALUE, MAX_PACKED_VALUE};
use crate::types::int;

/// `pallocSum` — three `LOG_MAX_PACKED_VALUE`-bit page-count fields
/// packed into a single u64. See module comment for layout.
#[derive(Clone, Copy, PartialEq, Eq)]
#[repr(transparent)]
pub struct PallocSum(u64);

const FIELD_MASK: u64 = (1u64 << LOG_MAX_PACKED_VALUE) - 1;
const FULL_BIT: u64 = 1u64 << 63;

impl PallocSum {
    /// `packPallocSum(start, max, end)` — build a summary from its
    /// three components. If `max == MAX_PACKED_VALUE` (i.e. the entire
    /// region is one free run), all three fields collapse to the
    /// sentinel encoding.
    pub const fn pack(start: usize, max_: usize, end: usize) -> Self {
        if max_ == MAX_PACKED_VALUE {
            return PallocSum(FULL_BIT);
        }
        let s = (start as u64) & FIELD_MASK;
        let m = ((max_ as u64) & FIELD_MASK) << LOG_MAX_PACKED_VALUE;
        let e = ((end as u64) & FIELD_MASK) << (2 * LOG_MAX_PACKED_VALUE);
        PallocSum(s | m | e)
    }

    /// Summary for a region with no free pages.
    pub const fn empty() -> Self {
        PallocSum(0)
    }

    /// Summary for a region whose every page is free, sized to
    /// `pages` pages where `pages <= MAX_PACKED_VALUE`. The caller
    /// guarantees the size — for the maximum-size case use
    /// [`Self::full_max`].
    pub const fn full(pages: usize) -> Self {
        Self::pack(pages, pages, pages)
    }

    /// Summary for a region of `MAX_PACKED_VALUE` fully-free pages —
    /// this is the sentinel encoding (bit 63 set, all other bits 0).
    pub const fn full_max() -> Self {
        PallocSum(FULL_BIT)
    }

    /// Raw underlying u64 — only for debugging / testing.
    pub const fn raw(self) -> u64 {
        self.0
    }

    /// `start()` — pages free at the start of the region.
    pub const fn start(self) -> usize {
        if self.0 & FULL_BIT != 0 {
            return MAX_PACKED_VALUE;
        }
        (self.0 & FIELD_MASK) as usize
    }

    /// `max()` — longest contiguous free run anywhere in the region.
    pub const fn max(self) -> usize {
        if self.0 & FULL_BIT != 0 {
            return MAX_PACKED_VALUE;
        }
        ((self.0 >> LOG_MAX_PACKED_VALUE) & FIELD_MASK) as usize
    }

    /// `end()` — pages free at the end of the region.
    pub const fn end(self) -> usize {
        if self.0 & FULL_BIT != 0 {
            return MAX_PACKED_VALUE;
        }
        ((self.0 >> (2 * LOG_MAX_PACKED_VALUE)) & FIELD_MASK) as usize
    }

    /// `unpack()` — return all three counts at once.
    pub const fn unpack(self) -> (usize, usize, usize) {
        if self.0 & FULL_BIT != 0 {
            return (MAX_PACKED_VALUE, MAX_PACKED_VALUE, MAX_PACKED_VALUE);
        }
        let s = (self.0 & FIELD_MASK) as usize;
        let m = ((self.0 >> LOG_MAX_PACKED_VALUE) & FIELD_MASK) as usize;
        let e = ((self.0 >> (2 * LOG_MAX_PACKED_VALUE)) & FIELD_MASK) as usize;
        (s, m, e)
    }
}

/// `mergeSummaries(sums, logMaxPagesPerSum)` — collapse a slice of
/// adjacent summaries into one summary covering their union, where
/// every input summary describes at most `1 << log_max_pages_per_sum`
/// pages.
///
/// This is the "synthesize parent from children" step of the radix
/// tree's bottom-up update path. Verbatim port of `mergeSummaries` in
/// runtime/mpagealloc.go:1041-1076.
pub fn merge_summaries(sums: &[PallocSum], log_max_pages_per_sum: u32) -> PallocSum {
    // Running summary over sums[0..i].
    let (mut start, mut most, mut end) = sums[0].unpack();

    let block: usize = 1usize << log_max_pages_per_sum;

    let mut i: int = 1;
    while (i as usize) < sums.len() {
        let (si, mi, ei) = sums[i as usize].unpack();

        // The running `start` only extends into sums[i] if every
        // preceding summary was wholly free — i.e. when the running
        // start equals exactly `i * block` pages.
        if start == (i as usize) * block {
            start += si;
        }

        // The new max comes from one of:
        //  (1) the previous running max
        //  (2) the new summary's max
        //  (3) the run straddling the boundary: `end + si`
        let candidate = end + si;
        let mut m = if most >= mi { most } else { mi };
        if candidate > m {
            m = candidate;
        }
        most = m;

        // If sums[i] is wholly free, extend the running end. Else
        // adopt sums[i].end as the new running end.
        if ei == block {
            end += block;
        } else {
            end = ei;
        }

        i += 1;
    }

    PallocSum::pack(start, most, end)
}

// ─── Tests ────────────────────────────────────────────────────────────
//
// Compiled out of release builds; the smoke example also exercises the
// hot path indirectly through `page_alloc::alloc`/`free`.

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pack_unpack_roundtrip() {
        let s = PallocSum::pack(3, 17, 9);
        assert_eq!(s.start(), 3);
        assert_eq!(s.max(), 17);
        assert_eq!(s.end(), 9);
        assert_eq!(s.unpack(), (3, 17, 9));
    }

    #[test]
    fn empty_is_all_zero() {
        let s = PallocSum::empty();
        assert_eq!(s.unpack(), (0, 0, 0));
    }

    #[test]
    fn full_max_uses_sentinel() {
        let s = PallocSum::full_max();
        assert_eq!(s.start(), MAX_PACKED_VALUE);
        assert_eq!(s.max(), MAX_PACKED_VALUE);
        assert_eq!(s.end(), MAX_PACKED_VALUE);
        assert_eq!(s.raw(), 1u64 << 63);
    }

    #[test]
    fn merge_two_free_blocks() {
        // [free 8] [free 8] → start=16, max=16, end=16
        let a = PallocSum::full(8);
        let b = PallocSum::full(8);
        let m = merge_summaries(&[a, b], 3); // 1<<3 = 8 pages each
        assert_eq!(m.unpack(), (16, 16, 16));
    }

    #[test]
    fn merge_straddle_boundary() {
        // [start=0, max=4, end=4] [start=4, max=4, end=0]
        // The 4-end of A and 4-start of B form an 8-page run.
        let a = PallocSum::pack(0, 4, 4);
        let b = PallocSum::pack(4, 4, 0);
        let m = merge_summaries(&[a, b], 3);
        // Combined: start=0 (A wasn't wholly free), max=8 (boundary
        // run), end=0 (B's end).
        assert_eq!(m.unpack(), (0, 8, 0));
    }

    #[test]
    fn merge_alloc_breaks_start_extension() {
        // A is fully free (8 pages); B has start=2, but we still
        // include A.start=8 + B.start=2 = 10 only if A was wholly
        // free — and it was, so start should be 10.
        let a = PallocSum::full(8);
        let b = PallocSum::pack(2, 5, 0);
        let m = merge_summaries(&[a, b], 3);
        assert_eq!(m.start(), 10);
        assert_eq!(m.end(), 0);
        // max = max(8, 5, A.end+B.start = 8+2 = 10) = 10
        assert_eq!(m.max(), 10);
    }
}
