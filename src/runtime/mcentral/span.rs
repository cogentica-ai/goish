// runtime::mcentral::span — Span metadata.
//
// A `Span` describes a contiguous run of pages drawn from mheap and
// subdivided into `nelems` slots of `elemsize` bytes for one size
// class. Mirrors the relevant subset of Go's `runtime.mspan` from
// runtime/mheap.go:420, dropping all GC-related fields
// (gcmarkBits, pinnerBits, sweepgen, freeIndexForScan,
// nextGreyIndexInSpan, etc.).
//
// Slots are tracked by a 1024-bit `alloc_bits` bitmap (Go's
// `MaxObjsPerSpan`); 1 = allocated, 0 = free. Spans are linked into
// per-class partial/full lists via `next` / `prev` indices into the
// global span pool — using indices instead of raw pointers keeps the
// data structure trivially `Send`/`Sync`-able under the central
// mcentral lock and avoids any `unsafe` for list manipulation.

#![allow(dead_code)]

/// Sentinel index meaning "no span" (head/tail of a list, or
/// "uninitialized" in the page → span map).
///
/// We use `0` rather than `u16::MAX` so that the static `MCentral`
/// instance — which contains a 4096-entry `[Span; 4096]` array —
/// stays in BSS (zero-initialized) rather than being lifted into the
/// data segment because of non-zero `next`/`prev` defaults. As a
/// consequence, span index `0` of the pool is reserved/unused; live
/// span indices start at `1`.
pub const NIL_SPAN: u16 = 0;

/// Maximum number of bits in a span's allocation bitmap. Matches
/// Go's `MaxObjsPerSpan = 1024`.
pub const MAX_OBJS_PER_SPAN: usize = 1024;

/// Words in `alloc_bits`. 1024 bits / 64 = 16 u64s.
pub const ALLOC_BITS_WORDS: usize = MAX_OBJS_PER_SPAN / 64;

/// `Span` — one run of pages serving one size class.
#[derive(Clone, Copy)]
pub struct Span {
    /// Virtual base address of the span's first page.
    pub base: usize,
    /// Span size in pages.
    pub npages: u16,
    /// Bytes per slot.
    pub elemsize: u32,
    /// Total number of slots in the span (`npages*PAGE_SIZE / elemsize`).
    pub nelems: u16,
    /// Size class (1..=67); 0 if span is unused.
    pub sizeclass: u8,
    /// Number of currently-allocated slots.
    pub alloc_count: u16,
    /// Hint: scan for free slots starting here.
    pub freeindex: u16,
    /// Slot allocation bitmap. Bits 0..nelems are valid; bits beyond
    /// must remain 0.
    pub alloc_bits: [u64; ALLOC_BITS_WORDS],
    /// Per-class partial/full list link.
    pub next: u16,
    pub prev: u16,
}

impl Span {
    /// Empty span (used as sentinel before initialization).
    pub const EMPTY: Span = Span {
        base: 0,
        npages: 0,
        elemsize: 0,
        nelems: 0,
        sizeclass: 0,
        alloc_count: 0,
        freeindex: 0,
        alloc_bits: [0; ALLOC_BITS_WORDS],
        next: NIL_SPAN,
        prev: NIL_SPAN,
    };

    /// True if every slot is allocated.
    #[inline]
    pub fn is_full(&self) -> bool {
        self.alloc_count == self.nelems
    }

    /// True if no slot is allocated (span eligible for return to mheap).
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.alloc_count == 0
    }

    /// Find a free slot starting at `freeindex`, mark it allocated,
    /// return its index. Returns `None` if the span is full.
    pub fn alloc_slot(&mut self) -> Option<u16> {
        let bits = &mut self.alloc_bits;
        // Scan u64 words starting from freeindex/64.
        let mut wi = (self.freeindex as usize) / 64;
        while wi < ALLOC_BITS_WORDS {
            let inv = !bits[wi];
            if inv == 0 {
                wi += 1;
                continue;
            }
            // Bits within this word that are >= freeindex.
            let start_bit = if wi * 64 < self.freeindex as usize {
                self.freeindex as usize - wi * 64
            } else {
                0
            };
            // Mask off bits below start_bit.
            let mask = if start_bit == 0 {
                u64::MAX
            } else {
                u64::MAX << start_bit
            };
            let candidate = inv & mask;
            if candidate == 0 {
                wi += 1;
                continue;
            }
            let bit = candidate.trailing_zeros() as usize;
            let slot = wi * 64 + bit;
            if slot >= self.nelems as usize {
                return None;
            }
            bits[wi] |= 1u64 << bit;
            self.alloc_count += 1;
            self.freeindex = (slot + 1) as u16;
            return Some(slot as u16);
        }
        None
    }

    /// Mark slot `idx` free. Caller is responsible for ensuring it
    /// was previously allocated (double-free is a no-op here).
    pub fn free_slot(&mut self, idx: u16) {
        let i = idx as usize;
        let wi = i / 64;
        let bi = i % 64;
        let mask = 1u64 << bi;
        if self.alloc_bits[wi] & mask != 0 {
            self.alloc_bits[wi] &= !mask;
            self.alloc_count -= 1;
            // Move freeindex back so a subsequent alloc finds this slot first.
            if (idx as u16) < self.freeindex {
                self.freeindex = idx;
            }
        }
    }

    /// Address of slot `idx` in this span.
    #[inline]
    pub fn slot_addr(&self, idx: u16) -> usize {
        self.base + (idx as usize) * (self.elemsize as usize)
    }

    /// Compute the slot index containing address `addr`. The caller
    /// must have already verified that `addr` lies inside this span.
    #[inline]
    pub fn slot_of(&self, addr: usize) -> u16 {
        let off = addr - self.base;
        (off / (self.elemsize as usize)) as u16
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fresh(elemsize: u32, nelems: u16) -> Span {
        Span {
            base: 0x100_0000,
            npages: 1,
            elemsize,
            nelems,
            sizeclass: 1,
            alloc_count: 0,
            freeindex: 0,
            alloc_bits: [0; ALLOC_BITS_WORDS],
            next: NIL_SPAN,
            prev: NIL_SPAN,
        }
    }

    #[test]
    fn alloc_then_free_slot() {
        let mut s = fresh(8, 1024);
        let a = s.alloc_slot().unwrap();
        let b = s.alloc_slot().unwrap();
        assert_eq!(a, 0);
        assert_eq!(b, 1);
        assert_eq!(s.alloc_count, 2);
        s.free_slot(0);
        assert_eq!(s.alloc_count, 1);
        // Next alloc reuses slot 0 (lower than freeindex=2).
        let c = s.alloc_slot().unwrap();
        assert_eq!(c, 0);
    }

    #[test]
    fn fill_then_overflow() {
        let mut s = fresh(8, 8);
        for i in 0..8u16 {
            assert_eq!(s.alloc_slot().unwrap(), i);
        }
        assert!(s.is_full());
        assert!(s.alloc_slot().is_none());
    }

    #[test]
    fn slot_addressing() {
        let mut s = fresh(32, 256);
        s.base = 0x4000;
        let _ = s.alloc_slot();
        let _ = s.alloc_slot();
        assert_eq!(s.slot_addr(2), 0x4000 + 2 * 32);
        assert_eq!(s.slot_of(0x4000 + 5 * 32), 5);
    }
}
