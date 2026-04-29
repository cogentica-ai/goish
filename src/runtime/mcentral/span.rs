// runtime::mcentral::span — Span metadata.
//
// A `Span` describes a contiguous run of pages drawn from mheap and
// subdivided into `nelems` slots of `elemsize` bytes for one size
// class. Mirrors the relevant subset of Go's `runtime.mspan` from
// `runtime/mheap.go:420`, dropping all GC-related fields
// (`gcmarkBits`, `pinnerBits`, `sweepgen`, `freeIndexForScan`,
// `nextGreyIndexInSpan`, etc.) since goish has no GC.
//
// **Concurrency model — Phase ε.lockfree (task #106).**
//
// The slot bitmap is no longer protected by `MCENTRAL.lock()`.
// Instead — modeled on Go's `mcache.allocCache` discipline
// (`runtime/mheap.go:464` and `runtime/mbitmap.go:1093`) — the bitmap
// is split into:
//
//   - `alloc_bits: [AtomicU64; 16]` — shared, atomic. Mutated by
//     cross-M frees (`free_slot_atomic`, `fetch_and`) and the owner's
//     refill (`refill_alloc_cache`, `fetch_or`).
//
//   - `alloc_cache: UnsafeCell<u64>` — owner-private. Once the span
//     is cached in a P's mcache, only that P touches `alloc_cache`.
//     The owner consumes slots from `alloc_cache` via
//     `nextFreeIndex`-style ctz; on word exhaustion it refills from
//     the next 8 bytes of `alloc_bits`. **Mirrors Go's `mspan.allocCache`
//     verbatim (mheap.go:464–470, mbitmap.go:1071–1140)**, with the
//     critical goish addition: refill claims the freshly-loaded free
//     bits via `fetch_or` (not a plain store) so a concurrent free on
//     the same word is preserved.
//
//   - `alloc_count: AtomicU16` — total live slots, decremented by any
//     M's free, incremented by the owner on alloc-from-cache.
//
//   - `freeindex: AtomicU16` — owner-only writer; consumed by the
//     owner-private `nextFreeIndex` loop. Atomic so non-owner reads
//     (e.g. `is_full` from any M) are well-defined.
//
//   - `cached: AtomicBool` — toggled under the central lock, but
//     read lock-free by `mcentral::free` to choose the lock-free or
//     locked path.
//
// **Why goish deviates from Go's plain-store discipline.** In Go,
// `allocBits` is mutated only by the sweeper (which holds the span
// via `sweepgen` state — mcentral.go:128), so the owner P can do a
// non-atomic refill. Goish has no GC and no sweeper, so explicit
// `free` from any M can race with the owner's refill. We close the
// gap with `fetch_or(claim_mask)` during refill: the OR semantics
// preserve any free that landed between the load and the publish.
//
// Slots are tracked by a 1024-bit bitmap (Go's `MaxObjsPerSpan`);
// 1 = allocated, 0 = free. Spans link via `next` / `prev` indices
// into the global span pool — using indices keeps the data structure
// trivially `Send`/`Sync`-able.

#![allow(dead_code)]

use core::cell::UnsafeCell;
use core::sync::atomic::{AtomicBool, AtomicU16, AtomicU64, Ordering};

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
///
/// **Not `Copy`** (atomics aren't `Copy`). Spans live in a fixed
/// `[Span; MAX_SPANS]` static; use the `const { Span::new() }`
/// inline-const initializer instead of `[Span::EMPTY; N]`.
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
    /// Number of currently-allocated slots. Atomic so frees from any
    /// M can decrement without taking the central lock.
    pub alloc_count: AtomicU16,
    /// Hint: scan for free slots starting here. Owner-only writer
    /// while `cached`. Atomic for well-defined cross-M reads.
    pub freeindex: AtomicU16,
    /// Slot allocation bitmap. Bits 0..nelems are valid; bits beyond
    /// must remain 0. Atomic so frees and refills race-free.
    pub alloc_bits: [AtomicU64; ALLOC_BITS_WORDS],
    /// **Owner-private allocCache** (Go: mheap.go:464). Bit-inverted
    /// snapshot of 8 bytes of `alloc_bits` starting at `freeindex`,
    /// shifted so the low bit corresponds to `freeindex`. The owner
    /// P consumes this via `nextFreeIndex` (ctz + shift); when
    /// exhausted, refilled from `alloc_bits` via `refill_alloc_cache`.
    ///
    /// `UnsafeCell` because the owner mutates through `&self`. Sound
    /// because exactly one P touches it during the cached lifetime
    /// (the P with this span in its `mcache[class]` slot).
    pub alloc_cache: UnsafeCell<u64>,
    /// Per-class partial/full list link.
    pub next: u16,
    pub prev: u16,
    /// `true` while this span is owned by a P's mcache. Toggled under
    /// the central lock (`cacheSpan` / `uncacheSpan`); read lock-free
    /// by `mcentral::free` to dispatch to the lock-free or locked
    /// path. Mirrors Go's `mspan.list = nil` while cached invariant.
    pub cached: AtomicBool,
}

// `Span` is `Send` and `Sync` because all shared mutation goes through
// atomics, and `alloc_cache` (the only non-atomic mutable field) is
// disciplined to a single-writer P during its cached lifetime.
unsafe impl Send for Span {}
unsafe impl Sync for Span {}

impl Span {
    /// Const constructor for static placement in `[Span; MAX_SPANS]`
    /// arrays. Use as `[const { Span::new() }; MAX_SPANS]`.
    pub const fn new() -> Span {
        Span {
            base: 0,
            npages: 0,
            elemsize: 0,
            nelems: 0,
            sizeclass: 0,
            alloc_count: AtomicU16::new(0),
            freeindex: AtomicU16::new(0),
            alloc_bits: [const { AtomicU64::new(0) }; ALLOC_BITS_WORDS],
            alloc_cache: UnsafeCell::new(0),
            next: NIL_SPAN,
            prev: NIL_SPAN,
            cached: AtomicBool::new(false),
        }
    }

    /// Reinitialize this span in place to the empty state. Called
    /// from `MCentral::release_span_idx` under the central lock. Does
    /// not touch `next` (caller links into freelist).
    pub fn reset(&mut self) {
        self.base = 0;
        self.npages = 0;
        self.elemsize = 0;
        self.nelems = 0;
        self.sizeclass = 0;
        self.alloc_count.store(0, Ordering::Relaxed);
        self.freeindex.store(0, Ordering::Relaxed);
        for w in &self.alloc_bits {
            w.store(0, Ordering::Relaxed);
        }
        unsafe { *self.alloc_cache.get() = 0; }
        self.next = NIL_SPAN;
        self.prev = NIL_SPAN;
        self.cached.store(false, Ordering::Relaxed);
    }

    /// True if every slot is allocated. Reads `alloc_count` with
    /// Acquire so a successful read pairs with the prior frees /
    /// allocs that produced it.
    #[inline]
    pub fn is_full(&self) -> bool {
        self.alloc_count.load(Ordering::Acquire) == self.nelems
    }

    /// True if no slot is allocated (span eligible for return to mheap).
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.alloc_count.load(Ordering::Acquire) == 0
    }

    /// **`refillAllocCache(whichWord)`** — load 64 bits of `alloc_bits`,
    /// claim every currently-free bit via `fetch_or`, and stash the
    /// inverted result in the owner-private `alloc_cache`. Mirrors
    /// Go's `mspan.refillAllocCache` (mbitmap.go:1075) plus the
    /// goish-specific fetch_or claim.
    ///
    /// **Concurrency**: only the owner P calls this. The `fetch_or`
    /// preserves any cross-M free that lands between our load and
    /// publish — those bits stay 0 in `alloc_bits` and (because they
    /// were 0 in the load) become 1 in `alloc_cache`, which means the
    /// owner sells them on the next `nextFreeIndex` call. Net effect:
    /// the freed slot is recycled by the owner. `alloc_count` is
    /// correctly balanced across the free + the resell.
    ///
    /// Returns the number of bits claimed (popcount of the load
    /// complement) so the caller can `fetch_add` `alloc_count`.
    ///
    /// Safety: caller must be the unique owner P of this span (the
    /// span must be `cached` and on no central list).
    #[inline]
    pub unsafe fn refill_alloc_cache(&self, wi: usize) -> u32 {
        debug_assert!(wi < ALLOC_BITS_WORDS);
        let load = self.alloc_bits[wi].load(Ordering::Acquire);
        let claim_mask = !load;
        if claim_mask != 0 {
            self.alloc_bits[wi].fetch_or(claim_mask, Ordering::Release);
        }
        *self.alloc_cache.get() = claim_mask;
        claim_mask.count_ones()
    }

    /// **`nextFreeIndex` (Go: mbitmap.go:1093) — owner-private slot
    /// pop.** Consumes one slot from `alloc_cache`, refilling from
    /// `alloc_bits` (via `refill_alloc_cache`) when exhausted.
    /// Returns the slot index, or `None` if the span is full.
    ///
    /// **Concurrency**: same as `refill_alloc_cache` — owner P only.
    /// Does not touch `alloc_count`; the caller must `fetch_add(1)`
    /// `alloc_count` for the slot it consumes (or pre-add at refill
    /// time, which is what `next_free_owner` does).
    ///
    /// Safety: same as `refill_alloc_cache`.
    pub unsafe fn next_free_owner(&self) -> Option<u16> {
        let nelems = self.nelems;
        let mut sfreeindex = self.freeindex.load(Ordering::Relaxed);
        if sfreeindex >= nelems {
            return None;
        }

        let mut acache = *self.alloc_cache.get();
        let mut bit_index = acache.trailing_zeros();
        while bit_index == 64 {
            // Move freeindex to start of next 64-bit window.
            sfreeindex = (sfreeindex.wrapping_add(64)) & !63;
            if sfreeindex >= nelems {
                self.freeindex.store(nelems, Ordering::Relaxed);
                return None;
            }
            let claimed = self.refill_alloc_cache((sfreeindex / 64) as usize);
            if claimed != 0 {
                self.alloc_count
                    .fetch_add(claimed as u16, Ordering::AcqRel);
            }
            acache = *self.alloc_cache.get();
            bit_index = acache.trailing_zeros();
        }

        let slot = sfreeindex.wrapping_add(bit_index as u16);
        if slot >= nelems {
            self.freeindex.store(nelems, Ordering::Relaxed);
            return None;
        }

        // Shift past the bit we just consumed.
        *self.alloc_cache.get() = acache >> (bit_index + 1);
        let new_freeindex = slot.wrapping_add(1);

        // If the shift exhausted alloc_cache and we're still at a
        // 64-bit boundary, prefetch the next word — mirrors Go
        // (mbitmap.go:1130–1138).
        if new_freeindex.is_multiple_of(64) && new_freeindex < nelems {
            let claimed = self.refill_alloc_cache((new_freeindex / 64) as usize);
            if claimed != 0 {
                self.alloc_count
                    .fetch_add(claimed as u16, Ordering::AcqRel);
            }
        }

        self.freeindex.store(new_freeindex, Ordering::Relaxed);
        Some(slot)
    }

    /// **`uncacheSpan` half — release unsold cached bits.** When the
    /// owner returns a cached span to the central lists, any bits
    /// still set in `alloc_cache` represent slots reserved during
    /// `refill_alloc_cache` but never sold to a user. Clear them
    /// from `alloc_bits` and decrement `alloc_count` to match.
    ///
    /// Safety: owner P only, called under the central lock during
    /// `mcentral::uncacheSpan` (the lock prevents another M from
    /// concurrently re-caching this span).
    pub unsafe fn release_unsold(&self) {
        let acache = *self.alloc_cache.get();
        if acache == 0 {
            return;
        }
        let sfreeindex = self.freeindex.load(Ordering::Relaxed) as usize;
        let wi = sfreeindex / 64;
        let bit_offset = sfreeindex % 64;
        // alloc_cache is shifted so its low bit corresponds to freeindex.
        // Convert back to absolute word coordinates via left-shift.
        if wi < ALLOC_BITS_WORDS {
            let release_mask = acache.wrapping_shl(bit_offset as u32);
            if release_mask != 0 {
                let cleared = release_mask.count_ones();
                self.alloc_bits[wi].fetch_and(!release_mask, Ordering::Release);
                self.alloc_count
                    .fetch_sub(cleared as u16, Ordering::AcqRel);
            }
        }
        *self.alloc_cache.get() = 0;
    }

    /// **Locked-path alloc** — scan `alloc_bits` directly (no
    /// `alloc_cache`), claim the first free bit at or after
    /// `freeindex`. Used by `mcentral::alloc` for the uncached
    /// central path where the central SpinLock provides single-writer
    /// discipline. Returns the slot index, or `None` if the span is
    /// full.
    ///
    /// Concurrency: safe to call against an atomic-backed span as
    /// long as the caller serializes itself with other locked-path
    /// callers via the central lock. Cross-M frees may still race
    /// (using `free_slot_atomic`); the `fetch_or` here only sets a
    /// bit that was 0 in our snapshot, so a concurrent free that
    /// cleared a different bit is preserved.
    pub fn alloc_slot_locked(&self) -> Option<u16> {
        let nelems = self.nelems;
        let sfreeindex = self.freeindex.load(Ordering::Relaxed);
        if sfreeindex >= nelems {
            return None;
        }
        let mut wi = (sfreeindex / 64) as usize;
        while wi < ALLOC_BITS_WORDS {
            let word = self.alloc_bits[wi].load(Ordering::Acquire);
            let inv = !word;
            let word_base = (wi * 64) as u16;
            let start_bit = if word_base < sfreeindex {
                (sfreeindex - word_base) as u32
            } else {
                0
            };
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
            let bit = candidate.trailing_zeros();
            let slot = word_base.wrapping_add(bit as u16);
            if slot >= nelems {
                self.freeindex.store(nelems, Ordering::Relaxed);
                return None;
            }
            self.alloc_bits[wi].fetch_or(1u64 << bit, Ordering::AcqRel);
            self.alloc_count.fetch_add(1, Ordering::AcqRel);
            self.freeindex.store(slot.wrapping_add(1), Ordering::Relaxed);
            return Some(slot);
        }
        None
    }

    /// **Locked-path free** — like `free_slot_atomic`, but also rewinds
    /// `freeindex` so the next `alloc_slot_locked` rediscovers this
    /// slot. Caller holds the central SpinLock (uncached spans only).
    pub fn free_slot_locked(&self, idx: u16) {
        let i = idx as usize;
        let wi = i / 64;
        if wi >= ALLOC_BITS_WORDS {
            return;
        }
        let mask = 1u64 << (i % 64);
        let prev = self.alloc_bits[wi].fetch_and(!mask, Ordering::AcqRel);
        if prev & mask != 0 {
            self.alloc_count.fetch_sub(1, Ordering::AcqRel);
            let cur = self.freeindex.load(Ordering::Relaxed);
            if idx < cur {
                self.freeindex.store(idx, Ordering::Relaxed);
            }
        }
    }

    /// **Atomic free** — clear bit `idx` and decrement `alloc_count`.
    /// Safe to call from any M; takes no locks. Idempotent: a
    /// double-free (bit already clear) is a no-op.
    ///
    /// Does not touch `freeindex` — that's owner-private and the
    /// owner will re-discover the freed slot on its next refill.
    /// Mirrors the property of Go's `freeindex` as a hint
    /// (mheap.go:431, "freeindex is then adjusted so that subsequent
    /// scans begin just past the newly discovered free object" — i.e.
    /// the scanner never relies on freeindex being a tight upper
    /// bound on alloc'd slots).
    pub fn free_slot_atomic(&self, idx: u16) {
        let i = idx as usize;
        let wi = i / 64;
        if wi >= ALLOC_BITS_WORDS {
            return;
        }
        let mask = 1u64 << (i % 64);
        let prev = self.alloc_bits[wi].fetch_and(!mask, Ordering::AcqRel);
        if prev & mask != 0 {
            self.alloc_count.fetch_sub(1, Ordering::AcqRel);
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

    /// Debug invariant: `popcount(alloc_bits) == alloc_count`. Walks
    /// every word; only meaningful while the span is at rest (not
    /// mid-refill on the owner path). Panics on mismatch.
    #[cfg(debug_assertions)]
    pub fn debug_audit(&self, ctx: &'static str) {
        let mut popcount: u32 = 0;
        for w in &self.alloc_bits {
            popcount += w.load(Ordering::Acquire).count_ones();
        }
        let count = self.alloc_count.load(Ordering::Acquire) as u32;
        if popcount != count {
            // Don't take any locks in here — we may be holding
            // MCENTRAL.lock() at the call site.
            const PRE: &[u8] = b"goish: span audit fail (";
            const MID: &[u8] = b") popcount=";
            const POST: &[u8] = b" alloc_count=";
            const NL: &[u8] = b"\n";
            crate::syscall::Write(crate::syscall::STDERR, PRE.as_ptr(), PRE.len());
            crate::syscall::Write(crate::syscall::STDERR, ctx.as_ptr(), ctx.len());
            crate::syscall::Write(crate::syscall::STDERR, MID.as_ptr(), MID.len());
            let mut buf = [0u8; 8];
            let n = u32_to_dec(popcount, &mut buf);
            crate::syscall::Write(crate::syscall::STDERR, buf.as_ptr(), n);
            crate::syscall::Write(crate::syscall::STDERR, POST.as_ptr(), POST.len());
            let n = u32_to_dec(count, &mut buf);
            crate::syscall::Write(crate::syscall::STDERR, buf.as_ptr(), n);
            crate::syscall::Write(crate::syscall::STDERR, NL.as_ptr(), NL.len());
            panic!("span audit fail");
        }
    }
}

/// Render `n` in decimal into `buf`, returning the byte length.
/// Async-signal / no-alloc safe; used by `debug_audit`.
#[cfg(debug_assertions)]
fn u32_to_dec(mut n: u32, buf: &mut [u8; 8]) -> usize {
    if n == 0 {
        buf[0] = b'0';
        return 1;
    }
    let mut tmp = [0u8; 8];
    let mut i = 0;
    while n > 0 && i < 8 {
        tmp[i] = b'0' + (n % 10) as u8;
        n /= 10;
        i += 1;
    }
    let len = i;
    for j in 0..len {
        buf[j] = tmp[len - 1 - j];
    }
    len
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fresh(elemsize: u32, nelems: u16) -> Span {
        let s = Span::new();
        // SAFETY: `s` is a stack-local Span we just constructed; we
        // hold the only reference, so writing through &self is sound
        // in this test.
        let s_ref: &Span = &s;
        unsafe {
            let m: *mut Span = s_ref as *const Span as *mut Span;
            (*m).base = 0x100_0000;
            (*m).npages = 1;
            (*m).elemsize = elemsize;
            (*m).nelems = nelems;
            (*m).sizeclass = 1;
        }
        s
    }

    #[test]
    fn alloc_then_free_via_owner_cache() {
        let s = fresh(8, 1024);
        // Prime the alloc cache (refill word 0).
        unsafe {
            let claimed = s.refill_alloc_cache(0);
            assert_eq!(claimed, 64);
            s.alloc_count.fetch_add(claimed as u16, Ordering::AcqRel);
        }
        let a = unsafe { s.next_free_owner().unwrap() };
        let b = unsafe { s.next_free_owner().unwrap() };
        assert_eq!(a, 0);
        assert_eq!(b, 1);
        // alloc_count tracks reserved bits; refill claimed 64.
        assert_eq!(s.alloc_count.load(Ordering::Relaxed), 64);
        // Freeing slot 0 just drops the bit + decrements count.
        s.free_slot_atomic(0);
        assert_eq!(s.alloc_count.load(Ordering::Relaxed), 63);
    }

    #[test]
    fn slot_addressing() {
        let s = fresh(32, 256);
        unsafe {
            let m: *mut Span = &s as *const Span as *mut Span;
            (*m).base = 0x4000;
        }
        assert_eq!(s.slot_addr(2), 0x4000 + 2 * 32);
        assert_eq!(s.slot_of(0x4000 + 5 * 32), 5);
    }

    #[test]
    fn cross_m_free_during_refill_preserved() {
        // Simulate: owner refills word 0 with bits 0..7 marked alloc'd;
        // a "concurrent" free clears bit 3 between load and fetch_or.
        let s = fresh(8, 1024);
        s.alloc_bits[0].store(0xFF, Ordering::Release);
        s.alloc_count.store(8, Ordering::Release);
        // Owner load sees 0xFF; would claim the 56 high-zero bits.
        let load = s.alloc_bits[0].load(Ordering::Acquire);
        let claim_mask = !load; // = 0xFFFF_FFFF_FFFF_FF00
        // Concurrent free clears bit 3.
        s.alloc_bits[0].fetch_and(!(1u64 << 3), Ordering::AcqRel);
        s.alloc_count.fetch_sub(1, Ordering::AcqRel);
        // Owner publishes claim via fetch_or.
        s.alloc_bits[0].fetch_or(claim_mask, Ordering::Release);
        // Final state: bit 3 still 0 (free preserved); high bits all 1.
        let final_word = s.alloc_bits[0].load(Ordering::Acquire);
        assert_eq!(final_word, 0xFFFF_FFFF_FFFF_FFF7);
        assert_eq!(s.alloc_count.load(Ordering::Relaxed), 7);
    }
}
