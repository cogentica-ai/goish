// runtime::mcentral — central per-size-class span pool.
//
// Slim port of Go's runtime/mcentral.go. Per size class we keep two
// intrusive linked lists of `Span`s:
//
//   - **partial**: spans with at least one free slot. Allocations
//     consume from the head; freeing into a full span moves it here.
//   - **full**: spans with no free slots. Spans land here when their
//     last slot is consumed; they leave when a free creates a gap.
//
// Spans themselves live in a global static `SpanPool` (bump-allocated
// indices into a fixed-size array, ~150 KiB BSS for 1024 spans).
// A `page_to_span` map gives O(1) lookup from any address back to
// the span containing it — needed because `dealloc` only receives a
// pointer + layout, not a span handle.
//
// Concurrency: one global SpinLock around the entire MCentral. The
// per-class locking + per-P mcache that Go uses to make this
// lock-free are (a) unnecessary for single-threaded goish today and
// (b) blocked on M16b (the P struct). Multi-M (M17a) will wait on
// per-P mcache (2d) before going wide.
//
// Bootstrap: `mcentral_init()` is a no-op — all data lives in BSS,
// the `partial`/`full` heads are static `NIL_SPAN`, and the page→span
// map is statically zero-initialized. The first alloc allocates its
// first span lazily from mheap.

#![allow(dead_code)]

pub mod sizeclasses;
pub mod span;

use crate::runtime::mheap::consts::PAGE_SIZE;
use crate::runtime::mheap::page_alloc::ALLOC_FAILED;
use crate::syscall;

use sizeclasses::{class_for, NPAGES_OF_CLASS, NUM_SIZE_CLASSES, SIZE_OF_CLASS};
use span::{Span, NIL_SPAN};

/// Maximum number of live spans in the heap. Saturates the `u16`
/// span-index width (sentinel 0 reserved). For a workload spawning
/// 1 M goroutines at ~400 B per G struct + ~50 B per closure box,
/// expect ~50 K spans of small classes — fits comfortably.
pub const MAX_SPANS: usize = 65535;

/// Maximum number of pages the page → span map covers. 256 K pages
/// × 8 KiB = 2 GiB of tracked arena. Sized for 1 M-goroutine
/// workloads (~450 MB G + closure heap, plus headroom).
pub const MAX_TRACKED_PAGES: usize = 256 * 1024;

/// `MCentral` — per-size-class central span lists, plus the span
/// pool and page-to-span map.
pub struct MCentral {
    /// `partial[c]` — head index of partially-filled spans for class c.
    pub partial: [u16; NUM_SIZE_CLASSES],
    /// `full[c]` — head index of fully-allocated spans for class c.
    pub full: [u16; NUM_SIZE_CLASSES],

    /// Span storage. Indices stored in `partial`/`full` and
    /// `page_to_span` refer into this array.
    pub spans: [Span; MAX_SPANS],

    /// Bump pointer for never-used span slots in `spans`.
    pub spans_bump: u16,

    /// Freelist of recyclable span slots (returned via `release_span`).
    pub spans_free_head: u16,

    /// `page_to_span[page_idx]` = span index, or `NIL_SPAN` if no
    /// span owns that page. `page_idx` is computed relative to the
    /// arena base; outside the tracked range, the small path returns
    /// failure and the caller falls back to the large path.
    pub page_to_span: [u16; MAX_TRACKED_PAGES],

    /// Arena base address — used to translate raw pointers into
    /// page indices.
    pub arena_base: usize,
}

impl MCentral {
    /// `const` constructor for static placement. With `NIL_SPAN = 0`
    /// and every other field zero-valued, the entire ~700 KiB
    /// static lands in BSS rather than the data segment, keeping
    /// the on-disk binary size identical to pre-mcentral builds.
    ///
    /// Span index 0 is reserved as the sentinel; `alloc_span_idx`
    /// returns indices `1..MAX_SPANS`. Equivalently, `spans_bump`
    /// is the number of slots allocated so far, and the next
    /// allocation gets index `spans_bump + 1`.
    pub const fn new() -> Self {
        MCentral {
            partial: [NIL_SPAN; NUM_SIZE_CLASSES],
            full: [NIL_SPAN; NUM_SIZE_CLASSES],
            spans: [const { Span::new() }; MAX_SPANS],
            spans_bump: 0,
            spans_free_head: NIL_SPAN,
            page_to_span: [NIL_SPAN; MAX_TRACKED_PAGES],
            arena_base: 0,
        }
    }

    /// Acquire a free slot in the `spans` array — either via the
    /// freelist (returned slots) or the bump pointer. `spans_bump`
    /// counts how many slots have been bump-allocated; the next
    /// returned index is `spans_bump + 1` (slot 0 is reserved as
    /// the `NIL_SPAN` sentinel).
    fn alloc_span_idx(&mut self) -> u16 {
        if self.spans_free_head != NIL_SPAN {
            let idx = self.spans_free_head;
            self.spans_free_head = self.spans[idx as usize].next;
            self.spans[idx as usize].reset();
            return idx;
        }
        let idx = self.spans_bump + 1;
        if (idx as usize) >= MAX_SPANS {
            oom(b"goish: mcentral: span table exhausted\n");
        }
        self.spans_bump += 1;
        idx
    }

    /// Return a span slot to the freelist after the span has been
    /// released to mheap. Caller must have already cleared the
    /// page_to_span entries.
    fn release_span_idx(&mut self, idx: u16) {
        self.spans[idx as usize].reset();
        self.spans[idx as usize].next = self.spans_free_head;
        self.spans_free_head = idx;
    }

    /// Pop the head of `partial[class]`, or `NIL_SPAN` if empty.
    fn partial_pop(&mut self, class: u8) -> u16 {
        let idx = self.partial[class as usize];
        if idx == NIL_SPAN {
            return NIL_SPAN;
        }
        self.list_remove(idx);
        idx
    }

    /// Insert span `idx` at the head of `partial[class]`.
    fn partial_push(&mut self, idx: u16) {
        let class = self.spans[idx as usize].sizeclass;
        let head = self.partial[class as usize];
        self.spans[idx as usize].next = head;
        self.spans[idx as usize].prev = NIL_SPAN;
        if head != NIL_SPAN {
            self.spans[head as usize].prev = idx;
        }
        self.partial[class as usize] = idx;
    }

    /// Insert span `idx` at the head of `full[class]`.
    fn full_push(&mut self, idx: u16) {
        let class = self.spans[idx as usize].sizeclass;
        let head = self.full[class as usize];
        self.spans[idx as usize].next = head;
        self.spans[idx as usize].prev = NIL_SPAN;
        if head != NIL_SPAN {
            self.spans[head as usize].prev = idx;
        }
        self.full[class as usize] = idx;
    }

    /// Remove span `idx` from whichever list (partial or full) it is
    /// currently on.
    fn list_remove(&mut self, idx: u16) {
        let next = self.spans[idx as usize].next;
        let prev = self.spans[idx as usize].prev;
        let class = self.spans[idx as usize].sizeclass;
        if prev != NIL_SPAN {
            self.spans[prev as usize].next = next;
        } else {
            // idx was a head — figure out which list.
            if self.partial[class as usize] == idx {
                self.partial[class as usize] = next;
            } else if self.full[class as usize] == idx {
                self.full[class as usize] = next;
            }
        }
        if next != NIL_SPAN {
            self.spans[next as usize].prev = prev;
        }
        self.spans[idx as usize].next = NIL_SPAN;
        self.spans[idx as usize].prev = NIL_SPAN;
    }

    /// Initialize a fresh span at `idx` for `class`, backed by pages
    /// already obtained from mheap at `base`.
    fn init_span(&mut self, idx: u16, class: u8, base: usize) {
        let elemsize = SIZE_OF_CLASS[class as usize] as u32;
        let npages = NPAGES_OF_CLASS[class as usize] as u16;
        let nelems = (npages as u32 * PAGE_SIZE as u32) / elemsize;
        let s = &mut self.spans[idx as usize];
        s.base = base;
        s.npages = npages;
        s.elemsize = elemsize;
        s.nelems = nelems as u16;
        s.sizeclass = class;
        s.alloc_count.store(0, Ordering::Relaxed);
        s.freeindex.store(0, Ordering::Relaxed);
        for w in &s.alloc_bits {
            w.store(0, Ordering::Relaxed);
        }
        unsafe { *s.alloc_cache.get() = 0; }
        s.next = NIL_SPAN;
        s.prev = NIL_SPAN;

        // Register this span's pages in the page → span map.
        let first_page = (base - self.arena_base) / PAGE_SIZE;
        for p in first_page..(first_page + npages as usize) {
            if p < MAX_TRACKED_PAGES {
                self.page_to_span[p] = idx;
            }
        }
    }
}

/// Print `msg` and exit(2). Used for fatal allocator errors.
fn oom(msg: &[u8]) -> ! {
    syscall::Write(syscall::STDERR, msg.as_ptr(), msg.len());
    syscall::Exit(2);
}

// ─── Global instance + init ───────────────────────────────────────────

use crate::runtime::spin::SpinLock;
use core::sync::atomic::{AtomicBool, Ordering};

static MCENTRAL: SpinLock<MCentral> = SpinLock::new(MCentral::new());
static MCENTRAL_READY: AtomicBool = AtomicBool::new(false);

/// One-time init. Called from `__goish_rt0` *after* `mheap_init`.
pub unsafe fn mcentral_init(arena_base: usize) {
    let mut g = MCENTRAL.lock();
    g.arena_base = arena_base;
    drop(g);
    MCENTRAL_READY.store(true, Ordering::Release);
}

/// True if mcentral is initialized and ready to serve allocations.
#[inline]
pub fn ready() -> bool {
    MCENTRAL_READY.load(Ordering::Acquire)
}

// ─── Public alloc / free ──────────────────────────────────────────────

/// Allocate `(size, align)` from mcentral. Returns null if the
/// requested class can't be served (caller should route to mheap).
pub unsafe fn alloc(size: usize, align: usize) -> *mut u8 {
    let class = match class_for(size, align) {
        Some(c) if c >= 1 => c,
        _ => return core::ptr::null_mut(),
    };

    // Try the partial list first.
    let mut g = MCENTRAL.lock();
    let mut idx = g.partial[class as usize];
    if idx == NIL_SPAN {
        // No partial span — allocate fresh from mheap.
        let npages = NPAGES_OF_CLASS[class as usize] as usize;
        // Drop the lock during the mheap call (mheap has its own lock).
        drop(g);
        let base = crate::runtime::mheap_alloc_pages(npages);
        if base == ALLOC_FAILED {
            return core::ptr::null_mut();
        }
        let mut g2 = MCENTRAL.lock();
        let new_idx = g2.alloc_span_idx();
        g2.init_span(new_idx, class, base);
        g2.partial_push(new_idx);
        idx = new_idx;
        g = g2;
    }

    // Pull a slot from the partial-head span.
    let span = &g.spans[idx as usize];
    let slot = match span.alloc_slot_locked() {
        Some(s) => s,
        None => {
            // Span head was full despite living on the partial list —
            // shouldn't happen, but recover gracefully.
            g.list_remove(idx);
            g.full_push(idx);
            return core::ptr::null_mut();
        }
    };
    let addr = span.slot_addr(slot);

    // Move span to full list if its last slot was consumed.
    if span.is_full() {
        g.list_remove(idx);
        g.full_push(idx);
    }

    addr as *mut u8
}

/// Free a pointer obtained from `mcentral::alloc`. Returns true on
/// success, false if `ptr` is not owned by mcentral (caller should
/// route to mheap).
///
/// **Concurrency** (post task #106). The lookup phase
/// (`page_to_span`, span bounds, `cached` flag) needs to consult
/// `MCentral` state; the lock is held briefly to read it. Once we
/// know the span is *cached*, the actual bit clear + count decrement
/// happen via atomic ops (`free_slot_atomic`) **after the lock is
/// dropped** — this is the path that the per-P mcache hot-path free
/// takes. For uncached spans, the lock is reacquired (or held) for
/// list manipulation and possible mheap return.
pub unsafe fn free(ptr: *mut u8) -> bool {
    let p = ptr as usize;
    let mut g = MCENTRAL.lock();
    let arena_base = g.arena_base;
    if p < arena_base {
        return false;
    }
    let page_idx = (p - arena_base) / PAGE_SIZE;
    if page_idx >= MAX_TRACKED_PAGES {
        return false;
    }
    let idx = g.page_to_span[page_idx];
    if idx == NIL_SPAN {
        return false;
    }
    let span = &g.spans[idx as usize];
    if p < span.base || p >= span.base + span.npages as usize * PAGE_SIZE {
        return false;
    }
    let was_cached = span.cached.load(Ordering::Acquire);
    let slot = span.slot_of(p);

    if was_cached {
        // Lock-free fast path: cached span lives on no central list,
        // so list manipulation is unnecessary. Drop the central lock
        // before the atomic bit clear so other Ms aren't blocked on
        // it. The owning P sees the freed slot on its next
        // `refill_alloc_cache` (which OR-claims fresh free bits) or
        // on `uncacheSpan` (which releases unsold reserved bits).
        drop(g);
        // Re-borrow span via the static for lock-free atomic ops.
        // Safe: spans live in a fixed-size static; index is stable
        // once allocated. The atomic ops on alloc_bits/alloc_count
        // are the only mutations.
        let span_ref = span_by_idx(idx);
        span_ref.free_slot_atomic(slot);
        return true;
    }

    let was_full = g.spans[idx as usize].is_full();
    g.spans[idx as usize].free_slot_locked(slot);

    if was_full {
        // Move span from full to partial.
        g.list_remove(idx);
        g.partial_push(idx);
    }
    if g.spans[idx as usize].is_empty() {
        // Return all pages to mheap.
        let base = g.spans[idx as usize].base;
        let npages = g.spans[idx as usize].npages as usize;
        // Clear page → span map for these pages.
        let first_page = (base - arena_base) / PAGE_SIZE;
        for pp in first_page..(first_page + npages) {
            if pp < MAX_TRACKED_PAGES {
                g.page_to_span[pp] = NIL_SPAN;
            }
        }
        g.list_remove(idx);
        g.release_span_idx(idx);
        drop(g);
        crate::runtime::mheap_free_pages(base, npages);
    }
    true
}

/// Borrow a `&'static Span` by index without holding the central
/// lock. Spans live in a fixed-size BSS-resident static array; their
/// addresses are stable across the program's lifetime once a slot is
/// bump-allocated. All mutation that races with this borrow goes
/// through atomic fields (`alloc_bits`, `alloc_count`, `freeindex`,
/// `cached`). The non-atomic descriptive fields (`base`, `npages`,
/// `elemsize`, `nelems`, `sizeclass`) are written exactly once under
/// the central lock during `init_span`, before any caller can ever
/// see this index, and are not mutated again until `release_span_idx`
/// (which only runs after the span is empty and removed from all
/// lists, by which point no concurrent reader holds the index).
unsafe fn span_by_idx(idx: u16) -> &'static Span {
    // `data_unchecked()` is the documented unsafe escape hatch. We
    // immediately re-borrow as `&Span` (shared) and only invoke
    // atomic methods on it. Lifetime extends to `'static` because
    // `MCENTRAL` is a static.
    let mc: &mut MCentral = MCENTRAL.data_unchecked();
    let s: &Span = &mc.spans[idx as usize];
    core::mem::transmute::<&Span, &'static Span>(s)
}

/// **`cacheSpan(class)`** — pop a span the calling P can alloc from
/// without contending the central lock on every slot. Mirrors Go's
/// `runtime.(*mcentral).cacheSpan` (mcentral.go).
///
/// Returns `NIL_SPAN` if the per-class central pool is empty AND no
/// fresh span can be drawn from mheap (OOM).
///
/// The returned span is **removed from the partial list** — it is
/// not on any central list while cached. The owning P must call
/// `uncacheSpan(idx)` to return it.
pub unsafe fn cacheSpan(class: u8) -> u16 {
    let mut g = MCENTRAL.lock();
    if class == 0 || (class as usize) >= NUM_SIZE_CLASSES {
        return NIL_SPAN;
    }
    let idx = g.partial[class as usize];
    if idx != NIL_SPAN {
        g.list_remove(idx);
        // Reset freeindex and prime alloc_cache so the owner P starts
        // fresh on this span. Mirrors Go's `cacheSpan` (mcentral.go:189):
        // `freeByteBase := s.freeindex &^ (64 - 1); whichByte := freeByteBase / 8;
        //  s.refillAllocCache(whichByte); s.allocCache >>= s.freeindex % 64`.
        let s = &g.spans[idx as usize];
        s.freeindex.store(0, Ordering::Relaxed);
        let claimed = s.refill_alloc_cache(0);
        if claimed != 0 {
            s.alloc_count.fetch_add(claimed as u16, Ordering::AcqRel);
        }
        s.cached.store(true, Ordering::Release);
        return idx;
    }
    // No partial — draw a fresh span from mheap.
    let npages = NPAGES_OF_CLASS[class as usize] as usize;
    drop(g);
    let base = crate::runtime::mheap_alloc_pages(npages);
    if base == ALLOC_FAILED {
        return NIL_SPAN;
    }
    let mut g2 = MCENTRAL.lock();
    let new_idx = g2.alloc_span_idx();
    g2.init_span(new_idx, class, base);
    let s = &g2.spans[new_idx as usize];
    let claimed = s.refill_alloc_cache(0);
    if claimed != 0 {
        s.alloc_count.fetch_add(claimed as u16, Ordering::AcqRel);
    }
    s.cached.store(true, Ordering::Release);
    // Don't push to partial — we hand it directly to the caller.
    new_idx
}

/// **`uncacheSpan(idx)`** — return a previously-cached span to the
/// central lists. Mirrors Go's `runtime.(*mcentral).uncacheSpan`.
///
/// Routes to `partial[class]` if the span has free slots, or
/// `full[class]` if every slot is allocated. If the span is fully
/// empty, it is released back to mheap (same path as `free`'s
/// last-slot release).
pub unsafe fn uncacheSpan(idx: u16) {
    if idx == NIL_SPAN {
        return;
    }
    let mut g = MCENTRAL.lock();
    // Release any unsold reserved bits from `alloc_cache` back to
    // `alloc_bits` + `alloc_count`. Without this, slots reserved
    // during `refill_alloc_cache` but never sold to a user would
    // remain marked as allocated until the span is fully recycled.
    g.spans[idx as usize].release_unsold();
    g.spans[idx as usize].cached.store(false, Ordering::Release);
    let s = &g.spans[idx as usize];
    let is_empty = s.is_empty();
    let is_full = s.is_full();
    let base = s.base;
    let npages = s.npages as usize;
    let arena_base = g.arena_base;
    if is_empty {
        // Empty: page → span entries cleared, slot returned, pages
        // released to mheap. Mirrors the last-slot path in `free`.
        let first_page = (base - arena_base) / PAGE_SIZE;
        for pp in first_page..(first_page + npages) {
            if pp < MAX_TRACKED_PAGES {
                g.page_to_span[pp] = NIL_SPAN;
            }
        }
        g.release_span_idx(idx);
        drop(g);
        crate::runtime::mheap_free_pages(base, npages);
        return;
    }
    if is_full {
        g.full_push(idx);
    } else {
        g.partial_push(idx);
    }
}

/// **`alloc_slot_in(idx)`** — allocate a single slot from a specific
/// cached span without consulting partial/full lists. Used by the
/// per-P mcache hot path.
///
/// **Lock-free** (post task #106). Calls `next_free_owner` on the
/// span, which consumes from `alloc_cache` (per-P private) and
/// refills via `fetch_or` from `alloc_bits` (atomic). Never touches
/// `MCENTRAL.lock()`.
///
/// Returns the slot's address, or null when the span is full (the
/// caller should refill via `uncacheSpan` + `cacheSpan`).
///
/// Safety: caller must own the cached span — i.e. this `idx` is in
/// the calling P's `mcache[class]` slot and the calling M is bound
/// to that P.
pub unsafe fn alloc_slot_in(idx: u16) -> *mut u8 {
    if idx == NIL_SPAN {
        return core::ptr::null_mut();
    }
    let s = span_by_idx(idx);
    match s.next_free_owner() {
        Some(slot) => s.slot_addr(slot) as *mut u8,
        None => core::ptr::null_mut(),
    }
}

/// **`is_full(idx)`** — true if the span at `idx` has no free slots.
/// Used by the per-P mcache to decide when to refill. Lock-free —
/// reads `alloc_count` atomically.
pub fn is_full(idx: u16) -> bool {
    if idx == NIL_SPAN {
        return true;
    }
    unsafe { span_by_idx(idx).is_full() }
}

/// Stress-test only: number of currently in-use slots across all
/// classes. Used by the smoke example.
///
/// Reads slots `1..=spans_bump` since slot 0 is the reserved sentinel.
pub fn live_slots() -> usize {
    let g = MCENTRAL.lock();
    let mut n = 0;
    for s in &g.spans[1..=(g.spans_bump as usize)] {
        n += s.alloc_count.load(Ordering::Acquire) as usize;
    }
    n
}

// `MCentral` lives in `static MCENTRAL` via `SpinLock`. The pool has
// internal mutability through that lock. Mark it `Send` because the
// whole struct moves through the lock.
unsafe impl Send for MCentral {}
