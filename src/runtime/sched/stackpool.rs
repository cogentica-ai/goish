// runtime::sched::stackpool — chunked sub-page goroutine stacks.
//
// **Slim port of Go's `runtime/stack.go` `stackpool` machinery.**
// Verified against `runtime/stack.go:194-273` (`stackpoolalloc` /
// `stackpoolfree`). Drops Go's per-P `stackcache` (deferred to a
// later refinement) and the GC-coordination guards (no GC in
// goish). Keeps the load-bearing structure: per-order span lists,
// freelist threaded through free slots via 8-byte "next free offset"
// headers (Go's `gclinkptr`).
//
// **Why this exists.** The `Stack::new_sized` path in
// `runtime::sched::stack` uses one `mmap()` per goroutine. Linux
// mmap is page-granular (4 KiB on x86_64), so a 2 KiB stack request
// actually consumes a whole page. For workloads spawning ~1M
// goroutines, that's a 2× memory tax compared to Go's design.
// `stackpool` carves stacks of `2K, 4K, 8K, 16K, 32K` from larger
// 32 KiB spans, so a 2 KiB stack genuinely costs 2 KiB of virtual
// (and proportionally less physical, due to demand paging).
//
// **Concurrency.** One global `SpinLock<StackPool>`. The mcentral
// lock-free refactor (commit 6e211a8) showed that single-spin-lock
// designs are workable for runtime allocators; per-P stackcache
// would lift contention further but isn't needed yet.
//
// **Layout.**
//
//   StackPool                      static SpinLock<StackPool>
//     spans: [StackSpan; N]        (BSS-resident, NIL_SPAN = 0 sentinel)
//     spans_bump                   bump-allocator for span slots
//     spans_free_head              freelist of recyclable span slots
//     partial[order]               head of partial-list per order
//
//   StackSpan
//     base                         mmap'd 32 KiB region's start
//     elemsize                     stack size for this span (2K..32K)
//     nelems                       slots per span (32K / elemsize)
//     free_count                   slots currently free
//     free_head_off                offset of first free slot, NIL_OFF if full
//     order                        size class (0..4)
//     next, prev                   per-order list links
//
// Each free slot's first 8 bytes hold a `u64` "next-free offset"
// within the span (or `NIL_OFF` if this is the last free slot).
// Live slots have arbitrary contents — those bytes are part of the
// goroutine's stack.

#![allow(dead_code)]

use core::sync::atomic::AtomicBool;

use crate::runtime::spin::SpinLock;
use crate::syscall;

// ─── tunables ────────────────────────────────────────────────────────

/// Smallest stack size class. Mirrors Go's `fixedStack` after rounding
/// (`runtime/stack.go:87`). Goish uses the bare value 2048 since we
/// have no `stackSystem` adjustment.
pub const FIXED_STACK: usize = 2 * 1024;

/// Number of sub-page stack-size classes. Orders 0..=4 →
/// 2K, 4K, 8K, 16K, 32K. Anything larger goes through direct
/// page-aligned mmap (`Stack::new_sized` large path).
pub const NUM_STACK_ORDERS: usize = 5;

/// Span size — the unit at which we mmap for the chunked pool.
/// Mirrors Go's `_StackCacheSize` (32 KiB). One span of order 0
/// holds 16 × 2 KiB slots.
pub const STACK_CACHE_SIZE: usize = 32 * 1024;

/// Maximum number of live stack spans the pool can track. Each span
/// of order 0 (2 KiB stacks) holds 16 slots, so 131072 spans cover
/// 2 M order-0 goroutines — comfortable headroom for the 1M-G goal.
/// BSS budget: ~4 MiB at `size_of::<StackSpan>() = 32`.
pub const MAX_STACK_SPANS: usize = 128 * 1024;

/// Sentinel meaning "no span" (lists, freelist heads).
pub const NIL_SPAN: u32 = 0;

/// Sentinel meaning "no free slot" inside a span's intra-span freelist.
pub const NIL_OFF: u32 = u32::MAX;

// ─── span ────────────────────────────────────────────────────────────

/// One stack-span (Go's `mspan` for stacks).
///
/// The intra-span freelist is threaded through the slots themselves:
/// each free slot's first 8 bytes are a `u64` containing the offset
/// (within the span) of the next free slot, or `NIL_OFF` if this is
/// the last. Allocation pops the head of this list; free pushes back.
#[derive(Copy, Clone)]
#[repr(C)]
pub struct StackSpan {
    /// Base address of the mmap'd 32 KiB region (page-aligned).
    pub base: usize,
    /// Stack size for this span (`FIXED_STACK << order`).
    pub elemsize: u32,
    /// Slots in this span (`STACK_CACHE_SIZE / elemsize`).
    pub nelems: u16,
    /// Slots currently free. Goes to 0 (full) or `nelems` (empty,
    /// span eligible for return to OS).
    pub free_count: u16,
    /// Offset (within the span) of the first free slot's header.
    /// `NIL_OFF` when the span is fully allocated.
    pub free_head_off: u32,
    /// Order this span serves (0..=4).
    pub order: u8,
    /// Per-order partial-list links.
    pub next: u32,
    pub prev: u32,
}

impl StackSpan {
    pub const EMPTY: StackSpan = StackSpan {
        base: 0,
        elemsize: 0,
        nelems: 0,
        free_count: 0,
        free_head_off: NIL_OFF,
        order: 0,
        next: NIL_SPAN,
        prev: NIL_SPAN,
    };
}

// ─── pool ────────────────────────────────────────────────────────────

pub struct StackPool {
    /// All spans known to the pool. Span 0 is reserved sentinel.
    pub spans: [StackSpan; MAX_STACK_SPANS],
    /// Bump allocator for fresh span slots.
    pub spans_bump: u32,
    /// Freelist of recyclable span slots (released back to OS).
    pub spans_free_head: u32,
    /// Per-order partial-list head — spans with at least one free slot.
    pub partial: [u32; NUM_STACK_ORDERS],
}

impl StackPool {
    pub const fn new() -> Self {
        StackPool {
            spans: [StackSpan::EMPTY; MAX_STACK_SPANS],
            spans_bump: 0,
            spans_free_head: NIL_SPAN,
            partial: [NIL_SPAN; NUM_STACK_ORDERS],
        }
    }

    /// Acquire a fresh span-table slot.
    fn alloc_span_idx(&mut self) -> u32 {
        if self.spans_free_head != NIL_SPAN {
            let idx = self.spans_free_head;
            self.spans_free_head = self.spans[idx as usize].next;
            self.spans[idx as usize] = StackSpan::EMPTY;
            return idx;
        }
        let idx = self.spans_bump + 1;
        if (idx as usize) >= MAX_STACK_SPANS {
            const MSG: &[u8] = b"goish: stackpool: span table exhausted\n";
            syscall::Write(syscall::STDERR, MSG.as_ptr(), MSG.len());
            syscall::Exit(2);
        }
        self.spans_bump += 1;
        idx
    }

    fn release_span_idx(&mut self, idx: u32) {
        self.spans[idx as usize] = StackSpan::EMPTY;
        self.spans[idx as usize].next = self.spans_free_head;
        self.spans_free_head = idx;
    }

    fn partial_push(&mut self, idx: u32) {
        let order = self.spans[idx as usize].order as usize;
        let head = self.partial[order];
        self.spans[idx as usize].next = head;
        self.spans[idx as usize].prev = NIL_SPAN;
        if head != NIL_SPAN {
            self.spans[head as usize].prev = idx;
        }
        self.partial[order] = idx;
    }

    fn partial_remove(&mut self, idx: u32) {
        let next = self.spans[idx as usize].next;
        let prev = self.spans[idx as usize].prev;
        let order = self.spans[idx as usize].order as usize;
        if prev != NIL_SPAN {
            self.spans[prev as usize].next = next;
        } else if self.partial[order] == idx {
            self.partial[order] = next;
        }
        if next != NIL_SPAN {
            self.spans[next as usize].prev = prev;
        }
        self.spans[idx as usize].next = NIL_SPAN;
        self.spans[idx as usize].prev = NIL_SPAN;
    }
}

// ─── public alloc / free ─────────────────────────────────────────────

static STACK_POOL: SpinLock<StackPool> = SpinLock::new(StackPool::new());

/// Order for `n` bytes, or `None` if `n` exceeds the largest order.
///
/// Mirrors the loop at `runtime/stack.go:373-378`:
///   order = log2(n / fixedStack), clamped to [0, NUM_STACK_ORDERS).
#[inline]
pub fn order_for(n: usize) -> Option<u8> {
    if n == 0 || n > FIXED_STACK << (NUM_STACK_ORDERS - 1) {
        return None;
    }
    let mut order: u8 = 0;
    let mut size = FIXED_STACK;
    while size < n {
        order += 1;
        size <<= 1;
    }
    Some(order)
}

/// Stack-size for `order` (0..=4).
#[inline]
pub fn size_for(order: u8) -> usize {
    FIXED_STACK << order
}

/// **Allocate a stack** for the given order. Returns `(base, span_idx,
/// size)`. The returned region is uninitialized (the goroutine writes
/// its initial frame at `base + size - 16`).
///
/// On per-pool OOM (span table exhausted, mmap fails), this is fatal —
/// matches Go's `throw("out of memory")` at `runtime/stack.go:202`.
pub unsafe fn alloc(order: u8) -> (*mut u8, u32, usize) {
    debug_assert!((order as usize) < NUM_STACK_ORDERS);
    let mut g = STACK_POOL.lock();

    // Get or create a partial span for this order.
    let mut idx = g.partial[order as usize];
    if idx == NIL_SPAN {
        // Drop the lock during the fresh mmap so the call doesn't
        // serialize all stack allocs through the kernel.
        drop(g);
        let base = mmap_span();
        let mut g2 = STACK_POOL.lock();
        idx = g2.alloc_span_idx();
        init_span(&mut g2.spans[idx as usize], idx, order, base);
        g2.partial_push(idx);
        g = g2;
    }

    // Pop the head of the intra-span freelist.
    let span = &mut g.spans[idx as usize];
    let head_off = span.free_head_off;
    debug_assert!(head_off != NIL_OFF, "partial span has no free slot");
    let slot_addr = (span.base + head_off as usize) as *mut u8;
    let next_off = unsafe { (slot_addr as *mut u64).read() };
    span.free_head_off = next_off as u32;
    span.free_count -= 1;
    let elemsize = span.elemsize as usize;

    // If span is now full, remove it from the partial list. It will
    // come back via `free()` when the first slot is returned.
    if span.free_count == 0 {
        g.partial_remove(idx);
    }

    (slot_addr, idx, elemsize)
}

/// **Free a stack** back to its span. Caller passes `span_idx` (stored
/// on the goroutine's `Stack` struct). The slot's first 8 bytes are
/// repurposed as the freelist header — the goroutine's stack contents
/// are gone by this point (G is `Dead`), so this is sound.
pub unsafe fn free(span_idx: u32, slot: *mut u8) {
    if span_idx == NIL_SPAN {
        return;
    }
    let mut g = STACK_POOL.lock();
    let span = &mut g.spans[span_idx as usize];
    let off = ((slot as usize) - span.base) as u32;
    debug_assert!(
        (off as usize) < STACK_CACHE_SIZE && off.is_multiple_of(span.elemsize),
        "stackpool::free: slot offset {} invalid for elemsize {}",
        off,
        span.elemsize,
    );
    let was_full = span.free_count == 0;
    // Push slot onto the head of the freelist.
    let prev_head = span.free_head_off;
    unsafe {
        (slot as *mut u64).write(prev_head as u64);
    }
    span.free_head_off = off;
    span.free_count += 1;

    // Re-add to partial list if this slot brought the span back from full.
    if was_full {
        g.partial_push(span_idx);
    }

    // If the span is fully empty, drop it back to the OS — keeps RSS
    // tight under bursty workloads. Mirrors the `s.allocCount == 0`
    // path at `runtime/stack.go:252` (minus GC coordination).
    if g.spans[span_idx as usize].free_count == g.spans[span_idx as usize].nelems {
        let base = g.spans[span_idx as usize].base;
        g.partial_remove(span_idx);
        g.release_span_idx(span_idx);
        drop(g);
        unsafe {
            munmap_span(base);
        }
    }
}

/// mmap a fresh 32 KiB span. Returns the page-aligned base, or aborts
/// the process on failure.
unsafe fn mmap_span() -> usize {
    let p = syscall::Mmap(
        core::ptr::null_mut(),
        STACK_CACHE_SIZE,
        syscall::PROT_READ | syscall::PROT_WRITE,
        syscall::MAP_PRIVATE | syscall::MAP_ANONYMOUS,
        -1,
        0,
    );
    if p == syscall::MAP_FAILED {
        const MSG: &[u8] = b"goish: stackpool: span mmap failed\n";
        syscall::Write(syscall::STDERR, MSG.as_ptr(), MSG.len());
        syscall::Exit(2);
    }
    p as usize
}

unsafe fn munmap_span(base: usize) {
    syscall::Munmap(base as *mut u8, STACK_CACHE_SIZE);
}

/// Initialize a fresh span at `idx`: subdivide it into slots of
/// `size_for(order)` bytes and thread the intra-span freelist through
/// every slot.
fn init_span(s: &mut StackSpan, _idx: u32, order: u8, base: usize) {
    let elemsize = size_for(order);
    let nelems = (STACK_CACHE_SIZE / elemsize) as u16;
    s.base = base;
    s.elemsize = elemsize as u32;
    s.nelems = nelems;
    s.free_count = nelems;
    s.order = order;
    s.next = NIL_SPAN;
    s.prev = NIL_SPAN;

    // Build the freelist: thread slots from low to high; each slot's
    // first 8 bytes hold the offset of the next free slot. Last slot
    // gets `NIL_OFF`.
    let mut off: usize = 0;
    while off + elemsize < STACK_CACHE_SIZE {
        let next_off = (off + elemsize) as u64;
        unsafe {
            ((base + off) as *mut u64).write(next_off);
        }
        off += elemsize;
    }
    // Last slot's "next" is NIL_OFF.
    unsafe {
        ((base + off) as *mut u64).write(NIL_OFF as u64);
    }
    s.free_head_off = 0;
}

// ─── diagnostics ─────────────────────────────────────────────────────

/// Suppress dead-code warning on items used only by tests.
#[allow(dead_code)]
pub fn _force_link() -> &'static AtomicBool {
    static A: AtomicBool = AtomicBool::new(false);
    &A
}

/// Total number of allocated (in-use) stacks across all orders.
/// Diagnostic only — racy under concurrent alloc/free.
pub fn live_stacks() -> usize {
    let g = STACK_POOL.lock();
    let mut n = 0usize;
    let bump = g.spans_bump as usize;
    for s in &g.spans[1..=bump] {
        if s.elemsize != 0 {
            n += (s.nelems - s.free_count) as usize;
        }
    }
    n
}
