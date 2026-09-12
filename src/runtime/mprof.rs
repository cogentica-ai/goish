// runtime/mprof — sampled heap allocation profiling.
//
// go: none — goish-only: models Go's `runtime/mprof.go` (the memRecord
// / bucket half). Prose rather than an anchor because mprof.go also
// holds the block, mutex and goroutine profilers plus their whole
// bucket taxonomy, and an anchor would make this file owe every one of
// them.
//
// WHAT THIS IS FOR. Issue #9 wants `Lookup("heap")` and
// `Lookup("allocs")` to return real profiles. Measured against Go, both
// carry the SAME four value types — alloc_objects, alloc_space,
// inuse_objects, inuse_space — and differ only in their default view.
// So "just count allocations" is not enough: inuse means a profile has
// to know about frees too.
//
// THE SHAPE. Go keys a hash table by call stack. Each bucket holds
// (allocs, frees, alloc_bytes, free_bytes), and inuse is the
// difference. A sampled object carries a `specialprofile` on its span
// so the free path can find its bucket again. goish has no span
// specials, so it keeps a small side table of sampled pointers instead
// — sampled objects are rare (one per `MemProfileRate` bytes, 512 KiB
// by default), so the table stays small and hot.
//
// NOTHING HERE ALLOCATES. It is called from inside the global
// allocator, so a Vec would recurse into the very path it is
// instrumenting. Every table is a fixed-size `static mut`, guarded by
// a SpinLock, and the stack walk writes into a `[u64; 32]` on the
// caller's frame. That is also why the tables have hard capacities and
// a drop counter rather than growing: overflowing is a reported number,
// not a reentrant allocation.

#![allow(non_snake_case)]

use core::sync::atomic::{AtomicI64, AtomicU64, AtomicUsize, Ordering};

use crate::runtime::spin::SpinLock;

/// Deepest stack recorded per bucket. Go's `maxStack` is 32 and its
/// frame walker is the same width.
pub(crate) const MAX_STACK: usize = 32;

/// Buckets in the stack table. A bucket is claimed per DISTINCT stack,
/// so this is a ceiling on allocation sites, not on allocations.
const NBUCKETS: usize = 2048;

/// Slots in the live-sampled-pointer table. At the default rate one
/// pointer is tracked per 512 KiB allocated and live, so this covers a
/// multi-gigabyte live heap.
const NADDR_BITS: u32 = 13;
const NADDRS: usize = 1 << NADDR_BITS;

// go: none — goish-only: Go's `MemProfileRate` (runtime/mprof.go line
// 750) is a plain `var` a program assigns to; goish has no mutable
// package-level vars, so it is an atomic with accessors.
/// Go: "MemProfileRate controls the fraction of memory allocations
/// that are recorded and reported in the memory profile. The profiler
/// aims to sample an average of one allocation per MemProfileRate
/// bytes allocated." Go's default is 512 * 1024 and so is this one:
/// heap profiling is on out of the box, as in Go.
static MEM_PROFILE_RATE: AtomicI64 = AtomicI64::new(512 * 1024);

/// One call stack's allocation history. Go's `memRecord` splits the
/// counters across GC cycles so a profile reads a consistent snapshot;
/// goish has no such cycle boundary yet, so the counters are live.
/// That is visible: an object allocated and freed between two reads can
/// make inuse move under a caller. Recorded here rather than left as a
/// surprise.
#[derive(Clone, Copy)]
struct Bucket {
    /// Stack hash. 0 means the slot is free — a real hash is forced
    /// nonzero, so there is no ambiguity.
    hash: u64,
    depth: u32,
    pcs: [u64; MAX_STACK],
    allocs: u64,
    frees: u64,
    alloc_bytes: u64,
    free_bytes: u64,
}

impl Bucket {
    // go: none — goish-only: Go zeroes a bucket by allocating it from
    // persistentalloc; a `static mut` array needs a const initializer.
    const fn empty() -> Self {
        return Bucket {
            hash: 0,
            depth: 0,
            pcs: [0; MAX_STACK],
            allocs: 0,
            frees: 0,
            alloc_bytes: 0,
            free_bytes: 0,
        };
    }
}

/// A live sampled object: which bucket to credit when it is freed.
#[derive(Clone, Copy)]
struct Addr {
    /// `EMPTY` (0) means never used; `TOMBSTONE` means used and freed.
    /// The distinction is load-bearing — see `record_free`.
    ptr: usize,
    bucket: u32,
    size: u64,
}

/// A slot that has never held an entry. A lookup may stop here.
const EMPTY: usize = 0;
/// A slot whose entry was removed. A lookup must KEEP GOING past it.
///
/// Without this, deleting from an open-addressed table cuts the probe
/// chain of every later entry that collided into the same run. It is
/// not a corner case: measured, 300 sampled 4 KiB objects produced
/// only 11 attributed frees, because each deletion orphaned the rest
/// of its cluster.
const TOMBSTONE: usize = usize::MAX;

// go: none — goish-only: Go hashes the address through its span
// lookup; goish needs its own.
/// Fibonacci hash of a pointer.
///
/// `ptr >> 4` was the first attempt and it is badly wrong here.
/// Same-sized allocations come back at a fixed stride — 4 KiB objects
/// step by 4096, so `(ptr >> 4) & 4095` takes only sixteen distinct
/// values and three hundred objects pile into sixteen slots. Measured
/// before fixing it: probe chains long enough to hit the give-up limit
/// and drop records. Multiplying by the golden-ratio constant and
/// taking the HIGH bits mixes the stride away.
#[inline]
fn addr_slot(ptr: usize) -> usize {
    let h = crate::uint64(ptr).wrapping_mul(0x9E37_79B9_7F4A_7C15);
    return ((h >> (64 - NADDR_BITS)) as usize) & (NADDRS - 1);
}

struct Tables {
    buckets: [Bucket; NBUCKETS],
    addrs: [Addr; NADDRS],
}

static TABLES: SpinLock<Tables> = SpinLock::new(Tables {
    buckets: [Bucket::empty(); NBUCKETS],
    addrs: [Addr {
        ptr: EMPTY,
        bucket: 0,
        size: 0,
    }; NADDRS],
});

/// How many live sampled pointers the address table holds. The free
/// path reads this FIRST and returns without touching the lock when it
/// is zero, which is the common case for a program that never
/// allocates enough to be sampled.
static LIVE_SAMPLED: AtomicUsize = AtomicUsize::new(0);

/// Sampled allocations that could not be recorded because a table was
/// full. A nonzero value means the profile UNDERCOUNTS, so it is
/// reported rather than hidden.
static DROPPED: AtomicU64 = AtomicU64::new(0);

// go: none — goish-only: see `MEM_PROFILE_RATE`.
/// Read Go's `MemProfileRate`.
pub fn MemProfileRate() -> crate::types::int {
    return MEM_PROFILE_RATE.load(Ordering::Relaxed);
}

// go: none — goish-only: see `MEM_PROFILE_RATE`.
/// Set Go's `MemProfileRate`. Go: "The tools that process the memory
/// profiles assume that the profile rate is constant across the lifetime
/// of the program and equal to the current value. Programs that change
/// the memory profiling rate should do so just once, as early as
/// possible in the execution of the program (for example, at the
/// beginning of main)."
pub fn SetMemProfileRate(rate: crate::types::int) {
    MEM_PROFILE_RATE.store(rate, Ordering::Relaxed);
}

// go: none — goish-only: Go's `fastlog2` (runtime/mprof.go line 1030),
// which exists because the sampler must not call into `math`.
/// Approximate log2 for the exponential sampling draw. Go's own
/// comment: "Compute the base-2 logarithm of x, with the mantissa
/// treated as a linear interpolation between exponents."
fn fastlog2(x: f64) -> f64 {
    let bits = x.to_bits();
    let exp = crate::int64((bits >> 52) & 0x7ff) - 1023;
    // Mantissa in [1, 2), used as a straight-line interpolation between
    // the two exponents. Go accepts the error; the draw is a sampling
    // interval, not a measurement.
    let mant = f64::from_bits((bits & 0x000f_ffff_ffff_ffff) | 0x3ff0_0000_0000_0000);
    return (exp as f64) + (mant - 1.0);
}

// go: none — goish-only: Go's `nextSample`/`fastexprand`
// (runtime/mprof.go line 1000 and runtime/malloc.go line 1440).
/// Bytes to allocate before the next sample, drawn from an exponential
/// distribution with the given mean.
///
/// A FIXED interval would be simpler and wrong: allocation sizes in a
/// real program are periodic, so a fixed stride aliases with them and
/// systematically samples the same site. Go randomizes for that reason
/// and so does this.
fn next_sample(rate: i64) -> i64 {
    if rate <= 1 {
        // Rate 1 profiles every allocation, which is what a test wants.
        return 0;
    }
    const RANDOM_BIT_COUNT: i32 = 26;
    let q = crate::runtime::rand::cheaprandn(1u32 << RANDOM_BIT_COUNT) + 1;
    let mut qlog = fastlog2(q as f64) - (RANDOM_BIT_COUNT as f64);
    if qlog > 0.0 {
        qlog = 0.0;
    }
    const MINUS_LOG2: f64 = -0.693_147_180_559_945_3;
    return crate::int64(qlog * (MINUS_LOG2 * crate::float64(rate))) + 1;
}

// go: none — goish-only: Go hashes the stack inside `stkbucket`
// (runtime/mprof.go line 260).
/// Hash a stack. Forced nonzero so 0 can mean "empty slot".
fn stack_hash(pcs: &[u64]) -> u64 {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for pc in pcs.iter() {
        h ^= *pc;
        h = h.wrapping_mul(0x1000_0000_01b3);
    }
    if h == 0 {
        return 1;
    }
    return h;
}

// go: none — goish-only: Go's `mProf_Malloc` (runtime/mprof.go line
// 460) records from `profilealloc`, which the mcache fast path calls
// when its `nextSample` counter runs out.
/// Record a sampled allocation. Called from the allocator with
/// preemption already masked.
///
/// The allocator's own frames are NOT skipped here. A skip count is
/// the obvious way to drop them and it is fragile: `alloc_masked` and
/// `malloc_hook` are `#[inline]`, so the number of real frames between
/// the walk and the caller depends on the optimizer. They are stripped
/// at READ time instead, by name, where symbolization is happening
/// anyway. They also do not split buckets — every allocation carries
/// the same prefix.
fn record_alloc(ptr: *mut u8, size: usize) {
    let mut frames = [0u64; MAX_STACK];
    let n = crate::runtime::collect_frames_for_profile(&mut frames);
    if n == 0 {
        // No G bound, so no safe stack bound to walk. Counting this
        // as a sample with an empty stack would put phantom bytes at
        // the root of the profile.
        DROPPED.fetch_add(1, Ordering::Relaxed);
        return;
    }
    let h = stack_hash(&frames[..n]);

    let mut t = TABLES.lock();
    // Buckets: open addressing, linear probe.
    let mask = NBUCKETS - 1;
    let mut i = (h as usize) & mask;
    let mut probes = 0usize;
    let idx = loop {
        if t.buckets[i].hash == 0 {
            t.buckets[i].hash = h;
            t.buckets[i].depth = crate::uint32(n);
            let mut k = 0usize;
            while k < n {
                t.buckets[i].pcs[k] = frames[k];
                k += 1;
            }
            break i;
        }
        if t.buckets[i].hash == h {
            break i;
        }
        i = (i + 1) & mask;
        probes += 1;
        if probes >= NBUCKETS {
            drop(t);
            DROPPED.fetch_add(1, Ordering::Relaxed);
            return;
        }
    };
    t.buckets[idx].allocs += 1;
    t.buckets[idx].alloc_bytes += crate::uint64(size);

    // Address table, so the free can be attributed back here. Either
    // kind of unoccupied slot will do for an insert.
    let amask = NADDRS - 1;
    let mut a = addr_slot(ptr as usize);
    let mut aprobes = 0usize;
    loop {
        if t.addrs[a].ptr == EMPTY || t.addrs[a].ptr == TOMBSTONE {
            t.addrs[a] = Addr {
                ptr: ptr as usize,
                bucket: crate::uint32(idx),
                size: crate::uint64(size),
            };
            LIVE_SAMPLED.fetch_add(1, Ordering::Relaxed);
            return;
        }
        a = (a + 1) & amask;
        aprobes += 1;
        if aprobes >= NADDRS {
            // The allocation stays counted in allocs/alloc_bytes; only
            // its free will be missed, which inflates inuse. Reported
            // through `dropped`.
            DROPPED.fetch_add(1, Ordering::Relaxed);
            return;
        }
    }
}

// go: none — goish-only: Go's `mProf_Free` (runtime/mprof.go line 490),
// reached from the sweeper when a span with a profile special is freed.
/// Credit a free back to the bucket that allocated it, if the pointer
/// was one of the sampled ones.
fn record_free(ptr: *mut u8) {
    let mut t = TABLES.lock();
    let amask = NADDRS - 1;
    let mut a = addr_slot(ptr as usize);
    let mut probes = 0usize;
    let target = ptr as usize;
    loop {
        let e = t.addrs[a];
        if e.ptr == EMPTY {
            // A never-used slot ends the chain, so the pointer was
            // never sampled. This is the overwhelmingly common case.
            // A TOMBSTONE does NOT end it — see the constant.
            return;
        }
        if e.ptr == target {
            t.addrs[a].ptr = TOMBSTONE;
            let b = e.bucket as usize;
            t.buckets[b].frees += 1;
            t.buckets[b].free_bytes += e.size;
            LIVE_SAMPLED.fetch_sub(1, Ordering::Relaxed);
            return;
        }
        a = (a + 1) & amask;
        probes += 1;
        if probes >= NADDRS {
            return;
        }
    }
}

// go: none — goish-only: the allocator's hook. Go's equivalent is the
// `nextSample` countdown inlined into `mallocgc`.
/// Called by `heap.rs` after every successful allocation, with
/// preemption already masked by the allocator's own `acquirem`.
///
/// The counter is per-M and lives in the TLS block, so the hot path is
/// a segment-relative load and store — no atomic, no contention. A
/// single global counter would put a `lock xadd` on every allocation in
/// the program.
#[inline]
pub(crate) fn malloc_hook(ptr: *mut u8, size: usize) {
    let rate = MEM_PROFILE_RATE.load(Ordering::Relaxed);
    if rate <= 0 || ptr.is_null() {
        return;
    }
    if !crate::runtime::sched::is_tls_ready() {
        // Pre-scheduler allocations have no M to hold the counter and
        // no G to bound a stack walk. Go has the same hole and fills
        // it later; goish leaves it uncounted rather than guessing.
        return;
    }
    let st = crate::runtime::sched::current_m_storage();
    let left = st.mprof_next.load(Ordering::Relaxed) - crate::int64(size);
    if left > 0 {
        st.mprof_next.store(left, Ordering::Relaxed);
        return;
    }
    // Suppress sampling of anything the recorder itself allocates, by
    // parking the countdown out of reach for the duration. A per-M
    // boolean would do the same job with an extra TLS field; this
    // needs none, and it cannot leave a flag set if the recorder
    // returns early. It matters because the SpinLock below is NOT
    // reentrant: a nested sample on this M would deadlock, not merely
    // double-count.
    st.mprof_next.store(i64::MAX, Ordering::Relaxed);
    record_alloc(ptr, size);
    st.mprof_next.store(next_sample(rate), Ordering::Relaxed);
}

// go: none — goish-only: see `malloc_hook`.
/// Called by `heap.rs` before every deallocation.
///
/// The `LIVE_SAMPLED` check is what keeps this off the hot path: with
/// no sampled object alive there is nothing to find, so the free path
/// costs one relaxed load and a branch.
#[inline]
pub(crate) fn free_hook(ptr: *mut u8) {
    if ptr.is_null() || LIVE_SAMPLED.load(Ordering::Relaxed) == 0 {
        return;
    }
    record_free(ptr);
}

// go: none — goish-only: the read side, for `runtime/pprof`.
/// One bucket, copied out of the table.
#[derive(Clone, Copy)]
pub struct BucketSnapshot {
    pub depth: usize,
    pub pcs: [u64; MAX_STACK],
    pub allocs: u64,
    pub frees: u64,
    pub alloc_bytes: u64,
    pub free_bytes: u64,
}

// go: none — goish-only: see `BucketSnapshot`.
/// How many slots `__bucket_at` accepts. Most are empty.
pub fn __bucket_slots() -> usize {
    return NBUCKETS;
}

// go: none — goish-only: see `BucketSnapshot`.
/// Copy slot `i` out of the table, or `None` if it is empty.
///
/// This deliberately does NOT take a callback. The first version did,
/// and its own doc comment had to warn that the callback ran under the
/// table lock and must not allocate — which is a way of saying the API
/// was wrong. The very first caller wrote `pcs.to_vec()`, the allocator
/// re-entered the sampler, the sampler asked for the lock the reader
/// was holding, and the process hung. A doc comment does not make a
/// deadlock unreachable; a signature can. The lock is taken and
/// released inside this call, so a caller may allocate freely between
/// calls.
///
/// DEVIATION: Go stops the world to read a memory profile, so its
/// snapshot is consistent. goish's iteration races with live
/// allocation, so a profile read during heavy allocation can show a
/// bucket's `allocs` from one instant and another's from the next.
/// Both are real counts; they are just not simultaneous.
pub fn __bucket_at(i: usize) -> Option<BucketSnapshot> {
    if i >= NBUCKETS {
        return None;
    }
    let t = TABLES.lock();
    let b = t.buckets[i];
    drop(t);
    if b.hash == 0 || b.allocs == 0 {
        return None;
    }
    return Some(BucketSnapshot {
        depth: crate::int(b.depth) as usize,
        pcs: b.pcs,
        allocs: b.allocs,
        frees: b.frees,
        alloc_bytes: b.alloc_bytes,
        free_bytes: b.free_bytes,
    });
}

// go: none — goish-only: see `DROPPED`.
/// Sampled allocations lost to a full table. Nonzero means the profile
/// undercounts.
pub fn __dropped() -> u64 {
    return DROPPED.load(Ordering::Relaxed);
}

// go: none — goish-only: test hook, so a smoke can profile a known
// workload without waiting for 512 KiB of allocation.
#[doc(hidden)]
pub fn __reset() {
    let mut t = TABLES.lock();
    let mut i = 0usize;
    while i < NBUCKETS {
        t.buckets[i] = Bucket::empty();
        i += 1;
    }
    let mut a = 0usize;
    while a < NADDRS {
        t.addrs[a].ptr = EMPTY;
        a += 1;
    }
    drop(t);
    LIVE_SAMPLED.store(0, Ordering::Relaxed);
    DROPPED.store(0, Ordering::Relaxed);
}

// go: none — goish-only: test hook. Setting the rate does not by itself
// re-arm the current M's countdown, which was drawn from the OLD rate;
// a test that sets rate=1 and allocates twice would otherwise miss its
// first allocations.
#[doc(hidden)]
pub fn __rearm() {
    if !crate::runtime::sched::is_tls_ready() {
        return;
    }
    let st = crate::runtime::sched::current_m_storage();
    st.mprof_next.store(0, Ordering::Relaxed);
}
