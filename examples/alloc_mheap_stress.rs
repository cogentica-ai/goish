// Stress test: M16 (2b'-γ) — integrated allocator routing under
// churn. Exercises the LARGE_THRESHOLD boundary, cross-tier realloc,
// and high-volume mixed alloc/free patterns through the global
// allocator (Vec/Box) — the path real user code takes.
//
// Coverage rationale:
//
//   - **Threshold edges.** Allocations exactly at 32 KiB ± 1 byte
//     test that route_to_mheap()'s `> LARGE_THRESHOLD` boundary is
//     exact and consistent between alloc and dealloc. A bug here
//     would cause a small-tier-allocated block to be freed via mheap
//     (or vice versa), corrupting both tiers.
//
//   - **Cross-tier realloc.** Vec grown one byte at a time crosses
//     the threshold deterministically; if cross-tier realloc loses
//     even one byte of content, the marker check fires.
//
//   - **High-volume churn.** Thousands of mixed alloc/free pairs
//     stress mheap's internal reuse, dlmalloc's internal reuse, and
//     their independence from each other.

#![no_std]
#![no_main]

extern crate alloc;

use alloc::boxed::Box;
use alloc::vec;
use alloc::vec::Vec;
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

// xorshift64* — same RNG as the isolated stress for reproducibility.
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

const THRESHOLD: usize = 32 * 1024; // matches runtime::heap::LARGE_THRESHOLD

#[goish::main]
fn main() {
    test_threshold_edges();
    test_cross_tier_grow();
    test_cross_tier_shrink();
    test_box_at_boundary();
    test_high_volume_churn();
    test_many_sizes_concurrent();
    test_arena_reuse_epochs();

    const OK: &[u8] = b"alloc_mheap_stress: ok\n";
    syscall::Write(syscall::STDOUT, OK.as_ptr(), OK.len());
}

// ─── Test 1: exact threshold boundaries ──────────────────────────────
//
// Alloc at THRESHOLD (small path), THRESHOLD+1 (large path),
// THRESHOLD-1 (small path). Each must round-trip its content.

fn test_threshold_edges() {
    for &size in &[THRESHOLD - 1, THRESHOLD, THRESHOLD + 1, 2 * THRESHOLD] {
        let mut v: Vec<u8> = Vec::with_capacity(size);
        for i in 0..size {
            v.push(((i ^ size) & 0xFF) as u8);
        }
        for i in 0..size {
            check(
                v[i] == ((i ^ size) & 0xFF) as u8,
                b"threshold-edges: content corrupted\n",
            );
        }
        // v drops here → free routes via the same tier as alloc.
    }
}

// ─── Test 2: Vec growing across the threshold ────────────────────────
//
// Push one byte at a time from 0 up to 64 KiB. Vec doubles its
// capacity periodically, triggering reallocs. Some of those reallocs
// cross the threshold (small→large). The cross-tier path is alloc +
// memcpy + free; if memcpy loses or shifts data, the byte-pattern
// check fires.

fn test_cross_tier_grow() {
    let mut v: Vec<u8> = Vec::new();
    let n = 64 * 1024usize;
    for i in 0..n {
        v.push((i & 0xFF) as u8);
    }
    for i in 0..n {
        check(v[i] == (i & 0xFF) as u8, b"cross-tier-grow: content lost\n");
    }
}

// ─── Test 3: Vec shrinking across the threshold ──────────────────────
//
// Inverse of Test 2: pre-allocate large, then `shrink_to_fit` to a
// small size. shrink_to_fit calls realloc(old, new) where old > new;
// if both are above threshold, both stay in mheap; if new drops
// below, that's a large→small cross-tier realloc.

fn test_cross_tier_shrink() {
    // Start large enough to be in mheap.
    let mut v: Vec<u8> = Vec::with_capacity(128 * 1024);
    for i in 0..128 * 1024 {
        v.push((i & 0xFF) as u8);
    }
    // Truncate + shrink to below threshold.
    v.truncate(8 * 1024);
    v.shrink_to_fit();
    // Verify content survived.
    for i in 0..8 * 1024 {
        check(
            v[i] == (i & 0xFF) as u8,
            b"cross-tier-shrink: content lost\n",
        );
    }
}

// ─── Test 4: Box<[u8; N]> at the threshold boundary ──────────────────
//
// Box::new of an exact-threshold-sized array. Drop calls dealloc
// with the original layout — a routing mismatch between alloc and
// dealloc would crash (free wrong tier). The fact that we don't
// crash and content checks pass is the assertion.

fn test_box_at_boundary() {
    {
        struct Just([u8; 32 * 1024]);
        let mut b: Box<Just> = Box::new(Just([0u8; 32 * 1024]));
        for i in 0..32 * 1024 {
            b.0[i] = (i & 0xFF) as u8;
        }
        for i in 0..32 * 1024 {
            check(
                b.0[i] == (i & 0xFF) as u8,
                b"box-boundary: just-threshold lost\n",
            );
        }
    }
    {
        struct OnePast([u8; 32 * 1024 + 1]);
        let mut b: Box<OnePast> = Box::new(OnePast([0u8; 32 * 1024 + 1]));
        for i in 0..32 * 1024 + 1 {
            b.0[i] = ((i * 3) & 0xFF) as u8;
        }
        for i in 0..32 * 1024 + 1 {
            check(
                b.0[i] == ((i * 3) & 0xFF) as u8,
                b"box-boundary: one-past lost\n",
            );
        }
    }
}

// ─── Test 5: high-volume churn through Vec ───────────────────────────
//
// 1000 rounds of: pick a random size in [1, 256 KiB], allocate a
// Vec<u8> filled with a unique marker, hold up to MAX_LIVE
// outstanding, randomly free old ones. Re-verify markers on every
// freed Vec to catch any cross-allocation corruption.

fn test_high_volume_churn() {
    const MAX_LIVE: usize = 50;
    const ROUNDS: u32 = 1000;
    let mut live: Vec<(Vec<u8>, u8)> = Vec::with_capacity(MAX_LIVE);
    let mut rng = Rng::new(0xCAFEFEED_DEAD_BEEFu64);

    for _ in 0..ROUNDS {
        let do_alloc = if live.is_empty() {
            true
        } else if live.len() >= MAX_LIVE {
            false
        } else {
            rng.range(2) == 0
        };

        if do_alloc {
            // Mix: 70% small (well under threshold), 30% large
            // (above threshold), so both tiers see real traffic.
            let size = if rng.range(10) < 7 {
                1 + rng.range(THRESHOLD - 1)
            } else {
                THRESHOLD + 1 + rng.range(256 * 1024 - THRESHOLD)
            };
            let marker = (rng.next() as u8).wrapping_add(1);
            let v: Vec<u8> = vec![marker; size];
            live.push((v, marker));
        } else {
            let idx = rng.range(live.len());
            let (v, marker) = live.swap_remove(idx);
            // Sample a few points; full sweep is O(n) per free
            // which would dominate runtime.
            check(v[0] == marker, b"churn: head corrupted\n");
            check(v[v.len() / 2] == marker, b"churn: middle corrupted\n");
            check(v[v.len() - 1] == marker, b"churn: tail corrupted\n");
            // v drops here → free.
        }
    }

    // Drain remaining live and verify on the way out.
    while let Some((v, marker)) = live.pop() {
        check(v[0] == marker, b"churn-drain: head corrupted\n");
        check(v[v.len() - 1] == marker, b"churn-drain: tail corrupted\n");
    }
}

// ─── Test 6: many concurrent allocations of varied sizes ─────────────
//
// Hold 200 simultaneous allocations spread across the threshold
// (small + large interleaved), do a full marker sweep, then free
// in shuffled order. The full sweep proves no allocation has been
// silently corrupted by any of its neighbours.

fn test_many_sizes_concurrent() {
    let mut rng = Rng::new(0x1234_5678_9ABC_DEF0u64);
    const N: usize = 200;
    let mut all: Vec<(Vec<u8>, u8)> = Vec::with_capacity(N);

    for _ in 0..N {
        let size = if rng.range(2) == 0 {
            1 + rng.range(8 * 1024)
        } else {
            32 * 1024 + rng.range(64 * 1024)
        };
        let marker = (rng.next() as u8).wrapping_add(1);
        let v: Vec<u8> = vec![marker; size];
        all.push((v, marker));
    }

    // Full sweep — read back every byte of every live allocation.
    for (v, marker) in all.iter() {
        for &b in v.iter() {
            check(b == *marker, b"concurrent: marker mismatch in sweep\n");
        }
    }

    // Free in shuffled order (Fisher-Yates) to exercise dealloc
    // patterns dlmalloc/mheap might fragment differently from FIFO.
    for i in (1..all.len()).rev() {
        let j = rng.range(i + 1);
        all.swap(i, j);
    }
    while let Some((v, marker)) = all.pop() {
        check(v[v.len() / 2] == marker, b"concurrent-free: corrupted\n");
    }
}

// ─── Test 7: arena reuse across epochs ───────────────────────────────
//
// The mheap arena is 64 MiB. If freed pages aren't reclaimed
// correctly, after a few large-allocation epochs we'll exhaust the
// arena and exit(2) with "arena exhausted".
//
// This test allocates ~32 MiB worth of large blocks per epoch, drops
// them, and repeats EPOCHS times. Each epoch sees fresh content
// pattern; surviving all epochs proves mheap's free path correctly
// returns pages to the radix tree's free pool and find() locates
// them again.

fn test_arena_reuse_epochs() {
    const EPOCHS: usize = 8;
    const PER_EPOCH_BYTES: usize = 32 * 1024 * 1024; // 32 MiB
    const BLOCK_SIZE: usize = 256 * 1024;
    const BLOCKS_PER_EPOCH: usize = PER_EPOCH_BYTES / BLOCK_SIZE; // 128

    for epoch in 0..EPOCHS {
        let pattern = (epoch as u64).wrapping_mul(0x9E37_79B9_7F4A_7C15u64) as u8;

        let mut blocks: Vec<Vec<u8>> = Vec::with_capacity(BLOCKS_PER_EPOCH);
        for _ in 0..BLOCKS_PER_EPOCH {
            let v: Vec<u8> = vec![pattern; BLOCK_SIZE];
            blocks.push(v);
        }

        // Spot-check that this epoch's content is intact and didn't
        // collide with a previous-epoch leak.
        for v in blocks.iter() {
            check(v[0] == pattern, b"epochs: head wrong pattern\n");
            check(v[BLOCK_SIZE / 2] == pattern, b"epochs: middle wrong pattern\n");
            check(v[BLOCK_SIZE - 1] == pattern, b"epochs: tail wrong pattern\n");
        }

        // Drop everything — mheap_free should reclaim all 128 spans.
        drop(blocks);
    }
}
