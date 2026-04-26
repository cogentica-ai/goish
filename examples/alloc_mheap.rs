// Smoke test: M16 (2b'-γ) — large allocations route through mheap
// via the global allocator path.
//
// Above 32 KiB (Go's MaxSmallSize), every allocation made by safe
// Rust constructs (Vec/Box/String) ends up in mheap. Below, dlmalloc
// continues to serve. We verify routing implicitly by exercising
// both tiers and confirming correctness end-to-end.

#![no_std]
#![no_main]

extern crate alloc;

use alloc::boxed::Box;
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

#[goish::main]
fn main() {
    // ─── Small allocations (below 32 KiB) → dlmalloc ────────────────
    //
    // These exercise the unchanged small path. Should behave identically
    // to the pre-2b'-γ build.
    let mut small: Vec<u32> = Vec::with_capacity(64);
    for i in 0..64u32 {
        small.push(i);
    }
    let mut sum: u64 = 0;
    for v in small.iter() {
        sum += *v as u64;
    }
    check(sum == 64 * 63 / 2, b"small: sum mismatch\n");

    // ─── Single large allocation (1 MiB) → mheap ────────────────────
    //
    // 1 MiB > 32 KiB threshold, so this Vec's backing storage comes
    // from mheap. Write a marker pattern, then read it back to prove
    // the memory is real and writable.
    {
        let mut big: Vec<u8> = Vec::with_capacity(1024 * 1024);
        for i in 0..1024 * 1024 {
            big.push((i & 0xFF) as u8);
        }
        for i in 0..1024 * 1024 {
            check(big[i] == (i & 0xFF) as u8, b"big: content corrupted\n");
        }
        // big drops here → free called → mheap_free
    }

    // ─── Many large allocations (verify non-overlap) ────────────────
    //
    // Allocate 16 × 256 KiB, write distinct markers into each, then
    // read back. If any two overlap, the markers will collide.
    const N_BIG: usize = 16;
    const BIG_SIZE: usize = 256 * 1024;
    let mut bigs: Vec<Vec<u8>> = Vec::with_capacity(N_BIG);
    for i in 0..N_BIG {
        let mut v: Vec<u8> = Vec::with_capacity(BIG_SIZE);
        let marker = (i as u8).wrapping_add(0x40);
        for _ in 0..BIG_SIZE {
            v.push(marker);
        }
        bigs.push(v);
    }
    for i in 0..N_BIG {
        let marker = (i as u8).wrapping_add(0x40);
        // Sample three points in each allocation.
        check(bigs[i][0] == marker, b"bigs: head corrupted\n");
        check(bigs[i][BIG_SIZE / 2] == marker, b"bigs: middle corrupted\n");
        check(bigs[i][BIG_SIZE - 1] == marker, b"bigs: tail corrupted\n");
    }
    // bigs drops here, releasing 16 × 256 KiB back to mheap.

    // ─── Cross-tier realloc (Vec growing past the threshold) ────────
    //
    // Push elements into a u8 Vec, forcing it to grow from <32 KiB
    // (small/dlmalloc) to >32 KiB (large/mheap). Each grow triggers a
    // realloc; the cross-tier path takes the alloc+memcpy+free branch
    // in runtime::heap::realloc. Verify content survives.
    let mut grow: Vec<u8> = Vec::new();
    for i in 0..200_000usize {
        grow.push((i & 0xFF) as u8);
    }
    for i in 0..200_000usize {
        check(grow[i] == (i & 0xFF) as u8, b"grow: content lost\n");
    }

    // ─── Box of a struct that spans multiple pages (mheap path) ─────
    {
        // A 100 KiB struct → boxed via mheap.
        struct Big([u8; 100 * 1024]);
        let mut b: Box<Big> = Box::new(Big([0u8; 100 * 1024]));
        for i in 0..100 * 1024 {
            b.0[i] = (i & 0xFF) as u8;
        }
        for i in 0..100 * 1024 {
            check(b.0[i] == (i & 0xFF) as u8, b"box: content lost\n");
        }
    }

    const OK: &[u8] = b"alloc_mheap: ok\n";
    syscall::Write(syscall::STDOUT, OK.as_ptr(), OK.len());
}
