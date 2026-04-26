// Smoke test: M16 (2c) — mcentral routes small allocations through
// size-class spans backed by mheap.
//
// Verifies the small-alloc path end-to-end:
//
//   - small Vecs (well under 32 KiB) get sub-page slots from
//     mcentral's per-class spans rather than each consuming a
//     dedicated page from mheap
//   - allocations + frees correctly track the partial / full lists
//     and return empty spans to mheap
//   - cross-class allocations don't trample each other's slots
//   - threshold-boundary allocations still work
//   - large allocations (>32 KiB) still take the mheap-direct path
//     unchanged
//
// We can't directly inspect mcentral's lock-protected internals from
// here, but `live_slots()` exposes the slot-occupancy total, which
// must be zero between fully-balanced alloc/free batches.

#![no_std]
#![no_main]

extern crate alloc;

use alloc::boxed::Box;
use alloc::vec::Vec;
use goish::runtime::mcentral;
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
    check(mcentral::ready(), b"mcentral: not ready\n");

    test_one_class();
    test_many_classes();
    test_full_span_then_drain();
    test_cross_class_independence();
    test_box_at_each_size_class();

    const OK: &[u8] = b"mcentral_smoke: ok\n";
    syscall::Write(syscall::STDOUT, OK.as_ptr(), OK.len());
}

// ─── A single size class — alloc/free roundtrip ──────────────────────

fn test_one_class() {
    let baseline = mcentral::live_slots();
    let mut v: Vec<u8> = Vec::with_capacity(20);
    for i in 0..20 {
        v.push(i as u8);
    }
    check(mcentral::live_slots() > baseline, b"one-class: no slot taken\n");
    for i in 0..20 {
        check(v[i] == i as u8, b"one-class: data corrupted\n");
    }
    drop(v);
    check(
        mcentral::live_slots() == baseline,
        b"one-class: slot not returned\n",
    );
}

// ─── Many distinct size classes alive simultaneously ─────────────────

fn test_many_classes() {
    let baseline = mcentral::live_slots();
    let sizes: [usize; 8] = [8, 16, 32, 64, 128, 256, 1024, 4096];
    let mut all: Vec<Vec<u8>> = Vec::with_capacity(sizes.len());
    for (i, &sz) in sizes.iter().enumerate() {
        let marker = (0x40 + i) as u8;
        let mut v: Vec<u8> = Vec::with_capacity(sz);
        for _ in 0..sz {
            v.push(marker);
        }
        all.push(v);
    }
    // After all allocations, live_slots increased by at least sizes.len().
    check(
        mcentral::live_slots() >= baseline + sizes.len(),
        b"many-classes: slot count low\n",
    );
    // Verify each marker survived.
    for (i, v) in all.iter().enumerate() {
        let marker = (0x40 + i) as u8;
        check(v[0] == marker, b"many-classes: head\n");
        check(v[v.len() / 2] == marker, b"many-classes: middle\n");
        check(v[v.len() - 1] == marker, b"many-classes: tail\n");
    }
    drop(all);
    check(
        mcentral::live_slots() == baseline,
        b"many-classes: not all freed\n",
    );
}

// ─── Fill an entire span (class 1 = 1024 slots) and drain it ────────

fn test_full_span_then_drain() {
    let baseline = mcentral::live_slots();

    // Class 1 has 1024 slots of 8 bytes each. Allocating 1024 × 8-byte
    // Vecs forces a fresh span, fills it, and exercises the
    // partial → full transition. Hold them via Box<[u8; 8]> so each
    // is a fixed-size, single-slot allocation.
    const N: usize = 1024;
    let mut held: Vec<Box<[u8; 8]>> = Vec::with_capacity(N);
    for i in 0..N {
        let marker = (i & 0xFF) as u8;
        let b: Box<[u8; 8]> = Box::new([marker; 8]);
        held.push(b);
    }
    check(
        mcentral::live_slots() >= baseline + N,
        b"full-span: live_slots too low\n",
    );

    // Verify each box's content.
    for (i, b) in held.iter().enumerate() {
        let marker = (i & 0xFF) as u8;
        for &byte in b.iter() {
            check(byte == marker, b"full-span: content corrupted\n");
        }
    }

    // Drain — should trigger full → partial → empty span return-to-mheap.
    drop(held);
    check(
        mcentral::live_slots() == baseline,
        b"full-span: drain incomplete\n",
    );
}

// ─── Cross-class isolation (alloc class A, then class B, verify A) ──

fn test_cross_class_independence() {
    let mut v_small: Vec<u8> = Vec::with_capacity(16);
    for _ in 0..16 {
        v_small.push(0xAA);
    }
    let mut v_mid: Vec<u8> = Vec::with_capacity(256);
    for _ in 0..256 {
        v_mid.push(0xBB);
    }
    let mut v_large: Vec<u8> = Vec::with_capacity(4000);
    for _ in 0..4000 {
        v_large.push(0xCC);
    }

    for &b in &v_small {
        check(b == 0xAA, b"cross-class: small\n");
    }
    for &b in &v_mid {
        check(b == 0xBB, b"cross-class: mid\n");
    }
    for &b in &v_large {
        check(b == 0xCC, b"cross-class: large\n");
    }
}

// ─── A Box at each representative size class ─────────────────────────

fn test_box_at_each_size_class() {
    // Touch a representative of each "tier" of class — at the lookup
    // table boundaries that make the class transitions interesting.
    {
        let mut b: Box<[u8; 8]> = Box::new([0; 8]);
        for v in b.iter_mut() {
            *v = 0x11;
        }
        check(b[7] == 0x11, b"box-class: 8\n");
    }
    {
        let mut b: Box<[u8; 100]> = Box::new([0; 100]);
        for v in b.iter_mut() {
            *v = 0x22;
        }
        check(b[99] == 0x22, b"box-class: 100\n");
    }
    {
        let mut b: Box<[u8; 1025]> = Box::new([0; 1025]);
        for v in b.iter_mut() {
            *v = 0x33;
        }
        check(b[1024] == 0x33, b"box-class: 1025 (boundary into class 33)\n");
    }
    {
        let mut b: Box<[u8; 5000]> = Box::new([0; 5000]);
        for v in b.iter_mut() {
            *v = 0x44;
        }
        check(b[4999] == 0x44, b"box-class: 5000\n");
    }
    {
        // Just under the 32 KiB threshold — still mcentral.
        let mut b: Box<[u8; 32768]> = Box::new([0; 32768]);
        for v in b.iter_mut() {
            *v = 0x55;
        }
        check(b[32767] == 0x55, b"box-class: 32768 (boundary into mheap)\n");
    }
    {
        // Above threshold — mheap directly.
        let mut b: Box<[u8; 32769]> = Box::new([0; 32769]);
        for v in b.iter_mut() {
            *v = 0x66;
        }
        check(b[32768] == 0x66, b"box-class: 32769 (mheap)\n");
    }
}
