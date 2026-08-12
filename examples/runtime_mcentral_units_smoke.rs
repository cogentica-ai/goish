// runtime_mcentral_units_smoke — unit-level coverage of the mcentral
// size-class lookup table and of Span's slot bookkeeping: the alloc
// cache refill, slot addressing, and the cross-M free that must survive
// a concurrent refill.
//
// Ported from the `#[cfg(test)] mod tests` blocks that used to live at
// the bottom of src/runtime/mcentral/{sizeclasses,span}.rs. `cargo test`
// cannot link in this crate (the test harness pulls in std, whose
// `panic_impl` lang item collides with goish's), so every in-tree
// #[test] was unreachable. Examples are goish's actual test mechanism —
// they run under e2e.
//
// mcentral_smoke covers the allocator end-to-end through Box; this one
// covers the bookkeeping underneath, where the lock-free refill
// invariant lives. See the note on `refill_alloc_cache`: the claim must
// be published with fetch_or, never a plain store, or a free that lands
// mid-refill is lost — goish has no GC sweeper to notice afterwards.

#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate goish;

use core::sync::atomic::Ordering;
use goish::fmt;
use goish::runtime::mcentral::sizeclasses::class_for;
use goish::runtime::mcentral::span::Span;
use goish::syscall;

/// A stack-local Span shaped as though mcentral had just handed it out.
///
/// `Span::new()` is a const constructor for static placement, so the
/// fields start zeroed; the writes below go through a raw pointer
/// because the span's own API only mutates through `&self` under the
/// central lock. Sound here: this is a fresh stack local and we hold
/// the only reference to it.
fn fresh(elemsize: u32, nelems: u16) -> Span {
    let s = Span::new();
    let s_ref: &Span = &s;
    unsafe {
        let m: *mut Span = s_ref as *const Span as *mut Span;
        (*m).base = 0x100_0000;
        (*m).npages = 1;
        (*m).elemsize = elemsize;
        (*m).nelems = nelems;
        (*m).sizeclass = 1;
    }
    return s;
}

#[goish::main]
fn main() {
    let mut failed = 0;

    // ─── sizeclasses ───────────────────────────────────────────────

    // 1. Small classes, including the alignment-driven jumps: class 3
    //    is 24 bytes but only 8-aligned, so a 16-aligned 20-byte
    //    request lands in class 4 (32 bytes) instead.
    {
        if class_for(1, 1) == Some(1)          // 8 bytes
            && class_for(8, 8) == Some(1)      // 8 bytes
            && class_for(9, 8) == Some(2)      // 16 bytes
            && class_for(16, 16) == Some(2)    // class 2 has min align 16
            && class_for(20, 16) == Some(4)    // 32 bytes (class 3 is 8-align)
            && class_for(32, 32) == Some(4)
        {
            fmt::Println!("[ 1] class_for small           PASS");
        } else {
            fmt::Println!("[ 1] class_for small           FAIL");
            failed += 1;
        }
    }

    // 2. The 1024-byte boundary into the large buckets.
    {
        if class_for(1024, 8) == Some(32)      // 1024 bytes
            && class_for(1025, 8) == Some(33)  // first large-bucket size
            && class_for(1152, 8) == Some(33)  // exactly class 33
            && class_for(1153, 8) == Some(34)  // first byte over class 33
        {
            fmt::Println!("[ 2] class_for large bucket    PASS");
        } else {
            fmt::Println!("[ 2] class_for large bucket    FAIL");
            failed += 1;
        }
    }

    // 3. The 32 KiB boundary: the last class, then the fall-through to
    //    mheap for anything bigger.
    {
        if class_for(32768, 8) == Some(67) && class_for(32769, 8).is_none() {
            fmt::Println!("[ 3] class_for 32K boundary    PASS");
        } else {
            fmt::Println!("[ 3] class_for 32K boundary    FAIL");
            failed += 1;
        }
    }

    // ─── Span ──────────────────────────────────────────────────────

    // 4. Refill the alloc cache, take two slots, free one.
    {
        let s = fresh(8, 1024);
        // Prime the alloc cache (refill word 0) — one 64-bit word, so
        // the owner claims all 64 slots at once.
        let claimed = unsafe { s.refill_alloc_cache(0) };
        s.alloc_count.fetch_add(claimed as u16, Ordering::AcqRel);
        let a = unsafe { s.next_free_owner() };
        let b = unsafe { s.next_free_owner() };
        let after_refill = s.alloc_count.load(Ordering::Relaxed);
        // Freeing slot 0 drops the bit and decrements the count.
        s.free_slot_atomic(0);
        if claimed == 64
            && a == Some(0)
            && b == Some(1)
            && after_refill == 64
            && s.alloc_count.load(Ordering::Relaxed) == 63
        {
            fmt::Println!("[ 4] Span refill/alloc/free    PASS");
        } else {
            fmt::Println!("[ 4] Span refill/alloc/free    FAIL");
            failed += 1;
        }
    }

    // 5. Slot addressing round-trips: index → address → index.
    {
        let s = fresh(32, 256);
        unsafe {
            let m: *mut Span = &s as *const Span as *mut Span;
            (*m).base = 0x4000;
        }
        if s.slot_addr(2) == 0x4000 + 2 * 32 && s.slot_of(0x4000 + 5 * 32) == 5 {
            fmt::Println!("[ 5] Span slot addressing      PASS");
        } else {
            fmt::Println!("[ 5] Span slot addressing      FAIL");
            failed += 1;
        }
    }

    // 6. A cross-M free landing between the owner's load and its
    //    fetch_or must survive. This is the invariant that forces
    //    fetch_or over a plain store: with a store, the owner would
    //    write back the stale word and resurrect the freed slot.
    {
        let s = fresh(8, 1024);
        s.alloc_bits[0].store(0xFF, Ordering::Release);
        s.alloc_count.store(8, Ordering::Release);

        // Owner loads 0xFF and computes the bits it intends to claim.
        let load = s.alloc_bits[0].load(Ordering::Acquire);
        let claim_mask = !load; // 0xFFFF_FFFF_FFFF_FF00

        // A concurrent free on another M clears bit 3.
        s.alloc_bits[0].fetch_and(!(1u64 << 3), Ordering::AcqRel);
        s.alloc_count.fetch_sub(1, Ordering::AcqRel);

        // Owner publishes its claim.
        s.alloc_bits[0].fetch_or(claim_mask, Ordering::Release);

        // Bit 3 must still be 0 (the free is preserved) and the high
        // bits all 1 (the claim landed).
        let final_word = s.alloc_bits[0].load(Ordering::Acquire);
        if final_word == 0xFFFF_FFFF_FFFF_FFF7 && s.alloc_count.load(Ordering::Relaxed) == 7 {
            fmt::Println!("[ 6] Span cross-M free race    PASS");
        } else {
            fmt::Println!("[ 6] Span cross-M free race    FAIL");
            failed += 1;
        }
    }

    if failed == 0 {
        fmt::Println!("ok 6/6");
        syscall::Exit(0);
    } else {
        fmt::Println!("FAIL", failed, "of 6");
        syscall::Exit(1);
    }
}
