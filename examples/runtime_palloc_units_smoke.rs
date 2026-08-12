// runtime_palloc_units_smoke — unit-level coverage of the page
// allocator's bit and summary primitives: PageBits set/clear/range,
// PallocBits summarize/find, find_bit_range64, PallocSum pack/unpack,
// and merge_summaries. Plus the grow-on-demand no-overlap replay at
// full checkpoint scale.
//
// Ported from the `#[cfg(test)] mod tests` blocks that used to live at
// the bottom of src/runtime/mheap/{palloc_bits,palloc_sum,page_alloc}.rs.
// `cargo test` cannot link in this crate (the test harness pulls in std,
// whose `panic_impl` lang item collides with goish's), so every in-tree
// #[test] was unreachable. Examples are goish's actual test mechanism —
// they run under e2e.
//
// The existing mheap_palloc / _multi / _stress examples cover PageAlloc
// end-to-end against real mmap'd memory; this one covers the layer
// below them, where a wrong bit is invisible until it corrupts a span.

#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

use alloc::vec::Vec;
use goish::fmt;
use goish::runtime::mheap::consts::{
    MAX_PACKED_VALUE, PAGE_SIZE, PALLOC_CHUNK_BYTES, PALLOC_CHUNK_PAGES,
};
use goish::runtime::mheap::page_alloc::{PageAlloc, ALLOC_FAILED};
use goish::runtime::mheap::palloc_bits::{find_bit_range64, PageBits, PallocBits};
use goish::runtime::mheap::palloc_sum::{merge_summaries, PallocSum};
use goish::syscall;

#[goish::main]
fn main() {
    let mut failed = 0;

    // ─── PageBits ──────────────────────────────────────────────────

    // 1. set / get / clear round-trip on a single bit.
    {
        let mut b = PageBits::zero();
        b.set(7);
        let after_set = b.get(7);
        b.clear(7);
        if after_set == 1 && b.get(7) == 0 {
            fmt::Println!("[ 1] PageBits set/clear        PASS");
        } else {
            fmt::Println!("[ 1] PageBits set/clear        FAIL");
            failed += 1;
        }
    }

    // 2. set_range wholly inside one word: bits 3..=7.
    {
        let mut b = PageBits::zero();
        b.set_range(3, 5);
        let mut ok = true;
        for i in 0..3 {
            if b.get(i) != 0 {
                ok = false;
            }
        }
        for i in 3..8 {
            if b.get(i) != 1 {
                ok = false;
            }
        }
        if b.get(8) != 0 {
            ok = false;
        }
        if ok {
            fmt::Println!("[ 2] PageBits set_range word   PASS");
        } else {
            fmt::Println!("[ 2] PageBits set_range word   FAIL");
            failed += 1;
        }
    }

    // 3. set_range straddling the 64-bit word boundary.
    {
        let mut b = PageBits::zero();
        b.set_range(60, 10);
        if b.popcnt_range(60, 10) == 10 && b.get(59) == 0 && b.get(70) == 0 {
            fmt::Println!("[ 3] PageBits set_range split  PASS");
        } else {
            fmt::Println!("[ 3] PageBits set_range split  FAIL");
            failed += 1;
        }
    }

    // ─── PallocBits::summarize ─────────────────────────────────────

    // 4. An all-free chunk summarizes as start=max=end=512.
    {
        let b = PallocBits::zero();
        if b.summarize().unpack() == (512, 512, 512) {
            fmt::Println!("[ 4] summarize all free        PASS");
        } else {
            fmt::Println!("[ 4] summarize all free        FAIL");
            failed += 1;
        }
    }

    // 5. A fully-allocated chunk summarizes as all zero.
    {
        let mut b = PallocBits::zero();
        b.alloc_range(0, 512);
        if b.summarize().unpack() == (0, 0, 0) {
            fmt::Println!("[ 5] summarize all allocated   PASS");
        } else {
            fmt::Println!("[ 5] summarize all allocated   FAIL");
            failed += 1;
        }
    }

    // 6. Free head, used middle, free tail: 100 / 312 / 100.
    {
        let mut b = PallocBits::zero();
        b.alloc_range(100, 312);
        let s = b.summarize();
        if s.start() == 100 && s.end() == 100 && s.max() == 100 {
            fmt::Println!("[ 6] summarize split chunk     PASS");
        } else {
            fmt::Println!("[ 6] summarize split chunk     FAIL");
            failed += 1;
        }
    }

    // ─── PallocBits::find ──────────────────────────────────────────

    // 7. Single page after a 5-page prefix.
    {
        let mut b = PallocBits::zero();
        b.alloc_range(0, 5);
        let (idx, _) = b.find(1, 0);
        if idx == 5 {
            fmt::Println!("[ 7] find(1) after prefix      PASS");
        } else {
            fmt::Println!("[ 7] find(1) after prefix      FAIL");
            failed += 1;
        }
    }

    // 8. An 8-page run, still within the first word.
    {
        let mut b = PallocBits::zero();
        b.alloc_range(0, 10);
        let (idx, _) = b.find(8, 0);
        if idx == 10 {
            fmt::Println!("[ 8] find(8) within word       PASS");
        } else {
            fmt::Println!("[ 8] find(8) within word       FAIL");
            failed += 1;
        }
    }

    // 9. A 128-page run must skip the partially-used first word.
    {
        let mut b = PallocBits::zero();
        b.alloc_range(60, 4); // bits 60..=63 used → run starts at 64
        let (idx, _) = b.find(128, 0);
        if idx == 64 {
            fmt::Println!("[ 9] find(128) spans words     PASS");
        } else {
            fmt::Println!("[ 9] find(128) spans words     FAIL");
            failed += 1;
        }
    }

    // 10. find_bit_range64 locates the first run of n set bits.
    {
        // 0xF0 = 0b1111_0000 → the run of 4 ones starts at bit 4.
        // There is no run of 5, so the result is out of range (>= 64).
        if find_bit_range64(0xF0, 4) == 4 && find_bit_range64(0xF0, 5) >= 64 {
            fmt::Println!("[10] find_bit_range64          PASS");
        } else {
            fmt::Println!("[10] find_bit_range64          FAIL");
            failed += 1;
        }
    }

    // ─── PallocSum ─────────────────────────────────────────────────

    // 11. pack/unpack round-trip preserves all three fields.
    {
        let s = PallocSum::pack(3, 17, 9);
        if s.start() == 3 && s.max() == 17 && s.end() == 9 && s.unpack() == (3, 17, 9) {
            fmt::Println!("[11] PallocSum pack/unpack     PASS");
        } else {
            fmt::Println!("[11] PallocSum pack/unpack     FAIL");
            failed += 1;
        }
    }

    // 12. The empty summary is all-zero.
    {
        if PallocSum::empty().unpack() == (0, 0, 0) {
            fmt::Println!("[12] PallocSum empty           PASS");
        } else {
            fmt::Println!("[12] PallocSum empty           FAIL");
            failed += 1;
        }
    }

    // 13. full_max uses the bit-63 sentinel, because MAX_PACKED_VALUE
    //     does not itself fit in a 21-bit field.
    {
        let s = PallocSum::full_max();
        if s.start() == MAX_PACKED_VALUE
            && s.max() == MAX_PACKED_VALUE
            && s.end() == MAX_PACKED_VALUE
            && s.raw() == 1u64 << 63
        {
            fmt::Println!("[13] PallocSum full_max        PASS");
        } else {
            fmt::Println!("[13] PallocSum full_max        FAIL");
            failed += 1;
        }
    }

    // ─── merge_summaries ───────────────────────────────────────────

    // 14. Two wholly-free 8-page blocks merge into one 16-page run.
    {
        let a = PallocSum::full(8);
        let b = PallocSum::full(8);
        let m = merge_summaries(&[a, b], 3); // 1<<3 = 8 pages each
        if m.unpack() == (16, 16, 16) {
            fmt::Println!("[14] merge two free blocks     PASS");
        } else {
            fmt::Println!("[14] merge two free blocks     FAIL");
            failed += 1;
        }
    }

    // 15. A run straddling the boundary — A's 4-page tail joins B's
    //     4-page head to make 8, which neither block reports alone.
    {
        let a = PallocSum::pack(0, 4, 4);
        let b = PallocSum::pack(4, 4, 0);
        let m = merge_summaries(&[a, b], 3);
        // start=0 (A wasn't wholly free), max=8 (the boundary run),
        // end=0 (B's tail is used).
        if m.unpack() == (0, 8, 0) {
            fmt::Println!("[15] merge straddle boundary   PASS");
        } else {
            fmt::Println!("[15] merge straddle boundary   FAIL");
            failed += 1;
        }
    }

    // 16. A wholly-free A extends B's head: start = 8 + 2 = 10.
    {
        let a = PallocSum::full(8);
        let b = PallocSum::pack(2, 5, 0);
        let m = merge_summaries(&[a, b], 3);
        // max = max(8, 5, A.end + B.start = 10) = 10.
        if m.start() == 10 && m.end() == 0 && m.max() == 10 {
            fmt::Println!("[16] merge start extension     PASS");
        } else {
            fmt::Println!("[16] merge start extension     FAIL");
            failed += 1;
        }
    }

    // ─── PageAlloc: grow-on-demand, no overlap, at full scale ──────

    // 17. Replay the goish-vllm-port full-checkpoint load pattern at
    //     the 81920-chunk (320 GiB) capacity: grow on demand in
    //     64-chunk steps from a 256-chunk start, interleaving multi-GiB
    //     tensor allocations with 1-page metadata allocations, freeing
    //     some. Every live span is checked against every other for
    //     overlap and for containment in the active arena. The real
    //     loader corrupted tensor dims once the heap crossed ~144 GiB —
    //     an overlap here is that bug.
    //
    //     Only bookkeeping is exercised; no page is ever dereferenced,
    //     so the arena base is nominal and nothing is mapped.
    {
        if no_overlap_at_full_checkpoint_scale() {
            fmt::Println!("[17] no overlap at 320 GiB     PASS");
        } else {
            fmt::Println!("[17] no overlap at 320 GiB     FAIL");
            failed += 1;
        }
    }

    if failed == 0 {
        fmt::Println!("ok 17/17");
        syscall::Exit(0);
    } else {
        fmt::Println!("FAIL", failed, "of 17");
        syscall::Exit(1);
    }
}

fn no_overlap_at_full_checkpoint_scale() -> bool {
    const MAX_CHUNKS: usize = 81920;
    let mut p = PageAlloc::new(0x10_0000_0000usize, 256, MAX_CHUNKS);

    // (base, npages) of live allocations.
    let mut live: Vec<(usize, usize)> = Vec::new();

    // Deterministic xorshift so a failure replays identically.
    let mut rng = 0x9e37_79b9_7f4a_7c15u64;
    let mut next = move || {
        rng ^= rng << 13;
        rng ^= rng >> 7;
        rng ^= rng << 17;
        return rng;
    };

    // Sizes drawn from the real load: KDA in_proj f32 = 1.416 GB
    // (~173k pages @ 8K), attn tensors ~350 MB, norms ~1 page.
    let big_sizes = [173_000usize, 43_000, 10_800, 86_000];

    let mut ok = true;
    let alloc_like_loader =
        |p: &mut PageAlloc, live: &mut Vec<(usize, usize)>, npages: usize| -> bool {
            let mut addr = p.alloc(npages);
            if addr == ALLOC_FAILED {
                // mheap_alloc_pages grow-on-demand replica.
                let need = npages.div_ceil(PALLOC_CHUNK_PAGES);
                let room = p.capacity_chunks() - p.end_chunk;
                let step = need.max(64).min(room);
                if step < need {
                    return false; // arena truly exhausted mid-test
                }
                p.grow(step);
                addr = p.alloc(npages);
            }
            if addr == ALLOC_FAILED {
                return false;
            }
            let end = addr + npages * PAGE_SIZE;
            if addr < p.arena_base {
                return false; // span below arena
            }
            if end > p.arena_base + p.end_chunk * PALLOC_CHUNK_BYTES {
                return false; // span past the active arena end
            }
            for &(b, n) in live.iter() {
                let e = b + n * PAGE_SIZE;
                if end > b && addr < e {
                    return false; // OVERLAP
                }
            }
            live.push((addr, npages));
            return true;
        };

    // ~93 layers x (1 big in_proj + several mid + ~6 small).
    for _layer in 0..93 {
        if !alloc_like_loader(&mut p, &mut live, big_sizes[0]) {
            ok = false;
            break;
        }
        for _ in 0..4 {
            let s = big_sizes[1 + (next() as usize % 3)];
            if !alloc_like_loader(&mut p, &mut live, s) {
                ok = false;
                break;
            }
        }
        for _ in 0..6 {
            if !alloc_like_loader(&mut p, &mut live, 1) {
                ok = false;
                break;
            }
        }
        if !ok {
            break;
        }
        // The loader frees cat temporaries: drop ~1 in 3 mid-size.
        if live.len() > 8 && next() % 3 == 0 {
            let idx = live.len() - 2;
            let (b, n) = live.swap_remove(idx);
            p.free(b, n);
        }
    }

    // Sanity: the run really did cross into high-chunk territory,
    // which is where the original corruption appeared.
    if p.end_chunk <= 16384 {
        return false;
    }
    return ok;
}
