// runtime_memstats_smoke — runtime::ReadMemStats, the primitive
// testing.B's allocs/op and B/op columns are built on.
//
// benchmark.go uses exactly two fields: it samples Mallocs and
// TotalAlloc before a run and after, and subtracts. So the contract
// that matters is not absolute accuracy — it is that both are
// cumulative and monotonic, and that the delta tracks work actually
// done. All three are asserted below.

#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

use alloc::boxed::Box;
use alloc::vec::Vec;
use goish::runtime::{MemStats, ReadMemStats};
use goish::{fmt, syscall};

#[goish::main]
fn main() {
    let mut failed = 0;

    // 1. A fresh read is populated at all — a process that has booted
    //    the runtime has necessarily allocated.
    let mut a = MemStats::default();
    ReadMemStats(&mut a);
    if a.Mallocs > 0 && a.TotalAlloc > 0 {
        fmt::Println!("[ 1] counters are populated    PASS");
    } else {
        fmt::Println!("[ 1] counters are populated    FAIL");
        failed += 1;
    }

    // 2. Allocating moves both counters up. This is the exact shape
    //    testing.B uses: sample, work, sample, subtract.
    {
        let mut before = MemStats::default();
        ReadMemStats(&mut before);

        // 64 boxes of 1 KiB. Kept alive in a Vec so nothing can be
        // optimised away before the second sample.
        let mut keep: Vec<Box<[u8; 1024]>> = Vec::with_capacity(64);
        for _ in 0..64 {
            keep.push(Box::new([7u8; 1024]));
        }

        let mut after = MemStats::default();
        ReadMemStats(&mut after);

        let d_mallocs = after.Mallocs - before.Mallocs;
        let d_bytes = after.TotalAlloc - before.TotalAlloc;

        // At least the 64 boxes, and at least their payload. More is
        // fine — the Vec's own growth allocates too.
        if d_mallocs >= 64 && d_bytes >= 64 * 1024 {
            fmt::Println!("[ 2] deltas track allocation   PASS");
        } else {
            fmt::Println!("[ 2] deltas track allocation   FAIL");
            failed += 1;
        }
        // Touch the data so the compiler cannot discard the whole loop.
        if keep[0][0] != 7 {
            fmt::Println!("    impossible");
            failed += 1;
        }
    }

    // 3. TotalAlloc and Mallocs are cumulative, never gauges: they must
    //    not fall when memory is released. Go documents this
    //    explicitly — "unlike Alloc and HeapAlloc, it does not decrease
    //    when objects are freed" — and testing.B's subtraction would
    //    underflow into a nonsense u64 if it ever did.
    {
        let mut before = MemStats::default();
        ReadMemStats(&mut before);
        {
            let mut tmp: Vec<Box<[u8; 4096]>> = Vec::new();
            for _ in 0..32 {
                tmp.push(Box::new([0u8; 4096]));
            }
            // dropped here
        }
        let mut after = MemStats::default();
        ReadMemStats(&mut after);

        if after.Mallocs >= before.Mallocs && after.TotalAlloc >= before.TotalAlloc {
            fmt::Println!("[ 3] monotonic across frees    PASS");
        } else {
            fmt::Println!("[ 3] monotonic across frees    FAIL");
            failed += 1;
        }
    }

    // 4. Alloc mirrors HeapAlloc, and Sys mirrors HeapSys, as Go's
    //    docs state ("This is the same as HeapAlloc").
    {
        let mut m = MemStats::default();
        ReadMemStats(&mut m);
        if m.Alloc == m.HeapAlloc && m.Sys == m.HeapSys {
            fmt::Println!("[ 4] Alloc mirrors HeapAlloc   PASS");
        } else {
            fmt::Println!("[ 4] Alloc mirrors HeapAlloc   FAIL");
            failed += 1;
        }
    }

    // 5. The fields goish cannot answer stay at zero rather than
    //    holding a plausible-looking guess. Frees in particular: goish
    //    frees through Drop at scattered sites, not one funnel, so
    //    `Mallocs - Frees` is NOT the live count here the way it is in
    //    Go. Reading Alloc is the correct move, and this pins that the
    //    zero is deliberate.
    {
        let mut m = MemStats::default();
        ReadMemStats(&mut m);
        if m.Frees == 0 && m.Lookups == 0 {
            fmt::Println!("[ 5] unknowable fields are 0   PASS");
        } else {
            fmt::Println!("[ 5] unknowable fields are 0   FAIL");
            failed += 1;
        }
    }

    if failed == 0 {
        fmt::Println!("ok 5/5");
        syscall::Exit(0);
    } else {
        fmt::Println!("FAIL", failed, "of 5");
        syscall::Exit(1);
    }
}
