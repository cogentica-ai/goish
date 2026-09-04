//! Pinned against Go 1.25.5: `sync/atomic`'s value semantics.
//!
//! `port_coverage.py sync` reports **46 UNVERIFIED names**, and 36 of
//! them are sync/atomic: goish's whole atomic package carried ZERO
//! provenance anchors, matching Go by name only. GOISH018 could not
//! diff any of it, so a wrong wrap, an inverted CompareAndSwap return
//! or a Swap that returned the NEW value would all have been
//! invisible — in the package the scheduler, the netpoller and every
//! counter in the runtime are built on.
//!
//! It measures clean: 22/22 identical to Go on the first run. No
//! defects. This file exists to keep it that way.
//!
//! What is pinned, chosen for where a reimplementation goes wrong:
//!
//!   * Signed Add WRAPS at both boundaries — MaxInt64+1 is MinInt64
//!     and MinInt64-1 is MaxInt64, not a saturate and not a panic.
//!   * Unsigned subtraction is Go's documented idiom: add the two's
//!     complement. `Uint32.Add(^uint32(2)+1)` on 5 gives 3, and
//!     `Add(^uint32(0))` is subtract-one, which wraps 0 to MaxUint32.
//!   * CompareAndSwap returns whether it SWAPPED and leaves the value
//!     untouched when it did not — including the degenerate
//!     old==new==have case, which still reports true.
//!   * Swap returns the OLD value.
//!   * The package-level functions agree with the typed methods.
//!
//! Reference generated with:
//!   CGO_ENABLED=0 scripts/goref.sh sync/atomic <atomic_ref_test.go>
#![no_std]
#![no_main]
#![allow(non_snake_case)]
extern crate alloc;
extern crate goish;
use goish::sync::atomic;
use goish::{fmt, string};

/// Go's output, verbatim.
const GO: [&str; 22] = [
    "Int64.Add        start=0                     delta=1                     -> 1",
    "Int64.Add        start=5                     delta=-3                    -> 2",
    "Int64.Add        start=9223372036854775807   delta=1                     -> -9223372036854775808",
    "Int64.Add        start=-9223372036854775808  delta=-1                    -> 9223372036854775807",
    "Int64.Add        start=-1                    delta=1                     -> 0",
    "Int64.Add        start=100                   delta=-100                  -> 0",
    "Uint32.Add       start=0                     delta=1                     -> 1",
    "Uint32.Add       start=4294967295            delta=1                     -> 0",
    "Uint32.Add       start=5                     delta=4294967294            -> 3",
    "Uint32.Add       start=0                     delta=4294967295            -> 4294967295",
    "Int64.CAS        have=1    old=1    new=2    -> ok=true  now=2",
    "Int64.CAS        have=1    old=9    new=2    -> ok=false now=1",
    "Int64.CAS        have=0    old=0    new=0    -> ok=true  now=0",
    "Int64.Swap       old=7 now=9",
    "Bool.Load        zero=false",
    "Bool.Swap        old=false now=true",
    "Bool.CAS         ok=true now=false",
    "Bool.CAS-miss    ok=false now=false",
    "AddInt64         -> -10",
    "CASInt64         -> true",
    "LoadInt64        -> 3",
    "AddUint64        -> 18446744073709551615",
];

static mut FAILED: i64 = 0;
static mut LINE: usize = 0;
#[goish::main]
fn main() {
    let i64cases: [(i64, i64); 6] = [
        (0, 1),
        (5, -3),
        (i64::MAX, 1),
        (i64::MIN, -1),
        (-1, 1),
        (100, -100),
    ];
    for (start, delta) in i64cases.iter() {
        let v = atomic::Int64::new(*start);
        let got = v.Add(*delta);
        chk(fmt::Sprintf!(
            "%-16s start=%-21d delta=%-21d -> %d",
            string("Int64.Add"),
            *start,
            *delta,
            got
        ));
    }
    let u32cases: [(u32, u32); 4] = [(0, 1), (u32::MAX, 1), (5, !2u32 + 1), (0, !0u32)];
    for (start, delta) in u32cases.iter() {
        let v = atomic::Uint32::new(*start);
        let got = v.Add(*delta);
        chk(fmt::Sprintf!(
            "%-16s start=%-21d delta=%-21d -> %d",
            string("Uint32.Add"),
            *start as i64,
            *delta as i64,
            got as i64
        ));
    }
    let cas: [(i64, i64, i64); 3] = [(1, 1, 2), (1, 9, 2), (0, 0, 0)];
    for (have, old, new) in cas.iter() {
        let v = atomic::Int64::new(*have);
        let ok = v.CompareAndSwap(*old, *new);
        chk(fmt::Sprintf!(
            "%-16s have=%-4d old=%-4d new=%-4d -> ok=%-5v now=%d",
            string("Int64.CAS"),
            *have,
            *old,
            *new,
            ok,
            v.Load()
        ));
    }
    let s = atomic::Int64::new(7);
    let old = s.Swap(9);
    chk(fmt::Sprintf!(
        "%-16s old=%d now=%d",
        string("Int64.Swap"),
        old,
        s.Load()
    ));

    let b = atomic::Bool::new(false);
    chk(fmt::Sprintf!(
        "%-16s zero=%v",
        string("Bool.Load"),
        b.Load()
    ));
    let bo = b.Swap(true);
    chk(fmt::Sprintf!(
        "%-16s old=%v now=%v",
        string("Bool.Swap"),
        bo,
        b.Load()
    ));
    let ok1 = b.CompareAndSwap(true, false);
    chk(fmt::Sprintf!(
        "%-16s ok=%v now=%v",
        string("Bool.CAS"),
        ok1,
        b.Load()
    ));
    let ok2 = b.CompareAndSwap(true, true);
    chk(fmt::Sprintf!(
        "%-16s ok=%v now=%v",
        string("Bool.CAS-miss"),
        ok2,
        b.Load()
    ));

    let pv = atomic::Int64::new(10);
    chk(fmt::Sprintf!(
        "%-16s -> %d",
        string("AddInt64"),
        atomic::AddInt64(&pv, -20)
    ));
    chk(fmt::Sprintf!(
        "%-16s -> %v",
        string("CASInt64"),
        atomic::CompareAndSwapInt64(&pv, -10, 3)
    ));
    chk(fmt::Sprintf!(
        "%-16s -> %d",
        string("LoadInt64"),
        atomic::LoadInt64(&pv)
    ));
    let pu = atomic::Uint64::new(0);
    chk(fmt::Sprintf!(
        "%-16s -> %d",
        string("AddUint64"),
        atomic::AddUint64(&pu, !0u64)
    ));
    let failed = unsafe { FAILED };
    let n = GO.len() as i64;
    if failed == 0 {
        fmt::Printf!("sync/atomic: %d/%d match Go\n", n, n);
        goish::os::Exit(0);
    }
    fmt::Printf!("FAIL: %d/%d diverge\n", failed, n);
    goish::os::Exit(1);
}

/// Compare one rendered line against the Go reference, in order.
fn chk(got: string) {
    let i = unsafe { LINE };
    unsafe { LINE += 1 };
    let want = string::from_static(GO[i]);
    if got == want {
        return;
    }
    fmt::Printf!("DIFF go   : %s\n", want);
    fmt::Printf!("     goish: %s\n", got);
    unsafe { FAILED += 1 };
}
