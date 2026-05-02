// sync_atomic_smoke — exercise the typed atomic structs.
//
// Covers Int32 / Int64 / Uint32 / Uint64 / Uintptr / Bool — every
// operation that maps to Go's `sync/atomic` post-1.19 typed API.
//
// References:
//   /share/go/src/sync/atomic/type.go (Int32/Int64/Uint32/Uint64/
//                                      Uintptr/Bool)

#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

use goish::sync::atomic;
use goish::{syscall, Println};

#[goish::main]
fn main() {
    let mut failed = 0;

    // 1. Int32 — Load/Store/Add/Swap/CAS/And/Or.
    {
        let x = atomic::Int32::new(0);
        x.Store(7);
        if x.Load() != 7 {
            Println!("[ 1] Int32 Load/Store           FAIL");
            failed += 1;
        } else {
            // Add returns NEW value.
            let new = x.Add(3);
            // Swap returns OLD value.
            let old = x.Swap(100);
            // CAS swap when stale.
            let cas_stale = x.CompareAndSwap(0, 999);
            // CAS swap when fresh.
            let cas_fresh = x.CompareAndSwap(100, 200);
            // And returns OLD value, applies mask in place.
            x.Store(0xF0);
            let and_old = x.And(0x0F);
            let and_now = x.Load();
            // Or returns OLD value.
            x.Store(0x10);
            let or_old = x.Or(0x01);
            let or_now = x.Load();
            if new == 10
                && old == 10
                && !cas_stale
                && cas_fresh
                && and_old == 0xF0
                && and_now == 0x00
                && or_old == 0x10
                && or_now == 0x11
            {
                Println!("[ 1] Int32 ops                  PASS");
            } else {
                Println!("[ 1] Int32 ops                  FAIL");
                failed += 1;
            }
        }
    }

    // 2. Int64 — same suite as Int32 with 64-bit values.
    {
        let x = atomic::Int64::new(0);
        x.Store(0x7fffffff_ffffffff);
        let new = x.Add(1);
        // 0x7f..f + 1 = 0x80..0 (signed overflow → most-negative).
        // Go's Add wraps; goish uses wrapping_add so should match.
        if x.Load() == new && new == -0x80000000_00000000 {
            Println!("[ 2] Int64 wrapping Add         PASS");
        } else {
            Println!("[ 2] Int64 wrapping Add         FAIL");
            failed += 1;
        }
    }

    // 3. Uint32 — And/Or composed.
    {
        let x = atomic::Uint32::new(0xff00_ff00);
        let _ = x.And(0xff_ffff);
        let _ = x.Or(0xff00_0000);
        // After And mask 0x00FFFFFF: 0x0000_FF00. After Or 0xFF00_0000:
        // 0xFF00_FF00.
        if x.Load() == 0xff00_ff00 {
            Println!("[ 3] Uint32 And/Or compose      PASS");
        } else {
            Println!("[ 3] Uint32 And/Or compose      FAIL");
            failed += 1;
        }
    }

    // 4. Uint64 — Swap returns previous.
    {
        let x = atomic::Uint64::new(42);
        let prev = x.Swap(0xdead_beef_cafe_babe);
        if prev == 42 && x.Load() == 0xdead_beef_cafe_babe {
            Println!("[ 4] Uint64 Swap                PASS");
        } else {
            Println!("[ 4] Uint64 Swap                FAIL");
            failed += 1;
        }
    }

    // 5. Uintptr — Load/Store/Swap basic.
    {
        let x = atomic::Uintptr::new(0);
        x.Store(0xdead_beef);
        let prev = x.Swap(0xcafe_d00d);
        if x.Load() == 0xcafe_d00d && prev == 0xdead_beef {
            Println!("[ 5] Uintptr Load/Store/Swap    PASS");
        } else {
            Println!("[ 5] Uintptr Load/Store/Swap    FAIL");
            failed += 1;
        }
    }

    // 6. Uintptr — Add returns NEW value (Go contract).
    {
        let x = atomic::Uintptr::new(100);
        let new = x.Add(50);
        if new == 150 && x.Load() == 150 {
            Println!("[ 6] Uintptr Add returns new    PASS");
        } else {
            Println!("[ 6] Uintptr Add returns new    FAIL");
            failed += 1;
        }
    }

    // 7. Uintptr — CompareAndSwap stale + fresh.
    {
        let x = atomic::Uintptr::new(7);
        let stale = x.CompareAndSwap(0, 99);
        let fresh = x.CompareAndSwap(7, 21);
        if !stale && fresh && x.Load() == 21 {
            Println!("[ 7] Uintptr CAS                PASS");
        } else {
            Println!("[ 7] Uintptr CAS                FAIL");
            failed += 1;
        }
    }

    // 8. Uintptr — And returns OLD value, masks in place.
    {
        let x = atomic::Uintptr::new(0xff00);
        let old = x.And(0x0ff0);
        if old == 0xff00 && x.Load() == 0x0f00 {
            Println!("[ 8] Uintptr And                PASS");
        } else {
            Println!("[ 8] Uintptr And                FAIL");
            failed += 1;
        }
    }

    // 9. Uintptr — Or returns OLD value, sets bits.
    {
        let x = atomic::Uintptr::new(0x0001);
        let old = x.Or(0x0080);
        if old == 0x0001 && x.Load() == 0x0081 {
            Println!("[ 9] Uintptr Or                 PASS");
        } else {
            Println!("[ 9] Uintptr Or                 FAIL");
            failed += 1;
        }
    }

    // 10. Bool — Load/Store/Swap/CAS.
    {
        let b = atomic::Bool::new(false);
        b.Store(true);
        if !b.Load() {
            Println!("[10] Bool Load/Store            FAIL");
            failed += 1;
        } else {
            let prev = b.Swap(false);
            let cas_stale = b.CompareAndSwap(true, true);
            let cas_fresh = b.CompareAndSwap(false, true);
            if prev && !cas_stale && cas_fresh && b.Load() {
                Println!("[10] Bool ops                   PASS");
            } else {
                Println!("[10] Bool ops                   FAIL");
                failed += 1;
            }
        }
    }

    // 11. Const constructor — usable in static context (compile-only).
    {
        const C32: atomic::Int32 = atomic::Int32::new(42);
        const CU: atomic::Uintptr = atomic::Uintptr::new(0xabc);
        if C32.Load() == 42 && CU.Load() == 0xabc {
            Println!("[11] const fn new               PASS");
        } else {
            Println!("[11] const fn new               FAIL");
            failed += 1;
        }
    }

    // 12. Default — zero value via Default trait.
    {
        let i: atomic::Int64 = Default::default();
        let b: atomic::Bool = Default::default();
        let u: atomic::Uintptr = Default::default();
        if i.Load() == 0 && !b.Load() && u.Load() == 0 {
            Println!("[12] Default zero               PASS");
        } else {
            Println!("[12] Default zero               FAIL");
            failed += 1;
        }
    }

    if failed == 0 {
        Println!("ok 12/12");
        syscall::Exit(0);
    } else {
        Println!("FAIL", failed, "of 12");
        syscall::Exit(1);
    }
}
