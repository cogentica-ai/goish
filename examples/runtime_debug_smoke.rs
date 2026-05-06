// runtime_debug_smoke — exercise the runtime/debug package.
// Mirrors Go's runtime/debug API. Covers: Stack, PrintStack,
// SetGCPercent, FreeOSMemory, SetMaxStack, SetMaxThreads,
// SetPanicOnFault, SetMemoryLimit, GCStats, ReadGCStats,
// SetTraceback, ReadBuildInfo.

#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

use goish::runtime::debug;
use goish::types::int;
use goish::{syscall, Println};

#[goish::main]
fn main() {
    let mut failed = 0;

    // 1. Stack returns a non-empty placeholder string.
    {
        let s = debug::Stack();
        let raw: &[goish::types::byte] = &s;
        let txt = goish::string::from_bytes(raw);
        let needle: goish::string = "stack trace".into();
        if raw.len() > 0 && goish::strings::Contains(txt.clone(), needle) {
            Println!("[ 1] Stack non-empty            PASS");
        } else {
            Println!("[ 1] Stack non-empty            FAIL got=", txt);
            failed += 1;
        }
    }

    // 2. SetGCPercent — first call returns the default (100), second
    //    call returns the previous value we just set.
    {
        let prev1 = debug::SetGCPercent(50);
        let prev2 = debug::SetGCPercent(75);
        // Restore default for cleanliness.
        let _ = debug::SetGCPercent(100);
        if prev1 == 100 && prev2 == 50 {
            Println!("[ 2] SetGCPercent round-trip    PASS");
        } else {
            Println!("[ 2] SetGCPercent round-trip    FAIL");
            failed += 1;
        }
    }

    // 3. FreeOSMemory — no-op, just check it doesn't panic.
    {
        debug::FreeOSMemory();
        Println!("[ 3] FreeOSMemory                PASS");
    }

    // 4. SetMaxStack — round-trip.
    {
        let prev1 = debug::SetMaxStack(1 << 20);
        let prev2 = debug::SetMaxStack(2 << 20);
        let _ = debug::SetMaxStack(1 << 30); // restore default
        if prev1 == (1 << 30) && prev2 == (1 << 20) {
            Println!("[ 4] SetMaxStack round-trip     PASS");
        } else {
            Println!("[ 4] SetMaxStack round-trip     FAIL");
            failed += 1;
        }
    }

    // 5. SetMaxThreads — round-trip.
    {
        let prev1 = debug::SetMaxThreads(500);
        let prev2 = debug::SetMaxThreads(1000);
        let _ = debug::SetMaxThreads(10_000); // restore default
        if prev1 == 10_000 && prev2 == 500 {
            Println!("[ 5] SetMaxThreads round-trip   PASS");
        } else {
            Println!("[ 5] SetMaxThreads round-trip   FAIL");
            failed += 1;
        }
    }

    // 6. SetPanicOnFault — round-trip.
    {
        let prev1 = debug::SetPanicOnFault(true);
        let prev2 = debug::SetPanicOnFault(false);
        if prev1 == false && prev2 == true {
            Println!("[ 6] SetPanicOnFault round-trip PASS");
        } else {
            Println!("[ 6] SetPanicOnFault round-trip FAIL");
            failed += 1;
        }
    }

    // 7. SetMemoryLimit — non-negative round-trip; negative reads.
    {
        let default = debug::SetMemoryLimit(-1); // read default (i64::MAX)
        let prev1 = debug::SetMemoryLimit(1 << 30);
        let read_back = debug::SetMemoryLimit(-1);
        let _ = debug::SetMemoryLimit(default); // restore
        if default == i64::MAX && prev1 == i64::MAX && read_back == (1 << 30) {
            Println!("[ 7] SetMemoryLimit             PASS");
        } else {
            Println!("[ 7] SetMemoryLimit             FAIL");
            failed += 1;
        }
    }

    // 8. SetTraceback — accepts a string, no-op.
    {
        debug::SetTraceback("all");
        debug::SetTraceback("system");
        Println!("[ 8] SetTraceback                PASS");
    }

    // 9. GCStats / ReadGCStats — fills with zeros (slim port).
    {
        let mut s = debug::GCStats::new();
        debug::ReadGCStats(&mut s);
        let pause_total_ns = s.PauseTotal.Nanoseconds();
        if s.NumGC == 0
            && pause_total_ns == 0
            && s.Pause.len() == 0
            && s.PauseEnd.len() == 0
            && s.PauseQuantiles.len() == 0
        {
            Println!("[ 9] ReadGCStats zero-fill      PASS");
        } else {
            Println!("[ 9] ReadGCStats zero-fill      FAIL");
            failed += 1;
        }
    }

    // 10. ReadBuildInfo — slim returns (zero, false).
    {
        let (_info, ok) = debug::ReadBuildInfo();
        if !ok {
            Println!("[10] ReadBuildInfo no-info     PASS");
        } else {
            Println!("[10] ReadBuildInfo no-info     FAIL");
            failed += 1;
        }
    }

    // 11. ReadGCStats with PauseQuantiles buffer — gets zeroed.
    {
        let mut s = debug::GCStats::new();
        // Pre-populate with five non-zero placeholders.
        let mut q: alloc::vec::Vec<goish::time::Duration> = alloc::vec::Vec::new();
        for _ in 0..5 {
            q.push(goish::time::Duration(42));
        }
        s.PauseQuantiles = goish::slice::__from_vec(q);
        debug::ReadGCStats(&mut s);
        let q = &s.PauseQuantiles;
        let mut all_zero = q.len() == 5;
        for i in 0..q.len() {
            if q[i as int].Nanoseconds() != 0 {
                all_zero = false;
                break;
            }
        }
        if all_zero {
            Println!("[11] PauseQuantiles zeroed     PASS");
        } else {
            Println!("[11] PauseQuantiles zeroed     FAIL");
            failed += 1;
        }
    }

    // 12. SetCrashOutput — accepts placeholder, returns nil.
    {
        let opts = debug::CrashOptions::default();
        let err = debug::SetCrashOutput((), opts);
        if err.IsNil() {
            Println!("[12] SetCrashOutput nil-err    PASS");
        } else {
            Println!("[12] SetCrashOutput nil-err    FAIL");
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
