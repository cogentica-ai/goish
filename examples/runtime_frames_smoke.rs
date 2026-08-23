// runtime_frames_smoke — runtime.CallersFrames, Frame and FuncForPC.
//
// goish already had runtime.Callers (PCs) and a full DWARF symboliser
// used by the SIGSEGV backtrace, but FuncForPC was a stub returning
// None and there was no Frames iterator — so nothing could turn a PC
// into a name. That is what gated testing's callerName, pcToName,
// frameSkip and callSite, and with them any file:line attribution on a
// test failure.
//
// The assertion that matters is check 2: the frames must name THIS
// program's functions, in call order. A symboliser that resolved
// nothing would still return the right number of frames with empty
// names, and checks 1 and 3 alone would not notice.

#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

use goish::gostring::string;
use goish::runtime::{Callers, CallersFrames, FuncForPC};
use goish::types::{int, uintptr};
use goish::{fmt, make, slice, syscall};

fn s(x: &str) -> string {
    return string::from_bytes(x.as_bytes());
}

/// Innermost of a three-deep chain, so the frame order is checkable.
#[inline(never)]
fn goish_frames_level_three(pcs: &mut slice<uintptr>) -> int {
    return Callers(0, pcs);
}

#[inline(never)]
fn goish_frames_level_two(pcs: &mut slice<uintptr>) -> int {
    let n = goish_frames_level_three(pcs);
    return core::hint::black_box(n);
}

#[inline(never)]
fn goish_frames_level_one(pcs: &mut slice<uintptr>) -> int {
    let n = goish_frames_level_two(pcs);
    return core::hint::black_box(n);
}

#[goish::main]
fn main() {
    let mut failed = 0;

    let mut pcs: slice<uintptr> = make!([]uintptr, 32);
    let n = goish_frames_level_one(&mut pcs);

    // 1. Callers filled some frames.
    {
        if n > 0 {
            fmt::Println!("[ 1] Callers returned frames   PASS");
        } else {
            fmt::Println!("[ 1] Callers returned frames   FAIL");
            failed += 1;
        }
    }

    // 2. The frames name this program's own functions, and in call
    //    order — level_three before level_two before level_one. This is
    //    the check a non-resolving symboliser fails.
    {
        let got = pcs.slice(0, n);
        let mut frames = CallersFrames(got);
        let mut seen: alloc::vec::Vec<string> = alloc::vec::Vec::new();
        loop {
            let (f, more) = frames.Next();
            if f.Function.Len() > 0 {
                seen.push(f.Function.clone());
            }
            if !more {
                break;
            }
        }
        // Find the three markers in order.
        let (mut i3, mut i2, mut i1): (i64, i64, i64) = (-1, -1, -1);
        for (i, name) in seen.iter().enumerate() {
            let nm: &str = name.as_ref();
            if i3 < 0 && nm.contains("goish_frames_level_three") {
                i3 = i as i64;
            }
            if i2 < 0 && nm.contains("goish_frames_level_two") {
                i2 = i as i64;
            }
            if i1 < 0 && nm.contains("goish_frames_level_one") {
                i1 = i as i64;
            }
        }
        if i3 >= 0 && i2 > i3 && i1 > i2 {
            fmt::Println!("[ 2] frames named, in order    PASS");
        } else {
            fmt::Println!(
                "[ 2] frames named, in order    FAIL (",
                i3,
                ",",
                i2,
                ",",
                i1,
                " of ",
                seen.len() as i64,
                ")"
            );
            for nm in seen.iter().take(6) {
                fmt::Println!("      ", nm.clone());
            }
            failed += 1;
        }
    }

    // 3. Next() reports a zero Frame and more=false once exhausted,
    //    rather than looping or panicking.
    {
        let mut frames = CallersFrames(pcs.slice(0, n));
        let mut guard = 0;
        loop {
            let (_, more) = frames.Next();
            guard += 1;
            if !more || guard > 1000 {
                break;
            }
        }
        let (f, more) = frames.Next();
        if !more && f.Function.Len() == 0 && f.PC == 0 && guard <= 1000 {
            fmt::Println!("[ 3] exhausted yields zero     PASS");
        } else {
            fmt::Println!("[ 3] exhausted yields zero     FAIL");
            failed += 1;
        }
    }

    // 4. FuncForPC resolves the same name for a PC the frames named,
    //    and returns None for an address that is not code.
    {
        let mut frames = CallersFrames(pcs.slice(0, n));
        let (first, _) = frames.Next();
        let named = match FuncForPC(first.PC) {
            Some(f) => f.Name().Len() > 0,
            None => false,
        };
        let junk = FuncForPC(1 as uintptr).is_none();
        if named && junk {
            fmt::Println!("[ 4] FuncForPC resolves        PASS");
        } else {
            fmt::Println!("[ 4] FuncForPC resolves        FAIL");
            failed += 1;
        }
    }

    // 5. File and Line are populated for a resolved frame — this is
    //    what a failure message's file:line would come from.
    {
        let mut frames = CallersFrames(pcs.slice(0, n));
        let mut ok = false;
        loop {
            let (f, more) = frames.Next();
            let fname: &str = f.File.as_ref();
            if fname.contains("runtime_frames_smoke") && f.Line > 0 {
                ok = true;
            }
            if !more {
                break;
            }
        }
        if ok {
            fmt::Println!("[ 5] file and line resolved    PASS");
        } else {
            fmt::Println!("[ 5] file and line resolved    FAIL");
            failed += 1;
        }
    }

    let _ = s("");
    if failed == 0 {
        fmt::Println!("ok 5/5");
        syscall::Exit(0);
    } else {
        fmt::Println!("FAIL", failed, "of 5");
        syscall::Exit(1);
    }
}
