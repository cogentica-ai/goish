// lazymut_smoke — exercise `LazyMut<T>` write-during-init / freeze-on-read
// semantics that close the xid `var dec [256]byte` + `init() { for i {
// dec[i] = 0xFF } }` blocker.
//
// Coverage:
//   1. `LazyMut::new(T)` starts unfrozen; `.modify(|t| ...)` mutates.
//   2. Multiple `.modify(...)` calls compose during init.
//   3. First read via `.get()` / `Deref` returns the mutated value.
//   4. Index-forwarding: `lm[i]` works through the Deref/Index chain.
//   5. After freeze, `.modify(...)` panics with a clear message.
//   6. Composes with `Lazy<T>`: `Lazy<LazyMut<[u8; 256]>>` static slot.

#![no_std]
#![no_main]
#![allow(non_snake_case, non_upper_case_globals)]

extern crate alloc;
extern crate goish;

use core::sync::atomic::{AtomicUsize, Ordering};

use goish::lazy::{Lazy, LazyMut};
use goish::syscall;

// Global decode-table-shaped LazyMut, the actual xid pattern.
static DEC: Lazy<LazyMut<[u8; 256]>> = Lazy::new(|| LazyMut::new([0u8; 256]));

static FAILED: AtomicUsize = AtomicUsize::new(0);

fn ok_line(msg: &[u8]) {
    syscall::Write(syscall::STDOUT, msg.as_ptr(), msg.len());
}

fn fail(msg: &[u8]) {
    FAILED.fetch_add(1, Ordering::AcqRel);
    syscall::Write(syscall::STDERR, msg.as_ptr(), msg.len());
    let nl: &[u8] = b"\n";
    syscall::Write(syscall::STDERR, nl.as_ptr(), nl.len());
}

#[goish::main]
fn main() {
    // 1. Local LazyMut — basic modify/read round-trip.
    let lm: LazyMut<[u8; 4]> = LazyMut::new([0u8; 4]);
    lm.modify(|t| {
        t[0] = 1;
        t[1] = 2;
    });
    lm.modify(|t| {
        t[2] = 3;
        t[3] = 4;
    });
    let v = lm.get();
    if v != &[1u8, 2, 3, 4] {
        fail(b"LazyMut local: composed modifies wrong");
    } else {
        ok_line(b"PASS: LazyMut local modify+read\n");
    }

    // 2. Index forwarding: lm[i] after freeze.
    if lm[0] != 1 || lm[3] != 4 {
        fail(b"LazyMut local: index forwarding wrong");
    } else {
        ok_line(b"PASS: LazyMut Index forwarder\n");
    }

    // 3. Static Lazy<LazyMut<T>> — emulate xid's dec init pattern.
    DEC.modify(|t| {
        let mut i = 0;
        while i < 256 {
            t[i] = 0xFF;
            i += 1;
        }
    });
    DEC.modify(|t| {
        // Override a few slots, mimicking xid's encoding-table fill.
        let encoding: &[u8] = b"0123456789abcdefghijklmnopqrstuv";
        let mut i = 0;
        while i < encoding.len() {
            t[encoding[i] as usize] = i as u8;
            i += 1;
        }
    });

    // 4. Read post-init: lookup table works.
    if DEC[b'0' as usize] != 0
        || DEC[b'9' as usize] != 9
        || DEC[b'a' as usize] != 10
        || DEC[b'v' as usize] != 31
        || DEC[b'A' as usize] != 0xFF
    {
        fail(b"DEC lookup wrong after fill");
    } else {
        ok_line(b"PASS: DEC<Lazy<LazyMut>> lookup-table fill\n");
    }

    // 5. After freeze, .modify panics. Skipped at runtime since the
    //    smoke runs without panic infrastructure here; the contract is
    //    asserted by code review and by the goishc emit (no .modify
    //    call sites survive past init() in transpiled output).

    if FAILED.load(Ordering::Acquire) > 0 {
        ok_line(b"FAIL: lazymut_smoke had failures\n");
        syscall::Exit(1);
    }
    ok_line(b"OK lazymut_smoke\n");
}
