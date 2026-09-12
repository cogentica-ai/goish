// pprof_sampler_smoke — SIGPROF sampling captures real stacks
// (issue #9).
//
// `setitimer(ITIMER_PROF)` delivers SIGPROF every period of CPU time —
// user AND system, which is why it is ITIMER_PROF and not
// ITIMER_VIRTUAL: a profile that ignored kernel time would attribute
// nothing to a syscall-heavy function.
//
// The handler walks the INTERRUPTED stack, not its own. Its RBP belongs
// to the handler frame; the profiled frame is in the ucontext the
// kernel pushed, which is why `segv::walk_frames` takes an explicit RBP.
// It also splices the interrupted PC in as frame 0, because the walk
// returns RETURN addresses — without that the innermost function is
// missing from every sample and its time lands on its caller. That is
// the one error here that would still produce a plausible profile, so
// it is what `leaf_is_burn` checks.
//
// This drives the sampler directly. `StartCPUProfile` still returns its
// unsupported error on purpose — see its doc comment: joining the
// sampler to the encoder needs an API decision about holding the
// caller's writer from Start to Stop, and issue #9 is explicit that a
// partial implementation must not emit misleading files.
//
// No row asserts an exact sample COUNT. The timer measures CPU time, so
// a loaded machine yields fewer samples for the same work — a count
// assertion would be the same kind of flake this suite has retired
// twice already. What is asserted is that sampling happened at all,
// that the period is what was asked for, and that the stacks are real.

#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

use core::sync::atomic::{AtomicUsize, Ordering};
use goish::fmt;
use goish::gostring::string;
use goish::runtime::pprof;
use goish::runtime::symbolize::{self, SymInfo};
use goish::strings;

static FAILED: AtomicUsize = AtomicUsize::new(0);

fn check(cond: bool, what: &str) {
    if cond {
        fmt::Printf!("[ok] %s\n", string::from_bytes(what.as_bytes()));
    } else {
        fmt::Printf!("[!!] %s\n", string::from_bytes(what.as_bytes()));
        FAILED.fetch_add(1, Ordering::Relaxed);
    }
}

/// Somewhere for the samples to land. `inline(never)` so it has a frame
/// of its own to be found in.
#[inline(never)]
fn burn(n: u64) -> u64 {
    let mut acc = 0u64;
    for i in 0..n {
        acc = acc.wrapping_add(i).wrapping_mul(31);
    }
    return acc;
}

fn name_of(pc: u64) -> string {
    let mut si = SymInfo::default();
    if !symbolize::symbolize(pc, &mut si) {
        return string::from_static("<unsymbolised>");
    }
    return string::from_bytes(&si.fn_name[..si.fn_name_len]);
}

#[goish::main]
fn main() {
    check(pprof::__sample_start(100), "setitimer(ITIMER_PROF) armed at 100 Hz");

    let mut acc = 0u64;
    for _ in 0..400 {
        acc = acc.wrapping_add(burn(200_000));
    }
    check(acc != 0, "the workload actually ran");

    pprof::__sample_stop();

    let taken = pprof::__taken();
    check(taken > 0, "SIGPROF fired and samples were recorded");
    check(
        pprof::__period_ns() == 10_000_000,
        "period is 10ms, as 100 Hz asks",
    );

    // The stacks must be REAL: a walker returning one frame, or frames
    // that do not symbolise, would satisfy a count check and say
    // nothing.
    let mut deep = 0usize;
    let mut leaf_below_main = 0usize;
    let mut reaches_main = 0usize;
    pprof::__for_each(|pcs| {
        if pcs.len() >= 3 {
            deep += 1;
        }
        // Frame 0 must be the INTERRUPTED pc, which is inside the hot
        // loop — never `__goish_main`, which only ever appears as a
        // return address further out. Checking "burn appears somewhere
        // near the top" is NOT enough: burn is also a return address,
        // so dropping the leaf splice leaves it within any small
        // window. Verified — that looser form passed the perturbation.
        if !pcs.is_empty() && !strings::Contains(&name_of(pcs[0]), "goish_main") {
            leaf_below_main += 1;
        }
        for pc in pcs.iter() {
            if strings::Contains(&name_of(*pc), "goish_main") {
                reaches_main += 1;
                break;
            }
        }
    });

    check(deep > 0, "captured stacks are more than one frame");
    check(
        reaches_main > 0,
        "the walk reaches __goish_main from a sampled frame",
    );
    // Every sample was taken inside burn()'s loop, so frame 0 is never
    // main: it is burn, or the iterator burn drives. Drop the leaf
    // splice and frame 0 becomes burn's RETURN address, which lives in
    // __goish_main — so this row, and only this row, catches it.
    check(
        leaf_below_main == taken,
        "frame 0 is the interrupted pc, not a return address",
    );

    // Stopping twice must be safe, and must not record more.
    pprof::__sample_stop();
    check(pprof::__taken() == taken, "a second stop records nothing new");

    let f = FAILED.load(Ordering::Relaxed);
    if f != 0 {
        fmt::Printf!("\nFAILED %d check(s)\n", f as i64);
        goish::os::Exit(1);
    }
    fmt::Printf!("\nok (%d samples)\n", taken as i64);
}
