// Debug feature flags — runtime-toggleable knobs for narrowing
// the source of multi-M select! deadlocks (M17b-δ investigation).
//
// All flags default to ON (current behavior). Set via env var:
//
//   GOISH_RUNNEXT=0          chan/sync-waker fastpath uses runq tail
//   GOISH_STEAL_RUNNEXT=0    work-stealing never grabs target's runnext
//   GOISH_WORK_STEALING=0    steal_work returns None unconditionally
//   GOISH_COOP_PREEMPT=0     spin::cooperative_preempt_check is a no-op
//   GOISH_ASYNC_PREEMPT=0    sysmon force-preempt scan is skipped
//
// Values "0", "false", "off" disable the flag; anything else (or
// unset) leaves it enabled.
//
// Wiring: __goish_rt0 calls init_from_argv before any goroutine code,
// computing envp from argv per the SysV ELF stack layout
// (envp = argv + argc + 1).

use core::sync::atomic::{AtomicBool, Ordering};

pub static RUNNEXT_FASTPATH: AtomicBool = AtomicBool::new(true);
pub static STEAL_RUNNEXT: AtomicBool = AtomicBool::new(true);
pub static WORK_STEALING: AtomicBool = AtomicBool::new(true);
pub static COOP_PREEMPT: AtomicBool = AtomicBool::new(true);
pub static ASYNC_PREEMPT: AtomicBool = AtomicBool::new(true);

/// Parse env vars from kernel-supplied stack and update flags.
///
/// Safety: argc/argv must be the same values passed to __goish_rt0
/// from the _start asm stub, so envp_start = argv + argc + 1 is a
/// valid pointer per Linux ELF auxv layout.
pub unsafe fn init_from_argv(argc: i32, argv: *const *const u8) {
    if argv.is_null() {
        return;
    }
    let envp_start = argv.add(argc as usize + 1);
    let mut i: usize = 0;
    loop {
        let entry = *envp_start.add(i);
        if entry.is_null() {
            break;
        }
        match_entry(entry);
        i += 1;
        // Safety bound: kernel envp is bounded; cap at 4096 entries
        // to avoid runaway scan if pointer is malformed.
        if i > 4096 {
            break;
        }
    }
}

unsafe fn match_entry(entry: *const u8) {
    const PREFIX: &[u8] = b"GOISH_";
    if !starts_with(entry, PREFIX) {
        return;
    }
    let after = entry.add(PREFIX.len());
    let mut j: usize = 0;
    loop {
        let b = *after.add(j);
        if b == b'=' || b == 0 {
            break;
        }
        j += 1;
        if j > 64 {
            return;
        }
    }
    if *after.add(j) != b'=' {
        return;
    }
    let name = core::slice::from_raw_parts(after, j);
    let value_start = after.add(j + 1);
    let mut k: usize = 0;
    while *value_start.add(k) != 0 {
        k += 1;
        if k > 64 {
            break;
        }
    }
    let value = core::slice::from_raw_parts(value_start, k);
    let on = !matches!(value, b"0" | b"false" | b"off" | b"FALSE" | b"OFF");
    set_flag(name, on);
}

unsafe fn set_flag(name: &[u8], on: bool) {
    let target = match name {
        b"RUNNEXT" => &RUNNEXT_FASTPATH,
        b"STEAL_RUNNEXT" => &STEAL_RUNNEXT,
        b"WORK_STEALING" => &WORK_STEALING,
        b"COOP_PREEMPT" => &COOP_PREEMPT,
        b"ASYNC_PREEMPT" => &ASYNC_PREEMPT,
        _ => return,
    };
    target.store(on, Ordering::Relaxed);
}

unsafe fn starts_with(s: *const u8, prefix: &[u8]) -> bool {
    let mut i: usize = 0;
    while i < prefix.len() {
        if *s.add(i) != prefix[i] {
            return false;
        }
        i += 1;
    }
    true
}

/// Print the active flag values to stderr. Useful when debugging
/// to confirm which configuration a stress run used.
pub fn dump_to_stderr() {
    let banner = b"goish flags: ";
    crate::syscall::Write(crate::syscall::STDERR, banner.as_ptr(), banner.len());
    write_one(b"RUNNEXT=", &RUNNEXT_FASTPATH);
    write_one(b" STEAL_RUNNEXT=", &STEAL_RUNNEXT);
    write_one(b" WORK_STEALING=", &WORK_STEALING);
    write_one(b" COOP_PREEMPT=", &COOP_PREEMPT);
    write_one(b" ASYNC_PREEMPT=", &ASYNC_PREEMPT);
    let nl = b"\n";
    crate::syscall::Write(crate::syscall::STDERR, nl.as_ptr(), 1);
}

fn write_one(label: &[u8], flag: &AtomicBool) {
    crate::syscall::Write(crate::syscall::STDERR, label.as_ptr(), label.len());
    let v: &[u8] = if flag.load(Ordering::Relaxed) {
        b"1"
    } else {
        b"0"
    };
    crate::syscall::Write(crate::syscall::STDERR, v.as_ptr(), v.len());
}
