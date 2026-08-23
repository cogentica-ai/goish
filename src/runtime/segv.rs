// runtime::segv — SIGSEGV handler for stack-overflow diagnostics.
//
// Without this handler, a goroutine that exhausts its stack dies with
// a silent "Segmentation fault (core dumped)" — the user has no way
// to tell *which* `go!()` site needs `stack(N)` or `maybe_grow_step`.
//
// This handler classifies the fault by checking `siginfo.si_addr`
// against the running G's stack bounds (and any grown regions in the
// growth chain). When the address falls within a page of any stack
// region, the handler prints a diagnostic identifying the spawn site
// and exits with code 2. Genuine memory bugs unrelated to a stack
// region chain to the default handler so the user still gets a core
// dump.
//
// All handler logic is async-signal-safe:
//   - runs on the per-M alt signal stack (SA_ONSTACK + sigaltstack,
//     installed by `runtime::sched::m::install_signal_stack`)
//   - no heap allocation
//   - no SpinLock / Mutex
//   - the spawn-site side table is a fixed-size open-addressed hash
//     table whose access path is plain atomics
//
// Companion design note: DISCUSSION_SEGFAULT_REPORT.md.

use core::sync::atomic::{AtomicU32, AtomicUsize, Ordering};

use crate::runtime::preempt::{UcontextT, REG_RBP, REG_RIP, REG_RSP};
use crate::runtime::sched::G;
use crate::syscall;

const PAGE: usize = 4096;

// ─── Spawn-site side table ────────────────────────────────────────────
//
// 4096 slots × 32 B = 128 KiB BSS. Open-addressed; linear probing on
// collision. If the table fills, new spawns silently drop their entry
// and the diagnostic falls back to "<unknown spawn site>".

const SPAWN_TABLE_SIZE: usize = 4096;
const SPAWN_TABLE_MASK: usize = SPAWN_TABLE_SIZE - 1;

#[repr(C, align(32))]
struct SpawnSlot {
    g_ptr: AtomicUsize,
    file_ptr: AtomicUsize,
    file_len: AtomicUsize,
    line: AtomicU32,
    _pad: u32,
}

const SLOT_INIT: SpawnSlot = SpawnSlot {
    g_ptr: AtomicUsize::new(0),
    file_ptr: AtomicUsize::new(0),
    file_len: AtomicUsize::new(0),
    line: AtomicU32::new(0),
    _pad: 0,
};

static SPAWN_TABLE: [SpawnSlot; SPAWN_TABLE_SIZE] = [SLOT_INIT; SPAWN_TABLE_SIZE];

#[inline]
fn hash_g(g_addr: usize) -> usize {
    // Strip the low alignment bits (G is at least 8-byte aligned, and
    // Box::leak spaces them by sizeof(G)) before mixing.
    let x = (g_addr >> 5) as u64;
    let h = x.wrapping_mul(0x9E3779B97F4A7C15u64);
    (h as usize) & SPAWN_TABLE_MASK
}

/// Record that the goroutine at `g` was spawned at `file:line`.
/// Called from `newproc_at` / `newproc_with_stack_at` after the G is
/// allocated. Drops the entry silently if the table is full.
pub fn register(g: *mut G, file: &'static str, line: u32) {
    let g_addr = g as usize;
    if g_addr == 0 {
        return;
    }
    let mut probe = hash_g(g_addr);
    for _ in 0..SPAWN_TABLE_SIZE {
        let slot = &SPAWN_TABLE[probe];
        if slot
            .g_ptr
            .compare_exchange(0, g_addr, Ordering::AcqRel, Ordering::Relaxed)
            .is_ok()
        {
            slot.file_ptr
                .store(file.as_ptr() as usize, Ordering::Release);
            slot.file_len.store(file.len(), Ordering::Release);
            slot.line.store(line, Ordering::Release);
            return;
        }
        probe = (probe + 1) & SPAWN_TABLE_MASK;
    }
    // Table full: drop the entry. Diagnostic will say "<unknown>".
}

/// Drop the spawn-site entry for `g`. Called from `goexit0` so dead
/// goroutines free their slot for reuse.
pub fn unregister(g: *mut G) {
    let g_addr = g as usize;
    if g_addr == 0 {
        return;
    }
    let mut probe = hash_g(g_addr);
    for _ in 0..SPAWN_TABLE_SIZE {
        let slot = &SPAWN_TABLE[probe];
        let cur = slot.g_ptr.load(Ordering::Acquire);
        if cur == g_addr {
            slot.file_len.store(0, Ordering::Release);
            slot.file_ptr.store(0, Ordering::Release);
            slot.line.store(0, Ordering::Release);
            slot.g_ptr.store(0, Ordering::Release);
            return;
        }
        if cur == 0 {
            // Empty slot reached without finding the key — entry was
            // never registered (table-full at register time) or has
            // already been removed.
            return;
        }
        probe = (probe + 1) & SPAWN_TABLE_MASK;
    }
}

/// Look up the spawn site for `g`. Async-signal-safe — only loads.
pub(crate) fn lookup(g: *mut G) -> Option<(&'static str, u32)> {
    let g_addr = g as usize;
    let mut probe = hash_g(g_addr);
    for _ in 0..SPAWN_TABLE_SIZE {
        let slot = &SPAWN_TABLE[probe];
        let cur = slot.g_ptr.load(Ordering::Acquire);
        if cur == g_addr {
            let ptr = slot.file_ptr.load(Ordering::Acquire);
            let len = slot.file_len.load(Ordering::Acquire);
            let line = slot.line.load(Ordering::Acquire);
            if ptr == 0 || len == 0 {
                return None;
            }
            // SAFETY: `register` was called with a `&'static str` from
            // `file!()` — the underlying bytes live in the binary's
            // rodata section for the program's lifetime.
            let s = unsafe {
                core::str::from_utf8_unchecked(core::slice::from_raw_parts(ptr as *const u8, len))
            };
            return Some((s, line));
        }
        if cur == 0 {
            return None;
        }
        probe = (probe + 1) & SPAWN_TABLE_MASK;
    }
    None
}

// ─── Async-signal-safe writers ────────────────────────────────────────

#[inline]
fn write_str(s: &[u8]) {
    syscall::Write(syscall::STDERR, s.as_ptr(), s.len());
}

fn write_hex(value: u64) {
    let mut buf = [b'0'; 18];
    buf[0] = b'0';
    buf[1] = b'x';
    let mut v = value;
    for i in (2..18).rev() {
        let nib = (v & 0xf) as u8;
        buf[i] = if nib < 10 {
            b'0' + nib
        } else {
            b'a' + nib - 10
        };
        v >>= 4;
    }
    write_str(&buf);
}

fn write_dec(value: u64) {
    if value == 0 {
        write_str(b"0");
        return;
    }
    let mut buf = [0u8; 20];
    let mut i = buf.len();
    let mut v = value;
    while v > 0 {
        i -= 1;
        buf[i] = b'0' + (v % 10) as u8;
        v /= 10;
    }
    write_str(&buf[i..]);
}

// ─── Classification ───────────────────────────────────────────────────

#[derive(Clone, Copy)]
enum Region {
    HomeOverflow { lo: usize, hi: usize },
    GrownOverflow { lo: usize, hi: usize },
    Unrelated,
}

fn classify(g: &G, fault_addr: usize) -> Region {
    let home_lo = g.stack.base();
    let home_hi = g.stack.top();

    // Home-stack overflow: fault address sits below `home_lo` but
    // within a page (the slot just below the bottom is what an
    // overflowing prologue / push would touch).
    if fault_addr < home_lo && home_lo - fault_addr <= PAGE {
        return Region::HomeOverflow {
            lo: home_lo,
            hi: home_hi,
        };
    }
    // Defensive: also catch the case where the runtime computes
    // `[rsp - N]` and lands a few bytes above `home_lo`. This happens
    // when the fault precedes the SP descent but the access is
    // already outside the live stack window.
    if fault_addr >= home_lo && fault_addr < home_lo + 32 {
        return Region::HomeOverflow {
            lo: home_lo,
            hi: home_hi,
        };
    }

    // Grown regions still attached to the G via the growth chain.
    let chain_ptr = g.growth_chain.load(Ordering::Acquire);
    if !chain_ptr.is_null() {
        let chain = unsafe { &*chain_ptr };
        for (base, size) in chain.regions.iter() {
            let lo = *base as usize;
            let hi = lo + *size;
            if fault_addr < lo && lo - fault_addr <= PAGE {
                return Region::GrownOverflow { lo, hi };
            }
            if fault_addr >= lo && fault_addr < lo + 32 {
                return Region::GrownOverflow { lo, hi };
            }
        }
    }

    // Active region (a `maybe_grow_step` pivot in flight whose region
    // is scope-bound and not yet on the chain).
    let active_lo = g.active_stack_lo.load(Ordering::Acquire);
    let active_hi = g.active_stack_hi.load(Ordering::Acquire);
    if active_lo != 0 && active_lo != home_lo {
        if fault_addr < active_lo && active_lo - fault_addr <= PAGE {
            return Region::GrownOverflow {
                lo: active_lo,
                hi: active_hi,
            };
        }
        if fault_addr >= active_lo && fault_addr < active_lo + 32 {
            return Region::GrownOverflow {
                lo: active_lo,
                hi: active_hi,
            };
        }
    }

    Region::Unrelated
}

// ─── Frame-pointer walk ───────────────────────────────────────────────
//
// With `-C force-frame-pointers=yes` (set in `.cargo/config.toml`),
// every function emits the SysV prologue `push rbp; mov rbp, rsp`.
// Each saved frame thus has the layout:
//
//   [rbp + 0]  → caller's saved RBP
//   [rbp + 8]  → caller's return PC (the address the next ret will jump to)
//
// Walking the chain is just `rbp = *rbp` until the value leaves the
// active stack region (or hits zero). We collect up to MAX_FRAMES PCs
// into a fixed array — no allocation, async-signal-safe.
//
// Bounds: every dereference is gated against `[stack_lo, stack_hi)`.
// A bogus RBP (uninitialised, smashed, or a leaf fn that didn't set
// up a frame) terminates the walk cleanly instead of double-faulting.

pub(crate) const MAX_FRAMES: usize = 32;

pub(crate) fn walk_frames(
    initial_rbp: u64,
    stack_lo: usize,
    stack_hi: usize,
    out: &mut [u64; MAX_FRAMES],
) -> usize {
    let mut rbp = initial_rbp as usize;
    let mut count = 0;
    while count < MAX_FRAMES {
        // Each frame needs 16 bytes ([rbp+0] saved RBP, [rbp+8] PC).
        // Reject frames that would read past the stack top, are below
        // the stack bottom, or aren't 8-byte aligned.
        if rbp == 0 || rbp < stack_lo || rbp + 16 > stack_hi || (rbp & 0x7) != 0 {
            break;
        }
        let saved_rbp = unsafe { (rbp as *const u64).read() };
        let saved_pc = unsafe { ((rbp + 8) as *const u64).read() };
        if saved_pc == 0 {
            break;
        }
        out[count] = saved_pc;
        count += 1;
        // Caller's RBP must climb (deeper-up = higher address) and stay
        // inside the same stack region.
        let next = saved_rbp as usize;
        if next <= rbp {
            break;
        }
        rbp = next;
    }
    count
}

// ─── Handler ──────────────────────────────────────────────────────────

extern "C" fn goish_segv_sigtramp(_sig: i32, info: *const u8, ctx: *mut UcontextT) {
    // `siginfo_t` for SIGSEGV (Linux x86_64): si_signo (4) + si_errno
    // (4) + si_code (4) + _pad (4) + 8-byte-aligned _sifields union;
    // for `_sigfault` the first member is `void *si_addr` at offset
    // 16. See `include/uapi/asm-generic/siginfo.h`.
    let fault_addr = unsafe { (info.add(16) as *const usize).read() };

    // Lock-free curg read via the per-M storage. The bootstrap thread
    // (and very early init) has no `curg` — chain to default so the
    // user gets the genuine SEGV behavior.
    let g_opt = unsafe { crate::runtime::sched::current_m().data_unchecked().curg };
    let g_ptr = match g_opt {
        Some(g) => g,
        None => return chain_to_default(),
    };
    let g = unsafe { g_ptr.as_ref() };

    let region = classify(g, fault_addr);
    if matches!(region, Region::Unrelated) {
        return chain_to_default();
    }

    let saved_rip = unsafe { (*ctx).uc_mcontext.gregs[REG_RIP] };
    let saved_rsp = unsafe { (*ctx).uc_mcontext.gregs[REG_RSP] };
    let saved_rbp = unsafe { (*ctx).uc_mcontext.gregs[REG_RBP] };

    // Frame-pointer walk. Bound to the region the fault came from so a
    // smashed RBP can't lead us out of the active stack.
    let (walk_lo, walk_hi) = match region {
        Region::HomeOverflow { lo, hi } => (lo, hi),
        Region::GrownOverflow { lo, hi } => (lo, hi),
        Region::Unrelated => (0, 0),
    };
    let mut frames = [0u64; MAX_FRAMES];
    let n = if walk_hi > walk_lo {
        walk_frames(saved_rbp, walk_lo, walk_hi, &mut frames)
    } else {
        0
    };

    // ── Header — Go's `runtime.Stack` uses
    //   "goroutine N [STATE]:" + "<reason>"
    // We adopt the same shape, with the goish-specific reason on its
    // own banner line above so users grep'ing for "stack overflow"
    // still match.
    write_str(b"\ngoish: runtime error: stack overflow\n\n");
    write_str(b"goroutine 1 [running]:\n");

    // ── Frames — Go's per-frame format:
    //   "<qualified.fn.name>(...)\n"
    //   "\t<file>:<line> +0x<offset>\n"
    //
    // Frame #0 is the faulting PC (taken from saved RIP, not from RBP
    // chain — leaf frames may not have set up RBP yet). The rest come
    // from `walk_frames`, which yields each caller's saved RIP.
    let mut info = crate::runtime::symbolize::SymInfo::default();
    write_frame(saved_rip, &mut info);
    let mut i = 0;
    while i < n {
        write_frame(frames[i], &mut info);
        i += 1;
    }
    if n == 0 {
        write_str(b"\t(no frames recovered - RBP chain unavailable)\n");
    }

    // ── Trailer — overflow-specific context Go's traceback wouldn't
    // print, but is exactly what a goish user needs to act on.
    write_str(b"\ncreated by ");
    match lookup(g_ptr.as_ptr()) {
        Some((file, line)) => {
            write_str(file.as_bytes());
            write_str(b":");
            write_dec(line as u64);
            write_str(b" (go!())\n");
        }
        None => {
            write_str(b"<unknown> (go!())\n");
        }
    }
    match region {
        Region::HomeOverflow { lo, hi } => {
            write_str(b"\tg.stack: ");
            write_hex(lo as u64);
            write_str(b"-");
            write_hex(hi as u64);
            write_str(b" (");
            write_dec((hi - lo) as u64);
            write_str(b" bytes, home)\n");
        }
        Region::GrownOverflow { lo, hi } => {
            write_str(b"\tg.stack: ");
            write_hex(lo as u64);
            write_str(b"-");
            write_hex(hi as u64);
            write_str(b" (");
            write_dec((hi - lo) as u64);
            write_str(b" bytes, grown)\n");
        }
        Region::Unrelated => {}
    }
    write_str(b"\tfault: SIGSEGV at ");
    write_hex(fault_addr as u64);
    write_str(b" (PC=");
    write_hex(saved_rip);
    write_str(b" SP=");
    write_hex(saved_rsp);
    write_str(b")\n");
    write_str(b"\nremedy:\n");
    write_str(b"\tbump the spawn-site stack:    go!(stack(4 * MB), || ...)\n");
    write_str(b"\tor raise all bare-go stacks:  runtime::debug::SetMaxStack(64 * MB)\n");
    write_str(
        b"\tor wrap the recursion site:   runtime::sched::maybe_grow(64 * KB, 4 * MB, || ...)\n",
    );

    syscall::Exit(2);
}

/// Emit one stack frame in Go's `runtime.Stack` format:
///
///   <qualified.fn.name>(...)
///   \t<file>:<line> +0x<offset>
///
/// If the symboliser can't resolve the PC, fall back to
/// `<unknown>(0xPC)` / `\t???:0`. Async-signal-safe — no allocation,
/// only writes via `syscall::Write`.
fn write_frame(pc: u64, info: &mut crate::runtime::symbolize::SymInfo) {
    let ok = crate::runtime::symbolize::symbolize(pc, info);
    if ok && info.fn_name_len > 0 {
        write_str(&info.fn_name[..info.fn_name_len]);
        write_str(b"(...)\n");
    } else {
        write_str(b"<unknown>(...)\n");
    }
    write_str(b"\t");
    if ok && info.file_len > 0 {
        write_str(&info.file[..info.file_len]);
        write_str(b":");
        write_dec(info.line as u64);
    } else {
        write_str(b"???:0");
    }
    write_str(b" +0x");
    // Fn-relative offset, 0 if symboliser missed.
    let off = if ok { info.fn_offset } else { 0 };
    write_hex_compact(off);
    write_str(b"\n");
}

/// Compact hex (no leading zeros, no `0x` prefix, lowercase). Used for
/// the `+0x<off>` suffix in Go-style frames.
fn write_hex_compact(value: u64) {
    if value == 0 {
        write_str(b"0");
        return;
    }
    let mut buf = [0u8; 16];
    let mut i = buf.len();
    let mut v = value;
    while v > 0 {
        i -= 1;
        let nib = (v & 0xf) as u8;
        buf[i] = if nib < 10 {
            b'0' + nib
        } else {
            b'a' + nib - 10
        };
        v >>= 4;
    }
    write_str(&buf[i..]);
}

#[cold]
fn chain_to_default() {
    // Reset SIGSEGV to SIG_DFL and return — the kernel will redeliver
    // the original fault from its preserved context, dumping core.
    let sa = syscall::Sigaction {
        sa_handler: 0, // SIG_DFL
        sa_flags: 0,
        sa_restorer: 0,
        sa_mask: 0,
    };
    unsafe {
        let _ = syscall::RtSigaction(syscall::SIGSEGV, &sa as *const _, core::ptr::null_mut());
    }
}

/// Install the SIGSEGV handler. Idempotent. Called once from
/// `__goish_rt0` after `preempt::install`.
pub fn install() {
    let sa = syscall::Sigaction {
        sa_handler: goish_segv_sigtramp as *const () as usize,
        sa_flags: syscall::SA_SIGINFO | syscall::SA_RESTORER | syscall::SA_ONSTACK,
        sa_restorer: syscall::SigreturnTrampoline as *const () as usize,
        sa_mask: 0,
    };
    unsafe {
        let r = syscall::RtSigaction(syscall::SIGSEGV, &sa as *const _, core::ptr::null_mut());
        if r != 0 {
            const MSG: &[u8] = b"goish: segv: rt_sigaction(SIGSEGV) failed\n";
            syscall::Write(syscall::STDERR, MSG.as_ptr(), MSG.len());
            syscall::Exit(2);
        }
    }
}
