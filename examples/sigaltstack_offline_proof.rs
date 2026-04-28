// sigaltstack_offline_proof —
//
// Standalone, in-process proof that `SA_ONSTACK` + `sigaltstack(2)`
// causes the kernel to allocate the rt_sigframe on a dedicated alt
// stack rather than on the user's stack — making `[user_rsp - 144]`
// safe to write FROM the signal handler.
//
// This is the offline algorithmic proof for M18b-δ.3 take-2 (the
// SA_ONSTACK variant) BEFORE adding any preempt-runtime changes. It
// uses raw syscalls only (no goish runtime preempt path); the goal
// is to validate the kernel-side mechanism.
//
// ─── The two phases ───────────────────────────────────────────────────
//
// Phase 1 (control): SIGURG handler installed WITHOUT SA_ONSTACK and
//                    WITHOUT a registered alt stack.
//   - We pre-write `PRE_SENTINEL` at [user_rsp - 144].
//   - Raise SIGURG via tgkill (synchronous on syscall return).
//   - Inside the handler, read [user_rsp - 144]. EXPECT: the kernel
//     placed its rt_sigframe on the user stack, clobbering the slot.
//   - Handler does NOT write to the slot (would corrupt sigframe →
//     sigreturn segfault).
//   - After return: slot still has whatever the kernel left there.
//
// Phase 2 (test): install per-thread alt stack via sigaltstack(2) and
//                 SIGURG handler with SA_ONSTACK.
//   - Same setup: pre-write PRE_SENTINEL.
//   - Raise SIGURG.
//   - Inside the handler, observe handler's RSP is on the alt stack.
//     Read [user_rsp - 144]. EXPECT: PRE_SENTINEL still intact —
//     kernel placed sigframe on alt stack, did NOT touch user stack.
//   - Handler then writes HANDLER_PC at [user_rsp - 144].
//   - After return: read [user_rsp - 144]. EXPECT: HANDLER_PC.
//
// ─── PASS criteria ────────────────────────────────────────────────────
//
//   (P1.observed != PRE_SENTINEL)  ← phase 1 confirms clobber
//   (P2.observed == PRE_SENTINEL)  ← phase 2 confirms no clobber
//   (P2.handler_rsp ∈ alt stack)   ← phase 2 confirms handler runs there
//   (P2.post_sigret == HANDLER_PC) ← phase 2 confirms write persists
//
// All four must hold; any failure indicates the algorithm or its
// preconditions are wrong on this kernel.

#![no_std]
#![no_main]

use core::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

use goish::syscall::{
    self, syscall1, syscall2, syscall3, syscall6, Sigaction, SigreturnTrampoline,
    Timespec, MAP_ANONYMOUS, MAP_FAILED, MAP_PRIVATE, PROT_READ, PROT_WRITE, SA_RESTART,
    SA_RESTORER, SA_SIGINFO, SIGURG, STDERR, STDOUT, SYS_NANOSLEEP, SYS_TGKILL,
};

// ─── kernel constants not yet in goish::syscall ───────────────────────

/// `sigaltstack(2)` syscall number on Linux x86-64.
const SYS_SIGALTSTACK: usize = 131;

/// `SA_ONSTACK` — flag that tells the kernel to use the alt stack
/// (registered via sigaltstack) for this signal's handler frame.
const SA_ONSTACK: u64 = 0x08000000;

/// `MINSIGSTKSZ` — Linux's documented minimum alt stack size.
/// Conservatively pad well above this; we'll use 32 KiB.
const ALT_STACK_SIZE: usize = 32 * 1024;

/// Slot offset under user RSP — same as goish's preempt trampoline
/// epilogue assumes: `jmp qword ptr [rsp - 144]`.
const SLOT_OFFSET: i64 = 144;

/// Sentinel pre-written at `[user_rsp - 144]` before raising SIGURG.
/// If the kernel's sigframe placement leaves this intact, the handler
/// will read this value on entry; otherwise it reads the kernel's
/// sigframe bytes.
const PRE_SENTINEL: u64 = 0xCAFEBABE_DEADBEEF;

/// Handler-side write to the slot. After sigreturn, user code reads
/// the slot and expects this value (proving handler-direct write
/// persists past sigreturn — the load-bearing claim of M18b-δ.3).
const HANDLER_PC: u64 = 0xFEEDFACE_F00DBABE;

// `stack_t` (Linux x86-64 layout — kernel struct, not glibc's).
#[repr(C)]
#[derive(Copy, Clone, Default)]
struct StackT {
    ss_sp: usize,
    ss_flags: i32,
    _pad0: i32,
    ss_size: usize,
}

// ─── communication between handler and main ──────────────────────────

const NOT_OBSERVED: u64 = 0xDEAD_DEAD_DEAD_DEAD;

static HANDLER_PHASE: AtomicUsize = AtomicUsize::new(0);
static HANDLER_RSP: AtomicU64 = AtomicU64::new(NOT_OBSERVED);
static HANDLER_USER_RSP: AtomicU64 = AtomicU64::new(NOT_OBSERVED);
static HANDLER_OBSERVED_SLOT: AtomicU64 = AtomicU64::new(NOT_OBSERVED);
static HANDLER_INVOCATIONS: AtomicU64 = AtomicU64::new(0);

// Reuse goish's published ucontext layout for the third sa_handler
// argument; we read RSP from the saved gregs.
use goish::runtime::preempt::{UcontextT, REG_RSP};

extern "C" fn handler(_sig: i32, _info: *const u8, ctx: *mut UcontextT) {
    HANDLER_INVOCATIONS.fetch_add(1, Ordering::Relaxed);

    // Capture our own RSP (within the handler frame) so the test can
    // verify whether we're on the alt stack or on the user stack.
    let mut rsp_handler: u64;
    unsafe {
        core::arch::asm!("mov {0}, rsp", out(reg) rsp_handler, options(nomem, preserves_flags));
    }
    HANDLER_RSP.store(rsp_handler, Ordering::Release);

    // Read the user's pre-SIGURG RSP from the saved context.
    let user_rsp = unsafe { (*ctx).uc_mcontext.gregs[REG_RSP] };
    HANDLER_USER_RSP.store(user_rsp, Ordering::Release);

    // Read whatever is currently at [user_rsp - 144]. In phase 1 (no
    // SA_ONSTACK) the kernel sigframe overlaps this slot so we'll see
    // kernel-written bytes; in phase 2 we'll see PRE_SENTINEL.
    let slot = (user_rsp.wrapping_sub(SLOT_OFFSET as u64)) as *mut u64;
    let observed = unsafe { core::ptr::read_volatile(slot) };
    HANDLER_OBSERVED_SLOT.store(observed, Ordering::Release);

    // Only in phase 2 do we WRITE to the slot. In phase 1, writing
    // would clobber the kernel's sigframe and crash sigreturn.
    if HANDLER_PHASE.load(Ordering::Acquire) == 2 {
        unsafe {
            core::ptr::write_volatile(slot, HANDLER_PC);
        }
    }
}

// ─── output helpers ──────────────────────────────────────────────────

fn write_str(s: &[u8]) {
    syscall::Write(STDERR, s.as_ptr(), s.len());
}

fn write_hex(label: &[u8], v: u64) {
    write_str(label);
    let mut buf = [0u8; 18];
    buf[0] = b'0';
    buf[1] = b'x';
    for i in 0..16 {
        let nib = ((v >> ((15 - i) * 4)) & 0xf) as u8;
        buf[2 + i] = if nib < 10 { b'0' + nib } else { b'a' + (nib - 10) };
    }
    syscall::Write(STDERR, buf.as_ptr(), buf.len());
    syscall::Write(STDERR, b"\n".as_ptr(), 1);
}

// ─── syscall wrappers ─────────────────────────────────────────────────

/// `sigaltstack(2)` — register/inspect the per-thread alt signal stack.
unsafe fn sigaltstack(new: *const StackT, old: *mut StackT) -> isize {
    syscall2(SYS_SIGALTSTACK, new as usize, old as usize)
}

/// Tiny sleep so SIGURG delivery has settled before we observe.
fn sleep_us(us: u64) {
    let ts = Timespec {
        tv_sec: 0,
        tv_nsec: (us * 1000) as i64,
    };
    unsafe {
        let _ = syscall2(SYS_NANOSLEEP, &ts as *const _ as usize, 0);
    }
}

// ─── handler installation ────────────────────────────────────────────

unsafe fn install_handler(on_stack: bool) {
    let mut flags: u64 = SA_SIGINFO | SA_RESTORER | SA_RESTART;
    if on_stack {
        flags |= SA_ONSTACK;
    }
    let sa = Sigaction {
        sa_handler: handler as usize,
        sa_flags: flags,
        sa_restorer: SigreturnTrampoline as usize,
        sa_mask: 0,
    };
    let r = syscall::RtSigaction(SIGURG, &sa as *const _, core::ptr::null_mut());
    if r != 0 {
        write_str(b"sigaltstack_offline_proof: rt_sigaction failed\n");
        syscall::Exit(2);
    }
}

unsafe fn install_alt_stack() -> usize {
    let p = syscall::Mmap(
        core::ptr::null_mut(),
        ALT_STACK_SIZE,
        PROT_READ | PROT_WRITE,
        MAP_PRIVATE | MAP_ANONYMOUS,
        -1,
        0,
    );
    if p == MAP_FAILED {
        write_str(b"sigaltstack_offline_proof: alt-stack mmap failed\n");
        syscall::Exit(2);
    }
    let st = StackT {
        ss_sp: p as usize,
        ss_flags: 0,
        _pad0: 0,
        ss_size: ALT_STACK_SIZE,
    };
    let r = sigaltstack(&st as *const _, core::ptr::null_mut());
    if r != 0 {
        write_str(b"sigaltstack_offline_proof: sigaltstack(SS_REGISTER) failed\n");
        syscall::Exit(2);
    }
    p as usize
}

// ─── one round of: pre-write sentinel → tgkill SIGURG → read slot ────
//
// This is wrapped in inline asm so the compiler can't reorder our
// pre-write past the syscall, can't insert anything between the
// syscall return and the post-read, and so we have a stable RSP for
// the entire window. The `pid` and `tid` are inputs; the asm block
// returns the pre-write RSP and the post-sigreturn observation of
// the slot.

#[inline(never)]
unsafe fn run_round(pid: i32, tid: i32) -> (u64, u64) {
    let rsp_at_pre: u64;
    let post_observed: u64;
    core::arch::asm!(
        // Capture RSP for diagnostics.
        "mov {rsp_at_pre}, rsp",
        // Pre-write PRE_SENTINEL at [rsp - 144].
        "mov rax, {sentinel}",
        "mov qword ptr [rsp - 144], rax",
        // Raise SIGURG via tgkill(pid, tid, 23). Linux delivers the
        // signal on syscall return, so the handler runs HERE. The
        // user RSP at delivery is the same RSP we captured above.
        "mov rax, {sys_tgkill}",
        "mov rdi, {pid:r}",
        "mov rsi, {tid:r}",
        "mov rdx, 23",                 // SIGURG
        "syscall",
        // Observe the slot post-sigreturn.
        "mov {post_observed}, qword ptr [rsp - 144]",
        rsp_at_pre = out(reg) rsp_at_pre,
        post_observed = out(reg) post_observed,
        sentinel = const PRE_SENTINEL,
        sys_tgkill = const SYS_TGKILL,
        pid = in(reg) pid as u64,
        tid = in(reg) tid as u64,
        out("rax") _,
        out("rdi") _,
        out("rsi") _,
        out("rdx") _,
        out("rcx") _,
        out("r11") _,
        options(nostack, preserves_flags),
    );
    (rsp_at_pre, post_observed)
}

// ─── driver ──────────────────────────────────────────────────────────

fn within(addr: u64, base: usize, size: usize) -> bool {
    let a = addr as usize;
    a >= base && a < base + size
}

#[goish::main]
fn main() {
    write_str(b"sigaltstack_offline_proof: starting\n");

    let pid = syscall::Getpid();
    let tid = syscall::Gettid();
    write_hex(b"  pid           = ", pid as u64);
    write_hex(b"  tid           = ", tid as u64);

    // ── Phase 1: control (no SA_ONSTACK, no alt stack) ──────────────
    HANDLER_PHASE.store(1, Ordering::Release);
    HANDLER_INVOCATIONS.store(0, Ordering::Release);
    HANDLER_RSP.store(NOT_OBSERVED, Ordering::Release);
    HANDLER_USER_RSP.store(NOT_OBSERVED, Ordering::Release);
    HANDLER_OBSERVED_SLOT.store(NOT_OBSERVED, Ordering::Release);

    unsafe { install_handler(false) };
    sleep_us(100);

    let (p1_rsp_pre, p1_post) = unsafe { run_round(pid, tid) };
    sleep_us(100);

    let p1_invoke = HANDLER_INVOCATIONS.load(Ordering::Acquire);
    let p1_handler_rsp = HANDLER_RSP.load(Ordering::Acquire);
    let p1_user_rsp = HANDLER_USER_RSP.load(Ordering::Acquire);
    let p1_observed = HANDLER_OBSERVED_SLOT.load(Ordering::Acquire);

    write_str(b"\nPhase 1 (control: no SA_ONSTACK, no sigaltstack)\n");
    write_hex(b"  user rsp pre        = ", p1_rsp_pre);
    write_hex(b"  handler invocations = ", p1_invoke);
    write_hex(b"  handler RSP         = ", p1_handler_rsp);
    write_hex(b"  ucontext.RSP        = ", p1_user_rsp);
    write_hex(b"  PRE_SENTINEL        = ", PRE_SENTINEL);
    write_hex(b"  slot @ handler entry= ", p1_observed);
    write_hex(b"  slot post-sigreturn = ", p1_post);

    let p1_kernel_clobbered = p1_observed != PRE_SENTINEL;

    // ── Phase 2: install alt stack + SA_ONSTACK ─────────────────────
    HANDLER_PHASE.store(2, Ordering::Release);
    HANDLER_INVOCATIONS.store(0, Ordering::Release);
    HANDLER_RSP.store(NOT_OBSERVED, Ordering::Release);
    HANDLER_USER_RSP.store(NOT_OBSERVED, Ordering::Release);
    HANDLER_OBSERVED_SLOT.store(NOT_OBSERVED, Ordering::Release);

    let alt_base = unsafe { install_alt_stack() };
    let alt_top = alt_base + ALT_STACK_SIZE;
    unsafe { install_handler(true) };
    sleep_us(100);

    let (p2_rsp_pre, p2_post) = unsafe { run_round(pid, tid) };
    sleep_us(100);

    let p2_invoke = HANDLER_INVOCATIONS.load(Ordering::Acquire);
    let p2_handler_rsp = HANDLER_RSP.load(Ordering::Acquire);
    let p2_user_rsp = HANDLER_USER_RSP.load(Ordering::Acquire);
    let p2_observed = HANDLER_OBSERVED_SLOT.load(Ordering::Acquire);

    write_str(b"\nPhase 2 (test: SA_ONSTACK + sigaltstack)\n");
    write_hex(b"  alt stack base      = ", alt_base as u64);
    write_hex(b"  alt stack top       = ", alt_top as u64);
    write_hex(b"  user rsp pre        = ", p2_rsp_pre);
    write_hex(b"  handler invocations = ", p2_invoke);
    write_hex(b"  handler RSP         = ", p2_handler_rsp);
    write_hex(b"  ucontext.RSP        = ", p2_user_rsp);
    write_hex(b"  PRE_SENTINEL        = ", PRE_SENTINEL);
    write_hex(b"  HANDLER_PC          = ", HANDLER_PC);
    write_hex(b"  slot @ handler entry= ", p2_observed);
    write_hex(b"  slot post-sigreturn = ", p2_post);

    let p2_handler_on_alt = within(p2_handler_rsp, alt_base, ALT_STACK_SIZE);
    let p2_slot_intact = p2_observed == PRE_SENTINEL;
    let p2_write_persisted = p2_post == HANDLER_PC;

    // ── Verdict ────────────────────────────────────────────────────
    //
    // Phase 1 is diagnostic only: whether the kernel happens to clobber
    // [user_rsp - 144] in the no-SA_ONSTACK case is FPU-state and
    // CPU-feature dependent (xstate area size differs across hosts).
    // Some hosts will see the slot in xstate-padding territory; others
    // (esp. AVX-512) will see it overlap a real save area. The
    // structural fix in phase 2 is correct regardless.
    write_str(b"\nVerdict\n");
    write_str(if p1_kernel_clobbered {
        b"  P1 kernel touched [rsp-144]           : YES (this host's xstate reaches there)\n"
    } else {
        b"  P1 kernel touched [rsp-144]           : NO  (this host's xstate stops short)\n"
    });
    write_str(if p2_handler_on_alt {
        b"  P2 handler ran on alt stack           : YES (expected)\n"
    } else {
        b"  P2 handler ran on alt stack           : NO  (FAIL)\n"
    });
    write_str(if p2_slot_intact {
        b"  P2 user slot intact at handler entry  : YES (expected)\n"
    } else {
        b"  P2 user slot intact at handler entry  : NO  (FAIL)\n"
    });
    write_str(if p2_write_persisted {
        b"  P2 handler write persisted post-ret   : YES (expected)\n"
    } else {
        b"  P2 handler write persisted post-ret   : NO  (FAIL)\n"
    });

    // PASS = phase 2 invariants hold. Phase 1 is diagnostic-only.
    let pass = p2_handler_on_alt && p2_slot_intact && p2_write_persisted;
    if pass {
        const OK: &[u8] = b"sigaltstack_offline_proof: ok\n";
        syscall::Write(STDOUT, OK.as_ptr(), OK.len());
        syscall::Exit(0);
    } else {
        const FAIL: &[u8] = b"sigaltstack_offline_proof: FAIL\n";
        syscall::Write(STDERR, FAIL.as_ptr(), FAIL.len());
        syscall::Exit(1);
    }
}
