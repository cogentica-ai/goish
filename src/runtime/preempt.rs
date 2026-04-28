// runtime::preempt — asynchronous preemption via SIGURG (M18b-α).
//
// Phase C — full injection. The SIGURG handler installs a kernel-
// level pushCall on the user G's `ucontext`, redirecting it through
// `goish_async_preempt` (asm trampoline). The trampoline saves all
// caller-saved GPRs/XMMs/flags, calls `goish_async_preempt2` (Rust),
// which yields the G via the cooperative scheduler. When the G is
// later resumed, control returns into the trampoline epilogue, which
// restores everything and `jmp`s back to the user's original PC —
// without writing to the user's red zone (`[SP_user-128, SP_user)`),
// because the trampoline's first instruction shifts SP below it.
//
// ─── Pipeline (Go's runtime/preempt.go + signal_unix.go +
//     signal_amd64.go) ─────────────────────────────────────────────
//
//   1. Sender (sysmon, or in tests a goroutine) issues
//      `tgkill`/`kill` with SIGURG.
//   2. Kernel saves the full register set into `ucontext_t` and
//      enters `goish_preempt_sigtramp` (SA_SIGINFO).
//   3. Handler runs the canPreemptM-equivalent predicates
//      (`isAsyncSafePoint` from preempt.go:363):
//        a. m.locks == 0
//        b. PC ∉ trampoline range
//        c. M.curg = Some(g)
//        d. g.status = Running
//        e. SP ∈ [g.stack.lo + ASYNC_PREEMPT_STACK, g.stack.top)
//   4. If all pass: stash user PC into `MStorage.preempt_resume_pc`,
//      set `ucontext.RIP = goish_async_preempt`, set `ucontext.RSP =
//      RSP - 8`. (Equivalent to Go's `pushCall` (signal_amd64.go:80)
//      but without writing the resume PC to user memory — we keep it
//      in per-M scratch so the user's red zone is fully preserved.)
//   5. Sigreturn → trampoline → `goish_async_preempt2` (yields) → on
//      resume, trampoline epilogue restores user state and `jmp`s
//      back to `MStorage.preempt_resume_pc`.
//
// ─── Why a separate handler from `os::signal::goish_sigtramp`? ─
//
// `os::signal::Notify` uses a single-arg handler that bumps a
// counter and wakes sysmon. It is intentionally minimal — async-
// signal-safe with no lock-free reads of M state. The preempt path
// needs three-arg `SA_SIGINFO` so it can inspect and modify the
// saved register set in `ucontext`. Keeping the two paths separate
// avoids overloading the established os::signal handler shape.

use core::arch::naked_asm;
use core::sync::atomic::{AtomicU64, Ordering};

use crate::runtime::sched::{
    current_g, current_m, current_m_locks, current_m_storage, goready, gopark,
    GStatus, MStorage, ParkCommit,
};
use crate::syscall;

// ─── ucontext_t layout (Linux x86_64) ──────────────────────────────
//
// Mirrors `/usr/include/x86_64-linux-gnu/sys/ucontext.h` and the
// kernel's `arch/x86/include/uapi/asm/sigcontext.h`. We define only
// the prefix we read/write; the trailing sigset/fpregs storage is
// represented as opaque padding.
//
// Cross-checked against Go's `runtime/defs_linux_amd64.go`:
//   - `type stackt`  ↔ `StackT` here
//   - `type sigcontext` (inline `gregs[23]` etc.) ↔ `McontextT`
//   - `type ucontext` ↔ `UcontextT`
//
// Field order is load-bearing — the kernel writes specific offsets.

#[repr(C)]
pub struct StackT {
    pub ss_sp: *mut u8,
    pub ss_flags: i32,
    _pad0: i32,
    pub ss_size: usize,
}

/// `mcontext_t` — saved register state pushed by the kernel on
/// signal entry. `gregs` is a 23-element array of `u64`; indices are
/// the `REG_*` constants below.
#[repr(C)]
pub struct McontextT {
    pub gregs: [u64; 23],
    pub fpregs: usize,
    pub _reserved: [u64; 8],
}

/// `ucontext_t` — the third argument to a SA_SIGINFO handler.
#[repr(C)]
pub struct UcontextT {
    pub uc_flags: u64,
    pub uc_link: *mut UcontextT,
    pub uc_stack: StackT,
    pub uc_mcontext: McontextT,
    // uc_sigmask + fpregs storage follow but we don't read or write
    // them; the kernel allocated the full struct, only the offsets
    // we touch matter.
}

// Linux x86_64 register indices in `gregs[]`. Matches
// arch/x86/include/uapi/asm/sigcontext.h enums.
pub const REG_R8: usize = 0;
pub const REG_R9: usize = 1;
pub const REG_R10: usize = 2;
pub const REG_R11: usize = 3;
pub const REG_R12: usize = 4;
pub const REG_R13: usize = 5;
pub const REG_R14: usize = 6;
pub const REG_R15: usize = 7;
pub const REG_RDI: usize = 8;
pub const REG_RSI: usize = 9;
pub const REG_RBP: usize = 10;
pub const REG_RBX: usize = 11;
pub const REG_RDX: usize = 12;
pub const REG_RAX: usize = 13;
pub const REG_RCX: usize = 14;
pub const REG_RSP: usize = 15;
pub const REG_RIP: usize = 16;
pub const REG_EFL: usize = 17;

/// Stack budget the trampoline needs below the kernel-saved RSP:
///   128 (red-zone skip) + 8 (saved BP) + 8 (saved FLAGS)
///   + 384 (GPR+XMM save area + alignment slack)
///   + 8 (call return) + ~256 (Rust frame margin)
/// Round up generously; a 64 KiB G stack has plenty of headroom.
pub const ASYNC_PREEMPT_STACK: usize = 1024;

// `goish_async_preempt_end` — a symbol the trampoline's naked_asm
// block emits immediately after the final `jmp`. Used to compute
// the trampoline's *exact* PC range for `is_in_trampoline`. Without
// this, a fixed-size bound would catch unrelated text under LTO
// (functions sharing the same `.text` section).
extern "C" {
    fn goish_async_preempt_end();
    fn goish_swap_context_end();
}

// ─── Diagnostic counters ───────────────────────────────────────────
//
// All `Relaxed` — the test only needs an eventual snapshot, and the
// signal handler runs on the same thread that produced the writes,
// so happens-before is implicit on x86 anyway.

static PREEMPT_INVOCATIONS: AtomicU64 = AtomicU64::new(0);
static PREEMPT_INJECTIONS: AtomicU64 = AtomicU64::new(0);
static SKIP_LOCKS: AtomicU64 = AtomicU64::new(0);
static SKIP_TRAMPOLINE: AtomicU64 = AtomicU64::new(0);
static SKIP_PARKING: AtomicU64 = AtomicU64::new(0);
static SKIP_NO_CURG: AtomicU64 = AtomicU64::new(0);
static SKIP_NOT_RUNNING: AtomicU64 = AtomicU64::new(0);
static SKIP_SP_RANGE: AtomicU64 = AtomicU64::new(0);

/// Total handler invocations since process start.
pub fn invocations() -> u64 {
    PREEMPT_INVOCATIONS.load(Ordering::Relaxed)
}

/// Times the handler injected an asyncPreempt call. Each injection
/// causes the targeted G to yield via `goish_async_preempt2`.
pub fn injections() -> u64 {
    PREEMPT_INJECTIONS.load(Ordering::Relaxed)
}

/// Per-skip-reason counts. Order:
/// (locks, trampoline, parking, no_curg, not_running, sp_range).
pub fn skip_breakdown() -> (u64, u64, u64, u64, u64, u64) {
    (
        SKIP_LOCKS.load(Ordering::Relaxed),
        SKIP_TRAMPOLINE.load(Ordering::Relaxed),
        SKIP_PARKING.load(Ordering::Relaxed),
        SKIP_NO_CURG.load(Ordering::Relaxed),
        SKIP_NOT_RUNNING.load(Ordering::Relaxed),
        SKIP_SP_RANGE.load(Ordering::Relaxed),
    )
}

// ─── is_in_trampoline ──────────────────────────────────────────────

#[inline]
fn is_in_trampoline(pc: u64) -> bool {
    let start = goish_async_preempt as usize as u64;
    let end = goish_async_preempt_end as usize as u64;
    pc >= start && pc < end
}

/// True when the saved RIP falls inside `swap_context`'s asm. We
/// must skip injection in this window — between the final
/// `mov rsp, [rsi+0x00]` and `ret`, RSP points at the *target* G's
/// stack but the user PC hasn't yet been popped, so an injection
/// would resume the trampoline on a half-switched context and
/// crash on a stale return address. Mirrors the role of Go's
/// PCDATA_UnsafePoint marking on `runtime/asm_amd64.s:gogo`.
#[inline]
fn is_in_swap_context(pc: u64) -> bool {
    let start = crate::runtime::sched::swap_context as usize as u64;
    let end = goish_swap_context_end as usize as u64;
    pc >= start && pc < end
}

// ─── async_preempt2: the Rust half ─────────────────────────────────
//
// Called by the trampoline after the full register set is on-stack.
// Runs on the user G's stack (we're between the kernel-injected
// pushCall and the user's pre-SIGURG PC). `acquirem` makes the M
// non-preemptible while we manipulate scheduler state and hold
// SpinLocks; `releasem` is paired *before* `swap_context` so the
// counter is balanced on the same M (mirrors Go's gopark in
// proc.go:419).
//
// The yield mechanism is `gopark(preempt_park_commit, …)` rather
// than `Gosched`: gopark + commit-fn lets the M release locks (none
// here) post-swap on g0, and the G stays in `Waiting` until
// `preempt_park_commit` immediately re-makes it Runnable via
// `goready`. This matches Go's `gopreempt_m` (proc.go:4332) →
// `goschedImpl(gp, true)` step shape — a yield that the *scheduler*
// (not the parker) marks runnable so other Ms can dispatch it.

/// gopark commit fn for async preempt — re-readies the G immediately
/// so it goes back into the runq for the next dispatch. Returns
/// true (commit park) so dispatch_one_g leaves the M to find more
/// work; the matching `goready` puts the G on a tail-of-queue runq
/// slot. Mirrors Go's `goschedImpl(gp, true)` (proc.go:4283).
#[inline(never)]
#[link_section = "goish_rt_text"]
unsafe fn preempt_park_commit(g_ptr: core::ptr::NonNull<crate::runtime::sched::G>) -> bool {
    // Push back onto the runq so any M can pick it up. We're on g0;
    // the parker is still claimed by this M's slot which dispatch_one_g
    // is about to clear via dropg-equivalent.
    goready(g_ptr);
    true
}

#[no_mangle]
#[inline(never)]
#[link_section = "goish_rt_text"]
extern "C" fn goish_async_preempt2() {
    // From this point through the matching `locks.fetch_sub` below,
    // the SIGURG handler's `m.locks > 0` predicate filters THIS M
    // out of preemption.
    //
    // **Migration-safe bookkeeping**. `gopark` below may resume on
    // a *different* M because `preempt_park_commit` `goready`s the
    // G into the local P's runnext, where another P's M can steal
    // it on the last steal-try (p.rs:`runqgrab` `steal_runnext_g`).
    // Using `acquirem()` / `releasem()` (which read
    // `current_m_storage()`) would land the increment on M_a but
    // the decrement on M_b — leaving M_a.locks permanently +1 and
    // M_b.locks underflowed. Both Ms then appear "always locked"
    // to the SIGURG handler and the cooperative-preempt check,
    // killing future preemption on those Ms.
    //
    // Capture the originating MStorage and operate on its `locks`
    // field directly, so the matching decrement always lands on
    // the same M as the increment regardless of which M dispatches
    // the resumed G.
    let storage = current_m_storage();
    storage.locks.fetch_add(1, Ordering::Relaxed);
    let _ = current_g();
    gopark(preempt_park_commit as ParkCommit, core::ptr::null());
    storage.locks.fetch_sub(1, Ordering::Relaxed);
}

// ─── goish_async_preempt: the asm trampoline ───────────────────────
//
// Entry: %rsp = SP_user - 8, %rip = trampoline. Kernel-set, by
// `goish_preempt_sigtramp`'s ucontext writes.
//
// Stack layout, top-to-bottom (each row 8 bytes unless noted):
//
//     [SP_user]                                ← %rsp at jmp back
//     [SP_user-8]    user's original byte      ← %rsp at entry
//     [SP_user-128]  ↘ user red-zone untouched (no writes here)
//     [SP_user-136]  user_rax snapshot         ← rsp after sub $128
//     [SP_user-144]  resume_pc snapshot        ← rsp after push fs:[…]
//     [SP_user-152]  saved BP                  ← rsp after pushq rbp
//     [SP_user-160]  saved FLAGS               ← rsp after pushfq
//     ...            384 bytes save area + ≤16 align slack
//     [save_top..save_top+368]  GPR (0..104) + XMM (112..352)
//     [save_top - 8] return PC for async_preempt2 call
//
// **Per-call snapshots on the G stack (load-bearing for cross-park
// safety).** The handler writes `MStorage.preempt_resume_pc` before
// every injection, but that slot is per-M and gets overwritten by
// each subsequent preempt that lands on the same worker thread.
// Without snapshotting, this sequence corrupts the resume PC:
//
//     1. G₁ preempted. Handler stores G₁'s PC in fs:[resume_pc].
//     2. G₁ yields in `async_preempt2 → gopark`. M dispatches G₂.
//     3. G₂ preempted. Handler **overwrites** fs:[resume_pc] with G₂'s PC.
//     4. G₂'s trampoline jmps to G₂'s PC (correct — last write wins).
//     5. M re-dispatches G₁. async_preempt2 returns to trampoline.
//     6. Trampoline jmps to fs:[resume_pc] = G₂'s PC, **not G₁'s**.
//
// The fix is to snapshot `fs:[resume_pc]` at trampoline ENTRY (the
// `push qword fs:[…]` below) onto G₁'s stack. Subsequent preempts'
// per-M writes don't disturb the per-call snapshot. The matching
// `jmp qword ptr [rsp - 144]` at the epilogue reads from the snapshot
// location relative to the post-teardown RSP, which is `SP_user`.
//
// Same scheme for `preempt_rax_save`: snapshotted to the G-stack
// scratch slot at `[SP_user-136]` before the save-area teardown.
//
// Calling convention: `extern "C"` so `call` semantics match SysV.
// Naked: no Rust prologue/epilogue.

#[unsafe(naked)]
#[no_mangle]
pub unsafe extern "C" fn goish_async_preempt() {
    naked_asm!(
        // ── Prologue ──
        // Step 1: shift SP below the user's red zone (`[SP_user-128,
        // SP_user)`). Anything we push from here on lives strictly
        // below the red zone, leaving leaf-fn locals untouched.
        "sub rsp, 128",                              // rsp = SP_user-136

        // Step 2: snapshot the per-M `preempt_resume_pc` slot onto
        // the G's stack BEFORE any other action that could yield
        // (which would let another preempt overwrite the per-M
        // slot). After this push, our resume PC lives at a
        // per-call-private location (`[SP_user-144]`) that no
        // subsequent preempt can clobber.
        "push qword ptr fs:[{resume_pc_offset}]",    // [SP_user-144] = resume_pc snapshot

        // Step 3: standard frame pointer.
        "push rbp",                                  // [SP_user-152] = user BP
        "mov rbp, rsp",                              // rbp = SP_user-152 — frame anchor

        // Step 4: save flags (so we can restore EFLAGS exactly).
        "pushfq",                                    // [SP_user-160] = flags

        // Step 5: 384-byte save area + 16-byte alignment for the
        // SysV `call` below (RSP%16 must be 0 immediately before
        // CALL; `andq $-16` rounds down).
        "sub rsp, 384",
        "and rsp, -16",

        // Step 6: save 14 GPRs (rax,rcx,rdx,rbx,rsi,rdi,r8-r15) at
        // offsets 0..104 (RBP and RSP are not in the save area —
        // RBP is on stack via pushq, RSP is implicit).
        "mov [rsp + 0],   rax",
        "mov [rsp + 8],   rcx",
        "mov [rsp + 16],  rdx",
        "mov [rsp + 24],  rbx",
        "mov [rsp + 32],  rsi",
        "mov [rsp + 40],  rdi",
        "mov [rsp + 48],  r8",
        "mov [rsp + 56],  r9",
        "mov [rsp + 64],  r10",
        "mov [rsp + 72],  r11",
        "mov [rsp + 80],  r12",
        "mov [rsp + 88],  r13",
        "mov [rsp + 96],  r14",
        "mov [rsp + 104], r15",

        // Step 7: save 16 XMMs at offsets 112..352.
        "movups [rsp + 112], xmm0",
        "movups [rsp + 128], xmm1",
        "movups [rsp + 144], xmm2",
        "movups [rsp + 160], xmm3",
        "movups [rsp + 176], xmm4",
        "movups [rsp + 192], xmm5",
        "movups [rsp + 208], xmm6",
        "movups [rsp + 224], xmm7",
        "movups [rsp + 240], xmm8",
        "movups [rsp + 256], xmm9",
        "movups [rsp + 272], xmm10",
        "movups [rsp + 288], xmm11",
        "movups [rsp + 304], xmm12",
        "movups [rsp + 320], xmm13",
        "movups [rsp + 336], xmm14",
        "movups [rsp + 352], xmm15",

        // ── Body ──
        // async_preempt2 manages m.locks (acquirem at entry,
        // releasem before gopark's swap_context). The trampoline's
        // own PC range is filtered by `is_in_trampoline(PC)` in the
        // handler, covering the prologue/epilogue windows where
        // m.locks could be 0.
        "call {async_preempt2}",

        // ── Epilogue ──
        // Snapshot user_rax (currently in save area at [rsp+0]) to
        // a frame-local scratch slot at [rbp+16] = [SP_user-136].
        // This slot is below the red zone and above the saved BP,
        // so it survives the save-area teardown without race.
        "mov rax, [rsp + 0]",
        "mov [rbp + 16], rax",

        // Restore the other GPRs (rax stays as scratch).
        "mov rcx, [rsp + 8]",
        "mov rdx, [rsp + 16]",
        "mov rbx, [rsp + 24]",
        "mov rsi, [rsp + 32]",
        "mov rdi, [rsp + 40]",
        "mov r8,  [rsp + 48]",
        "mov r9,  [rsp + 56]",
        "mov r10, [rsp + 64]",
        "mov r11, [rsp + 72]",
        "mov r12, [rsp + 80]",
        "mov r13, [rsp + 88]",
        "mov r14, [rsp + 96]",
        "mov r15, [rsp + 104]",

        // Restore XMMs.
        "movups xmm0,  [rsp + 112]",
        "movups xmm1,  [rsp + 128]",
        "movups xmm2,  [rsp + 144]",
        "movups xmm3,  [rsp + 160]",
        "movups xmm4,  [rsp + 176]",
        "movups xmm5,  [rsp + 192]",
        "movups xmm6,  [rsp + 208]",
        "movups xmm7,  [rsp + 224]",
        "movups xmm8,  [rsp + 240]",
        "movups xmm9,  [rsp + 256]",
        "movups xmm10, [rsp + 272]",
        "movups xmm11, [rsp + 288]",
        "movups xmm12, [rsp + 304]",
        "movups xmm13, [rsp + 320]",
        "movups xmm14, [rsp + 336]",
        "movups xmm15, [rsp + 352]",

        // Tear down: rbp anchors us regardless of how the andq
        // alignment shifted RSP.
        "lea rsp, [rbp - 8]",                        // popfq slot at [SP_user-160]
        "popfq",                                     // rsp = SP_user-152
        "pop rbp",                                   // restore user BP, rsp = SP_user-144 (= resume_pc snapshot slot)

        // Discard the resume_pc snapshot slot (we'll read it via
        // memory operand below).
        "add rsp, 8",                                // rsp = SP_user-136 (= user_rax snapshot slot)

        // Restore user's rax from the snapshot.
        "mov rax, [rsp]",                            // rax = user_rax

        // Walk rsp up to user's pre-SIGURG SP. We never wrote into
        // [SP_user-128, SP_user) (red zone) — only read at the very
        // end via the [rsp - 144] absolute jmp operand below.
        "add rsp, 128",                              // rsp = SP_user-8
        "add rsp, 8",                                // rsp = SP_user

        // Jump via memory: [rsp - 144] = [SP_user - 144] = the
        // resume_pc snapshot we wrote at trampoline entry. The slot
        // is below the red zone so reading it is benign for the
        // user's stack invariants.
        "jmp qword ptr [rsp - 144]",

        // Emit a global end-of-trampoline label inline so
        // `is_in_trampoline` can compute the exact PC range. `int3`
        // ensures any errant fall-through traps loudly.
        ".globl goish_async_preempt_end",
        "goish_async_preempt_end:",
        "int3",

        async_preempt2 = sym goish_async_preempt2,
        resume_pc_offset = const core::mem::offset_of!(MStorage, preempt_resume_pc),
    )
}

// ─── Handler ───────────────────────────────────────────────────────
//
// SA_SIGINFO calling convention: `(int sig, siginfo_t *info, void *ctx)`.
// `ctx` is `ucontext_t *`. Runs on the kernel-supplied signal stack
// (default: user's current SP minus the 128-byte red zone minus the
// signal frame). For goroutines on 64 KiB stacks this is fine.
//
// **Allowed operations** (all async-signal-safe):
//   - lock-free atomic loads/stores (counters, m.locks)
//   - reading the M's struct via `data_unchecked()` (Theorem 1
//     applies: at L=0 no concurrent write is in flight)
//   - reading G.status, G.stack metadata
//   - writing to per-M scratch slots in MStorage (preempt_resume_pc)
//   - writing to ucontext.gregs (kernel-allocated, single-thread)
//
// **Forbidden** (would deadlock or violate AS-safety):
//   - SpinLock acquisition (`current_m().lock()`, etc.)
//   - heap allocation
//   - any `gopark` / `swap_context` (handler is *not* the trampoline)

extern "C" fn goish_preempt_sigtramp(
    _sig: i32,
    _info: *const u8,
    ctx: *mut UcontextT,
) {
    PREEMPT_INVOCATIONS.fetch_add(1, Ordering::Relaxed);

    // 1. m.locks == 0
    if current_m_locks() != 0 {
        SKIP_LOCKS.fetch_add(1, Ordering::Relaxed);
        return;
    }

    let pc = unsafe { (*ctx).uc_mcontext.gregs[REG_RIP] };

    // 2. PC ∉ trampoline range AND PC ∉ swap_context range. Both
    // are runtime asm windows where m.locks == 0 but injection
    // would corrupt scheduler state.
    if is_in_trampoline(pc) || is_in_swap_context(pc) {
        SKIP_TRAMPOLINE.fetch_add(1, Ordering::Relaxed);
        return;
    }

    // 2b. PC ∈ goish runtime text section. Mirrors Go's
    // `name.HasPrefix("runtime.")` filter (preempt.go:420). Runtime
    // functions have brief windows where `m.locks == 0` but the
    // scheduler / lock primitive / wake-protocol state is
    // half-mutated; injecting there yields the G with that state
    // visible to other Ms, causing corruption (SEGV) or stuck
    // wakeups (hang). The cooperative path catches these Gs at the
    // next `raw_unlock` safe point — no forward-progress loss.
    if crate::runtime::rt_section::is_in_runtime(pc) {
        crate::runtime::rt_section::SKIP_RUNTIME_PC
            .fetch_add(1, Ordering::Relaxed);
        return;
    }

    // 3. M has a current G — lock-free read justified by Theorem 1
    // (m.locks == 0 ⟹ no concurrent write to current_g).
    let m = unsafe { current_m().data_unchecked() };
    let g_ptr = match m.current_g {
        Some(p) => p,
        None => {
            SKIP_NO_CURG.fetch_add(1, Ordering::Relaxed);
            return;
        }
    };

    // 4. The G is not mid-park. `gopark` sets `M.waitunlockf` (and
    // `M.waitlock`) under `m.locks > 0`, then drops the lock and
    // calls `releasem` *before* `swap_context` (Go-style discipline,
    // proc.go:419). The window between `releasem` and the
    // `swap_context` asm is precisely when `m.locks == 0` while the
    // M is committed to a park — injecting a preempt here would
    // overwrite the parker's commit fn and either deadlock the chan
    // it was supposed to release or corrupt scheduler state.
    //
    // `waitunlockf` is `Option<ParkCommit>` (8-byte fn pointer with
    // niche), naturally aligned, written only under `m.locks > 0`.
    // At `m.locks == 0` (already gated above) the read is stable.
    if m.waitunlockf.is_some() {
        SKIP_PARKING.fetch_add(1, Ordering::Relaxed);
        return;
    }

    // 5. G.status == Running
    let g_ref = unsafe { g_ptr.as_ref() };
    if g_ref.status != GStatus::Running {
        SKIP_NOT_RUNNING.fetch_add(1, Ordering::Relaxed);
        return;
    }

    // 6. SP ∈ [stack.lo + ASYNC_PREEMPT_STACK, stack.top)
    let sp = unsafe { (*ctx).uc_mcontext.gregs[REG_RSP] } as usize;
    let stack_lo = g_ref.stack.base();
    let stack_hi = g_ref.stack.top();
    if sp < stack_lo + ASYNC_PREEMPT_STACK || sp >= stack_hi {
        SKIP_SP_RANGE.fetch_add(1, Ordering::Relaxed);
        return;
    }

    // ── Inject ──
    //
    // Stash user PC for the trampoline epilogue's `jmp qword ptr
    // fs:[resume_pc_offset]`. Then point ucontext at the trampoline
    // and shift RSP down by 8 — exactly Go's `pushCall` shape
    // (signal_amd64.go:80) but with the resume PC carried in MStorage
    // rather than on the user's stack, so we don't write to the red
    // zone and don't depend on `-C no-redzone`.
    let storage = current_m_storage();
    unsafe {
        *storage.preempt_resume_pc.get() = pc;
        (*ctx).uc_mcontext.gregs[REG_RSP] = (sp - 8) as u64;
        (*ctx).uc_mcontext.gregs[REG_RIP] = goish_async_preempt as u64;
    }

    // Clear the cooperative-preempt flag (M18b-β/γ): we're about to
    // honor the request asynchronously, so the next safe-point check
    // doesn't need to fire again. Sysmon will re-set it on its next
    // tick if the G is still hogging the M.
    g_ref.preempt.store(false, Ordering::Release);

    PREEMPT_INJECTIONS.fetch_add(1, Ordering::Relaxed);
}

// ─── Install ───────────────────────────────────────────────────────

/// Install the SIGURG preempt handler. Idempotent. Called from
/// `__goish_rt0` after sysmon has started.
///
/// Uses SA_SIGINFO so the kernel passes `(sig, info, ctx)` and we
/// can reach `ucontext`. SA_RESTORER + the existing
/// `SigreturnTrampoline` complete the kernel's mandated sigreturn
/// path.
pub fn install() {
    let sa = syscall::Sigaction {
        sa_handler: goish_preempt_sigtramp as usize,
        sa_flags: syscall::SA_SIGINFO | syscall::SA_RESTORER | syscall::SA_RESTART,
        sa_restorer: syscall::SigreturnTrampoline as usize,
        sa_mask: 0,
    };
    unsafe {
        let r = syscall::RtSigaction(syscall::SIGURG, &sa as *const _, core::ptr::null_mut());
        if r != 0 {
            const MSG: &[u8] = b"goish: preempt: rt_sigaction(SIGURG) failed\n";
            syscall::Write(syscall::STDERR, MSG.as_ptr(), MSG.len());
            syscall::Exit(2);
        }
    }
}
