// runtime::sched::gobuf — saved register set + the asm context switch.
//
// Layout of `Gobuf` (offsets are load-bearing — referenced by the
// `naked_asm!` block below):
//
//   off  field   purpose
//    0   rsp     stack pointer; the PC to resume at lives at `[rsp]`
//    8   rbp     base / frame pointer
//   16   rbx     callee-saved
//   24   r12     callee-saved
//   32   r13     callee-saved
//   40   r14     callee-saved
//   48   r15     callee-saved
//
// We don't store rip/rax/rdi/rsi/rdx/rcx/r8/r9/r10/r11 because they
// are caller-saved in SysV — Rust calling code cannot rely on them
// being preserved across a function call (which `swap_context` looks
// like, from the caller's POV), so we don't need to round-trip them.
//
// Bit-for-bit mirror of Go's gobuf for the registers that survive
// `gogo`'s "longjmp" semantics. We don't carry `g`, `ctxt`, or `lr`:
//
//   - `g` — Go uses R14 to address the current goroutine via TLS;
//     M16b will introduce a parallel mechanism, but M16a doesn't
//     need it.
//   - `ctxt` — closure context pointer, only meaningful when
//     resuming a closure (relevant once goroutines spawn closures).
//   - `lr` — link register, irrelevant on amd64.

use core::arch::naked_asm;

/// Saved register file for a suspended G. Layout matches Go's
/// `runtime.gobuf` semantically. Offsets 0x00..0x38 are the legacy
/// `swap_context` save/restore region (rsp/rbp/rbx/r12-r15) and are
/// PINNED for asm compat — `swap_context` uses literal offsets in
/// `naked_asm!`. M17b-ε β.1 adds `pc` at offset 0x38 for `gogo`'s
/// JMP-based resume; legacy `swap_context` does not touch it (it
/// resumes via RET-pops-PC-from-stack).
#[repr(C)]
#[derive(Default)]
pub struct Gobuf {
    /// Saved stack pointer. Loaded into `rsp` on resume.
    pub rsp: u64,
    /// Saved base pointer.
    pub rbp: u64,
    /// Saved callee-saved registers.
    pub rbx: u64,
    pub r12: u64,
    pub r13: u64,
    pub r14: u64,
    pub r15: u64,
    /// Saved program counter. Used by `gogo` (β.2): loaded via `JMP`
    /// to resume without a RET. `swap_context` does NOT write/read
    /// this field — its RET resumes by popping PC from `[rsp]`.
    pub pc: u64,
}

/// Field offsets — verified at compile time. Asm uses these as
/// literal constants.
pub const GOBUF_RSP: usize = 0x00;
pub const GOBUF_RBP: usize = 0x08;
pub const GOBUF_RBX: usize = 0x10;
pub const GOBUF_R12: usize = 0x18;
pub const GOBUF_R13: usize = 0x20;
pub const GOBUF_R14: usize = 0x28;
pub const GOBUF_R15: usize = 0x30;
pub const GOBUF_PC:  usize = 0x38;

const _: () = {
    assert!(core::mem::offset_of!(Gobuf, rsp) == GOBUF_RSP);
    assert!(core::mem::offset_of!(Gobuf, rbp) == GOBUF_RBP);
    assert!(core::mem::offset_of!(Gobuf, rbx) == GOBUF_RBX);
    assert!(core::mem::offset_of!(Gobuf, r12) == GOBUF_R12);
    assert!(core::mem::offset_of!(Gobuf, r13) == GOBUF_R13);
    assert!(core::mem::offset_of!(Gobuf, r14) == GOBUF_R14);
    assert!(core::mem::offset_of!(Gobuf, r15) == GOBUF_R15);
    assert!(core::mem::offset_of!(Gobuf, pc)  == GOBUF_PC);
};

impl Gobuf {
    pub const fn new() -> Self {
        Gobuf {
            rsp: 0, rbp: 0,
            rbx: 0, r12: 0, r13: 0, r14: 0, r15: 0,
            pc: 0,
        }
    }
}

/// `swap_context(from, to)` — symmetric two-context exchange.
///
/// Saves the current callee-saved register set (rsp, rbp, rbx,
/// r12-r15) into `*from`, loads `*to` into those same registers,
/// then `RET`s. Because PC lives at `[rsp]`, the RET pops the saved
/// PC from `*to`'s stack and jumps there.
///
/// Calling convention: `extern "C"` so SysV places `from` in `rdi`
/// and `to` in `rsi`. The function is naked — no Rust prologue or
/// epilogue. From Rust's perspective, calling this looks like a
/// regular `extern "C"` call that may take a long time to return,
/// since "return" can happen via a different `swap_context` call
/// from another stack.
///
/// Safety: caller must guarantee `from` and `to` point to valid
/// `Gobuf` instances and that `*to` either represents a previously
/// suspended context (saved by an earlier `swap_context`) or a
/// fresh context laid out by `make_context`. Failing these
/// preconditions corrupts the stack pointer and crashes the
/// process.
#[unsafe(naked)]
pub unsafe extern "C" fn swap_context(_from: *mut Gobuf, _to: *const Gobuf) {
    naked_asm!(
        // Save callee-saved registers into *from (rdi).
        "mov [rdi + 0x00], rsp",
        "mov [rdi + 0x08], rbp",
        "mov [rdi + 0x10], rbx",
        "mov [rdi + 0x18], r12",
        "mov [rdi + 0x20], r13",
        "mov [rdi + 0x28], r14",
        "mov [rdi + 0x30], r15",
        // Load callee-saved registers from *to (rsi). RSP last so
        // we don't disturb the rest of the load by pointing at
        // unfamiliar memory.
        "mov rbp, [rsi + 0x08]",
        "mov rbx, [rsi + 0x10]",
        "mov r12, [rsi + 0x18]",
        "mov r13, [rsi + 0x20]",
        "mov r14, [rsi + 0x28]",
        "mov r15, [rsi + 0x30]",
        "mov rsp, [rsi + 0x00]",
        // Resume target context — pops the saved PC from its
        // stack and jumps.
        "ret",
        // M18b-α phase C: mark the end of `swap_context`'s text so
        // the SIGURG preempt handler can refuse to inject when PC
        // falls anywhere inside this asm. SIGURG arriving mid-swap
        // (after `mov rsp, [rsi+0x00]` but before `ret`) would have
        // the kernel-saved RSP pointing at the *target* G's stack
        // while the target's user PC has not yet been popped — a
        // hijacked injection there would make the trampoline
        // resume at a non-PC byte and crash the worker.
        ".globl goish_swap_context_end",
        "goish_swap_context_end:",
        "int3",
    )
}

/// Set up `gobuf` so that the first `swap_context(_, gobuf)` enters
/// `entry` running on the stack `[stack_base, stack_top)`.
///
/// `stack_top` must be 16-byte aligned (mmap-page-aligned suffices).
/// The function reserves the topmost 16 bytes of the stack as the
/// initial frame:
///
///     stack_top - 8    `goexit_trampoline` address (executed if
///                       `entry` ever returns; abort for now)
///     stack_top - 16   `entry` address (popped by the first RET in
///                       `swap_context`)
///
/// After construction, `gobuf.rsp` points at `stack_top - 16`. When
/// `swap_context` loads this gobuf and executes RET, it pops `entry`
/// and jumps. The stack alignment (rsp % 16 == 8 at function entry)
/// matches the SysV convention.
///
/// Safety: caller must have allocated a writable stack
/// `[stack_base, stack_top)` of at least 32 bytes; `entry` must be
/// a valid `extern "C" fn() -> !` address.
pub unsafe fn make_context(gobuf: &mut Gobuf, stack_top: usize, entry: extern "C" fn() -> !) {
    debug_assert!(stack_top % 16 == 0, "stack_top not 16-byte aligned");

    let sp = stack_top - 16;
    // Topmost slot — return address if `entry` ever falls through.
    *((stack_top - 8) as *mut usize) = goexit_trampoline as *const () as usize;
    // Below — first PC popped by the initial RET.
    *(sp as *mut usize) = entry as usize;

    *gobuf = Gobuf::new();
    gobuf.rsp = sp as u64;
}

/// `gogo(buf)` — load `*buf` into registers and JMP to `buf.pc`.
///
/// Unlike `swap_context`, `gogo` has no save side: the caller is
/// expected to be on a context that won't be resumed (typically
/// `m.g0`'s scheduler stack, where the next iteration of `schedule()`
/// will overwrite this frame anyway).
///
/// **Why JMP, not RET.** Mirrors Go's `runtime·gogo`
/// (runtime/asm_amd64.s:404). RET would pop a PC from `[rsp]` —
/// requiring us to lay the resume PC on the target G's stack and to
/// adjust `gobuf.rsp` to point one slot below it. Under the SysV
/// red-zone rules (128 bytes below RSP are reserved scratch for the
/// resumed function), the slot we'd write would alias the target G's
/// red zone. JMP avoids that — `gobuf.pc` is loaded directly from
/// the gobuf via an indirect jump and the target's stack stays
/// untouched.
///
/// Calling convention: SysV places `buf` in `rdi`. The function is
/// naked and never returns to its caller (control transfers to
/// `buf.pc`). Used by `execute(g)` to enter the next runnable G.
///
/// Safety: caller must guarantee `buf` is a valid `Gobuf` whose `pc`
/// is a callable instruction (typically a goroutine entry or a
/// previously-saved resume point) and whose `sp` is correctly aligned
/// for the SysV ABI at that PC. Failing these preconditions crashes
/// the process.
#[unsafe(naked)]
pub unsafe extern "C" fn gogo(_buf: *const Gobuf) -> ! {
    naked_asm!(
        // Load callee-saved registers from *buf (rdi). RSP is loaded
        // last — JMP through the gobuf indirection works regardless
        // of order, but loading RSP last keeps the asm parallel to
        // `swap_context`.
        "mov rbp, [rdi + 0x08]",
        "mov rbx, [rdi + 0x10]",
        "mov r12, [rdi + 0x18]",
        "mov r13, [rdi + 0x20]",
        "mov r14, [rdi + 0x28]",
        "mov r15, [rdi + 0x30]",
        "mov rsp, [rdi + 0x00]",
        // JMP to *(buf + 0x38) — no PC popped from stack, no red
        // zone touched. Target executes with rsp == buf.sp.
        "jmp qword ptr [rdi + 0x38]",
        // M17b-ε β.2: end-marker for the SIGURG preempt handler's
        // PC-range filter. SIGURG landing inside this asm would
        // corrupt the resume.
        ".globl goish_gogo_end",
        "goish_gogo_end:",
        "int3",
    )
}

/// `mcall_asm(from, to, fn, arg)` — internal half of `mcall`.
///
/// Saves the current callee-saved registers, return PC, and SP into
/// `*from` (the caller G's gobuf). Then switches RSP to `(*to).sp`
/// (g0's stack pointer) and calls `fn(arg)`.
///
/// **Layout of the save side, parallel to Go's `runtime·mcall`
/// (asm_amd64.s:427):**
///
///   - `from.pc` = `[rsp]` at entry — the return address pushed by
///     the `call mcall_asm` instruction in the Rust wrapper.
///   - `from.sp` = `rsp + 8` at entry — the SP value the caller had
///     before the `call` (i.e., the SP a future `gogo(from)` should
///     restore to so that an implicit RET would return to `from.pc`).
///   - `from.bp` = `rbp` at entry.
///   - `from.{rbx, r12-r15}` = callee-saved regs at entry.
///
/// **Switch side:**
///
///   - `rsp` ← `(*to).sp`  (g0's stack)
///   - `rbp` ← `(*to).bp`  (g0's saved frame pointer)
///   - `rdi` ← `arg`        (first SysV arg)
///   - `call rdx`           (`fn(arg)`)
///
/// `fn` must be `-> !`. If it returns, the asm executes `ud2`.
///
/// Calling convention (SysV): rdi=from, rsi=to, rdx=fn, rcx=arg.
///
/// **Resume.** When something later calls `gogo(from)`, control
/// transfers to `from.pc` with `rsp = from.sp` and the saved
/// callee-saved registers — i.e., back into the Rust wrapper's
/// frame at the instruction after `call mcall_asm`. The wrapper then
/// returns normally to its caller (the user-visible `Gosched`,
/// `gopark`, etc. site).
///
/// **Why split mcall this way.** Go's mcall is a single asm primitive
/// because Go's calling convention exposes the current G via a
/// dedicated register (R14). Rust's calling convention does not, so
/// curg/g0 lookup happens in the Rust `mcall` wrapper before this
/// asm. The asm itself only handles the red-zone-safe save+switch.
#[unsafe(naked)]
pub(crate) unsafe extern "C" fn mcall_asm(
    _from: *mut Gobuf,
    _to: *const Gobuf,
    _fn: extern "C" fn(*mut crate::runtime::sched::g::G) -> !,
    _arg: *mut crate::runtime::sched::g::G,
) {
    naked_asm!(
        // Save callee-saved registers FIRST, before any clobber.
        "mov [rdi + 0x10], rbx",
        "mov [rdi + 0x18], r12",
        "mov [rdi + 0x20], r13",
        "mov [rdi + 0x28], r14",
        "mov [rdi + 0x30], r15",
        "mov [rdi + 0x08], rbp",
        // Save caller's PC (return address at [rsp]) and the SP
        // value the caller had pre-CALL (rsp + 8). Mirrors Go's
        // `MOVQ 0(SP), BX` / `LEAQ fn+0(FP), BX`.
        "mov rax, [rsp]",
        "mov [rdi + 0x38], rax",
        "lea rax, [rsp + 8]",
        "mov [rdi + 0x00], rax",
        // Switch to g0 stack.
        "mov rsp, [rsi + 0x00]",
        "mov rbp, [rsi + 0x08]",
        // Move fn arg into rdi (first SysV arg).
        "mov rdi, rcx",
        // Call fn(arg). CALL pushes return address, leaving rsp
        // 8-mod-16 aligned at fn entry — correct per SysV.
        "call rdx",
        // fn is -> !; if it returns, abort.
        "ud2",
        ".globl goish_mcall_end",
        "goish_mcall_end:",
        "int3",
    )
}

/// Set up `gobuf` so that a future `gogo(&gobuf)` enters `entry` on
/// `[stack_base, stack_top)`.
///
/// Mirrors Go's `gostartcall` (runtime/stack.go) — used by `newproc`
/// to lay out a fresh G's first execution context.
///
/// Layout (different from `make_context`'s swap_context layout):
///
///     stack_top - 8    `goexit_trampoline` address — popped by
///                       `entry`'s RET if it ever falls through.
///     gobuf.rsp        = stack_top - 8     (one slot above trampoline)
///     gobuf.pc         = entry             (loaded into RIP via JMP)
///
/// The first `gogo(&gobuf)` JMPs to `entry` with `rsp = stack_top - 8`.
/// At entry, `rsp % 16 == 8` (because the trampoline slot is 8 bytes
/// below the 16-aligned `stack_top`), matching the SysV convention as
/// if `entry` had been CALLed.
///
/// Safety: caller must have allocated a writable stack
/// `[stack_base, stack_top)` of at least 16 bytes; `entry` must be a
/// valid `extern "C" fn() -> !` address; `stack_top` must be 16-byte
/// aligned.
pub unsafe fn make_context_gogo(
    gobuf: &mut Gobuf,
    stack_top: usize,
    entry: extern "C" fn() -> !,
) {
    debug_assert!(stack_top % 16 == 0, "stack_top not 16-byte aligned");
    let sp = stack_top - 8;
    // Trampoline catches the case where `entry` returns.
    *(sp as *mut usize) = goexit_trampoline as *const () as usize;
    *gobuf = Gobuf::new();
    gobuf.rsp = sp as u64;
    gobuf.pc = entry as u64;
}

/// Fallback PC if a coroutine entry function returns. M16a doesn't
/// have a scheduler to dispatch to, so this aborts the process. M16b
/// replaces it with `runtime.goexit1` semantics — return the G to
/// the scheduler.
extern "C" fn goexit_trampoline() -> ! {
    const MSG: &[u8] = b"goish: sched: goroutine returned without scheduler\n";
    crate::syscall::Write(crate::syscall::STDERR, MSG.as_ptr(), MSG.len());
    crate::syscall::Exit(2);
}
