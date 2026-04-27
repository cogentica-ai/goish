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

#[repr(C)]
#[derive(Default)]
pub struct Gobuf {
    pub rsp: u64,
    pub rbp: u64,
    pub rbx: u64,
    pub r12: u64,
    pub r13: u64,
    pub r14: u64,
    pub r15: u64,
}

impl Gobuf {
    pub const fn new() -> Self {
        Gobuf {
            rsp: 0,
            rbp: 0,
            rbx: 0,
            r12: 0,
            r13: 0,
            r14: 0,
            r15: 0,
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
    *((stack_top - 8) as *mut usize) = goexit_trampoline as usize;
    // Below — first PC popped by the initial RET.
    *(sp as *mut usize) = entry as usize;

    *gobuf = Gobuf::new();
    gobuf.rsp = sp as u64;
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
