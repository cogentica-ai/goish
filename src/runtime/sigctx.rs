// runtime::sigctx — the interrupted thread's registers, from the third
// argument of an `SA_SIGINFO` handler.
//
// The handlers that need them (the SIGPROF sampler; the SIGURG
// preemptor; the SIGSEGV stack-overflow report) ask the same four questions on every target — where was
// it (pc), what is its frame chain (fp), its stack (sp), and on arm64
// its return address (lr) — but the answer lives somewhere different
// on each:
//
//   linux/amd64   `ucontext_t.uc_mcontext.gregs[REG_*]`, inline.
//   darwin/arm64  `ucontext_t.uc_mcontext` is a POINTER (offset 48) to
//                 an `__darwin_mcontext64`, whose `__ss` thread state
//                 starts at 16: fp 232, lr 240, sp 248, pc 256. Measured
//                 against <sys/ucontext.h> / <mach/arm/_structs.h>; Go's
//                 equivalents are `runtime/defs_darwin_arm64.go`
//                 (ucontext, mcontext64, regs64) and
//                 `signal_darwin_arm64.go`.
//
// Linux/arm64 is not wired: nothing installs an SA_SIGINFO handler
// there yet (preemption and the sampler are gated off), so an accessor
// would have no caller to be checked against.
//
// All accessors take the raw `ctx` pointer and are async-signal-safe:
// plain loads and stores into kernel-provided memory.
//
// `fault_addr` reads the handler's SECOND argument, `siginfo_t`, for
// the address a SIGSEGV/SIGBUS faulted on. Its offset differs too:
//
//   linux         16 — si_signo, si_errno, si_code, pad, then the
//                 8-aligned `_sifields` union whose `_sigfault` starts
//                 with `si_addr` (include/uapi/asm-generic/siginfo.h).
//   darwin        24 — si_signo, si_errno, si_code, si_pid, si_uid,
//                 si_status, then `si_addr` (<sys/signal.h>; Go's
//                 `siginfo` in runtime/defs_darwin_arm64.go).

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
mod imp {
    const UC_MCONTEXT: usize = 48;
    const MC_SS: usize = 16;
    const SS_FP: usize = 232;
    const SS_LR: usize = 240;
    const SS_SP: usize = 248;
    const SS_PC: usize = 256;

    #[inline(always)]
    unsafe fn reg(ctx: *mut u8, off: usize) -> *mut u64 {
        let mc = *(ctx.add(UC_MCONTEXT) as *const *mut u8);
        mc.add(MC_SS + off) as *mut u64
    }
    #[inline(always)]
    pub unsafe fn pc(ctx: *mut u8) -> u64 { *reg(ctx, SS_PC) }
    #[inline(always)]
    pub unsafe fn fp(ctx: *mut u8) -> u64 { *reg(ctx, SS_FP) }
    #[inline(always)]
    pub unsafe fn sp(ctx: *mut u8) -> u64 { *reg(ctx, SS_SP) }
    #[inline(always)]
    pub unsafe fn lr(ctx: *mut u8) -> u64 { *reg(ctx, SS_LR) }
    #[inline(always)]
    pub unsafe fn fault_addr(info: *const u8) -> usize { *(info.add(24) as *const usize) }
    #[inline(always)]
    pub unsafe fn set_pc(ctx: *mut u8, v: u64) { *reg(ctx, SS_PC) = v }
    #[inline(always)]
    pub unsafe fn set_lr(ctx: *mut u8, v: u64) { *reg(ctx, SS_LR) = v }
    #[inline(always)]
    pub unsafe fn set_sp(ctx: *mut u8, v: u64) { *reg(ctx, SS_SP) = v }

    /// `__ss.__cpsr` (offset 264, 32-bit) and the NEON state
    /// `__ns` at mcontext offset 288: `__v[32]` then FPSR/FPCR at
    /// 512/516 within it.
    const SS_CPSR: usize = 264;
    const MC_NS: usize = 288;

    /// Restore a whole register file saved by the arm64 preempt
    /// trampoline (`preempt_asm_arm64.rs` documents the layout): the
    /// sigreturn after this handler then resumes the interrupted code
    /// exactly. x18 is left as the kernel delivered it.
    pub unsafe fn restore_preempt_frame(ctx: *mut u8, area: *const u8, lr: u64, sp: u64, pc: u64) {
        let mc = *(ctx.add(UC_MCONTEXT) as *const *mut u8);
        let x = mc.add(MC_SS) as *mut u64;
        let saved = area as *const u64;
        for i in 0..29 {
            if i != 18 {
                *x.add(i) = *saved.add(i);
            }
        }
        *reg(ctx, SS_FP) = *saved.add(29);
        *reg(ctx, SS_LR) = lr;
        *reg(ctx, SS_SP) = sp;
        *reg(ctx, SS_PC) = pc;
        let cpsr = mc.add(MC_SS + SS_CPSR) as *mut u32;
        let nzcv = *saved.add(30) as u32 & 0xF000_0000;
        *cpsr = (*cpsr & 0x0FFF_FFFF) | nzcv;
        let ns = mc.add(MC_NS);
        core::ptr::copy_nonoverlapping(area.add(256), ns, 512);
        *(ns.add(512) as *mut u32) = *(area.add(248) as *const u32);
        *(ns.add(516) as *mut u32) = *(area.add(252) as *const u32);
    }
}

#[cfg(not(all(target_os = "macos", target_arch = "aarch64")))]
mod imp {
    use crate::runtime::preempt::{UcontextT, REG_RBP, REG_RIP, REG_RSP};

    #[inline(always)]
    pub unsafe fn pc(ctx: *mut u8) -> u64 { (*(ctx as *mut UcontextT)).uc_mcontext.gregs[REG_RIP] }
    #[inline(always)]
    pub unsafe fn fp(ctx: *mut u8) -> u64 { (*(ctx as *mut UcontextT)).uc_mcontext.gregs[REG_RBP] }
    #[inline(always)]
    pub unsafe fn sp(ctx: *mut u8) -> u64 { (*(ctx as *mut UcontextT)).uc_mcontext.gregs[REG_RSP] }
    #[inline(always)]
    pub unsafe fn fault_addr(info: *const u8) -> usize { *(info.add(16) as *const usize) }
}

pub use imp::*;
