// Same workload as chan_micro_select_send_only but installs a
// SA_SIGINFO handler for SIGSEGV that prints the saved RIP and
// si_addr before exiting. Used to localize where the bug actually
// crashes, which tells us which preempt-unsafe region is missed
// by the goish_rt_text PC-range filter.

#![no_std]
#![no_main]

use core::sync::atomic::{AtomicI64, AtomicUsize, Ordering};

use goish::gochan::chan;
use goish::runtime::sched::schedule;
use goish::syscall::{
    self, RtSigaction, Sigaction, SigreturnTrampoline, SA_SIGINFO, SIGSEGV,
};
use goish::{go, make, select};

const N: i64 = 100_000;

static SEND_TOTAL: AtomicI64 = AtomicI64::new(0);
static RECV_TOTAL: AtomicI64 = AtomicI64::new(0);
static GS_DONE: AtomicUsize = AtomicUsize::new(0);

#[repr(C)]
struct StackT {
    ss_sp: *mut u8,
    ss_flags: i32,
    _pad0: i32,
    ss_size: usize,
}

#[repr(C)]
struct McontextT {
    gregs: [u64; 23],
    fpregs: usize,
    _reserved: [u64; 8],
}

#[repr(C)]
struct UcontextT {
    uc_flags: u64,
    uc_link: *mut UcontextT,
    uc_stack: StackT,
    uc_mcontext: McontextT,
}

const REG_RIP: usize = 16;
const REG_RSP: usize = 15;

fn write_hex(label: &[u8], v: u64) {
    syscall::Write(syscall::STDERR, label.as_ptr(), label.len());
    let mut buf = [0u8; 18];
    buf[0] = b'0';
    buf[1] = b'x';
    for i in 0..16 {
        let nib = ((v >> ((15 - i) * 4)) & 0xf) as u8;
        buf[2 + i] = if nib < 10 { b'0' + nib } else { b'a' + (nib - 10) };
    }
    syscall::Write(syscall::STDERR, buf.as_ptr(), buf.len());
    syscall::Write(syscall::STDERR, b"\n".as_ptr(), 1);
}

extern "C" fn segv_handler(_sig: i32, info: *const u8, ctx: *mut UcontextT) {
    const TAG: &[u8] = b"\n=== SIGSEGV ===\n";
    syscall::Write(syscall::STDERR, TAG.as_ptr(), TAG.len());
    unsafe {
        let rip = (*ctx).uc_mcontext.gregs[REG_RIP];
        let rsp = (*ctx).uc_mcontext.gregs[REG_RSP];
        write_hex(b"rip = ", rip);
        write_hex(b"rsp = ", rsp);
        // siginfo: si_addr is at offset 16 on x86_64
        let si_addr = *((info as *const u64).add(2));
        write_hex(b"si_addr = ", si_addr);
        let (start, end, _) = goish::runtime::rt_section::section_bounds();
        write_hex(b"rt_start = ", start);
        write_hex(b"rt_end   = ", end);
        // Inspect the 8 bytes immediately ABOVE rsp — usually the
        // most recently popped slot. With the trampoline epilogue's
        // `jmp qword ptr [rsp - 144]` pattern, faulty resume PCs
        // come from address `rsp - 144`, but rsp may already point
        // past the user's RSP if the bug is elsewhere. Print a few
        // surrounding bytes for context.
        for off in [-144i64, -136, -128, -8, 0, 8, 16].iter() {
            let addr = rsp.wrapping_add(*off as u64);
            // Read bytewise to avoid re-faulting if memory is invalid.
            // We write the address, then attempt a load — if the load
            // faults, we'll see at least the address.
            let mut label = [0u8; 24];
            label[0..8].copy_from_slice(b"[rsp+   ");
            // tiny formatter for signed off
            let mut off_v = *off;
            let neg = off_v < 0;
            if neg { off_v = -off_v; }
            let mut buf = [0u8; 8];
            let mut i = buf.len();
            let mut x = off_v as u64;
            if x == 0 { i -= 1; buf[i] = b'0'; }
            else { while x > 0 { i -= 1; buf[i] = b'0' + (x % 10) as u8; x /= 10; } }
            if neg { i -= 1; buf[i] = b'-'; }
            let s = &buf[i..];
            // place s into label[4..]
            let n = s.len().min(label.len() - 8 - 4);
            for k in 0..n { label[4 + k] = s[k]; }
            label[4 + n] = b']';
            label[4 + n + 1] = b' ';
            label[4 + n + 2] = b'=';
            label[4 + n + 3] = b' ';
            // Get just the prefix
            // Just dump address; reading the actual value may fault.
            syscall::Write(syscall::STDERR, label.as_ptr(), 4 + n + 4);
            // Try to read the value at addr (8 bytes). If unmapped, may not return.
            let val = *(addr as *const u64);
            write_hex(b"", val);
        }
    }
    syscall::Exit(139);
}

#[goish::main]
fn main() {
    let sa = Sigaction {
        sa_handler: segv_handler as usize,
        sa_flags: SA_SIGINFO | 0x04000000, // SA_SIGINFO | SA_RESTORER
        sa_restorer: SigreturnTrampoline as usize,
        sa_mask: 0,
    };
    unsafe {
        RtSigaction(SIGSEGV, &sa, core::ptr::null_mut());
    }

    let c: [chan<i64>; 3] = [
        make!(chan i64),
        make!(chan i64),
        make!(chan i64),
    ];

    {
        let c1_init: [chan<i64>; 3] = [c[0].clone(), c[1].clone(), c[2].clone()];
        go!(move || {
            let mut c1 = c1_init;
            let mut n = [0i64; 3];
            for _ in 0..(3 * N) {
                select! {
                    (c1[0]).Send(0) => { n[0] += 1; if n[0] == N { c1[0] = chan::nil(); } },
                    (c1[1]).Send(0) => { n[1] += 1; if n[1] == N { c1[1] = chan::nil(); } },
                    (c1[2]).Send(0) => { n[2] += 1; if n[2] == N { c1[2] = chan::nil(); } },
                }
                SEND_TOTAL.fetch_add(1, Ordering::Relaxed);
            }
            GS_DONE.fetch_add(1, Ordering::Relaxed);
        });
    }

    for k in 0..3 {
        let ck = c[k].clone();
        go!(move || {
            for _ in 0..N {
                let _ = ck.Recv();
                RECV_TOTAL.fetch_add(1, Ordering::Relaxed);
            }
            GS_DONE.fetch_add(1, Ordering::Relaxed);
        });
    }

    schedule();

    if GS_DONE.load(Ordering::Relaxed) == 4 {
        const OK: &[u8] = b"chan_micro_send_only_segvinfo: ok\n";
        syscall::Write(syscall::STDOUT, OK.as_ptr(), OK.len());
    }
}
