// preempt_slot_offline_proof —
//
// Standalone, in-process proof of the M18b-δ.3 per-G stack-slot resume-PC
// algorithm. NO dependence on goish::runtime::preempt — we re-implement the
// slot semantics in plain Rust and stress-test the structural claims:
//
//   (A) Address disjointness: slots from N independent stacks are at
//       N distinct 8-byte-aligned addresses, and no slot overlaps any
//       other stack's body.
//
//   (B) Per-stack fidelity: the slot survives the trampoline-body's
//       stack writes (BP, FLAGS, save area at offsets -152..-544 below
//       the stack-top reference). Writing PC to slot, then mirroring
//       every trampoline-body store, then reading the slot, returns PC.
//
//   (C) Cross-park preservation: writing slot_a on stack_a, then
//       simulating a yield + dispatch of stack_b (with its own
//       trampoline cycle on stack_b), then "resuming" stack_a by
//       reading slot_a, returns the original pc_a. This is the
//       residual-clobber scenario the M18b-δ.2 per-M `MStorage.preempt_resume_pc`
//       slot was designed to defend; the δ.3 design eliminates the
//       defense by removing the shared slot entirely.
//
// If all three sub-proofs pass with zero mismatches, the slot algorithm
// is empirically clobber-free at the data-plane level. The integrated
// path (asm trampoline + signal handler) still requires runtime stress
// (`chan_micro_select_send_only`) — that is a separate proof, run AFTER
// this offline proof passes.

#![no_std]
#![no_main]

use goish::syscall;

// ─── Slot offset (matches preempt.rs trampoline epilogue) ─────────────
//
// The δ.3 trampoline reads its resume PC via `jmp qword ptr [rsp - 144]`
// after the epilogue has restored RSP to the user's pre-SIGURG SP. The
// slot is therefore at `[user_sp - SLOT_OFFSET]`. The handler writes
// directly to this address.
const SLOT_OFFSET: usize = 144;

// Trampoline-body stack writes (mirrored). The actual asm writes:
//   [user_sp - 152]  rbp
//   [user_sp - 160]  flags
//   [user_sp - 544]+ save area (384 bytes for GPR + XMM + alignment)
// All offsets are STRICTLY > 144, so no body write touches the slot.
// The proof simulates each of these writes to verify aliasing assumptions.
const RBP_OFFSET: usize = 152;
const FLAGS_OFFSET: usize = 160;
const SAVE_AREA_BASE: usize = 544;
const SAVE_AREA_BYTES: usize = 384;

// ─── Fake "G stack" — a 64 KiB mmap region ────────────────────────────
//
// Mirrors `runtime::sched::stack::Stack` but inlined here so the proof
// harness has no runtime dependency on the goroutine scheduler.

const STACK_SIZE: usize = 64 * 1024;

struct FakeStack {
    base: *mut u8,
}

impl FakeStack {
    fn new() -> Self {
        let p = syscall::Mmap(
            core::ptr::null_mut(),
            STACK_SIZE,
            syscall::PROT_READ | syscall::PROT_WRITE,
            syscall::MAP_PRIVATE | syscall::MAP_ANONYMOUS,
            -1,
            0,
        );
        if p == syscall::MAP_FAILED {
            const MSG: &[u8] = b"preempt_slot_offline_proof: mmap failed\n";
            syscall::Write(syscall::STDERR, MSG.as_ptr(), MSG.len());
            syscall::Exit(2);
        }
        FakeStack { base: p }
    }

    fn top(&self) -> usize {
        self.base as usize + STACK_SIZE
    }

    fn slot_addr(&self) -> *mut u64 {
        (self.top() - SLOT_OFFSET) as *mut u64
    }
}

impl Drop for FakeStack {
    fn drop(&mut self) {
        syscall::Munmap(self.base, STACK_SIZE);
    }
}

// ─── Algorithm primitives ─────────────────────────────────────────────

/// Mirror of the M18b-δ.3 handler's slot write. Writes resume PC to
/// `[stack_top - 144]`. The actual handler sources this from
/// `ucontext.RIP` (the user's pre-SIGURG PC); here we feed it directly.
#[inline(never)]
fn handler_inject(stack: &FakeStack, pc: u64) {
    unsafe {
        stack.slot_addr().write(pc);
    }
}

/// Mirror of every trampoline-body write that lands on the user's stack
/// after the slot is initialized. Writes:
///   - rbp at [top - 152]
///   - flags at [top - 160]
///   - save area starting at [top - 544], 384 bytes of arbitrary data
/// If any of these aliases the slot at [top - 144], the body would
/// corrupt the resume PC. The proof asserts the slot survives.
#[inline(never)]
fn trampoline_body_writes(stack: &FakeStack, marker: u64) {
    let top = stack.top();
    unsafe {
        ((top - RBP_OFFSET) as *mut u64).write(marker.wrapping_add(0xAAAA_AAAA));
        ((top - FLAGS_OFFSET) as *mut u64).write(marker.wrapping_add(0xBBBB_BBBB));
        let save_base = (top - SAVE_AREA_BASE) as *mut u8;
        for i in 0..SAVE_AREA_BYTES {
            save_base.add(i).write((marker as u8).wrapping_add(i as u8));
        }
    }
}

/// Mirror of the trampoline epilogue's final `jmp qword [rsp - 144]`.
/// Reads the slot.
#[inline(never)]
fn trampoline_resume(stack: &FakeStack) -> u64 {
    unsafe { stack.slot_addr().read() }
}

// ─── Stable PRNG (xorshift) for deterministic stress ──────────────────

struct Xorshift {
    state: u64,
}
impl Xorshift {
    const fn new(seed: u64) -> Self {
        Xorshift { state: seed }
    }
    fn next(&mut self) -> u64 {
        let mut x = self.state;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.state = x;
        x
    }
}

// ─── Output helpers ───────────────────────────────────────────────────

fn write_str(s: &[u8]) {
    syscall::Write(syscall::STDERR, s.as_ptr(), s.len());
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
    syscall::Write(syscall::STDERR, buf.as_ptr(), buf.len());
    syscall::Write(syscall::STDERR, b"\n".as_ptr(), 1);
}

fn write_dec(label: &[u8], v: u64) {
    write_str(label);
    let mut buf = [0u8; 20];
    let mut i = buf.len();
    let mut x = v;
    if x == 0 {
        i -= 1;
        buf[i] = b'0';
    } else {
        while x > 0 {
            i -= 1;
            buf[i] = b'0' + (x % 10) as u8;
            x /= 10;
        }
    }
    syscall::Write(syscall::STDERR, buf[i..].as_ptr(), buf.len() - i);
    syscall::Write(syscall::STDERR, b"\n".as_ptr(), 1);
}

// ─── Stack pool ───────────────────────────────────────────────────────

const N_STACKS: usize = 64;

struct StackPool {
    stacks: [Option<FakeStack>; N_STACKS],
}

impl StackPool {
    fn new() -> Self {
        let mut s: [Option<FakeStack>; N_STACKS] = [const { None }; N_STACKS];
        for i in 0..N_STACKS {
            s[i] = Some(FakeStack::new());
        }
        StackPool { stacks: s }
    }
    fn get(&self, i: usize) -> &FakeStack {
        self.stacks[i].as_ref().unwrap()
    }
}

// ─── Sub-proof (A): address disjointness ──────────────────────────────

fn proof_a_disjointness(pool: &StackPool) -> u64 {
    let mut errors = 0u64;
    // Pairwise: every slot address is unique.
    for i in 0..N_STACKS {
        for j in (i + 1)..N_STACKS {
            let a = pool.get(i).slot_addr() as usize;
            let b = pool.get(j).slot_addr() as usize;
            if a == b {
                errors += 1;
            }
        }
    }
    // Slot must be 8-byte aligned (qword load/store assumption).
    for i in 0..N_STACKS {
        let a = pool.get(i).slot_addr() as usize;
        if a & 7 != 0 {
            errors += 1;
        }
    }
    // Slot must lie within its own stack region.
    for i in 0..N_STACKS {
        let s = pool.get(i);
        let slot = s.slot_addr() as usize;
        let base = s.base as usize;
        let top = s.top();
        if !(slot >= base && slot + 8 <= top) {
            errors += 1;
        }
    }
    // Slot of stack i must not lie inside stack j's body, for any j != i.
    for i in 0..N_STACKS {
        let slot = pool.get(i).slot_addr() as usize;
        for j in 0..N_STACKS {
            if i == j {
                continue;
            }
            let other = pool.get(j);
            let base = other.base as usize;
            let top = other.top();
            if slot >= base && slot < top {
                errors += 1;
            }
        }
    }
    errors
}

// ─── Sub-proof (B): per-stack fidelity ────────────────────────────────
//
// For each stack: write PC to slot, mirror every trampoline-body write,
// read PC back. Repeat with many distinct PCs.

fn proof_b_fidelity(pool: &StackPool) -> u64 {
    let mut errors = 0u64;
    let mut rng = Xorshift::new(0xDEADBEEF_CAFEBABE);
    let iters_per_stack: u64 = 10_000;
    for i in 0..N_STACKS {
        let s = pool.get(i);
        for _ in 0..iters_per_stack {
            let pc = rng.next();
            handler_inject(s, pc);
            trampoline_body_writes(s, pc);
            let read = trampoline_resume(s);
            if read != pc {
                errors += 1;
            }
        }
    }
    errors
}

// ─── Sub-proof (C): cross-park preservation ───────────────────────────
//
// Simulates the residual-clobber scenario:
//   1. Inject pc_a on stack_a (G_a is "preempted").
//   2. Run trampoline body on stack_a (writes BP, flags, save area).
//   3. "Yield": stack_a goes dormant.
//   4. Inject pc_b on stack_b (G_b is preempted).
//   5. Run trampoline body on stack_b. (Cross-park: writes happen on
//      stack_b, must NOT touch stack_a's slot.)
//   6. Resume stack_a: read slot_a. Must equal pc_a.
//   7. Resume stack_b: read slot_b. Must equal pc_b.

fn proof_c_cross_park(pool: &StackPool) -> u64 {
    let mut errors = 0u64;
    let mut rng = Xorshift::new(0x1234_5678_9ABC_DEF0);
    let iters: u64 = 10_000;
    for _ in 0..iters {
        let i = (rng.next() as usize) % N_STACKS;
        let mut j = (rng.next() as usize) % N_STACKS;
        if j == i {
            j = (j + 1) % N_STACKS;
        }
        let stack_a = pool.get(i);
        let stack_b = pool.get(j);
        let pc_a = rng.next();
        let pc_b = rng.next();

        handler_inject(stack_a, pc_a);
        trampoline_body_writes(stack_a, pc_a);
        // Yield on a: stack_a dormant.
        handler_inject(stack_b, pc_b);
        trampoline_body_writes(stack_b, pc_b);
        // Resume a: read slot_a.
        let resume_a = trampoline_resume(stack_a);
        if resume_a != pc_a {
            errors += 1;
        }
        // Resume b.
        let resume_b = trampoline_resume(stack_b);
        if resume_b != pc_b {
            errors += 1;
        }
    }
    errors
}

// ─── Sub-proof (D): deeply interleaved cross-park ─────────────────────
//
// Stronger version of (C): N stacks, K iterations each, randomly
// interleaved. Each preempt event chooses a random stack, writes pc,
// mirrors body. After all writes, every stack is read in order; every
// read must match the LAST write to that stack.

const D_EVENTS: usize = 100_000;

fn proof_d_interleaved(pool: &StackPool) -> u64 {
    let mut errors = 0u64;
    let mut rng = Xorshift::new(0xFEEDFACE_F00DBABE);
    // Track the most-recent PC injected per stack.
    let mut last_pc: [u64; N_STACKS] = [0; N_STACKS];
    let mut written: [bool; N_STACKS] = [false; N_STACKS];

    for _ in 0..D_EVENTS {
        let i = (rng.next() as usize) % N_STACKS;
        let pc = rng.next();
        handler_inject(pool.get(i), pc);
        trampoline_body_writes(pool.get(i), pc);
        last_pc[i] = pc;
        written[i] = true;
    }

    // Now resume every written stack and verify last-write-wins.
    for i in 0..N_STACKS {
        if !written[i] {
            continue;
        }
        let read = trampoline_resume(pool.get(i));
        if read != last_pc[i] {
            errors += 1;
        }
    }
    errors
}

// ─── Driver ───────────────────────────────────────────────────────────

#[goish::main]
fn main() {
    write_str(b"preempt_slot_offline_proof: starting\n");
    write_dec(b"  stacks    = ", N_STACKS as u64);
    write_dec(b"  d_events  = ", D_EVENTS as u64);

    let pool = StackPool::new();

    // Show a few slot addresses so the user can eyeball disjointness.
    for i in 0..4 {
        write_hex(b"  slot[ ]   = ", pool.get(i).slot_addr() as u64);
    }

    write_str(b"  (A) disjointness        ... ");
    let e_a = proof_a_disjointness(&pool);
    if e_a == 0 {
        write_str(b"PASS\n");
    } else {
        write_dec(b"FAIL  errors = ", e_a);
    }

    write_str(b"  (B) per-stack fidelity  ... ");
    let e_b = proof_b_fidelity(&pool);
    if e_b == 0 {
        write_str(b"PASS\n");
    } else {
        write_dec(b"FAIL  errors = ", e_b);
    }

    write_str(b"  (C) cross-park preserve ... ");
    let e_c = proof_c_cross_park(&pool);
    if e_c == 0 {
        write_str(b"PASS\n");
    } else {
        write_dec(b"FAIL  errors = ", e_c);
    }

    write_str(b"  (D) interleaved stress  ... ");
    let e_d = proof_d_interleaved(&pool);
    if e_d == 0 {
        write_str(b"PASS\n");
    } else {
        write_dec(b"FAIL  errors = ", e_d);
    }

    let total = e_a + e_b + e_c + e_d;
    if total == 0 {
        const OK: &[u8] = b"preempt_slot_offline_proof: ok\n";
        syscall::Write(syscall::STDOUT, OK.as_ptr(), OK.len());
        syscall::Exit(0);
    } else {
        const FAIL: &[u8] = b"preempt_slot_offline_proof: FAIL\n";
        syscall::Write(syscall::STDERR, FAIL.as_ptr(), FAIL.len());
        syscall::Exit(1);
    }
}
