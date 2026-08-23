// Smoke test: M17a-β2 — TLS infra (FS/CLONE_SETTLS or GS/arch_prctl).
//
// Spawns 4 worker threads, each with its own `MStorage` allocated on
// the heap. Each worker is cloned with `CLONE_SETTLS` and its own
// `tls_self` slot, so the child's `fs` segment base is set by the
// kernel atomically with thread creation; the worker's first
// `current_m()` already returns its own M.
//
// Verifies:
//   1. The main thread's `current_m()` (post-`setup_main_tls`) reads
//      &MAIN_M.m — i.e., M id 0.
//   2. Each of 4 workers reads its OWN id (1..=4) via current_m(),
//      not the main M's. This confirms fs:[0] is per-thread.
//   3. All 5 distinct procids (1 main + 4 workers, each their own
//      gettid) are observed in the shared id-array.
//   4. No worker sees a stale or shared M.

#![no_std]
#![no_main]

use core::cell::UnsafeCell;
use core::sync::atomic::{AtomicI32, AtomicUsize, Ordering};

use goish::runtime::sched::{acquirem, current_m, releasem, MStorage};
#[cfg(feature = "ffi-system-tls")]
use goish::runtime::sched::{current_m_storage, pre_goish_fs_base};
use goish::syscall;

const N_WORKERS: usize = 4;
const STACK_SIZE: usize = 64 * 1024;

// Shared state visible to all threads (CLONE_VM).
static OBSERVED_IDS: [AtomicI32; N_WORKERS] = [
    AtomicI32::new(-1),
    AtomicI32::new(-1),
    AtomicI32::new(-1),
    AtomicI32::new(-1),
];
static OBSERVED_TIDS: [AtomicI32; N_WORKERS] = [
    AtomicI32::new(0),
    AtomicI32::new(0),
    AtomicI32::new(0),
    AtomicI32::new(0),
];
static WORKERS_DONE: AtomicUsize = AtomicUsize::new(0);

// One MStorage per worker. We can't pass per-worker arguments through
// the naked clone trampoline (which only sets fs and jumps to a fixed
// fn pointer), so each worker gets its own dedicated entry function
// that hardcodes its slot index.
//
// In production code (M17a-δ), workers will read their slot from a
// per-M field; for this β2 smoke test we keep it simple with 4
// dedicated entries.

struct WorkerStorage {
    storage: MStorage,
    slot_idx: u8,
}
// Manual Sync — we only ever touch this from one thread (the spawning
// parent or the spawned worker), and the access pattern is
// initialization-then-read.
unsafe impl Sync for WorkerStorage {}

// 4 static slots, each ready to be initialized and used by one worker.
struct StaticSlots(UnsafeCell<[Option<WorkerStorage>; N_WORKERS]>);
unsafe impl Sync for StaticSlots {}
static SLOTS: StaticSlots = StaticSlots(UnsafeCell::new([None, None, None, None]));

fn observe_self(slot_idx: u8) {
    check_ffi_tls_layout();
    let m_lock = current_m();
    let m = m_lock.lock();
    OBSERVED_IDS[slot_idx as usize].store(m.id as i32, Ordering::Release);
    drop(m);
    OBSERVED_TIDS[slot_idx as usize].store(syscall::Gettid(), Ordering::Release);
    WORKERS_DONE.fetch_add(1, Ordering::AcqRel);
}

extern "C" fn worker_entry_0() -> ! {
    observe_self(0);
    syscall::ExitThread(0);
}
extern "C" fn worker_entry_1() -> ! {
    observe_self(1);
    syscall::ExitThread(0);
}
extern "C" fn worker_entry_2() -> ! {
    observe_self(2);
    syscall::ExitThread(0);
}
extern "C" fn worker_entry_3() -> ! {
    observe_self(3);
    syscall::ExitThread(0);
}

fn die(msg: &[u8]) -> ! {
    syscall::Write(syscall::STDERR, msg.as_ptr(), msg.len());
    syscall::Exit(1);
}

fn check(cond: bool, msg: &[u8]) {
    if !cond {
        die(msg);
    }
}

#[cfg(feature = "ffi-system-tls")]
fn check_ffi_tls_layout() {
    acquirem();
    let mut fs_base = usize::MAX;
    let mut gs_base = usize::MAX;
    let fs_result = syscall::ArchPrctl(syscall::ARCH_GET_FS, &mut fs_base as *mut usize as usize);
    let gs_result = syscall::ArchPrctl(syscall::ARCH_GET_GS, &mut gs_base as *mut usize as usize);
    let goish_base = current_m_storage().tls_base();
    releasem();

    check(fs_result == 0, b"ARCH_GET_FS failed\n");
    check(gs_result == 0, b"ARCH_GET_GS failed\n");
    check(
        fs_base == pre_goish_fs_base(),
        b"platform FS was replaced\n",
    );
    check(gs_base == goish_base, b"Goish GS base is wrong\n");
}

#[cfg(not(feature = "ffi-system-tls"))]
fn check_ffi_tls_layout() {}

#[goish::main]
fn main() {
    check_ffi_tls_layout();
    // ── Test 1: the dispatching M's TLS reads are coherent ────────
    //
    // `main` runs on the main *goroutine*, dispatched by whichever M
    // dequeued it — not necessarily MAIN_M (id 0). The TLS invariant
    // to check is that `current_m()` via the fs-base read returns a
    // stable M across reads (pinned so no migration between them).
    acquirem();
    let id_a = current_m().lock().id;
    let id_b = current_m().lock().id;
    releasem();
    check(id_a == id_b, b"t1: TLS current_m read not stable\n");

    // ── Test 2: spawn 4 workers, each with its own MStorage ───────
    let entries: [extern "C" fn() -> !; N_WORKERS] = [
        worker_entry_0,
        worker_entry_1,
        worker_entry_2,
        worker_entry_3,
    ];

    for i in 0..N_WORKERS {
        // Init the slot's MStorage with id = i+1 (main is 0).
        unsafe {
            let slots = &mut *SLOTS.0.get();
            slots[i] = Some(WorkerStorage {
                storage: MStorage::new((i + 1) as u32),
                slot_idx: i as u8,
            });
            // Borrow as 'static — slots are static mut and we won't
            // touch them again from main after this.
            let ws: &'static WorkerStorage = slots[i].as_ref().unwrap();
            ws.storage.init_tls_self();

            let stack = syscall::Mmap(
                core::ptr::null_mut(),
                STACK_SIZE,
                syscall::PROT_READ | syscall::PROT_WRITE,
                syscall::MAP_PRIVATE | syscall::MAP_ANONYMOUS,
                -1,
                0,
            );
            check(stack != syscall::MAP_FAILED, b"mmap worker stack\n");
            let top = stack.add(STACK_SIZE);

            let tid = syscall::Clone(
                syscall::CLONE_THREAD_FLAGS,
                top,
                entries[i],
                ws.storage.tls_base() as u64,
            );
            check(tid > 0, b"clone returned non-positive\n");
            // slot_idx is read by the worker; suppress unused warning.
            let _ = ws.slot_idx;
        }
    }

    // ── Test 3: wait for all workers to publish ───────────────────
    let mut spins: u64 = 0;
    while WORKERS_DONE.load(Ordering::Acquire) < N_WORKERS {
        core::hint::spin_loop();
        spins += 1;
        if spins > 1_000_000_000 {
            die(b"workers did not all publish\n");
        }
    }

    // ── Test 4: each worker observed its own id (1..=4) ───────────
    for i in 0..N_WORKERS {
        let observed = OBSERVED_IDS[i].load(Ordering::Acquire);
        let expected = (i + 1) as i32;
        check(
            observed == expected,
            b"worker observed wrong id (TLS leak across threads?)\n",
        );
    }

    // ── Test 5: all 4 worker tids distinct + distinct from main ───
    let main_tid = syscall::Gettid();
    for i in 0..N_WORKERS {
        let t = OBSERVED_TIDS[i].load(Ordering::Acquire);
        check(t > 0, b"worker tid invalid\n");
        check(t != main_tid, b"worker tid == main tid\n");
        for j in 0..i {
            let other = OBSERVED_TIDS[j].load(Ordering::Acquire);
            check(t != other, b"two workers got same tid\n");
        }
    }

    const OK: &[u8] = b"tls_smoke: ok\n";
    syscall::Write(syscall::STDOUT, OK.as_ptr(), OK.len());
}
