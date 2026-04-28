// runtime — startup, panic handling, and (later) the heap allocator.
//
// Mirrors Go's startup pipeline:
//
//   _rt0_amd64        →  _start                (asm stub in user binary,
//                                                emitted by #[goish::main])
//   runtime.rt0_go    →  __goish_rt0           (this file)
//   runtime.main      →  body of __goish_rt0   (sets things up, calls user main)
//   main.main         →  user's #[goish::main] fn main()
//   runtime.exit      →  syscall::Exit
//
// The _start stub lives in the user's binary (so the linker actually
// emits the symbol); __goish_rt0 lives here in the rlib and is the first
// Rust code to run.

use crate::syscall;

pub mod args;
pub mod debug;
pub mod flags;
pub mod heap;
pub mod mcentral;
pub mod mheap;
mod mem;
pub mod note;
pub mod preempt;
pub mod rand;
pub mod rt_section;
pub mod sched;
pub mod signal;
pub mod spin;
pub mod sysmon;
pub use debug::{NumCPU, NumGoroutine, GOMAXPROCS};
pub use heap::{alloc, free, mheap_alloc_pages, mheap_free_pages, realloc};

/// First Rust code to run after the kernel hands control to `_start`.
/// `_start` (emitted by `#[goish::main]`) reads argc/argv off the stack,
/// loads them into rdi/rsi per SysV, then `call`s here.
///
/// `extern "C"` so the asm stub can call us with the C ABI.
#[no_mangle]
pub extern "C" fn __goish_rt0(argc: i32, argv: *const *const u8) -> ! {
    // Stash argc/argv so os::Args() can decode them lazily on first use.
    args::__set(argc, argv);

    // Parse GOISH_* env vars before any goroutine code runs. The kernel
    // ELF stack layout puts envp right after argv's null terminator,
    // so we recover envp = argv + argc + 1 here.
    unsafe { flags::init_from_argv(argc, argv); }

    // Plant the main M's TLS slot. After this, `current_m()` reads
    // `&MAIN_M.m` via `mov %fs:0, _` instead of the (legacy β1)
    // static-pointer return. Must come before any code that calls
    // current_m() — chan ops, scheduler, gopark/goready all do.
    sched::setup_main_tls();

    // Seed the cheaprand state from rdtsc so each process run starts
    // with a different select fairness sequence.
    rand::init();

    // Bring mheap online before user code runs. Until this finishes,
    // every alloc routes through dlmalloc (MHEAP_READY = false). After
    // this, large allocs route through mheap.
    unsafe { heap::mheap_init() }

    // Bring mcentral online so small allocs route through size-class
    // spans backed by mheap rather than dlmalloc. Must follow
    // mheap_init since mcentral draws spans from mheap.
    unsafe {
        // Pull arena base from mheap to set up mcentral's page→span map.
        let arena_base = heap::mheap_arena_base();
        mcentral::mcentral_init(arena_base);
    }

    // Now that the allocator is up, register the main M with the
    // global M_LIST so wakers can find it (M17c). Main M parks via
    // futex when its runq drains; without registration the
    // wake_idle_m scan would skip it. Deferred from setup_main_tls
    // because registration push()es to a Vec, which alloc-traps if
    // mheap isn't online yet.
    sched::register_m_storage(&sched::MAIN_M);

    // M17b-α: bootstrap GOMAXPROCS Ps and bind P[0] to the main M.
    // Must follow the allocator coming online (Ps are leaked Box<P>)
    // and precede `bootstrap_workers` (each worker `acquirep`s
    // P[id] in its `mstart`).
    let nprocs = sched::num_cpus();
    sched::bootstrap_ps(nprocs);
    if let Some(p0) = sched::p_at(0) {
        sched::acquirep(p0);
    }

    // Bootstrap N-1 worker Ms (M17a-δ.1) so the worker pool is
    // already dispatching by the time `__goish_main` runs. Each
    // worker thread has its own MStorage with a fresh fs base; the
    // main M shares the global SCHED runq with them.
    sched::bootstrap_workers();

    // Spawn the sysmon thread (M18a). Owns the global timer heap;
    // wakes timer-parked goroutines via `time::Sleep`. Must come
    // after bootstrap_workers so register_m_storage's allocator is
    // up.
    sysmon::start_sysmon();

    // Install the SIGURG preempt handler (M18b-α phase B).
    // Decision-only: counts would-be preempts but does not modify
    // ucontext yet. Phase C wires the asyncPreempt trampoline.
    preempt::install();

    // Hand off to the user's main. The proc-macro #[goish::main]
    // generates a #[no_mangle] extern "C" fn __goish_main wrapping the
    // user's body, so the linker resolves this `extern` block to it.
    extern "C" {
        fn __goish_main();
    }
    unsafe { __goish_main() }

    // Drain any goroutines spawned with go!() that are still
    // runnable. Mirrors Go's runtime.main() draining loop: after
    // main.main returns, the runtime keeps dispatching goroutines
    // until the queue empties.
    sched::schedule();

    // Normal termination — Go's runtime.exit(0) equivalent.
    syscall::Exit(0)
}

// ─── panic handler ─────────────────────────────────────────────────────
//
// no_std crates must define exactly one #[panic_handler]. Since goish is
// built `panic = "abort"`, this only fires on explicit `panic!()` /
// unrecoverable conditions; we print a short marker and exit(2).

#[panic_handler]
fn on_panic(info: &core::panic::PanicInfo) -> ! {
    const MSG: &[u8] = b"goish: panic\n";
    syscall::Write(syscall::STDERR, MSG.as_ptr(), MSG.len());
    // Best-effort: dump the panic message text + location so post-
    // mortem diagnosis (and rr replay) can identify which panic
    // fired without disassembly.
    if let Some(loc) = info.location() {
        const AT: &[u8] = b"  at ";
        syscall::Write(syscall::STDERR, AT.as_ptr(), AT.len());
        let f = loc.file().as_bytes();
        syscall::Write(syscall::STDERR, f.as_ptr(), f.len());
        const COLON: &[u8] = b":";
        syscall::Write(syscall::STDERR, COLON.as_ptr(), COLON.len());
        let mut buf = [0u8; 12];
        let mut n = loc.line();
        let mut i = buf.len();
        if n == 0 {
            i -= 1;
            buf[i] = b'0';
        } else {
            while n > 0 {
                i -= 1;
                buf[i] = b'0' + (n % 10) as u8;
                n /= 10;
            }
        }
        syscall::Write(syscall::STDERR, buf[i..].as_ptr(), buf.len() - i);
        const NL: &[u8] = b"\n";
        syscall::Write(syscall::STDERR, NL.as_ptr(), NL.len());
    }
    // The PanicInfo's message itself isn't directly extractable as
    // bytes in no_std without `core::fmt`. We can at least emit the
    // message via the Display trait through a fixed buffer. For now,
    // location-only is enough to identify the panic site.
    syscall::Exit(2)
}

// Required because core's DWARF unwind tables reference this symbol,
// even though we build with `panic = "abort"`. It's never actually
// invoked at runtime — provide an empty no-mangle stub so the linker
// is satisfied.
#[no_mangle]
pub extern "C" fn rust_eh_personality() {}
