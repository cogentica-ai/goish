// runtime::rt0_darwin — the staged boot on macOS/arm64.
//
// The Linux `__goish_rt0` in `runtime/mod.rs` runs fifteen steps before
// it hands off to the user's `main`. This one runs eight. It is a
// separate function rather than a third `#[cfg]` arm threaded through
// that one because the difference is not a branch or two — it is which
// two thirds of the sequence exist at all, and a reader of either file
// should be able to see the whole boot without unpicking cfgs.
//
// ─── What runs ─────────────────────────────────────────────────────────
//
//   1. `args::__set`         — stash argc/argv for `os::Args()`.
//   2. `flags::init_from_envp` — GOISH_* knobs, from `main`'s third
//      argument rather than an ELF stack walk (see `runtime/flags.rs`).
//   3. `sched::setup_main_tls` — the main M's thread pointer, in a
//      pthread TSD slot (M4; see `sched/tls/tls_darwin_arm64.rs`).
//   4. `rand::init` — seed `select`'s fairness PRNG from `cputicks`.
//   5. `heap::mheap_init` + `mcentral::mcentral_init` — the allocator.
//   6. `sched::register_m_storage` + `sched::setup_main_g0` — the main
//      M's `g0`, adopting the OS stack from libpthread's bounds.
//   7. `sched::bootstrap_ps(n)` + `acquirep`, then `bootstrap_workers`
//      and `start_sysmon` — n Ps, a pthread M per P beyond the first,
//      and sysmon (M7).
//   8. `__goish_main()` on a goroutine, then `m_schedule_loop` on g0;
//      the process exits when `main` returns (M5a).
//
// **Step 5 is more than the port plan budgeted for**, and the reason is
// worth recording: the plan was written when `runtime/heap.rs` still
// had a pre-mheap dlmalloc tier, and scheduled M1 to boot on that and
// leave mheap for M2. dlmalloc is gone — `PageAlloc`'s metadata moved
// to raw `mmap`, so mheap and mcentral now need nothing but `Mmap`,
// which is real on this target from M1. Both come online here.
//
// The 320 GiB `MAP_NORESERVE` arena reservation was the one thing that
// looked likely to fail on a 16 KiB-page kernel with no overcommit
// accounting to opt out of. Measured before relying on it: macOS
// returns a mapping at 0x70_0000_0000 for exactly the size
// `map_arena(MAX_ARENA_CHUNKS)` asks for.
//
// After step 7: the boot signal handlers, SIGURG preemption, the
// symboliser and the SIGSEGV stack-overflow report — the Linux boot's
// tail, in its order.
//
// `symbolize::init` runs, just before the hand-off to `main` as on
// Linux, but it reads a different container: names from the mapped
// image's `LC_SYMTAB`, and `file:line` from the dSYM bundle next to the
// executable, because ld64 never puts DWARF in the linked image (see
// `symbolize/macho.rs`). Without a dSYM — a build that overrides the
// `split-debuginfo=packed` in `.cargo/config.toml`, or a binary copied
// away from its bundle — frames still get function names, but no
// `file:line`.
//
use crate::runtime::{args, flags, heap, mcentral, rand, sched};
use crate::sys;

/// First Rust code to run after dyld calls `main`.
///
/// `extern "C"` and `#[no_mangle]` so the `main` that `#[goish::main]`
/// emits into the user's crate can call it across the C ABI, under the
/// same symbol name the Linux `_start` stubs use.
///
/// Diverges: the process exits from inside, either through the user's
/// own `syscall::Exit` or through the `sys::sys_exit(0)` at the foot —
/// which is Go's `runtime.main` shape, where the program ends when
/// `main` returns and whatever else was running stops where it stands.
#[no_mangle]
pub extern "C" fn __goish_rt0(
    argc: i32,
    argv: *const *const u8,
    envp: *const *const u8,
) -> ! {
    // Stash argc/argv so `os::Args()` can decode them lazily.
    args::__set(argc, argv);

    // GOISH_* knobs, before anything reads one. `envp` arrives as an
    // argument here; the `argv + argc + 1` walk the Linux path uses is
    // an ELF stack-layout fact and does not hold on this target.
    unsafe { flags::init_from_envp(envp) };

    // The main M's thread pointer: allocate the TSD key and plant
    // `&MAIN_M.tls_self` in it. From here `current_m()` works. Same
    // position as on Linux — before the allocator, because nothing in
    // it may take a SpinLock across the `TLS_READY` flip.
    sched::setup_main_tls();

    // Seed the cheaprand state so each run starts with a different
    // `select` fairness sequence. Same position as on Linux.
    rand::init();

    // Bring the allocator online. Both steps mmap directly and neither
    // routes through `#[global_allocator]`, so there is no bootstrap
    // cycle to break — see the file header on the dlmalloc removal.
    unsafe { heap::mheap_init() };
    unsafe {
        let arena_base = heap::mheap_arena_base();
        mcentral::mcentral_init(arena_base);
    }

    // Now that the allocator is up: register the main M so a waker
    // can find it, and give it a `g0` adopting the OS stack — from
    // libpthread's bounds rather than `/proc/self/maps`.
    sched::register_m_storage(&sched::MAIN_M);
    sched::setup_main_g0();

    // One P per usable CPU (or `GOMAXPROCS`), P0 bound to the main M,
    // then a worker M for each of the rest and the sysmon thread — the
    // Linux boot's order. Both kinds of thread are pthreads here and
    // park on `__ulock` (M7; see `syscall::Futex`).
    let nprocs = sched::startup_procs();
    sched::bootstrap_ps(nprocs);
    if let Some(p0) = sched::p_at(0) {
        sched::acquirep(p0);
    }
    sched::bootstrap_workers(nprocs);

    crate::runtime::sysmon::start_sysmon();

    // SIGPIPE ignored and Go's catch-and-drop set handled, as on Linux
    // (M6). Signal handlers here are libc `sigaction` handlers entered
    // through libSystem's `_sigtramp`.
    crate::runtime::signal::install_boot_handlers();

    // SIGURG async preemption (M8): the arm64 trampoline, with the
    // SIGTRAP half that resumes it — see `preempt_asm_arm64.rs`.
    crate::runtime::preempt::install();

    // The symboliser, at the Linux boot's position: after the allocator
    // (it builds Vecs) and before any user code can call
    // `runtime::Caller` or print a panic backtrace.
    crate::runtime::symbolize::init();

    // The stack-overflow report: a fault within a guard page of the
    // running G's stack prints its `go!` spawn site and exits 2; any
    // other fault falls through to the default action. After
    // `symbolize::init`, whose tables the report's frames read.
    crate::runtime::segv::install();

    // Hand off to the user's `main` on a goroutine, as Go's
    // `runtime.main` does and as the amd64 boot does: an 8 MiB lazily
    // committed reservation, and `exit(0)` when `main` returns, killing
    // whatever else is still running.
    extern "C" {
        fn __goish_main();
    }
    sched::mark_dispatching();
    sched::newproc_with_stack_at(
        8 * 1024 * 1024,
        file!(),
        line!(),
        alloc::boxed::Box::new(|| {
            unsafe { __goish_main() };
            unsafe { sys::sys_exit(0) }
        }),
    );

    // Enter the dispatch loop on g0. Never returns: the process ends in
    // the closure above, or in the user's own `syscall::Exit`.
    sched::m_schedule_loop()
}
