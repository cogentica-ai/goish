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
pub mod lockfree_ring;
pub mod mcentral;
pub mod mheap;
mod mem;
pub mod netpoll;
pub mod note;
pub mod pkginit;
pub mod preempt;
pub mod rand;
pub mod rt_section;
pub mod sched;
pub mod segv;
pub mod signal;
pub mod symbolize;
pub mod spin;
pub mod sysmon;
pub use debug::{NumCPU, NumGoroutine, GOMAXPROCS};
pub use heap::{alloc, free, mheap_alloc_pages, mheap_capacity_pages, mheap_free_pages, realloc};

// ─── GOOS / GOARCH / Compiler — Go runtime build identifiers ─────────
//
// Go: extern.go:397 / :401 — `const GOOS string = goos.GOOS`
//                            `const GOARCH string = goarch.GOARCH`
//
// goish v1 is Linux-only, x86_64-only — these are baked at compile
// time. Compiler is "goish" (matches the Go convention of returning
// the build's compiler name; gc / gccgo / gollvm are the upstream
// values).

/// `runtime.GOOS` (extern.go:397) — operating-system target. Always
/// `"linux"` for goish v1.
pub const GOOS: &str = "linux";

/// `runtime.GOARCH` (extern.go:401) — CPU architecture target.
/// Always `"amd64"` for goish v1.
pub const GOARCH: &str = "amd64";

/// `runtime.Compiler` (extern.go:412) — name of the compiler used
/// to build this binary. Goish reports `"goish"` to distinguish from
/// upstream Go's `"gc"`.
pub const Compiler: &str = "goish";

/// `runtime.Version()` (extern.go:439) — runtime version string.
/// Goish v1 reports `"goish1.0"` while staying close to Go's format.
pub fn Version() -> crate::gostring::string {
    crate::gostring::string::from_static("goish1.0")
}

// ─── Stub fns common Go programs call ────────────────────────────────
//
// These are no-ops or constant-return stubs. They exist so user code
// that imports `runtime` for these names compiles without rewriting.
// All have line refs to the Go SDK so the contract is documented.

/// `runtime.LockOSThread()` (proc.go:4172) — wire the calling
/// goroutine to its current OS thread. Slim is a no-op: each M owns
/// its own OS thread, and the scheduler doesn't migrate Gs across Ms
/// in ways that would violate this contract for typical use cases
/// (cgo callbacks, OpenGL, locale-sensitive C libs). If real
/// thread-pinning becomes load-bearing, this fn is the hook.
pub fn LockOSThread() {
    // Slim: no-op.
}

/// `runtime.UnlockOSThread()` (proc.go:4196) — undo a prior
/// `LockOSThread`. Slim is a no-op (mirroring `LockOSThread`).
pub fn UnlockOSThread() {
    // Slim: no-op.
}

/// `runtime.NumCgoCall()` (extern.go:330) — number of cgo calls made
/// by the current process. Goish has no cgo (every call is native),
/// so this is constant `0`.
pub fn NumCgoCall() -> i64 {
    0
}

/// `runtime.GC()` (mgc.go:455) — trigger a garbage-collection cycle
/// and block until it completes. Slim has no managed GC (Vec-backed
/// slices/strings + Arc/Box for shared boxed data), so this is a
/// no-op. User code that calls `runtime.GC()` for tests / fuzz seeds
/// gets exactly the behavior it expects: an explicit "force GC now"
/// is a hint, never load-bearing.
pub fn GC() {
    // Slim: no-op.
}

/// `runtime.SetFinalizer(obj, finalizer)` (Go mfinal.go:84) — register
/// a finalizer that runs when `obj` becomes unreachable. Slim is a
/// no-op: Goish v1 uses Arc/Box + RAII (`Drop`) for resource cleanup,
/// so finalizer registration is redundant — the `Drop` impl on the
/// concrete type already runs at the correct time.
///
/// Ports calling this for OS resource teardown (file descriptors,
/// locks) should rely on the type's `Drop` impl instead. Surfaced by
/// porting fluxcd/pkg/lockedfile, which uses SetFinalizer to ensure a
/// lock file gets closed; the goish File's Drop handles that already.
pub fn SetFinalizer<T, F>(_obj: T, _finalizer: F) {
    // Slim: no-op. Drop handles cleanup.
}

// go: sdk 1.25.5 runtime/panic.go:603-622 Goexit
/// Go: "Goexit terminates the goroutine that calls it. No other
/// goroutine is affected. Goexit runs all deferred calls before
/// terminating the goroutine. Because Goexit is not a panic, any
/// recover calls in those deferred functions will return nil.
///
/// Calling Goexit from the main goroutine terminates that goroutine
/// without func main returning. Since func main has not returned,
/// the program continues execution of other goroutines. If all other
/// goroutines exit, the program crashes.
///
/// It crashes if called from a thread not created by the Go runtime."
///
/// This is what `testing.T`'s `FailNow`, `Fatal`, `Fatalf` and `Skip`
/// are built on: end this test's goroutine, leave the suite running.
///
/// **Deviation — which deferred work runs.** Go unwinds frame by
/// frame and runs every deferred call. goish builds with
/// `panic = "abort"` and has no frame-level unwind tables, so the
/// termination is a `gogo` to the G's recovery point, which abandons
/// the intervening frames without running their `Drop` impls. What
/// does run is the per-G `cleanups` registry (`SpinLock` guards,
/// fd-owning resources — the same set the panic path releases), and
/// it runs here, before the jump, while those frames are still
/// intact. Callers needing more than that must run it themselves
/// before calling Goexit, which is what `testing`'s `T` does with its
/// own cleanup stack.
///
/// **Deviation — no main goroutine.** goish's `#[goish::main]` body is
/// not a goroutine (it is the bootstrap thread), so there is no
/// "terminates main without returning" case. Called from there — or
/// from any thread with no current G — this panics rather than
/// crashing silently, matching Go's "crashes if called from a thread
/// not created by the Go runtime".
pub fn Goexit() -> ! {
    // Go: the _panic object with p.goexit = true exists so a recover()
    // in a deferred call can be recognized and refused. goish's
    // `recover!()` reads `g.panicking`, which we deliberately leave
    // false — a Goexit is not a panic, so recover sees nil, as Go
    // documents.
    if sched::is_tls_ready() {
        if let Some(g_ptr) = sched::current_g() {
            let g = unsafe { &*g_ptr.as_ptr() };
            if g.panic_recover.rsp != 0 {
                g.goexiting
                    .store(true, core::sync::atomic::Ordering::Release);
                // Release registered resources while the frames that
                // registered them are still valid. Same ordering the
                // `#[panic_handler]` uses, and for the same reason:
                // the nodes live in those frames.
                unsafe { sched::cleanup::run_all(g) };
                // Re-enter this G at the top of its own stack and
                // chain to `goexit`, so the scheduler reclaims it
                // normally and every other goroutine keeps running.
                unsafe { sched::gogo(&g.panic_recover) };
            }
        }
    }
    panic!("runtime::Goexit called outside a goroutine");
}

/// `runtime.GOROOT()` (extern.go:285) — directory containing the
/// Go installation. Goish doesn't ship as a tree (single-binary
/// rlib), so this returns `""` to mirror Go's "not set" sentinel.
/// Deprecated in Go 1.24+.
pub fn GOROOT() -> crate::gostring::string {
    crate::gostring::string::from_static("")
}

/// `runtime.GoroutineProfile(p)` (mprof.go:889) — collect a stack
/// trace of every active goroutine. Slim returns `(0, false)` —
/// no profile collected, never enough room in any caller buffer —
/// so users branch on the "not enough room" path and skip profiling.
pub fn GoroutineProfile(_p: crate::goslice::slice<()>) -> (crate::types::int, bool) {
    // Slim: profile collection deferred — no goroutine stack walker.
    (0, false)
}

// ─── Caller / FuncForPC — stack-frame introspection ──────────────────
//
// Go: `runtime.Caller(skip)` (extern.go:315) returns
// `(pc uintptr, file string, line int, ok bool)` for the call site
// `skip` frames up the stack. `runtime.Callers(skip, pcs)`
// (extern.go:338) fills `pcs` with return PCs of the goroutine's
// frames. `runtime.FuncForPC(pc)` (symtab.go) maps a PC to a `*Func`.
//
// Both are implemented via a frame-pointer walk. The build forces
// frame pointers (`-C force-frame-pointers=yes`), so every function
// has a valid `rbp` chain — `[rbp]` is the saved RBP, `[rbp+8]` is the
// return PC. `runtime::segv::walk_frames` does the bounds-checked walk.
//
// Both must run on a real goroutine: the walk is bounded against the
// running G's live stack window (`active_stack_lo`/`active_stack_hi`).
// On g0 / the bootstrap thread (`current_g()` is `None`) there is no
// safe bound, so `Caller` returns `ok == false` and `Callers` returns
// `0` — matching Go's "unable to recover information" contract.

/// Read the caller's frame-base pointer (`rbp`). `#[inline(never)]` so
/// the call site emits a real `call` and this helper sets up its own
/// SysV frame (`push rbp; mov rbp, rsp`) — the returned value is *this
/// helper's* `rbp`. The caller accounts for that extra frame in `skip`.
#[inline(never)]
fn caller_rbp() -> u64 {
    let v: u64;
    // SAFETY: a plain register read; no memory touched, no stack use.
    unsafe {
        core::arch::asm!("mov {}, rbp", out(reg) v, options(nomem, nostack));
    }
    v
}

/// Walk the current goroutine's `rbp` chain into `out`, returning the
/// number of return PCs collected. `out[0]` is the return PC of the
/// frame for the function that called `collect_frames` — i.e. the
/// goish `Caller`/`Callers` body. Returns `0` (and writes nothing)
/// when not running on a goroutine.
///
/// `#[inline(never)]` so it always occupies a real, separate frame —
/// the `skip` arithmetic in `Caller`/`Callers` depends on exactly one
/// helper frame (this one) sitting between the public API body and the
/// frame `out[0]` should name.
#[inline(never)]
fn collect_frames(out: &mut [u64; segv::MAX_FRAMES]) -> usize {
    // The running goroutine bounds the walk. No goroutine → no safe
    // bound; refuse the walk.
    let g_ptr = match sched::current_g() {
        Some(g) => g,
        None => return 0,
    };
    let g = unsafe { g_ptr.as_ref() };
    let stack_lo = g
        .active_stack_lo
        .load(core::sync::atomic::Ordering::Acquire);
    let stack_hi = g
        .active_stack_hi
        .load(core::sync::atomic::Ordering::Acquire);
    if stack_hi <= stack_lo {
        return 0;
    }
    // `caller_rbp` is `#[inline(never)]`: it has its own frame, so the
    // value it returns is its own `rbp`. Walking from there yields, at
    // index 0, the return PC of `caller_rbp`'s caller — which is this
    // `collect_frames`. Step past `collect_frames`'s own frame so that
    // `out[0]` lands on the public `Caller`/`Callers` body's frame.
    let rbp = caller_rbp();
    let n = segv::walk_frames(rbp, stack_lo, stack_hi, out);
    if n == 0 {
        return 0;
    }
    // Drop index 0 (the `collect_frames` frame) by shifting left.
    let kept = n - 1;
    let mut i = 0;
    while i < kept {
        out[i] = out[i + 1];
        i += 1;
    }
    while i < segv::MAX_FRAMES {
        out[i] = 0;
        i += 1;
    }
    kept
}

/// `runtime.Caller(skip)` (Go 1.25 extern.go:315) — reports file/line
/// information about a function invocation on the calling goroutine's
/// stack. `skip == 0` identifies the caller of `Caller`. Returns the
/// program counter, file name, line number, and an `ok` flag that is
/// `false` when the information could not be recovered.
///
/// Implemented by walking the `rbp` chain. `ok` reflects whether a
/// *frame* was recovered, not whether symbolization succeeded — if the
/// symboliser misses, the recovered `pc` is still returned with
/// `ok == true`, an empty `file`, and `line == 0`.
pub fn Caller(
    skip: crate::types::int,
) -> (crate::types::uintptr, crate::gostring::string, crate::types::int, bool) {
    let empty = crate::gostring::string::from_static("");
    if skip < 0 {
        return (0, empty, 0, false);
    }
    let mut frames = [0u64; segv::MAX_FRAMES];
    let n = collect_frames(&mut frames);
    // `frames[0]` is the `Caller` body's own frame; `skip == 0` wants
    // the caller of `Caller`, i.e. `frames[1]`. Generally `frames[skip
    // + 1]`.
    let skip_us = match usize::try_from(skip) {
        Ok(s) => s,
        Err(_) => return (0, empty, 0, false),
    };
    let idx = match skip_us.checked_add(1) {
        Some(i) => i,
        None => return (0, empty, 0, false),
    };
    if idx >= n {
        return (0, empty, 0, false);
    }
    let pc = frames[idx];
    if pc == 0 {
        return (0, empty, 0, false);
    }
    let mut info = symbolize::SymInfo::default();
    let mut file = empty;
    let mut line: crate::types::int = 0;
    if symbolize::symbolize(pc, &mut info) {
        if info.file_len > 0 {
            file = crate::gostring::string::from_bytes(&info.file[..info.file_len]);
        }
        line = crate::types::int::from(info.line);
    }
    (pc, file, line, true)
}

/// `runtime.Callers(skip, pcs)` (Go 1.25 extern.go:338) — fills `pcs`
/// with the return program counters of function invocations on the
/// calling goroutine's stack. `skip == 0` identifies the frame for
/// `Callers` itself; `skip == 1` the caller of `Callers`. Returns the
/// number of entries written to `pcs`.
///
/// Implemented by walking the `rbp` chain. Writes at most `len(pcs)`
/// entries. Returns `0` when `pcs` is empty or when not running on a
/// goroutine (g0 / bootstrap thread — no safe stack bound).
///
/// `pcs` is taken by `&mut` — Go's `[]uintptr` is a write-through
/// header over a caller-owned array; goish's `slice` owns its backing
/// `Vec`, so the borrowed form preserves the "filled in place" contract
/// (mirrors `io::Reader::Read`, whose `p []byte` is `&mut slice<byte>`).
pub fn Callers(
    skip: crate::types::int,
    pcs: &mut crate::goslice::slice<crate::types::uintptr>,
) -> crate::types::int {
    let cap = pcs.Len();
    if cap <= 0 || skip < 0 {
        return 0;
    }
    let cap_us = match usize::try_from(cap) {
        Ok(c) => c,
        Err(_) => return 0,
    };
    let start = match usize::try_from(skip) {
        Ok(s) => s,
        Err(_) => return 0,
    };
    let mut frames = [0u64; segv::MAX_FRAMES];
    let n = collect_frames(&mut frames);
    // `frames[0]` is the `Callers` body's own frame, which is exactly
    // Go's `skip == 0`. Write `frames[skip ..]` into `pcs`.
    if start >= n {
        return 0;
    }
    let avail = n - start;
    let want = if avail < cap_us { avail } else { cap_us };
    let mut i = 0;
    while i < want {
        let pc = frames[start + i];
        if pc == 0 {
            break;
        }
        let slot = match crate::types::int::try_from(i) {
            Ok(v) => v,
            Err(_) => break,
        };
        pcs[slot] = pc;
        i += 1;
    }
    crate::types::int::try_from(i).unwrap_or(0)
}

/// `runtime.Func` (Go 1.25 symtab.go) — opaque handle returned by
/// `FuncForPC`. Goish stub is a unit struct; `.Name()` always returns
/// `""` (matches Go's behaviour for an unknown PC).
#[derive(Clone, Copy)]
pub struct Func {
    _priv: (),
}

impl Func {
    /// `(*Func).Name()` (symtab.go) — qualified function name. Goish
    /// stub returns the empty string until real symbolization lands.
    pub fn Name(&self) -> crate::gostring::string {
        crate::gostring::string::from_static("")
    }
}

/// `runtime.FuncForPC(pc)` (Go 1.25 symtab.go) — slim stub returning
/// `None` for any PC since goish has no symbol table. Callers that
/// guard `if fp != nil { name = fp.Name() }` get the empty-name path.
pub fn FuncForPC(_pc: crate::types::uintptr) -> Option<Func> {
    None
}

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

    // M17b-ε.α: allocate main M's g0 after the allocator is online.
    // setup_main_g0 parses /proc/self/maps for the main thread's
    // [stack] mapping and constructs g0 with that as a non-owning
    // adopted Stack. Workers allocate their g0 in `spawn_worker_m`.
    sched::setup_main_g0();

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

    // Initialise the in-process DWARF symboliser. Mmaps
    // `/proc/self/exe` and pre-builds (PC → fn_name) and
    // (PC → file:line) lookup tables. Used by the SIGSEGV handler to
    // emit Go-style symbolised backtraces. Heavy-ish at startup
    // (parses .debug_line for every CU); skipped for `cargo build
    // --release` once we strip DWARF.
    symbolize::init();

    // Install the SIGSEGV stack-overflow handler. Reads spawn-site
    // info from the side table populated by `newproc_at` /
    // `newproc_with_stack_at` and prints an actionable diagnostic
    // when a goroutine overflows its stack. Genuine memory bugs that
    // don't fall within a known stack region chain to the default
    // handler so the user still gets a core dump.
    segv::install();

    // Hand off to the user's main. The proc-macro #[goish::main]
    // generates a #[no_mangle] extern "C" fn __goish_main wrapping the
    // user's body, so the linker resolves this `extern` block to it.
    //
    // Mirror Go's `runtime.main`: the user's `main` runs on a regular
    // goroutine (the "main goroutine"), NOT directly on m0's g0
    // scheduler stack. Running it on a G means `current_g()` is set
    // while user code executes, so blocking primitives (channel
    // send/recv, sync.WaitGroup.Wait, sync.Mutex contention) can park
    // and resume like in Go. Running it on g0 — as the previous direct
    // call did — left `current_g() == None`, so any blocking channel op
    // from `main`/test code fatal'd with "outside of any goroutine".
    //
    // The main goroutine gets a generous 8 MiB reservation (large
    // `new_sized` path: lazily committed, guard page below) — main
    // often hosts the deepest inline call chains, and the virtual
    // size costs nothing until touched.
    extern "C" {
        fn __goish_main();
    }
    // Go's `runtime.main` ends `main_main(); … exit(0)` — the program
    // terminates when `main` RETURNS, and whatever goroutines are still
    // running are killed where they stand. goish previously let the
    // main goroutine exit like any other and left the process alive
    // until `LIVE_G_COUNT == 0`, which is not Go's rule and is not
    // reachable in general: one leaked goroutine hangs the process
    // forever.
    //
    // It bit exactly that way. `sysrand.Read` arms Go's 60-second
    // first-use "blocked on entropy" warning and stops it on the way
    // out; goish's `Timer::Stop` cancels the watcher but not the
    // sleeper underneath it (see the note in time/mod.rs), so every
    // binary that drew randomness and returned from `main` sat for a
    // further 60 s before exiting 0. Ten declared examples did, which
    // is the whole of what CI reports as `timeout: 10, fail: 0`.
    //
    // Killing live goroutines at main's return is the Go-faithful half
    // of the fix and the half that generalises — a leaked goroutine
    // stops being able to hold the process at all. The sleeper leak
    // itself is still worth closing, and is tracked separately.
    sched::newproc_with_stack_at(
        8 * 1024 * 1024,
        file!(),
        line!(),
        alloc::boxed::Box::new(|| {
            unsafe { __goish_main() };
            // Go: `exit(0)` at the foot of runtime.main.
            crate::syscall::Exit(0);
        }),
    );

    // M17b-ε: enter the dispatch loop on g0 — never returns. It
    // dispatches the main goroutine (and any others), and the main M
    // exits via `Exit(0)` from `maybe_exit_main_m` once
    // `LIVE_G_COUNT == 0` (or the user calls syscall::Exit directly).
    // Workers keep parking indefinitely, reaped by the main M's
    // exit_group(2). (`m_schedule_loop`, not the public `schedule()`:
    // the public entry is `-> ()` because from inside a goroutine it
    // acts as a returning drain barrier.)
    sched::m_schedule_loop()
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
    // Render the panic message via `core::fmt::Write` into a fixed
    // 1 KiB stack buffer. Truncates if longer; that's fine — the
    // first few hundred bytes are usually enough to identify the
    // panic. Helps diagnose location-ambiguous panics where inlining
    // attributes the file:line to an outer frame.
    {
        use core::fmt::Write;
        struct StderrBuf {
            buf: [u8; 1024],
            len: usize,
        }
        impl core::fmt::Write for StderrBuf {
            fn write_str(&mut self, s: &str) -> core::fmt::Result {
                let bytes = s.as_bytes();
                let room = self.buf.len() - self.len;
                let n = bytes.len().min(room);
                self.buf[self.len..self.len + n].copy_from_slice(&bytes[..n]);
                self.len += n;
                Ok(())
            }
        }
        let mut buf = StderrBuf { buf: [0u8; 1024], len: 0 };
        const PRE: &[u8] = b"  msg: ";
        syscall::Write(syscall::STDERR, PRE.as_ptr(), PRE.len());
        let _ = write!(&mut buf, "{}", info.message());
        syscall::Write(syscall::STDERR, buf.buf.as_ptr(), buf.len);
        const NL: &[u8] = b"\n";
        syscall::Write(syscall::STDERR, NL.as_ptr(), NL.len());

        // Dump SIGURG-handler counters + current m.locks at panic.
        // Helps separate "async-preempt was the trigger" from
        // "something else panicked" for race-class bugs.
        let mut buf2 = StderrBuf { buf: [0u8; 1024], len: 0 };
        let inv = crate::runtime::preempt::invocations();
        let inj = crate::runtime::preempt::injections();
        let (sk_locks, sk_tramp, sk_parking, sk_no_curg, sk_not_running, sk_sp) =
            crate::runtime::preempt::skip_breakdown();
        let mlocks = crate::runtime::sched::current_m_locks();
        let _ = write!(
            &mut buf2,
            "  preempt: inv={inv} inj={inj} skip(locks={sk_locks},tramp={sk_tramp},park={sk_parking},nocurg={sk_no_curg},notrun={sk_not_running},sp={sk_sp}) m.locks={mlocks}\n"
        );
        syscall::Write(syscall::STDERR, buf2.buf.as_ptr(), buf2.len);

        // Dump the last few injection PCs — correlate with the
        // user-code site preempted right before this panic.
        let mut pcs = [0u64; 8];
        let n = crate::runtime::preempt::snapshot_injection_pcs(&mut pcs);
        if n > 0 {
            let mut buf3 = StderrBuf { buf: [0u8; 1024], len: 0 };
            let _ = write!(&mut buf3, "  inject_pcs(newest-first):");
            for k in 0..n {
                let _ = write!(&mut buf3, " 0x{:x}", pcs[k]);
            }
            let _ = write!(&mut buf3, "\n");
            syscall::Write(syscall::STDERR, buf3.buf.as_ptr(), buf3.len);
        }
    }

    // Per-G panic recovery (Phase B). If we're on a user goroutine
    // with `panic_recover` installed by `g_entry`, run any registered
    // cleanups (release fds, unlock SpinLocks, etc.), then `gogo` to
    // the recovery point. The recovery fn (`on_g_panic_aborted`)
    // chains to `goexit` so the scheduler reclaims this G normally
    // and other goroutines keep running.
    //
    // Skipped when:
    //   - TLS isn't set up yet (panic during early `__goish_rt0`)
    //   - We're on g0 / scheduler stack (no curg) — runtime-internal
    //     panic, fatal
    //   - The G doesn't have a recovery installed (rsp==0) — either
    //     before `g_entry` planted it, or after the user closure
    //     returned and we cleared it
    //
    // Falls through to `Exit(2)` in those cases.
    if sched::is_tls_ready() {
        if let Some(g_ptr) = sched::current_g() {
            let g = unsafe { &*g_ptr.as_ptr() };
            if g.panic_recover.rsp != 0 {
                // Mark this G as panicking BEFORE running cleanups so
                // `recover!()` inside `defer!` bodies can distinguish
                // the panic path from normal scope exit. Cleared by
                // `on_g_panic_aborted` after the gogo lands.
                g.panicking.store(true, core::sync::atomic::Ordering::Release);
                // Capture the panic value (rendered from `PanicInfo`)
                // for `recover!()` to retrieve. We render through a
                // bounded buffer to avoid allocator pressure during
                // panic; the buffer feeds an `errors::New(<message>)`
                // call that copies into a heap string. Bounded at
                // 1 KiB; longer panic messages truncate.
                {
                    use core::fmt::Write;
                    struct CaptureBuf {
                        buf: [u8; 1024],
                        len: usize,
                    }
                    impl core::fmt::Write for CaptureBuf {
                        fn write_str(&mut self, s: &str) -> core::fmt::Result {
                            let bytes = s.as_bytes();
                            let room = self.buf.len() - self.len;
                            let n = bytes.len().min(room);
                            self.buf[self.len..self.len + n].copy_from_slice(&bytes[..n]);
                            self.len += n;
                            Ok(())
                        }
                    }
                    let mut cap_buf = CaptureBuf { buf: [0u8; 1024], len: 0 };
                    let _ = write!(&mut cap_buf, "{}", info.message());
                    let s = core::str::from_utf8(&cap_buf.buf[..cap_buf.len]).unwrap_or("");
                    // Build an owned goish::string from the borrowed
                    // panic message before handing to errors::New
                    // (which requires non-borrowed input).
                    let owned: crate::string = crate::string::from(s);
                    let e = crate::errors::New(owned);
                    *g.panic_value.lock() = Some(e);
                }
                // Walk cleanups while the panicked frames are still
                // intact — the cleanup nodes live there and will be
                // abandoned by the gogo. Callbacks must not allocate
                // or panic.
                unsafe { sched::cleanup::run_all(g) };
                // Jump to the recovery fn on this G's clean stack.
                // Never returns.
                unsafe { sched::gogo(&g.panic_recover) };
            }
        }
    }
    syscall::Exit(2)
}

// Required because core's DWARF unwind tables reference this symbol,
// even though we build with `panic = "abort"`. It's never actually
// invoked at runtime — provide an empty no-mangle stub so the linker
// is satisfied.
#[no_mangle]
pub extern "C" fn rust_eh_personality() {}
