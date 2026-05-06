// pkginit — Goish equivalent of Go's `runtime.initTask` machinery.
//
// Mirrors `runtime/proc.go:7616-7692` (Go 1.25.5):
//
//   * Three-state machine — `0 = uninitialized`, `1 = in progress`,
//     `2 = done`. Re-entry while in-progress is the "recursive call
//     during initialization - linker skew" panic. State=2 short-
//     circuits, matching Go's idempotent re-call.
//   * Single owner. Go's `runtime.main` runs the entire init walk
//     under `lockOSThread`, on `m0`, before user goroutines start.
//     Goish ports invoke `init()` from `#[goish::main]` — also a
//     single bootstrap thread — and the runtime never spawns init
//     work onto goroutines.
//   * `run_once(f)` is the user-facing entry. It's both the per-
//     package idempotency guard AND the "linker skew" detector.
//
// **Why a state machine when `Lazy<T>` already does first-touch
// init**: `Lazy<T>` is *value-shaped* — it computes a value when first
// read. `PkgInit` is *side-effect-shaped* — it runs a closure for
// effect (registry mutations, hook setup) without producing a value.
// Lazy can't model "init this side effect before main runs" because
// nothing reads from it.
//
// **Diamond dependency handling**: if both A and B import C, A.init()
// and B.init() both call C.init(). The first wins; the second sees
// state=2 and returns. Same observable behavior as Go's linker-
// generated dependency-ordered init list.
//
// **Cross-package ordering**: each package's `init()` is responsible
// for invoking its own dependencies' `init()`s first (in import-list
// order). The transpiler emits these calls based on the Go file's
// import block. Hand-written ports do it manually — see the worked
// pattern in `opencontainers/go-digest`.

use core::sync::atomic::{AtomicU8, Ordering};

use crate::runtime::spin::SpinLock;

/// Per-package init state. Construct as a `static`:
///
/// ```ignore
/// static __PKG_INIT: PkgInit = PkgInit::new("opencontainers_go_digest");
/// ```
pub struct PkgInit {
    state: AtomicU8,
    /// Human-readable identifier for the panic message on recursive
    /// init. Typically the Go package import path (or the Rust crate
    /// name when used at the crate boundary).
    name: &'static str,
    /// Serializes concurrent first-touch attempts on the rare cross-
    /// goroutine race. The fast path (state == DONE) doesn't take
    /// this lock; only first init goes through.
    barrier: SpinLock<()>,
}

impl PkgInit {
    /// State 0 — `init()` has never been called for this package.
    pub const UNINIT: u8 = 0;
    /// State 1 — `init()` is currently running. Re-entering while in
    /// this state is a cycle (Go's "linker skew").
    pub const IN_PROGRESS: u8 = 1;
    /// State 2 — `init()` has completed.
    pub const DONE: u8 = 2;

    /// Build a fresh init slot. `name` appears in the recursive-call
    /// panic message; pass the Go package import path or the Rust
    /// crate name.
    pub const fn new(name: &'static str) -> Self {
        Self {
            state: AtomicU8::new(Self::UNINIT),
            name,
            barrier: SpinLock::new(()),
        }
    }

    /// Current state. Mostly useful for tests.
    pub fn state(&self) -> u8 {
        self.state.load(Ordering::Acquire)
    }

    /// Has `init()` finished?
    pub fn is_done(&self) -> bool {
        self.state.load(Ordering::Acquire) == Self::DONE
    }

    /// Run `f` exactly once. Subsequent calls (from the same or any
    /// other goroutine) return immediately without re-entering `f`.
    ///
    /// Panics with a clear message if invoked recursively from within
    /// `f`'s own call chain — Go's "recursive call during
    /// initialization - linker skew" diagnostic, surfaced for the
    /// goish equivalent (a port's `init()` accidentally importing
    /// itself transitively).
    pub fn run_once<F: FnOnce()>(&self, f: F) {
        // Fast path. Acquire-release pairing makes the writes inside
        // `f` visible to readers that observe state == DONE, matching
        // Go's `init` happens-before guarantee.
        if self.state.load(Ordering::Acquire) == Self::DONE {
            return;
        }

        // Same-thread recursion detector. If state is IN_PROGRESS
        // before we acquire the barrier, the only way we got here is
        // a re-entrant call from within `f` itself — Go panics with
        // "linker skew"; goish does the same.
        //
        // Cross-thread observers race past this check (their sibling
        // is mid-init), then block on `barrier.lock()` below; once
        // the first thread's `f()` returns and state flips to DONE,
        // they take the fast path on the recheck.
        if self.state.load(Ordering::Acquire) == Self::IN_PROGRESS {
            panic_recursive(self.name);
        }

        let _guard = self.barrier.lock();

        // Re-check under barrier. Another thread may have completed
        // init while we waited.
        match self.state.load(Ordering::Acquire) {
            Self::DONE => return,
            Self::IN_PROGRESS => panic_recursive(self.name),
            _ => {}
        }

        self.state.store(Self::IN_PROGRESS, Ordering::Release);
        f();
        self.state.store(Self::DONE, Ordering::Release);
    }
}

#[inline(never)]
#[cold]
fn panic_recursive(name: &'static str) -> ! {
    panic!("goish::pkginit: recursive call during init of {}", name);
}

/// Convenience — declare and drive an init slot in one expression.
///
/// ```ignore
/// goish::pkg_init_once!("opencontainers_go_digest", {
///     // dependency init first (mirrors Go's import order)
///     ::goish::pkg_init();
///     // package-level state setup
///     register_algorithms();
/// });
/// ```
///
/// Expands to:
///
/// ```ignore
/// {
///     static __PKG_INIT: ::goish::runtime::pkginit::PkgInit
///         = ::goish::runtime::pkginit::PkgInit::new("opencontainers_go_digest");
///     __PKG_INIT.run_once(|| { /* body */ });
/// }
/// ```
#[macro_export]
macro_rules! pkg_init_once {
    ($name:literal, $body:block) => {{
        static __PKG_INIT: $crate::runtime::pkginit::PkgInit =
            $crate::runtime::pkginit::PkgInit::new($name);
        __PKG_INIT.run_once(|| $body);
    }};
}
