// runtime::signal — Linux signal handler infrastructure (M23).
//
// Reference: runtime/signal_unix.go,
// runtime/sigaction.go.
//
// Architecture (Go-faithful):
//
//   1. At init, we install a single process-wide signal handler
//      (`goish_sigtramp`) for each signal os::signal::Notify
//      cares about. The handler must be async-signal-safe — its
//      ONLY action is `SIGNAL_COUNT[sig].fetch_add(1)`. No locks,
//      no allocator, no chan ops.
//
//   2. Sysmon polls SIGNAL_COUNT in its existing loop. When a
//      counter increments above the last-observed value, sysmon
//      forwards the signal to every channel registered for that
//      signal via `os::signal::Notify(c, sig)`. The forward is
//      a non-blocking send (matching Go's behavior — full chans
//      drop signals).
//
//   3. The os/signal layer keeps a SpinLock'd registration table
//      (signal -> Vec<chan<i32>>). Notify pushes; Stop removes.

use alloc::vec::Vec;
use core::sync::atomic::{AtomicI64, Ordering};

use crate::gochan::chan;
use crate::runtime::spin::SpinLock;
use crate::syscall;

/// Maximum signal number we track. SIGSYS = 31; we go a bit
/// higher for room. Linux also has 32–64 for real-time signals
/// but we don't use those.
pub const MAX_SIG: usize = 64;

/// Per-signal counter bumped by the signal handler. Reads done by
/// sysmon's polling loop. AtomicI64 because we need wraparound-
/// resistant arithmetic and atomic load/store for cross-thread
/// visibility — and because `fetch_add(1, AcqRel)` is the only
/// async-signal-safe non-trivial op we can do in a Linux signal
/// handler on amd64 (atomics on aligned u64 are lock-free).
static SIGNAL_COUNT: [AtomicI64; MAX_SIG] = {
    // Const-init array: AtomicI64::new(0) repeated MAX_SIG times.
    // Use a const fn to avoid the [AtomicI64::new(0); 64] non-Copy
    // limitation.
    const fn init() -> [AtomicI64; MAX_SIG] {
        // SAFETY: AtomicI64 has the same layout as i64; zero-init
        // is the valid 0-value for AtomicI64.
        unsafe { core::mem::transmute([0i64; MAX_SIG]) }
    }
    init()
};

/// Last observed counter values (sysmon side). Compared against
/// SIGNAL_COUNT to detect deliveries since the last poll.
static SIGNAL_LAST_SEEN: [AtomicI64; MAX_SIG] = {
    const fn init() -> [AtomicI64; MAX_SIG] {
        unsafe { core::mem::transmute([0i64; MAX_SIG]) }
    }
    init()
};

/// Signal-handler entry. Called by the kernel in async context
/// when a registered signal arrives. The two operations are both
/// async-signal-safe: a lock-free atomic fetch_add, and a raw
/// futex_wake syscall (raw `syscall` instruction with no glibc /
/// TLS / allocator state in between). NO locks, NO allocation —
/// the handler can pre-empt a thread holding any of those.
///
/// Without the sysmon wake, dispatch is delayed until sysmon's
/// next periodic poll (up to 60 s when the timer heap is empty)
/// — the exact bug Go solves with `notewakeup(&sig.note)` in
/// `runtime/sigqueue.go:sigsend`.
extern "C" fn goish_sigtramp(sig: i32) {
    if (sig as usize) < MAX_SIG {
        SIGNAL_COUNT[sig as usize].fetch_add(1, Ordering::AcqRel);
        crate::runtime::sysmon::wake();
    }
}

/// Install our handler for `sig`. Idempotent: re-installing
/// over the same signal is fine.
pub fn install_handler(sig: i32) {
    let sa = syscall::Sigaction {
        sa_handler: goish_sigtramp as *const () as usize,
        sa_flags: syscall::SA_RESTORER | syscall::SA_RESTART,
        sa_restorer: syscall::SigreturnTrampoline as *const () as usize,
        sa_mask: 0,
    };
    unsafe {
        syscall::RtSigaction(sig, &sa as *const _, core::ptr::null_mut());
    }
}

/// Read-and-clear the delta since the last sysmon poll.
/// Returns how many of `sig` have arrived since the previous call.
pub fn drain_count(sig: i32) -> i64 {
    let i = sig as usize;
    if i >= MAX_SIG {
        return 0;
    }
    let now = SIGNAL_COUNT[i].load(Ordering::Acquire);
    let prev = SIGNAL_LAST_SEEN[i].swap(now, Ordering::AcqRel);
    now.wrapping_sub(prev)
}

// ─── Registration table (used by os::signal) ──────────────────────

/// A chan + the set of signals it's interested in. Stored together
/// so Stop can find the entry by chan identity.
struct Registration {
    /// We dispatch by sending the signal number on the chan.
    target: chan<i32>,
    /// Bitmap: bit i set ⟺ this chan wants signal i.
    sigs: u64,
}

static REGISTRY: SpinLock<Vec<Registration>> = SpinLock::new(Vec::new());

/// Register `c` to receive the given signals. Idempotent for any
/// (chan, sig) pair already registered. Mirrors `signal.Notify`
/// (signal_unix.go).
pub fn register(c: &chan<i32>, sigs: &[i32]) {
    let mut bitmap: u64 = 0;
    if sigs.is_empty() {
        // Go: "If no signals are provided, all incoming signals will
        // be relayed to c" (os/signal/signal.go, Notify). An empty
        // list used to build an EMPTY bitmap here, so `Notify(c)`
        // registered the channel for nothing at all and installed no
        // handler — the exact opposite of what it asks for.
        //
        // SIGKILL (9) and SIGSTOP (19) cannot be caught; asking for
        // them is not an error, they simply never arrive, and
        // rt_sigaction would fail on them anyway.
        let max_sig = MAX_SIG as i32; // goishlint:ignore GOISH005 - a signal-table bound, not a Go value
        for s in 1..max_sig {
            if s == 9 || s == 19 {
                continue;
            }
            bitmap |= 1u64 << s;
            install_handler(s);
        }
    }
    for &s in sigs {
        if (s as u32) < 64 {
            bitmap |= 1u64 << s;
            install_handler(s);
        }
    }
    let mut reg = REGISTRY.lock();
    // If c is already registered, OR the new sigs into its bitmap.
    for entry in reg.iter_mut() {
        if chans_eq(&entry.target, c) {
            entry.sigs |= bitmap;
            return;
        }
    }
    reg.push(Registration {
        target: c.clone(),
        sigs: bitmap,
    });
}

// go: none — goish-only: Go's `ignoreSignal` is a runtime
// intrinsic (runtime/sigqueue.go) reaching into sigtable. goish
// changes the kernel disposition directly.
/// Set `sig` to SIG_IGN. Mirrors the runtime side of
/// `signal.Ignore`.
///
/// Go's `ignoreSignal` changes the DISPOSITION, which is what
/// `signal.Ignored` reports and what survives a later `Reset` — see
/// `is_ignored` and the note on `signal::Reset`.
pub fn ignore_signal(sig: i32) {
    let idx = sig as u32; // goishlint:ignore GOISH005 - a table index bound, not a Go value
    if idx >= 64 || sig == 9 || sig == 19 {
        return;
    }
    let sa = syscall::Sigaction {
        sa_handler: 1, // SIG_IGN
        sa_flags: syscall::SA_RESTORER | syscall::SA_RESTART,
        sa_restorer: syscall::SigreturnTrampoline as *const () as usize,
        sa_mask: 0,
    };
    unsafe {
        syscall::RtSigaction(sig, &sa as *const _, core::ptr::null_mut());
    }
}

// go: none — goish-only: Go's `signalIgnored` is a runtime
// intrinsic. goish asks the kernel.
/// Whether `sig`'s current disposition is SIG_IGN. Mirrors Go's
/// `signalIgnored`.
///
/// Asks the kernel rather than tracking a shadow flag: a disposition
/// can also be inherited across exec, and a shadow flag would answer
/// for goish's own calls only.
pub fn is_ignored(sig: i32) -> bool {
    let idx = sig as u32; // goishlint:ignore GOISH005 - a table index bound, not a Go value
    if idx >= 64 {
        return false;
    }
    let mut old = syscall::Sigaction {
        sa_handler: 0,
        sa_flags: 0,
        sa_restorer: 0,
        sa_mask: 0,
    };
    let r = unsafe { syscall::RtSigaction(sig, core::ptr::null(), &mut old as *mut _) };
    if r < 0 {
        return false;
    }
    return old.sa_handler == 1; // SIG_IGN
}

// go: none — goish-only: the registry half of Go's `cancel`
// (os/signal/signal.go:141-170), which lives in the os/signal
// package there because the handler map does too.
/// Drop `sigs` from every registration. Mirrors the registry half of
/// Go's `cancel`, which both `signal.Ignore` and `signal.Reset` run.
/// An empty list means every signal, as Go's does.
pub fn unregister_sigs(sigs: &[i32]) {
    let mut bitmap: u64 = 0;
    if sigs.is_empty() {
        bitmap = u64::MAX;
    } else {
        for &s in sigs {
            let i = s as u32; // goishlint:ignore GOISH005 - a table index bound, not a Go value
            if i < 64 {
                bitmap |= 1u64 << s;
            }
        }
    }
    let mut reg = REGISTRY.lock();
    for entry in reg.iter_mut() {
        entry.sigs &= !bitmap;
    }
    // Go deletes the handler entry once its mask is empty.
    reg.retain(|e| e.sigs != 0);
}

/// Unregister `c` from all signals. Mirrors `signal.Stop`.
pub fn unregister(c: &chan<i32>) {
    let mut reg = REGISTRY.lock();
    reg.retain(|e| !chans_eq(&e.target, c));
}

fn chans_eq(a: &chan<i32>, b: &chan<i32>) -> bool {
    // chan<T> wraps Arc<Hchan<T>>; two chans share state iff the
    // Arcs point at the same allocation.
    a.__lock_atom() == b.__lock_atom()
}

/// Sysmon hook: called periodically. Drains per-signal counters
/// and forwards each signal to every chan registered for it.
/// Non-blocking sends — full chans drop signals (Go semantics).
pub fn dispatch_pending() {
    for sig_i in 1..MAX_SIG {
        let n = drain_count(sig_i as i32);
        if n == 0 {
            continue;
        }
        // Forward each delivery to every interested chan. We
        // collect target clones under the registry lock then send
        // outside it to avoid holding registry lock across chan ops.
        let targets: Vec<chan<i32>> = {
            let reg = REGISTRY.lock();
            reg.iter()
                .filter(|e| e.sigs & (1u64 << sig_i) != 0)
                .map(|e| e.target.clone())
                .collect()
        };
        for _ in 0..n {
            for c in &targets {
                // Non-blocking send via __try_send. Drop on full.
                let _ = c.__try_send(sig_i as i32);
            }
        }
    }
}
