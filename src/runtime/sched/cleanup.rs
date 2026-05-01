// runtime::sched::cleanup — per-G best-effort resource cleanup registry.
//
// Why: goish runs `panic = "abort"` (no_std + stable), so a panic does
// NOT unwind frame-by-frame running Drops. Instead, the `#[panic_handler]`
// runs cleanups synchronously, then `gogo`s to the G's recovery point
// (see `G::panic_recover`). This module provides the registry the
// handler walks.
//
// Design:
//   - `Cleanup` is a singly-linked-list node holding a `(callback, arg)`
//     pair. Nodes live in the resource owner's stack frame (no heap
//     allocation per resource).
//   - On resource acquire: `register(g, &mut node, cb, arg)` pushes the
//     node onto `g.cleanups` (LIFO).
//   - On normal resource Drop: `unregister(g, &mut node)` unlinks.
//   - On panic: `run_all(g)` walks the list head→tail (LIFO from the
//     acquire perspective — most-recently-acquired resource is freed
//     first) and calls each callback with its arg.
//
// Concurrency: a G's cleanup list is owned by the G, so all mutations
// happen on the M currently running that G. `AtomicPtr` is used only
// to ensure correct memory ordering of the head pointer between
// resource Drop and the panic handler reading it. No cross-thread
// access occurs because a panicking G is, by definition, the running G
// on its M.
//
// Limits:
//   - We catch SpinLock guards, fd-owning resources, and any opt-in
//     callers. We do NOT catch raw heap allocations (Box/Vec/String) —
//     those leak per panic. mheap will reuse the freed-via-cleanup
//     pages eventually; the bounded growth is acceptable for an HTTP
//     server use case.

use core::ptr::null_mut;
use core::sync::atomic::Ordering;

/// One link in a G's cleanup list.
///
/// Nodes are stack-allocated by the resource owner (typically inline
/// in the owner's struct). The owner registers on acquire, unregisters
/// on Drop. If the G panics between those events, the panic handler
/// walks the list and calls each registered callback to release the
/// resource synchronously.
#[repr(C)]
pub struct Cleanup {
    /// Next node toward older registrations. `null` = end of list.
    pub next: *mut Cleanup,
    /// Release callback. Called with `arg`. Must not panic, must not
    /// allocate (we may already be inside the panic handler).
    pub callback: unsafe extern "C" fn(arg: *mut ()),
    /// Opaque argument passed to `callback` — typically a pointer to
    /// the resource being released (lock atom, fd, etc.).
    pub arg: *mut (),
}

impl Cleanup {
    /// Construct an unregistered node. Caller must `register` it
    /// before relying on the panic handler to run the callback.
    pub const fn new(callback: unsafe extern "C" fn(arg: *mut ()), arg: *mut ()) -> Self {
        Cleanup {
            next: null_mut(),
            callback,
            arg,
        }
    }
}

/// Push `node` onto `g.cleanups`. The node must outlive the G's
/// reachability of it (i.e., until `unregister` or `run_all`).
///
/// Safety: `node` must point to a writable `Cleanup` struct that
/// is valid until unregistered or the G panics.
pub unsafe fn register(g: &super::g::G, node: *mut Cleanup) {
    let mut head = g.cleanups.load(Ordering::Acquire);
    loop {
        unsafe { (*node).next = head };
        match g.cleanups.compare_exchange_weak(
            head,
            node,
            Ordering::AcqRel,
            Ordering::Acquire,
        ) {
            Ok(_) => return,
            Err(observed) => head = observed,
        }
    }
}

/// Unlink `node` from `g.cleanups`.
///
/// Common case (LIFO Drop order matching LIFO acquire order): node is
/// at the head and we pop it via CAS. Uncommon case (out-of-order
/// Drop, e.g. via `mem::swap`): walk the list to find and unlink it.
///
/// Safety: `node` must currently be in `g.cleanups` (i.e. previously
/// `register`ed and not yet `run_all`'d or unregistered).
pub unsafe fn unregister(g: &super::g::G, node: *mut Cleanup) {
    let head = g.cleanups.load(Ordering::Acquire);
    if head == node {
        let next = unsafe { (*node).next };
        // Single-threaded mutation; relaxed swap is fine but use AcqRel
        // for memory model clarity.
        let _ = g.cleanups.compare_exchange(
            node,
            next,
            Ordering::AcqRel,
            Ordering::Acquire,
        );
        return;
    }
    // Walk the list looking for `node`'s predecessor.
    let mut prev = head;
    while !prev.is_null() {
        let nxt = unsafe { (*prev).next };
        if nxt == node {
            unsafe { (*prev).next = (*node).next };
            return;
        }
        prev = nxt;
    }
    // If we get here, `node` wasn't in the list. Likely a double
    // unregister; benign — just no-op.
}

/// Walk the cleanup list LIFO and call every callback. Used by
/// `#[panic_handler]` (or `on_g_panic_aborted`) to release resources
/// before abandoning the panicked frames.
///
/// Each callback runs in the panic context — no allocations, no
/// further panics. After the walk, `g.cleanups` is empty.
///
/// Safety: must only be called when no other M is mutating this G's
/// cleanup list (i.e., only on the M currently running this G, which
/// is the contract anyway).
pub unsafe fn run_all(g: &super::g::G) {
    let mut node = g.cleanups.swap(null_mut(), Ordering::AcqRel);
    while !node.is_null() {
        let cur = node;
        // Read next before invoking callback: callback may scribble
        // over the node's storage (it lives on a stack frame we're
        // about to abandon, but we'd like to walk safely first).
        let next = unsafe { (*cur).next };
        let cb = unsafe { (*cur).callback };
        let arg = unsafe { (*cur).arg };
        unsafe { cb(arg) };
        node = next;
    }
}
