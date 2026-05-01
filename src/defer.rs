// defer — Go's `defer` statement, ported.
//
//   Go                                   goish
//   ──────────────────────────────────   ──────────────────────────────────
//   defer f.Close()                      defer!{ f.Close(); }
//   defer fmt.Println("done")            defer!{ Println!("done"); }
//
// Built on Rust's Drop. The `defer!` macro expands to:
//
//     let mut _deferred = defer::Guard::new(move || { <body> });
//     unsafe { _deferred.__register(); }
//
// `_deferred` lives until the end of the enclosing scope, so the closure
// runs at scope exit. Multiple `defer!`s in one scope each declare a
// fresh binding (the name is the same but Rust still keeps both alive
// — they shadow without dropping); end-of-scope drops them in reverse
// declaration order, giving Go's LIFO semantics.
//
// **Panic-safety (B.1+).** The Guard also registers itself with the
// current goroutine's cleanup list (`runtime::sched::cleanup`). On
// panic, `#[panic_handler]` walks the list and runs each registered
// callback BEFORE `gogo`-ing to the recovery point. So:
//
//   - Normal scope exit  → Drop unregisters + runs the body
//   - Panic in this G    → cleanup::run_all runs the body, gogo abandons
//                          the stack (Drop never fires)
//
// Either path executes the body exactly once. The body must not
// allocate or panic during the panic path (we're inside the panic
// handler, between the panic and the gogo).
//
// **Move discipline.** The Guard's cleanup_node holds a pointer to
// the Guard's own `f` field. The `__register()` step happens AFTER
// construction (in the macro expansion), once the Guard sits at its
// final stack location via the `let` binding. The Guard must not be
// moved after `__register()`. The macro enforces this; users who
// construct Guard directly must keep it pinned to a `let` binding.

#![allow(non_snake_case)]

use crate::runtime::sched::cleanup;

#[doc(hidden)]
pub struct Guard<F: FnOnce()> {
    f: Option<F>,
    cleanup_node: cleanup::Cleanup,
    registered: bool,
}

impl<F: FnOnce()> Guard<F> {
    #[inline]
    #[doc(hidden)]
    pub fn new(f: F) -> Self {
        Self {
            f: Some(f),
            // arg is patched by `__register` once the Guard is at its
            // final stack address; stub the callback now so the field
            // type is correct.
            cleanup_node: cleanup::Cleanup::new(run_deferred::<F>, core::ptr::null_mut()),
            registered: false,
        }
    }

    /// Register this Guard with the current goroutine's cleanup list,
    /// so the body runs on panic too. Called by the `defer!` macro
    /// AFTER the `let` binding is established (so `&mut self.f` is at
    /// a stable stack address that survives until scope exit).
    ///
    /// No-op if not on a user goroutine (g0/sysmon panics are fatal
    /// anyway; cleanup never runs there).
    ///
    /// Safety: must be called exactly once per Guard, on the same M
    /// that owns the current_g, with the Guard at its final stack
    /// location (no moves until Drop).
    #[inline]
    #[doc(hidden)]
    pub unsafe fn __register(&mut self) {
        // Patch the cleanup node's arg to point at our `f` field. The
        // `run_deferred<F>` callback will reinterpret this as
        // `*mut Option<F>` and `take()` the closure on panic.
        self.cleanup_node.arg = &mut self.f as *mut Option<F> as *mut ();
        if let Some(g_ptr) = crate::runtime::sched::current_g() {
            unsafe {
                cleanup::register(&*g_ptr.as_ptr(), &mut self.cleanup_node);
            }
            self.registered = true;
        }
    }
}

impl<F: FnOnce()> Drop for Guard<F> {
    #[inline]
    fn drop(&mut self) {
        // Unregister before running the body — if the body panics,
        // we don't want the panic_handler to find this same node and
        // double-run it (the f.take() inside run_deferred would see
        // None, but unlinking is cleaner).
        if self.registered {
            if let Some(g_ptr) = crate::runtime::sched::current_g() {
                unsafe {
                    cleanup::unregister(&*g_ptr.as_ptr(), &mut self.cleanup_node);
                }
            }
            self.registered = false;
        }
        if let Some(f) = self.f.take() {
            f();
        }
    }
}

/// Cleanup-registry callback. Invoked by `panic_handler::run_all` when
/// the goroutine panics with this Guard live. `arg` was set by
/// `__register` to point at the Guard's `Option<F>` field.
///
/// Safety: invoked only from `cleanup::run_all` with `arg` pointing
/// at a valid `Option<F>` whose owning Guard hasn't been dropped.
unsafe extern "C" fn run_deferred<F: FnOnce()>(arg: *mut ()) {
    let opt_f = arg as *mut Option<F>;
    if let Some(f) = unsafe { (*opt_f).take() } {
        f();
    }
}

/// Schedule a body of statements to run at the end of the enclosing scope.
///
/// ```ignore
/// let (f, err) = os::Open(path);
/// if err != nil { return (string(""), err); }
/// defer!{ f.Close(); }
/// // ... use f ...
/// // f.Close() runs here, even on early return — and now also on panic.
/// ```
#[macro_export]
macro_rules! defer {
    ($($body:tt)*) => {
        let mut _deferred = $crate::defer::Guard::new(move || { $($body)* });
        // SAFETY: _deferred is at its final stack location now (let
        // binding); won't move until end-of-scope Drop.
        unsafe { _deferred.__register(); }
    };
}
