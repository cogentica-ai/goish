// defer — Go's `defer` statement, ported.
//
//   Go                                   goish
//   ──────────────────────────────────   ──────────────────────────────────
//   defer f.Close()                      defer!{ f.Close(); }
//   defer fmt.Println("done")            defer!{ Println!("done"); }
//
// Built on Rust's Drop. The `defer!` macro expands to:
//
//     let _deferred = defer::Guard::new(move || { <body> });
//
// `_deferred` lives until the end of the enclosing scope, so the closure
// runs at scope exit. Multiple `defer!`s in one scope each declare a
// fresh binding (the name is the same but Rust still keeps both alive
// — they shadow without dropping); end-of-scope drops them in reverse
// declaration order, giving Go's LIFO semantics.
//
// v1 deviations from Go's `defer`:
//
//   * **No panic recovery.** goish builds with `panic = "abort"`, so
//     panics do not unwind and drops do not run on panic. `defer!` is
//     for normal-control-flow cleanup; failure paths use the
//     `if err != nil { return ... }` idiom from M9.
//   * **Move capture.** The macro uses `move ||`, so the closure
//     captures values by ownership/copy at defer-time. This matches
//     Go's argument evaluation at defer-time. To observe a value
//     mutated after the defer, capture a reference manually (e.g., via
//     `Cell` or `RefCell` from `core::cell`).

#![allow(non_snake_case)]

#[doc(hidden)]
pub struct Guard<F: FnOnce()> {
    f: Option<F>,
}

impl<F: FnOnce()> Guard<F> {
    #[inline]
    #[doc(hidden)]
    pub fn new(f: F) -> Self {
        Self { f: Some(f) }
    }
}

impl<F: FnOnce()> Drop for Guard<F> {
    #[inline]
    fn drop(&mut self) {
        if let Some(f) = self.f.take() {
            f();
        }
    }
}

/// Schedule a body of statements to run at the end of the enclosing scope.
///
/// ```ignore
/// let (f, err) = os::Open(path);
/// if err != nil { return (string(""), err); }
/// defer!{ f.Close(); }
/// // ... use f ...
/// // f.Close() runs here, even on early return.
/// ```
#[macro_export]
macro_rules! defer {
    ($($body:tt)*) => {
        let _deferred = $crate::defer::Guard::new(move || { $($body)* });
    };
}
