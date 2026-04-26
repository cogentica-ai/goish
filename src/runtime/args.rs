// runtime::args — argv stash for os::Args().
//
// `__goish_rt0` calls `__set` once at startup with the kernel-supplied
// (argc, argv). Later, `os::Args()` calls `get` to read the stashed
// pointers and lazily decode them into a `slice<string>`.
//
// argv is a pointer into the auxiliary process stack mapped by the
// kernel. The pointers it holds are valid for the lifetime of the
// process, so retaining them as raw `*const *const u8` is safe.

use crate::runtime::spin::SpinLock;

#[derive(Clone, Copy)]
pub struct Raw {
    pub argc: i32,
    pub argv: *const *const u8,
}

// SAFETY: argv lives in the kernel-mapped process auxiliary region,
// valid for the entire process lifetime; the SpinLock provides the
// required Sync envelope.
unsafe impl Send for Raw {}

static SLOT: SpinLock<Option<Raw>> = SpinLock::new(None);

/// Called once from `__goish_rt0`. Subsequent calls overwrite (which
/// shouldn't happen in normal flow).
#[doc(hidden)]
pub fn __set(argc: i32, argv: *const *const u8) {
    *SLOT.lock() = Some(Raw { argc, argv });
}

/// Read the stashed (argc, argv). Returns `None` if `__goish_rt0`
/// hasn't run yet (e.g., test harness or unusual entry point).
pub fn get() -> Option<Raw> {
    *SLOT.lock()
}
