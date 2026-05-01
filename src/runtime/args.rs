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

/// Walk the kernel-supplied envp (located at argv + argc + 1 per the
/// Linux ELF stack layout) looking for an entry of the form `KEY=...`
/// where `KEY` matches `key`. Returns `(value, true)` on hit. The
/// returned bytes alias kernel memory and are valid for the process
/// lifetime — callers should copy as needed before storing.
pub unsafe fn envp_lookup(key: &[u8]) -> Option<&'static [u8]> {
    let raw = match get() {
        Some(r) => r,
        None => return None,
    };
    if raw.argv.is_null() {
        return None;
    }
    let envp_start = raw.argv.add(raw.argc as usize + 1);
    let mut i: usize = 0;
    loop {
        let entry = *envp_start.add(i);
        if entry.is_null() {
            return None;
        }
        // Compare against `key`, looking for "KEY=...".
        let mut j: usize = 0;
        while j < key.len() {
            if *entry.add(j) != key[j] {
                break;
            }
            j += 1;
        }
        if j == key.len() && *entry.add(j) == b'=' {
            // Found. Find the trailing NUL.
            let val_start = entry.add(j + 1);
            let mut k: usize = 0;
            // 16 KiB cap to avoid runaway.
            while k < 16 * 1024 && *val_start.add(k) != 0 {
                k += 1;
            }
            return Some(core::slice::from_raw_parts(val_start, k));
        }
        i += 1;
        if i > 4096 {
            return None;
        }
    }
}
