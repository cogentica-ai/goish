// runtime::args — argv stash for os::Args().
//
// `__goish_rt0` calls `__set` once at startup with the kernel-supplied
// (argc, argv). Later, `os::Args()` calls `get` to read the stashed
// pointers and lazily decode them into a `slice<string>`.
//
// argv is a pointer into the auxiliary process stack mapped by the
// kernel. The pointers it holds are valid for the lifetime of the
// process, so retaining them as raw `*const *const u8` is safe.
//
// `envp_overlay` provides Setenv/Unsetenv semantics on top of the
// kernel envp without mutating it directly. The overlay is consulted
// first by `envp_lookup`; a `None` value acts as a tombstone (Unsetenv).

extern crate alloc;
use alloc::vec::Vec;

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

// Process-wide overlay for Setenv/Unsetenv. Linear-scan Vec keeps the
// lock simple; environment overrides are uncommon and small.
// `Some(value)` is a set; `None` is a tombstone (Unsetenv mask).
static OVERLAY: SpinLock<Vec<(Vec<u8>, Option<Vec<u8>>)>> = SpinLock::new(Vec::new());

/// Insert or update an overlay entry for `key`. Used by `os::Setenv`.
pub fn envp_set(key: &[u8], value: &[u8]) {
    let mut g = OVERLAY.lock();
    for (k, v) in g.iter_mut() {
        if k.as_slice() == key {
            *v = Some(value.to_vec());
            return;
        }
    }
    g.push((key.to_vec(), Some(value.to_vec())));
}

/// Mask `key` as unset. Used by `os::Unsetenv`. Future lookups will
/// return None even if the kernel envp holds the key.
pub fn envp_unset(key: &[u8]) {
    let mut g = OVERLAY.lock();
    for (k, v) in g.iter_mut() {
        if k.as_slice() == key {
            *v = None;
            return;
        }
    }
    g.push((key.to_vec(), None));
}

/// Walk the merged environment (kernel envp + overlay) and produce a
/// list of `KEY=VALUE` byte buffers. Overlay tombstones suppress the
/// kernel-supplied entry; overlay sets win for ordering (entries come
/// after kernel entries).
pub unsafe fn envp_environ() -> Vec<Vec<u8>> {
    let mut out: Vec<Vec<u8>> = Vec::new();
    // Build a quick set of overlay-shadowed keys to skip from kernel walk.
    let g = OVERLAY.lock();
    let overlay_keys: Vec<Vec<u8>> = g.iter().map(|(k, _)| k.clone()).collect();
    drop(g);

    let raw = match get() {
        Some(r) => r,
        None => Raw {
            argc: 0,
            argv: core::ptr::null(),
        },
    };
    if !raw.argv.is_null() {
        let envp_start = raw.argv.add(raw.argc as usize + 1);
        let mut i: usize = 0;
        while i < 4096 {
            let entry = *envp_start.add(i);
            if entry.is_null() {
                break;
            }
            // Find '=' offset and total NUL-terminated length.
            let mut eq: usize = 0;
            while eq < 16 * 1024 && *entry.add(eq) != b'=' && *entry.add(eq) != 0 {
                eq += 1;
            }
            let key = core::slice::from_raw_parts(entry, eq);
            // Skip if shadowed by overlay (we'll emit the overlay version below).
            let shadowed = overlay_keys.iter().any(|k| k.as_slice() == key);
            if !shadowed {
                let mut total = eq;
                if *entry.add(eq) == b'=' {
                    total = eq + 1;
                    while total < 64 * 1024 && *entry.add(total) != 0 {
                        total += 1;
                    }
                }
                let buf = core::slice::from_raw_parts(entry, total).to_vec();
                out.push(buf);
            }
            i += 1;
        }
    }
    // Append overlay sets (tombstones suppressed).
    let g = OVERLAY.lock();
    for (k, v) in g.iter() {
        if let Some(val) = v {
            let mut buf: Vec<u8> = Vec::with_capacity(k.len() + 1 + val.len());
            buf.extend_from_slice(k);
            buf.push(b'=');
            buf.extend_from_slice(val);
            out.push(buf);
        }
    }
    out
}

/// Clear the entire visible environment: install a tombstone for every
/// kernel-envp key, then drop overlay sets. Subsequent Setenv calls
/// repopulate the overlay normally.
pub unsafe fn envp_clear() {
    let mut keys_to_tombstone: Vec<Vec<u8>> = Vec::new();
    let raw = match get() {
        Some(r) => r,
        None => Raw {
            argc: 0,
            argv: core::ptr::null(),
        },
    };
    if !raw.argv.is_null() {
        let envp_start = raw.argv.add(raw.argc as usize + 1);
        let mut i: usize = 0;
        while i < 4096 {
            let entry = *envp_start.add(i);
            if entry.is_null() {
                break;
            }
            let mut eq: usize = 0;
            while eq < 16 * 1024 && *entry.add(eq) != b'=' && *entry.add(eq) != 0 {
                eq += 1;
            }
            keys_to_tombstone.push(core::slice::from_raw_parts(entry, eq).to_vec());
            i += 1;
        }
    }
    let mut g = OVERLAY.lock();
    g.clear();
    for k in keys_to_tombstone.into_iter() {
        g.push((k, None));
    }
}

/// Walk the kernel-supplied envp (located at argv + argc + 1 per the
/// Linux ELF stack layout) looking for an entry of the form `KEY=...`
/// where `KEY` matches `key`. Returns `(value, true)` on hit. The
/// returned bytes alias kernel memory and are valid for the process
/// lifetime — callers should copy as needed before storing.
///
/// The overlay (Setenv/Unsetenv) is consulted first; a None overlay
/// entry acts as a tombstone, hiding any kernel-supplied value.
pub unsafe fn envp_lookup(key: &[u8]) -> Option<&'static [u8]> {
    {
        // Scope the overlay borrow so we never hold the lock across
        // raw-pointer walks below.
        let g = OVERLAY.lock();
        for (k, v) in g.iter() {
            if k.as_slice() == key {
                match v {
                    Some(val) => {
                        // Promote overlay value to 'static via a leaked
                        // copy. Goish leaks happen at startup-only
                        // scope; Setenv calls are rare in practice.
                        let leaked: &'static [u8] =
                            alloc::boxed::Box::leak(val.clone().into_boxed_slice());
                        return Some(leaked);
                    }
                    None => return None,
                }
            }
        }
    }
    envp_lookup_kernel(key)
}

unsafe fn envp_lookup_kernel(key: &[u8]) -> Option<&'static [u8]> {
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
