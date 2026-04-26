// runtime::mem — C memory intrinsics (memcpy, memset, memmove, memcmp).
//
// LLVM lowers `core::ptr::copy_nonoverlapping`, `slice::copy_from_slice`,
// and similar built-ins to direct calls to `memcpy` / `memset` / etc.
// Normally these come from libc; since we don't link it, we provide
// them here. Trivial reference implementations — the compiler still
// inlines a fast path for known sizes / alignments.

#[no_mangle]
pub unsafe extern "C" fn memcpy(dst: *mut u8, src: *const u8, n: usize) -> *mut u8 {
    let mut i = 0;
    while i < n {
        *dst.add(i) = *src.add(i);
        i += 1;
    }
    dst
}

#[no_mangle]
pub unsafe extern "C" fn memmove(dst: *mut u8, src: *const u8, n: usize) -> *mut u8 {
    // Handle overlap by copying in the safe direction.
    if (dst as usize) < (src as usize) {
        let mut i = 0;
        while i < n {
            *dst.add(i) = *src.add(i);
            i += 1;
        }
    } else {
        let mut i = n;
        while i > 0 {
            i -= 1;
            *dst.add(i) = *src.add(i);
        }
    }
    dst
}

#[no_mangle]
pub unsafe extern "C" fn memset(dst: *mut u8, c: i32, n: usize) -> *mut u8 {
    let byte = c as u8;
    let mut i = 0;
    while i < n {
        *dst.add(i) = byte;
        i += 1;
    }
    dst
}

#[no_mangle]
pub unsafe extern "C" fn memcmp(a: *const u8, b: *const u8, n: usize) -> i32 {
    let mut i = 0;
    while i < n {
        let av = *a.add(i);
        let bv = *b.add(i);
        if av != bv {
            return av as i32 - bv as i32;
        }
        i += 1;
    }
    0
}

#[no_mangle]
pub unsafe extern "C" fn bcmp(a: *const u8, b: *const u8, n: usize) -> i32 {
    memcmp(a, b, n)
}

// strlen — was previously satisfied by dlmalloc-rs's transitive deps;
// after dropping that dependency, compiler-generated CStr/format paths
// that emit a strlen call need it from us.
#[no_mangle]
pub unsafe extern "C" fn strlen(p: *const u8) -> usize {
    let mut n = 0;
    while *p.add(n) != 0 {
        n += 1;
    }
    n
}
