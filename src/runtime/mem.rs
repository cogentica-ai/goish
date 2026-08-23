// runtime::mem — C memory intrinsics (memcpy, memset, memmove, memcmp).
//
// LLVM lowers `core::ptr::copy_nonoverlapping`, `slice::copy_from_slice`,
// and similar built-ins to direct calls to `memcpy` / `memset` / etc.
// Normally these come from libc; since we don't link it, we provide
// them here. Trivial reference implementations — the compiler still
// inlines a fast path for known sizes / alignments.

use core::ffi::{c_char, c_void};

#[no_mangle]
pub unsafe extern "C" fn memcpy(dst: *mut c_void, src: *const c_void, n: usize) -> *mut c_void {
    let dst_bytes = dst.cast::<u8>();
    let src_bytes = src.cast::<u8>();
    let mut i = 0;
    while i < n {
        *dst_bytes.add(i) = *src_bytes.add(i);
        i += 1;
    }
    dst
}

#[no_mangle]
pub unsafe extern "C" fn memmove(dst: *mut c_void, src: *const c_void, n: usize) -> *mut c_void {
    let dst_bytes = dst.cast::<u8>();
    let src_bytes = src.cast::<u8>();
    // Handle overlap by copying in the safe direction.
    if (dst as usize) < (src as usize) {
        let mut i = 0;
        while i < n {
            *dst_bytes.add(i) = *src_bytes.add(i);
            i += 1;
        }
    } else {
        let mut i = n;
        while i > 0 {
            i -= 1;
            *dst_bytes.add(i) = *src_bytes.add(i);
        }
    }
    dst
}

#[no_mangle]
pub unsafe extern "C" fn memset(dst: *mut c_void, c: i32, n: usize) -> *mut c_void {
    let dst_bytes = dst.cast::<u8>();
    let byte = c as u8;
    let mut i = 0;
    while i < n {
        *dst_bytes.add(i) = byte;
        i += 1;
    }
    dst
}

#[no_mangle]
pub unsafe extern "C" fn memcmp(a: *const c_void, b: *const c_void, n: usize) -> i32 {
    let a_bytes = a.cast::<u8>();
    let b_bytes = b.cast::<u8>();
    let mut i = 0;
    while i < n {
        let av = *a_bytes.add(i);
        let bv = *b_bytes.add(i);
        if av != bv {
            return av as i32 - bv as i32;
        }
        i += 1;
    }
    0
}

#[no_mangle]
pub unsafe extern "C" fn bcmp(a: *const c_void, b: *const c_void, n: usize) -> i32 {
    memcmp(a, b, n)
}

// strlen — was previously satisfied by dlmalloc-rs's transitive deps;
// after dropping that dependency, compiler-generated CStr/format paths
// that emit a strlen call need it from us.
#[no_mangle]
pub unsafe extern "C" fn strlen(p: *const c_char) -> usize {
    let mut n = 0;
    while *p.add(n) != 0 {
        n += 1;
    }
    n
}
