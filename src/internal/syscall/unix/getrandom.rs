// go: file internal/syscall/unix/getrandom.go decls: vgetrandom, GetRandom
//
// Deviations from getrandom[go] @ Go 1.25.5:
//
//   * `vgetrandom` is `//go:linkname runtime.vgetrandom` — the vDSO
//     `getrandom(2)` fast path, which the Go runtime wires up by
//     parsing the process's vDSO image at startup. goish's runtime does
//     not parse the vDSO, so the port answers "not supported" and every
//     call falls through to the raw syscall below. That is the same
//     branch Go takes on any kernel that does not export the vDSO
//     symbol, so no behaviour is lost — only the fast path.
//
//   * `syscall.Syscall(getrandomTrap, …)` is `syscall::syscall3(…)`.
//     goish's syscall package has no variadic `Syscall`; `syscall3` is
//     the three-argument primitive it is built on, and it returns the
//     kernel's raw `rc` rather than Go's `(r1, r2, errno)` triple —
//     a negative `rc` is Go's `errno != 0`.

#![allow(non_snake_case, non_upper_case_globals)]

use crate::error;
use crate::goslice::slice;
use crate::sync::atomic;
use crate::syscall;
use crate::{byte, int, int32, uint32, uintptr};

use super::sysnum_linux_amd64::getrandomTrap;

// go: sdk 1.25.5 internal/syscall/unix/getrandom.go:15-17 vgetrandom
/// Go: `//go:linkname vgetrandom runtime.vgetrandom`. Returns
/// `(ret, supported)`; `supported` is false when the runtime could not
/// resolve the vDSO `getrandom` entry point. goish never resolves it —
/// see the file header.
fn vgetrandom(p: &mut slice<byte>, flags: uint32) -> (int, bool) {
    let _ = (p, flags);
    return (0, false);
}

/// Go: `var getrandomUnsupported atomic.Bool` — latched once the kernel
/// answers ENOSYS so later calls skip the syscall entirely.
static getrandomUnsupported: atomic::Bool = atomic::Bool::new(false);

// go: sdk 1.25.5 internal/syscall/unix/getrandom.go:21-22 GetRandomFlag
/// A flag supported by the getrandom system call.
pub type GetRandomFlag = uintptr;

// go: sdk 1.25.5 internal/syscall/unix/getrandom.go:24-47 GetRandom
/// Call the `getrandom` system call, filling `p` with kernel randomness.
/// Returns the number of bytes written and, on failure, the errno.
pub fn GetRandom(p: &mut slice<byte>, flags: GetRandomFlag) -> (int, error) {
    // Go: ret, supported := vgetrandom(p, uint32(flags))
    let (ret, supported) = vgetrandom(p, uint32(flags));
    if supported {
        // Go: if ret < 0 { return 0, syscall.Errno(-ret) }
        if ret < 0 {
            return (0, syscall::Errno(int32(-ret)).into());
        }
        return (ret, crate::nil.into());
    }
    // Go: if getrandomUnsupported.Load() { return 0, syscall.ENOSYS }
    if getrandomUnsupported.Load() {
        return (0, syscall::ENOSYS.into());
    }
    // Go: r1, _, errno := syscall.Syscall(getrandomTrap,
    //         uintptr(unsafe.Pointer(unsafe.SliceData(p))),
    //         uintptr(len(p)), uintptr(flags))
    let n = p.Len();
    let raw: &mut [byte] = p;
    let rc = unsafe {
        syscall::syscall3(
            getrandomTrap as usize,
            raw.as_mut_ptr() as usize,
            n as usize,
            flags as usize,
        )
    };
    // Go: if errno != 0 { if errno == syscall.ENOSYS {
    //         getrandomUnsupported.Store(true) }; return 0, errno }
    if rc < 0 {
        let errno = syscall::Errno(int32(-rc));
        if errno == syscall::ENOSYS {
            getrandomUnsupported.Store(true);
        }
        return (0, errno.into());
    }
    // Go: return int(r1), nil
    return (int(rc), crate::nil.into());
}
