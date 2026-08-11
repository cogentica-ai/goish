// go: file crypto/internal/sysrand/rand_getrandom.go decls: read
//
// Go build tag: `dragonfly || freebsd || linux || solaris`. goish targets
// linux/amd64 only, so this is the only `read` in the package — the
// arc4random, netbsd, plan9, js, wasip1 and windows variants have no
// reachable target and are not ported.
//
// Deviations from rand_getrandom[go] @ Go 1.25.5:
//
//   * `errors.Is(err, syscall.ENOSYS)` is `err == syscall::ENOSYS`.
//     goish's `errors::Is` matches by `Arc::ptr_eq`, which a freshly
//     boxed errno never satisfies; `syscall::Errno` instead carries a
//     cross-type `PartialEq<error>` that downcasts, which is the
//     spelling AGENTS.md §8 prescribes for sentinel comparison.
//   * `b = b[n:]` becomes an `off` cursor and `b[:size]` becomes a
//     scratch chunk copied into place: goish subslicing copies rather
//     than aliasing, so a callee writing into `b[:size]` would write
//     into a temporary. Same rendering as `io::ReadAtLeast`.

#![allow(non_snake_case)]

use crate::error;
use crate::goslice::slice;
use crate::internal::syscall::unix;
use crate::math;
use crate::runtime;
use crate::syscall;
use crate::types::{byte, int};

use super::rand::urandomRead;

// go: sdk 1.25.5 crypto/internal/sysrand/rand_getrandom.go:17-64 read
/// Fill `b` from `getrandom(2)`, falling back to `/dev/urandom` when the
/// syscall is not implemented.
pub(crate) fn read(b: &mut slice<byte>) -> error {
    // Linux, DragonFly, and illumos don't have a limit on the buffer size.
    // FreeBSD has a limit of IOSIZE_MAX, which seems to be either INT_MAX or
    // SSIZE_MAX. 2^31-1 is a safe and high enough value to use for all of them.
    //
    // Note that Linux returns "a maximum of 32Mi-1 bytes", but that will only
    // result in a short read, not an error. Short reads can also happen above
    // 256 bytes due to signals. Reads up to 256 bytes are guaranteed not to
    // return short (and not to return an error IF THE POOL IS INITIALIZED) on
    // at least Linux, FreeBSD, DragonFly, and Oracle Solaris, but we don't make
    // use of that.
    let mut maxSize: int = int::from(math::MaxInt32);

    // Oracle Solaris has a limit of 133120 bytes. Very specific.
    //
    //    The getrandom() and getentropy() functions fail if: [...]
    //
    //    - bufsz is <= 0 or > 133120, when GRND_RANDOM is not set
    //
    // https://docs.oracle.com/cd/E88353_01/html/E37841/getrandom-2.html
    if runtime::GOOS == "solaris" {
        maxSize = 133120;
    }

    // Go: for len(b) > 0 { … b = b[n:] }
    let total = b.Len();
    let mut off: int = 0;
    while off < total {
        // Go: size := len(b); if size > maxSize { size = maxSize }
        let mut size = total - off;
        if size > maxSize {
            size = maxSize;
        }
        // Go: n, err := unix.GetRandom(b[:size], 0)
        let mut tmp = crate::make!([]byte, size);
        let (n, err) = unix::GetRandom(&mut tmp, 0);
        // Go: if errors.Is(err, syscall.ENOSYS) { return urandomRead(b) }
        if err == syscall::ENOSYS {
            // If getrandom(2) is not available, presumably on Linux versions
            // earlier than 3.17, fall back to reading from /dev/urandom.
            let mut tail = crate::make!([]byte, total - off);
            let e = urandomRead(&mut tail);
            for i in 0..(total - off) {
                b[off + i] = tail[i];
            }
            return e;
        }
        // Go: if errors.Is(err, syscall.EINTR) { continue }
        if err == syscall::EINTR {
            // If getrandom(2) is blocking, either because it is waiting for the
            // entropy pool to become initialized or because we requested more
            // than 256 bytes, it might get interrupted by a signal.
            continue;
        }
        // Go: if err != nil { return err }
        if !err.IsNil() {
            return err;
        }
        for i in 0..n {
            b[off + i] = tmp[i];
        }
        off += n;
    }
    return crate::nil.into();
}
