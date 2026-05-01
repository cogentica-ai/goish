// crypto/rand — slim port of Go's crypto/rand package.
//
// Provides Read(b) which fills b with cryptographically secure random
// bytes from the kernel CSPRNG via SYS_GETRANDOM(2). Mirrors:
//
//     // Go: var Reader io.Reader = ...
//     // Go: func Read(b []byte) (n int, err error)
//
// goish exposes only the free Read function — no Reader interface
// instance — because the per-call signature is what most callers
// (boundary generation, token generation) reach for.
//
// Reference: src/crypto/rand/rand.go (Go 1.25).

#![allow(non_snake_case)]

extern crate alloc;

use crate::errors::{self, error};
use crate::goslice::slice;
use crate::string;
use crate::types::{byte, int};

/// `crypto/rand.Read(b)` — fill `b` with random bytes from the kernel
/// CSPRNG. Returns `(len(b), nil)` on success; on failure (the kernel
/// CSPRNG isn't ready yet, or the syscall returns an error), returns
/// `(n, err)` where `n` is the number of bytes already filled before
/// the error.
pub fn Read(b: &mut slice<byte>) -> (int, error) {
    let want = b.Len();
    if want == 0 {
        return (0, errors::nil);
    }
    // We need a contiguous &mut [u8] for the syscall. slice<byte> is
    // already backed by a Vec<u8>, but we copy through a temp Vec to
    // avoid leaking its raw pointer.
    let mut tmp: alloc::vec::Vec<u8> = alloc::vec![0u8; want as usize];
    let mut filled: int = 0;
    while filled < want {
        let remaining = (want - filled) as usize;
        let n = crate::syscall::Getrandom(
            unsafe { tmp.as_mut_ptr().add(filled as usize) },
            remaining,
            0,
        );
        if n < 0 {
            // Errno path. Surface the count we've already filled so the
            // caller can use the partial result if it's enough.
            for i in 0..filled {
                b[i] = tmp[i as usize];
            }
            return (filled, errors::New(string("crypto/rand: getrandom failed")));
        }
        if n == 0 {
            // Shouldn't happen — getrandom blocks until the pool is
            // ready unless GRND_NONBLOCK is set. Treat as EOF-ish.
            break;
        }
        filled += n as int;
    }
    for i in 0..filled {
        b[i] = tmp[i as usize];
    }
    (filled, errors::nil)
}
