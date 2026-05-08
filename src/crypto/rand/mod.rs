// crypto/rand — slim port of Go's crypto/rand package.
//
// Provides Read(b) which fills b with cryptographically secure random
// bytes from the kernel CSPRNG via SYS_GETRANDOM(2). Mirrors:
//
//     // Go: var Reader io.Reader = ...
//     // Go: func Read(b []byte) (n int, err error)
//
// Reference: src/crypto/rand/rand.go (Go 1.25).

#![allow(non_snake_case)]

extern crate alloc;

use crate::errors::{self, error};
use crate::goslice::slice;
use crate::string;
use crate::types::{byte, int};

// ─── rand.Reader — package-global io.Reader instance ──────────────────
//
// Go: `var Reader io.Reader = &reader{}` — package-global handle that
// callers pass to `io.ReadFull(rand.Reader, buf)` and friends.
//
// Goish: a unit struct whose `.Read(buf)` matches the io::Reader trait
// signature. The free `rand::Read(b)` function is the underlying
// implementation; the trait method delegates. Exposed both as the
// `Reader` static (Go-faithful call site `rand::Reader.Read(b)`) and
// as the `RandReader` type for explicit-typed slots.

/// `crypto/rand.Reader` instance. Reading from it draws bytes from
/// the kernel CSPRNG (same source as `rand::Read`).
pub struct RandReader;

impl RandReader {
    /// `Reader.Read(b)` — fills `b` with random bytes. Mirrors
    /// `io.Reader::Read` for direct call-syntax use.
    pub fn Read(&self, mut b: slice<byte>) -> (int, error) {
        Read(&mut b)
    }
}

impl crate::io::Reader for RandReader {
    fn Read(&mut self, p: &mut slice<byte>) -> (int, error) {
        Read(p)
    }
}

/// Package-level `Reader` handle — Go's `rand.Reader`.
#[allow(non_upper_case_globals)]
pub const Reader: RandReader = RandReader;

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
