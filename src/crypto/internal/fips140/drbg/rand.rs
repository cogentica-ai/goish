// go: file crypto/internal/fips140/drbg/rand.go decls: Read, ReadWithReader, ReadWithReaderDeterministic
//
// Package drbg provides cryptographically secure random bytes usable by
// FIPS code. In FIPS mode it uses an SP 800-90A Rev. 1 Deterministic
// Random Bit Generator (DRBG). Otherwise, it uses the operating system's
// random number generator.
//
// Deviations from rand[go] @ Go 1.25.5:
//
//   * `fips140.Enabled` is a function in goish, not a package-level bool,
//     so the guard reads `fips140::Enabled()`. It is always false, which
//     means the DRBG path below is currently unreachable — but the body
//     is ported in full rather than collapsed to its reachable branch,
//     because the branch is real Go code and a future FIPS mode would
//     need it.

#![allow(non_snake_case)]

extern crate alloc;
use alloc::boxed::Box;

use crate::crypto::internal::entropy;
use crate::crypto::internal::fips140;
use crate::crypto::internal::randutil;
use crate::crypto::internal::sysrand;
use crate::errors;
use crate::goslice::slice;
use crate::io;
use crate::sync;
use crate::types::{byte, int};
use crate::{error, lazy::Lazy};

use super::ctrdrbg::{maxRequestSize, Counter, NewCounter, SeedSize};

// Go: rand.go:20-28
//   var drbgs = sync.Pool{New: func() any { … entropy.Depleted(…) … }}
static drbgs: Lazy<sync::Pool<Box<Counter>>> = Lazy::new(|| {
    sync::Pool::new(|| {
        // Go: var c *Counter
        //     entropy.Depleted(func(seed *[48]byte) { c = NewCounter(seed) })
        //     return c
        let mut c: Option<Counter> = None;
        entropy::Depleted(|seed: &[byte; SeedSize]| {
            c = Some(NewCounter(seed));
        });
        return Box::new(c.unwrap());
    })
});

// go: sdk 1.25.5 crypto/internal/fips140/drbg/rand.go:30-65 Read
/// Fill `b` with cryptographically secure random bytes. In FIPS mode, it
/// uses an SP 800-90A Rev. 1 Deterministic Random Bit Generator (DRBG).
/// Otherwise, it uses the operating system's random number generator.
pub fn Read(b: &mut slice<byte>) {
    // Go: if !fips140.Enabled { sysrand.Read(b); return }
    if !fips140::Enabled() {
        sysrand::Read(b);
        return;
    }

    // At every read, 128 random bits from the operating system are mixed
    // as additional input, to make the output as strong as non-FIPS
    // randomness. This is not credited as entropy for FIPS purposes, as
    // allowed by Section 8.7.2: "Note that a DRBG does not rely on
    // additional input to provide entropy, even though entropy could be
    // provided in the additional input".
    // Go: additionalInput := new([SeedSize]byte); sysrand.Read(additionalInput[:16])
    let mut additionalInput = [0u8; SeedSize];
    let mut head = slice::__from_vec(alloc::vec![0u8; 16]);
    sysrand::Read(&mut head);
    let hr: &[byte] = &head;
    additionalInput[..16].copy_from_slice(hr);
    let mut additionalInput: Option<[byte; SeedSize]> = Some(additionalInput);

    // Go: drbg := drbgs.Get().(*Counter); defer drbgs.Put(drbg)
    let mut drbg = drbgs.Get();

    // Go: for len(b) > 0 { … }
    let mut off: usize = 0;
    let total = b.Len() as usize;
    let mut out = slice::__into_vec(core::mem::replace(b, slice::__from_vec(alloc::vec![])));
    while off < total {
        // Go: size := min(len(b), maxRequestSize)
        let size = core::cmp::min(total - off, maxRequestSize);
        let reseedRequired = drbg.Generate(&mut out[off..off + size], additionalInput.as_ref());
        if reseedRequired {
            // See SP 800-90A Rev. 1, Section 9.3.1, Steps 6-8, as
            // explained in Section 9.3.2: if Generate reports a reseed is
            // required, the additional input is passed to Reseed along
            // with the entropy and then nulled before the next Generate
            // call.
            let ai = additionalInput.unwrap_or([0u8; SeedSize]);
            entropy::Depleted(|seed: &[byte; SeedSize]| {
                drbg.Reseed(seed, &ai);
            });
            additionalInput = None;
            continue;
        }
        // Go: b = b[size:]
        off += size;
    }
    *b = slice::__from_vec(out);
    drbgs.Put(drbg);
}

// Go: rand.go:67-70
//   type DefaultReader interface{ defaultReader() }
/// A sentinel type, embedded in the default [crypto/rand.Reader], used to
/// recognize it when passed to APIs that accept a rand io.Reader.
#[goish::interface]
pub trait DefaultReader {
    fn defaultReader(&self);
}

// go: sdk 1.25.5 crypto/internal/fips140/drbg/rand.go:72-87 ReadWithReader
/// Use `r` to fill `b` with cryptographically secure random bytes. It is
/// intended for use in APIs that expose a rand io.Reader.
///
/// If `r` is not the default Reader from crypto/rand,
/// [randutil::MaybeReadByte] and [fips140::RecordNonApproved] are called.
pub fn ReadWithReader(
    r: &mut (dyn io::Reader + Send + Sync + 'static),
    b: &mut slice<byte>,
) -> error {
    // Go: if _, ok := r.(DefaultReader); ok { Read(b); return nil }
    let (_, ok) = goish::cast!(r, DefaultReader);
    if ok {
        Read(b);
        return crate::nil.into();
    }

    // Go: fips140.RecordNonApproved(); randutil.MaybeReadByte(r)
    fips140::RecordNonApproved();
    randutil::MaybeReadByte(r);
    // Go: _, err := io.ReadFull(r, b); return err
    let (_, err) = io::ReadFull(r, b);
    return err;
}

// go: sdk 1.25.5 crypto/internal/fips140/drbg/rand.go:89-100 ReadWithReaderDeterministic
/// Like ReadWithReader, but it doesn't call [randutil::MaybeReadByte] on
/// non-default Readers.
pub fn ReadWithReaderDeterministic(
    r: &mut (dyn io::Reader + Send + Sync + 'static),
    b: &mut slice<byte>,
) -> error {
    // Go: if _, ok := r.(DefaultReader); ok { Read(b); return nil }
    let (_, ok) = goish::cast!(r, DefaultReader);
    if ok {
        Read(b);
        return crate::nil.into();
    }

    // Go: fips140.RecordNonApproved()
    fips140::RecordNonApproved();
    // Go: _, err := io.ReadFull(r, b); return err
    let (_, err) = io::ReadFull(r, b);
    return err;
}

// Silence the unused-import warning: errors is reached only when the
// upstream ReadFull returns one.
const _: fn(&'static str) -> error = errors::New;
const _: fn(int) -> int = |x| x;
