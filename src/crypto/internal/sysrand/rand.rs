// go: file crypto/internal/sysrand/rand.go decls: warnBlocked, fatal, Read, urandomRead
//
// Package sysrand provides cryptographically secure random bytes from
// the operating system.
//
// Deviations from rand[go] @ Go 1.25.5:
//
//   * `println(...)` is a Go builtin that writes to stderr; goish has no
//     builtin `println`, so `warnBlocked` writes the same bytes to fd 2
//     the way the runtime's own diagnostics do.
//   * `fatal` is `//go:linkname runtime.fatal` — an abort that skips
//     deferred functions. goish's nearest equivalent is `panic!`, which
//     under `panic = "abort"` has the same effect. Same rendering as
//     `crypto/internal/fips140/cast.go`'s `fatal`.
//   * `var testingOnlyFailRead bool` is flipped from `rand_test.go` via
//     an `export_test.go` alias. goish ports no test files, so it is a
//     `const false`; the branch it guards is ported in full because it
//     is real Go code.
//   * `defer t.Stop()` is a *conditional* defer — Go registers it inside
//     the `if` but runs it when `Read` returns. goish's `defer!` is
//     Drop-based and therefore block-scoped, so the timer handle is
//     carried in a local and stopped at the same point Go's defer fires.
//     `fatal` never reaches that point, exactly as Go's abort skips it.
//   * `b = b[n:]` becomes an `off` cursor: goish subslicing copies
//     rather than aliasing, so re-slicing a buffer the callee writes
//     into would discard the bytes. Same rendering as `io::ReadAtLeast`.

#![allow(non_snake_case, non_upper_case_globals)]

use crate::error;
use crate::errors;
use crate::gonilable::nilable;
use crate::goslice::slice;
use crate::gostring::string;
use crate::os;
use crate::sync;
use crate::sync::atomic;
use crate::syscall;
use crate::time;
use crate::types::{byte, int};

use super::rand_getrandom::read;

/// Go: `var firstUse atomic.Bool` — false until the first `Read`, which
/// arms the "blocked on entropy" warning timer.
static firstUse: atomic::Bool = atomic::Bool::new(false);

// go: sdk 1.25.5 crypto/internal/sysrand/rand.go:19-21 warnBlocked
/// Go: `println("crypto/rand: blocked for 60 seconds …")`.
fn warnBlocked() {
    const MSG: &[u8] =
        b"crypto/rand: blocked for 60 seconds waiting to read random data from the kernel\n";
    syscall::Write(syscall::STDERR, MSG.as_ptr(), MSG.len());
}

// go: sdk 1.25.5 crypto/internal/sysrand/rand.go:23-26 fatal
/// Go declares this `//go:linkname fatal runtime.fatal`; the runtime
/// defines it, aborting without running deferred functions.
fn fatal(msg: string) -> ! {
    let raw: &str = msg.as_ref();
    panic!("{}", raw)
}

/// Go: `var testingOnlyFailRead bool` — set by `rand_test.go` to
/// exercise the abort path. Always false in goish; see the file header.
const testingOnlyFailRead: bool = false;

// go: sdk 1.25.5 crypto/internal/sysrand/rand.go:30-51 Read
/// Fill `b` with cryptographically secure random bytes from the
/// operating system. It always fills `b` entirely and crashes the
/// program irrecoverably if an error is encountered. The operating
/// system APIs are documented to never return an error on all but
/// legacy Linux systems.
pub fn Read(b: &mut slice<byte>) {
    // Go: if firstUse.CompareAndSwap(false, true) {
    //         t := time.AfterFunc(time.Minute, warnBlocked)
    //         defer t.Stop()
    //     }
    let mut t: Option<time::Timer> = None;
    if firstUse.CompareAndSwap(false, true) {
        // First use of randomness. Start timer to warn about
        // being blocked on entropy not being available.
        t = Some(time::AfterFunc(time::Minute, warnBlocked));
    }
    // Go: if err := read(b); err != nil || testingOnlyFailRead { … }
    let err = read(b);
    if !err.IsNil() || testingOnlyFailRead {
        let errStr: string;
        if !testingOnlyFailRead {
            errStr = err.Error();
        } else {
            errStr = string::from_static("testing simulated failure");
        }
        fatal(
            string::from_static(
                "crypto/rand: failed to read random data (see https://go.dev/issue/66821): ",
            ) + errStr,
        );
        // Go: panic("unreachable") — `fatal` is `-> !` here, so the
        // compiler already knows this point is unreachable.
    }
    // Go: `defer t.Stop()` fires here.
    if let Some(t) = t {
        t.Stop();
    }
}

// The urandom fallback is only used on Linux kernels before 3.17 and on AIX.

/// Go: `var urandomOnce sync.Once`.
static urandomOnce: sync::Once = sync::Once::new();
/// Go: `var urandomFile *os.File`.
static urandomFile: sync::Mutex<nilable<os::File>> = sync::Mutex::new(nilable::nil());
/// Go: `var urandomErr error`.
static urandomErr: sync::Mutex<error> = sync::Mutex::new(errors::nil);

// go: sdk 1.25.5 crypto/internal/sysrand/rand.go:59-77 urandomRead
/// Fill `b` from `/dev/urandom`, opening it once on first use.
pub(crate) fn urandomRead(b: &mut slice<byte>) -> error {
    // Go: urandomOnce.Do(func() { urandomFile, urandomErr = os.Open("/dev/urandom") })
    urandomOnce.Do(|| {
        let (f, e) = os::Open("/dev/urandom");
        *urandomFile.Lock() = f;
        *urandomErr.Lock() = e;
    });
    // Go: if urandomErr != nil { return urandomErr }
    let e: error = urandomErr.Lock().clone();
    if !e.IsNil() {
        return e;
    }
    let f: nilable<os::File> = urandomFile.Lock().clone();
    // Go: for len(b) > 0 { n, err := urandomFile.Read(b); … ; b = b[n:] }
    let total = b.Len();
    let mut off: int = 0;
    while off < total {
        let mut tmp = crate::make!([]byte, total - off);
        // Go: urandomFile.Read(b) — the nil case is unreachable, the
        // `urandomErr` guard above returns first.
        let (n, err) = f.Must().Read(&mut tmp);
        // Note that we don't ignore EAGAIN because it should not be
        // possible to hit for a blocking read from urandom, although
        // there were unreproducible reports of it at
        // https://go.dev/issue/9205.
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
