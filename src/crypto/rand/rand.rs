// go: file crypto/rand/rand.go decls: reader.Read, fatal, Read
//
// Package rand implements a cryptographically secure random number
// generator.
//
// Deviations from rand[go] @ Go 1.25.5:
//
//   * `var Reader io.Reader` + `func init()` collapse into
//     `pub const Reader: reader`. Go's `init` picks `boring.RandReader`
//     when `boring.Enabled`, else `&reader{}`; `crypto/internal/boring`
//     is a cgo binding to BoringCrypto and goish has no cgo, so the
//     `else` arm is the only reachable one and the dynamic type of
//     `Reader` is always `*reader`. What is lost is Go's ability to
//     *reassign* `rand.Reader` — a package-level `var` of interface
//     type. goish's `hook::Hook<dyn io::Reader>` can model that, but it
//     is not a value, and every call site in this tree spells
//     `let mut r = rand::Reader;` to get a `&mut dyn io::Reader`.
//     Deferred until a port actually needs to swap the reader.
//   * `fatal` is `//go:linkname runtime.fatal`, an abort that skips
//     deferred functions; `panic!` under `panic = "abort"` is the same
//     thing. Same rendering as `crypto/internal/fips140/cast.go`.
//   * `boring.Unreachable()` is dropped with the rest of the boring
//     shim — there is no BoringCrypto build to assert we are outside of.
//   * Go's `reader` embeds `drbg.DefaultReader`, an interface with one
//     unexported method whose only job is to make the default reader
//     recognizable by type assertion. goish spells the embedding as a
//     real `impl`; the downcast registry it feeds is populated by
//     `register_rand_impls`, following the `crypto/sha1` precedent.
//
// goishlint:ignore GOISH018 init — Go's `init` exists only to choose
// between `boring.RandReader` and `&reader{}`; with no boring build the
// choice is constant and folds into the `Reader` const above.

#![allow(non_snake_case, non_upper_case_globals, non_camel_case_types)]

use crate::crypto::internal::fips140;
use crate::crypto::internal::fips140::drbg;
use crate::crypto::internal::sysrand;
use crate::error;
use crate::goslice::slice;
use crate::gostring::string;
use crate::io;
use crate::types::{byte, int};

// go: sdk 1.25.5 crypto/rand/rand.go:41-43 reader
/// Go: `type reader struct { drbg.DefaultReader }`.
pub struct reader;

/// Go: `var Reader io.Reader` — a global, shared instance of a
/// cryptographically secure random number generator. It is safe for
/// concurrent use.
///
///   - On Linux, FreeBSD, Dragonfly, and Solaris, Reader uses getrandom(2).
///   - On legacy Linux (< 3.17), Reader opens /dev/urandom on first use.
///   - On macOS, iOS, and OpenBSD Reader, uses arc4random_buf(3).
///   - On NetBSD, Reader uses the kern.arandom sysctl.
///   - On Windows, Reader uses the ProcessPrng API.
///   - On js/wasm, Reader uses the Web Crypto API.
///   - On wasip1/wasm, Reader uses random_get.
///
/// In FIPS 140-3 mode, the output passes through an SP 800-90A Rev. 1
/// Deterministric Random Bit Generator (DRBG).
pub const Reader: reader = reader;

impl io::Reader for reader {
    // go: sdk 1.25.5 crypto/rand/rand.go:45-53 reader.Read
    fn Read(&mut self, b: &mut slice<byte>) -> (int, error) {
        // Go: if fips140.Enabled { drbg.Read(b) } else { sysrand.Read(b) }
        if fips140::Enabled() {
            drbg::Read(b);
        } else {
            sysrand::Read(b);
        }
        // Go: return len(b), nil
        return (b.Len(), crate::nil.into());
    }

    // go: none — goish idiom: the hidden Any-view hook every
    // `#[goish::interface]` concrete impl overrides.
    fn __goish_as_dyn_any(&self) -> Option<&(dyn core::any::Any + Send + Sync)> {
        return Some(self);
    }
    // go: none — goish idiom: see __goish_as_dyn_any above.
    fn __goish_as_dyn_any_mut(&mut self) -> Option<&mut (dyn core::any::Any + Send + Sync)> {
        return Some(self);
    }
}

impl drbg::DefaultReader for reader {
    // go: none — goish idiom: Go gets this method by *embedding* the
    // `drbg.DefaultReader` interface in `reader`, so there is no Go
    // declaration to anchor. The embedded interface value is nil, so
    // calling it panics in Go too; nothing ever does — the method exists
    // only so `r.(drbg.DefaultReader)` succeeds.
    fn defaultReader(&self) {}

    // go: none — goish idiom: see `impl io::Reader for reader`.
    fn __goish_as_dyn_any(&self) -> Option<&(dyn core::any::Any + Send + Sync)> {
        return Some(self);
    }
    // go: none — goish idiom: see `impl io::Reader for reader`.
    fn __goish_as_dyn_any_mut(&mut self) -> Option<&mut (dyn core::any::Any + Send + Sync)> {
        return Some(self);
    }
}

// go: none — goish idiom: Go's interface satisfaction is structural and
// checked by the compiler; goish's `cast!` scans a per-trait registry
// that concrete impls opt into at runtime. Same shape as
// `crypto/sha1::register_sha1_impls`.
pub fn register_rand_impls() {
    drbg::__goish_register_DefaultReader_impl::<reader>();
}

// go: sdk 1.25.5 crypto/rand/rand.go:55-58 fatal
/// Go declares this `//go:linkname fatal runtime.fatal`.
fn fatal(msg: string) -> ! {
    let raw: &str = msg.as_ref();
    panic!("{}", raw)
}

// go: sdk 1.25.5 crypto/rand/rand.go:60-83 Read
/// Fill `b` with cryptographically secure random bytes. It never returns
/// an error, and always fills `b` entirely.
///
/// Read calls [io::ReadFull] on [Reader] and crashes the program
/// irrecoverably if an error is returned. The default Reader uses
/// operating system APIs that are documented to never return an error on
/// all but legacy Linux systems.
pub fn Read(b: &mut slice<byte>) -> (int, error) {
    // Go: if r, ok := Reader.(*reader); ok { _, err = r.Read(b) } else {
    //         bb := make([]byte, len(b)); _, err = io.ReadFull(Reader, bb)
    //         copy(b, bb) }
    // `Reader` is the concrete `reader` here (see the file header), so
    // the assertion always holds and the heap-buffer arm — which exists
    // only to keep `b` non-escaping past a user-substituted Reader — is
    // unreachable.
    let mut r = Reader;
    let (_, err) = io::Reader::Read(&mut r, b);
    // Go: if err != nil { fatal("crypto/rand: failed …" + err.Error());
    //                     panic("unreachable") }
    if !err.IsNil() {
        fatal(
            string::from_static(
                "crypto/rand: failed to read random data (see https://go.dev/issue/66821): ",
            ) + err.Error(),
        );
    }
    // Go: return len(b), nil
    return (b.Len(), crate::nil.into());
}
