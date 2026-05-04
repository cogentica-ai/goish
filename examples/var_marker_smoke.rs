// var-marker smoke — validates the Doctrine 2 `goish::var!` macro emits
// identity-stable error sentinels usable in all four positions:
//   1. errors::Is(err, EOF)        — bare-symbol target
//   2. err == EOF, EOF == err      — PartialEq both directions
//   3. let e: error = EOF.into();  — From<Marker> for error
//   4. handle::<impl Into<error>>(EOF)  — generic API takes bare marker
//
// Identity contract: every access path (.into(), errors::Is, From,
// IsTarget::__resolve) returns a clone of the same Arc per sentinel.

#![no_std]
#![no_main]

extern crate alloc;

use goish::errors::{self, IsTarget};
use goish::{error, nil, syscall};

// ─── goish::var! at file scope, both single-line and block form ────────

goish::var! { pub EOF: error = "EOF"; }

goish::var! {
    pub ErrShortWrite: error    = "short write";
    pub ErrUnexpectedEOF: error = "unexpected EOF";
    /// Internal — not exported.
    errInvalidWrite: error      = "invalid write result";
}

// Plain const fallback in the same macro
goish::var! {
    pub MaxBufSize: goish::int = 4096;
}

// ─── Test harness ──────────────────────────────────────────────────────

fn die(msg: &[u8]) -> ! {
    syscall::Write(syscall::STDERR, msg.as_ptr(), msg.len());
    syscall::Exit(1);
}

fn check(cond: bool, msg: &[u8]) {
    if !cond { die(msg); }
}

fn read_done() -> error { EOF.into() }

fn handle<E: Into<error>>(e: E) -> error { e.into() }

#[goish::main]
fn main() {
    // ── (1) errors::Is(err, EOF) — bare-symbol target ──────────────────
    let err = read_done();
    check(errors::Is(err.clone(), EOF), b"Is(err, EOF) wrong\n");

    // ── (2) err == EOF — bare PartialEq, both directions ───────────────
    check(err == EOF, b"err == EOF wrong\n");
    check(EOF == err, b"EOF == err wrong (commutative)\n");

    // ── (3) Different errors should NOT match the EOF sentinel ─────────
    let other = errors::New("not EOF");
    check(!errors::Is(other.clone(), EOF), b"Is(other, EOF) false-positive\n");
    check(other != EOF, b"other != EOF wrong\n");

    // ── (4) From<Marker> for error — let / return / struct slot ────────
    let e: error = EOF.into();
    check(e == EOF, b"EOF.into() identity wrong\n");

    // ── (5) Identity stable across ALL access paths ────────────────────
    let a: error = EOF.into();
    let b: error = EOF.into();
    let c: error = read_done();
    let d: error = IsTarget::__resolve(&EOF);
    check(a == EOF && b == EOF && c == EOF && d == EOF, b"identity wrong\n");
    check(errors::Is(a.clone(), b.clone()), b"Is(a, b) cross-call wrong\n");
    check(errors::Is(c, d), b"Is(c, d) wrong\n");

    // ── (6) impl Into<error> public API — bare marker passes ───────────
    let routed: error = handle(EOF);
    check(routed == EOF, b"handle(EOF) identity wrong\n");

    // ── (7) errors::Is reflexive — error value still works ─────────────
    let runtime_err = errors::New("foo");
    check(errors::Is(runtime_err.clone(), runtime_err.clone()), b"Is(err,err) wrong\n");
    check(!errors::Is(runtime_err.clone(), EOF), b"Is(runtime, EOF) false-positive\n");

    // ── (8) Wrapped error — Is walks Unwrap chain ──────────────────────
    struct Wrapper { inner: error }
    impl errors::ErrorTrait for Wrapper {
        fn Error(&self) -> goish::string {
            goish::string::from_static("wrapped")
        }
        fn Unwrap(&self) -> error { self.inner.clone() }
    }
    let wrapped = errors::Wrap(Wrapper { inner: EOF.into() });
    check(errors::Is(wrapped.clone(), EOF), b"Is(wrapped, EOF) chain walk wrong\n");
    check(wrapped != EOF, b"wrapped == EOF wrong (top is wrapper, not EOF)\n");

    // ── (9) Cross-sentinel discrimination ──────────────────────────────
    // Compare via converted error (cross-marker `EOF != ErrShortWrite`
    // doesn't compile — they're orthogonal types — so funnel through
    // `error` which has PartialEq<Marker> for every marker).
    let eof_e: error      = EOF.into();
    let short_e: error    = ErrShortWrite.into();
    let unexp_e: error    = ErrUnexpectedEOF.into();
    check(eof_e != ErrShortWrite, b"EOF Arc == ErrShortWrite Arc - collapsed\n");
    check(eof_e != ErrUnexpectedEOF, b"EOF Arc == ErrUnexpectedEOF Arc - collapsed\n");
    check(short_e != ErrUnexpectedEOF, b"ErrShortWrite Arc == ErrUnexpectedEOF Arc - collapsed\n");
    let _ = unexp_e;

    let s_err: error = ErrShortWrite.into();
    check(s_err == ErrShortWrite, b"ErrShortWrite identity wrong\n");
    check(s_err != EOF, b"ErrShortWrite == EOF wrong\n");
    check(!errors::Is(s_err.clone(), EOF), b"Is(ErrShortWrite, EOF) false-positive\n");
    check(errors::Is(s_err, ErrShortWrite), b"Is(ErrShortWrite, ErrShortWrite) wrong\n");

    // ── (10) Unexported sentinel works the same way ────────────────────
    let inv_err: error = errInvalidWrite.into();
    check(inv_err == errInvalidWrite, b"errInvalidWrite identity wrong\n");

    // ── (11) Plain-const fallback in the same macro ────────────────────
    check(MaxBufSize == 4096, b"MaxBufSize const wrong\n");

    // ── (12) nil sentinel still works alongside markers ────────────────
    let nil_err: error = nil.into();
    let nil_target: error = nil.into();
    check(errors::Is(nil_err, nil_target), b"Is(nil, nil) wrong\n");
    let nil_err2: error = nil.into();
    check(!errors::Is(nil_err2, EOF), b"Is(nil, EOF) false-positive\n");

    const OK: &[u8] = b"var-marker: ok\n";
    syscall::Write(syscall::STDOUT, OK.as_ptr(), OK.len());
}
