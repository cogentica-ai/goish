// Milestone 9 smoke test: errors package.
//
// Exercises the M9 surface: error type, nil sentinel, errors::New,
// errors::Wrap, errors::Is, errors::Unwrap, custom ErrorTrait impl,
// chain traversal. Writes "errors: ok\n" on success.

#![no_std]
#![no_main]

use goish::errors::ErrorTrait;
use goish::{error, errors, int, nil, string, syscall};

fn die(msg: &[u8]) -> ! {
    syscall::Write(syscall::STDERR, msg.as_ptr(), msg.len());
    syscall::Exit(1);
}

fn check(cond: bool, msg: &[u8]) {
    if !cond {
        die(msg);
    }
}

// ─── Function returning (T, error) — the canonical Go shape ──────────

fn parse(s: string) -> (int, error) {
    if s == "" {
        return (0, errors::New("empty input"));
    }
    (42, nil)
}

// ─── Custom error type ───────────────────────────────────────────────

struct ParseErr {
    #[allow(dead_code)]
    line: int,
}

impl ErrorTrait for ParseErr {
    fn Error(&self) -> string {
        // M8 fmt would let us format the line number. For now, fixed.
        string("parse error")
    }
}

// ─── Wrapping error: holds an inner error, exposes via Unwrap ────────

struct WrapErr {
    msg: string,
    inner: error,
}

impl ErrorTrait for WrapErr {
    fn Error(&self) -> string {
        self.msg.clone()
    }
    fn Unwrap(&self) -> error {
        self.inner.clone()
    }
}

#[goish::main]
fn main() {
    // (1) `nil` returned from happy path; caller's `if err != nil`.
    let (n, err) = parse(string("hello"));
    check(err == nil, b"errors: nil expected on success\n");
    check(n == 42, b"errors: value wrong on success\n");

    // (2) Error returned from sad path; comparable against nil.
    let (n, err) = parse(string(""));
    check(err != nil, b"errors: non-nil expected on failure\n");
    check(n == 0, b"errors: zero value on failure\n");

    // (3) err.Error() returns the message.
    check(err.Error() == "empty input", b"errors: Error() text wrong\n");

    // (4) errors::New returns distinct values for same text (Go semantic).
    let e1 = errors::New("same");
    let e2 = errors::New("same");
    check(e1 != e2, b"errors: distinct New values must be != \n");

    // (5) ...but each is equal to itself (clone shares Arc).
    let e1_clone = e1.clone();
    check(e1 == e1_clone, b"errors: clone must equal original\n");

    // (6) Custom error type via Wrap.
    let pe = errors::Wrap(ParseErr { line: 7 });
    check(pe.Error() == "parse error", b"errors: custom Error() wrong\n");
    check(pe != nil, b"errors: custom != nil\n");

    // (7) errors::Is — sentinel match through clone.
    let sentinel = errors::New("sentinel");
    let same = sentinel.clone();
    check(errors::Is(same, sentinel.clone()), b"errors: Is(clone, sentinel) failed\n");

    // (8) errors::Is — different errors with same text are NOT equal.
    let other = errors::New("sentinel");
    check(!errors::Is(other, sentinel.clone()), b"errors: Is must use ptr identity\n");

    // (9) errors::Is — nil cases.
    check(errors::Is(nil, nil), b"errors: Is(nil, nil) must be true\n");
    check(!errors::Is(sentinel.clone(), nil), b"errors: Is(non-nil, nil) must be false\n");
    check(!errors::Is(nil, sentinel.clone()), b"errors: Is(nil, non-nil) must be false\n");

    // (10) Wrapping chain — inner is reachable via Unwrap and Is.
    let inner = errors::New("inner cause");
    let wrapped = errors::Wrap(WrapErr {
        msg: string("wrapped"),
        inner: inner.clone(),
    });
    check(errors::Is(wrapped.clone(), inner.clone()), b"errors: Is must walk Unwrap chain\n");
    check(errors::Unwrap(wrapped.clone()) == inner, b"errors: Unwrap must return inner\n");

    // (11) Unwrap of leaf returns nil.
    check(errors::Unwrap(inner) == nil, b"errors: Unwrap of leaf must be nil\n");

    // (12) Two-level wrap: outer.Unwrap.Unwrap reaches the deepest.
    let leaf = errors::New("leaf");
    let mid = errors::Wrap(WrapErr {
        msg: string("mid"),
        inner: leaf.clone(),
    });
    let outer = errors::Wrap(WrapErr {
        msg: string("outer"),
        inner: mid.clone(),
    });
    check(errors::Is(outer.clone(), leaf.clone()), b"errors: Is must walk 2 levels\n");
    check(errors::Is(outer, mid), b"errors: Is must walk 1 level\n");

    const OK: &[u8] = b"errors: ok\n";
    syscall::Write(syscall::STDOUT, OK.as_ptr(), OK.len());
}
