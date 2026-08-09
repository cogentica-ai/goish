// errors_as_smoke — exercise errors.As.
// (errors/wrap.go:97)

#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

use goish::fmt;
use goish::errors::{self, error, ErrorTrait};
use goish::gostring::string;
use goish::types::int;
use goish::{syscall};

// Custom typed error 1.
struct ParseError {
    line: int,
    col: int,
}
impl ErrorTrait for ParseError {
    fn Error(&self) -> string {
        string::from_static("parse failed")
    }
}

// Custom typed error 2.
struct IOError {
    code: int,
}
impl ErrorTrait for IOError {
    fn Error(&self) -> string {
        string::from_static("io failed")
    }
}

// Wrapper that provides Unwrap to a wrapped IOError.
struct WrappedError {
    inner: error,
}
impl ErrorTrait for WrappedError {
    fn Error(&self) -> string {
        string::from_static("wrapped: io failed")
    }
    fn Unwrap(&self) -> error {
        self.inner.clone()
    }
}

#[goish::main]
fn main() {
    let mut failed = 0;

    // 1. As of matching type at head of chain.
    {
        let e = errors::Wrap(ParseError { line: 7, col: 12 });
        match errors::As::<ParseError>(e) {
            Some(pe) => {
                if pe.line == 7 && pe.col == 12 {
                    fmt::Println!("[ 1] As head match           PASS");
                } else {
                    fmt::Println!("[ 1] As head match           FAIL line={} col={}", pe.line, pe.col);
                    failed += 1;
                }
            }
            None => {
                fmt::Println!("[ 1] As head match           FAIL None");
                failed += 1;
            }
        }
    }

    // 2. As of non-matching type returns None.
    {
        let e = errors::Wrap(ParseError { line: 1, col: 1 });
        if errors::As::<IOError>(e).is_none() {
            fmt::Println!("[ 2] As mismatch None        PASS");
        } else {
            fmt::Println!("[ 2] As mismatch None        FAIL");
            failed += 1;
        }
    }

    // 3. As walks Unwrap chain to find inner type.
    {
        let inner = errors::Wrap(IOError { code: 42 });
        let outer = errors::Wrap(WrappedError { inner });
        match errors::As::<IOError>(outer) {
            Some(io) => {
                if io.code == 42 {
                    fmt::Println!("[ 3] As walk chain           PASS");
                } else {
                    fmt::Println!("[ 3] As walk chain           FAIL code={}", io.code);
                    failed += 1;
                }
            }
            None => {
                fmt::Println!("[ 3] As walk chain           FAIL None");
                failed += 1;
            }
        }
    }

    // 4. As on nil returns None.
    {
        if errors::As::<ParseError>(errors::nil).is_none() {
            fmt::Println!("[ 4] As nil None             PASS");
        } else {
            fmt::Println!("[ 4] As nil None             FAIL");
            failed += 1;
        }
    }

    // 5. As at outer level still works (not skipped to inner).
    {
        let inner = errors::Wrap(IOError { code: 1 });
        let outer = errors::Wrap(WrappedError { inner });
        // Asking for WrappedError should match the head, not skip to inner.
        match errors::As::<WrappedError>(outer) {
            Some(_) => {
                fmt::Println!("[ 5] As outer level          PASS");
            }
            None => {
                fmt::Println!("[ 5] As outer level          FAIL");
                failed += 1;
            }
        }
    }

    // 6. As with errors::New (untyped) returns None for typed search.
    {
        let e = errors::New("plain message");
        if errors::As::<ParseError>(e).is_none() {
            fmt::Println!("[ 6] As skips New            PASS");
        } else {
            fmt::Println!("[ 6] As skips New            FAIL");
            failed += 1;
        }
    }

    // 7. Existing errors::Is still works after Any supertrait change.
    {
        let sentinel: error = errors::ErrUnsupported.into();
        let same: error = errors::ErrUnsupported.into();
        if errors::Is(sentinel, same) {
            fmt::Println!("[ 7] Is still works          PASS");
        } else {
            fmt::Println!("[ 7] Is still works          FAIL");
            failed += 1;
        }
    }

    // 8. Errors::Unwrap still works.
    {
        let inner = errors::Wrap(IOError { code: 99 });
        let outer = errors::Wrap(WrappedError {
            inner: inner.clone(),
        });
        let unwrapped = errors::Unwrap(outer);
        if !unwrapped.IsNil() && unwrapped.Error() == inner.Error() {
            fmt::Println!("[ 8] Unwrap still works      PASS");
        } else {
            fmt::Println!("[ 8] Unwrap still works      FAIL");
            failed += 1;
        }
    }

    // 9. Two ParseErrors with different fields — As returns the head one.
    {
        let inner = errors::Wrap(ParseError { line: 100, col: 200 });
        let outer = errors::Wrap(WrappedError { inner });
        // Outer is WrappedError; As<ParseError> should walk to inner.
        match errors::As::<ParseError>(outer) {
            Some(pe) => {
                if pe.line == 100 && pe.col == 200 {
                    fmt::Println!("[ 9] As walks past wrapper   PASS");
                } else {
                    fmt::Println!("[ 9] As walks past wrapper   FAIL line={}", pe.line);
                    failed += 1;
                }
            }
            None => {
                fmt::Println!("[ 9] As walks past wrapper   FAIL None");
                failed += 1;
            }
        }
    }

    if failed == 0 {
        fmt::Println!("ok 9/9");
        syscall::Exit(0);
    } else {
        fmt::Println!("FAIL", failed, "of 9");
        syscall::Exit(1);
    }
}
