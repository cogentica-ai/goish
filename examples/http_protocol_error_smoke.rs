// http_protocol_error_smoke — exercise ProtocolError + the
// ErrNotSupported / ErrUnexpectedTrailer / ErrHeaderTooLong /
// ErrShortBody / ErrMissingContentLength sentinels.
//
// Mirrors Go's request.go:43-94. The salient invariant is:
//
//   errors.Is(http.ErrNotSupported, errors.ErrUnsupported)  // true
//
// while every other ProtocolError sentinel does NOT chain to
// errors.ErrUnsupported.

#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

use goish::error;
use goish::errors;
use goish::net::http;
use goish::{syscall, Println};

#[goish::main]
fn main() {
    let mut failed = 0;

    // 1. ErrNotSupported is non-nil and stable across calls.
    {
        let a = http::ErrNotSupported();
        let b = http::ErrNotSupported();
        if !a.IsNil() && errors::Is(a, b) {
            Println!("[ 1] ErrNotSupported stable    PASS");
        } else {
            Println!("[ 1] ErrNotSupported stable    FAIL");
            failed += 1;
        }
    }

    // 2. ErrNotSupported message matches Go.
    {
        let s = http::ErrNotSupported().Error();
        if s == "feature not supported" {
            Println!("[ 2] ErrNotSupported message   PASS");
        } else {
            Println!("[ 2] ErrNotSupported message   FAIL got={}", s);
            failed += 1;
        }
    }

    // 3. ErrNotSupported chains to errors.ErrUnsupported.
    {
        if errors::Is(http::ErrNotSupported(), errors::ErrUnsupported) {
            Println!("[ 3] ErrNotSupported→ErrUnsup  PASS");
        } else {
            Println!("[ 3] ErrNotSupported→ErrUnsup  FAIL");
            failed += 1;
        }
    }

    // 4. ErrUnexpectedTrailer sentinel + message + stable.
    {
        let a = http::ErrUnexpectedTrailer();
        let s = a.Error();
        if errors::Is(a.clone(), http::ErrUnexpectedTrailer())
            && s == "trailer header without chunked transfer encoding"
        {
            Println!("[ 4] ErrUnexpectedTrailer      PASS");
        } else {
            Println!("[ 4] ErrUnexpectedTrailer      FAIL got={}", s);
            failed += 1;
        }
    }

    // 5. ErrHeaderTooLong sentinel + message.
    {
        let s = http::ErrHeaderTooLong().Error();
        if s == "header too long" {
            Println!("[ 5] ErrHeaderTooLong message  PASS");
        } else {
            Println!("[ 5] ErrHeaderTooLong message  FAIL got={}", s);
            failed += 1;
        }
    }

    // 6. ErrShortBody sentinel + message.
    {
        let s = http::ErrShortBody().Error();
        if s == "entity body too short" {
            Println!("[ 6] ErrShortBody message      PASS");
        } else {
            Println!("[ 6] ErrShortBody message      FAIL got={}", s);
            failed += 1;
        }
    }

    // 7. ErrMissingContentLength sentinel + message.
    {
        let s = http::ErrMissingContentLength().Error();
        if s == "missing ContentLength in HEAD response" {
            Println!("[ 7] ErrMissingContentLength   PASS");
        } else {
            Println!("[ 7] ErrMissingContentLength   FAIL got={}", s);
            failed += 1;
        }
    }

    // 8. Non-ErrNotSupported sentinels do NOT chain to ErrUnsupported.
    {
        let any_chain =
               errors::Is(http::ErrUnexpectedTrailer(), errors::ErrUnsupported)
            || errors::Is(http::ErrHeaderTooLong(),     errors::ErrUnsupported)
            || errors::Is(http::ErrShortBody(),         errors::ErrUnsupported)
            || errors::Is(http::ErrMissingContentLength(), errors::ErrUnsupported);
        if !any_chain {
            Println!("[ 8] other sentinels !ErrUnsup PASS");
        } else {
            Println!("[ 8] other sentinels !ErrUnsup FAIL");
            failed += 1;
        }
    }

    // 9. User-constructed ProtocolError exposes its ErrorString.
    {
        let pe = http::ProtocolError { ErrorString: goish::string("custom oops") };
        let e: errors::error = errors::Wrap(pe);
        let s = e.Error();
        if s == "custom oops" {
            Println!("[ 9] ProtocolError user ctor   PASS");
        } else {
            Println!("[ 9] ProtocolError user ctor   FAIL got={}", s);
            failed += 1;
        }
    }

    // 10. User-constructed ProtocolError does NOT chain to ErrUnsupported.
    {
        let pe = http::ProtocolError { ErrorString: goish::string("feature not supported") };
        let e: errors::error = errors::Wrap(pe);
        if !errors::Is(e, errors::ErrUnsupported) {
            Println!("[10] user pe !ErrUnsup chain   PASS");
        } else {
            Println!("[10] user pe !ErrUnsup chain   FAIL");
            failed += 1;
        }
    }

    // 11. Different ProtocolError sentinels are distinct from each other.
    {
        if !errors::Is(http::ErrHeaderTooLong(), http::ErrShortBody())
            && !errors::Is(http::ErrShortBody(), http::ErrHeaderTooLong())
        {
            Println!("[11] sentinels are distinct   PASS");
        } else {
            Println!("[11] sentinels are distinct   FAIL");
            failed += 1;
        }
    }

    // 12. errors.ErrUnsupported is itself stable.
    {
        let a: error = errors::ErrUnsupported.into();
        let b: error = errors::ErrUnsupported.into();
        if !a.IsNil() && a.Error() == "unsupported operation" && errors::Is(a, b) {
            Println!("[12] errors.ErrUnsupported     PASS");
        } else {
            Println!("[12] errors.ErrUnsupported     FAIL");
            failed += 1;
        }
    }

    if failed == 0 {
        Println!("ok 12/12");
        syscall::Exit(0);
    } else {
        Println!("FAIL {} of 12", failed);
        syscall::Exit(1);
    }
}
