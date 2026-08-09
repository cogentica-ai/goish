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

use goish::fmt;
use goish::error;
use goish::errors;
use goish::net::http;
use goish::{syscall};

#[goish::main]
fn main() {
    let mut failed = 0;

    // 1. ErrNotSupported is non-nil and stable across calls.
    {
        let a: error = http::ErrNotSupported.into();
        let b: error = http::ErrNotSupported.into();
        if !a.IsNil() && errors::Is(a, b) {
            fmt::Println!("[ 1] ErrNotSupported stable    PASS");
        } else {
            fmt::Println!("[ 1] ErrNotSupported stable    FAIL");
            failed += 1;
        }
    }

    // 2. ErrNotSupported message matches Go.
    {
        let __e_s: error = http::ErrNotSupported.into(); let s = __e_s.Error();
        if s == "feature not supported" {
            fmt::Println!("[ 2] ErrNotSupported message   PASS");
        } else {
            fmt::Println!("[ 2] ErrNotSupported message   FAIL got={}", s);
            failed += 1;
        }
    }

    // 3. ErrNotSupported chains to errors.ErrUnsupported.
    {
        if errors::Is(http::ErrNotSupported.into(), errors::ErrUnsupported) {
            fmt::Println!("[ 3] ErrNotSupported→ErrUnsup  PASS");
        } else {
            fmt::Println!("[ 3] ErrNotSupported→ErrUnsup  FAIL");
            failed += 1;
        }
    }

    // 4. ErrUnexpectedTrailer sentinel + message + stable.
    {
        let a: error = http::ErrUnexpectedTrailer.into();
        let s = a.Error();
        if errors::Is(a.clone(), http::ErrUnexpectedTrailer)
            && s == "trailer header without chunked transfer encoding"
        {
            fmt::Println!("[ 4] ErrUnexpectedTrailer      PASS");
        } else {
            fmt::Println!("[ 4] ErrUnexpectedTrailer      FAIL got={}", s);
            failed += 1;
        }
    }

    // 5. ErrHeaderTooLong sentinel + message.
    {
        let __e_s: error = http::ErrHeaderTooLong.into(); let s = __e_s.Error();
        if s == "header too long" {
            fmt::Println!("[ 5] ErrHeaderTooLong message  PASS");
        } else {
            fmt::Println!("[ 5] ErrHeaderTooLong message  FAIL got={}", s);
            failed += 1;
        }
    }

    // 6. ErrShortBody sentinel + message.
    {
        let __e_s: error = http::ErrShortBody.into(); let s = __e_s.Error();
        if s == "entity body too short" {
            fmt::Println!("[ 6] ErrShortBody message      PASS");
        } else {
            fmt::Println!("[ 6] ErrShortBody message      FAIL got={}", s);
            failed += 1;
        }
    }

    // 7. ErrMissingContentLength sentinel + message.
    {
        let __e_s: error = http::ErrMissingContentLength.into(); let s = __e_s.Error();
        if s == "missing ContentLength in HEAD response" {
            fmt::Println!("[ 7] ErrMissingContentLength   PASS");
        } else {
            fmt::Println!("[ 7] ErrMissingContentLength   FAIL got={}", s);
            failed += 1;
        }
    }

    // 8. Non-ErrNotSupported sentinels do NOT chain to ErrUnsupported.
    {
        let any_chain =
               errors::Is(http::ErrUnexpectedTrailer.into(), errors::ErrUnsupported)
            || errors::Is(http::ErrHeaderTooLong.into(),     errors::ErrUnsupported)
            || errors::Is(http::ErrShortBody.into(),         errors::ErrUnsupported)
            || errors::Is(http::ErrMissingContentLength.into(), errors::ErrUnsupported);
        if !any_chain {
            fmt::Println!("[ 8] other sentinels !ErrUnsup PASS");
        } else {
            fmt::Println!("[ 8] other sentinels !ErrUnsup FAIL");
            failed += 1;
        }
    }

    // 9. User-constructed ProtocolError exposes its ErrorString.
    {
        let pe = http::ProtocolError { ErrorString: goish::string("custom oops") };
        let e: error = errors::Wrap(pe);
        let s = e.Error();
        if s == "custom oops" {
            fmt::Println!("[ 9] ProtocolError user ctor   PASS");
        } else {
            fmt::Println!("[ 9] ProtocolError user ctor   FAIL got={}", s);
            failed += 1;
        }
    }

    // 10. User-constructed ProtocolError does NOT chain to ErrUnsupported.
    {
        let pe = http::ProtocolError { ErrorString: goish::string("feature not supported") };
        let e: error = errors::Wrap(pe);
        if !errors::Is(e, errors::ErrUnsupported) {
            fmt::Println!("[10] user pe !ErrUnsup chain   PASS");
        } else {
            fmt::Println!("[10] user pe !ErrUnsup chain   FAIL");
            failed += 1;
        }
    }

    // 11. Different ProtocolError sentinels are distinct from each other.
    {
        let __htl: error = http::ErrHeaderTooLong.into();
        let __sb: error = http::ErrShortBody.into();
        if !errors::Is(__htl.clone(), http::ErrShortBody)
            && !errors::Is(__sb.clone(), http::ErrHeaderTooLong)
        {
            fmt::Println!("[11] sentinels are distinct   PASS");
        } else {
            fmt::Println!("[11] sentinels are distinct   FAIL");
            failed += 1;
        }
    }

    // 12. errors.ErrUnsupported is itself stable.
    {
        let a: error = errors::ErrUnsupported.into();
        let b: error = errors::ErrUnsupported.into();
        if !a.IsNil() && a.Error() == "unsupported operation" && errors::Is(a, b) {
            fmt::Println!("[12] errors.ErrUnsupported     PASS");
        } else {
            fmt::Println!("[12] errors.ErrUnsupported     FAIL");
            failed += 1;
        }
    }

    if failed == 0 {
        fmt::Println!("ok 12/12");
        syscall::Exit(0);
    } else {
        fmt::Println!("FAIL {} of 12", failed);
        syscall::Exit(1);
    }
}
