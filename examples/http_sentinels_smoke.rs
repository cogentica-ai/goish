// http_sentinels_smoke — exercise the sentinel error constants
// (ErrNoCookie, ErrMissingFile, ErrBodyNotAllowed, ErrHijacked,
//  ErrContentLength, ErrAbortHandler, ErrHandlerTimeout, ErrServerClosed).
//
// Each sentinel must:
//   • be non-nil
//   • be stable across calls (errors::Is identifies it)
//   • carry the same human-readable message Go uses

#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

use goish::errors;
use goish::net::http;
use goish::{syscall, Println};

#[goish::main]
fn main() {
    let mut failed = 0;

    // 1. ErrNoCookie is non-nil and stable.
    {
        let a: goish::errors::error = http::ErrNoCookie.into();
        let b: goish::errors::error = http::ErrNoCookie.into();
        if !a.IsNil() && errors::Is(a, b) {
            Println!("[ 1] ErrNoCookie stable        PASS");
        } else {
            Println!("[ 1] ErrNoCookie stable        FAIL");
            failed += 1;
        }
    }

    // 2. ErrNoCookie message matches Go.
    {
        let __e_for_s: goish::errors::error = http::ErrNoCookie.into(); let s = __e_for_s.Error();
        if s == "http: named cookie not present" {
            Println!("[ 2] ErrNoCookie message       PASS");
        } else {
            Println!("[ 2] ErrNoCookie message       FAIL got={}", s);
            failed += 1;
        }
    }

    // 3. ErrMissingFile sentinel + message.
    {
        let __e_for_s: goish::errors::error = http::ErrMissingFile.into(); let s = __e_for_s.Error();
        if s == "http: no such file" {
            Println!("[ 3] ErrMissingFile message    PASS");
        } else {
            Println!("[ 3] ErrMissingFile message    FAIL got={}", s);
            failed += 1;
        }
    }

    // 4. ErrBodyNotAllowed sentinel.
    {
        let __ev_s: goish::errors::error = http::ErrBodyNotAllowed.into(); let s = __ev_s.Error();
        if s == "http: request method or response status code does not allow body" {
            Println!("[ 4] ErrBodyNotAllowed message PASS");
        } else {
            Println!("[ 4] ErrBodyNotAllowed message FAIL got={}", s);
            failed += 1;
        }
    }

    // 5. ErrHijacked sentinel.
    {
        let a: goish::errors::error = http::ErrHijacked.into();
        let b: goish::errors::error = http::ErrHijacked.into();
        if errors::Is(a.clone(), b) && a.Error() == "http: connection has been hijacked" {
            Println!("[ 5] ErrHijacked stable+msg    PASS");
        } else {
            Println!("[ 5] ErrHijacked stable+msg    FAIL");
            failed += 1;
        }
    }

    // 6. ErrContentLength sentinel.
    {
        let __ev_s: goish::errors::error = http::ErrContentLength.into(); let s = __ev_s.Error();
        if s == "http: wrote more than the declared Content-Length" {
            Println!("[ 6] ErrContentLength message  PASS");
        } else {
            Println!("[ 6] ErrContentLength message  FAIL");
            failed += 1;
        }
    }

    // 7. ErrAbortHandler sentinel + stability.
    {
        let a: goish::errors::error = http::ErrAbortHandler.into();
        let b: goish::errors::error = http::ErrAbortHandler.into();
        if errors::Is(a.clone(), b) && a.Error() == "net/http: abort Handler" {
            Println!("[ 7] ErrAbortHandler           PASS");
        } else {
            Println!("[ 7] ErrAbortHandler           FAIL");
            failed += 1;
        }
    }

    // 8. ErrHandlerTimeout sentinel.
    {
        let __ev_s: goish::errors::error = http::ErrHandlerTimeout.into(); let s = __ev_s.Error();
        if s == "http: Handler timeout" {
            Println!("[ 8] ErrHandlerTimeout message PASS");
        } else {
            Println!("[ 8] ErrHandlerTimeout message FAIL");
            failed += 1;
        }
    }

    // 9. ErrServerClosed (pre-existing) sentinel still works alongside.
    {
        let __ev_s: goish::errors::error = http::ErrServerClosed.into(); let s = __ev_s.Error();
        if s == "http: Server closed" {
            Println!("[ 9] ErrServerClosed message   PASS");
        } else {
            Println!("[ 9] ErrServerClosed message   FAIL");
            failed += 1;
        }
    }

    // 10. Two different sentinels are NOT Is-equal.
    {
        if !errors::Is(http::ErrNoCookie.into(), http::ErrMissingFile) {
            Println!("[10] distinct sentinels        PASS");
        } else {
            Println!("[10] distinct sentinels        FAIL");
            failed += 1;
        }
    }

    // 11. Wire-up: Request.Cookie returns ErrNoCookie for missing.
    {
        let (r, _) = http::NewRequest(
            goish::string("GET"),
            goish::string("http://example.com/"),
            goish::make!([]goish::byte, 0),
        );
        let (_, err) = r.Cookie(goish::string("missing"));
        if errors::Is(err, http::ErrNoCookie) {
            Println!("[11] Request.Cookie wires it   PASS");
        } else {
            Println!("[11] Request.Cookie wires it   FAIL");
            failed += 1;
        }
    }

    if failed == 0 {
        Println!("ok 11/11");
        syscall::Exit(0);
    } else {
        Println!("FAIL {} of 11", failed);
        syscall::Exit(1);
    }
}
