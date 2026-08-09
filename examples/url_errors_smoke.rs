// url_errors_smoke — exercise net/url typed errors.
//
// Coverage:
//   1. url::Error::new — Error() renders "Op \"URL\": inner-msg".
//   2. url::Error — Unwrap() returns the inner error.
//   3. url::Error — errors::Is matches the inner sentinel via chain.
//   4. url::Error — Op/URL fields preserved through downcast.
//   5. url::EscapeError::new — Error() = `invalid URL escape "..."`.
//   6. url::EscapeError — embedded text round-trips via downcast.
//   7. url::InvalidHostError::new — Error() = `invalid character "..." in host name`.
//   8. url::InvalidHostError — text round-trips via downcast.

#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

use core::sync::atomic::{AtomicUsize, Ordering};

use goish::errors::{self, error};
use goish::gostring::string;
use goish::net::http::url::{self, EscapeError, InvalidHostError};
use goish::runtime::sched::schedule;
use goish::{go, syscall, Println};


static FAILED: AtomicUsize = AtomicUsize::new(0);

fn ok_line(msg: &[u8]) {
    syscall::Write(syscall::STDOUT, msg.as_ptr(), msg.len());
}

fn fail() {
    FAILED.fetch_add(1, Ordering::AcqRel);
}

#[goish::main]
fn main() {
    go!(|| {
        run_tests();
        let f = FAILED.load(Ordering::Acquire);
        if f == 0 {
            Println!("ok 8/8");
            syscall::Exit(0);
        } else {
            Println!("FAIL", f as i64, "of 8");
            syscall::Exit(1);
        }
    });
    schedule();
}

fn run_tests() {
    test_1_error_format();
    test_2_error_unwrap();
    test_3_error_is_inner();
    test_4_error_fields_via_downcast();
    test_5_escape_error_format();
    test_6_escape_error_round_trip();
    test_7_invalid_host_error_format();
    test_8_invalid_host_round_trip();
}

fn s(x: &'static str) -> string {
    string::from_static(x)
}

fn test_1_error_format() {
    let inner = errors::New(s("connection refused"));
    let e: error = url::Error::new(s("Get"), s("http://example.com"), inner);
    let want = s("Get \"http://example.com\": connection refused");
    if e.Error() == want {
        ok_line(b"[ 1] url::Error format            PASS\n");
    } else {
        ok_line(b"[ 1] url::Error format            FAIL\n");
        fail();
    }
}

fn test_2_error_unwrap() {
    let inner = errors::New(s("boom"));
    let e: error = url::Error::new(s("Open"), s("https://x.test"), inner.clone());
    let unw = errors::Unwrap(e);
    if unw == inner {
        ok_line(b"[ 2] url::Error Unwrap            PASS\n");
    } else {
        ok_line(b"[ 2] url::Error Unwrap            FAIL\n");
        fail();
    }
}

fn test_3_error_is_inner() {
    let sentinel = errors::New(s("eof"));
    let e: error = url::Error::new(s("Read"), s("file:///tmp/x"), sentinel.clone());
    if errors::Is(e, sentinel) {
        ok_line(b"[ 3] errors::Is walks chain      PASS\n");
    } else {
        ok_line(b"[ 3] errors::Is walks chain      FAIL\n");
        fail();
    }
}

fn test_4_error_fields_via_downcast() {
    let inner = errors::New(s("x"));
    let e: error = url::Error::new(s("OP"), s("//u"), inner);
    match errors::As::<url::Error>(e) {
        Some(arc) => {
            if arc.Op == s("OP") && arc.URL == s("//u") {
                ok_line(b"[ 4] url::Error errors::As fields PASS\n");
            } else {
                ok_line(b"[ 4] url::Error errors::As fields FAIL\n");
                fail();
            }
        }
        None => {
            ok_line(b"[ 4] url::Error errors::As fields FAIL\n");
            fail();
        }
    }
}

fn test_5_escape_error_format() {
    let e: error = EscapeError::new(s("%ZZ"));
    let want = s("invalid URL escape \"%ZZ\"");
    if e.Error() == want {
        ok_line(b"[ 5] EscapeError format          PASS\n");
    } else {
        ok_line(b"[ 5] EscapeError format          FAIL\n");
        fail();
    }
}

fn test_6_escape_error_round_trip() {
    let e: error = EscapeError::new(s("%qq"));
    match errors::As::<EscapeError>(e) {
        Some(arc) => {
            if arc.0 == s("%qq") {
                ok_line(b"[ 6] EscapeError downcast        PASS\n");
            } else {
                ok_line(b"[ 6] EscapeError downcast        FAIL\n");
                fail();
            }
        }
        None => {
            ok_line(b"[ 6] EscapeError downcast        FAIL\n");
            fail();
        }
    }
}

fn test_7_invalid_host_error_format() {
    let e: error = InvalidHostError::new(s("\x01"));
    let want = s("invalid character \"\\x01\" in host name");
    if e.Error() == want {
        ok_line(b"[ 7] InvalidHostError format     PASS\n");
    } else {
        ok_line(b"[ 7] InvalidHostError format     FAIL\n");
        fail();
    }
}

fn test_8_invalid_host_round_trip() {
    let e: error = InvalidHostError::new(s("?"));
    match errors::As::<InvalidHostError>(e) {
        Some(arc) => {
            if arc.0 == s("?") {
                ok_line(b"[ 8] InvalidHostError downcast   PASS\n");
            } else {
                ok_line(b"[ 8] InvalidHostError downcast   FAIL\n");
                fail();
            }
        }
        None => {
            ok_line(b"[ 8] InvalidHostError downcast   FAIL\n");
            fail();
        }
    }
}
