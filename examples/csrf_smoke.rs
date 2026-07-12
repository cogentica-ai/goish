// csrf_smoke — exercise http.CrossOriginProtection.
//
// Test vectors derived from /share/go/src/net/http/csrf_test.go
// behavioral expectations.
//
// Coverage:
//   1. NewCrossOriginProtection — zero-value valid; no panics.
//   2. Safe methods (GET/HEAD/OPTIONS) always pass Check.
//   3. Sec-Fetch-Site: same-origin / none — passes.
//   4. Sec-Fetch-Site: cross-site — rejected.
//   5. Origin matches Host (no Sec-Fetch-Site) — passes.
//   6. Origin mismatches Host — rejected.
//   7. AddTrustedOrigin: valid origin accepted.
//   8. AddTrustedOrigin: rejects bad origins (no scheme, with path).
//   9. Trusted origin bypasses Sec-Fetch-Site cross-site rejection.
//  10. Origin/Sec-Fetch-Site both absent — passes (non-browser).

#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

use core::sync::atomic::{AtomicUsize, Ordering};

use goish::gostring::string;
use goish::net::http;
use goish::{syscall, Println};

const KB: usize = 1024;

static FAILED: AtomicUsize = AtomicUsize::new(0);

fn fail() {
    FAILED.fetch_add(1, Ordering::AcqRel);
}

fn write_result(idx: u8, label: &[u8], pass: bool) {
    syscall::Write(syscall::STDOUT, b"[".as_ptr(), 1);
    let d2 = b'0' + (idx % 10);
    if idx >= 10 {
        let d1 = b'0' + (idx / 10);
        let buf = [d1, d2];
        syscall::Write(syscall::STDOUT, buf.as_ptr(), 2);
    } else {
        let buf = [b' ', d2];
        syscall::Write(syscall::STDOUT, buf.as_ptr(), 2);
    }
    syscall::Write(syscall::STDOUT, b"] ".as_ptr(), 2);
    syscall::Write(syscall::STDOUT, label.as_ptr(), label.len());
    if pass {
        syscall::Write(syscall::STDOUT, b" PASS\n".as_ptr(), 6);
    } else {
        syscall::Write(syscall::STDOUT, b" FAIL\n".as_ptr(), 6);
    }
}

fn make_request(method: &'static str, host: &'static str) -> http::Request {
    let (mut r, _) = http::NewRequest(
        string::from_static(method),
        string::from_static("/"),
        goish::slice::__from_vec(alloc::vec::Vec::new()),
    );
    r.Host = string::from_static(host);
    r
}

#[goish::main]
fn main() {
    goish::go!(|| {
        run_tests();
        let f = FAILED.load(Ordering::Acquire);
        if f == 0 {
            Println!("ok 10/10");
            syscall::Exit(0);
        } else {
            Println!("FAIL", f as i64, "of 10");
            syscall::Exit(1);
        }
    });
    goish::runtime::sched::schedule();
}

fn run_tests() {
    test_1_zero_value();
    test_2_safe_methods();
    test_3_sec_fetch_site_safe();
    test_4_sec_fetch_site_cross();
    test_5_origin_matches_host();
    test_6_origin_mismatch();
    test_7_add_trusted_origin();
    test_8_invalid_origins();
    test_9_trusted_bypasses_cross_site();
    test_10_no_browser_headers();
}

fn test_1_zero_value() {
    let c = http::NewCrossOriginProtection();
    let r = make_request("POST", "example.com");
    let err = c.Check(&r);
    // POST with no headers → non-browser fallthrough → pass.
    write_result(1, b"NewCrossOriginProtection     ", err.IsNil());
    if !err.IsNil() {
        fail();
    }
}

fn test_2_safe_methods() {
    let c = http::NewCrossOriginProtection();
    let mut ok = true;
    for m in ["GET", "HEAD", "OPTIONS"] {
        let mut r = make_request(m, "example.com");
        // Add a hostile header set; safe methods must still pass.
        r.Header.Set(
            string::from_static("Sec-Fetch-Site"),
            string::from_static("cross-site"),
        );
        r.Header.Set(
            string::from_static("Origin"),
            string::from_static("https://attacker.com"),
        );
        if !c.Check(&r).IsNil() {
            ok = false;
            break;
        }
    }
    write_result(2, b"safe methods pass            ", ok);
    if !ok {
        fail();
    }
}

fn test_3_sec_fetch_site_safe() {
    let c = http::NewCrossOriginProtection();
    let mut ok = true;
    for v in ["same-origin", "none"] {
        let mut r = make_request("POST", "example.com");
        r.Header.Set(string::from_static("Sec-Fetch-Site"), string::from_static(v));
        if !c.Check(&r).IsNil() {
            ok = false;
            break;
        }
    }
    write_result(3, b"Sec-Fetch-Site safe          ", ok);
    if !ok {
        fail();
    }
}

fn test_4_sec_fetch_site_cross() {
    let c = http::NewCrossOriginProtection();
    let mut r = make_request("POST", "example.com");
    r.Header.Set(
        string::from_static("Sec-Fetch-Site"),
        string::from_static("cross-site"),
    );
    let err = c.Check(&r);
    write_result(4, b"Sec-Fetch-Site cross reject  ", !err.IsNil());
    if err.IsNil() {
        fail();
    }
}

fn test_5_origin_matches_host() {
    let c = http::NewCrossOriginProtection();
    let mut r = make_request("POST", "example.com");
    r.Header.Set(
        string::from_static("Origin"),
        string::from_static("https://example.com"),
    );
    let err = c.Check(&r);
    write_result(5, b"Origin matches Host          ", err.IsNil());
    if !err.IsNil() {
        fail();
    }
}

fn test_6_origin_mismatch() {
    let c = http::NewCrossOriginProtection();
    let mut r = make_request("POST", "example.com");
    r.Header.Set(
        string::from_static("Origin"),
        string::from_static("https://attacker.com"),
    );
    let err = c.Check(&r);
    write_result(6, b"Origin mismatches Host       ", !err.IsNil());
    if err.IsNil() {
        fail();
    }
}

fn test_7_add_trusted_origin() {
    let c = http::NewCrossOriginProtection();
    let err = c.AddTrustedOrigin(string::from_static("https://trusted.com"));
    write_result(7, b"AddTrustedOrigin valid       ", err.IsNil());
    if !err.IsNil() {
        fail();
    }
}

fn test_8_invalid_origins() {
    let c = http::NewCrossOriginProtection();
    let bad: [&str; 3] = [
        "no-scheme.com",                 // missing scheme
        "https://with.path/page",        // path not allowed
        "https://with.query?x=1",        // query not allowed
    ];
    let mut ok = true;
    for o in bad.iter() {
        let err = c.AddTrustedOrigin(string::from_static(*o));
        if err.IsNil() {
            ok = false;
            break;
        }
    }
    write_result(8, b"AddTrustedOrigin rejects bad ", ok);
    if !ok {
        fail();
    }
}

fn test_9_trusted_bypasses_cross_site() {
    let c = http::NewCrossOriginProtection();
    let _ = c.AddTrustedOrigin(string::from_static("https://trusted.com"));
    let mut r = make_request("POST", "example.com");
    r.Header.Set(
        string::from_static("Sec-Fetch-Site"),
        string::from_static("cross-site"),
    );
    r.Header.Set(
        string::from_static("Origin"),
        string::from_static("https://trusted.com"),
    );
    let err = c.Check(&r);
    write_result(9, b"trusted origin bypasses cross", err.IsNil());
    if !err.IsNil() {
        fail();
    }
}

fn test_10_no_browser_headers() {
    let c = http::NewCrossOriginProtection();
    let r = make_request("POST", "example.com");
    // No Sec-Fetch-Site, no Origin → assume non-browser → pass.
    let err = c.Check(&r);
    write_result(10, b"no browser headers (curl)   ", err.IsNil());
    if !err.IsNil() {
        fail();
    }
}
