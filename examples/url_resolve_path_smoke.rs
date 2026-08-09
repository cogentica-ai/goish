// url_resolve_path_smoke — exercise url.resolvePath (RFC 3986 §5.2.4).
//
// Validates the line-by-line port of net/url/url.go:1050. Test cases
// copied from Go's net/url url_test.go (resolvePath table).

#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

use goish::fmt;
use goish::net::http;
use goish::{string, syscall};

#[goish::main]
fn main() {
    let mut failed = 0;

    // Helper: run resolvePath(base, ref) and compare to want.
    let check = |idx: i32, base: &'static str, reference: &'static str, want: &'static str, fail: &mut i32| {
        let got = http::ResolvePath(string(base), string(reference));
        if got == want {
            fmt::Println!("[{}] resolvePath PASS", idx);
        } else {
            fmt::Println!(
                "[{}] resolvePath FAIL base={} ref={} got={} want={}",
                idx, base, reference, got, want
            );
            *fail += 1;
        }
    };

    //  1. Empty reference -> base.
    check(1, "/a/b/c", "", "/a/b/c", &mut failed);
    //  2. Relative ref appended to last-slash position of base.
    check(2, "/a/b", "g", "/a/g", &mut failed);
    //  3. Absolute ref replaces base.
    check(3, "/a/b/c", "/g", "/g", &mut failed);
    //  4. "." segment dropped.
    check(4, "/a/b/c", "./", "/a/b/", &mut failed);
    //  5. ".." pops one segment.
    check(5, "/a/b/c", "../", "/a/", &mut failed);
    //  6. "../.." pops two segments.
    check(6, "/a/b/c", "../../", "/", &mut failed);
    //  7. "../../.." pops everything (clamped at root).
    check(7, "/a/b/c", "../../../", "/", &mut failed);
    //  8. Combined: relative + dot-pop + name.
    check(8, "/a/b/c/d", "../e", "/a/b/e", &mut failed);
    //  9. Trailing-slash preservation through ".".
    check(9, "/a/b/", ".", "/a/b/", &mut failed);
    // 10. Pop with new last segment.
    check(10, "/a/b/c", "..", "/a/", &mut failed);
    // 11. Multiple "." dropped, name appended.
    check(11, "/a/b", "./c", "/a/c", &mut failed);
    // 12. "/./" segments dropped mid-path.
    check(12, "/a/b/c", "/./d", "/d", &mut failed);
    // 13. "/../" segments pop.
    check(13, "/a/b/c", "/../d", "/d", &mut failed);
    // 14. ".." at start of relative ref.
    check(14, "/a/b", "../", "/", &mut failed);
    // 15. Empty path inputs: result is "/".
    check(15, "/", "", "/", &mut failed);

    if failed == 0 {
        fmt::Println!("ok 15/15");
        syscall::Exit(0);
    } else {
        fmt::Println!("FAIL {} of 15", failed);
        syscall::Exit(1);
    }
}
