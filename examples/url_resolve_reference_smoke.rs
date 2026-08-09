// url_resolve_reference_smoke — exercise URL.EscapedPath (url.go:744) +
// URL.ResolveReference (url.go:1137) against the RFC 3986 §5.4 table.

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

    // Helper: parse base+ref, resolve, compare to want.
    let check = |label: &'static str, base: &'static str, reference: &'static str, want: &'static str, fail: &mut i32| {
        let (b, _) = http::ParseURL(string(base));
        let (r, _) = http::ParseURL(string(reference));
        let merged = b.ResolveReference(&r);
        let got = merged.String();
        if got == want {
            fmt::Println!(label, "PASS");
        } else {
            fmt::Println!(label, "FAIL base=", base, "ref=", reference, "got=", got, "want=", want);
            *fail += 1;
        }
    };

    // ---- EscapedPath checks ----

    //  1. Plain path, no escape needed.
    {
        let (u, _) = http::ParseURL(string("http://example.com/foo/bar"));
        let got = u.EscapedPath();
        if got == "/foo/bar" {
            fmt::Println!("[ 1] EscapedPath plain          PASS");
        } else {
            fmt::Println!("[ 1] EscapedPath plain          FAIL got={}", got);
            failed += 1;
        }
    }

    //  2. Path "*" stays as "*" (Issue 11202).
    {
        let mut u = http::URL::default();
        u.Path = string("*");
        if u.EscapedPath() == "*" {
            fmt::Println!("[ 2] EscapedPath star            PASS");
        } else {
            fmt::Println!("[ 2] EscapedPath star            FAIL got={}", u.EscapedPath());
            failed += 1;
        }
    }

    //  3. Empty path -> empty.
    {
        let u = http::URL::default();
        if u.EscapedPath() == "" {
            fmt::Println!("[ 3] EscapedPath empty           PASS");
        } else {
            fmt::Println!("[ 3] EscapedPath empty           FAIL got={}", u.EscapedPath());
            failed += 1;
        }
    }

    // ---- ResolveReference RFC 3986 §5.4.1 normal examples ----
    // Base: http://a/b/c/d;p?q

    //  4. "g"        -> "http://a/b/c/g"
    check("[ 4] resolve g                ", "http://a/b/c/d;p?q", "g", "http://a/b/c/g", &mut failed);
    //  5. "./g"      -> "http://a/b/c/g"
    check("[ 5] resolve ./g              ", "http://a/b/c/d;p?q", "./g", "http://a/b/c/g", &mut failed);
    //  6. "g/"       -> "http://a/b/c/g/"
    check("[ 6] resolve g/               ", "http://a/b/c/d;p?q", "g/", "http://a/b/c/g/", &mut failed);
    //  7. "/g"       -> "http://a/g"
    check("[ 7] resolve /g               ", "http://a/b/c/d;p?q", "/g", "http://a/g", &mut failed);
    //  8. "//g"      -> skipped (slim: no Host parse from //g).
    //  9. "?y"       -> "http://a/b/c/d;p?y"
    check("[ 9] resolve ?y               ", "http://a/b/c/d;p?q", "?y", "http://a/b/c/d;p?y", &mut failed);
    // 10. "g?y"      -> "http://a/b/c/g?y"
    check("[10] resolve g?y              ", "http://a/b/c/d;p?q", "g?y", "http://a/b/c/g?y", &mut failed);
    // 11. ""         -> "http://a/b/c/d;p?q"  (identity; query+frag inherited)
    check("[11] resolve \"\" identity       ", "http://a/b/c/d;p?q", "", "http://a/b/c/d;p?q", &mut failed);

    // ---- §5.4.2 abnormal examples ----
    // 12. "../g"     -> "http://a/b/g"
    check("[12] resolve ../g             ", "http://a/b/c/d;p?q", "../g", "http://a/b/g", &mut failed);
    // 13. "../.."    -> "http://a/"
    check("[13] resolve ../..            ", "http://a/b/c/d;p?q", "../..", "http://a/", &mut failed);
    // 14. "../../g"  -> "http://a/g"
    check("[14] resolve ../../g          ", "http://a/b/c/d;p?q", "../../g", "http://a/g", &mut failed);
    // 15. Absolute ref replaces base entirely.
    check("[15] resolve absolute replace ", "http://a/b/c/d;p?q", "http://other/x", "http://other/x", &mut failed);

    if failed == 0 {
        fmt::Println!("ok 15/15");
        syscall::Exit(0);
    } else {
        fmt::Println!("FAIL {} of 15", failed);
        syscall::Exit(1);
    }
}
