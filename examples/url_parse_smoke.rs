// url_parse_smoke — exercise url::Parse / url::ParseRequestURI
// (line-by-line slim ports of url.go:479 / :500).

#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

use goish::fmt;
use goish::net::http::url;
use goish::{string, syscall};

#[goish::main]
fn main() {
    let mut failed = 0;

    // 1. Absolute URL with scheme://host/path?query#frag.
    {
        let (u, err) = url::Parse(string("http://example.com:8080/path?a=1#frag"));
        // Fragment is dropped per slim port; otherwise fields are populated.
        if err.IsNil()
            && u.Scheme == "http"
            && u.Host == "example.com:8080"
            && u.Path == "/path"
            && u.RawQuery == "a=1"
        {
            fmt::Println!("[ 1] absolute URL              PASS");
        } else {
            fmt::Println!(
                "[ 1] absolute URL              FAIL scheme={} host={} path={} q={}",
                u.Scheme,
                u.Host,
                u.Path,
                u.RawQuery
            );
            failed += 1;
        }
    }

    // 2. Origin form: /path?query.
    {
        let (u, err) = url::Parse(string("/foo/bar?x=y"));
        if err.IsNil()
            && u.Scheme == ""
            && u.Host == ""
            && u.Path == "/foo/bar"
            && u.RawQuery == "x=y"
        {
            fmt::Println!("[ 2] origin form              PASS");
        } else {
            fmt::Println!("[ 2] origin form              FAIL");
            failed += 1;
        }
    }

    // 3. Scheme is lowercased.
    {
        let (u, err) = url::Parse(string("HTTPS://Example.COM/Foo"));
        if err.IsNil() && u.Scheme == "https" {
            fmt::Println!("[ 3] scheme lowercased         PASS");
        } else {
            fmt::Println!("[ 3] scheme lowercased         FAIL scheme={}", u.Scheme);
            failed += 1;
        }
    }

    // 4. Empty URL via ParseRequestURI → error.
    {
        let (_u, err) = url::ParseRequestURI(string(""));
        if !err.IsNil() {
            fmt::Println!("[ 4] empty ParseRequestURI    PASS");
        } else {
            fmt::Println!("[ 4] empty ParseRequestURI    FAIL");
            failed += 1;
        }
    }

    // 5. ParseRequestURI accepts /path.
    {
        let (u, err) = url::ParseRequestURI(string("/abs/path?k=v"));
        if err.IsNil() && u.Path == "/abs/path" && u.RawQuery == "k=v" {
            fmt::Println!("[ 5] ParseRequestURI /path    PASS");
        } else {
            fmt::Println!("[ 5] ParseRequestURI /path    FAIL");
            failed += 1;
        }
    }

    // 6. ParseRequestURI rejects relative path (no leading /, no scheme).
    {
        let (_u, err) = url::ParseRequestURI(string("relative/path"));
        if !err.IsNil() {
            fmt::Println!("[ 6] reject relative          PASS");
        } else {
            fmt::Println!("[ 6] reject relative          FAIL");
            failed += 1;
        }
    }

    // 7. Asterisk form (OPTIONS *).
    {
        let (u, err) = url::Parse(string("*"));
        if err.IsNil() && u.Path == "*" {
            fmt::Println!("[ 7] asterisk form            PASS");
        } else {
            fmt::Println!("[ 7] asterisk form            FAIL");
            failed += 1;
        }
    }

    // 8. Round-trip via URL.RequestURI() preserves path?query.
    {
        let (u, err) = url::Parse(string("https://example.com/p1/p2?a=1&b=2"));
        if err.IsNil() && u.RequestURI() == "/p1/p2?a=1&b=2" {
            fmt::Println!("[ 8] round-trip RequestURI     PASS");
        } else {
            fmt::Println!("[ 8] round-trip RequestURI     FAIL got={}", u.RequestURI());
            failed += 1;
        }
    }

    // 9. Bare host (no scheme, no leading /) — accepted in non-request mode.
    //    Slim port: treats it as Path.
    {
        let (u, err) = url::Parse(string("relative"));
        if err.IsNil() && u.Path == "relative" {
            fmt::Println!("[ 9] bare relative            PASS");
        } else {
            fmt::Println!("[ 9] bare relative            FAIL");
            failed += 1;
        }
    }

    // 10. Missing scheme — leading colon.
    {
        let (_u, err) = url::Parse(string(":bad"));
        if !err.IsNil() {
            fmt::Println!("[10] missing scheme err       PASS");
        } else {
            fmt::Println!("[10] missing scheme err       FAIL");
            failed += 1;
        }
    }

    if failed == 0 {
        fmt::Println!("ok 10/10");
        syscall::Exit(0);
    } else {
        fmt::Println!("FAIL {} of 10", failed);
        syscall::Exit(1);
    }
}
