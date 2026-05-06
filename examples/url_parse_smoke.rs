// url_parse_smoke — exercise url::Parse / url::ParseRequestURI
// (line-by-line slim ports of url.go:479 / :500).

#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

use goish::net::http::url;
use goish::{string, syscall, Println};

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
            Println!("[ 1] absolute URL              PASS");
        } else {
            Println!(
                "[ 1] absolute URL              FAIL scheme={} host={} path={} q={}",
                u.Scheme, u.Host, u.Path, u.RawQuery
            );
            failed += 1;
        }
    }

    // 2. Origin form: /path?query.
    {
        let (u, err) = url::Parse(string("/foo/bar?x=y"));
        if err.IsNil() && u.Scheme == "" && u.Host == "" && u.Path == "/foo/bar" && u.RawQuery == "x=y" {
            Println!("[ 2] origin form              PASS");
        } else {
            Println!("[ 2] origin form              FAIL");
            failed += 1;
        }
    }

    // 3. Scheme is lowercased.
    {
        let (u, err) = url::Parse(string("HTTPS://Example.COM/Foo"));
        if err.IsNil() && u.Scheme == "https" {
            Println!("[ 3] scheme lowercased         PASS");
        } else {
            Println!("[ 3] scheme lowercased         FAIL scheme={}", u.Scheme);
            failed += 1;
        }
    }

    // 4. Empty URL via ParseRequestURI → error.
    {
        let (_u, err) = url::ParseRequestURI(string(""));
        if !err.IsNil() {
            Println!("[ 4] empty ParseRequestURI    PASS");
        } else {
            Println!("[ 4] empty ParseRequestURI    FAIL");
            failed += 1;
        }
    }

    // 5. ParseRequestURI accepts /path.
    {
        let (u, err) = url::ParseRequestURI(string("/abs/path?k=v"));
        if err.IsNil() && u.Path == "/abs/path" && u.RawQuery == "k=v" {
            Println!("[ 5] ParseRequestURI /path    PASS");
        } else {
            Println!("[ 5] ParseRequestURI /path    FAIL");
            failed += 1;
        }
    }

    // 6. ParseRequestURI rejects relative path (no leading /, no scheme).
    {
        let (_u, err) = url::ParseRequestURI(string("relative/path"));
        if !err.IsNil() {
            Println!("[ 6] reject relative          PASS");
        } else {
            Println!("[ 6] reject relative          FAIL");
            failed += 1;
        }
    }

    // 7. Asterisk form (OPTIONS *).
    {
        let (u, err) = url::Parse(string("*"));
        if err.IsNil() && u.Path == "*" {
            Println!("[ 7] asterisk form            PASS");
        } else {
            Println!("[ 7] asterisk form            FAIL");
            failed += 1;
        }
    }

    // 8. Round-trip via URL.RequestURI() preserves path?query.
    {
        let (u, err) = url::Parse(string("https://example.com/p1/p2?a=1&b=2"));
        if err.IsNil() && u.RequestURI() == "/p1/p2?a=1&b=2" {
            Println!("[ 8] round-trip RequestURI     PASS");
        } else {
            Println!("[ 8] round-trip RequestURI     FAIL got={}", u.RequestURI());
            failed += 1;
        }
    }

    // 9. Bare host (no scheme, no leading /) — accepted in non-request mode.
    //    Slim port: treats it as Path.
    {
        let (u, err) = url::Parse(string("relative"));
        if err.IsNil() && u.Path == "relative" {
            Println!("[ 9] bare relative            PASS");
        } else {
            Println!("[ 9] bare relative            FAIL");
            failed += 1;
        }
    }

    // 10. Missing scheme — leading colon.
    {
        let (_u, err) = url::Parse(string(":bad"));
        if !err.IsNil() {
            Println!("[10] missing scheme err       PASS");
        } else {
            Println!("[10] missing scheme err       FAIL");
            failed += 1;
        }
    }

    if failed == 0 {
        Println!("ok 10/10");
        syscall::Exit(0);
    } else {
        Println!("FAIL {} of 10", failed);
        syscall::Exit(1);
    }
}
