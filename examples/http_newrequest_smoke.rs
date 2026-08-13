// NewRequest against Go 1.25.5. Expected values from a goref run.
//
// The cases that separate a real port from a plausible one:
//   ""            -> Method becomes "GET"
//   "get"         -> stays lowercase (Go does NOT canonicalise)
//   "BAD METHOD"  -> error, because a space is not a token char
//   "//host/x"    -> scheme-relative; Host is still parsed out
//   "/just/path"  -> relative; Host is empty, not an error
//   user:pw@host  -> Host excludes the userinfo
#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

use goish::net::http;
use goish::{errors, fmt, string, syscall};

fn desc(method: &'static str, url: &'static str, body: &'static str) -> string {
    let (r, err) = if body == "" {
        http::NewRequest(string(method), string(url), goish::nil)
    } else {
        http::NewRequest(
            string(method),
            string(url),
            goish::slice::<u8>::__from_vec(body.as_bytes().to_vec()),
        )
    };
    if err != errors::nil {
        return string("err ") + err.Error();
    }
    return fmt::Sprintf!(
        "Method=%s Host=%s Path=%s RawQuery=%s CL=%d Proto=%s",
        r.Method.clone(),
        r.Host.clone(),
        r.URL.Path.clone(),
        r.URL.RawQuery.clone(),
        r.ContentLength,
        r.Proto.clone()
    );
}

fn eq(got: string, want: &'static str, what: &'static str, bad: &mut i32) {
    if got != want {
        fmt::Println!("FAIL ", what);
        fmt::Println!("  got  ", got);
        fmt::Println!("  want ", want);
        *bad += 1;
    }
}

#[goish::main]
fn main() {
    let mut bad = 0i32;

    eq(
        desc("GET", "http://example.com/a/b?q=1", ""),
        "Method=GET Host=example.com Path=/a/b RawQuery=q=1 CL=0 Proto=HTTP/1.1",
        "absolute with query",
        &mut bad,
    );
    eq(
        desc("", "http://example.com/", ""),
        "Method=GET Host=example.com Path=/ RawQuery= CL=0 Proto=HTTP/1.1",
        "empty method defaults to GET",
        &mut bad,
    );
    eq(
        desc("POST", "http://example.com/", "hello"),
        "Method=POST Host=example.com Path=/ RawQuery= CL=5 Proto=HTTP/1.1",
        "ContentLength from body",
        &mut bad,
    );
    eq(
        desc("GET", "//example.com/x", ""),
        "Method=GET Host=example.com Path=/x RawQuery= CL=0 Proto=HTTP/1.1",
        "scheme-relative",
        &mut bad,
    );
    eq(
        desc("GET", "/just/a/path", ""),
        "Method=GET Host= Path=/just/a/path RawQuery= CL=0 Proto=HTTP/1.1",
        "relative path",
        &mut bad,
    );
    eq(
        desc("BAD METHOD", "http://x/", ""),
        "err net/http: invalid method \"BAD METHOD\"",
        "invalid method",
        &mut bad,
    );
    eq(
        desc("GET", "http://user:pw@example.com/p", ""),
        "Method=GET Host=example.com Path=/p RawQuery= CL=0 Proto=HTTP/1.1",
        "userinfo excluded from Host",
        &mut bad,
    );
    eq(
        desc("GET", "http://example.com:8080/p", ""),
        "Method=GET Host=example.com:8080 Path=/p RawQuery= CL=0 Proto=HTTP/1.1",
        "port kept in Host",
        &mut bad,
    );
    eq(
        desc("get", "http://example.com/", ""),
        "Method=get Host=example.com Path=/ RawQuery= CL=0 Proto=HTTP/1.1",
        "lowercase method preserved",
        &mut bad,
    );

    if bad == 0 {
        fmt::Println!("NEWREQUEST_OK 9/9");
        syscall::Exit(0);
    } else {
        fmt::Println!("FAILED ", bad);
        syscall::Exit(1);
    }
}
