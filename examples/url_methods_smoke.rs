// url_methods_smoke — exercise URL.IsAbs / RequestURI / Hostname /
// Port / Query (line-by-line ports of url.go:1116/1186/1208/1216/1179).

#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

use goish::convert::bytes;
use goish::fmt;
use goish::net::http;
use goish::{string, syscall};

#[goish::main]
fn main() {
    let mut failed = 0;

    // 1. Absolute URL: IsAbs true; RequestURI strips scheme+host.
    {
        let (req, _) = http::NewRequest(
            string("GET"),
            string("http://example.com:8080/path?a=1"),
            bytes(""),
        );
        if req.URL.IsAbs() && req.URL.RequestURI() == "/path?a=1" {
            fmt::Println!("[ 1] absolute URL IsAbs+ReqURI  PASS");
        } else {
            fmt::Println!(
                "[ 1] absolute URL IsAbs+ReqURI  FAIL abs={} reqURI={}",
                req.URL.IsAbs(),
                req.URL.RequestURI()
            );
            failed += 1;
        }
    }

    // 2. Hostname / Port — host:port form.
    {
        let (req, _) = http::NewRequest(
            string("GET"),
            string("http://example.com:8080/foo"),
            bytes(""),
        );
        if req.URL.Hostname() == "example.com" && req.URL.Port() == "8080" {
            fmt::Println!("[ 2] hostname:port              PASS");
        } else {
            fmt::Println!(
                "[ 2] hostname:port              FAIL host={} port={}",
                req.URL.Hostname(),
                req.URL.Port()
            );
            failed += 1;
        }
    }

    // 3. Hostname only — no port.
    {
        let (req, _) = http::NewRequest(string("GET"), string("http://example.com/foo"), bytes(""));
        if req.URL.Hostname() == "example.com" && req.URL.Port() == "" {
            fmt::Println!("[ 3] hostname no port           PASS");
        } else {
            fmt::Println!(
                "[ 3] hostname no port           FAIL host={} port={}",
                req.URL.Hostname(),
                req.URL.Port()
            );
            failed += 1;
        }
    }

    // 4. Query method parses RawQuery.
    {
        let (req, _) = http::NewRequest(
            string("GET"),
            string("http://x/foo?a=1&b=two&a=2"),
            bytes(""),
        );
        let q = req.URL.Query();
        let (a_vals, ok_a) = q.Get(string("a"));
        let (b_vals, ok_b) = q.Get(string("b"));
        if ok_a
            && a_vals.Len() == 2
            && a_vals[0] == "1"
            && a_vals[1] == "2"
            && ok_b
            && b_vals[0] == "two"
        {
            fmt::Println!("[ 4] URL.Query                  PASS");
        } else {
            fmt::Println!("[ 4] URL.Query                  FAIL");
            failed += 1;
        }
    }

    // 5. Empty path → RequestURI yields "/".
    {
        let (req, _) = http::NewRequest(string("GET"), string("http://example.com"), bytes(""));
        if req.URL.RequestURI() == "/" {
            fmt::Println!("[ 5] empty path → /             PASS");
        } else {
            fmt::Println!(
                "[ 5] empty path → /             FAIL got={}",
                req.URL.RequestURI()
            );
            failed += 1;
        }
    }

    // 6. IsAbs false on origin-form URL.
    {
        let (req, _) = http::NewRequest(string("GET"), string("/just/path"), bytes(""));
        if !req.URL.IsAbs() && req.URL.RequestURI() == "/just/path" {
            fmt::Println!("[ 6] origin form !IsAbs         PASS");
        } else {
            fmt::Println!(
                "[ 6] origin form !IsAbs         FAIL abs={} req={}",
                req.URL.IsAbs(),
                req.URL.RequestURI()
            );
            failed += 1;
        }
    }

    // 7. IPv6 host bracket stripping.
    {
        // Borrow a URL via NewRequest, then overwrite the Host field.
        let (mut req, _) =
            http::NewRequest(string("GET"), string("http://placeholder/"), bytes(""));
        req.URL.Host = string("[::1]:443");
        if req.URL.Hostname() == "::1" && req.URL.Port() == "443" {
            fmt::Println!("[ 7] IPv6 host bracket strip    PASS");
        } else {
            fmt::Println!(
                "[ 7] IPv6 host bracket strip    FAIL host={} port={}",
                req.URL.Hostname(),
                req.URL.Port()
            );
            failed += 1;
        }
    }

    if failed == 0 {
        fmt::Println!("ok 7/7");
        syscall::Exit(0);
    } else {
        fmt::Println!("FAIL {} of 7", failed);
        syscall::Exit(1);
    }
}
