// net_hostport_smoke — exercise net::SplitHostPort and net::JoinHostPort
// (line-by-line ports of ipsock.go:165 / :236).

#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

use goish::net;
use goish::{string, syscall, Println};

#[goish::main]
fn main() {
    let mut failed = 0;

    // 1. Plain host:port.
    {
        let (host, port, err) = net::SplitHostPort(string("example.com:8080"));
        if err.IsNil() && host == "example.com" && port == "8080" {
            Println!("[ 1] plain host:port           PASS");
        } else {
            Println!("[ 1] plain host:port           FAIL host={} port={}", host, port);
            failed += 1;
        }
    }

    // 2. IPv4 literal.
    {
        let (host, port, err) = net::SplitHostPort(string("127.0.0.1:443"));
        if err.IsNil() && host == "127.0.0.1" && port == "443" {
            Println!("[ 2] IPv4 literal              PASS");
        } else {
            Println!("[ 2] IPv4 literal              FAIL");
            failed += 1;
        }
    }

    // 3. IPv6 literal in brackets.
    {
        let (host, port, err) = net::SplitHostPort(string("[::1]:80"));
        if err.IsNil() && host == "::1" && port == "80" {
            Println!("[ 3] IPv6 brackets             PASS");
        } else {
            Println!("[ 3] IPv6 brackets             FAIL host={} port={}", host, port);
            failed += 1;
        }
    }

    // 4. Missing port → error.
    {
        let (_, _, err) = net::SplitHostPort(string("example.com"));
        if !err.IsNil() {
            Println!("[ 4] missing port → err        PASS");
        } else {
            Println!("[ 4] missing port → err        FAIL");
            failed += 1;
        }
    }

    // 5. Too many colons (IPv6 without brackets) → error.
    {
        let (_, _, err) = net::SplitHostPort(string("::1:80"));
        if !err.IsNil() {
            Println!("[ 5] too many colons → err     PASS");
        } else {
            Println!("[ 5] too many colons → err     FAIL");
            failed += 1;
        }
    }

    // 6. JoinHostPort with hostname.
    {
        let s = net::JoinHostPort(string("example.com"), string("8080"));
        if s == "example.com:8080" {
            Println!("[ 6] Join hostname:port        PASS");
        } else {
            Println!("[ 6] Join hostname:port        FAIL got={}", s);
            failed += 1;
        }
    }

    // 7. JoinHostPort with IPv6 — adds brackets.
    {
        let s = net::JoinHostPort(string("::1"), string("80"));
        if s == "[::1]:80" {
            Println!("[ 7] Join IPv6                 PASS");
        } else {
            Println!("[ 7] Join IPv6                 FAIL got={}", s);
            failed += 1;
        }
    }

    // 8. Round-trip: Join → Split.
    {
        let joined = net::JoinHostPort(string("fe80::1"), string("9000"));
        let (h, p, err) = net::SplitHostPort(joined);
        if err.IsNil() && h == "fe80::1" && p == "9000" {
            Println!("[ 8] Join → Split round-trip   PASS");
        } else {
            Println!("[ 8] Join → Split round-trip   FAIL h={} p={}", h, p);
            failed += 1;
        }
    }

    if failed == 0 {
        Println!("ok 8/8");
        syscall::Exit(0);
    } else {
        Println!("FAIL {} of 8", failed);
        syscall::Exit(1);
    }
}
