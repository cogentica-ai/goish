// url_userinfo_smoke — exercise url::User / UserPassword / Userinfo.

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

    // 1. User() yields no-password Userinfo.
    {
        let u = url::User(string("alice"));
        let (p, ok) = u.Password();
        if u.Username() == "alice" && !ok && p.Len() == 0 {
            fmt::Println!("[ 1] User() no password         PASS");
        } else {
            fmt::Println!("[ 1] User() no password         FAIL");
            failed += 1;
        }
    }

    // 2. UserPassword() round-trip.
    {
        let u = url::UserPassword(string("bob"), string("s3cret"));
        let (p, ok) = u.Password();
        if u.Username() == "bob" && ok && p == "s3cret" {
            fmt::Println!("[ 2] UserPassword              PASS");
        } else {
            fmt::Println!("[ 2] UserPassword              FAIL");
            failed += 1;
        }
    }

    // 3. String() with no password.
    {
        let u = url::User(string("alice"));
        let s = u.String();
        if s == "alice" {
            fmt::Println!("[ 3] String() no password      PASS");
        } else {
            fmt::Println!("[ 3] String() no password      FAIL got={}", s);
            failed += 1;
        }
    }

    // 4. String() with password.
    {
        let u = url::UserPassword(string("bob"), string("pw"));
        let s = u.String();
        if s == "bob:pw" {
            fmt::Println!("[ 4] String() with password    PASS");
        } else {
            fmt::Println!("[ 4] String() with password    FAIL got={}", s);
            failed += 1;
        }
    }

    // 5. Special chars are escaped via PathEscape.
    {
        let u = url::UserPassword(string("a b"), string("pw"));
        let s = u.String();
        if s == "a%20b:pw" {
            fmt::Println!("[ 5] String() escapes spaces   PASS");
        } else {
            fmt::Println!("[ 5] String() escapes spaces   FAIL got={}", s);
            failed += 1;
        }
    }

    // 6. Empty password (set vs unset).
    {
        let u = url::UserPassword(string("alice"), string(""));
        let (p, ok) = u.Password();
        if ok && p.Len() == 0 {
            fmt::Println!("[ 6] empty pass distinct       PASS");
        } else {
            fmt::Println!("[ 6] empty pass distinct       FAIL");
            failed += 1;
        }
    }

    if failed == 0 {
        fmt::Println!("ok 6/6");
        syscall::Exit(0);
    } else {
        fmt::Println!("FAIL {} of 6", failed);
        syscall::Exit(1);
    }
}
