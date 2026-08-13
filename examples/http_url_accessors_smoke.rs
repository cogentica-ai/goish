// URL accessors and ParseQuery against Go 1.25.5's net/url.
//
// Expected values from a goref run. Continues the sweep of
// src/net/http/url.rs, which has zero provenance anchors and has
// already yielded three divergences.
//
// Cases chosen for the edges Go handles specially:
//   [::1]:8080  -> Hostname strips the brackets, Port is "8080"
//   [::1]       -> Hostname strips brackets, Port is ""
//   no path     -> RequestURI is "/" even though EscapedPath is ""
//   "a"         -> ParseQuery yields key "a" with ONE empty-string
//                  value, not an absent key and not an empty list
//   "a=1;b=2"   -> semicolons are an ERROR since Go 1.17, not a separator
#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

use goish::net::http::url;
use goish::{errors, fmt, string, syscall};

fn chk(raw: &'static str, want: &'static str, bad: &mut i32) {
    let (u, err) = url::Parse(string(raw));
    if err != errors::nil {
        fmt::Println!("FAIL ", raw, ": err ", err.Error());
        *bad += 1;
        return;
    }
    let got = fmt::Sprintf!(
        "Hostname=%s Port=%s RequestURI=%s EscapedPath=%s",
        u.Hostname(),
        u.Port(),
        u.RequestURI(),
        u.EscapedPath()
    );
    if got != want {
        fmt::Println!("FAIL ", raw);
        fmt::Println!("  got  ", got);
        fmt::Println!("  want ", want);
        *bad += 1;
    }
}

#[goish::main]
fn main() {
    let mut bad = 0i32;

    chk("http://example.com/p",
        "Hostname=example.com Port= RequestURI=/p EscapedPath=/p", &mut bad);
    chk("http://example.com:8080/p",
        "Hostname=example.com Port=8080 RequestURI=/p EscapedPath=/p", &mut bad);
    chk("http://[::1]:8080/p",
        "Hostname=::1 Port=8080 RequestURI=/p EscapedPath=/p", &mut bad);
    chk("http://[::1]/p",
        "Hostname=::1 Port= RequestURI=/p EscapedPath=/p", &mut bad);
    chk("http://example.com/p?q=1&r=2",
        "Hostname=example.com Port= RequestURI=/p?q=1&r=2 EscapedPath=/p", &mut bad);
    chk("http://example.com",
        "Hostname=example.com Port= RequestURI=/ EscapedPath=", &mut bad);

    // ParseQuery — repeated keys accumulate in order.
    {
        let (v, err) = url::ParseQuery(string("a=1&b=2&a=3"));
        if err != errors::nil {
            fmt::Println!("FAIL ParseQuery basic err");
            bad += 1;
        } else {
            let (a, _) = v.Get(string("a"));
            let (b, _) = v.Get(string("b"));
            if a.len() != 2 || a[0] != "1" || a[1] != "3" {
                fmt::Println!("FAIL ParseQuery a-values");
                bad += 1;
            }
            if b.len() != 1 || b[0] != "2" {
                fmt::Println!("FAIL ParseQuery b-values");
                bad += 1;
            }
        }
    }

    // A bare key "a" yields key "a" with ONE empty-string value.
    // Go prints this as map[a:[]], which reads like an empty list —
    // it is not. `len=1, vals=[""]`, same as for "a=".
    {
        let (v, err) = url::ParseQuery(string("a"));
        let (a, ok) = v.Get(string("a"));
        if err != errors::nil || !ok || a.len() != 1 || a[0] != "" {
            fmt::Println!("FAIL ParseQuery bare key");
            bad += 1;
        }
        let (v2, _) = url::ParseQuery(string("a="));
        let (a2, ok2) = v2.Get(string("a"));
        if !ok2 || a2.len() != 1 || a2[0] != "" {
            fmt::Println!("FAIL ParseQuery a=");
            bad += 1;
        }
    }

    // An empty key is legal.
    {
        let (v, err) = url::ParseQuery(string("=v"));
        let (e, ok) = v.Get(string(""));
        if err != errors::nil || !ok || e.len() != 1 || e[0] != "v" {
            fmt::Println!("FAIL ParseQuery empty key");
            bad += 1;
        }
    }

    // Bad escape is an error.
    {
        let (_, err) = url::ParseQuery(string("a=%zz"));
        if err == errors::nil {
            fmt::Println!("FAIL ParseQuery bad escape: expected error");
            bad += 1;
        }
    }

    // Semicolon is an ERROR since Go 1.17, not a separator.
    {
        let (_, err) = url::ParseQuery(string("a=1;b=2"));
        if err == errors::nil {
            fmt::Println!("FAIL ParseQuery semicolon: expected error");
            bad += 1;
        }
    }

    if bad == 0 {
        fmt::Println!("URL_ACCESSORS_OK 12/12");
        syscall::Exit(0);
    } else {
        fmt::Println!("FAILED ", bad);
        syscall::Exit(1);
    }
}
