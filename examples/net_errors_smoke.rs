// net_errors_smoke — net/net.go's error hierarchy and the Addr interface.
//
// These types are the reason this file exists: `net.Addr` and
// `*net.OpError` are what net/http's remaining transport work
// (socks_bundle.go, httputil/persist.go, Transport.DialContext,
// DumpRequestOut) takes and returns. None of them can be written
// without these two.
//
// The error STRINGS are the contract — they reach users and get
// matched in tests — so every expectation here is a live go1.25.5 run,
// not a reading of the source:
//
//   dial tcp 10.0.0.1:1234->93.184.216.34:80: connection refused
//   dial tcp 93.184.216.34:80: connection refused
//   listen tcp: connection refused
//   read: connection refused
//   invalid IP address: 1.2.3
//   address example.com: missing port in address
//   bare
//   unknown network sctp
//   lookup nope.example on 8.8.8.8:53: no such host
//   lookup slow.example: timeout
//
// OpError.Error is a four-way join and each field can be absent, so all
// four shapes are checked. The "->" between Source and Addr appears
// ONLY when Source is set; with Addr alone it is a space. Getting that
// wrong produces "dial tcp->93.184.216.34:80", which reads as a typo
// rather than a bug.

#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

use alloc::sync::Arc;

use goish::errors;
use goish::fmt;
use goish::net::net::{Addr, DNSError, InvalidAddrError, OpError, ParseError, UnknownNetworkError};
use goish::net::{AddrError, ErrClosed, TCPAddr};
use goish::{string, syscall};

/// Print one comparison; returns true on a match. A plain fn rather
/// than a closure so it does not hold `failed`/`n` borrowed for the
/// whole of main.
fn eq(n: i64, label: &'static str, got: goish::gostring::string, want: &'static str) -> bool {
    if got == want {
        fmt::Println!("[", n, "] ", label, "  PASS");
        return true;
    }
    fmt::Println!("[", n, "] ", label, "  FAIL");
    fmt::Println!("     got:  ", got);
    fmt::Println!("     want: ", want);
    return false;
}

fn addr(a: u8, b: u8, c: u8, d: u8, port: i64) -> Arc<dyn Addr> {
    return Arc::new(TCPAddr {
        IP: [a, b, c, d],
        Port: port,
    });
}

#[goish::main]
fn main() {
    let mut failed = 0;
    let mut n = 1;

    let base = errors::New(string("connection refused"));

    // 1-4. OpError's four shapes. Source present -> "->"; Source absent
    //      but Addr present -> a space; neither -> nothing.
    {
        let e = OpError {
            Op: string("dial"),
            Net: string("tcp"),
            Source: Some(addr(10, 0, 0, 1, 1234)),
            Addr: Some(addr(93, 184, 216, 34, 80)),
            Err: base.clone(),
        };
        if !eq(
            n,
            "OpError src->addr",
            goish::errors::ErrorTrait::Error(&e),
            "dial tcp 10.0.0.1:1234->93.184.216.34:80: connection refused",
        ) {
            failed += 1;
        }
        n += 1;
    }
    {
        let e = OpError {
            Op: string("dial"),
            Net: string("tcp"),
            Source: None,
            Addr: Some(addr(93, 184, 216, 34, 80)),
            Err: base.clone(),
        };
        if !eq(
            n,
            "OpError addr only",
            goish::errors::ErrorTrait::Error(&e),
            "dial tcp 93.184.216.34:80: connection refused",
        ) {
            failed += 1;
        }
        n += 1;
    }
    {
        let e = OpError {
            Op: string("listen"),
            Net: string("tcp"),
            Source: None,
            Addr: None,
            Err: base.clone(),
        };
        if !eq(
            n,
            "OpError net only",
            goish::errors::ErrorTrait::Error(&e),
            "listen tcp: connection refused",
        ) {
            failed += 1;
        }
        n += 1;
    }
    {
        let e = OpError {
            Op: string("read"),
            Net: string(""),
            Source: None,
            Addr: None,
            Err: base.clone(),
        };
        if !eq(
            n,
            "OpError op only",
            goish::errors::ErrorTrait::Error(&e),
            "read: connection refused",
        ) {
            failed += 1;
        }
        n += 1;
    }

    // 5. OpError unwraps to the error it carries, so errors::Is reaches
    //    through it — which is how callers test for ErrClosed.
    {
        let e = OpError {
            Op: string("read"),
            Net: string("tcp"),
            Source: None,
            Addr: None,
            Err: ErrClosed.into(),
        };
        let wrapped: goish::error = errors::Wrap(e);
        let target: goish::error = ErrClosed.into();
        let ok = errors::Is(wrapped.clone(), target);
        if ok {
            fmt::Println!("[", n, "] OpError unwraps  PASS");
        } else {
            fmt::Println!("[", n, "] OpError unwraps  FAIL");
            failed += 1;
        }
        n += 1;
    }

    // 6-10. The literal-parser and address errors.
    {
        let e = ParseError {
            Type: string("IP address"),
            Text: string("1.2.3"),
        };
        if !eq(
            n,
            "ParseError",
            goish::errors::ErrorTrait::Error(&e),
            "invalid IP address: 1.2.3",
        ) {
            failed += 1;
        }
        n += 1;
    }
    {
        let e = AddrError {
            Err: string("missing port in address"),
            Addr: string("example.com"),
        };
        if !eq(
            n,
            "AddrError with addr",
            goish::errors::ErrorTrait::Error(&e),
            "address example.com: missing port in address",
        ) {
            failed += 1;
        }
        n += 1;
    }
    {
        // A bare AddrError prints Err alone — no "address : " prefix.
        let e = AddrError {
            Err: string("bare"),
            Addr: string(""),
        };
        if !eq(
            n,
            "AddrError bare",
            goish::errors::ErrorTrait::Error(&e),
            "bare",
        ) {
            failed += 1;
        }
        n += 1;
    }
    {
        let e = UnknownNetworkError(string("sctp"));
        if !eq(
            n,
            "UnknownNetworkError",
            goish::errors::ErrorTrait::Error(&e),
            "unknown network sctp",
        ) {
            failed += 1;
        }
        n += 1;
    }
    {
        let e = InvalidAddrError(string("bad addr"));
        if !eq(
            n,
            "InvalidAddrError",
            goish::errors::ErrorTrait::Error(&e),
            "bad addr",
        ) {
            failed += 1;
        }
        n += 1;
    }

    // 11-12. DNSError, with and without a server.
    {
        let mut e = DNSError::default();
        e.Err = string("no such host");
        e.Name = string("nope.example");
        e.Server = string("8.8.8.8:53");
        e.IsNotFound = true;
        if !eq(
            n,
            "DNSError with server",
            goish::errors::ErrorTrait::Error(&e),
            "lookup nope.example on 8.8.8.8:53: no such host",
        ) {
            failed += 1;
        }
        n += 1;
    }
    {
        let mut e = DNSError::default();
        e.Err = string("timeout");
        e.Name = string("slow.example");
        if !eq(
            n,
            "DNSError no server",
            goish::errors::ErrorTrait::Error(&e),
            "lookup slow.example: timeout",
        ) {
            failed += 1;
        }
        n += 1;
    }

    // 13. Temporary() is IsTimeout OR IsTemporary — not IsTemporary
    //     alone. A DNS timeout counts as temporary even when nobody set
    //     the temporary flag.
    {
        let mut t = DNSError::default();
        t.IsTimeout = true;
        let mut p = DNSError::default();
        p.IsTemporary = true;
        let neither = DNSError::default();
        if t.Temporary() && p.Temporary() && !neither.Temporary() && t.Timeout() && !p.Timeout() {
            fmt::Println!("[", n, "] DNSError Temporary  PASS");
        } else {
            fmt::Println!("[", n, "] DNSError Temporary  FAIL");
            failed += 1;
        }
        n += 1;
    }

    // 14. ErrClosed's text, and that TCPAddr satisfies Addr.
    {
        let a = addr(93, 184, 216, 34, 80);
        let closed: goish::error = ErrClosed.into();
        let ok = closed.Error() == "use of closed network connection"
            && a.Network() == "tcp"
            && a.String() == "93.184.216.34:80";
        if ok {
            fmt::Println!("[", n, "] ErrClosed + Addr impl  PASS");
        } else {
            fmt::Println!("[", n, "] ErrClosed + Addr impl  FAIL ", a.String());
            failed += 1;
        }
    }

    if failed == 0 {
        fmt::Println!("ok 14/14");
        syscall::Exit(0);
    } else {
        fmt::Println!("FAIL", failed, "of 14");
        syscall::Exit(1);
    }
}
