// net_ip_marshal_smoke — exercise net.IP.{Equal, MarshalText,
// UnmarshalText, AppendText}. (ip.go:349-402)

#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

use alloc::vec::Vec;
use goish::bytes;
use goish::convert::bytes as to_bytes;
use goish::fmt;
use goish::goslice::slice;
use goish::net;
use goish::string;
use goish::syscall;
use goish::types::byte;

#[goish::main]
fn main() {
    let mut failed = 0;

    // 1. Equal — same IPv4 address.
    {
        let a = net::IPv4(127, 0, 0, 1);
        let b = net::IPv4(127, 0, 0, 1);
        if a.Equal(&b) {
            fmt::Println!("[ 1] Equal same v4             PASS");
        } else {
            fmt::Println!("[ 1] Equal same v4             FAIL");
            failed += 1;
        }
    }

    // 2. Equal — different IPv4 addresses.
    {
        let a = net::IPv4(127, 0, 0, 1);
        let b = net::IPv4(127, 0, 0, 2);
        if !a.Equal(&b) {
            fmt::Println!("[ 2] Equal differ v4           PASS");
        } else {
            fmt::Println!("[ 2] Equal differ v4           FAIL");
            failed += 1;
        }
    }

    // 3. Equal — both nil.
    {
        let a = net::IP::default();
        let b = net::IP::default();
        if a.Equal(&b) {
            fmt::Println!("[ 3] Equal nil-nil             PASS");
        } else {
            fmt::Println!("[ 3] Equal nil-nil             FAIL");
            failed += 1;
        }
    }

    // 4. Equal — nil vs non-nil.
    {
        let a = net::IP::default();
        let b = net::IPv4(0, 0, 0, 0);
        if !a.Equal(&b) {
            fmt::Println!("[ 4] Equal nil-vs-v4           PASS");
        } else {
            fmt::Println!("[ 4] Equal nil-vs-v4           FAIL");
            failed += 1;
        }
    }

    // 5. MarshalText — IPv4 → dotted-decimal bytes.
    {
        let ip = net::IPv4(192, 0, 2, 1);
        let (txt, err) = ip.MarshalText();
        let want = to_bytes("192.0.2.1");
        if err.IsNil() && bytes::Equal(txt, want) {
            fmt::Println!("[ 5] MarshalText v4            PASS");
        } else {
            fmt::Println!("[ 5] MarshalText v4            FAIL");
            failed += 1;
        }
    }

    // 6. MarshalText — nil IP → empty slice.
    {
        let ip = net::IP::default();
        let (txt, err) = ip.MarshalText();
        if err.IsNil() && txt.Len() == 0 {
            fmt::Println!("[ 6] MarshalText nil           PASS");
        } else {
            fmt::Println!("[ 6] MarshalText nil           FAIL");
            failed += 1;
        }
    }

    // 7. UnmarshalText — round-trip ParseIP through bytes.
    {
        let mut ip = net::IP::default();
        let err = ip.UnmarshalText(to_bytes("10.0.0.1"));
        if err.IsNil() && ip.String() == string("10.0.0.1") {
            fmt::Println!("[ 7] UnmarshalText round-trip  PASS");
        } else {
            fmt::Println!("[ 7] UnmarshalText round-trip  FAIL");
            failed += 1;
        }
    }

    // 8. UnmarshalText — empty resets IP to nil.
    {
        let mut ip = net::IPv4(1, 2, 3, 4);
        let err = ip.UnmarshalText(slice::<byte>::__from_vec(Vec::new()));
        if err.IsNil() && ip.IsNil() {
            fmt::Println!("[ 8] UnmarshalText empty→nil   PASS");
        } else {
            fmt::Println!("[ 8] UnmarshalText empty→nil   FAIL");
            failed += 1;
        }
    }

    // 9. UnmarshalText — invalid text returns error.
    {
        let mut ip = net::IP::default();
        let err = ip.UnmarshalText(to_bytes("not-an-ip"));
        if !err.IsNil() {
            fmt::Println!("[ 9] UnmarshalText invalid     PASS");
        } else {
            fmt::Println!("[ 9] UnmarshalText invalid     FAIL");
            failed += 1;
        }
    }

    // 10. AppendText — appends to existing buffer.
    {
        let ip = net::IPv4(1, 2, 3, 4);
        let prefix = to_bytes("ip=");
        let (out, err) = ip.AppendText(prefix);
        let want = to_bytes("ip=1.2.3.4");
        if err.IsNil() && bytes::Equal(out, want) {
            fmt::Println!("[10] AppendText                PASS");
        } else {
            fmt::Println!("[10] AppendText                FAIL");
            failed += 1;
        }
    }

    if failed == 0 {
        fmt::Println!("ok 10/10");
        syscall::Exit(0);
    } else {
        fmt::Println!("FAIL", failed, "of 10");
        syscall::Exit(1);
    }
}
