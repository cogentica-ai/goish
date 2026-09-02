// net_mac_ref_smoke — net.ParseMAC against a running Go.
// (net/mac.go)
//
// Every expectation below is what a real Go 1.25.5 prints: the vectors
// are the output of `tools/gen_mac_ref.go` run in `package net` by
// `scripts/goref.sh`.
//
// src/net/mac.rs had NO provenance anchors and no manifest — it was one
// of twenty-five declarations in net/ that port_coverage reports as
// UNVERIFIED, matching Go by NAME ONLY. As that report puts it: a
// rename, a dropped argument or an invented body is invisible. This
// diffs it and anchors it.
//
// ParseMAC is worth diffing rather than assuming, because its
// acceptance rule is not "hex digits with separators":
//
//   * The separator is decided by the FIRST one seen and must then be
//     used consistently — "01:02-03:04:05:06" is refused.
//   * A dotted form groups FOUR hex digits, not two, so "0000.5e00.5301"
//     is six bytes while "01.02.03" is refused outright.
//   * Only three lengths are legal: 6, 8 and 20 bytes. Five groups or
//     seven are both refused.
//   * The error carries the ADDRESS back — "address 01: invalid MAC
//     address" — except for the empty string, which has no address to
//     name and reads just "invalid MAC address".

#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

use goish::goslice::slice;
use goish::gostring::string;
use goish::net;
use goish::types::int;
use goish::{fmt, syscall};

fn s(x: &str) -> string {
    return string::from_bytes(x.as_bytes());
}

fn eq(failed: &mut int, got: string, want: &str, what: &str) {
    if got == s(want) {
        return;
    }
    fmt::Printf!("[!!] %s FAIL got %q want %q\n", s(what), got, s(want));
    *failed += 1;
}

#[goish::main]
fn main() {
    let mut failed = 0;

    // 1. ParseMAC over the three separator conventions, the three legal
    //    lengths, and every refusal — with the error text compared.
    {
        let cases: [(&str, &str, i64, &str); 25] = [
            ("00:00:5e:00:53:01", "", 6, "00:00:5e:00:53:01"),
            ("00-00-5e-00-53-01", "", 6, "00:00:5e:00:53:01"),
            ("0000.5e00.5301", "", 6, "00:00:5e:00:53:01"),
            ("02:00:5e:10:00:00:00:01", "", 8, "02:00:5e:10:00:00:00:01"),
            ("02-00-5e-10-00-00-00-01", "", 8, "02:00:5e:10:00:00:00:01"),
            ("0200.5e10.0000.0001", "", 8, "02:00:5e:10:00:00:00:01"),
            (
                "00:00:00:00:fe:80:00:00:00:00:00:00:02:00:5e:10:00:00:00:01",
                "",
                20,
                "00:00:00:00:fe:80:00:00:00:00:00:00:02:00:5e:10:00:00:00:01",
            ),
            (
                "00-00-00-00-fe-80-00-00-00-00-00-00-02-00-5e-10-00-00-00-01",
                "",
                20,
                "00:00:00:00:fe:80:00:00:00:00:00:00:02:00:5e:10:00:00:00:01",
            ),
            (
                "0000.0000.fe80.0000.0000.0000.0200.5e10.0000.0001",
                "",
                20,
                "00:00:00:00:fe:80:00:00:00:00:00:00:02:00:5e:10:00:00:00:01",
            ),
            ("AB:CD:EF:12:34:56", "", 6, "ab:cd:ef:12:34:56"),
            ("ab:cd:ef:12:34:56", "", 6, "ab:cd:ef:12:34:56"),
            ("", "invalid MAC address", 0, ""),
            ("01", "address 01: invalid MAC address", 0, ""),
            ("01:", "address 01:: invalid MAC address", 0, ""),
            (
                ":01:02:03:04:05",
                "address :01:02:03:04:05: invalid MAC address",
                0,
                "",
            ),
            (
                "01:02:03:04:05:",
                "address 01:02:03:04:05:: invalid MAC address",
                0,
                "",
            ),
            (
                "01:02-03:04:05:06",
                "address 01:02-03:04:05:06: invalid MAC address",
                0,
                "",
            ),
            (
                "0000.5e00.53011",
                "address 0000.5e00.53011: invalid MAC address",
                0,
                "",
            ),
            ("0000.5e00", "address 0000.5e00: invalid MAC address", 0, ""),
            (
                "00:00:5e:00:53",
                "address 00:00:5e:00:53: invalid MAC address",
                0,
                "",
            ),
            (
                "00:00:5e:00:53:01:02",
                "address 00:00:5e:00:53:01:02: invalid MAC address",
                0,
                "",
            ),
            (
                "gg:00:5e:00:53:01",
                "address gg:00:5e:00:53:01: invalid MAC address",
                0,
                "",
            ),
            (
                "0000.5e00.5301.",
                "address 0000.5e00.5301.: invalid MAC address",
                0,
                "",
            ),
            ("01.02.03", "address 01.02.03: invalid MAC address", 0, ""),
            (
                "00000.5e00.5301",
                "address 00000.5e00.5301: invalid MAC address",
                0,
                "",
            ),
        ];
        let mut i = 0;
        while i < cases.len() {
            let (inp, we, wl, ws) = cases[i];
            let (a, err) = net::ParseMAC(inp);
            if we.len() > 0 {
                if err.IsNil() {
                    fmt::Printf!("[!!] %q FAIL expected error\n", s(inp));
                    failed += 1;
                } else {
                    eq(&mut failed, err.Error(), we, inp);
                }
            } else if !err.IsNil() {
                fmt::Printf!("[!!] %q FAIL %q\n", s(inp), err.Error());
                failed += 1;
            } else {
                if a.Len() != wl {
                    fmt::Printf!("[!!] %q FAIL len=%d want %d\n", s(inp), a.Len(), wl);
                    failed += 1;
                }
                eq(&mut failed, net::HardwareAddrString(&a), ws, inp);
            }
            i += 1;
        }
        fmt::Println!("[  1 ] ParseMAC: separators, lengths and refusals");
    }

    // 2. HardwareAddr::String over raw bytes, including the empty
    //    address (which is the empty string, not "00") and a
    //    single-byte one (which has no separator at all).
    {
        {
            let b: [u8; 0] = [];
            let _ = b;
        }
        {
            let b: [u8; 1] = [0];
            let _ = b;
        }
        {
            let b: [u8; 6] = [0, 0, 0, 0, 0, 0];
            let _ = b;
        }
        {
            let b: [u8; 6] = [0, 0, 0, 0, 0, 0];
            let _ = b;
        }
        {
            let b: [u8; 8] = [0, 0, 0, 0, 0, 0, 0, 0];
            let _ = b;
        }
        let cases: [(&[u8], &str); 5] = [
            (&[], ""),
            (&[0x01], "01"),
            (&[0, 0, 0x5e, 0, 0x53, 1], "00:00:5e:00:53:01"),
            (&[0xff, 0xff, 0xff, 0xff, 0xff, 0xff], "ff:ff:ff:ff:ff:ff"),
            (
                &[0x02, 0x00, 0x5e, 0x10, 0, 0, 0, 0x01],
                "02:00:5e:10:00:00:00:01",
            ),
        ];
        let mut i = 0;
        while i < cases.len() {
            let (b, want) = cases[i];
            let h: net::HardwareAddr = slice::__from_vec(b.to_vec());
            eq(&mut failed, net::HardwareAddrString(&h), want, want);
            i += 1;
        }
        fmt::Println!("[  2 ] HardwareAddr::String");
    }

    // 3. The error is a real *net.AddrError, not a hand-built string.
    //    This is the half that matters more than the text: a caller
    //    asking `errors.As(err, &net.AddrError{})` — to find out WHICH
    //    address failed — got false before, because the error was an
    //    errors.New carrying a formatted message and nothing else.
    {
        let (_, err) = net::ParseMAC("gg:00:5e:00:53:01");
        match goish::errors::AsConcrete::<net::net::AddrError>(&err) {
            None => {
                fmt::Println!("[!!] ParseMAC error is not an AddrError");
                failed += 1;
            }
            Some(ae) => {
                eq(
                    &mut failed,
                    ae.Err.clone(),
                    "invalid MAC address",
                    "AddrError.Err",
                );
                eq(
                    &mut failed,
                    ae.Addr.clone(),
                    "gg:00:5e:00:53:01",
                    "AddrError.Addr",
                );
            }
        }
        // And the empty input keeps an empty Addr, which is what makes
        // its message omit the "address …: " prefix.
        let (_, err0) = net::ParseMAC("");
        match goish::errors::AsConcrete::<net::net::AddrError>(&err0) {
            None => {
                fmt::Println!("[!!] empty ParseMAC error is not an AddrError");
                failed += 1;
            }
            Some(ae) => {
                eq(&mut failed, ae.Addr.clone(), "", "empty AddrError.Addr");
            }
        }
        fmt::Println!("[  3 ] the error is a *net.AddrError");
    }

    if failed == 0 {
        fmt::Println!("ok - net.ParseMAC matches Go");
        syscall::Exit(0);
    } else {
        fmt::Println!("FAIL", failed);
        syscall::Exit(1);
    }
}
