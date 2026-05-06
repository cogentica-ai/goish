// parse_mac_smoke — exercise net.ParseMAC + HardwareAddr.
// (net/mac.go)

#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

use goish::goslice::slice;
use goish::net::{HardwareAddr, HardwareAddrString, ParseMAC};
use goish::types::byte;
use goish::{string, syscall, Println};

#[goish::main]
fn main() {
    let mut failed = 0;

    // 1. 6-octet colon-separated.
    {
        let (hw, e) = ParseMAC(string("00:00:5e:00:53:01"));
        let raw: &[byte] = &hw;
        let want: &[u8] = &[0x00, 0x00, 0x5e, 0x00, 0x53, 0x01];
        if e.IsNil() && raw == want {
            Println!("[ 1] 6-octet colon            PASS");
        } else {
            Println!("[ 1] 6-octet colon            FAIL");
            failed += 1;
        }
    }

    // 2. 8-octet colon-separated (EUI-64).
    {
        let (hw, e) = ParseMAC(string("02:00:5e:10:00:00:00:01"));
        if e.IsNil() && hw.len() == 8 {
            Println!("[ 2] 8-octet colon            PASS");
        } else {
            Println!("[ 2] 8-octet colon            FAIL");
            failed += 1;
        }
    }

    // 3. 20-octet IPoIB (3*20 - 1 = 59 chars).
    {
        let (hw, e) = ParseMAC(string(
            "00:00:00:00:fe:80:00:00:00:00:00:00:02:00:5e:10:00:00:00:01",
        ));
        if e.IsNil() && hw.len() == 20 {
            Println!("[ 3] 20-octet IPoIB           PASS");
        } else {
            Println!("[ 3] 20-octet IPoIB           FAIL");
            failed += 1;
        }
    }

    // 4. Dash separator.
    {
        let (hw, e) = ParseMAC(string("00-00-5e-00-53-01"));
        let raw: &[byte] = &hw;
        let want: &[u8] = &[0x00, 0x00, 0x5e, 0x00, 0x53, 0x01];
        if e.IsNil() && raw == want {
            Println!("[ 4] dash sep                 PASS");
        } else {
            Println!("[ 4] dash sep                 FAIL");
            failed += 1;
        }
    }

    // 5. Cisco-style dotted (XXXX.XXXX.XXXX → 6 octets).
    {
        let (hw, e) = ParseMAC(string("0000.5e00.5301"));
        let raw: &[byte] = &hw;
        let want: &[u8] = &[0x00, 0x00, 0x5e, 0x00, 0x53, 0x01];
        if e.IsNil() && raw == want {
            Println!("[ 5] dotted 6-octet           PASS");
        } else {
            Println!("[ 5] dotted 6-octet           FAIL");
            failed += 1;
        }
    }

    // 6. Cisco-style dotted EUI-64.
    {
        let (hw, e) = ParseMAC(string("0200.5e10.0000.0001"));
        if e.IsNil() && hw.len() == 8 {
            Println!("[ 6] dotted 8-octet           PASS");
        } else {
            Println!("[ 6] dotted 8-octet           FAIL");
            failed += 1;
        }
    }

    // 7. Too short.
    {
        let (_hw, e) = ParseMAC(string("00:00:5e:00:53"));
        if !e.IsNil() {
            Println!("[ 7] too short err            PASS");
        } else {
            Println!("[ 7] too short err            FAIL");
            failed += 1;
        }
    }

    // 8. Wrong delimiter consistency (mixing : and -).
    {
        let (_hw, e) = ParseMAC(string("00:00-5e:00-53:01"));
        if !e.IsNil() {
            Println!("[ 8] mixed delim err          PASS");
        } else {
            Println!("[ 8] mixed delim err          FAIL");
            failed += 1;
        }
    }

    // 9. Non-hex digit.
    {
        let (_hw, e) = ParseMAC(string("00:00:5z:00:53:01"));
        if !e.IsNil() {
            Println!("[ 9] non-hex err              PASS");
        } else {
            Println!("[ 9] non-hex err              FAIL");
            failed += 1;
        }
    }

    // 10. HardwareAddrString round-trip on 6-octet.
    {
        let hw: HardwareAddr = slice::__from_vec(alloc::vec![0xab, 0xcd, 0xef, 0x01, 0x23, 0x45]);
        let s = HardwareAddrString(&hw);
        if s == "ab:cd:ef:01:23:45" {
            Println!("[10] String round-trip        PASS");
        } else {
            Println!("[10] String round-trip        FAIL got {}", s);
            failed += 1;
        }
    }

    // 11. Empty HardwareAddr → empty String.
    {
        let hw: HardwareAddr = slice::__from_vec(alloc::vec![]);
        let s = HardwareAddrString(&hw);
        if s == "" {
            Println!("[11] empty String             PASS");
        } else {
            Println!("[11] empty String             FAIL");
            failed += 1;
        }
    }

    // 12. Parse → String round-trip preserves canonical form.
    {
        let original = string("00:00:5e:00:53:01");
        let (hw, e) = ParseMAC(original.clone());
        if e.IsNil() {
            let back = HardwareAddrString(&hw);
            if back == original {
                Println!("[12] Parse-String round-trip PASS");
            } else {
                Println!("[12] Parse-String round-trip FAIL got {}", back);
                failed += 1;
            }
        } else {
            Println!("[12] Parse-String round-trip FAIL parse");
            failed += 1;
        }
    }

    if failed == 0 {
        Println!("ok 12/12");
        syscall::Exit(0);
    } else {
        Println!("FAIL", failed, "of 12");
        syscall::Exit(1);
    }
}
