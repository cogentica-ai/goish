// net_ipmask_smoke — exercise net.IPMask + IP.{DefaultMask, Mask}
// + IPv4Mask + CIDRMask.  (ip.go:43, 67, 79, 248, 272, 440, 449)

#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

use goish::fmt;
use goish::net;
use goish::string;
use goish::syscall;
use goish::types::int;

#[goish::main]
fn main() {
    let mut failed = 0;

    // 1. IPv4Mask — constructs a 4-byte mask.
    {
        let m = net::IPv4Mask(255, 255, 255, 0);
        if m.bytes.Len() == 4 && m.bytes[0] == 255 && m.bytes[3] == 0 {
            fmt::Println!("[ 1] IPv4Mask                  PASS");
        } else {
            fmt::Println!("[ 1] IPv4Mask                  FAIL");
            failed += 1;
        }
    }

    // 2. CIDRMask /24 over 32 bits → 255.255.255.0.
    {
        let m = net::CIDRMask(24, 32);
        if m.bytes.Len() == 4
            && m.bytes[0] == 0xff
            && m.bytes[1] == 0xff
            && m.bytes[2] == 0xff
            && m.bytes[3] == 0
        {
            fmt::Println!("[ 2] CIDRMask /24              PASS");
        } else {
            fmt::Println!("[ 2] CIDRMask /24              FAIL");
            failed += 1;
        }
    }

    // 3. CIDRMask /1 over 32 → 0x80, 0, 0, 0.
    {
        let m = net::CIDRMask(1, 32);
        if m.bytes[0] == 0x80 && m.bytes[1] == 0 && m.bytes[2] == 0 && m.bytes[3] == 0 {
            fmt::Println!("[ 3] CIDRMask /1               PASS");
        } else {
            fmt::Println!("[ 3] CIDRMask /1               FAIL");
            failed += 1;
        }
    }

    // 4. CIDRMask /0 over 32 → all zeros.
    {
        let m = net::CIDRMask(0, 32);
        if m.bytes.Len() == 4
            && m.bytes[0] == 0
            && m.bytes[1] == 0
            && m.bytes[2] == 0
            && m.bytes[3] == 0
        {
            fmt::Println!("[ 4] CIDRMask /0               PASS");
        } else {
            fmt::Println!("[ 4] CIDRMask /0               FAIL");
            failed += 1;
        }
    }

    // 5. CIDRMask invalid (ones > bits) → nil mask.
    {
        let m = net::CIDRMask(33, 32);
        if m.bytes.Len() == 0 {
            fmt::Println!("[ 5] CIDRMask invalid          PASS");
        } else {
            fmt::Println!("[ 5] CIDRMask invalid          FAIL");
            failed += 1;
        }
    }

    // 6. CIDRMask bad bits (e.g. 64) → nil mask.
    {
        let m = net::CIDRMask(8, 64);
        if m.bytes.Len() == 0 {
            fmt::Println!("[ 6] CIDRMask bad bits         PASS");
        } else {
            fmt::Println!("[ 6] CIDRMask bad bits         FAIL");
            failed += 1;
        }
    }

    // 7. IPMask.Size — /24 → (24, 32).
    {
        let m = net::CIDRMask(24, 32);
        let (ones, bits) = m.Size();
        if ones == 24 && bits == 32 {
            fmt::Println!("[ 7] IPMask.Size /24           PASS");
        } else {
            fmt::Println!("[ 7] IPMask.Size /24           FAIL");
            failed += 1;
        }
    }

    // 8. IPMask.Size non-canonical → (0, 0).
    {
        let m = net::IPv4Mask(0xff, 0, 0xff, 0); // not 1s-then-0s
        let (ones, bits) = m.Size();
        if ones == 0 && bits == 0 {
            fmt::Println!("[ 8] IPMask.Size non-canon     PASS");
        } else {
            fmt::Println!("[ 8] IPMask.Size non-canon     FAIL");
            failed += 1;
        }
    }

    // 9. IPMask.String — hex, no punctuation.
    {
        let m = net::IPv4Mask(0xff, 0xff, 0xff, 0);
        let s = m.String();
        if s == string("ffffff00") {
            fmt::Println!("[ 9] IPMask.String hex         PASS");
        } else {
            fmt::Println!("[ 9] IPMask.String hex         FAIL");
            failed += 1;
        }
    }

    // 10. IPMask.String nil → "<nil>".
    {
        let m: net::IPMask = net::IPMask::default();
        let s = m.String();
        if s == string("<nil>") {
            fmt::Println!("[10] IPMask.String nil         PASS");
        } else {
            fmt::Println!("[10] IPMask.String nil         FAIL");
            failed += 1;
        }
    }

    // 11. IP.DefaultMask — class A (1.2.3.4) → /8.
    {
        let m = net::IPv4(1, 2, 3, 4).DefaultMask();
        let (ones, _) = m.Size();
        if ones == 8 {
            fmt::Println!("[11] DefaultMask class A       PASS");
        } else {
            fmt::Println!("[11] DefaultMask class A       FAIL");
            failed += 1;
        }
    }

    // 12. IP.DefaultMask — class B (128.1.0.0) → /16.
    {
        let m = net::IPv4(128, 1, 0, 0).DefaultMask();
        let (ones, _) = m.Size();
        if ones == 16 {
            fmt::Println!("[12] DefaultMask class B       PASS");
        } else {
            fmt::Println!("[12] DefaultMask class B       FAIL");
            failed += 1;
        }
    }

    // 13. IP.DefaultMask — class C (192.168.1.1) → /24.
    {
        let m = net::IPv4(192, 168, 1, 1).DefaultMask();
        let (ones, _) = m.Size();
        if ones == 24 {
            fmt::Println!("[13] DefaultMask class C       PASS");
        } else {
            fmt::Println!("[13] DefaultMask class C       FAIL");
            failed += 1;
        }
    }

    // 14. IP.DefaultMask — nil IP → nil mask.
    {
        let m = net::IP::default().DefaultMask();
        if m.bytes.Len() == 0 {
            fmt::Println!("[14] DefaultMask nil-IP        PASS");
        } else {
            fmt::Println!("[14] DefaultMask nil-IP        FAIL");
            failed += 1;
        }
    }

    // 15. IP.Mask — 192.168.1.42 & /24 → 192.168.1.0.
    {
        let ip = net::IPv4(192, 168, 1, 42);
        let m = net::CIDRMask(24, 32);
        let masked = ip.Mask(m);
        if masked.bytes.Len() == 4
            && masked.bytes[0] == 192
            && masked.bytes[1] == 168
            && masked.bytes[2] == 1
            && masked.bytes[3] == 0
        {
            fmt::Println!("[15] IP.Mask /24               PASS");
        } else {
            fmt::Println!("[15] IP.Mask /24               FAIL");
            failed += 1;
        }
    }

    // 16. IP.Mask — 10.20.30.40 & /16 → 10.20.0.0.
    {
        let ip = net::IPv4(10, 20, 30, 40);
        let m = net::CIDRMask(16, 32);
        let masked = ip.Mask(m);
        if masked.bytes[0] == 10
            && masked.bytes[1] == 20
            && masked.bytes[2] == 0
            && masked.bytes[3] == 0
        {
            fmt::Println!("[16] IP.Mask /16               PASS");
        } else {
            fmt::Println!("[16] IP.Mask /16               FAIL");
            failed += 1;
        }
    }

    // 17. IP.Mask — shape mismatch (4-byte IP, 16-byte mask) → nil.
    {
        let ip = net::IPv4(10, 0, 0, 1);
        let m = net::CIDRMask(64, 128);
        let masked = ip.Mask(m);
        if masked.bytes.Len() == 0 {
            fmt::Println!("[17] IP.Mask shape mismatch    PASS");
        } else {
            fmt::Println!("[17] IP.Mask shape mismatch    FAIL");
            failed += 1;
        }
    }

    let total: int = 17;
    if failed == 0 {
        fmt::Println!("ok 17/17");
        syscall::Exit(0);
    } else {
        fmt::Println!("FAIL", failed, "of", total);
        syscall::Exit(1);
    }
}
