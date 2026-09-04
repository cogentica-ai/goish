// net_ip_smoke — exercise net.IP, net.IPv4, net.ParseIP and methods
// (IsNil, To4, String). IPv4-only slim port; IPv6 forms return nil.

#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

use goish::fmt;
use goish::net;
use goish::string;
use goish::syscall;

#[goish::main]
fn main() {
    let mut failed = 0;

    // 1. IPv4 constructor + String.
    {
        let ip = net::IPv4(192, 0, 2, 1);
        if ip.String() == string("192.0.2.1") {
            fmt::Println!("[ 1] IPv4 + String             PASS");
        } else {
            fmt::Println!("[ 1] IPv4 + String             FAIL");
            failed += 1;
        }
    }

    // 2. IPv4 boundary values.
    {
        let zero = net::IPv4(0, 0, 0, 0);
        let max = net::IPv4(255, 255, 255, 255);
        if zero.String() == string("0.0.0.0") && max.String() == string("255.255.255.255") {
            fmt::Println!("[ 2] IPv4 boundary             PASS");
        } else {
            fmt::Println!("[ 2] IPv4 boundary             FAIL");
            failed += 1;
        }
    }

    // 3. ParseIP valid IPv4 dotted-decimal.
    {
        let ip = net::ParseIP(string("127.0.0.1"));
        if !ip.IsNil() && ip.String() == string("127.0.0.1") {
            fmt::Println!("[ 3] ParseIP 127.0.0.1         PASS");
        } else {
            fmt::Println!("[ 3] ParseIP 127.0.0.1         FAIL");
            failed += 1;
        }
    }

    // 4. ParseIP rejects malformed input. "::1" used to sit in this
    //    list, on the grounds that goish had no IPv6 form at all —
    //    which made a valid address indistinguishable from garbage.
    //    Case 9 now asserts the opposite.
    {
        let cases = [
            "",
            "256.0.0.0",  // octet > 255
            "1.2.3",      // too few octets
            "1.2.3.4.5",  // too many
            "1.2.3.4 ",   // trailing space
            "1.2.3.04",   // leading zero in non-zero octet
            "1.2.3.x",    // non-digit
            "1234.0.0.0", // 4 digits in an octet
        ];
        let mut all_nil = true;
        let mut i = 0;
        while i < cases.len() {
            let ip = net::ParseIP(string(cases[i]));
            if !ip.IsNil() {
                all_nil = false;
                break;
            }
            i += 1;
        }
        if all_nil {
            fmt::Println!("[ 4] ParseIP rejects bad       PASS");
        } else {
            fmt::Println!("[ 4] ParseIP rejects bad       FAIL");
            failed += 1;
        }
    }

    // 9. ParseIP accepts IPv6, and round-trips it through the RFC 5952
    //    form. Verified against Go 1.25.5; net_ip_ref_smoke pins the
    //    whole surface line for line.
    {
        let ip = net::ParseIP(string("::1"));
        let mapped = net::ParseIP(string("::ffff:1.2.3.4"));
        if !ip.IsNil()
            && ip.String() == string("::1")
            && ip.bytes.Len() == 16
            && ip.IsLoopback()
            && mapped.String() == string("1.2.3.4")
            && mapped.Equal(&net::IPv4(1, 2, 3, 4))
        {
            fmt::Println!("[ 9] ParseIP IPv6              PASS");
        } else {
            fmt::Println!("[ 9] ParseIP IPv6              FAIL");
            failed += 1;
        }
    }

    // 5. ParseIP accepts single-zero octet (e.g. "0.0.0.0").
    {
        let ip = net::ParseIP(string("0.0.0.0"));
        if !ip.IsNil() && ip.String() == string("0.0.0.0") {
            fmt::Println!("[ 5] ParseIP 0.0.0.0           PASS");
        } else {
            fmt::Println!("[ 5] ParseIP 0.0.0.0           FAIL");
            failed += 1;
        }
    }

    // 6. To4 returns 4-byte form for IPv4.
    {
        let ip = net::IPv4(10, 0, 0, 1);
        let v4 = ip.To4();
        if !v4.IsNil() && v4.String() == string("10.0.0.1") {
            fmt::Println!("[ 6] To4 on IPv4               PASS");
        } else {
            fmt::Println!("[ 6] To4 on IPv4               FAIL");
            failed += 1;
        }
    }

    // 7. To4 on nil-IP returns nil-IP.
    {
        let nil_ip = net::IP::default();
        if nil_ip.To4().IsNil() {
            fmt::Println!("[ 7] To4 on nil-IP             PASS");
        } else {
            fmt::Println!("[ 7] To4 on nil-IP             FAIL");
            failed += 1;
        }
    }

    // 8. nil-IP.String() == "<nil>".
    {
        let nil_ip = net::IP::default();
        if nil_ip.String() == string("<nil>") {
            fmt::Println!("[ 8] nil IP String             PASS");
        } else {
            fmt::Println!("[ 8] nil IP String             FAIL");
            failed += 1;
        }
    }

    if failed == 0 {
        fmt::Println!("ok 9/9");
        syscall::Exit(0);
    } else {
        fmt::Println!("FAIL", failed, "of 9");
        syscall::Exit(1);
    }
}
