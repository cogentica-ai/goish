// net_ipnet_smoke — exercise net.IPNet + ParseCIDR + Contains/String.
// (ip.go:46, 480, 506, 550)

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

    // 1. ParseCIDR — happy path "192.0.2.1/24".
    {
        let (ip, network, err) = net::ParseCIDR(string("192.0.2.1/24"));
        if err.IsNil()
            && ip.String() == string("192.0.2.1")
            && network.IP.String() == string("192.0.2.0")
        {
            fmt::Println!("[ 1] ParseCIDR happy           PASS");
        } else {
            fmt::Println!("[ 1] ParseCIDR happy           FAIL");
            failed += 1;
        }
    }

    // 2. ParseCIDR — /0 catches everything.
    {
        let (_, network, err) = net::ParseCIDR(string("0.0.0.0/0"));
        if err.IsNil() && network.IP.String() == string("0.0.0.0") {
            fmt::Println!("[ 2] ParseCIDR /0              PASS");
        } else {
            fmt::Println!("[ 2] ParseCIDR /0              FAIL");
            failed += 1;
        }
    }

    // 3. ParseCIDR — /32 host route.
    {
        let (_, network, err) = net::ParseCIDR(string("10.1.2.3/32"));
        if err.IsNil() && network.IP.String() == string("10.1.2.3") {
            fmt::Println!("[ 3] ParseCIDR /32             PASS");
        } else {
            fmt::Println!("[ 3] ParseCIDR /32             FAIL");
            failed += 1;
        }
    }

    // 4. ParseCIDR — missing slash.
    {
        let (_, _, err) = net::ParseCIDR(string("192.0.2.1"));
        if !err.IsNil() {
            fmt::Println!("[ 4] ParseCIDR no-slash        PASS");
        } else {
            fmt::Println!("[ 4] ParseCIDR no-slash        FAIL");
            failed += 1;
        }
    }

    // 5. ParseCIDR — bad IP.
    {
        let (_, _, err) = net::ParseCIDR(string("999.0.0.1/24"));
        if !err.IsNil() {
            fmt::Println!("[ 5] ParseCIDR bad IP          PASS");
        } else {
            fmt::Println!("[ 5] ParseCIDR bad IP          FAIL");
            failed += 1;
        }
    }

    // 6. ParseCIDR — bad prefix-length (>32).
    {
        let (_, _, err) = net::ParseCIDR(string("10.0.0.0/33"));
        if !err.IsNil() {
            fmt::Println!("[ 6] ParseCIDR bad prefix      PASS");
        } else {
            fmt::Println!("[ 6] ParseCIDR bad prefix      FAIL");
            failed += 1;
        }
    }

    // 7. ParseCIDR — non-numeric prefix.
    {
        let (_, _, err) = net::ParseCIDR(string("10.0.0.0/x"));
        if !err.IsNil() {
            fmt::Println!("[ 7] ParseCIDR non-num         PASS");
        } else {
            fmt::Println!("[ 7] ParseCIDR non-num         FAIL");
            failed += 1;
        }
    }

    // 8. IPNet.Contains — within range.
    {
        let (_, network, _) = net::ParseCIDR(string("192.168.1.0/24"));
        if network.Contains(&net::IPv4(192, 168, 1, 42))
            && network.Contains(&net::IPv4(192, 168, 1, 0))
            && network.Contains(&net::IPv4(192, 168, 1, 255))
        {
            fmt::Println!("[ 8] Contains within           PASS");
        } else {
            fmt::Println!("[ 8] Contains within           FAIL");
            failed += 1;
        }
    }

    // 9. IPNet.Contains — outside range.
    {
        let (_, network, _) = net::ParseCIDR(string("192.168.1.0/24"));
        if !network.Contains(&net::IPv4(192, 168, 2, 1))
            && !network.Contains(&net::IPv4(10, 0, 0, 1))
        {
            fmt::Println!("[ 9] Contains outside          PASS");
        } else {
            fmt::Println!("[ 9] Contains outside          FAIL");
            failed += 1;
        }
    }

    // 10. IPNet.Contains — /0 contains everything.
    {
        let (_, network, _) = net::ParseCIDR(string("0.0.0.0/0"));
        if network.Contains(&net::IPv4(8, 8, 8, 8))
            && network.Contains(&net::IPv4(255, 255, 255, 255))
            && network.Contains(&net::IPv4(0, 0, 0, 0))
        {
            fmt::Println!("[10] Contains /0               PASS");
        } else {
            fmt::Println!("[10] Contains /0               FAIL");
            failed += 1;
        }
    }

    // 11. IPNet.Contains — /32 host-only.
    {
        let (_, network, _) = net::ParseCIDR(string("10.0.0.5/32"));
        if network.Contains(&net::IPv4(10, 0, 0, 5)) && !network.Contains(&net::IPv4(10, 0, 0, 6)) {
            fmt::Println!("[11] Contains /32              PASS");
        } else {
            fmt::Println!("[11] Contains /32              FAIL");
            failed += 1;
        }
    }

    // 12. IPNet.String — canonical CIDR form.
    {
        let (_, network, _) = net::ParseCIDR(string("192.168.1.0/24"));
        let s = network.String();
        if s == string("192.168.1.0/24") {
            fmt::Println!("[12] IPNet.String              PASS");
        } else {
            fmt::Println!("[12] IPNet.String              FAIL");
            failed += 1;
        }
    }

    // 13. IPNet.String — non-canonical mask falls back to hex form.
    {
        let network = net::IPNet {
            IP: net::IPv4(192, 168, 1, 0),
            Mask: net::IPv4Mask(0xff, 0, 0xff, 0),
        };
        // Mask is not canonical (1s-then-0s), so IPNet.String falls
        // back to "<ip>/<hex-mask>" without re-masking the IP — the
        // IP is taken as-is from the IPNet field.
        let s = network.String();
        if s == string("192.168.1.0/ff00ff00") {
            fmt::Println!("[13] IPNet.String non-canon    PASS");
        } else {
            fmt::Println!("[13] IPNet.String non-canon    FAIL: got ", s);
            failed += 1;
        }
    }

    // 14. IPNet.Network — constant "ip+net".
    {
        let (_, network, _) = net::ParseCIDR(string("10.0.0.0/8"));
        if network.Network() == string("ip+net") {
            fmt::Println!("[14] IPNet.Network             PASS");
        } else {
            fmt::Println!("[14] IPNet.Network             FAIL");
            failed += 1;
        }
    }

    let total: int = 14;
    if failed == 0 {
        fmt::Println!("ok 14/14");
        syscall::Exit(0);
    } else {
        fmt::Println!("FAIL", failed, "of", total);
        syscall::Exit(1);
    }
}
