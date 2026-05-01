// net_ip_predicates_smoke — exercise net.IP.{IsUnspecified, IsLoopback,
// IsPrivate, IsMulticast, IsLinkLocalMulticast, IsLinkLocalUnicast}.
// IPv4 slim. (ip.go:121-181)

#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

use goish::net;
use goish::{syscall, Println};

#[goish::main]
fn main() {
    let mut failed = 0;

    // 1. IsUnspecified — 0.0.0.0 only.
    {
        if net::IPv4(0, 0, 0, 0).IsUnspecified()
            && !net::IPv4(127, 0, 0, 1).IsUnspecified()
            && !net::IPv4(1, 2, 3, 4).IsUnspecified()
        {
            Println!("[ 1] IsUnspecified             PASS");
        } else {
            Println!("[ 1] IsUnspecified             FAIL");
            failed += 1;
        }
    }

    // 2. IsLoopback — 127.0.0.0/8.
    {
        if net::IPv4(127, 0, 0, 1).IsLoopback()
            && net::IPv4(127, 255, 255, 255).IsLoopback()
            && !net::IPv4(128, 0, 0, 1).IsLoopback()
            && !net::IPv4(192, 168, 0, 1).IsLoopback()
        {
            Println!("[ 2] IsLoopback                PASS");
        } else {
            Println!("[ 2] IsLoopback                FAIL");
            failed += 1;
        }
    }

    // 3. IsPrivate — RFC 1918 ranges.
    {
        if net::IPv4(10, 0, 0, 1).IsPrivate()
            && net::IPv4(10, 255, 255, 255).IsPrivate()
            && net::IPv4(172, 16, 0, 1).IsPrivate()
            && net::IPv4(172, 31, 255, 255).IsPrivate()
            && !net::IPv4(172, 15, 0, 1).IsPrivate() // outside 172.16/12
            && !net::IPv4(172, 32, 0, 1).IsPrivate()
            && net::IPv4(192, 168, 0, 1).IsPrivate()
            && !net::IPv4(192, 169, 0, 1).IsPrivate()
            && !net::IPv4(8, 8, 8, 8).IsPrivate()
        {
            Println!("[ 3] IsPrivate RFC 1918        PASS");
        } else {
            Println!("[ 3] IsPrivate RFC 1918        FAIL");
            failed += 1;
        }
    }

    // 4. IsMulticast — 224.0.0.0/4.
    {
        if net::IPv4(224, 0, 0, 1).IsMulticast()
            && net::IPv4(239, 255, 255, 255).IsMulticast()
            && !net::IPv4(223, 255, 255, 255).IsMulticast()
            && !net::IPv4(240, 0, 0, 1).IsMulticast()
        {
            Println!("[ 4] IsMulticast               PASS");
        } else {
            Println!("[ 4] IsMulticast               FAIL");
            failed += 1;
        }
    }

    // 5. IsLinkLocalMulticast — 224.0.0.0/24.
    {
        if net::IPv4(224, 0, 0, 1).IsLinkLocalMulticast()
            && net::IPv4(224, 0, 0, 251).IsLinkLocalMulticast()  // mDNS
            && !net::IPv4(224, 0, 1, 1).IsLinkLocalMulticast()
            && !net::IPv4(225, 0, 0, 1).IsLinkLocalMulticast()
        {
            Println!("[ 5] IsLinkLocalMulticast      PASS");
        } else {
            Println!("[ 5] IsLinkLocalMulticast      FAIL");
            failed += 1;
        }
    }

    // 6. IsLinkLocalUnicast — 169.254.0.0/16.
    {
        if net::IPv4(169, 254, 0, 1).IsLinkLocalUnicast()
            && net::IPv4(169, 254, 255, 255).IsLinkLocalUnicast()
            && !net::IPv4(169, 253, 0, 1).IsLinkLocalUnicast()
            && !net::IPv4(170, 254, 0, 1).IsLinkLocalUnicast()
        {
            Println!("[ 6] IsLinkLocalUnicast        PASS");
        } else {
            Println!("[ 6] IsLinkLocalUnicast        FAIL");
            failed += 1;
        }
    }

    // 7. nil-IP — all predicates false.
    {
        let nil_ip = net::IP::default();
        if !nil_ip.IsUnspecified() && !nil_ip.IsLoopback()
            && !nil_ip.IsPrivate() && !nil_ip.IsMulticast()
            && !nil_ip.IsLinkLocalMulticast() && !nil_ip.IsLinkLocalUnicast()
        {
            Println!("[ 7] nil-IP all-false          PASS");
        } else {
            Println!("[ 7] nil-IP all-false          FAIL");
            failed += 1;
        }
    }

    if failed == 0 {
        Println!("ok 7/7");
        syscall::Exit(0);
    } else {
        Println!("FAIL", failed, "of 7");
        syscall::Exit(1);
    }
}
