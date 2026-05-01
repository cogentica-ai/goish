// net_ip_global_unicast_smoke — exercise net.IP.{IsGlobalUnicast,
// IsInterfaceLocalMulticast}. (ip.go:162 + 192)

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

    // 1. IsGlobalUnicast — ordinary public IPv4 (8.8.8.8) is unicast.
    {
        if net::IPv4(8, 8, 8, 8).IsGlobalUnicast() {
            Println!("[ 1] IsGlobalUnicast public    PASS");
        } else {
            Println!("[ 1] IsGlobalUnicast public    FAIL");
            failed += 1;
        }
    }

    // 2. IsGlobalUnicast — RFC 1918 private addresses still count.
    {
        if net::IPv4(10, 0, 0, 1).IsGlobalUnicast()
            && net::IPv4(192, 168, 0, 1).IsGlobalUnicast()
            && net::IPv4(172, 20, 0, 1).IsGlobalUnicast()
        {
            Println!("[ 2] IsGlobalUnicast private   PASS");
        } else {
            Println!("[ 2] IsGlobalUnicast private   FAIL");
            failed += 1;
        }
    }

    // 3. IsGlobalUnicast — broadcast 255.255.255.255 is excluded.
    {
        if !net::IPv4(255, 255, 255, 255).IsGlobalUnicast() {
            Println!("[ 3] IsGlobalUnicast bcast     PASS");
        } else {
            Println!("[ 3] IsGlobalUnicast bcast     FAIL");
            failed += 1;
        }
    }

    // 4. IsGlobalUnicast — unspecified 0.0.0.0 is excluded.
    {
        if !net::IPv4(0, 0, 0, 0).IsGlobalUnicast() {
            Println!("[ 4] IsGlobalUnicast unspec    PASS");
        } else {
            Println!("[ 4] IsGlobalUnicast unspec    FAIL");
            failed += 1;
        }
    }

    // 5. IsGlobalUnicast — loopback 127.x.x.x is excluded.
    {
        if !net::IPv4(127, 0, 0, 1).IsGlobalUnicast()
            && !net::IPv4(127, 255, 255, 255).IsGlobalUnicast()
        {
            Println!("[ 5] IsGlobalUnicast loopback  PASS");
        } else {
            Println!("[ 5] IsGlobalUnicast loopback  FAIL");
            failed += 1;
        }
    }

    // 6. IsGlobalUnicast — multicast 224.0.0.0/4 is excluded.
    {
        if !net::IPv4(224, 0, 0, 1).IsGlobalUnicast()
            && !net::IPv4(239, 255, 255, 255).IsGlobalUnicast()
        {
            Println!("[ 6] IsGlobalUnicast multicast PASS");
        } else {
            Println!("[ 6] IsGlobalUnicast multicast FAIL");
            failed += 1;
        }
    }

    // 7. IsGlobalUnicast — link-local unicast 169.254.0.0/16 is excluded.
    {
        if !net::IPv4(169, 254, 0, 1).IsGlobalUnicast() {
            Println!("[ 7] IsGlobalUnicast link-loc  PASS");
        } else {
            Println!("[ 7] IsGlobalUnicast link-loc  FAIL");
            failed += 1;
        }
    }

    // 8. IsGlobalUnicast — nil IP is excluded.
    {
        if !net::IP::default().IsGlobalUnicast() {
            Println!("[ 8] IsGlobalUnicast nil       PASS");
        } else {
            Println!("[ 8] IsGlobalUnicast nil       FAIL");
            failed += 1;
        }
    }

    // 9. IsInterfaceLocalMulticast — IPv4 always false (slim, no IPv6).
    {
        if !net::IPv4(1, 2, 3, 4).IsInterfaceLocalMulticast()
            && !net::IPv4(224, 0, 0, 1).IsInterfaceLocalMulticast()
            && !net::IPv4(255, 255, 255, 255).IsInterfaceLocalMulticast()
            && !net::IP::default().IsInterfaceLocalMulticast()
        {
            Println!("[ 9] IsInterfaceLocalMulticast PASS");
        } else {
            Println!("[ 9] IsInterfaceLocalMulticast FAIL");
            failed += 1;
        }
    }

    if failed == 0 {
        Println!("ok 9/9");
        syscall::Exit(0);
    } else {
        Println!("FAIL", failed, "of 9");
        syscall::Exit(1);
    }
}
