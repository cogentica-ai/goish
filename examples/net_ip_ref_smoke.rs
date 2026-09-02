// net_ip_ref_smoke — net/ip.go against a running Go.
// (net/ip.go)
//
// Every expectation below is what a real Go 1.25.5 prints: the lines in
// GO are the verbatim output of `tools/gen_netip4_ref.go` run in
// `package net_test` by `scripts/goref.sh`.
//
// `net.IP` is a []byte that means two different things at 4 and 16
// bytes, and almost every method has to reconcile the two. ParseIP
// always returns 16; an IP SAN in a certificate is 4; Equal must call
// those the same address; Mask has to trim whichever side is wider.
// Before this file, goish's net.IP held only the 4-byte form: it
// returned nil for EVERY IPv6 address, so `ParseIP("::1")` was
// indistinguishable from `ParseIP("garbage")`, and any 16-byte IP
// printed as "<nil>".
//
// The rules worth pinning, because a plausible port gets them wrong:
//
//   * String has four forms, not two: "<nil>" at length 0, dotted
//     decimal for IPv4 AND v4-mapped IPv6, RFC 5952 for IPv6, and
//     "?" + hex for any other length. That last one keeps a malformed
//     address printable instead of panicking.
//   * "::" compresses the LONGEST zero run, ties go to the FIRST, and
//     a run of one is never compressed — so "1:0:0:2:0:0:0:3" is
//     "1:0:0:2::3" while "1:0:0:2:0:0:3:0" is "1::2:0:0:3:0".
//   * Equal is not byte equality. A 4-byte 1.2.3.4 equals a 16-byte
//     ::ffff:1.2.3.4. x509 hostname verification depends on exactly
//     that: the host comes from ParseIP (16 bytes), the SAN from DER
//     (4 bytes).
//   * ParseIP rejects a zone ("fe80::1%eth0") even though netip accepts
//     one, and rejects a leading zero ("01.2.3.4") because a leading
//     zero has meant OCTAL in enough parsers that accepting it is a
//     security question.
//   * ParseCIDR returns the address WITH its host bits and the network
//     WITHOUT them: "192.0.2.1/24" gives 192.0.2.1 and 192.0.2.0/24.
//   * A non-canonical mask (ones NOT followed only by zeros) makes
//     Size report (0,0) and IPNet.String fall back to hex.
//
// Go's own ip.go delegates parsing to netip.ParseAddr and formatting to
// netip.Addr.AppendTo; this port does the same against goish's
// net::netip, so the two packages cannot drift apart.

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

// go: none — goish idiom: the reference lines, in the order Go printed
//     them. Comparing whole rendered lines keeps this smoke and the
//     generator in lockstep: a case added to one is a mismatch in the
//     other, never a silent pass.
const GO: [&str; 151] = [
    "parse \"1.2.3.4\"          -> \"1.2.3.4\" len=16 to4=\"1.2.3.4\" to16=\"1.2.3.4\"",
    "  pred \"1.2.3.4\"          unspec=false loop=false priv=false mcast=false ilm=false llm=false llu=false gu=true",
    "  dmask \"1.2.3.4\"          -> \"ff000000\"",
    "parse \"0.0.0.0\"          -> \"0.0.0.0\" len=16 to4=\"0.0.0.0\" to16=\"0.0.0.0\"",
    "  pred \"0.0.0.0\"          unspec=true  loop=false priv=false mcast=false ilm=false llm=false llu=false gu=false",
    "  dmask \"0.0.0.0\"          -> \"ff000000\"",
    "parse \"255.255.255.255\"  -> \"255.255.255.255\" len=16 to4=\"255.255.255.255\" to16=\"255.255.255.255\"",
    "  pred \"255.255.255.255\"  unspec=false loop=false priv=false mcast=false ilm=false llm=false llu=false gu=false",
    "  dmask \"255.255.255.255\"  -> \"ffffff00\"",
    "parse \"127.0.0.1\"        -> \"127.0.0.1\" len=16 to4=\"127.0.0.1\" to16=\"127.0.0.1\"",
    "  pred \"127.0.0.1\"        unspec=false loop=true  priv=false mcast=false ilm=false llm=false llu=false gu=false",
    "  dmask \"127.0.0.1\"        -> \"ff000000\"",
    "parse \"10.1.2.3\"         -> \"10.1.2.3\" len=16 to4=\"10.1.2.3\" to16=\"10.1.2.3\"",
    "  pred \"10.1.2.3\"         unspec=false loop=false priv=true  mcast=false ilm=false llm=false llu=false gu=true",
    "  dmask \"10.1.2.3\"         -> \"ff000000\"",
    "parse \"172.16.0.1\"       -> \"172.16.0.1\" len=16 to4=\"172.16.0.1\" to16=\"172.16.0.1\"",
    "  pred \"172.16.0.1\"       unspec=false loop=false priv=true  mcast=false ilm=false llm=false llu=false gu=true",
    "  dmask \"172.16.0.1\"       -> \"ffff0000\"",
    "parse \"172.32.0.1\"       -> \"172.32.0.1\" len=16 to4=\"172.32.0.1\" to16=\"172.32.0.1\"",
    "  pred \"172.32.0.1\"       unspec=false loop=false priv=false mcast=false ilm=false llm=false llu=false gu=true",
    "  dmask \"172.32.0.1\"       -> \"ffff0000\"",
    "parse \"192.168.1.1\"      -> \"192.168.1.1\" len=16 to4=\"192.168.1.1\" to16=\"192.168.1.1\"",
    "  pred \"192.168.1.1\"      unspec=false loop=false priv=true  mcast=false ilm=false llm=false llu=false gu=true",
    "  dmask \"192.168.1.1\"      -> \"ffffff00\"",
    "parse \"169.254.1.1\"      -> \"169.254.1.1\" len=16 to4=\"169.254.1.1\" to16=\"169.254.1.1\"",
    "  pred \"169.254.1.1\"      unspec=false loop=false priv=false mcast=false ilm=false llm=false llu=true  gu=false",
    "  dmask \"169.254.1.1\"      -> \"ffff0000\"",
    "parse \"224.0.0.1\"        -> \"224.0.0.1\" len=16 to4=\"224.0.0.1\" to16=\"224.0.0.1\"",
    "  pred \"224.0.0.1\"        unspec=false loop=false priv=false mcast=true  ilm=false llm=true  llu=false gu=false",
    "  dmask \"224.0.0.1\"        -> \"ffffff00\"",
    "parse \"224.0.1.1\"        -> \"224.0.1.1\" len=16 to4=\"224.0.1.1\" to16=\"224.0.1.1\"",
    "  pred \"224.0.1.1\"        unspec=false loop=false priv=false mcast=true  ilm=false llm=false llu=false gu=false",
    "  dmask \"224.0.1.1\"        -> \"ffffff00\"",
    "parse \"239.1.2.3\"        -> \"239.1.2.3\" len=16 to4=\"239.1.2.3\" to16=\"239.1.2.3\"",
    "  pred \"239.1.2.3\"        unspec=false loop=false priv=false mcast=true  ilm=false llm=false llu=false gu=false",
    "  dmask \"239.1.2.3\"        -> \"ffffff00\"",
    "parse \"::\"               -> \"::\" len=16 to4=\"<nil>\" to16=\"::\"",
    "  pred \"::\"               unspec=true  loop=false priv=false mcast=false ilm=false llm=false llu=false gu=false",
    "  dmask \"::\"               -> \"<nil>\"",
    "parse \"::1\"              -> \"::1\" len=16 to4=\"<nil>\" to16=\"::1\"",
    "  pred \"::1\"              unspec=false loop=true  priv=false mcast=false ilm=false llm=false llu=false gu=false",
    "  dmask \"::1\"              -> \"<nil>\"",
    "parse \"fe80::1\"          -> \"fe80::1\" len=16 to4=\"<nil>\" to16=\"fe80::1\"",
    "  pred \"fe80::1\"          unspec=false loop=false priv=false mcast=false ilm=false llm=false llu=true  gu=false",
    "  dmask \"fe80::1\"          -> \"<nil>\"",
    "parse \"ff01::1\"          -> \"ff01::1\" len=16 to4=\"<nil>\" to16=\"ff01::1\"",
    "  pred \"ff01::1\"          unspec=false loop=false priv=false mcast=true  ilm=true  llm=false llu=false gu=false",
    "  dmask \"ff01::1\"          -> \"<nil>\"",
    "parse \"ff02::1\"          -> \"ff02::1\" len=16 to4=\"<nil>\" to16=\"ff02::1\"",
    "  pred \"ff02::1\"          unspec=false loop=false priv=false mcast=true  ilm=false llm=true  llu=false gu=false",
    "  dmask \"ff02::1\"          -> \"<nil>\"",
    "parse \"ff05::2\"          -> \"ff05::2\" len=16 to4=\"<nil>\" to16=\"ff05::2\"",
    "  pred \"ff05::2\"          unspec=false loop=false priv=false mcast=true  ilm=false llm=false llu=false gu=false",
    "  dmask \"ff05::2\"          -> \"<nil>\"",
    "parse \"fc00::1\"          -> \"fc00::1\" len=16 to4=\"<nil>\" to16=\"fc00::1\"",
    "  pred \"fc00::1\"          unspec=false loop=false priv=true  mcast=false ilm=false llm=false llu=false gu=true",
    "  dmask \"fc00::1\"          -> \"<nil>\"",
    "parse \"fd12::34\"         -> \"fd12::34\" len=16 to4=\"<nil>\" to16=\"fd12::34\"",
    "  pred \"fd12::34\"         unspec=false loop=false priv=true  mcast=false ilm=false llm=false llu=false gu=true",
    "  dmask \"fd12::34\"         -> \"<nil>\"",
    "parse \"2001:db8::1\"      -> \"2001:db8::1\" len=16 to4=\"<nil>\" to16=\"2001:db8::1\"",
    "  pred \"2001:db8::1\"      unspec=false loop=false priv=false mcast=false ilm=false llm=false llu=false gu=true",
    "  dmask \"2001:db8::1\"      -> \"<nil>\"",
    "parse \"::ffff:1.2.3.4\"   -> \"1.2.3.4\" len=16 to4=\"1.2.3.4\" to16=\"1.2.3.4\"",
    "  pred \"::ffff:1.2.3.4\"   unspec=false loop=false priv=false mcast=false ilm=false llm=false llu=false gu=true",
    "  dmask \"::ffff:1.2.3.4\"   -> \"ff000000\"",
    "parse \"1:0:0:2:0:0:0:3\"  -> \"1:0:0:2::3\" len=16 to4=\"<nil>\" to16=\"1:0:0:2::3\"",
    "  pred \"1:0:0:2:0:0:0:3\"  unspec=false loop=false priv=false mcast=false ilm=false llm=false llu=false gu=true",
    "  dmask \"1:0:0:2:0:0:0:3\"  -> \"<nil>\"",
    "parse \"1:0:0:2:0:0:3:0\"  -> \"1::2:0:0:3:0\" len=16 to4=\"<nil>\" to16=\"1::2:0:0:3:0\"",
    "  pred \"1:0:0:2:0:0:3:0\"  unspec=false loop=false priv=false mcast=false ilm=false llm=false llu=false gu=true",
    "  dmask \"1:0:0:2:0:0:3:0\"  -> \"<nil>\"",
    "parse \"0:0:1:0:0:2:0:0\"  -> \"::1:0:0:2:0:0\" len=16 to4=\"<nil>\" to16=\"::1:0:0:2:0:0\"",
    "  pred \"0:0:1:0:0:2:0:0\"  unspec=false loop=false priv=false mcast=false ilm=false llm=false llu=false gu=true",
    "  dmask \"0:0:1:0:0:2:0:0\"  -> \"<nil>\"",
    "parse \"64:ff9b::1.2.3.4\" -> \"64:ff9b::102:304\" len=16 to4=\"<nil>\" to16=\"64:ff9b::102:304\"",
    "  pred \"64:ff9b::1.2.3.4\" unspec=false loop=false priv=false mcast=false ilm=false llm=false llu=false gu=true",
    "  dmask \"64:ff9b::1.2.3.4\" -> \"<nil>\"",
    "parse \"01.2.3.4\"         -> nil",
    "parse \"1.2.3\"            -> nil",
    "parse \"256.1.1.1\"        -> nil",
    "parse \"\"                 -> nil",
    "parse \"garbage\"          -> nil",
    "parse \"fe80::1%eth0\"     -> nil",
    "parse \"::ffff:0:0\"       -> \"0.0.0.0\" len=16 to4=\"0.0.0.0\" to16=\"0.0.0.0\"",
    "  pred \"::ffff:0:0\"       unspec=true  loop=false priv=false mcast=false ilm=false llm=false llu=false gu=false",
    "  dmask \"::ffff:0:0\"       -> \"ff000000\"",
    "parse \"2001:db8::\"       -> \"2001:db8::\" len=16 to4=\"<nil>\" to16=\"2001:db8::\"",
    "  pred \"2001:db8::\"       unspec=false loop=false priv=false mcast=false ilm=false llm=false llu=false gu=true",
    "  dmask \"2001:db8::\"       -> \"<nil>\"",
    "raw   len=0   -> \"<nil>\" marshal=\"\" err=<nil>",
    "raw   len=3   -> \"?010203\" marshal=\"\" err=address 010203: invalid IP address",
    "raw   len=5   -> \"?0102030405\" marshal=\"\" err=address 0102030405: invalid IP address",
    "raw   len=4   -> \"1.2.3.4\" marshal=\"1.2.3.4\" err=<nil>",
    "raw   len=16  -> \"1.2.3.4\" marshal=\"1.2.3.4\" err=<nil>",
    "equal \"1.2.3.4\"            \"1.2.3.4\"            -> true",
    "equal \"1.2.3.4\"            \"1.2.3.4\"            -> true",
    "equal \"1.2.3.4\"            \"1.2.3.5\"            -> false",
    "equal \"::1\"                \"0.0.0.0\"            -> false",
    "equal \"::1\"                \"::1\"                -> true",
    "equal \"<nil>\"              \"<nil>\"              -> true",
    "equal \"<nil>\"              \"1.2.3.4\"            -> false",
    "cidrmask(  0, 32) -> \"00000000\"                         size=(0,32)",
    "cidrmask(  1, 32) -> \"80000000\"                         size=(1,32)",
    "cidrmask( 24, 32) -> \"ffffff00\"                         size=(24,32)",
    "cidrmask( 32, 32) -> \"ffffffff\"                         size=(32,32)",
    "cidrmask( 33, 32) -> \"<nil>\"                            size=(0,0)",
    "cidrmask( -1, 32) -> \"<nil>\"                            size=(0,0)",
    "cidrmask(  0,128) -> \"00000000000000000000000000000000\" size=(0,128)",
    "cidrmask( 64,128) -> \"ffffffffffffffff0000000000000000\" size=(64,128)",
    "cidrmask(128,128) -> \"ffffffffffffffffffffffffffffffff\" size=(128,128)",
    "cidrmask(129,128) -> \"<nil>\"                            size=(0,0)",
    "cidrmask( 24, 33) -> \"<nil>\"                            size=(0,0)",
    "noncanon size=(0,0) str=\"c000ff00\" net=\"198.51.100.0/c000ff00\"",
    "mask  192.168.1.130  /25  bits=32  -> \"192.168.1.128\"",
    "mask  192.168.1.130  /24  bits=32  -> \"192.168.1.0\"",
    "mask  192.168.1.130  /121 bits=128 -> \"192.168.1.128\"",
    "mask  2001:db8::1    /32  bits=128 -> \"2001:db8::\"",
    "mask  2001:db8::1    /32  bits=32  -> \"<nil>\"",
    "cidr  \"192.0.2.1/24\"     -> ip=\"192.0.2.1\" net=\"192.0.2.0/24\" netip=\"192.0.2.0\" mask=\"ffffff00\"",
    "cidr  \"192.0.2.0/24\"     -> ip=\"192.0.2.0\" net=\"192.0.2.0/24\" netip=\"192.0.2.0\" mask=\"ffffff00\"",
    "cidr  \"192.0.2.1/32\"     -> ip=\"192.0.2.1\" net=\"192.0.2.1/32\" netip=\"192.0.2.1\" mask=\"ffffffff\"",
    "cidr  \"2001:db8::1/32\"   -> ip=\"2001:db8::1\" net=\"2001:db8::/32\" netip=\"2001:db8::\" mask=\"ffffffff000000000000000000000000\"",
    "cidr  \"2001:db8::/48\"    -> ip=\"2001:db8::\" net=\"2001:db8::/48\" netip=\"2001:db8::\" mask=\"ffffffffffff00000000000000000000\"",
    "cidr  \"10.0.0.0/8\"       -> ip=\"10.0.0.0\" net=\"10.0.0.0/8\" netip=\"10.0.0.0\" mask=\"ff000000\"",
    "cidr  \"0.0.0.0/0\"        -> ip=\"0.0.0.0\" net=\"0.0.0.0/0\" netip=\"0.0.0.0\" mask=\"00000000\"",
    "cidr  \"::/0\"             -> ip=\"::\" net=\"::/0\" netip=\"::\" mask=\"00000000000000000000000000000000\"",
    "cidr  \"192.0.2.1/33\"     -> err=\"invalid CIDR address: 192.0.2.1/33\"",
    "cidr  \"2001:db8::1/129\"  -> err=\"invalid CIDR address: 2001:db8::1/129\"",
    "cidr  \"192.0.2.1\"        -> err=\"invalid CIDR address: 192.0.2.1\"",
    "cidr  \"192.0.2.1/\"       -> err=\"invalid CIDR address: 192.0.2.1/\"",
    "cidr  \"/24\"              -> err=\"invalid CIDR address: /24\"",
    "cidr  \"192.0.2.1/-1\"     -> err=\"invalid CIDR address: 192.0.2.1/-1\"",
    "cidr  \"192.0.2.1/2x\"     -> err=\"invalid CIDR address: 192.0.2.1/2x\"",
    "cidr  \"fe80::1%eth0/64\"  -> err=\"invalid CIDR address: fe80::1%eth0/64\"",
    "cidr  \"192.0.2.1/024\"    -> ip=\"192.0.2.1\" net=\"192.0.2.0/24\" netip=\"192.0.2.0\" mask=\"ffffff00\"",
    "contains \"192.168.1.1\"        v4net=true  v6net=false",
    "contains \"192.168.2.1\"        v4net=false v6net=false",
    "contains \"::ffff:192.168.1.1\" v4net=true  v6net=false",
    "contains \"2001:db8::1\"        v4net=false v6net=true",
    "contains \"2001:db9::1\"        v4net=false v6net=false",
    "contains \"::1\"                v4net=false v6net=false",
    "contains 4-byte \"192.168.1.1\" v4net=true v6net=false",
    "network name=\"ip+net\"",
    "unmarshal \"1.2.3.4\"  -> \"1.2.3.4\" len=16",
    "unmarshal \"::1\"      -> \"::1\" len=16",
    "unmarshal \"\"         -> \"<nil>\" len=0",
    "unmarshal \"nope\"     -> err=\"invalid IP address: nope\"",
    "ipv4ctor \"192.0.2.1\" len=16 mask=\"ffffff00\"",
    "wellknown bcast=\"255.255.255.255\" allsys=\"224.0.0.1\" allrouter=\"224.0.0.2\" zero=\"0.0.0.0\"",
    "wellknown6 zero=\"::\" unspec=\"::\" loop=\"::1\" ilan=\"ff01::1\" llan=\"ff02::1\" llar=\"ff02::2\"",
];

// go: none — goish idiom: one comparison, printing the divergence when
//     it is one, so a FAIL says what it got and not just that it did.
fn chk(failed: &mut int, n: &mut int, got: string) {
    if *n >= GO.len() as int {
        fmt::Printf!("[!!] extra line %d: %q\n", *n + 1, got);
        *failed += 1;
        *n += 1;
        return;
    }
    let want = s(GO[*n as usize]);
    *n += 1;
    if got == want {
        return;
    }
    fmt::Printf!("[!!] line %d FAIL\n  got  %q\n  want %q\n", *n, got, want);
    *failed += 1;
}

// go: none — goish idiom: Go writes `net.IP{1, 2, 3, 4}` for a literal
//     of the named slice type; goish spells the same thing this way.
fn ipof(b: &[u8]) -> net::IP {
    return net::IP {
        bytes: slice::__from_vec(b.to_vec()),
    };
}

#[goish::main]
fn main() {
    let mut failed: int = 0;
    let mut n: int = 0;

    // 1. ParseIP over both families, then every classification
    //    predicate and the classful default mask for each.
    for v in [
        "1.2.3.4",
        "0.0.0.0",
        "255.255.255.255",
        "127.0.0.1",
        "10.1.2.3",
        "172.16.0.1",
        "172.32.0.1",
        "192.168.1.1",
        "169.254.1.1",
        "224.0.0.1",
        "224.0.1.1",
        "239.1.2.3",
        "::",
        "::1",
        "fe80::1",
        "ff01::1",
        "ff02::1",
        "ff05::2",
        "fc00::1",
        "fd12::34",
        "2001:db8::1",
        "::ffff:1.2.3.4",
        "1:0:0:2:0:0:0:3",
        "1:0:0:2:0:0:3:0",
        "0:0:1:0:0:2:0:0",
        "64:ff9b::1.2.3.4",
        "01.2.3.4",
        "1.2.3",
        "256.1.1.1",
        "",
        "garbage",
        "fe80::1%eth0",
        "::ffff:0:0",
        "2001:db8::",
    ] {
        let ip = net::ParseIP(s(v));
        if ip.IsNil() {
            chk(
                &mut failed,
                &mut n,
                fmt::Sprintf!("parse %-18q -> nil", s(v)),
            );
            continue;
        }
        chk(
            &mut failed,
            &mut n,
            fmt::Sprintf!(
                "parse %-18q -> %q len=%d to4=%q to16=%q",
                s(v),
                ip.String(),
                ip.bytes.Len(),
                ip.To4().String(),
                ip.To16().String()
            ),
        );
        chk(&mut failed, &mut n, fmt::Sprintf!("  pred %-18q unspec=%-5v loop=%-5v priv=%-5v mcast=%-5v ilm=%-5v llm=%-5v llu=%-5v gu=%v",
            s(v), ip.IsUnspecified(), ip.IsLoopback(), ip.IsPrivate(), ip.IsMulticast(),
            ip.IsInterfaceLocalMulticast(), ip.IsLinkLocalMulticast(),
            ip.IsLinkLocalUnicast(), ip.IsGlobalUnicast()));
        chk(
            &mut failed,
            &mut n,
            fmt::Sprintf!("  dmask %-18q -> %q", s(v), ip.DefaultMask().String()),
        );
    }

    // 2. String and MarshalText on the lengths that are not addresses:
    //    the "?"+hex fallback, and the AddrError it marshals to.
    for b in [
        &[][..],
        &[1u8, 2, 3][..],
        &[1, 2, 3, 4, 5][..],
        &[1, 2, 3, 4][..],
        &[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 1, 2, 3, 4][..],
    ] {
        let ip = ipof(b);
        let (txt, err) = ip.MarshalText();
        chk(
            &mut failed,
            &mut n,
            fmt::Sprintf!(
                "raw   len=%-3d -> %q marshal=%q err=%v",
                b.len() as int,
                ip.String(),
                string::from_bytes(&txt),
                err
            ),
        );
    }

    // 3. Equal reconciles the 4-byte and 16-byte forms of one address.
    let pairs: [(net::IP, net::IP); 7] = [
        (ipof(&[1, 2, 3, 4]), net::ParseIP(s("1.2.3.4"))),
        (net::ParseIP(s("1.2.3.4")), ipof(&[1, 2, 3, 4])),
        (ipof(&[1, 2, 3, 4]), ipof(&[1, 2, 3, 5])),
        (net::ParseIP(s("::1")), ipof(&[0, 0, 0, 0])),
        (net::ParseIP(s("::1")), net::ParseIP(s("::1"))),
        (net::IP::default(), net::IP::default()),
        (net::IP::default(), net::ParseIP(s("1.2.3.4"))),
    ];
    for (a, b) in pairs.iter() {
        chk(
            &mut failed,
            &mut n,
            fmt::Sprintf!(
                "equal %-20q %-20q -> %v",
                a.String(),
                b.String(),
                a.Equal(b)
            ),
        );
    }

    // 4. CIDRMask over both families, including every out-of-range form
    //    that must give the nil mask.
    for (o, bits) in [
        (0, 32),
        (1, 32),
        (24, 32),
        (32, 32),
        (33, 32),
        (-1, 32),
        (0, 128),
        (64, 128),
        (128, 128),
        (129, 128),
        (24, 33),
    ] {
        let m = net::CIDRMask(o, bits);
        let (ones, mb) = m.Size();
        chk(
            &mut failed,
            &mut n,
            fmt::Sprintf!(
                "cidrmask(%3d,%3d) -> %-34q size=(%d,%d)",
                o as int,
                bits as int,
                m.String(),
                ones,
                mb
            ),
        );
    }

    // 5. A non-canonical mask: Size gives (0,0) and IPNet.String falls
    //    back to the hexadecimal form.
    let nc = net::IPMask {
        bytes: slice::__from_vec(alloc::vec![0xc0u8, 0x00, 0xff, 0x00]),
    };
    let (ones, bits) = nc.Size();
    let nn = net::IPNet {
        IP: net::ParseIP(s("198.51.100.0")),
        Mask: nc.clone(),
    };
    chk(
        &mut failed,
        &mut n,
        fmt::Sprintf!(
            "noncanon size=(%d,%d) str=%q net=%q",
            ones,
            bits,
            nc.String(),
            nn.String()
        ),
    );

    // 6. Mask trims whichever side is wider — a /121 applied to a
    //    16-byte v4-mapped address still yields a 4-byte result.
    for (v, o, bits) in [
        ("192.168.1.130", 25, 32),
        ("192.168.1.130", 24, 32),
        ("192.168.1.130", 121, 128),
        ("2001:db8::1", 32, 128),
        ("2001:db8::1", 32, 32),
    ] {
        let ip = net::ParseIP(s(v));
        let m = net::CIDRMask(o, bits);
        chk(
            &mut failed,
            &mut n,
            fmt::Sprintf!(
                "mask  %-14s /%-3d bits=%-3d -> %q",
                s(v),
                o as int,
                bits as int,
                ip.Mask(&m).String()
            ),
        );
    }

    // 7. ParseCIDR: the address keeps its host bits, the network drops
    //    them — plus the exact refusal text for every malformed form.
    for v in [
        "192.0.2.1/24",
        "192.0.2.0/24",
        "192.0.2.1/32",
        "2001:db8::1/32",
        "2001:db8::/48",
        "10.0.0.0/8",
        "0.0.0.0/0",
        "::/0",
        "192.0.2.1/33",
        "2001:db8::1/129",
        "192.0.2.1",
        "192.0.2.1/",
        "/24",
        "192.0.2.1/-1",
        "192.0.2.1/2x",
        "fe80::1%eth0/64",
        "192.0.2.1/024",
    ] {
        let (ip, net_, err) = net::ParseCIDR(s(v));
        if !err.IsNil() {
            chk(
                &mut failed,
                &mut n,
                fmt::Sprintf!("cidr  %-18q -> err=%q", s(v), err.Error()),
            );
            continue;
        }
        chk(
            &mut failed,
            &mut n,
            fmt::Sprintf!(
                "cidr  %-18q -> ip=%q net=%q netip=%q mask=%q",
                s(v),
                ip.String(),
                net_.String(),
                net_.IP.String(),
                net_.Mask.String()
            ),
        );
    }

    // 8. Contains across families, and the 4-vs-16 pairing that x509
    //    name-constraint checking leans on.
    let (_, n4, _) = net::ParseCIDR(s("192.168.1.0/24"));
    let (_, n6, _) = net::ParseCIDR(s("2001:db8::/32"));
    for v in [
        "192.168.1.1",
        "192.168.2.1",
        "::ffff:192.168.1.1",
        "2001:db8::1",
        "2001:db9::1",
        "::1",
    ] {
        let ip = net::ParseIP(s(v));
        chk(
            &mut failed,
            &mut n,
            fmt::Sprintf!(
                "contains %-20q v4net=%-5v v6net=%v",
                s(v),
                n4.Contains(&ip),
                n6.Contains(&ip)
            ),
        );
    }
    let four = ipof(&[192, 168, 1, 1]);
    chk(
        &mut failed,
        &mut n,
        fmt::Sprintf!(
            "contains 4-byte %q v4net=%v v6net=%v",
            four.String(),
            n4.Contains(&four),
            n6.Contains(&four)
        ),
    );
    chk(
        &mut failed,
        &mut n,
        fmt::Sprintf!("network name=%q", n4.Network()),
    );

    // 9. UnmarshalText, including the ParseError text it returns.
    for v in ["1.2.3.4", "::1", "", "nope"] {
        let mut ip = net::IP::default();
        let err = ip.UnmarshalText(slice::__from_vec(v.as_bytes().to_vec()));
        if !err.IsNil() {
            chk(
                &mut failed,
                &mut n,
                fmt::Sprintf!("unmarshal %-10q -> err=%q", s(v), err.Error()),
            );
            continue;
        }
        chk(
            &mut failed,
            &mut n,
            fmt::Sprintf!(
                "unmarshal %-10q -> %q len=%d",
                s(v),
                ip.String(),
                ip.bytes.Len()
            ),
        );
    }

    // 10. IPv4 builds the 16-byte v4-in-v6 form; IPv4Mask stays 4 bytes;
    //     and the two well-known-address blocks.
    chk(
        &mut failed,
        &mut n,
        fmt::Sprintf!(
            "ipv4ctor %q len=%d mask=%q",
            net::IPv4(192, 0, 2, 1).String(),
            net::IPv4(192, 0, 2, 1).bytes.Len(),
            net::IPv4Mask(255, 255, 255, 0).String()
        ),
    );
    chk(
        &mut failed,
        &mut n,
        fmt::Sprintf!(
            "wellknown bcast=%q allsys=%q allrouter=%q zero=%q",
            net::IPv4bcast().String(),
            net::IPv4allsys().String(),
            net::IPv4allrouter().String(),
            net::IPv4zero().String()
        ),
    );
    chk(
        &mut failed,
        &mut n,
        fmt::Sprintf!(
            "wellknown6 zero=%q unspec=%q loop=%q ilan=%q llan=%q llar=%q",
            net::IPv6zero().String(),
            net::IPv6unspecified().String(),
            net::IPv6loopback().String(),
            net::IPv6interfacelocalallnodes().String(),
            net::IPv6linklocalallnodes().String(),
            net::IPv6linklocalallrouters().String()
        ),
    );

    if n != GO.len() as int {
        fmt::Printf!("[!!] produced %d lines, pinned %d\n", n, GO.len() as int);
        failed += 1;
    }
    if failed == 0 {
        fmt::Printf!("ok %d/%d\n", n, n);
        return;
    }
    fmt::Printf!("FAILED %d of %d\n", failed, n);
    syscall::Exit(1);
}
