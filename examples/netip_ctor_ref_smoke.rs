// netip_ctor_ref_smoke — net/netip's CONSTRUCTORS, zones and
// prefixes, against a running Go 1.25.5.
//
// netip_ref_smoke next to this file is thorough about parsing and
// formatting. It never builds an address any other way: AddrFrom4,
// AddrFrom16, AddrFromSlice, AddrPortFrom, PrefixFrom, WithZone,
// As4/As16/AsSlice and the well-known addresses are named by no
// example in the tree. Every address a goish program constructs rather
// than parses starts at one of those.
//
// All 26 lines matched Go on the first run; nothing is fixed here.
// They are pinned because the answers are not the obvious ones:
//
//   AddrFrom16 of a v4-mapped block is Is4()=FALSE and Is6()=TRUE — it
//     stays a v6 address until Unmap(), and prints
//     "::ffff:192.168.1.1" rather than "192.168.1.1".
//   AddrFromSlice(nil) and a 3-byte slice are both ok=false, and the
//     Addr they return prints "invalid IP" rather than empty.
//   WithZone on a v4 address is a NO-OP — zones are v6-only — so the
//     zone reads back "" and not "eth0".
//   A zone changes equality AND ordering: fe80::1%eth0 != fe80::1.
//   PrefixFrom does not validate at construction. It keeps the bits it
//     was given, and 33 or -1 surfaces later as IsValid()=false with a
//     String() of "invalid Prefix".
//   Prefix.Contains across families is false, not an error: 10.0.0.0/8
//     does not contain ::1.
//
// The last two are the ones worth having pinned. A prefix that
// silently accepted 33 bits, or one that matched across families,
// is a CIDR allowlist that admits what it was written to exclude.
#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

use goish::fmt;
use goish::goslice::slice;
use goish::gostring::string;
use goish::net::netip;
use goish::types::{byte, int};

const GO: [&str; 26] = [
    "from4                192.168.1.1                    v4=true v6=false un=false valid=true bits=32",
    "from16-v4mapped      ::ffff:192.168.1.1             v4=false v6=true un=true valid=true bits=128",
    "from16-v6            2001:db8::1                    v4=false v6=true un=false valid=true bits=128",
    "zero                 invalid IP                     v4=false v6=false un=false valid=false bits=0",
    "fromslice-4          10.0.0.1 ok=true",
    "fromslice-16         :: ok=true",
    "fromslice-bad        invalid IP ok=false",
    "fromslice-nil        invalid IP ok=false",
    "as4                  [1 2 3 4] 00000000000000000000ffff01020304",
    "mapped-as4           [1 2 3 4] is4in6=true unmap=1.2.3.4",
    "addrport             1.2.3.4:8080 addr=1.2.3.4 port=8080 valid=true",
    "addrport-v6          [2001:db8::1]:443",
    "compare              lt=true eq=true gt=true",
    "compare-family       v4-vs-v6=true",
    "wellknown              0.0.0.0 :: ::1 ff02::1 ff02::2",
    "withzone               fe80::1%eth0 zone=\"eth0\" is6=true",
    "withzone-cleared       fe80::1 zone=\"\"",
    "withzone-v4            1.2.3.4 zone=\"\"",
    "withzone-cmp           eq=false cmp=true",
    "prefixfrom             10.1.2.3/8 bits=8 addr=10.1.2.3 valid=true",
    "prefix-mask            masked=10.0.0.0/8 contains-10.9=true contains-11=false",
    "prefix-badbits         invalid Prefix valid=false",
    "prefix-negbits         invalid Prefix valid=false",
    "prefix-family          false",
    "mustparseaddrport      [2001:db8::1]:443 port=443",
    "asslice                [1 2 3 4] 16",
];

fn chk(ln: &mut usize, got: &string) {
    if *ln >= GO.len() {
        fmt::Printf!("[!!] extra line %d: %q\n", *ln as int + 1, got);
        *ln += 1;
        return;
    }
    if got == GO[*ln] {
        fmt::Printf!("[ok] %s\n", got);
    } else {
        fmt::Printf!("[!!] line %d\n  got  %q\n  want %q\n", *ln as int + 1, got, GO[*ln]);
    }
    *ln += 1;
}

fn show(ln: &mut usize, tag: &str, a: netip::Addr) {

    chk(ln, &fmt::Sprintf!("%-20s %-30s v4=%v v6=%v un=%v valid=%v bits=%d",
        tag, a.String(), a.Is4(), a.Is6(), a.Is4In6(), a.IsValid(), a.BitLen() as int));
}

#[goish::main]
fn main() {
    let mut ln: usize = 0;

    show(&mut ln, "from4", netip::AddrFrom4([192, 168, 1, 1]));
    show(&mut ln, "from16-v4mapped", netip::AddrFrom16([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 192, 168, 1, 1]));
    show(&mut ln, "from16-v6", netip::AddrFrom16([0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]));
    show(&mut ln, "zero", netip::Addr::default());

    let (a4, ok4) = netip::AddrFromSlice(slice::__from_vec(alloc::vec![10u8, 0, 0, 1]));
    chk(&mut ln, &fmt::Sprintf!("%-20s %s ok=%v", "fromslice-4", a4.String(), ok4));
    let (a16, ok16) = netip::AddrFromSlice(slice::__from_vec(alloc::vec![0u8; 16]));
    chk(&mut ln, &fmt::Sprintf!("%-20s %s ok=%v", "fromslice-16", a16.String(), ok16));
    let (ab, okb) = netip::AddrFromSlice(slice::__from_vec(alloc::vec![1u8, 2, 3]));
    chk(&mut ln, &fmt::Sprintf!("%-20s %s ok=%v", "fromslice-bad", ab.String(), okb));
    let (an, okn) = netip::AddrFromSlice(slice::new());
    chk(&mut ln, &fmt::Sprintf!("%-20s %s ok=%v", "fromslice-nil", an.String(), okn));

    let v4 = netip::MustParseAddr("1.2.3.4");
    let a = v4.As4();
    let mut hexs = goish::gostring::string::from("");
    for b in v4.As16().iter() {
        hexs = hexs + fmt::Sprintf!("%02x", *b as int);
    }
    chk(&mut ln, &fmt::Sprintf!("%-20s [%d %d %d %d] %s", "as4", a[0] as int, a[1] as int, a[2] as int, a[3] as int, hexs));

    let mapped = netip::MustParseAddr("::ffff:1.2.3.4");
    let m = mapped.As4();
    chk(&mut ln, &fmt::Sprintf!("%-20s [%d %d %d %d] is4in6=%v unmap=%s", "mapped-as4",
        m[0] as int, m[1] as int, m[2] as int, m[3] as int, mapped.Is4In6(), mapped.Unmap().String()));

    let ap = netip::AddrPortFrom(netip::MustParseAddr("1.2.3.4"), 8080);
    chk(&mut ln, &fmt::Sprintf!("%-20s %s addr=%s port=%d valid=%v", "addrport",
        ap.String(), ap.Addr().String(), ap.Port() as int, ap.IsValid()));
    let ap6 = netip::AddrPortFrom(netip::MustParseAddr("2001:db8::1"), 443);
    chk(&mut ln, &fmt::Sprintf!("%-20s %s", "addrport-v6", ap6.String()));

    let x = netip::MustParseAddr("1.2.3.4");
    let y = netip::MustParseAddr("1.2.3.5");
    chk(&mut ln, &fmt::Sprintf!("%-20s lt=%v eq=%v gt=%v", "compare",
        x.Compare(&y) < 0, x.Compare(&x) == 0, y.Compare(&x) > 0));
    chk(&mut ln, &fmt::Sprintf!("%-20s v4-vs-v6=%v", "compare-family",
        x.Compare(&netip::MustParseAddr("::1")) < 0));
    let _: byte = 0;

    chk(&mut ln, &fmt::Sprintf!("%-22s %s %s %s %s %s", "wellknown",
        netip::IPv4Unspecified().String(), netip::IPv6Unspecified().String(),
        netip::IPv6Loopback().String(), netip::IPv6LinkLocalAllNodes().String(),
        netip::IPv6LinkLocalAllRouters().String()));

    let v6 = netip::MustParseAddr("fe80::1");
    let z = v6.WithZone("eth0");
    chk(&mut ln, &fmt::Sprintf!("%-22s %s zone=%q is6=%v", "withzone", z.String(), z.Zone(), z.Is6()));
    chk(&mut ln, &fmt::Sprintf!("%-22s %s zone=%q", "withzone-cleared",
        z.WithZone("").String(), z.WithZone("").Zone()));
    let v4 = netip::MustParseAddr("1.2.3.4");
    let zv4 = v4.WithZone("eth0");
    chk(&mut ln, &fmt::Sprintf!("%-22s %s zone=%q", "withzone-v4", zv4.String(), zv4.Zone()));
    chk(&mut ln, &fmt::Sprintf!("%-22s eq=%v cmp=%v", "withzone-cmp", z == v6, z.Compare(&v6) != 0));

    let p = netip::PrefixFrom(netip::MustParseAddr("10.1.2.3"), 8);
    chk(&mut ln, &fmt::Sprintf!("%-22s %s bits=%d addr=%s valid=%v", "prefixfrom",
        p.String(), p.Bits() as int, p.Addr().String(), p.IsValid()));
    chk(&mut ln, &fmt::Sprintf!("%-22s masked=%s contains-10.9=%v contains-11=%v", "prefix-mask",
        p.Masked().String(), p.Contains(&netip::MustParseAddr("10.9.9.9")),
        p.Contains(&netip::MustParseAddr("11.0.0.1"))));
    let bad = netip::PrefixFrom(netip::MustParseAddr("10.0.0.0"), 33);
    chk(&mut ln, &fmt::Sprintf!("%-22s %s valid=%v", "prefix-badbits", bad.String(), bad.IsValid()));
    let neg = netip::PrefixFrom(netip::MustParseAddr("10.0.0.0"), -1);
    chk(&mut ln, &fmt::Sprintf!("%-22s %s valid=%v", "prefix-negbits", neg.String(), neg.IsValid()));
    chk(&mut ln, &fmt::Sprintf!("%-22s %v", "prefix-family", p.Contains(&netip::MustParseAddr("::1"))));

    let ap = netip::MustParseAddrPort("[2001:db8::1]:443");
    chk(&mut ln, &fmt::Sprintf!("%-22s %s port=%d", "mustparseaddrport", ap.String(), ap.Port() as int));
    let s4 = netip::MustParseAddr("1.2.3.4").AsSlice();
    chk(&mut ln, &fmt::Sprintf!("%-22s [%d %d %d %d] %d", "asslice",
        s4[0] as int, s4[1] as int, s4[2] as int, s4[3] as int,
        netip::MustParseAddr("::1").AsSlice().Len() as int));
    if ln != GO.len() {
        fmt::Printf!("[!!] produced %d lines, pinned %d\n", ln as int, GO.len() as int);
    }
}
