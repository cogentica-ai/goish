// netip_ref_smoke — net/netip against a running Go.
// (net/netip/netip.go, net/netip/uint128.go)
//
// Every expectation below is what a real Go 1.25.5 prints: the vectors
// are the output of `tools/gen_netip_ref.go` run in `package netip` by
// `scripts/goref.sh`.
//
// net/netip was 0% ported — no counterpart file at all — and it is the
// address type modern Go networking is written against.
//
// It is a parser and a formatter wearing a value type, and both halves
// have rules a plausible port gets subtly wrong:
//
//   * Parsing is STRICTER than net.ParseIP. "01.2.3.4" is refused for
//     the leading zero (a leading zero has meant OCTAL in enough
//     parsers that accepting it is a security question), "1.2.3" for
//     being short, "1::2::3" for the second ellipsis — each with its
//     own message naming where it gave up. The error TEXT is compared
//     here, because a parser that refuses the right inputs for the
//     wrong stated reason is still telling the caller something false.
//   * Formatting compresses the LONGEST run of zero groups to "::",
//     ties go to the FIRST run, and a run of length one is never
//     compressed. So "1:0:0:2:0:0:0:3" is "1:0:0:2::3" while
//     "1:0:0:2:0:0:3:0" is "1::2:0:0:3:0" — the same number of zero
//     groups, a different answer. Getting this wrong produces addresses
//     that still parse, still name the right host, and do not match
//     anyone else's string form.
//
// goish deviation: Go's `Addr.z` is a `*unique.Handle` used as a
// three-way sentinel (invalid / IPv4 / IPv6-no-zone) or an interned
// zone name. Rust has no pointer-identity sentinel to borrow, so `z` is
// a four-case enum and Go's `ip.z == z4` becomes a match.

#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

use goish::gostring::string;
use goish::net::netip;
use goish::types::int;
use goish::{fmt, syscall};

fn s(x: &str) -> string {
    return string::from_bytes(x.as_bytes());
}

// go: none — goish idiom: one comparison, printing the divergence when
//     it is one, so a FAIL says what it got and not just that it did.
fn eq(failed: &mut int, got: string, want: &str, what: &str) {
    if got == s(want) {
        return;
    }
    fmt::Printf!("[!!] %s FAIL got %q want %q\n", s(what), got, s(want));
    *failed += 1;
}

fn eqb(failed: &mut int, got: bool, want: bool, what: &str) {
    if got == want {
        return;
    }
    fmt::Printf!("[!!] %s FAIL got %v want %v\n", s(what), got, want);
    *failed += 1;
}

fn eqi(failed: &mut int, got: int, want: int, what: &str) {
    if got == want {
        return;
    }
    fmt::Printf!("[!!] %s FAIL got %d want %d\n", s(what), got, want);
    *failed += 1;
}

#[goish::main]
fn main() {
    let mut failed = 0;
    // 1. ParseAddr: the round trip, the family predicates, the zone,
    //    and the exact refusal text for every malformed form.
    {
        let cases: [(&str, &str, &str, bool, bool, bool, &str, i64); 40] = [
            ("1.2.3.4", "", "1.2.3.4", true, false, false, "", 32),
            ("0.0.0.0", "", "0.0.0.0", true, false, false, "", 32),
            ("255.255.255.255", "", "255.255.255.255", true, false, false, "", 32),
            ("127.0.0.1", "", "127.0.0.1", true, false, false, "", 32),
            ("01.2.3.4", "ParseAddr(\"01.2.3.4\"): IPv4 field has octet with leading zero", "", false, false, false, "", 0),
            ("1.2.3", "ParseAddr(\"1.2.3\"): IPv4 address too short", "", false, false, false, "", 0),
            ("1.2.3.4.5", "ParseAddr(\"1.2.3.4.5\"): IPv4 address too long", "", false, false, false, "", 0),
            ("256.1.1.1", "ParseAddr(\"256.1.1.1\"): IPv4 field has value >255", "", false, false, false, "", 0),
            ("1.2.3.04", "ParseAddr(\"1.2.3.04\"): IPv4 field has octet with leading zero", "", false, false, false, "", 0),
            ("1.2.3.4.", "ParseAddr(\"1.2.3.4.\"): IPv4 field must have at least one digit (at \".\")", "", false, false, false, "", 0),
            (".1.2.3.4", "ParseAddr(\".1.2.3.4\"): IPv4 field must have at least one digit (at \".1.2.3.4\")", "", false, false, false, "", 0),
            ("1..2.3", "ParseAddr(\"1..2.3\"): IPv4 field must have at least one digit (at \".2.3\")", "", false, false, false, "", 0),
            ("", "ParseAddr(\"\"): unable to parse IP", "", false, false, false, "", 0),
            ("::", "", "::", false, false, true, "", 128),
            ("::1", "", "::1", false, false, true, "", 128),
            ("1::", "", "1::", false, false, true, "", 128),
            ("fe80::1", "", "fe80::1", false, false, true, "", 128),
            ("2001:db8::1", "", "2001:db8::1", false, false, true, "", 128),
            ("2001:0db8:0000:0000:0000:0000:0000:0001", "", "2001:db8::1", false, false, true, "", 128),
            ("0:0:0:0:0:0:0:0", "", "::", false, false, true, "", 128),
            ("1:0:0:2:0:0:0:3", "", "1:0:0:2::3", false, false, true, "", 128),
            ("1:0:0:2:0:0:3:0", "", "1::2:0:0:3:0", false, false, true, "", 128),
            ("1:2:0:0:3:0:0:4", "", "1:2::3:0:0:4", false, false, true, "", 128),
            ("0:0:1:0:0:2:0:0", "", "::1:0:0:2:0:0", false, false, true, "", 128),
            ("::ffff:1.2.3.4", "", "::ffff:1.2.3.4", false, true, true, "", 128),
            ("::ffff:192.168.0.1", "", "::ffff:192.168.0.1", false, true, true, "", 128),
            ("64:ff9b::1.2.3.4", "", "64:ff9b::102:304", false, false, true, "", 128),
            ("fe80::1%eth0", "", "fe80::1%eth0", false, false, true, "eth0", 128),
            ("fe80::1%1", "", "fe80::1%1", false, false, true, "1", 128),
            ("::%zone", "", "::%zone", false, false, true, "zone", 128),
            ("1:2:3:4:5:6:7:8", "", "1:2:3:4:5:6:7:8", false, false, true, "", 128),
            ("1:2:3:4:5:6:7:8:9", "ParseAddr(\"1:2:3:4:5:6:7:8:9\"): trailing garbage after address (at \"9\")", "", false, false, false, "", 0),
            ("1:2:3:4:5:6:7", "ParseAddr(\"1:2:3:4:5:6:7\"): address string too short", "", false, false, false, "", 0),
            ("1::2::3", "ParseAddr(\"1::2::3\"): multiple :: in address (at \":3\")", "", false, false, false, "", 0),
            (":1:2:3:4:5:6:7", "ParseAddr(\":1:2:3:4:5:6:7\"): each colon-separated field must have at least one digit (at \":1:2:3:4:5:6:7\")", "", false, false, false, "", 0),
            ("1:2:3:4:5:6:7:", "ParseAddr(\"1:2:3:4:5:6:7:\"): colon must be followed by more characters (at \":\")", "", false, false, false, "", 0),
            ("12345::", "ParseAddr(\"12345::\"): each group must have 4 or less digits (at \"12345::\")", "", false, false, false, "", 0),
            ("g::1", "ParseAddr(\"g::1\"): each colon-separated field must have at least one digit (at \"g::1\")", "", false, false, false, "", 0),
            ("::ffff:1.2.3", "ParseAddr(\"::ffff:1.2.3\"): IPv4 address too short", "", false, false, false, "", 0),
            ("::1.2.3.4", "", "::102:304", false, false, true, "", 128),
        ];
        let mut i = 0;
        while i < cases.len() {
            let (inp, we, ws, w4, w46, w6, wz, wb) = cases[i];
            let (a, err) = netip::ParseAddr(inp);
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
                eq(&mut failed, a.String(), ws, inp);
                eqb(&mut failed, a.Is4(), w4, inp);
                eqb(&mut failed, a.Is4In6(), w46, inp);
                eqb(&mut failed, a.Is6(), w6, inp);
                eq(&mut failed, a.Zone(), wz, inp);
                eqi(&mut failed, a.BitLen(), wb, inp);
            }
            i += 1;
        }
        fmt::Println!("[  1 ] ParseAddr: forms, families and refusals");
    }

    // 2. The address-class predicates. ::ffff:127.0.0.1 is a LOOPBACK
    //    — the 4-in-6 forms are unmapped first — while ff01::1 is
    //    interface-local and ff02::1 link-local multicast, one nibble
    //    apart.
    {
        let cases: [(&str, bool, bool, bool, bool, bool, bool, bool, bool); 16] = [
            (
                "127.0.0.1",
                true,
                false,
                false,
                false,
                false,
                false,
                false,
                false,
            ),
            ("::1", true, false, false, false, false, false, false, false),
            (
                "10.0.0.1", false, true, false, false, false, false, true, false,
            ),
            (
                "172.16.0.1",
                false,
                true,
                false,
                false,
                false,
                false,
                true,
                false,
            ),
            (
                "192.168.1.1",
                false,
                true,
                false,
                false,
                false,
                false,
                true,
                false,
            ),
            (
                "8.8.8.8", false, false, false, false, false, false, true, false,
            ),
            (
                "169.254.1.1",
                false,
                false,
                true,
                false,
                false,
                false,
                false,
                false,
            ),
            (
                "fe80::1", false, false, true, false, false, false, false, false,
            ),
            (
                "ff02::1", false, false, false, true, false, true, false, false,
            ),
            (
                "ff01::1", false, false, false, false, true, true, false, false,
            ),
            (
                "224.0.0.1",
                false,
                false,
                false,
                true,
                false,
                true,
                false,
                false,
            ),
            (
                "0.0.0.0", false, false, false, false, false, false, false, true,
            ),
            ("::", false, false, false, false, false, false, false, true),
            (
                "fc00::1", false, true, false, false, false, false, true, false,
            ),
            (
                "2001:db8::1",
                false,
                false,
                false,
                false,
                false,
                false,
                true,
                false,
            ),
            (
                "::ffff:127.0.0.1",
                true,
                false,
                false,
                false,
                false,
                false,
                false,
                false,
            ),
        ];
        let mut i = 0;
        while i < cases.len() {
            let (inp, lo, pv, lu, lm, il, mu, gu, un) = cases[i];
            let a = netip::MustParseAddr(inp);
            eqb(&mut failed, a.IsLoopback(), lo, inp);
            eqb(&mut failed, a.IsPrivate(), pv, inp);
            eqb(&mut failed, a.IsLinkLocalUnicast(), lu, inp);
            eqb(&mut failed, a.IsLinkLocalMulticast(), lm, inp);
            eqb(&mut failed, a.IsInterfaceLocalMulticast(), il, inp);
            eqb(&mut failed, a.IsMulticast(), mu, inp);
            eqb(&mut failed, a.IsGlobalUnicast(), gu, inp);
            eqb(&mut failed, a.IsUnspecified(), un, inp);
            i += 1;
        }
        fmt::Println!("[  2 ] the address-class predicates");
    }

    // 3. Unmap, Next and Prev — including the overflow edges, where Go
    //    returns the ZERO Addr whose String is "invalid IP".
    {
        let cases: [(&str, &str, &str, &str); 5] = [
            ("1.2.3.4", "1.2.3.4", "1.2.3.5", "1.2.3.3"),
            (
                "::ffff:1.2.3.4",
                "1.2.3.4",
                "::ffff:1.2.3.5",
                "::ffff:1.2.3.3",
            ),
            (
                "255.255.255.255",
                "255.255.255.255",
                "invalid IP",
                "255.255.255.254",
            ),
            ("::", "::", "::1", "invalid IP"),
            (
                "fe80::1%eth0",
                "fe80::1%eth0",
                "fe80::2%eth0",
                "fe80::%eth0",
            ),
        ];
        let mut i = 0;
        while i < cases.len() {
            let (inp, wu, wn, wp) = cases[i];
            let a = netip::MustParseAddr(inp);
            eq(&mut failed, a.Unmap().String(), wu, inp);
            eq(&mut failed, a.Next().String(), wn, inp);
            eq(&mut failed, a.Prev().String(), wp, inp);
            i += 1;
        }
        fmt::Println!("[  3 ] Unmap, Next, Prev and their edges");
    }

    // 4. Compare sorts by LENGTH first, so every IPv4 address sorts
    //    before every IPv6 one, and a zone breaks a tie.
    {
        let cases: [(&str, &str, i64); 5] = [
            ("1.2.3.4", "1.2.3.5", -1),
            ("1.2.3.4", "1.2.3.4", 0),
            ("::1", "1.2.3.4", 1),
            ("fe80::1", "fe80::2", -1),
            ("fe80::1%a", "fe80::1%b", -1),
        ];
        let mut i = 0;
        while i < cases.len() {
            let (a1, a2, want) = cases[i];
            eqi(
                &mut failed,
                netip::MustParseAddr(a1).Compare(&netip::MustParseAddr(a2)),
                want,
                a1,
            );
            i += 1;
        }
        fmt::Println!("[  4 ] Compare orders by length, then bits, then zone");
    }

    // 5. ParsePrefix. "1.2.3.4/24" KEEPS its host bits until you ask
    //    for Masked — which is what Go documents and what a port that
    //    masks eagerly gets wrong.
    {
        let cases: [(&str, &str, &str, &str, i64, &str, bool); 13] = [
            (
                "1.2.3.0/24",
                "",
                "1.2.3.0/24",
                "1.2.3.0",
                24,
                "1.2.3.0/24",
                false,
            ),
            (
                "1.2.3.4/24",
                "",
                "1.2.3.4/24",
                "1.2.3.4",
                24,
                "1.2.3.0/24",
                false,
            ),
            (
                "0.0.0.0/0",
                "",
                "0.0.0.0/0",
                "0.0.0.0",
                0,
                "0.0.0.0/0",
                false,
            ),
            (
                "1.2.3.4/32",
                "",
                "1.2.3.4/32",
                "1.2.3.4",
                32,
                "1.2.3.4/32",
                true,
            ),
            (
                "2001:db8::/32",
                "",
                "2001:db8::/32",
                "2001:db8::",
                32,
                "2001:db8::/32",
                false,
            ),
            ("::/0", "", "::/0", "::", 0, "::/0", false),
            (
                "fe80::1/128",
                "",
                "fe80::1/128",
                "fe80::1",
                128,
                "fe80::1/128",
                true,
            ),
            (
                "1.2.3.4/33",
                "netip.ParsePrefix(\"1.2.3.4/33\"): prefix length out of range",
                "",
                "",
                0,
                "",
                false,
            ),
            (
                "1.2.3.4/-1",
                "netip.ParsePrefix(\"1.2.3.4/-1\"): bad bits after slash: \"-1\"",
                "",
                "",
                0,
                "",
                false,
            ),
            (
                "1.2.3.4/",
                "netip.ParsePrefix(\"1.2.3.4/\"): bad bits after slash: \"\"",
                "",
                "",
                0,
                "",
                false,
            ),
            (
                "1.2.3.4",
                "netip.ParsePrefix(\"1.2.3.4\"): no '/'",
                "",
                "",
                0,
                "",
                false,
            ),
            (
                "::ffff:1.2.3.4/120",
                "",
                "::ffff:1.2.3.4/120",
                "::ffff:1.2.3.4",
                120,
                "::ffff:1.2.3.0/120",
                false,
            ),
            (
                "fe80::1%eth0/64",
                "netip.ParsePrefix(\"fe80::1%eth0/64\"): IPv6 zones cannot be present in a prefix",
                "",
                "",
                0,
                "",
                false,
            ),
        ];
        let mut i = 0;
        while i < cases.len() {
            let (inp, we, ws, wa, wb, wm, wsing) = cases[i];
            let (p, err) = netip::ParsePrefix(inp);
            if we.len() > 0 {
                if err.IsNil() {
                    fmt::Printf!("[!!] pfx %q FAIL expected error\n", s(inp));
                    failed += 1;
                } else {
                    eq(&mut failed, err.Error(), we, inp);
                }
            } else if !err.IsNil() {
                fmt::Printf!("[!!] pfx %q FAIL %q\n", s(inp), err.Error());
                failed += 1;
            } else {
                eq(&mut failed, p.String(), ws, inp);
                eq(&mut failed, p.Addr().String(), wa, inp);
                eqi(&mut failed, p.Bits(), wb, inp);
                eq(&mut failed, p.Masked().String(), wm, inp);
                eqb(&mut failed, p.IsSingleIP(), wsing, inp);
            }
            i += 1;
        }
        fmt::Println!("[  5 ] ParsePrefix, Masked and IsSingleIP");
    }

    // 6. Contains and Overlaps. An IPv4 prefix does NOT contain the
    //    IPv4-mapped form of an address it otherwise would — the
    //    families must match — which is the row that catches a port
    //    comparing the 128-bit value blindly.
    {
        let cases: [(&str, &str, bool); 5] = [
            ("1.2.3.0/24", "1.2.3.4", true),
            ("1.2.3.0/24", "1.2.4.1", false),
            ("::/0", "::1", true),
            ("1.2.3.0/24", "::ffff:1.2.3.4", false),
            ("2001:db8::/32", "2001:db8::1", true),
        ];
        let mut i = 0;
        while i < cases.len() {
            let (p, a, want) = cases[i];
            eqb(
                &mut failed,
                netip::MustParsePrefix(p).Contains(&netip::MustParseAddr(a)),
                want,
                p,
            );
            i += 1;
        }
        let ovl: [(&str, &str, bool); 4] = [
            ("1.2.3.0/24", "1.2.3.128/25", true),
            ("1.2.3.0/24", "1.2.4.0/24", false),
            ("::/0", "2001:db8::/32", true),
            ("1.2.3.0/24", "::/0", false),
        ];
        let mut j = 0;
        while j < ovl.len() {
            let (p1, p2, want) = ovl[j];
            eqb(
                &mut failed,
                netip::MustParsePrefix(p1).Overlaps(&netip::MustParsePrefix(p2)),
                want,
                p1,
            );
            j += 1;
        }
        fmt::Println!("[  6 ] Contains and Overlaps across families");
    }

    // 7. AddrPort. An IPv6 address MUST be bracketed and an IPv4 one
    //    must not be, so "::1:80" is refused rather than read as port
    //    80 — the last colon is not a separator when the address is v6.
    {
        let cases: [(&str, &str, &str, &str, i64); 9] = [
            ("1.2.3.4:80", "", "1.2.3.4:80", "1.2.3.4", 80),
            ("[::1]:80", "", "[::1]:80", "::1", 80),
            (
                "[fe80::1%eth0]:53",
                "",
                "[fe80::1%eth0]:53",
                "fe80::1%eth0",
                53,
            ),
            ("1.2.3.4", "not an ip:port", "", "", 0),
            ("[::1]", "missing ]", "", "", 0),
            (
                "::1:80",
                "invalid ip:port \"::1:80\", IPv6 addresses must be surrounded by square brackets",
                "",
                "",
                0,
            ),
            ("1.2.3.4:", "no port", "", "", 0),
            (
                "1.2.3.4:99999",
                "invalid port \"99999\" parsing \"1.2.3.4:99999\"",
                "",
                "",
                0,
            ),
            (
                "[::1]:x",
                "invalid port \"x\" parsing \"[::1]:x\"",
                "",
                "",
                0,
            ),
        ];
        let mut i = 0;
        while i < cases.len() {
            let (inp, we, ws, wa, wp) = cases[i];
            let (ap, err) = netip::ParseAddrPort(inp);
            if we.len() > 0 {
                if err.IsNil() {
                    fmt::Printf!("[!!] ap %q FAIL expected error\n", s(inp));
                    failed += 1;
                } else {
                    eq(&mut failed, err.Error(), we, inp);
                }
            } else if !err.IsNil() {
                fmt::Printf!("[!!] ap %q FAIL %q\n", s(inp), err.Error());
                failed += 1;
            } else {
                eq(&mut failed, ap.String(), ws, inp);
                eq(&mut failed, ap.Addr().String(), wa, inp);
                eqi(&mut failed, ap.Port() as i64, wp, inp);
            }
            i += 1;
        }
        fmt::Println!("[  7 ] AddrPort and its bracket rule");
    }

    // 8. The binary and text encodings, and StringExpanded. The binary
    //    form is 4 bytes for IPv4 and 16 for IPv6 — with any ZONE
    //    appended raw after the 16, so a zoned address is LONGER than 16
    //    and a reader must take the tail as the zone.
    {
        {
            let a = netip::MustParseAddr("1.2.3.4");
            let (b, _) = a.MarshalBinary();
            let want: [u8; 4] = [1, 2, 3, 4];
            eqi(&mut failed, b.Len(), 4, "binlen 1.2.3.4");
            if b.clone().__into_vec() != want.to_vec() {
                fmt::Println!("[!!] bin FAIL 1.2.3.4");
                failed += 1;
            }
            let (t, _) = a.MarshalText();
            eq(
                &mut failed,
                string::from_bytes(&t.clone().__into_vec()),
                "1.2.3.4",
                "text 1.2.3.4",
            );
            let mut back = netip::Addr::default();
            if !back.UnmarshalBinary(b).IsNil() {
                fmt::Println!("[!!] unmarshal err 1.2.3.4");
                failed += 1;
            }
            eq(
                &mut failed,
                back.String(),
                "1.2.3.4",
                "binary round trip 1.2.3.4",
            );
        }
        {
            let a = netip::MustParseAddr("::1");
            let (b, _) = a.MarshalBinary();
            let want: [u8; 16] = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
            eqi(&mut failed, b.Len(), 16, "binlen ::1");
            if b.clone().__into_vec() != want.to_vec() {
                fmt::Println!("[!!] bin FAIL ::1");
                failed += 1;
            }
            let (t, _) = a.MarshalText();
            eq(
                &mut failed,
                string::from_bytes(&t.clone().__into_vec()),
                "::1",
                "text ::1",
            );
            let mut back = netip::Addr::default();
            if !back.UnmarshalBinary(b).IsNil() {
                fmt::Println!("[!!] unmarshal err ::1");
                failed += 1;
            }
            eq(&mut failed, back.String(), "::1", "binary round trip ::1");
        }
        {
            let a = netip::MustParseAddr("fe80::1%eth0");
            let (b, _) = a.MarshalBinary();
            let want: [u8; 20] = [
                254, 128, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 101, 116, 104, 48,
            ];
            eqi(&mut failed, b.Len(), 20, "binlen fe80::1%eth0");
            if b.clone().__into_vec() != want.to_vec() {
                fmt::Println!("[!!] bin FAIL fe80::1%eth0");
                failed += 1;
            }
            let (t, _) = a.MarshalText();
            eq(
                &mut failed,
                string::from_bytes(&t.clone().__into_vec()),
                "fe80::1%eth0",
                "text fe80::1%eth0",
            );
            let mut back = netip::Addr::default();
            if !back.UnmarshalBinary(b).IsNil() {
                fmt::Println!("[!!] unmarshal err fe80::1%eth0");
                failed += 1;
            }
            eq(
                &mut failed,
                back.String(),
                "fe80::1%eth0",
                "binary round trip fe80::1%eth0",
            );
        }
        eq(
            &mut failed,
            netip::MustParseAddr("::1").StringExpanded(),
            "0000:0000:0000:0000:0000:0000:0000:0001",
            "expanded ::1",
        );
        eq(
            &mut failed,
            netip::MustParseAddr("2001:db8::1").StringExpanded(),
            "2001:0db8:0000:0000:0000:0000:0000:0001",
            "expanded 2001:db8::1",
        );
        eq(
            &mut failed,
            netip::MustParseAddr("1.2.3.4").StringExpanded(),
            "1.2.3.4",
            "expanded 1.2.3.4",
        );
        // The zero Addr: not valid, and its String says so.
        let z = netip::Addr::default();
        eqb(&mut failed, z.IsValid(), false, "zero IsValid");
        eq(&mut failed, z.String(), "invalid IP", "zero String");
        eqb(&mut failed, z.Is4(), false, "zero Is4");
        eqi(&mut failed, z.BitLen(), 0, "zero BitLen");
        fmt::Println!("[  8 ] encodings, StringExpanded and the zero Addr");
    }

    if failed == 0 {
        fmt::Println!("ok - net/netip matches Go");
        syscall::Exit(0);
    } else {
        fmt::Println!("FAIL", failed);
        syscall::Exit(1);
    }
}
