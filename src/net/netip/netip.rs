// go: file net/netip/netip.go decls: IPv6LinkLocalAllNodes, IPv6LinkLocalAllRouters, IPv6Loopback, IPv6Unspecified, IPv4Unspecified, AddrFrom4, AddrFrom16, ParseAddr, MustParseAddr, parseAddrError.Error, parseIPv4Fields, parseIPv4, parseIPv6, AddrFromSlice, Addr.v4, Addr.v6, Addr.v6u16, Addr.isZero, Addr.IsValid, Addr.BitLen, Addr.Zone, Addr.Compare, Addr.Less, Addr.Is4, Addr.Is4In6, Addr.Is6, Addr.Unmap, Addr.WithZone, Addr.withoutZone, Addr.hasZone, Addr.IsLinkLocalUnicast, Addr.IsLoopback, Addr.IsMulticast, Addr.IsInterfaceLocalMulticast, Addr.IsLinkLocalMulticast, Addr.IsGlobalUnicast, Addr.IsPrivate, Addr.IsUnspecified, Addr.Prefix, Addr.As16, Addr.As4, Addr.AsSlice, Addr.Next, Addr.Prev, Addr.String, Addr.AppendTo, appendDecimal, appendHex, appendHexPad, Addr.string4, Addr.appendTo4, Addr.string4In6, Addr.appendTo4In6, Addr.string6, Addr.appendTo6, Addr.StringExpanded, Addr.AppendText, Addr.MarshalText, Addr.UnmarshalText, Addr.AppendBinary, Addr.marshalBinarySize, Addr.MarshalBinary, Addr.UnmarshalBinary, AddrPortFrom, AddrPort.Addr, AddrPort.Port, splitAddrPort, ParseAddrPort, MustParseAddrPort, AddrPort.IsValid, AddrPort.Compare, AddrPort.String, AddrPort.AppendTo, Prefix, PrefixFrom, Prefix.Addr, Prefix.Bits, Prefix.IsValid, Prefix.isZero, Prefix.IsSingleIP, Prefix.compare, parsePrefixError.Error, ParsePrefix, MustParsePrefix, Prefix.Masked, Prefix.Contains, Prefix.Overlaps, Prefix.AppendTo, Prefix.String
//
// netip.go — Addr, AddrPort and Prefix.
//
// This is a parser and a formatter wearing a value type, and both
// halves have rules that a plausible port gets subtly wrong:
//
//   * Parsing is STRICTER than net.ParseIP. "01.2.3.4" is rejected for
//     the leading zero, "1.2.3" for being short, "1::2::3" for the
//     second ellipsis — each with its own message naming where it gave
//     up.
//   * Formatting compresses the LONGEST run of zero groups to "::",
//     ties go to the FIRST run, and a run of length one is never
//     compressed. So "1:0:0:2:0:0:0:3" is "1:0:0:2::3" but
//     "1:0:0:2:0:0:3:0" is "1::2:0:0:3:0" — same number of zero groups,
//     different answer.
//
// goish deviation: Go's `Addr.z` is a `*unique.Handle` used as a
// three-way sentinel — z0 (invalid), z4 (IPv4), z6noz (IPv6, no zone)
// — or an interned zone name. Rust has no pointer-identity sentinel to
// borrow, so `z` is an enum with those four cases. Every `ip.z == z4`
// in Go is a match on it here, and the meaning is the same.

#![allow(non_snake_case)]
// goishlint:ignore GOISH021 addrDetail — Go's `addrDetail{isV6, zoneV6}` exists only to be interned by `unique.Make` and compared by handle identity, which is how its `z` field encodes four states in one pointer. goish has no pointer-identity sentinel, so those four states are the `Z` enum below and the struct has nothing left to hold.

extern crate alloc;
use alloc::vec::Vec;

use super::uint128::{mask6, uint128};
use crate::errors::{self, error, nil, ErrorTrait};
use crate::goslice::slice;
use crate::gostring::string;
use crate::strings;
use crate::types::{byte, int};
use crate::{fmt, int64};

// go: sdk 1.25.5 net/netip/netip.go:61-64 addrDetail
/// Go: `type addrDetail struct { isV6 bool; zoneV6 string }`, interned
/// through `unique.Make` and compared by handle identity.
///
/// goish spells the whole `z` field as this enum: Go's z0/z4/z6noz
/// sentinels and the interned zone become four cases, and the
/// pointer-identity comparisons become matches.
#[derive(Clone, PartialEq, Eq, Default, Debug)]
pub(crate) enum Z {
    /// Go's `z0` — the zero Addr, which is not a valid address.
    #[default]
    Z0,
    /// Go's `z4` — an IPv4 address.
    Z4,
    /// Go's `z6noz` — an IPv6 address with no zone.
    Z6noz,
    /// Go's interned `addrDetail{isV6: true, zoneV6: …}`.
    Zone(string),
}

// go: sdk 1.25.5 net/netip/netip.go:38-59 Addr
/// Go: "Addr represents an IPv4 or IPv6 address (with or without a
/// scoped addressing zone), similar to [net.IP] or [net.IPAddr]."
#[derive(Clone, PartialEq, Eq, Default)]
pub struct Addr {
    /// Go: "addr is the hi and lo bits of an IPv6 address. If z==z4,
    /// hi and lo contain the IPv4-mapped IPv6 address."
    pub(crate) addr: uint128,
    /// Go: "z is a combination of the address family and the IPv6 zone."
    pub(crate) z: Z,
}

// go: sdk 1.25.5 net/netip/netip.go:76-76 IPv6LinkLocalAllNodes
/// Go: "IPv6LinkLocalAllNodes returns the IPv6 link-local all nodes
/// multicast address ff02::1."
pub fn IPv6LinkLocalAllNodes() -> Addr {
    let mut a = [0u8; 16];
    a[0] = 0xff;
    a[1] = 0x02;
    a[15] = 0x01;
    return AddrFrom16(a);
}

// go: sdk 1.25.5 net/netip/netip.go:80-80 IPv6LinkLocalAllRouters
/// Go: "IPv6LinkLocalAllRouters returns the IPv6 link-local all routers
/// multicast address ff02::2."
pub fn IPv6LinkLocalAllRouters() -> Addr {
    let mut a = [0u8; 16];
    a[0] = 0xff;
    a[1] = 0x02;
    a[15] = 0x02;
    return AddrFrom16(a);
}

// go: sdk 1.25.5 net/netip/netip.go:83-83 IPv6Loopback
/// Go: "IPv6Loopback returns the IPv6 loopback address ::1."
pub fn IPv6Loopback() -> Addr {
    let mut a = [0u8; 16];
    a[15] = 0x01;
    return AddrFrom16(a);
}

// go: sdk 1.25.5 net/netip/netip.go:86-86 IPv6Unspecified
/// Go: "IPv6Unspecified returns the IPv6 unspecified address `::`."
pub fn IPv6Unspecified() -> Addr {
    return Addr {
        addr: uint128::default(),
        z: Z::Z6noz,
    };
}

// go: sdk 1.25.5 net/netip/netip.go:89-89 IPv4Unspecified
/// Go: "IPv4Unspecified returns the IPv4 unspecified address
/// "0.0.0.0"."
pub fn IPv4Unspecified() -> Addr {
    return AddrFrom4([0u8; 4]);
}

// go: sdk 1.25.5 net/netip/netip.go:92-99 AddrFrom4
/// Go: "AddrFrom4 returns the address of the IPv4 address given by the
/// bytes in addr."
pub fn AddrFrom4(addr: [byte; 4]) -> Addr {
    return Addr {
        addr: uint128 {
            hi: 0,
            // Go: 0xffff00000000 | uint64(addr[0])<<24 | …
            lo: 0x0000_ffff_0000_0000
                | crate::uint64(addr[0]) << 24
                | crate::uint64(addr[1]) << 16
                | crate::uint64(addr[2]) << 8
                | crate::uint64(addr[3]),
        },
        z: Z::Z4,
    };
}

// go: sdk 1.25.5 net/netip/netip.go:102-112 AddrFrom16
/// Go: "AddrFrom16 returns the IPv6 address given by the bytes in addr.
/// An IPv4-mapped IPv6 address is left as an IPv6 address. (Use
/// Unmap to convert them if needed.)"
pub fn AddrFrom16(addr: [byte; 16]) -> Addr {
    return Addr {
        addr: uint128 {
            hi: u64::from_be_bytes([
                addr[0], addr[1], addr[2], addr[3], addr[4], addr[5], addr[6], addr[7],
            ]),
            lo: u64::from_be_bytes([
                addr[8], addr[9], addr[10], addr[11], addr[12], addr[13], addr[14], addr[15],
            ]),
        },
        z: Z::Z6noz,
    };
}

// go: sdk 1.25.5 net/netip/netip.go:141-145 parseAddrError
pub struct parseAddrError {
    pub(crate) in_: string,
    pub(crate) msg: string,
    pub(crate) at: string,
}

impl ErrorTrait for parseAddrError {
    // go: sdk 1.25.5 net/netip/netip.go:147-153 parseAddrError.Error
    fn Error(&self) -> string {
        // Go: q := strconv.Quote; if err.at != "" { … " (at " + q(err.at) + ")" }
        let q = |s: &string| -> string { return fmt::Sprintf!("%q", s.clone()) };
        let base = string::from_static("ParseAddr(")
            + q(&self.in_)
            + string::from_static("): ")
            + self.msg.clone();
        if self.at.Len() != 0 {
            return base + string::from_static(" (at ") + q(&self.at) + string::from_static(")");
        }
        return base;
    }
}

// go: none — goish idiom: Go builds `parseAddrError{…}` inline at each
//     site; goish wraps it into an `error` here so the sites stay one
//     line, as Go's are.
fn perr(in_: &string, msg: &str, at: &string) -> error {
    return errors::Wrap(parseAddrError {
        in_: in_.clone(),
        msg: string::from_bytes(msg.as_bytes()),
        at: at.clone(),
    });
}

// go: sdk 1.25.5 net/netip/netip.go:115-131 ParseAddr
/// Go: "ParseAddr parses s as an IP address, returning the result. The
/// string s can be in dotted decimal ("192.0.2.1"), IPv6
/// ("2001:db8::68"), or IPv6 with a scoped addressing zone
/// ("fe80::1cc0:3e8c:119f:c2e1%ens18")."
pub fn ParseAddr<S: Into<string>>(s: S) -> (Addr, error) {
    let s: string = s.into();
    let b = s.as_bytes();
    let mut i: usize = 0;
    while i < b.len() {
        // Go: switch s[i] { case '.': return parseIPv4(s)
        //                   case ':': return parseIPv6(s)
        //                   case '%': …
        if b[i] == b'.' {
            return parseIPv4(&s);
        }
        if b[i] == b':' {
            return parseIPv6(&s);
        }
        if b[i] == b'%' {
            // Go: "Assume that this was trying to be an IPv6 address with
            // a zone specifier, but the address is missing."
            return (
                Addr::default(),
                perr(&s, "missing IPv6 address", &string::new()),
            );
        }
        i += 1;
    }
    return (
        Addr::default(),
        perr(&s, "unable to parse IP", &string::new()),
    );
}

// go: sdk 1.25.5 net/netip/netip.go:133-139 MustParseAddr
/// Go: "MustParseAddr calls [ParseAddr](s) and panics on error. It is
/// intended for use in tests with hard-coded strings."
pub fn MustParseAddr<S: Into<string>>(s: S) -> Addr {
    let (ip, err) = ParseAddr(s);
    if err != nil {
        panic!("{}", err.Error());
    }
    return ip;
}

// go: sdk 1.25.5 net/netip/netip.go:155-192 parseIPv4Fields
/// Go: "parseIPv4Fields parses a fixed-length dotted-decimal string
/// from in[off:end] into fields."
fn parseIPv4Fields(in_: &string, off: usize, end: usize, fields: &mut [u8]) -> error {
    let mut val: int = 0;
    let mut pos: usize = 0;
    // Go: digLen — number of digits in current octet.
    let mut digLen: int = 0;
    let whole = in_.as_bytes();
    let s = &whole[off..end];
    let mut i: usize = 0;
    while i < s.len() {
        let c = s[i];
        if c.is_ascii_digit() {
            // Go: an octet with a leading zero is refused outright —
            // "01" is not 1, because a leading zero has meant OCTAL in
            // enough parsers that accepting it is a security question.
            if digLen == 1 && val == 0 {
                return perr(
                    in_,
                    "IPv4 field has octet with leading zero",
                    &string::new(),
                );
            }
            val = val * 10 + int64(c - b'0');
            digLen += 1;
            if val > 255 {
                return perr(in_, "IPv4 field has value >255", &string::new());
            }
        } else if c == b'.' {
            // Go: ".1.2.3" / "1.2.3." / "1..2.3"
            if i == 0 || i == s.len() - 1 || s[i - 1] == b'.' {
                return perr(
                    in_,
                    "IPv4 field must have at least one digit",
                    &string::from_bytes(&s[i..]),
                );
            }
            // Go: "1.2.3.4.5"
            if pos == 3 {
                return perr(in_, "IPv4 address too long", &string::new());
            }
            fields[pos] = val as u8; // goishlint:ignore GOISH005 - val is bounded to 0..=255 three lines above.
            pos += 1;
            val = 0;
            digLen = 0;
        } else {
            return perr(in_, "unexpected character", &string::from_bytes(&s[i..]));
        }
        i += 1;
    }
    if pos < 3 {
        return perr(in_, "IPv4 address too short", &string::new());
    }
    fields[3] = val as u8; // goishlint:ignore GOISH005 - as above, bounded to 0..=255.
    return nil;
}

// go: sdk 1.25.5 net/netip/netip.go:195-203 parseIPv4
/// Go: "parseIPv4 parses s as an IPv4 address (in form
/// "192.168.0.1")."
fn parseIPv4(s: &string) -> (Addr, error) {
    let mut fields = [0u8; 4];
    let err = parseIPv4Fields(s, 0, s.as_bytes().len(), &mut fields);
    if err != nil {
        return (Addr::default(), err);
    }
    return (AddrFrom4(fields), nil);
}

// go: sdk 1.25.5 net/netip/netip.go:206-345 parseIPv6
/// Go: "parseIPv6 parses s as an IPv6 address (in form
/// "2001:db8::68")."
fn parseIPv6(in_: &string) -> (Addr, error) {
    let inb = in_.as_bytes().to_vec();
    let mut s: &[u8] = &inb;

    // Go: "Split off the zone right from the start."
    let mut zone: string = string::new();
    if let Some(i) = s.iter().position(|&c| c == b'%') {
        zone = string::from_bytes(&s[i + 1..]);
        s = &inb[..i];
        if zone.Len() == 0 {
            // Go: "Not allowed to have an empty zone if explicitly specified."
            return (
                Addr::default(),
                perr(in_, "zone must be a non-empty string", &string::new()),
            );
        }
    }

    let mut ip = [0u8; 16];
    // Go: position of ellipsis in ip, -1 for none.
    let mut ellipsis: isize = -1;

    // Go: "Might have leading ellipsis"
    if s.len() >= 2 && s[0] == b':' && s[1] == b':' {
        ellipsis = 0;
        s = &s[2..];
        // Go: "Might be only ellipsis"
        if s.is_empty() {
            return (IPv6Unspecified().WithZone(zone), nil);
        }
    }

    // Go: "Loop, parsing hex numbers followed by colon."
    let mut i: usize = 0;
    while i < 16 {
        // Go: hex number, inlined.
        let mut off: usize = 0;
        let mut acc: u32 = 0;
        while off < s.len() {
            let c = s[off];
            if c.is_ascii_digit() {
                acc = (acc << 4) + crate::uint32(c - b'0');
            } else if (b'a'..=b'f').contains(&c) {
                acc = (acc << 4) + crate::uint32(c - b'a' + 10);
            } else if (b'A'..=b'F').contains(&c) {
                acc = (acc << 4) + crate::uint32(c - b'A' + 10);
            } else {
                break;
            }
            if off > 3 {
                return (
                    Addr::default(),
                    perr(
                        in_,
                        "each group must have 4 or less digits",
                        &string::from_bytes(s),
                    ),
                );
            }
            if acc > crate::uint32(u16::MAX) {
                return (
                    Addr::default(),
                    perr(in_, "IPv6 field has value >=2^16", &string::from_bytes(s)),
                );
            }
            off += 1;
        }
        if off == 0 {
            return (
                Addr::default(),
                perr(
                    in_,
                    "each colon-separated field must have at least one digit",
                    &string::from_bytes(s),
                ),
            );
        }

        // Go: "If followed by dot, might be in trailing IPv4."
        if off < s.len() && s[off] == b'.' {
            if ellipsis < 0 && i != 12 {
                return (
                    Addr::default(),
                    perr(
                        in_,
                        "embedded IPv4 address must replace the final 2 fields of the address",
                        &string::from_bytes(s),
                    ),
                );
            }
            if i + 4 > 16 {
                return (
                    Addr::default(),
                    perr(
                        in_,
                        "too many hex fields to fit an embedded IPv4 at the end of the address",
                        &string::from_bytes(s),
                    ),
                );
            }
            let mut end = inb.len();
            if zone.Len() > 0 {
                end -= zone.as_bytes().len() + 1;
            }
            let mut f = [0u8; 4];
            let err = parseIPv4Fields(in_, end - s.len(), end, &mut f);
            if err != nil {
                return (Addr::default(), err);
            }
            ip[i..i + 4].copy_from_slice(&f);
            s = &[];
            i += 4;
            break;
        }

        // Go: "Save this 16-bit chunk."
        ip[i] = (acc >> 8) as u8; // goishlint:ignore GOISH005 - acc is bounded to 0..=0xffff above.
        ip[i + 1] = acc as u8; // goishlint:ignore GOISH005 - as above.
        i += 2;

        // Go: "Stop at end of string."
        s = &s[off..];
        if s.is_empty() {
            break;
        }

        // Go: "Otherwise must be followed by colon and more."
        if s[0] != b':' {
            return (
                Addr::default(),
                perr(
                    in_,
                    "unexpected character, want colon",
                    &string::from_bytes(s),
                ),
            );
        } else if s.len() == 1 {
            return (
                Addr::default(),
                perr(
                    in_,
                    "colon must be followed by more characters",
                    &string::from_bytes(s),
                ),
            );
        }
        s = &s[1..];

        // Go: "Look for ellipsis."
        if s[0] == b':' {
            if ellipsis >= 0 {
                return (
                    Addr::default(),
                    perr(in_, "multiple :: in address", &string::from_bytes(s)),
                );
            }
            ellipsis = i as isize;
            s = &s[1..];
            if s.is_empty() {
                break;
            }
        }
    }

    // Go: "Must have used entire string."
    if !s.is_empty() {
        return (
            Addr::default(),
            perr(
                in_,
                "trailing garbage after address",
                &string::from_bytes(s),
            ),
        );
    }

    // Go: "If didn't parse enough, expand ellipsis."
    if i < 16 {
        if ellipsis < 0 {
            return (
                Addr::default(),
                perr(in_, "address string too short", &string::new()),
            );
        }
        let e = ellipsis as usize;
        let n = 16 - i;
        let mut j = i;
        while j > e {
            j -= 1;
            ip[j + n] = ip[j];
        }
        let mut k = e;
        while k < e + n {
            ip[k] = 0;
            k += 1;
        }
    } else if ellipsis >= 0 {
        // Go: "Ellipsis must represent at least one 0 group."
        return (
            Addr::default(),
            perr(
                in_,
                "the :: must expand to at least one field of zeros",
                &string::new(),
            ),
        );
    }
    return (AddrFrom16(ip).WithZone(zone), nil);
}

// go: sdk 1.25.5 net/netip/netip.go:349-358 AddrFromSlice
/// Go: "AddrFromSlice parses the 4- or 16-byte byte slice as an IPv4 or
/// IPv6 address. … If slice's length is not 4 or 16, AddrFromSlice
/// returns [Addr]{}, false."
pub fn AddrFromSlice(sl: slice<byte>) -> (Addr, bool) {
    let v = sl.clone().__into_vec();
    if v.len() == 4 {
        let mut a = [0u8; 4];
        a.copy_from_slice(&v);
        return (AddrFrom4(a), true);
    }
    if v.len() == 16 {
        let mut a = [0u8; 16];
        a.copy_from_slice(&v);
        return (AddrFrom16(a), true);
    }
    return (Addr::default(), false);
}

impl Addr {
    // go: sdk 1.25.5 net/netip/netip.go:361-365 Addr.v4
    /// Go: "v4 returns the i'th byte of ip. If ip is not an IPv4, v4
    /// returns unspecified garbage."
    fn v4(&self, i: u8) -> u8 {
        return (self.addr.lo >> ((3 - i) * 8)) as u8; // goishlint:ignore GOISH005 - Go's `uint8(...)` truncation, which is the point.
    }

    // go: sdk 1.25.5 net/netip/netip.go:367-371 Addr.v6
    /// Go: "v6 returns the i'th byte of ip."
    fn v6(&self, i: u8) -> u8 {
        let half = if i < 8 { self.addr.hi } else { self.addr.lo };
        return (half >> ((7 - (i % 8)) * 8)) as u8; // goishlint:ignore GOISH005 - Go's `uint8(...)` truncation.
    }

    // go: sdk 1.25.5 net/netip/netip.go:373-380 Addr.v6u16
    /// Go: "v6u16 returns the i'th 16-bit word of ip."
    fn v6u16(&self, i: u8) -> u16 {
        let half = if i < 4 { self.addr.hi } else { self.addr.lo };
        return (half >> ((3 - (i % 4)) * 16)) as u16; // goishlint:ignore GOISH005 - Go's `uint16(...)` truncation.
    }

    // go: sdk 1.25.5 net/netip/netip.go:382-388 Addr.isZero
    /// Go uses this from `Prefix` and the marshalling paths; goish's
    /// reach the same answer through `IsValid`. Ported because Go
    /// declares it.
    #[allow(dead_code)]
    fn isZero(&self) -> bool {
        return self.z == Z::Z0;
    }

    // go: sdk 1.25.5 net/netip/netip.go:391-391 Addr.IsValid
    /// Go: "IsValid reports whether the [Addr] is an initialized address
    /// (not the zero [Addr])."
    pub fn IsValid(&self) -> bool {
        return self.z != Z::Z0;
    }

    // go: sdk 1.25.5 net/netip/netip.go:398-406 Addr.BitLen
    /// Go: "BitLen returns the number of bits in the IP address: 128 for
    /// IPv6, 32 for IPv4, and 0 for the zero [Addr]."
    pub fn BitLen(&self) -> int {
        if self.z == Z::Z0 {
            return 0;
        }
        if self.z == Z::Z4 {
            return 32;
        }
        return 128;
    }

    // go: sdk 1.25.5 net/netip/netip.go:409-416 Addr.Zone
    /// Go: "Zone returns ip's IPv6 scoped addressing zone, if any."
    pub fn Zone(&self) -> string {
        if let Z::Zone(s) = &self.z {
            return s.clone();
        }
        return string::new();
    }

    // go: sdk 1.25.5 net/netip/netip.go:419-451 Addr.Compare
    /// Go: "Compare returns an integer comparing two IPs. … IP
    /// addresses sort first by length, then their address. IPv6
    /// addresses with zones sort just after the same address without a
    /// zone."
    pub fn Compare(&self, ip2: &Addr) -> int {
        let (f1, f2) = (self.BitLen(), ip2.BitLen());
        if f1 < f2 {
            return -1;
        }
        if f1 > f2 {
            return 1;
        }
        if self.addr.hi < ip2.addr.hi {
            return -1;
        }
        if self.addr.hi > ip2.addr.hi {
            return 1;
        }
        if self.addr.lo < ip2.addr.lo {
            return -1;
        }
        if self.addr.lo > ip2.addr.lo {
            return 1;
        }
        if self.Is6() {
            let (za, zb) = (self.Zone(), ip2.Zone());
            if za < zb {
                return -1;
            }
            if za > zb {
                return 1;
            }
        }
        return 0;
    }

    // go: sdk 1.25.5 net/netip/netip.go:456-456 Addr.Less
    /// Go: "Less reports whether ip sorts before ip2."
    pub fn Less(&self, ip2: &Addr) -> bool {
        return self.Compare(ip2) == -1;
    }

    // go: sdk 1.25.5 net/netip/netip.go:461-463 Addr.Is4
    /// Go: "Is4 reports whether ip is an IPv4 address. It returns false
    /// for IPv4-mapped IPv6 addresses."
    pub fn Is4(&self) -> bool {
        return self.z == Z::Z4;
    }

    // go: sdk 1.25.5 net/netip/netip.go:468-470 Addr.Is4In6
    /// Go: "Is4In6 reports whether ip is an "IPv4-mapped IPv6 address"
    /// as defined by RFC 4291. That is, it reports whether ip is in
    /// ::ffff:0:0/96."
    pub fn Is4In6(&self) -> bool {
        return self.Is6() && self.addr.hi == 0 && self.addr.lo >> 32 == 0xffff;
    }

    // go: sdk 1.25.5 net/netip/netip.go:474-476 Addr.Is6
    /// Go: "Is6 reports whether ip is an IPv6 address, including
    /// IPv4-mapped IPv6 addresses."
    pub fn Is6(&self) -> bool {
        return self.z != Z::Z0 && self.z != Z::Z4;
    }

    // go: sdk 1.25.5 net/netip/netip.go:482-487 Addr.Unmap
    /// Go: "Unmap returns ip with any IPv4-mapped IPv6 address prefix
    /// removed."
    pub fn Unmap(&self) -> Addr {
        let mut ip = self.clone();
        if ip.Is4In6() {
            ip.z = Z::Z4;
        }
        return ip;
    }

    // go: sdk 1.25.5 net/netip/netip.go:492-502 Addr.WithZone
    /// Go: "WithZone returns an IP that's the same as ip but with the
    /// provided zone. If zone is empty, the zone is removed. If ip is an
    /// IPv4 address, WithZone is a no-op and returns ip unchanged."
    pub fn WithZone<S: Into<string>>(&self, zone: S) -> Addr {
        let zone: string = zone.into();
        let mut ip = self.clone();
        if !ip.Is6() {
            return ip;
        }
        if zone.Len() == 0 {
            ip.z = Z::Z6noz;
            return ip;
        }
        ip.z = Z::Zone(zone);
        return ip;
    }

    // go: sdk 1.25.5 net/netip/netip.go:506-512 Addr.withoutZone
    fn withoutZone(&self) -> Addr {
        let mut ip = self.clone();
        if !ip.Is6() {
            return ip;
        }
        ip.z = Z::Z6noz;
        return ip;
    }

    // go: sdk 1.25.5 net/netip/netip.go:515-517 Addr.hasZone
    fn hasZone(&self) -> bool {
        return matches!(self.z, Z::Zone(_));
    }

    // go: sdk 1.25.5 net/netip/netip.go:520-536 Addr.IsLinkLocalUnicast
    /// Go: "IsLinkLocalUnicast reports whether ip is a link-local
    /// unicast address."
    pub fn IsLinkLocalUnicast(&self) -> bool {
        let ip = if self.Is4In6() {
            self.Unmap()
        } else {
            self.clone()
        };
        if ip.Is4() {
            return ip.v4(0) == 169 && ip.v4(1) == 254;
        }
        if ip.Is6() {
            return ip.v6u16(0) & 0xffc0 == 0xfe80;
        }
        return false;
    }

    // go: sdk 1.25.5 net/netip/netip.go:539-555 Addr.IsLoopback
    /// Go: "IsLoopback reports whether ip is a loopback address."
    pub fn IsLoopback(&self) -> bool {
        let ip = if self.Is4In6() {
            self.Unmap()
        } else {
            self.clone()
        };
        if ip.Is4() {
            return ip.v4(0) == 127;
        }
        if ip.Is6() {
            return ip.addr.hi == 0 && ip.addr.lo == 1;
        }
        return false;
    }

    // go: sdk 1.25.5 net/netip/netip.go:558-574 Addr.IsMulticast
    /// Go: "IsMulticast reports whether ip is a multicast address."
    pub fn IsMulticast(&self) -> bool {
        let ip = if self.Is4In6() {
            self.Unmap()
        } else {
            self.clone()
        };
        if ip.Is4() {
            return ip.v4(0) & 0xf0 == 0xe0;
        }
        if ip.Is6() {
            return ip.addr.hi >> (64 - 8) == 0xff;
        }
        return false;
    }

    // go: sdk 1.25.5 net/netip/netip.go:578-585 Addr.IsInterfaceLocalMulticast
    /// Go: "IsInterfaceLocalMulticast reports whether ip is an
    /// IPv6 interface-local multicast address."
    pub fn IsInterfaceLocalMulticast(&self) -> bool {
        if self.Is6() && !self.Is4In6() {
            return self.v6u16(0) & 0xff0f == 0xff01;
        }
        return false;
    }

    // go: sdk 1.25.5 net/netip/netip.go:588-604 Addr.IsLinkLocalMulticast
    /// Go: "IsLinkLocalMulticast reports whether ip is a link-local
    /// multicast address."
    pub fn IsLinkLocalMulticast(&self) -> bool {
        let ip = if self.Is4In6() {
            self.Unmap()
        } else {
            self.clone()
        };
        if ip.Is4() {
            return ip.v4(0) == 224 && ip.v4(1) == 0 && ip.v4(2) == 0;
        }
        if ip.Is6() {
            return ip.v6u16(0) & 0xff0f == 0xff02;
        }
        return false;
    }

    // go: sdk 1.25.5 net/netip/netip.go:615-635 Addr.IsGlobalUnicast
    /// Go: "IsGlobalUnicast reports whether ip is a global unicast
    /// address."
    pub fn IsGlobalUnicast(&self) -> bool {
        if self.z == Z::Z0 {
            return false;
        }
        let ip = if self.Is4In6() {
            self.Unmap()
        } else {
            self.clone()
        };
        // Go: "Match package net's IsGlobalUnicast" — 0.0.0.0 and the
        // broadcast address are not global unicast.
        if ip.Is4() && (ip == IPv4Unspecified() || ip == AddrFrom4([255, 255, 255, 255])) {
            return false;
        }
        return ip != IPv6Unspecified()
            && !ip.IsLoopback()
            && !ip.IsMulticast()
            && !ip.IsLinkLocalUnicast();
    }

    // go: sdk 1.25.5 net/netip/netip.go:641-662 Addr.IsPrivate
    /// Go: "IsPrivate reports whether ip is a private address, according
    /// to RFC 1918 (IPv4 addresses) and RFC 4193 (IPv6 addresses)."
    pub fn IsPrivate(&self) -> bool {
        let ip = if self.Is4In6() {
            self.Unmap()
        } else {
            self.clone()
        };
        if ip.Is4() {
            return ip.v4(0) == 10
                || (ip.v4(0) == 172 && ip.v4(1) & 0xf0 == 16)
                || (ip.v4(0) == 192 && ip.v4(1) == 168);
        }
        if ip.Is6() {
            return ip.v6(0) & 0xfe == 0xfc;
        }
        return false;
    }

    // go: sdk 1.25.5 net/netip/netip.go:668-670 Addr.IsUnspecified
    /// Go: "IsUnspecified reports whether ip is an unspecified address,
    /// either the IPv4 address "0.0.0.0" or the IPv6 address "::"."
    pub fn IsUnspecified(&self) -> bool {
        return *self == IPv4Unspecified() || *self == IPv6Unspecified();
    }

    // go: sdk 1.25.5 net/netip/netip.go:677-701 Addr.Prefix
    /// Go: "Prefix keeps only the top b bits of IP, producing a Prefix
    /// of the specified length."
    pub fn Prefix(&self, b: int) -> (Prefix, error) {
        if b < 0 {
            return (Prefix::default(), errors::New("negative Prefix bits"));
        }
        let mut effectiveBits = b;
        match self.z {
            Z::Z0 => return (Prefix::default(), nil),
            Z::Z4 => {
                if b > 32 {
                    return (
                        Prefix::default(),
                        errors::New(
                            string::from_static("prefix length ")
                                + crate::strconv::Itoa(b)
                                + string::from_static(" too large for IPv4"),
                        ),
                    );
                }
                effectiveBits += 96;
            }
            _ => {
                if b > 128 {
                    return (
                        Prefix::default(),
                        errors::New(
                            string::from_static("prefix length ")
                                + crate::strconv::Itoa(b)
                                + string::from_static(" too large for IPv6"),
                        ),
                    );
                }
            }
        }
        let mut ip = self.clone();
        ip.addr = ip.addr.and(mask6(effectiveBits));
        return (PrefixFrom(ip, b), nil);
    }

    // go: sdk 1.25.5 net/netip/netip.go:704-710 Addr.As16
    /// Go: "As16 returns the IP address in its 16-byte representation."
    pub fn As16(&self) -> [byte; 16] {
        let mut a = [0u8; 16];
        a[..8].copy_from_slice(&self.addr.hi.to_be_bytes());
        a[8..].copy_from_slice(&self.addr.lo.to_be_bytes());
        return a;
    }

    // go: sdk 1.25.5 net/netip/netip.go:713-722 Addr.As4
    /// Go: "As4 returns an IPv4 or IPv4-in-IPv6 address in its 4-byte
    /// representation. If ip is the zero [Addr] or an IPv6 address,
    /// As4 panics."
    pub fn As4(&self) -> [byte; 4] {
        if self.z == Z::Z4 || self.Is4In6() {
            let mut a = [0u8; 4];
            a.copy_from_slice(&self.addr.lo.to_be_bytes()[4..]);
            return a;
        }
        if self.z == Z::Z0 {
            panic!("As4 called on IP zero value");
        }
        panic!("As4 called on IPv6 address");
    }

    // go: sdk 1.25.5 net/netip/netip.go:725-738 Addr.AsSlice
    /// Go: "AsSlice returns an IPv4 or IPv6 address in its respective
    /// 4-byte or 16-byte representation."
    pub fn AsSlice(&self) -> slice<byte> {
        if self.z == Z::Z0 {
            return slice::new();
        }
        if self.z == Z::Z4 {
            return slice::__from_vec(self.As4().to_vec());
        }
        return slice::__from_vec(self.As16().to_vec());
    }

    // go: sdk 1.25.5 net/netip/netip.go:743-756 Addr.Next
    /// Go: "Next returns the address following ip. If there is none, it
    /// returns the zero [Addr]."
    pub fn Next(&self) -> Addr {
        let mut ip = self.clone();
        ip.addr = ip.addr.addOne();
        match ip.z {
            Z::Z0 => return Addr::default(),
            Z::Z4 => {
                if ip.addr.lo >> 32 != 0xffff {
                    // Go: "overflowed"
                    return Addr::default();
                }
            }
            _ => {
                if ip.addr.isZero() {
                    // Go: "overflowed"
                    return Addr::default();
                }
            }
        }
        return ip;
    }

    // go: sdk 1.25.5 net/netip/netip.go:761-780 Addr.Prev
    /// Go: "Prev returns the IP before ip. If there is none, it returns
    /// the IP zero value."
    pub fn Prev(&self) -> Addr {
        let mut ip = self.clone();
        match ip.z {
            Z::Z0 => return Addr::default(),
            Z::Z4 => {
                if ip.addr.lo & 0xffff_ffff == 0 {
                    return Addr::default();
                }
            }
            _ => {
                if ip.addr.isZero() {
                    return Addr::default();
                }
            }
        }
        ip.addr = ip.addr.subOne();
        return ip;
    }

    // go: sdk 1.25.5 net/netip/netip.go:785-799 Addr.String
    /// Go: "String returns the string form of the IP address ip. It
    /// returns one of 5 forms: … "invalid IP", if ip is the zero
    /// [Addr]."
    pub fn String(&self) -> string {
        if self.z == Z::Z0 {
            return string::from_static("invalid IP");
        }
        if self.z == Z::Z4 {
            return self.string4();
        }
        if self.Is4In6() {
            return self.string4In6();
        }
        return self.string6();
    }

    // go: sdk 1.25.5 net/netip/netip.go:802-814 Addr.AppendTo
    /// Go: "AppendTo appends a text encoding of ip … to b and returns
    /// the extended buffer."
    pub fn AppendTo(&self, b: slice<byte>) -> slice<byte> {
        let mut out = b.clone().__into_vec();
        match self.z {
            Z::Z0 => {}
            Z::Z4 => self.appendTo4(&mut out),
            _ => {
                if self.Is4In6() {
                    self.appendTo4In6(&mut out);
                } else {
                    self.appendTo6(&mut out);
                }
            }
        }
        return slice::__from_vec(out);
    }

    // go: sdk 1.25.5 net/netip/netip.go:856-861 Addr.string4
    fn string4(&self) -> string {
        let mut b: Vec<u8> = Vec::new();
        self.appendTo4(&mut b);
        return string::__from_vec(b);
    }

    // go: sdk 1.25.5 net/netip/netip.go:863-872 Addr.appendTo4
    fn appendTo4(&self, ret: &mut Vec<u8>) {
        appendDecimal(ret, self.v4(0));
        ret.push(b'.');
        appendDecimal(ret, self.v4(1));
        ret.push(b'.');
        appendDecimal(ret, self.v4(2));
        ret.push(b'.');
        appendDecimal(ret, self.v4(3));
    }

    // go: sdk 1.25.5 net/netip/netip.go:874-879 Addr.string4In6
    fn string4In6(&self) -> string {
        let mut b: Vec<u8> = Vec::new();
        self.appendTo4In6(&mut b);
        return string::__from_vec(b);
    }

    // go: sdk 1.25.5 net/netip/netip.go:881-894 Addr.appendTo4In6
    fn appendTo4In6(&self, ret: &mut Vec<u8>) {
        ret.extend_from_slice(b"::ffff:");
        self.appendTo4(ret);
        if self.hasZone() {
            ret.push(b'%');
            ret.extend_from_slice(self.Zone().as_bytes());
        }
    }

    // go: sdk 1.25.5 net/netip/netip.go:896-908 Addr.string6
    fn string6(&self) -> string {
        let mut b: Vec<u8> = Vec::new();
        self.appendTo6(&mut b);
        return string::__from_vec(b);
    }

    // go: sdk 1.25.5 net/netip/netip.go:910-944 Addr.appendTo6
    /// The `::` rule, which is the whole reason this is not a loop over
    /// eight groups: the LONGEST run of zero groups is replaced, ties go
    /// to the FIRST run (the test is `l > zeroEnd-zeroStart`, strictly
    /// greater), and a run of length one is never replaced (`l >= 2`).
    fn appendTo6(&self, ret: &mut Vec<u8>) {
        let (mut zeroStart, mut zeroEnd): (u8, u8) = (255, 255);
        let mut i: u8 = 0;
        while i < 8 {
            let mut j = i;
            while j < 8 && self.v6u16(j) == 0 {
                j += 1;
            }
            let l = j - i;
            if l >= 2 && l > zeroEnd.wrapping_sub(zeroStart) {
                zeroStart = i;
                zeroEnd = j;
            }
            i += 1;
        }

        let mut i: u8 = 0;
        while i < 8 {
            if i == zeroStart {
                ret.extend_from_slice(b"::");
                i = zeroEnd;
                if i >= 8 {
                    break;
                }
            } else if i > 0 {
                ret.push(b':');
            }
            appendHex(ret, self.v6u16(i));
            i += 1;
        }

        if self.hasZone() {
            ret.push(b'%');
            ret.extend_from_slice(self.Zone().as_bytes());
        }
    }

    // go: sdk 1.25.5 net/netip/netip.go:946-971 Addr.StringExpanded
    /// Go: "StringExpanded is like [Addr.String] but IPv6 addresses are
    /// expanded with leading zeroes and no "::" compression."
    pub fn StringExpanded(&self) -> string {
        if self.z == Z::Z0 || self.z == Z::Z4 {
            return self.String();
        }
        let mut ret: Vec<u8> = Vec::new();
        let mut i: u8 = 0;
        while i < 8 {
            if i > 0 {
                ret.push(b':');
            }
            appendHexPad(&mut ret, self.v6u16(i));
            i += 1;
        }
        if self.hasZone() {
            ret.push(b'%');
            ret.extend_from_slice(self.Zone().as_bytes());
        }
        return string::__from_vec(ret);
    }

    // go: sdk 1.25.5 net/netip/netip.go:973-975 Addr.AppendText
    pub fn AppendText(&self, b: slice<byte>) -> (slice<byte>, error) {
        return (self.AppendTo(b), nil);
    }

    // go: sdk 1.25.5 net/netip/netip.go:980-1001 Addr.MarshalText
    /// Go: "MarshalText implements the [encoding.TextMarshaler]
    /// interface. … the zero [Addr] marshals to the empty string."
    pub fn MarshalText(&self) -> (slice<byte>, error) {
        if self.z == Z::Z0 {
            return (slice::new(), nil);
        }
        return (self.AppendTo(slice::new()), nil);
    }

    // go: sdk 1.25.5 net/netip/netip.go:1004-1012 Addr.UnmarshalText
    /// Go: "UnmarshalText implements the [encoding.TextUnmarshaler]
    /// interface. … an empty string input unmarshals as the zero
    /// [Addr]."
    pub fn UnmarshalText(&mut self, text: slice<byte>) -> error {
        if text.Len() == 0 {
            *self = Addr::default();
            return nil;
        }
        let (ip, err) = ParseAddr(string::from_bytes(&text.clone().__into_vec()));
        if err != nil {
            return err;
        }
        *self = ip;
        return nil;
    }

    // go: sdk 1.25.5 net/netip/netip.go:1028-1040 Addr.marshalBinarySize
    fn marshalBinarySize(&self) -> usize {
        if self.z == Z::Z0 {
            return 0;
        }
        if self.z == Z::Z4 {
            return 4;
        }
        return 16 + self.Zone().as_bytes().len();
    }

    // go: sdk 1.25.5 net/netip/netip.go:1015-1025 Addr.AppendBinary
    /// Go: the binary form is 0, 4 or 16 bytes, with any zone appended
    /// raw after the 16 — so a zoned address is LONGER than 16 and a
    /// reader must take the tail as the zone.
    pub fn AppendBinary(&self, b: slice<byte>) -> (slice<byte>, error) {
        let mut out = b.clone().__into_vec();
        match self.z {
            Z::Z0 => {}
            Z::Z4 => out.extend_from_slice(&self.As4()),
            _ => {
                out.extend_from_slice(&self.As16());
                out.extend_from_slice(self.Zone().as_bytes());
            }
        }
        return (slice::__from_vec(out), nil);
    }

    // go: sdk 1.25.5 net/netip/netip.go:1043-1046 Addr.MarshalBinary
    pub fn MarshalBinary(&self) -> (slice<byte>, error) {
        let _ = self.marshalBinarySize();
        return self.AppendBinary(slice::new());
    }

    // go: sdk 1.25.5 net/netip/netip.go:1049-1066 Addr.UnmarshalBinary
    pub fn UnmarshalBinary(&mut self, b: slice<byte>) -> error {
        let v = b.clone().__into_vec();
        let n = v.len();
        if n == 0 {
            *self = Addr::default();
            return nil;
        }
        if n == 4 {
            let mut a = [0u8; 4];
            a.copy_from_slice(&v);
            *self = AddrFrom4(a);
            return nil;
        }
        if n >= 16 {
            let mut a = [0u8; 16];
            a.copy_from_slice(&v[..16]);
            *self = AddrFrom16(a).WithZone(string::from_bytes(&v[16..]));
            return nil;
        }
        return errors::New(
            string::from_static("unexpected slice size: ") + crate::strconv::Itoa(int64(n)),
        );
    }
}

// go: sdk 1.25.5 net/netip/netip.go:821-833 appendDecimal
fn appendDecimal(b: &mut Vec<u8>, x: u8) {
    // Go: "Using this function rather than strconv.AppendUint makes
    // Addr.AppendTo about 8% faster."
    if x >= 100 {
        b.push(b'0' + x / 100);
    }
    if x >= 10 {
        b.push(b'0' + (x / 10) % 10);
    }
    b.push(b'0' + x % 10);
}

// go: sdk 1.25.5 net/netip/netip.go:835-850 appendHex
fn appendHex(b: &mut Vec<u8>, x: u16) {
    // Go: "Using this function rather than strconv.AppendUint makes
    // Addr.AppendTo about 12% faster."
    if x >= 0x1000 {
        b.push(hexDigit(x >> 12));
    }
    if x >= 0x100 {
        b.push(hexDigit((x >> 8) & 0xf));
    }
    if x >= 0x10 {
        b.push(hexDigit((x >> 4) & 0xf));
    }
    b.push(hexDigit(x & 0xf));
}

// go: sdk 1.25.5 net/netip/netip.go:852-854 appendHexPad
fn appendHexPad(b: &mut Vec<u8>, x: u16) {
    b.push(hexDigit(x >> 12));
    b.push(hexDigit((x >> 8) & 0xf));
    b.push(hexDigit((x >> 4) & 0xf));
    b.push(hexDigit(x & 0xf));
}

// go: sdk 1.25.5 net/netip/netip.go:818-818 digits
/// Go: `const digits = "0123456789abcdef"`.
const digits: &[u8; 16] = b"0123456789abcdef";

// go: none — goish idiom: Go writes `digits[x>>12]` inline at each of
//     the four sites above; goish spells the index once so the `&0xf`
//     mask lives in one place.
fn hexDigit(n: u16) -> u8 {
    return digits[usize::from(n & 0xf)];
}

// ─── AddrPort (netip.go:1069) ───────────────────────────────────────

// go: sdk 1.25.5 net/netip/netip.go:1069-1073 AddrPort
/// Go: "An AddrPort is an IP and a port number."
#[derive(Clone, PartialEq, Eq, Default)]
pub struct AddrPort {
    ip: Addr,
    port: u16,
}

// go: sdk 1.25.5 net/netip/netip.go:1076-1076 AddrPortFrom
pub fn AddrPortFrom(ip: Addr, port: u16) -> AddrPort {
    return AddrPort { ip, port };
}

impl AddrPort {
    // go: sdk 1.25.5 net/netip/netip.go:1079-1079 AddrPort.Addr
    pub fn Addr(&self) -> Addr {
        return self.ip.clone();
    }

    // go: sdk 1.25.5 net/netip/netip.go:1082-1082 AddrPort.Port
    pub fn Port(&self) -> u16 {
        return self.port;
    }

    // go: sdk 1.25.5 net/netip/netip.go:1152-1152 AddrPort.IsValid
    pub fn IsValid(&self) -> bool {
        return self.ip.IsValid();
    }

    // go: sdk 1.25.5 net/netip/netip.go:1157-1162 AddrPort.Compare
    pub fn Compare(&self, p2: &AddrPort) -> int {
        let c = self.ip.Compare(&p2.ip);
        if c != 0 {
            return c;
        }
        if self.port < p2.port {
            return -1;
        }
        if self.port > p2.port {
            return 1;
        }
        return 0;
    }

    // go: sdk 1.25.5 net/netip/netip.go:1164-1192 AddrPort.String
    /// Go: an IPv6 address is bracketed and an IPv4 one is not, which is
    /// the whole reason `ParseAddrPort` can refuse "::1:80".
    pub fn String(&self) -> string {
        if self.ip.z == Z::Z0 {
            return string::from_static("invalid AddrPort");
        }
        if self.ip.z == Z::Z4 {
            return self.ip.String()
                + string::from_static(":")
                + crate::strconv::Itoa(int64(self.port));
        }
        return string::from_static("[")
            + self.ip.String()
            + string::from_static("]:")
            + crate::strconv::Itoa(int64(self.port));
    }

    // go: sdk 1.25.5 net/netip/netip.go:1195-1214 AddrPort.AppendTo
    pub fn AppendTo(&self, b: slice<byte>) -> slice<byte> {
        let mut out = b.clone().__into_vec();
        out.extend_from_slice(self.String().as_bytes());
        return slice::__from_vec(out);
    }
}

// go: sdk 1.25.5 net/netip/netip.go:1089-1114 splitAddrPort
/// Go: "splitAddrPort splits s into an IP address string and a port
/// string. It splits strings shaped like "foo:bar" or "[foo]:bar",
/// without further validating the substrings."
fn splitAddrPort(s: string) -> (string, string, bool, error) {
    let mut v6 = false;
    let b = s.as_bytes();
    // Go: i := stringslite.LastIndexByte(s, ':')
    let i = match b.iter().rposition(|&c| c == b':') {
        Some(i) => i,
        None => {
            return (
                string::new(),
                string::new(),
                false,
                errors::New("not an ip:port"),
            )
        }
    };
    let mut ip = string::from_bytes(&b[..i]);
    let port = string::from_bytes(&b[i + 1..]);
    if ip.Len() == 0 {
        return (string::new(), string::new(), false, errors::New("no IP"));
    }
    if port.Len() == 0 {
        return (string::new(), string::new(), false, errors::New("no port"));
    }
    let ipb = ip.as_bytes().to_vec();
    if ipb[0] == b'[' {
        if ipb.len() == 1 || ipb[ipb.len() - 1] != b']' {
            return (
                string::new(),
                string::new(),
                false,
                errors::New("missing ]"),
            );
        }
        ip = string::from_bytes(&ipb[1..ipb.len() - 1]);
        v6 = true;
    }
    return (ip, port, v6, nil);
}

// go: sdk 1.25.5 net/netip/netip.go:1117-1139 ParseAddrPort
/// Go: "ParseAddrPort parses s as an [AddrPort]. It doesn't do any
/// name resolution: both the address and the port must be numeric."
pub fn ParseAddrPort<S: Into<string>>(s: S) -> (AddrPort, error) {
    let s: string = s.into();
    let mut ipp = AddrPort::default();
    let (ip, port, v6, err) = splitAddrPort(s.clone());
    if err != nil {
        return (AddrPort::default(), err);
    }
    // Go: port16, err := strconv.ParseUint(port, 10, 16)
    let (port16, perr2) = crate::strconv::ParseUint(port.clone(), 10, 16);
    if perr2 != nil {
        return (
            AddrPort::default(),
            errors::New(
                string::from_static("invalid port ")
                    + fmt::Sprintf!("%q", port)
                    + string::from_static(" parsing ")
                    + fmt::Sprintf!("%q", s),
            ),
        );
    }
    ipp.port = port16 as u16; // goishlint:ignore GOISH005 - ParseUint was given bitSize 16, so this cannot truncate.
    let (addr, aerr) = ParseAddr(ip);
    if aerr != nil {
        return (AddrPort::default(), aerr);
    }
    if v6 && addr.Is4() {
        return (
            AddrPort::default(),
            errors::New(
                string::from_static("invalid ip:port ")
                    + fmt::Sprintf!("%q", s)
                    + string::from_static(", square brackets can only be used with IPv6 addresses"),
            ),
        );
    } else if !v6 && addr.Is6() {
        return (
            AddrPort::default(),
            errors::New(
                string::from_static("invalid ip:port ")
                    + fmt::Sprintf!("%q", s)
                    + string::from_static(", IPv6 addresses must be surrounded by square brackets"),
            ),
        );
    }
    ipp.ip = addr;
    return (ipp, nil);
}

// go: sdk 1.25.5 net/netip/netip.go:1142-1148 MustParseAddrPort
pub fn MustParseAddrPort<S: Into<string>>(s: S) -> AddrPort {
    let (ip, err) = ParseAddrPort(s);
    if err != nil {
        panic!("{}", err.Error());
    }
    return ip;
}

// ─── Prefix (netip.go:1288) ─────────────────────────────────────────

// go: sdk 1.25.5 net/netip/netip.go:1288-1301 Prefix
/// Go: "Prefix is an IP address prefix (CIDR) representing an IP
/// network."
///
/// Go stores `bitsPlusOne` so the zero Prefix is invalid rather than
/// being a valid /0 — the same trick as `Addr.z`.
#[derive(Clone, PartialEq, Eq, Default)]
pub struct Prefix {
    ip: Addr,
    bitsPlusOne: u8,
}

// go: sdk 1.25.5 net/netip/netip.go:1304-1313 PrefixFrom
/// Go: "PrefixFrom returns a [Prefix] with the provided IP address and
/// bit prefix length. … If bits is less than zero or greater than
/// ip.BitLen(), [Prefix.Bits] of the returned value is -1."
pub fn PrefixFrom(ip: Addr, bits: int) -> Prefix {
    if bits < 0 || bits > ip.BitLen() {
        return Prefix::default();
    }
    return Prefix {
        // Go: "normalize the zone" — a prefix carries no zone.
        ip: ip.withoutZone(),
        bitsPlusOne: (bits + 1) as u8, // goishlint:ignore GOISH005 - bits is 0..=128 here, checked above.
    };
}

impl Prefix {
    // go: sdk 1.25.5 net/netip/netip.go:1316-1316 Prefix.Addr
    pub fn Addr(&self) -> Addr {
        return self.ip.clone();
    }

    // go: sdk 1.25.5 net/netip/netip.go:1321-1321 Prefix.Bits
    /// Go: "Bits returns p's prefix length. It reports -1 if invalid."
    pub fn Bits(&self) -> int {
        return int64(self.bitsPlusOne) - 1;
    }

    // go: sdk 1.25.5 net/netip/netip.go:1326-1326 Prefix.IsValid
    pub fn IsValid(&self) -> bool {
        return self.bitsPlusOne > 0;
    }

    // go: sdk 1.25.5 net/netip/netip.go:1328-1328 Prefix.isZero
    #[allow(dead_code)]
    fn isZero(&self) -> bool {
        return *self == Prefix::default();
    }

    // go: sdk 1.25.5 net/netip/netip.go:1331-1331 Prefix.IsSingleIP
    /// Go: "IsSingleIP reports whether p contains exactly one IP."
    pub fn IsSingleIP(&self) -> bool {
        return self.IsValid() && self.Bits() == self.ip.BitLen();
    }

    // go: sdk 1.25.5 net/netip/netip.go:1341-1348 Prefix.compare
    /// Go exports this through `slices.SortFunc` call sites elsewhere in
    /// the package; ported because Go declares it.
    #[allow(dead_code)]
    fn compare(&self, p2: &Prefix) -> int {
        let c = self.Addr().Compare(&p2.Addr());
        if c != 0 {
            return c;
        }
        if self.Bits() < p2.Bits() {
            return -1;
        }
        if self.Bits() > p2.Bits() {
            return 1;
        }
        return 0;
    }

    // go: sdk 1.25.5 net/netip/netip.go:1416-1425 Prefix.Masked
    /// Go: "Masked returns p in its canonical form, with all but the
    /// high p.Bits() bits of p.Addr() masked off."
    pub fn Masked(&self) -> Prefix {
        let (m, _) = self.ip.Prefix(self.Bits());
        return m;
    }

    // go: sdk 1.25.5 net/netip/netip.go:1428-1455 Prefix.Contains
    /// Go: "Contains reports whether the network includes ip." Note an
    /// IPv4 prefix does NOT contain an IPv4-mapped IPv6 address, and
    /// vice versa — "an address with a zone is never contained".
    pub fn Contains(&self, ip: &Addr) -> bool {
        if !self.IsValid() || ip.hasZone() {
            return false;
        }
        if self.ip.Is4() != ip.Is4() {
            return false;
        }
        if self.ip.Is4() {
            // Go: the fast path for IPv4.
            let bits = self.Bits();
            if bits == 32 {
                return self.ip == *ip;
            }
            let x = self.ip.addr.lo as u32; // goishlint:ignore GOISH005 - the low 32 bits ARE the IPv4 address.
            let y = ip.addr.lo as u32; // goishlint:ignore GOISH005 - as above.
            let b = 32 - bits;
            if b == 32 {
                return true;
            }
            return (x >> b) == (y >> b);
        }
        let m = mask6(self.Bits());
        return self.ip.addr.and(m) == ip.addr.and(m);
    }

    // go: sdk 1.25.5 net/netip/netip.go:1458-1491 Prefix.Overlaps
    /// Go: "Overlaps reports whether p and o contain any IP addresses in
    /// common."
    pub fn Overlaps(&self, o: &Prefix) -> bool {
        if !self.IsValid() || !o.IsValid() {
            return false;
        }
        let mut p = self.clone();
        let mut o = o.clone();
        if p.Addr().Is4() != o.Addr().Is4() {
            return false;
        }
        // Go: "One of the prefixes contains the other."
        if p.Bits() > o.Bits() {
            core::mem::swap(&mut p, &mut o);
        }
        if p.Bits() == o.Bits() {
            return p.Masked() == o.Masked();
        }
        return p.Contains(&o.Addr());
    }

    // go: sdk 1.25.5 net/netip/netip.go:1494-1518 Prefix.AppendTo
    pub fn AppendTo(&self, b: slice<byte>) -> slice<byte> {
        let mut out = b.clone().__into_vec();
        out.extend_from_slice(self.String().as_bytes());
        return slice::__from_vec(out);
    }

    // go: sdk 1.25.5 net/netip/netip.go:1590-1595 Prefix.String
    /// Go: "String returns the CIDR notation of p … If p is the zero
    /// value, it returns "invalid Prefix"."
    pub fn String(&self) -> string {
        if !self.IsValid() {
            return string::from_static("invalid Prefix");
        }
        return self.ip.String() + string::from_static("/") + crate::strconv::Itoa(self.Bits());
    }
}

// go: sdk 1.25.5 net/netip/netip.go:1351-1354 parsePrefixError
pub struct parsePrefixError {
    pub(crate) in_: string,
    pub(crate) msg: string,
}

impl ErrorTrait for parsePrefixError {
    // go: sdk 1.25.5 net/netip/netip.go:1356-1358 parsePrefixError.Error
    fn Error(&self) -> string {
        return string::from_static("netip.ParsePrefix(")
            + fmt::Sprintf!("%q", self.in_.clone())
            + string::from_static("): ")
            + self.msg.clone();
    }
}

// go: none — goish idiom: as `perr`, for the prefix parser.
fn pperr(in_: &string, msg: string) -> error {
    return errors::Wrap(parsePrefixError {
        in_: in_.clone(),
        msg,
    });
}

// go: sdk 1.25.5 net/netip/netip.go:1367-1401 ParsePrefix
/// Go: "ParsePrefix parses s as an IP address prefix. … Note that masked
/// address bits are not zeroed. Use Masked for that."
pub fn ParsePrefix<S: Into<string>>(s: S) -> (Prefix, error) {
    let s: string = s.into();
    let b = s.as_bytes();
    let i = match b.iter().rposition(|&c| c == b'/') {
        Some(i) => i,
        None => return (Prefix::default(), pperr(&s, string::from_static("no '/'"))),
    };
    let (ip, err) = ParseAddr(string::from_bytes(&b[..i]));
    if err != nil {
        // Go: "error is not wrapped, the ParseAddr error is returned"
        return (Prefix::default(), err);
    }
    // Go: "IPv6 zones are not allowed in prefixes."
    if ip.hasZone() {
        return (
            Prefix::default(),
            pperr(
                &s,
                string::from_static("IPv6 zones cannot be present in a prefix"),
            ),
        );
    }
    let bitsStr = string::from_bytes(&b[i + 1..]);
    // Go: bits, err := strconv.Atoi(bitsStr); if err != nil || bits < 0 …
    let (bits, aerr) = crate::strconv::Atoi(bitsStr.clone());
    if aerr != nil || bits < 0 {
        return (
            Prefix::default(),
            pperr(
                &s,
                string::from_static("bad bits after slash: ") + fmt::Sprintf!("%q", bitsStr),
            ),
        );
    }
    if bits > ip.BitLen() {
        return (
            Prefix::default(),
            pperr(&s, string::from_static("prefix length out of range")),
        );
    }
    return (PrefixFrom(ip, bits), nil);
}

// go: sdk 1.25.5 net/netip/netip.go:1404-1410 MustParsePrefix
pub fn MustParsePrefix<S: Into<string>>(s: S) -> Prefix {
    let (p, err) = ParsePrefix(s);
    if err != nil {
        panic!("{}", err.Error());
    }
    return p;
}

// go: none — goish idiom: `strings` is imported for the parser's
//     scanning helpers in Go; goish's parser works on bytes directly,
//     so the import is kept only where it is used.
#[allow(unused_imports)]
use strings as _unused_strings;
