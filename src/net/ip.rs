// go: file net/ip.go decls: IPv4, IPv4Mask, CIDRMask, IP.IsUnspecified, IP.IsLoopback, IP.IsPrivate, IP.IsMulticast, IP.IsInterfaceLocalMulticast, IP.IsLinkLocalMulticast, IP.IsLinkLocalUnicast, IP.IsGlobalUnicast, isZeros, IP.To4, IP.To16, IP.DefaultMask, allFF, IP.Mask, IP.String, hexString, ipEmptyString, IP.appendTo, IP.AppendText, IP.MarshalText, IP.UnmarshalText, IP.Equal, IP.matchAddrFamily, simpleMaskLength, IPMask.Size, IPMask.String, networkNumberAndMask, IPNet.Contains, IPNet.Network, IPNet.String, ParseIP, parseIP, ParseCIDR, copyIP, IP.IsNil, IPMask.IsNil, IPv4bcast, IPv4allsys,
// go: file net/ip.go decls: IPv4allrouter, IPv4zero, IPv6zero, IPv6unspecified, IPv6loopback,
// go: file net/ip.go decls: IPv6interfacelocalallnodes, IPv6linklocalallnodes,
// go: file net/ip.go decls: IPv6linklocalallrouters, classAMask, classBMask, classCMask
//
// net/ip.go — IP address manipulation. Go's own implementation
// delegates parsing to `net/netip` (`parseIP` calls `netip.ParseAddr`)
// and formatting to `netip.Addr.AppendTo`; this port does the same,
// against goish's `net::netip`, so the two packages cannot drift.
//
//   Go                                   goish
//   ──────────────────────────────────   ──────────────────────────────────
//   net.IPv4(192, 0, 2, 1)               IPv4(192, 0, 2, 1)            -> IP
//   net.ParseIP("::1")                   ParseIP(string("::1"))        -> IP
//   ip == nil                            ip.IsNil()
//   len(ip)                              ip.bytes.Len()
//   ip[i]                                ip.bytes[i]

#![allow(non_snake_case)]

extern crate alloc;

use alloc::vec::Vec;

use crate::error;
use crate::errors;
use crate::goslice::slice;
use crate::gostring::string;
use crate::net::mac::HEX_DIGIT;
use crate::net::net::{AddrError, ParseError};
use crate::net::netip;
use crate::{byte, int};

// go: sdk 1.25.5 net/ip.go:23-36 IPv4len
/// Go: "IP address lengths (bytes)." goish spells each member of the
/// Go `const` block as its own `pub const`; same names, same values.
pub const IPv4len: int = 4;
// go: sdk 1.25.5 net/ip.go:23-36 IPv6len
/// Go: "IP address lengths (bytes)." Second half of the same block.
pub const IPv6len: int = 16;

// go: sdk 1.25.5 net/ip.go:37-42 IP
/// Go: "An IP is a single IP address, a slice of bytes. Functions in
/// this package accept either 4-byte (IPv4) or 16-byte (IPv6) slices
/// as input. […] a 4-byte address and the same address in 16-byte
/// form […] denote the same IP address."
///
/// Go's `type IP []byte` is a named slice; goish wraps the backing
/// `slice<byte>` in a struct so it can carry methods. Length 0 is the
/// `nil` sentinel — test it with [`IP::IsNil`].
#[derive(Clone, Default)]
pub struct IP {
    /// The address bytes: 4 (IPv4), 16 (IPv6), or 0 (nil).
    pub bytes: slice<byte>,
}

// go: sdk 1.25.5 net/ip.go:43-45 IPMask
/// Go: "An IPMask is a bitmask that can be used to manipulate IP
/// addresses for IP addressing and routing. See type [IPNet] and
/// func [ParseCIDR] for details."
#[derive(Clone, Default)]
pub struct IPMask {
    /// The mask bytes: 4 (IPv4), 16 (IPv6), or 0 (nil).
    pub bytes: slice<byte>,
}

// go: sdk 1.25.5 net/ip.go:46-52 IPNet
/// Go: "An IPNet represents an IP network."
#[derive(Clone, Default)]
pub struct IPNet {
    /// Go: "network number".
    pub IP: IP,
    /// Go: "network mask".
    pub Mask: IPMask,
}

impl IP {
    // go: none — goish idiom: `IP` is a Go slice, so `nil` is its zero
    // value. goish spells the `ip == nil` test as a method rather than
    // leaking `Option` into every signature that returns an address.
    /// True when this is the zero value — Go's `ip == nil`.
    pub fn IsNil(&self) -> bool {
        return self.bytes.Len() == 0;
    }
}

impl IPMask {
    // go: none — goish idiom: see `IP::IsNil`.
    /// True when this is the zero value — Go's `m == nil`.
    pub fn IsNil(&self) -> bool {
        return self.bytes.Len() == 0;
    }
}

// go: none — goish idiom: the ports below work on plain `&[byte]`
// scratch (the module's stated discipline: convert at the boundary),
// so this is the one place that rebuilds a `slice<byte>`.
fn ip_of(b: &[byte]) -> IP {
    return IP {
        bytes: slice::<byte>::__from_vec(b.to_vec()),
    };
}

// go: none — goish idiom: `IPMask` counterpart of `ip_of`.
fn mask_of(b: &[byte]) -> IPMask {
    return IPMask {
        bytes: slice::<byte>::__from_vec(b.to_vec()),
    };
}

// go: sdk 1.25.5 net/ip.go:53-61 IPv4
/// Go: "IPv4 returns the IP address (in 16-byte form) of the IPv4
/// address a.b.c.d."
pub fn IPv4(a: byte, b: byte, c: byte, d: byte) -> IP {
    // Go: p := make(IP, IPv6len); copy(p, v4InV6Prefix)
    let mut p: Vec<byte> = V4_IN_V6_PREFIX.to_vec();
    p.push(a);
    p.push(b);
    p.push(c);
    p.push(d);
    return IP {
        bytes: slice::<byte>::__from_vec(p),
    };
}

// go: sdk 1.25.5 net/ip.go:63-63 v4InV6Prefix
/// Go: `var v4InV6Prefix = []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff}`.
const V4_IN_V6_PREFIX: [byte; 12] = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff];

// go: sdk 1.25.5 net/ip.go:67-78 IPv4Mask
/// Go: "IPv4Mask returns the IP mask (in 4-byte form) of the IPv4 mask
/// a.b.c.d."
pub fn IPv4Mask(a: byte, b: byte, c: byte, d: byte) -> IPMask {
    // Go: p := make(IPMask, IPv4len)
    return mask_of(&[a, b, c, d]);
}

// go: sdk 1.25.5 net/ip.go:79-101 CIDRMask
/// Go: "CIDRMask returns an [IPMask] consisting of 'ones' 1 bits
/// followed by 0s up to a total length of 'bits' bits. For a mask of
/// this form, CIDRMask is the inverse of [IPMask.Size]."
pub fn CIDRMask(ones: int, bits: int) -> IPMask {
    // Go: if bits != 8*IPv4len && bits != 8*IPv6len { return nil }
    if bits != 8 * IPv4len && bits != 8 * IPv6len {
        return IPMask::default();
    }
    // Go: if ones < 0 || ones > bits { return nil }
    if ones < 0 || ones > bits {
        return IPMask::default();
    }
    // Go: l := bits / 8; m := make(IPMask, l)
    let l = int(bits / 8);
    let mut m: Vec<byte> = alloc::vec![0u8; l as usize];
    let mut n = ones;
    for i in 0..(l as usize) {
        // Go: if n >= 8 { m[i] = 0xff; n -= 8; continue }
        if n >= 8 {
            m[i] = 0xff;
            n -= 8;
            continue;
        }
        // Go: m[i] = ^byte(0xff >> n); n = 0
        m[i] = !(0xff_u8 >> n);
        n = 0;
    }
    return mask_of(&m);
}

impl IP {
    // go: sdk 1.25.5 net/ip.go:121-125 IP.IsUnspecified
    /// Go: "IsUnspecified reports whether ip is an unspecified
    /// address, either the IPv4 address "0.0.0.0" or the IPv6 address
    /// "::"."
    pub fn IsUnspecified(&self) -> bool {
        // Go: return ip.Equal(IPv4zero) || ip.Equal(IPv6unspecified)
        return self.Equal(&IPv4zero()) || self.Equal(&IPv6unspecified());
    }

    // go: sdk 1.25.5 net/ip.go:126-134 IP.IsLoopback
    /// Go: "IsLoopback reports whether ip is a loopback address."
    pub fn IsLoopback(&self) -> bool {
        // Go: if ip4 := ip.To4(); ip4 != nil { return ip4[0] == 127 }
        let ip4 = self.To4();
        if !ip4.IsNil() {
            return ip4.bytes[0] == 127;
        }
        // Go: return ip.Equal(IPv6loopback)
        return self.Equal(&IPv6loopback());
    }

    // go: sdk 1.25.5 net/ip.go:135-152 IP.IsPrivate
    /// Go: "IsPrivate reports whether ip is a private address,
    /// according to RFC 1918 (IPv4 addresses) and RFC 4193 (IPv6
    /// addresses)."
    pub fn IsPrivate(&self) -> bool {
        let ip4 = self.To4();
        if !ip4.IsNil() {
            // Go: "Following RFC 1918, Section 3. Private Address Space
            // which says: 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16"
            return ip4.bytes[0] == 10
                || (ip4.bytes[0] == 172 && (ip4.bytes[1] & 0xf0) == 16)
                || (ip4.bytes[0] == 192 && ip4.bytes[1] == 168);
        }
        // Go: "Following RFC 4193, Section 8. IANA Considerations which
        // says: fc00::/7"
        return self.bytes.Len() == IPv6len && (self.bytes[0] & 0xfe) == 0xfc;
    }

    // go: sdk 1.25.5 net/ip.go:153-161 IP.IsMulticast
    /// Go: "IsMulticast reports whether ip is a multicast address."
    pub fn IsMulticast(&self) -> bool {
        // Go: if ip4 := ip.To4(); ip4 != nil { return ip4[0]&0xf0 == 0xe0 }
        let ip4 = self.To4();
        if !ip4.IsNil() {
            return (ip4.bytes[0] & 0xf0) == 0xe0;
        }
        // Go: return len(ip) == IPv6len && ip[0] == 0xff
        return self.bytes.Len() == IPv6len && self.bytes[0] == 0xff;
    }

    // go: sdk 1.25.5 net/ip.go:162-167 IP.IsInterfaceLocalMulticast
    /// Go: "IsInterfaceLocalMulticast reports whether ip is an
    /// interface-local multicast address."
    pub fn IsInterfaceLocalMulticast(&self) -> bool {
        // Go: return len(ip) == IPv6len && ip[0] == 0xff && ip[1]&0x0f == 0x01
        return self.bytes.Len() == IPv6len
            && self.bytes[0] == 0xff
            && (self.bytes[1] & 0x0f) == 0x01;
    }

    // go: sdk 1.25.5 net/ip.go:168-176 IP.IsLinkLocalMulticast
    /// Go: "IsLinkLocalMulticast reports whether ip is a link-local
    /// multicast address."
    pub fn IsLinkLocalMulticast(&self) -> bool {
        // Go: if ip4 := ip.To4(); ip4 != nil {
        //         return ip4[0] == 224 && ip4[1] == 0 && ip4[2] == 0 }
        let ip4 = self.To4();
        if !ip4.IsNil() {
            return ip4.bytes[0] == 224 && ip4.bytes[1] == 0 && ip4.bytes[2] == 0;
        }
        // Go: return len(ip) == IPv6len && ip[0] == 0xff && ip[1]&0x0f == 0x02
        return self.bytes.Len() == IPv6len
            && self.bytes[0] == 0xff
            && (self.bytes[1] & 0x0f) == 0x02;
    }

    // go: sdk 1.25.5 net/ip.go:177-191 IP.IsLinkLocalUnicast
    /// Go: "IsLinkLocalUnicast reports whether ip is a link-local
    /// unicast address."
    pub fn IsLinkLocalUnicast(&self) -> bool {
        // Go: if ip4 := ip.To4(); ip4 != nil {
        //         return ip4[0] == 169 && ip4[1] == 254 }
        let ip4 = self.To4();
        if !ip4.IsNil() {
            return ip4.bytes[0] == 169 && ip4.bytes[1] == 254;
        }
        // Go: return len(ip) == IPv6len && ip[0] == 0xfe && ip[1]&0xc0 == 0x80
        return self.bytes.Len() == IPv6len
            && self.bytes[0] == 0xfe
            && (self.bytes[1] & 0xc0) == 0x80;
    }

    // go: sdk 1.25.5 net/ip.go:192-201 IP.IsGlobalUnicast
    /// Go: "IsGlobalUnicast reports whether ip is a global unicast
    /// address. […] the identification of global unicast addresses uses
    /// address type identification as defined in RFC 1122, RFC 4632 and
    /// RFC 4291 with the exception of IPv4 directed broadcast addresses."
    pub fn IsGlobalUnicast(&self) -> bool {
        // Go: return (len(ip) == IPv4len || len(ip) == IPv6len) &&
        //            !ip.Equal(IPv4bcast) && !ip.IsUnspecified() &&
        //            !ip.IsLoopback() && !ip.IsMulticast() &&
        //            !ip.IsLinkLocalUnicast()
        return (self.bytes.Len() == IPv4len || self.bytes.Len() == IPv6len)
            && !self.Equal(&IPv4bcast())
            && !self.IsUnspecified()
            && !self.IsLoopback()
            && !self.IsMulticast()
            && !self.IsLinkLocalUnicast();
    }

    // go: sdk 1.25.5 net/ip.go:213-227 IP.To4
    /// Go: "To4 converts the IPv4 address ip to a 4-byte
    /// representation. If ip is not an IPv4 address, To4 returns nil."
    pub fn To4(&self) -> IP {
        let p: &[byte] = &self.bytes;
        // Go: if len(ip) == IPv4len { return ip }
        if p.len() == IPv4len as usize {
            return self.clone();
        }
        // Go: if len(ip) == IPv6len && isZeros(ip[0:10]) &&
        //        ip[10] == 0xff && ip[11] == 0xff { return ip[12:16] }
        if p.len() == IPv6len as usize && isZeros(&p[0..10]) && p[10] == 0xff && p[11] == 0xff {
            return ip_of(&p[12..16]);
        }
        return IP::default();
    }

    // go: sdk 1.25.5 net/ip.go:228-238 IP.To16
    /// Go: "To16 converts the IP address ip to a 16-byte
    /// representation. If ip is not an IP address (it is the wrong
    /// length), To16 returns nil."
    pub fn To16(&self) -> IP {
        let p: &[byte] = &self.bytes;
        // Go: if len(ip) == IPv4len { return IPv4(ip[0], ip[1], ip[2], ip[3]) }
        if p.len() == IPv4len as usize {
            return IPv4(p[0], p[1], p[2], p[3]);
        }
        // Go: if len(ip) == IPv6len { return ip }
        if p.len() == IPv6len as usize {
            return self.clone();
        }
        return IP::default();
    }

    // go: sdk 1.25.5 net/ip.go:248-260 IP.DefaultMask
    /// Go: "DefaultMask returns the default IP mask for the IP address
    /// ip. Only IPv4 addresses have default masks; DefaultMask returns
    /// nil if ip is not a valid IPv4 address."
    pub fn DefaultMask(&self) -> IPMask {
        // Go: if ip = ip.To4(); ip == nil { return nil }
        let ip = self.To4();
        if ip.IsNil() {
            return IPMask::default();
        }
        // Go: switch { case ip[0] < 0x80: classA; case ip[0] < 0xC0: classB;
        //              default: classC }
        if ip.bytes[0] < 0x80 {
            return classAMask();
        }
        if ip.bytes[0] < 0xC0 {
            return classBMask();
        }
        return classCMask();
    }

    // go: sdk 1.25.5 net/ip.go:272-295 IP.Mask
    /// Go: "Mask returns the result of masking the IP address ip with
    /// mask."
    pub fn Mask(&self, mask: &IPMask) -> IP {
        let mut ip: &[byte] = &self.bytes;
        let mut m: &[byte] = &mask.bytes;
        // Go: if len(mask) == IPv6len && len(ip) == IPv4len && allFF(mask[:12]) {
        //         mask = mask[12:] }
        if m.len() == IPv6len as usize && ip.len() == IPv4len as usize && allFF(&m[..12]) {
            m = &m[12..];
        }
        // Go: if len(mask) == IPv4len && len(ip) == IPv6len &&
        //        bytealg.Equal(ip[:12], v4InV6Prefix) { ip = ip[12:] }
        if m.len() == IPv4len as usize
            && ip.len() == IPv6len as usize
            && ip[..12] == V4_IN_V6_PREFIX
        {
            ip = &ip[12..];
        }
        // Go: n := len(ip); if n != len(mask) { return nil }
        let n = ip.len();
        if n != m.len() {
            return IP::default();
        }
        // Go: out := make(IP, n); for i := range n { out[i] = ip[i] & mask[i] }
        let mut out: Vec<byte> = Vec::with_capacity(n);
        for i in 0..n {
            out.push(ip[i] & m[i]);
        }
        return ip_of(&out);
    }

    // go: sdk 1.25.5 net/ip.go:296-316 IP.String
    /// Go: "String returns the string form of the IP address ip. It
    /// returns one of 4 forms: "<nil>", if ip has length 0; dotted
    /// decimal ("192.0.2.1"), if ip is an IPv4 or IP4-mapped IPv6
    /// address; IPv6 conforming to RFC 5952 ("2001:db8::1"), if ip is
    /// a valid IPv6 address; the hexadecimal form of ip, without
    /// punctuation, if no other cases apply."
    pub fn String(&self) -> string {
        // Go: if len(ip) == 0 { return "<nil>" }
        if self.bytes.Len() == 0 {
            return string::from_static("<nil>");
        }
        // Go: if len(ip) != IPv4len && len(ip) != IPv6len {
        //         return "?" + hexString(ip) }
        if self.bytes.Len() != IPv4len && self.bytes.Len() != IPv6len {
            return string::from_static("?") + hexString(&self.bytes);
        }
        // Go: buf = make([]byte, 0, maxCap); buf = ip.appendTo(buf)
        let buf = slice::<byte>::__from_vec(Vec::with_capacity(39));
        let out = self.appendTo(buf);
        return string::from_bytes(&out);
    }

    // go: sdk 1.25.5 net/ip.go:337-348 IP.appendTo
    /// Go: "appendTo appends the string representation of ip to b and
    /// returns the expanded b. If len(ip) != IPv4len or IPv6len, it
    /// appends nothing."
    fn appendTo(&self, b: slice<byte>) -> slice<byte> {
        // Go: if p4 := ip.To4(); len(p4) == IPv4len { ip = p4 }
        let p4 = self.To4();
        let ip = if p4.bytes.Len() == IPv4len {
            p4
        } else {
            self.clone()
        };
        // Go: addr, _ := netip.AddrFromSlice(ip); return addr.AppendTo(b)
        let (addr, _) = netip::AddrFromSlice(ip.bytes.clone());
        return addr.AppendTo(b);
    }

    // go: sdk 1.25.5 net/ip.go:349-362 IP.AppendText
    /// Go: "AppendText implements the [encoding.TextAppender]
    /// interface. The encoding is the same as returned by [IP.String],
    /// with one exception: When len(ip) is zero, it appends nothing."
    pub fn AppendText(&self, b: slice<byte>) -> (slice<byte>, error) {
        // Go: if len(ip) == 0 { return b, nil }
        if self.bytes.Len() == 0 {
            return (b, errors::nil);
        }
        // Go: if len(ip) != IPv4len && len(ip) != IPv6len {
        //         return b, &AddrError{Err: "invalid IP address",
        //                              Addr: hexString(ip)} }
        if self.bytes.Len() != IPv4len && self.bytes.Len() != IPv6len {
            return (
                b,
                error::from(AddrError {
                    Err: string::from_static("invalid IP address"),
                    Addr: hexString(&self.bytes),
                }),
            );
        }
        // Go: return ip.appendTo(b), nil
        return (self.appendTo(b), errors::nil);
    }

    // go: sdk 1.25.5 net/ip.go:363-373 IP.MarshalText
    /// Go: "MarshalText implements the [encoding.TextMarshaler]
    /// interface. The encoding is the same as returned by [IP.String],
    /// with one exception: When len(ip) is zero, it returns an empty
    /// slice."
    pub fn MarshalText(&self) -> (slice<byte>, error) {
        // Go: b, err := ip.AppendText(make([]byte, 0, 24))
        let (b, err) = self.AppendText(slice::<byte>::__from_vec(Vec::with_capacity(24)));
        if !err.IsNil() {
            return (slice::<byte>::default(), err);
        }
        return (b, errors::nil);
    }

    // go: sdk 1.25.5 net/ip.go:374-390 IP.UnmarshalText
    /// Go: "UnmarshalText implements the [encoding.TextUnmarshaler]
    /// interface. The IP address is expected in a form accepted by
    /// [ParseIP]."
    pub fn UnmarshalText(&mut self, text: slice<byte>) -> error {
        // Go: if len(text) == 0 { *ip = nil; return nil }
        if text.Len() == 0 {
            *self = IP::default();
            return errors::nil;
        }
        // Go: s := string(text); x := ParseIP(s)
        let s = string::from_bytes(&text);
        let x = ParseIP(s.clone());
        // Go: if x == nil { return &ParseError{Type: "IP address", Text: s} }
        if x.IsNil() {
            return error::from(ParseError {
                Type: string::from_static("IP address"),
                Text: s,
            });
        }
        *self = x;
        return errors::nil;
    }

    // go: sdk 1.25.5 net/ip.go:391-402 IP.Equal
    /// Go: "Equal reports whether ip and x are the same IP address. An
    /// IPv4 address and that same address in IPv6 form are considered
    /// to be equal."
    pub fn Equal(&self, x: &IP) -> bool {
        let a: &[byte] = &self.bytes;
        let b: &[byte] = &x.bytes;
        // Go: if len(ip) == len(x) { return bytealg.Equal(ip, x) }
        if a.len() == b.len() {
            return a == b;
        }
        // Go: if len(ip) == IPv4len && len(x) == IPv6len {
        //         return bytealg.Equal(x[0:12], v4InV6Prefix) &&
        //                bytealg.Equal(ip, x[12:]) }
        if a.len() == IPv4len as usize && b.len() == IPv6len as usize {
            return b[0..12] == V4_IN_V6_PREFIX && a == &b[12..];
        }
        // Go: if len(ip) == IPv6len && len(x) == IPv4len {
        //         return bytealg.Equal(ip[0:12], v4InV6Prefix) &&
        //                bytealg.Equal(ip[12:], x) }
        if a.len() == IPv6len as usize && b.len() == IPv4len as usize {
            return a[0..12] == V4_IN_V6_PREFIX && &a[12..] == b;
        }
        return false;
    }

    // go: sdk 1.25.5 net/ip.go:404-409 IP.matchAddrFamily
    /// Go: unexported — true when `ip` and `x` are the same address
    /// family (both IPv4, or both non-v4-mapped IPv6).
    pub(crate) fn matchAddrFamily(&self, x: &IP) -> bool {
        // Go: return ip.To4() != nil && x.To4() != nil ||
        //            ip.To16() != nil && ip.To4() == nil &&
        //            x.To16() != nil && x.To4() == nil
        return !self.To4().IsNil() && !x.To4().IsNil()
            || !self.To16().IsNil() && self.To4().IsNil() && !x.To16().IsNil() && x.To4().IsNil();
    }
}

// go: sdk 1.25.5 net/ip.go:202-212 isZeros
/// Go: "Is p all zeros?"
fn isZeros(p: &[byte]) -> bool {
    for i in 0..p.len() {
        if p[i] != 0 {
            return false;
        }
    }
    return true;
}

// go: sdk 1.25.5 net/ip.go:262-271 allFF
/// Go: unexported — true when every byte of `b` is 0xff.
fn allFF(b: &[byte]) -> bool {
    for &c in b {
        if c != 0xff {
            return false;
        }
    }
    return true;
}

// go: sdk 1.25.5 net/ip.go:318-327 hexString
/// Go: unexported — the hexadecimal form of `b`, without punctuation.
fn hexString(b: &[byte]) -> string {
    // Go: s := make([]byte, len(b)*2)
    let mut s: Vec<byte> = Vec::with_capacity(b.len() * 2);
    for &tn in b {
        // Go: s[i*2], s[i*2+1] = hexDigit[tn>>4], hexDigit[tn&0xf]
        s.push(HEX_DIGIT[(tn >> 4) as usize]);
        s.push(HEX_DIGIT[(tn & 0xf) as usize]);
    }
    return string::from_bytes(&s);
}

// go: sdk 1.25.5 net/ip.go:328-336 ipEmptyString
/// Go: "ipEmptyString is like ip.String except that it returns an
/// empty string when ip is unset."
pub(crate) fn ipEmptyString(ip: &IP) -> string {
    // Go: if len(ip) == 0 { return "" }
    if ip.bytes.Len() == 0 {
        return string::default();
    }
    return ip.String();
}

// go: sdk 1.25.5 net/ip.go:102-109 IPv4bcast
/// Go: "Well-known IPv4 addresses." goish spells each member of the Go
/// `var` block as its own function: a `slice<byte>` is heap-backed, so
/// it cannot be a `const`, and a mutable global would let one caller
/// scribble on every other caller's copy.
pub fn IPv4bcast() -> IP {
    return IPv4(255, 255, 255, 255);
}
// go: sdk 1.25.5 net/ip.go:102-109 IPv4allsys
/// Go: "Well-known IPv4 addresses" — `IPv4allsys`.
pub fn IPv4allsys() -> IP {
    return IPv4(224, 0, 0, 1);
}
// go: sdk 1.25.5 net/ip.go:102-109 IPv4allrouter
/// Go: "Well-known IPv4 addresses" — `IPv4allrouter`.
pub fn IPv4allrouter() -> IP {
    return IPv4(224, 0, 0, 2);
}
// go: sdk 1.25.5 net/ip.go:102-109 IPv4zero
/// Go: "Well-known IPv4 addresses" — `IPv4zero`.
pub fn IPv4zero() -> IP {
    return IPv4(0, 0, 0, 0);
}

// go: sdk 1.25.5 net/ip.go:110-117 IPv6zero
/// Go: "Well-known IPv6 addresses." Same goish idiom as the IPv4 block
/// above: one function per member.
pub fn IPv6zero() -> IP {
    return ip_of(&[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
}
// go: sdk 1.25.5 net/ip.go:110-117 IPv6unspecified
/// Go: "Well-known IPv6 addresses" — `IPv6unspecified`.
pub fn IPv6unspecified() -> IP {
    return ip_of(&[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
}
// go: sdk 1.25.5 net/ip.go:110-117 IPv6loopback
/// Go: "Well-known IPv6 addresses" — `IPv6loopback`.
pub fn IPv6loopback() -> IP {
    return ip_of(&[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
}
// go: sdk 1.25.5 net/ip.go:110-117 IPv6interfacelocalallnodes
/// Go: "Well-known IPv6 addresses" — `IPv6interfacelocalallnodes`.
pub fn IPv6interfacelocalallnodes() -> IP {
    return ip_of(&[0xff, 0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01]);
}
// go: sdk 1.25.5 net/ip.go:110-117 IPv6linklocalallnodes
/// Go: "Well-known IPv6 addresses" — `IPv6linklocalallnodes`.
pub fn IPv6linklocalallnodes() -> IP {
    return ip_of(&[0xff, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01]);
}
// go: sdk 1.25.5 net/ip.go:110-117 IPv6linklocalallrouters
/// Go: "Well-known IPv6 addresses" — `IPv6linklocalallrouters`.
pub fn IPv6linklocalallrouters() -> IP {
    return ip_of(&[0xff, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x02]);
}

// go: sdk 1.25.5 net/ip.go:239-243 classAMask
/// Go: "Default route masks for IPv4." One function per member — see
/// the note on `IPv4bcast`.
fn classAMask() -> IPMask {
    return IPv4Mask(0xff, 0, 0, 0);
}
// go: sdk 1.25.5 net/ip.go:239-243 classBMask
/// Go: "Default route masks for IPv4" — `classBMask`.
fn classBMask() -> IPMask {
    return IPv4Mask(0xff, 0xff, 0, 0);
}
// go: sdk 1.25.5 net/ip.go:239-243 classCMask
/// Go: "Default route masks for IPv4" — `classCMask`.
fn classCMask() -> IPMask {
    return IPv4Mask(0xff, 0xff, 0xff, 0);
}

// go: sdk 1.25.5 net/ip.go:410-439 simpleMaskLength
/// Go: "If mask is a sequence of 1 bits followed by 0 bits, return the
/// number of 1 bits."
fn simpleMaskLength(mask: &[byte]) -> int {
    let mut n: int = 0;
    let mut i = 0usize;
    while i < mask.len() {
        let mut v = mask[i];
        // Go: if v == 0xff { n += 8; continue }
        if v == 0xff {
            n += 8;
            i += 1;
            continue;
        }
        // Go: "found non-ff byte; count 1 bits"
        while (v & 0x80) != 0 {
            n += 1;
            v <<= 1;
        }
        // Go: "rest must be 0 bits"
        if v != 0 {
            return -1;
        }
        i += 1;
        while i < mask.len() {
            if mask[i] != 0 {
                return -1;
            }
            i += 1;
        }
        break;
    }
    return n;
}

impl IPMask {
    // go: sdk 1.25.5 net/ip.go:440-448 IPMask.Size
    /// Go: "Size returns the number of leading ones and total bits in
    /// the mask. If the mask is not in the canonical form--ones
    /// followed by zeros--then Size returns 0, 0."
    pub fn Size(&self) -> (int, int) {
        // Go: ones, bits = simpleMaskLength(m), len(m)*8
        let ones = simpleMaskLength(&self.bytes);
        let bits = int(self.bytes.Len() * 8);
        // Go: if ones == -1 { return 0, 0 }
        if ones == -1 {
            return (0, 0);
        }
        return (ones, bits);
    }

    // go: sdk 1.25.5 net/ip.go:449-454 IPMask.String
    /// Go: "String returns the hexadecimal form of m, with no
    /// punctuation."
    pub fn String(&self) -> string {
        // Go: if len(m) == 0 { return "<nil>" }
        if self.bytes.Len() == 0 {
            return string::from_static("<nil>");
        }
        return hexString(&self.bytes);
    }
}

// go: sdk 1.25.5 net/ip.go:456-479 networkNumberAndMask
/// Go: unexported — normalise `n.IP` and `n.Mask` to a matching pair
/// of address families, or `(nil, nil)` when they cannot agree.
fn networkNumberAndMask(n: &IPNet) -> (IP, IPMask) {
    // Go: if ip = n.IP.To4(); ip == nil { ip = n.IP;
    //         if len(ip) != IPv6len { return nil, nil } }
    let mut ip = n.IP.To4();
    if ip.IsNil() {
        ip = n.IP.clone();
        if ip.bytes.Len() != IPv6len {
            return (IP::default(), IPMask::default());
        }
    }
    let mut m = n.Mask.clone();
    // Go: switch len(m) { case IPv4len: … case IPv6len: … default: nil }
    match m.bytes.Len() {
        IPv4len => {
            // Go: if len(ip) != IPv4len { return nil, nil }
            if ip.bytes.Len() != IPv4len {
                return (IP::default(), IPMask::default());
            }
        }
        IPv6len => {
            // Go: if len(ip) == IPv4len { m = m[12:] }
            if ip.bytes.Len() == IPv4len {
                let mb: &[byte] = &m.bytes;
                let trimmed = mask_of(&mb[12..]);
                m = trimmed;
            }
        }
        _ => {
            return (IP::default(), IPMask::default());
        }
    }
    return (ip, m);
}

impl IPNet {
    // go: sdk 1.25.5 net/ip.go:480-497 IPNet.Contains
    /// Go: "Contains reports whether the network includes ip."
    pub fn Contains(&self, ip: &IP) -> bool {
        // Go: nn, m := networkNumberAndMask(n)
        let (nn, m) = networkNumberAndMask(self);
        // Go: if x := ip.To4(); x != nil { ip = x }
        let x = ip.To4();
        let ip = if x.IsNil() { ip.clone() } else { x };
        // Go: l := len(ip); if l != len(nn) { return false }
        let l = ip.bytes.Len();
        if l != nn.bytes.Len() {
            return false;
        }
        // Go: for i := range l { if nn[i]&m[i] != ip[i]&m[i] { return false } }
        for i in 0..(l as usize) {
            if (nn.bytes[i] & m.bytes[i]) != (ip.bytes[i] & m.bytes[i]) {
                return false;
            }
        }
        return true;
    }

    // go: sdk 1.25.5 net/ip.go:498-505 IPNet.Network
    /// Go: "Network returns the address's network name, "ip+net"."
    pub fn Network(&self) -> string {
        return string::from_static("ip+net");
    }

    // go: sdk 1.25.5 net/ip.go:506-526 IPNet.String
    /// Go: "String returns the CIDR notation of n like "192.0.2.0/24"
    /// or "2001:db8::/48" as defined in RFC 4632 and RFC 4291. If the
    /// mask is not in the canonical form, it returns the string which
    /// consists of an IP address, followed by a slash character and a
    /// mask expressed as hexadecimal form with no punctuation like
    /// "198.51.100.0/c000ff00"."
    pub fn String(&self) -> string {
        // Go's `if n == nil { return "<nil>" }` guards a nil *IPNet;
        // goish takes `&self`, so the zero value takes its place —
        // and it falls out of `networkNumberAndMask` below anyway.
        let (nn, m) = networkNumberAndMask(self);
        // Go: if nn == nil || m == nil { return "<nil>" }
        if nn.IsNil() || m.IsNil() {
            return string::from_static("<nil>");
        }
        // Go: l := simpleMaskLength(m)
        let l = simpleMaskLength(&m.bytes);
        // Go: if l == -1 { return nn.String() + "/" + m.String() }
        if l == -1 {
            return nn.String() + string::from_static("/") + m.String();
        }
        // Go: return nn.String() + "/" + itoa.Uitoa(uint(l))
        return nn.String() + string::from_static("/") + crate::strconv::Itoa(l);
    }
}

// go: sdk 1.25.5 net/ip.go:527-532 ParseIP
/// Go: "ParseIP parses s as an IP address, returning the result. The
/// string s can be in IPv4 dotted decimal ("192.0.2.1"), IPv6
/// ("2001:db8::68"), or IPv4-mapped IPv6 ("::ffff:192.0.2.1") form. If
/// s is not a valid textual representation of an IP address, ParseIP
/// returns nil. The returned address is always 16 bytes, IPv4
/// addresses are returned in IPv4-mapped IPv6 form."
pub fn ParseIP(s: string) -> IP {
    // Go: if addr, valid := parseIP(s); valid { return IP(addr[:]) }
    let (addr, valid) = parseIP(s);
    if valid {
        return ip_of(&addr);
    }
    return IP::default();
}

// go: sdk 1.25.5 net/ip.go:534-549 parseIP
/// Go: unexported — parse `s` via `netip.ParseAddr`, rejecting any
/// address that carries a zone, and return its 16-byte form.
fn parseIP(s: string) -> ([byte; 16], bool) {
    // Go: ip, err := netip.ParseAddr(s)
    let (ip, err) = netip::ParseAddr(s);
    // Go: if err != nil || ip.Zone() != "" { return [16]byte{}, false }
    if !err.IsNil() || ip.Zone().Len() != 0 {
        return ([0u8; 16], false);
    }
    // Go: return ip.As16(), true
    return (ip.As16(), true);
}

// go: sdk 1.25.5 net/ip.go:550-568 ParseCIDR
/// Go: "ParseCIDR parses s as a CIDR notation IP address and prefix
/// length, like "192.0.2.0/24" or "2001:db8::/32", as defined in RFC
/// 4632 and RFC 4291. It returns the IP address and the network
/// implied by the IP and prefix length. For example,
/// ParseCIDR("192.0.2.1/24") returns the IP address 192.0.2.1 and the
/// network 192.0.2.0/24."
pub fn ParseCIDR(s: string) -> (IP, IPNet, error) {
    // Go: addr, mask, found := stringslite.Cut(s, "/")
    let (addr, mask, found) = crate::strings::Cut(s.clone(), string::from_static("/"));
    // Go: if !found { return nil, nil, &ParseError{Type: "CIDR address", Text: s} }
    let cidr_err = || -> error {
        return error::from(ParseError {
            Type: string::from_static("CIDR address"),
            Text: s.clone(),
        });
    };
    if !found {
        return (IP::default(), IPNet::default(), cidr_err());
    }
    // Go: ipAddr, err := netip.ParseAddr(addr)
    let (ipAddr, err) = netip::ParseAddr(addr);
    // Go: if err != nil || ipAddr.Zone() != "" { … }
    if !err.IsNil() || ipAddr.Zone().Len() != 0 {
        return (IP::default(), IPNet::default(), cidr_err());
    }
    // Go: n, i, ok := dtoi(mask)
    let (n, i, ok) = dtoi(&mask);
    // Go: if !ok || i != len(mask) || n < 0 || n > ipAddr.BitLen() { … }
    if !ok || i != mask.Len() || n < 0 || n > ipAddr.BitLen() {
        return (IP::default(), IPNet::default(), cidr_err());
    }
    // Go: m := CIDRMask(n, ipAddr.BitLen())
    let m = CIDRMask(n, ipAddr.BitLen());
    // Go: addr16 := ipAddr.As16()
    let addr16 = ipAddr.As16();
    let ip = ip_of(&addr16);
    // Go: return IP(addr16[:]),
    //            &IPNet{IP: IP(addr16[:]).Mask(m), Mask: m}, nil
    return (
        ip.clone(),
        IPNet {
            IP: ip.Mask(&m),
            Mask: m,
        },
        errors::nil,
    );
}

// go: none — goish idiom: Go's `dtoi` lives in net/parse.go and is
// shared package-wide; goish has no port of that file yet, so ParseCIDR
// carries the one decimal scan it needs. Same contract as Go's: the
// value, the index one past the last digit consumed, and whether any
// digit was seen (with `big` on overflow past `1<<30`).
fn dtoi(s: &string) -> (int, int, bool) {
    let b = s.as_bytes();
    let mut n: int = 0;
    let mut i = 0usize;
    while i < b.len() && b[i] >= b'0' && b[i] <= b'9' {
        n = n * 10 + int(b[i] - b'0');
        if n >= 1 << 30 {
            return (1 << 30, int(i + 1), false);
        }
        i += 1;
    }
    if i == 0 {
        return (0, 0, false);
    }
    return (n, int(i), true);
}

// go: sdk 1.25.5 net/ip.go:570-574 copyIP
/// Go: unexported — return a fresh copy of `x`.
pub(crate) fn copyIP(x: &IP) -> IP {
    return ip_of(&x.bytes);
}

// go: none — goish idiom: Go's `fmt` finds `String()` by structural
// assertion, so `%%v` and `%%s` on a value whose METHOD SET includes it
// print through it. goish's printer dispatches on `Format`, which a
// type reaches through `Stringer`, and these did not implement it —
// so `fmt.Printf("%%v", x)`, entirely ordinary Go, did not compile.
//
// Only VALUE-receiver String methods are bridged. Go puts a
// pointer-receiver String in the POINTER's method set only, so
// printing the value prints the struct instead; goish has no
// value/pointer distinction, and implementing Stringer for those types
// would print where Go does not. net.IPNet, url.URL, url.Userinfo,
// http.Cookie, mail.Address and regexp.Regexp are left alone for that
// reason.
impl crate::fmt::Stringer for IP {
    // go: none — goish idiom: see the note above.
    fn String(&self) -> crate::gostring::string {
        let v = self;
        return IP::String(v);
    }
}

impl crate::fmt::Stringer for IPMask {
    // go: none — goish idiom: see the note above.
    fn String(&self) -> crate::gostring::string {
        let v = self;
        return IPMask::String(v);
    }
}
