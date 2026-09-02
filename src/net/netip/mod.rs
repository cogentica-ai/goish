// go: package net/netip
//
// net/netip — the value-type IP address, prefix and address:port.

mod netip;
mod uint128;

pub use netip::{
    Addr, AddrFrom16, AddrFrom4, AddrFromSlice, AddrPort, AddrPortFrom, IPv4Unspecified,
    IPv6LinkLocalAllNodes, IPv6LinkLocalAllRouters, IPv6Loopback, IPv6Unspecified, MustParseAddr,
    MustParseAddrPort, MustParsePrefix, ParseAddr, ParseAddrPort, ParsePrefix, Prefix, PrefixFrom,
};
