// Port of net/lookup.go @ Go 1.25.5
//
// Public Resolver type and package-level LookupHost / LookupIP /
// LookupCNAME / LookupAddr / LookupTXT / LookupNS / LookupMX / LookupSRV.
//
// These wrap the lower-level dnsclient functions and present a Goish
// public API using `string`, `slice<T>`, and the goish `IP` type.
// Context parameters are accepted but not yet wired into cancellation
// (the underlying dnsclient is context-free in this port).

#![allow(non_snake_case)]
#![allow(dead_code)]
#![allow(unused_variables)]
#![allow(unused_mut)]

extern crate alloc;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;

use crate::context;
use crate::errors::{self, error};
use crate::goslice::slice;
use crate::gostring::string;
use crate::nilable;
use crate::types::{byte, uint16};

use super::dnsclient;
use super::dnsmessage as dns;

// ─── Public record types ────────────────────────────────────────────────────

/// `net.IPAddr` — an IP address with optional zone.
#[derive(Clone, Default)]
pub struct IPAddr {
    pub IP: super::IP,
    pub Zone: string,
}

/// `net.SRV` — a single DNS SRV record.
#[derive(Clone, Default, Debug)]
pub struct SRV {
    pub Target: string,
    pub Port: uint16,
    pub Priority: uint16,
    pub Weight: uint16,
}

/// `net.MX` — a single DNS MX record.
#[derive(Clone, Default, Debug)]
pub struct MX {
    pub Host: string,
    pub Pref: uint16,
}

/// `net.NS` — a single DNS NS record.
#[derive(Clone, Default, Debug)]
pub struct NS {
    pub Host: string,
}

// ─── Resolver ───────────────────────────────────────────────────────────────

/// `net.Resolver` — wraps DNS lookup configuration.
/// The Dial field and singleflight group are not yet wired in this port;
/// all lookups delegate directly to the dnsclient functions.
#[derive(Clone, Default)]
pub struct Resolver {
    pub PreferGo: bool,
    pub StrictErrors: bool,
}

/// Package-level default resolver.
pub fn default_resolver() -> Resolver {
    Resolver::default()
}

// ─── Internal helpers ────────────────────────────────────────────────────────

/// Convert a raw `Vec<u8>` IP to a goish `IP`.
fn raw_to_ip(raw: &[u8]) -> super::IP {
    let mut b = slice::<byte>::new();
    for &oct in raw {
        b = crate::append!(b, oct);
    }
    super::IP { bytes: b }
}

/// Check that a string is a valid domain name (mirrors Go's `isDomainName`).
fn is_domain_name(s: &str) -> bool {
    if s == "." {
        return true;
    }
    let l = s.len();
    let sb = s.as_bytes();
    if l == 0 || l > 254 || (l == 254 && sb[l - 1] != b'.') {
        return false;
    }
    let mut last = b'.';
    let mut non_numeric = false;
    let mut part_len = 0usize;
    for i in 0..l {
        let c = sb[i];
        match c {
            b'a'..=b'z' | b'A'..=b'Z' | b'_' => {
                non_numeric = true;
                part_len += 1;
            }
            b'0'..=b'9' => {
                part_len += 1;
            }
            b'-' => {
                if last == b'.' {
                    return false;
                }
                part_len += 1;
                non_numeric = true;
            }
            b'.' => {
                if last == b'.' || last == b'-' {
                    return false;
                }
                if part_len > 63 || part_len == 0 {
                    return false;
                }
                part_len = 0;
            }
            _ => return false,
        }
        last = c;
    }
    if last == b'-' || part_len > 63 {
        return false;
    }
    non_numeric
}

/// Build a new DNS error (simplified — just wraps an `errors::New`).
fn new_dns_error<M: Into<string>>(msg: M, name: &str) -> error {
    let m = msg.into();
    let mut b = crate::strings::Builder::new();
    let _ = b.WriteString(m);
    if !name.is_empty() {
        let _ = b.WriteString(string::from_static(": "));
        let _ = b.WriteString(string::from_bytes(name.as_bytes()));
    }
    errors::New(b.String())
}

const ERR_MALFORMED_DNS: &str = "DNS response contained records which contain invalid names";

// ─── Resolver methods ────────────────────────────────────────────────────────

impl Resolver {
    /// `(*Resolver).LookupHost` — resolves host to a list of address strings.
    pub fn LookupHost<S: Into<string>>(
        &self,
        ctx: &Arc<dyn context::Context>,
        host: S,
    ) -> (slice<string>, error) {
        let host = host.into();
        let h: &str = host.as_ref();

        if h.is_empty() {
            return (slice::<string>::new(), new_dns_error("no such host", h));
        }
        // Already an IP literal?
        let ip_lit = super::ParseIP(host.clone());
        if !ip_lit.IsNil() {
            let mut r = slice::<string>::new();
            r = crate::append!(r, host);
            return (r, errors::nil);
        }

        let (raw_strs, e) = dnsclient::lookup_host(h);
        if e != errors::nil {
            return (slice::<string>::new(), e);
        }
        let mut out = slice::<string>::new();
        for s in &raw_strs {
            out = crate::append!(out, string::from_bytes(s.as_bytes()));
        }
        (out, errors::nil)
    }

    /// `(*Resolver).LookupIPAddr` — resolves host to a list of `IPAddr`.
    pub fn LookupIPAddr<S: Into<string>>(
        &self,
        ctx: &Arc<dyn context::Context>,
        host: S,
    ) -> (slice<IPAddr>, error) {
        self.lookup_ip_addr_inner(ctx, "ip", host.into())
    }

    /// `(*Resolver).LookupIP` — resolves host to a list of `IP` for the
    /// given network ("ip", "ip4", "ip6").
    pub fn LookupIP<N: Into<string>, S: Into<string>>(
        &self,
        ctx: &Arc<dyn context::Context>,
        network: N,
        host: S,
    ) -> (slice<super::IP>, error) {
        let network = network.into();
        let net_ref: &str = network.as_ref();
        match net_ref {
            "ip" | "ip4" | "ip6" => {}
            _ => {
                let net_err = (string::from_static("unknown network ")) + (network);
                return (slice::<super::IP>::new(), errors::New(net_err));
            }
        }
        let host = host.into();
        let h: &str = host.as_ref();

        if h.is_empty() {
            return (slice::<super::IP>::new(), new_dns_error("no such host", h));
        }
        let (raw_addrs, _cname, e) =
            dnsclient::go_lookup_ip_cname_order(&dnsclient::get_system_dns_config(), net_ref, h);
        if e != errors::nil {
            return (slice::<super::IP>::new(), e);
        }
        let mut out = slice::<super::IP>::new();
        for a in &raw_addrs {
            out = crate::append!(out, raw_to_ip(&a.ip));
        }
        (out, errors::nil)
    }

    /// `(*Resolver).LookupCNAME` — returns the canonical name.
    pub fn LookupCNAME<S: Into<string>>(
        &self,
        ctx: &Arc<dyn context::Context>,
        host: S,
    ) -> (string, error) {
        let host = host.into();
        let h: &str = host.as_ref();
        let cfg = dnsclient::get_system_dns_config();
        let (mut p, _server, e) = dnsclient::lookup(&cfg, h, dns::TypeCNAME);
        if e != errors::nil {
            return (string::from_static(""), e);
        }
        // Walk answers for CNAME record
        loop {
            let (hdr, e2) = p.AnswerHeader();
            if e2 == dns::ErrSectionDone {
                break;
            }
            if e2 != errors::nil {
                return (
                    string::from_static(""),
                    errors::New(string::from_static("cannot unmarshal DNS message")),
                );
            }
            if hdr.Type == dns::TypeCNAME {
                let (r, e3) = p.CNAMEResource();
                if e3 != errors::nil {
                    return (
                        string::from_static(""),
                        errors::New(string::from_static("cannot unmarshal DNS message")),
                    );
                }
                let cname = r.CNAME.String();
                if !is_domain_name(cname.as_ref()) {
                    return (
                        string::from_static(""),
                        errors::New(string::from_bytes(h.as_bytes())),
                    );
                }
                return (cname, errors::nil);
            }
            let _ = p.SkipAnswer();
        }
        // No CNAME record — return host itself with trailing dot
        let mut cname_str = String::with_capacity(h.len() + 1);
        cname_str.push_str(h);
        if !h.ends_with('.') {
            cname_str.push('.');
        }
        let cname = string::from_bytes(cname_str.as_bytes());
        if !is_domain_name(cname.as_ref()) {
            return (string::from_static(""), new_dns_error("invalid CNAME", h));
        }
        (cname, errors::nil)
    }

    /// `(*Resolver).LookupAddr` — reverse DNS lookup.
    pub fn LookupAddr<S: Into<string>>(
        &self,
        ctx: &Arc<dyn context::Context>,
        addr: S,
    ) -> (slice<string>, error) {
        let addr = addr.into();
        let a: &str = addr.as_ref();
        // Build reverse lookup name (e.g. "1.2.3.4" → "4.3.2.1.in-addr.arpa.")
        let arpa = match build_arpa_name(a) {
            Some(s) => s,
            None => {
                return (slice::<string>::new(), new_dns_error("invalid address", a));
            }
        };
        let cfg = dnsclient::get_system_dns_config();
        let (mut p, _server, e) = dnsclient::lookup(&cfg, &arpa, dns::TypePTR);
        if e != errors::nil {
            return (slice::<string>::new(), e);
        }
        let mut names: Vec<String> = Vec::new();
        loop {
            let (hdr, e2) = p.AnswerHeader();
            if e2 == dns::ErrSectionDone {
                break;
            }
            if e2 != errors::nil {
                break;
            }
            if hdr.Type != dns::TypePTR {
                let _ = p.SkipAnswer();
                continue;
            }
            let (r, e3) = p.PTRResource();
            if e3 != errors::nil {
                break;
            }
            let name_str = {
                let s = r.PTR.String();
                let mut ns = String::with_capacity(s.Len() as usize);
                ns.push_str(s.as_ref());
                ns
            };
            if is_domain_name(&name_str) {
                names.push(name_str);
            }
        }
        let mut out = slice::<string>::new();
        for n in &names {
            out = crate::append!(out, string::from_bytes(n.as_bytes()));
        }
        (out, errors::nil)
    }

    /// `(*Resolver).LookupTXT` — returns TXT records for name.
    pub fn LookupTXT<S: Into<string>>(
        &self,
        ctx: &Arc<dyn context::Context>,
        name: S,
    ) -> (slice<string>, error) {
        let name = name.into();
        let n: &str = name.as_ref();
        let cfg = dnsclient::get_system_dns_config();
        let (mut p, _server, e) = dnsclient::lookup(&cfg, n, dns::TypeTXT);
        if e != errors::nil {
            return (slice::<string>::new(), e);
        }
        let mut out = slice::<string>::new();
        loop {
            let (hdr, e2) = p.AnswerHeader();
            if e2 == dns::ErrSectionDone {
                break;
            }
            if e2 != errors::nil {
                break;
            }
            if hdr.Type != dns::TypeTXT {
                let _ = p.SkipAnswer();
                continue;
            }
            let (txt, e3) = p.TXTResource();
            if e3 != errors::nil {
                break;
            }
            // Concatenate all strings in the TXT record
            let mut total = 0usize;
            for s in &txt.TXT {
                total += s.len();
            }
            let mut joined = String::with_capacity(total);
            for s in &txt.TXT {
                joined.push_str(s);
            }
            out = crate::append!(out, string::from_bytes(joined.as_bytes()));
        }
        (out, errors::nil)
    }

    /// `(*Resolver).LookupNS` — returns NS records for name.
    pub fn LookupNS<S: Into<string>>(
        &self,
        ctx: &Arc<dyn context::Context>,
        name: S,
    ) -> (slice<nilable<NS>>, error) {
        let name = name.into();
        let n: &str = name.as_ref();
        let cfg = dnsclient::get_system_dns_config();
        let (mut p, _server, e) = dnsclient::lookup(&cfg, n, dns::TypeNS);
        if e != errors::nil {
            return (slice::<nilable<NS>>::new(), e);
        }
        let mut nss: Vec<NS> = Vec::new();
        loop {
            let (hdr, e2) = p.AnswerHeader();
            if e2 == dns::ErrSectionDone {
                break;
            }
            if e2 != errors::nil {
                break;
            }
            if hdr.Type != dns::TypeNS {
                let _ = p.SkipAnswer();
                continue;
            }
            let (r, e3) = p.NSResource();
            if e3 != errors::nil {
                break;
            }
            let host = r.NS.String();
            if is_domain_name(host.as_ref()) {
                nss.push(NS { Host: host });
            }
        }
        let mut out = slice::<nilable<NS>>::new();
        for ns in nss {
            out = crate::append!(out, nilable::new(ns));
        }
        (out, errors::nil)
    }

    /// `(*Resolver).LookupMX` — returns MX records sorted by preference.
    pub fn LookupMX<S: Into<string>>(
        &self,
        ctx: &Arc<dyn context::Context>,
        name: S,
    ) -> (slice<nilable<MX>>, error) {
        let name = name.into();
        let n: &str = name.as_ref();
        let cfg = dnsclient::get_system_dns_config();
        let (mut p, _server, e) = dnsclient::lookup(&cfg, n, dns::TypeMX);
        if e != errors::nil {
            return (slice::<nilable<MX>>::new(), e);
        }
        let mut mxs: Vec<MX> = Vec::new();
        loop {
            let (hdr, e2) = p.AnswerHeader();
            if e2 == dns::ErrSectionDone {
                break;
            }
            if e2 != errors::nil {
                break;
            }
            if hdr.Type != dns::TypeMX {
                let _ = p.SkipAnswer();
                continue;
            }
            let (r, e3) = p.MXResource();
            if e3 != errors::nil {
                break;
            }
            let host = r.MX.String();
            let pref = r.Pref;
            let host_str: &str = host.as_ref();
            if is_domain_name(host_str) {
                mxs.push(MX {
                    Host: host,
                    Pref: pref,
                });
            }
        }
        // Sort by preference (ascending)
        mxs.sort_by_key(|m| m.Pref);
        let mut out = slice::<nilable<MX>>::new();
        for mx in mxs {
            out = crate::append!(out, nilable::new(mx));
        }
        (out, errors::nil)
    }

    /// `(*Resolver).LookupSRV` — returns SRV records.
    pub fn LookupSRV<Svc: Into<string>, Proto: Into<string>, N: Into<string>>(
        &self,
        ctx: &Arc<dyn context::Context>,
        service: Svc,
        proto: Proto,
        name: N,
    ) -> (string, slice<nilable<SRV>>, error) {
        let service = service.into();
        let proto = proto.into();
        let name = name.into();
        let svc_ref: &str = service.as_ref();
        let proto_ref: &str = proto.as_ref();
        let name_ref: &str = name.as_ref();

        let target: String = if svc_ref.is_empty() && proto_ref.is_empty() {
            let mut s = String::with_capacity(name_ref.len());
            s.push_str(name_ref);
            s
        } else {
            // "_service._proto.name"
            let mut s =
                String::with_capacity(1 + svc_ref.len() + 2 + proto_ref.len() + 1 + name_ref.len());
            s.push('_');
            s.push_str(svc_ref);
            s.push_str("._");
            s.push_str(proto_ref);
            s.push('.');
            s.push_str(name_ref);
            s
        };

        let cfg = dnsclient::get_system_dns_config();
        let (mut p, _server, e) = dnsclient::lookup(&cfg, &target, dns::TypeSRV);
        if e != errors::nil {
            return (string::from_static(""), slice::<nilable<SRV>>::new(), e);
        }

        let mut srvs: Vec<SRV> = Vec::new();
        let mut cname_name = dns::Name::default();

        loop {
            let (hdr, e2) = p.AnswerHeader();
            if e2 == dns::ErrSectionDone {
                break;
            }
            if e2 != errors::nil {
                return (
                    string::from_static(""),
                    slice::<nilable<SRV>>::new(),
                    errors::New(string::from_static("cannot unmarshal DNS message")),
                );
            }
            if hdr.Type != dns::TypeSRV {
                let _ = p.SkipAnswer();
                continue;
            }
            if cname_name.Length == 0 && hdr.Name.Length != 0 {
                cname_name = hdr.Name.clone();
            }
            let (r, e3) = p.SRVResource();
            if e3 != errors::nil {
                return (
                    string::from_static(""),
                    slice::<nilable<SRV>>::new(),
                    errors::New(string::from_static("cannot unmarshal DNS message")),
                );
            }
            let tgt = r.Target.String();
            if is_domain_name(tgt.as_ref()) {
                srvs.push(SRV {
                    Target: tgt,
                    Port: r.Port,
                    Priority: r.Priority,
                    Weight: r.Weight,
                });
            }
        }

        // Sort by priority then randomise by weight (simplified: sort by priority only)
        srvs.sort_by(|a, b| a.Priority.cmp(&b.Priority).then(b.Weight.cmp(&a.Weight)));

        let cname_str = if cname_name.Length > 0 {
            cname_name.String()
        } else {
            string::from_bytes(target.as_bytes())
        };

        if cname_str != string::from_static("") && !is_domain_name(cname_str.as_ref()) {
            return (
                string::from_static(""),
                slice::<nilable<SRV>>::new(),
                errors::New(string::from_static("SRV header name is invalid")),
            );
        }

        let mut out = slice::<nilable<SRV>>::new();
        for srv in srvs {
            out = crate::append!(out, nilable::new(srv));
        }
        (cname_str, out, errors::nil)
    }

    // ─── internal helper ─────────────────────────────────────────────────────

    fn lookup_ip_addr_inner(
        &self,
        _ctx: &Arc<dyn context::Context>,
        network: &str,
        host: string,
    ) -> (slice<IPAddr>, error) {
        let h: &str = host.as_ref();
        if h.is_empty() {
            return (slice::<IPAddr>::new(), new_dns_error("no such host", h));
        }
        // Already an IP literal?
        let ip_lit = super::ParseIP(host.clone());
        if !ip_lit.IsNil() {
            let mut r = slice::<IPAddr>::new();
            r = crate::append!(
                r,
                IPAddr {
                    IP: ip_lit,
                    Zone: string::from_static("")
                }
            );
            return (r, errors::nil);
        }
        let cfg = dnsclient::get_system_dns_config();
        let (raw_addrs, _cname, e) = dnsclient::go_lookup_ip_cname_order(&cfg, network, h);
        if e != errors::nil {
            return (slice::<IPAddr>::new(), e);
        }
        let mut out = slice::<IPAddr>::new();
        for a in &raw_addrs {
            out = crate::append!(
                out,
                IPAddr {
                    IP: raw_to_ip(&a.ip),
                    Zone: string::from_static(""),
                }
            );
        }
        (out, errors::nil)
    }
}

// ─── Reverse DNS helper ──────────────────────────────────────────────────────

/// Build the ARPA name for a reverse DNS lookup of an IPv4 address.
/// "1.2.3.4" → "4.3.2.1.in-addr.arpa."
fn build_arpa_name(addr: &str) -> Option<String> {
    // Try IPv4
    let parts: Vec<&str> = addr.split('.').collect();
    if parts.len() == 4 {
        let mut all_ok = true;
        let mut octets = [""; 4];
        for (i, p) in parts.iter().enumerate() {
            if p.parse::<u8>().is_ok() {
                octets[i] = p;
            } else {
                all_ok = false;
                break;
            }
        }
        if all_ok {
            let mut s = String::with_capacity(addr.len() + 14);
            s.push_str(octets[3]);
            s.push('.');
            s.push_str(octets[2]);
            s.push('.');
            s.push_str(octets[1]);
            s.push('.');
            s.push_str(octets[0]);
            s.push_str(".in-addr.arpa.");
            return Some(s);
        }
    }
    // IPv6 not yet supported
    None
}

// ─── Package-level convenience functions ────────────────────────────────────

static DEFAULT_RESOLVER: Resolver = Resolver {
    PreferGo: false,
    StrictErrors: false,
};

/// `net.LookupHost` — resolves host to a list of address strings.
pub fn LookupHost<S: Into<string>>(host: S) -> (slice<string>, error) {
    let host = host.into();
    let h: &str = host.as_ref();

    if h.is_empty() {
        return (slice::<string>::new(), new_dns_error("no such host", h));
    }
    // Already an IP literal?
    let ip_lit = super::ParseIP(host.clone());
    if !ip_lit.IsNil() {
        let mut r = slice::<string>::new();
        r = crate::append!(r, host);
        return (r, errors::nil);
    }

    let (raw_strs, e) = dnsclient::lookup_host(h);
    if e != errors::nil {
        return (slice::<string>::new(), e);
    }
    let mut out = slice::<string>::new();
    for s in &raw_strs {
        out = crate::append!(out, string::from_bytes(s.as_bytes()));
    }
    (out, errors::nil)
}

/// `net.LookupIP` — resolves host to a list of IPv4 and IPv6 addresses.
pub fn LookupIP<S: Into<string>>(host: S) -> (slice<super::IP>, error) {
    let host = host.into();
    let h: &str = host.as_ref();

    if h.is_empty() {
        return (slice::<super::IP>::new(), new_dns_error("no such host", h));
    }
    let cfg = dnsclient::get_system_dns_config();
    let (raw_addrs, _cname, e) = dnsclient::go_lookup_ip_cname_order(&cfg, "ip", h);
    if e != errors::nil {
        return (slice::<super::IP>::new(), e);
    }
    let mut out = slice::<super::IP>::new();
    for a in &raw_addrs {
        out = crate::append!(out, raw_to_ip(&a.ip));
    }
    (out, errors::nil)
}

/// `net.LookupCNAME` — returns the canonical name for host.
pub fn LookupCNAME<S: Into<string>>(host: S) -> (string, error) {
    let host = host.into();
    let h: &str = host.as_ref();
    let cfg = dnsclient::get_system_dns_config();
    let (mut p, _server, e) = dnsclient::lookup(&cfg, h, dns::TypeCNAME);
    if e != errors::nil {
        return (string::from_static(""), e);
    }
    loop {
        let (hdr, e2) = p.AnswerHeader();
        if e2 == dns::ErrSectionDone {
            break;
        }
        if e2 != errors::nil {
            return (
                string::from_static(""),
                errors::New(string::from_static("cannot unmarshal DNS message")),
            );
        }
        if hdr.Type == dns::TypeCNAME {
            let (r, e3) = p.CNAMEResource();
            if e3 != errors::nil {
                return (
                    string::from_static(""),
                    errors::New(string::from_static("cannot unmarshal DNS message")),
                );
            }
            return (r.CNAME.String(), errors::nil);
        }
        let _ = p.SkipAnswer();
    }
    // Return host + trailing dot
    let mut cname_str = String::with_capacity(h.len() + 1);
    cname_str.push_str(h);
    if !h.ends_with('.') {
        cname_str.push('.');
    }
    (string::from_bytes(cname_str.as_bytes()), errors::nil)
}

/// `net.LookupTXT` — returns TXT records for name.
pub fn LookupTXT<S: Into<string>>(name: S) -> (slice<string>, error) {
    let ctx = crate::context::Background();
    DEFAULT_RESOLVER.LookupTXT(&ctx, name)
}

/// `net.LookupAddr` — reverse DNS lookup.
pub fn LookupAddr<S: Into<string>>(addr: S) -> (slice<string>, error) {
    let ctx = crate::context::Background();
    DEFAULT_RESOLVER.LookupAddr(&ctx, addr)
}

/// `net.LookupNS` — returns NS records for name.
pub fn LookupNS<S: Into<string>>(name: S) -> (slice<nilable<NS>>, error) {
    let ctx = crate::context::Background();
    DEFAULT_RESOLVER.LookupNS(&ctx, name)
}

/// `net.LookupMX` — returns MX records for name, sorted by preference.
pub fn LookupMX<S: Into<string>>(name: S) -> (slice<nilable<MX>>, error) {
    let ctx = crate::context::Background();
    DEFAULT_RESOLVER.LookupMX(&ctx, name)
}

/// `net.LookupSRV` — resolves SRV records.
pub fn LookupSRV<Svc: Into<string>, Proto: Into<string>, N: Into<string>>(
    service: Svc,
    proto: Proto,
    name: N,
) -> (string, slice<nilable<SRV>>, error) {
    let ctx = crate::context::Background();
    DEFAULT_RESOLVER.LookupSRV(&ctx, service, proto, name)
}

// go: sdk 1.25.5 net/lookup.go:40-60 services
/// Go's built-in port map, consulted alongside /etc/services.
///
/// Go declares it as a package variable that `readServices` MUTATES,
/// merging the system file into these defaults. goish keeps the two
/// apart — this table is constant, and `port_unix::readServices`
/// returns the file's rows — which is the same lookup with no shared
/// mutable state. Go's gopher entry keeps its comment: ʕ◔ϖ◔ʔ
const services: [(&str, &str, i64); 15] = [
    ("udp", "domain", 53),
    ("tcp", "ftp", 21),
    ("tcp", "ftps", 990),
    ("tcp", "gopher", 70),
    ("tcp", "http", 80),
    ("tcp", "https", 443),
    ("tcp", "imap2", 143),
    ("tcp", "imap3", 220),
    ("tcp", "imaps", 993),
    ("tcp", "pop3", 110),
    ("tcp", "pop3s", 995),
    ("tcp", "smtp", 25),
    ("tcp", "submissions", 465),
    ("tcp", "ssh", 22),
    ("tcp", "telnet", 23),
];

// go: sdk 1.25.5 net/lookup.go:79-84 maxPortBufSize
/// Go: "the longest reasonable name of a service … Currently the
/// longest known IANA-unregistered name is 'mobility-header', so we
/// use that length, plus some slop."
///
/// It is a real behavioural limit, not a buffer detail: a service name
/// longer than this cannot match, because Go lowercases into a fixed
/// array and then requires the copy to have been complete.
const maxPortBufSize: usize = "mobility-header".len() + 10;

// go: sdk 1.25.5 net/lookup.go:86-99 lookupPortMap
/// Go: resolve a service name for `network`. "ip" tries tcp first and
/// then udp; the 4/6 suffixes fold onto their base.
pub(crate) fn lookupPortMap(network: &str, service: &str) -> (crate::types::int, error) {
    match network {
        "ip" => {
            // Go: "no hints" — try tcp, then udp.
            let (p, err) = lookupPortMapWithNetwork("tcp", "ip", service);
            if err.IsNil() {
                return (p, errors::nil);
            }
            return lookupPortMapWithNetwork("udp", "ip", service);
        }
        "tcp" | "tcp4" | "tcp6" => return lookupPortMapWithNetwork("tcp", "tcp", service),
        "udp" | "udp4" | "udp6" => return lookupPortMapWithNetwork("udp", "udp", service),
        _ => {}
    }
    return (
        crate::types::int::from(0),
        unknown_network_dns_error(network, service),
    );
}

// go: sdk 1.25.5 net/lookup.go:101-112 lookupPortMapWithNetwork
/// Go lowercases the service into a fixed buffer and then requires
/// `n == len(service)`, so a name longer than `maxPortBufSize` never
/// matches however it is spelled. That is why "HTTP" resolves and a
/// 30-character name does not.
fn lookupPortMapWithNetwork(
    network: &str,
    errNetwork: &str,
    service: &str,
) -> (crate::types::int, error) {
    if service.len() <= maxPortBufSize {
        let lower = service.to_ascii_lowercase();
        // The system table wins where it disagrees, as it does in Go:
        // readServices writes into the same map these defaults live in.
        if let Some(port) = super::port_unix::systemPort(network, &lower) {
            return (port, errors::nil);
        }
        for (netw, name, port) in services.iter() {
            if *netw == network && *name == lower {
                return (crate::types::int::from(*port), errors::nil);
            }
        }
    }
    return (
        crate::types::int::from(0),
        unknown_port_dns_error(errNetwork, service),
    );
}

// go: none — goish-only: Go writes `newDNSError(errUnknownPort, …)`
// and `&DNSError{Err: "unknown network", …}` inline; this names the
// two compositions once. `lookup <net>/<service>: <err>` is how
// DNSError.Error renders them.
fn unknown_port_dns_error(network: &str, service: &str) -> error {
    return errors::Wrap(super::net::DNSError {
        UnwrapErr: errors::nil,
        Err: string::from_static("unknown port"),
        Name: string::from_bytes(network.as_bytes())
            + string::from_static("/")
            + string::from_bytes(service.as_bytes()),
        Server: string::from_static(""),
        IsTimeout: false,
        IsTemporary: false,
        IsNotFound: false,
    });
}

// go: none — goish-only: see unknown_port_dns_error.
fn unknown_network_dns_error(network: &str, service: &str) -> error {
    return errors::Wrap(super::net::DNSError {
        UnwrapErr: errors::nil,
        Err: string::from_static("unknown network"),
        Name: string::from_bytes(network.as_bytes())
            + string::from_static("/")
            + string::from_bytes(service.as_bytes()),
        Server: string::from_static(""),
        IsTimeout: false,
        IsTemporary: false,
        IsNotFound: false,
    });
}

// go: sdk 1.25.5 net/lookup.go:415-434 Resolver.LookupPort
/// Go: "LookupPort looks up the port for the given network and
/// service."
///
/// The network is validated ONLY when a lookup is actually needed —
/// `LookupPort("bogus", "80")` answers 80, because a numeric service
/// never reaches the switch. Measured.
pub fn LookupPort<N: Into<string>, S: Into<string>>(
    network: N,
    service: S,
) -> (crate::types::int, error) {
    let network: string = network.into();
    let service: string = service.into();
    let svc: &str = service.as_ref();
    let (mut port, needs_lookup) = super::port::parsePort(svc);
    if needs_lookup {
        let mut netw: &str = network.as_ref();
        match netw {
            "tcp" | "tcp4" | "tcp6" | "udp" | "udp4" | "udp6" | "ip" => {}
            // Go: "" is a hint wildcard meaning "ip".
            "" => netw = "ip",
            _ => {
                return (
                    crate::types::int::from(0),
                    errors::Wrap(super::net::AddrError {
                        Err: string::from_static("unknown network"),
                        Addr: network.clone(),
                    }),
                );
            }
        }
        let (p, err) = super::port_unix::goLookupPort(netw, svc);
        if !err.IsNil() {
            return (crate::types::int::from(0), err);
        }
        port = p;
    }
    if port < 0 || port > 65535 {
        return (
            crate::types::int::from(0),
            errors::Wrap(super::net::AddrError {
                Err: string::from_static("invalid port"),
                Addr: service.clone(),
            }),
        );
    }
    return (port, errors::nil);
}
