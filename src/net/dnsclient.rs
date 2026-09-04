// Port of net/dnsclient.go + net/dnsclient_unix.go @ Go 1.26.0
//
// Provides:
//   - newRequest        — build a DNS query packet using dnsmessage::Builder
//   - checkResponse     — validate response header matches request
//   - dnsPacketRoundTrip — UDP DNS exchange
//   - dnsStreamRoundTrip — TCP DNS exchange
//   - exchange          — tries UDP then TCP for one server
//   - checkHeader       — inspect response flags
//   - skipToAnswer      — advance parser to first matching answer record
//   - extractExtendedRCode — read OPT (EDNS0) extended rcode
//   - tryOneName        — full attempt loop over servers × attempts
//   - lookup            — applies nameList expansion, calls tryOneName
//   - goLookupIPCNAMEOrder — parallel A + AAAA queries
//   - LookupHost        — public top-level API (returns []string)
//   - LookupA           — returns first IPv4 address as [u8;4] (used by parse.rs)

#![allow(non_snake_case)]
#![allow(dead_code)]
#![allow(unused_mut)]

// Resolver diagnostics — gated so production and e2e output stay
// clean, following crypto/tls's TLS_DEBUG. These three prints used to
// be unconditional, and two of them sit on paths that are not even
// failures: falling back to TCP after a truncated UDP answer is
// ordinary DNS. Go's resolver prints NOTHING — a failed lookup returns
// an error and says nothing on stdout — so a goish program that
// resolved a bad name, or got a truncated answer, wrote unsolicited
// lines into the middle of its own output.
//
// Flip DNS_DEBUG to true when diagnosing a resolver problem.
const DNS_DEBUG: bool = false;

macro_rules! dns_debug {
    ($($arg:tt)*) => { if DNS_DEBUG { crate::fmt::Println!($($arg)*); } };
}

extern crate alloc;
use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;

use super::dnsconfig::{dns_read_config, DnsConfig};
use super::dnsmessage as dns;
use crate::errors::{self, error};
use crate::gostring::string;
use crate::syscall;

// ─── Error sentinels ───────────────────────────────────────────────────────

crate::var! {
    pub errLameReferral:              error = "lame referral";
    pub errCannotUnmarshalDNSMessage: error = "cannot unmarshal DNS message";
    pub errCannotMarshalDNSMessage:   error = "cannot marshal DNS message";
    pub errServerMisbehaving:         error = "server misbehaving";
    pub errInvalidDNSResponse:        error = "invalid DNS response";
    pub errNoAnswerFromDNSServer:     error = "no answer from DNS server";
    pub errServerTemporarilyMisbehaving: error = "server misbehaving";
    pub errNoSuchHost:                error = "no such host";
}

// ─── Constants ─────────────────────────────────────────────────────────────

const MAX_DNS_PACKET_SIZE: usize = 1232;

// ─── randInt ───────────────────────────────────────────────────────────────
//
// Go: dnsclient.go:22 — `func randInt() int { return
//     int(uint(runtime_rand()) >> 1) }`, where `runtime_rand` is the
//     runtime's generator, seeded from the OS.
//
// This was a xorshift64 with a hardcoded seed, mixed with
// clock_gettime, under a heading that called it "poor-man's random
// using clock". It produced the DNS TRANSACTION ID.
//
// That ID is the whole of a stub resolver's defence against off-path
// spoofing: an attacker who can guess it, and the source port, can race
// a forged answer ahead of the real one and be believed. Sixteen bits
// is already thin, which is exactly why the value has to be
// unpredictable rather than merely varying. A xorshift with a known
// constant seed is recoverable from a few observed IDs, and the clock
// mixed into it is something an off-path attacker can approximate to
// within microseconds.
//
// goish has a real CSPRNG — the one `crypto/tls` draws record IVs from
// — so this uses it. `crypto::rand::Read` can fail; Go's cannot, so
// there is no Go behaviour to copy for that case, and the caller is
// given the error rather than a guessable ID.
fn rand_u16() -> (u16, error) {
    let mut b = crate::goslice::slice::<u8>::__from_vec(vec![0u8; 2]);
    let (n, err) = crate::crypto::rand::Read(&mut b);
    if !err.IsNil() {
        return (0, err);
    }
    if n != 2 {
        return (0, errors::New("net: short read from random source"));
    }
    let v = b.__into_vec();
    return (((v[0] as u16) << 8) | (v[1] as u16), errors::nil);
}

// ─── newRequest ────────────────────────────────────────────────────────────

/// Build a DNS query for `q`. Returns (id, udpReq, tcpReq, err).
/// udpReq is the bare DNS message; tcpReq has a 2-byte length prefix.
pub fn new_request(q: dns::Question, ad: bool) -> (u16, Vec<u8>, Vec<u8>, error) {
    let (id, rerr) = rand_u16();
    if !rerr.IsNil() {
        return (0, Vec::new(), Vec::new(), rerr);
    }
    let mut buf = vec![0u8; 2];
    buf.resize(2, 0); // 2-byte placeholder for TCP len prefix
    let mut b = dns::NewBuilder(
        buf,
        dns::Header {
            ID: id,
            RecursionDesired: true,
            AuthenticData: ad,
            ..Default::default()
        },
    );

    let e = b.StartQuestions();
    if e != errors::nil {
        return (0, Vec::new(), Vec::new(), errCannotMarshalDNSMessage.into());
    }
    let e = b.Question(q);
    if e != errors::nil {
        return (0, Vec::new(), Vec::new(), errCannotMarshalDNSMessage.into());
    }

    // Add EDNS0 OPT record (Accept packets up to MAX_DNS_PACKET_SIZE, RFC 6891)
    let e = b.StartAdditionals();
    if e != errors::nil {
        return (0, Vec::new(), Vec::new(), errCannotMarshalDNSMessage.into());
    }
    let mut rh = dns::ResourceHeader::default();
    let e = rh.SetEDNS0(MAX_DNS_PACKET_SIZE, dns::RCodeSuccess, false);
    if e != errors::nil {
        return (0, Vec::new(), Vec::new(), errCannotMarshalDNSMessage.into());
    }
    let e = b.OPTResource(rh, dns::OPTResource::default());
    if e != errors::nil {
        return (0, Vec::new(), Vec::new(), errCannotMarshalDNSMessage.into());
    }

    let (mut tcp_req, e) = b.Finish();
    if e != errors::nil {
        return (0, Vec::new(), Vec::new(), errCannotMarshalDNSMessage.into());
    }

    // tcp_req[0..2] are the placeholder bytes; fill in length
    let l = (tcp_req.len() - 2) as u16;
    tcp_req[0] = (l >> 8) as u8;
    tcp_req[1] = (l & 0xFF) as u8;

    let udp_req = tcp_req[2..].to_vec();
    (id, udp_req, tcp_req, errors::nil)
}

// ─── checkResponse ─────────────────────────────────────────────────────────

fn check_response(
    req_id: u16,
    req_q: &dns::Question,
    resp_hdr: &dns::Header,
    resp_q: &dns::Question,
) -> bool {
    if !resp_hdr.Response {
        return false;
    }
    if req_id != resp_hdr.ID {
        return false;
    }
    if req_q.Type != resp_q.Type || req_q.Class != resp_q.Class {
        return false;
    }
    if !equal_ascii_name(&req_q.Name, &resp_q.Name) {
        return false;
    }
    true
}

fn equal_ascii_name(x: &dns::Name, y: &dns::Name) -> bool {
    if x.Length != y.Length {
        return false;
    }
    let len = x.Length as usize;
    for i in 0..len {
        let mut a = x.Data[i];
        let mut b = y.Data[i];
        if a >= b'A' && a <= b'Z' {
            a += 0x20;
        }
        if b >= b'A' && b <= b'Z' {
            b += 0x20;
        }
        if a != b {
            return false;
        }
    }
    true
}

// ─── UDP send/recv helpers ─────────────────────────────────────────────────

/// Parse host:port string into (ip_octets, port) for UDP.
/// The server string is in "ip:port" form from DnsConfig.
fn parse_server_addr(server: &str) -> Option<([u8; 4], u16)> {
    // server is "ip:port" or "[::1]:port"
    // For IPv4 only (our syscall layer is IPv4-only in v1)
    let colon = server.rfind(':')?;
    let host = &server[..colon];
    let port_str = &server[colon + 1..];
    let port: u16 = port_str.parse().ok()?;
    // Strip brackets if present (IPv6 literal)
    let host = if host.starts_with('[') && host.ends_with(']') {
        return None; // IPv6 not supported
    } else {
        host
    };
    let parts: Vec<&str> = host.split('.').collect();
    if parts.len() != 4 {
        return None;
    }
    let mut octets = [0u8; 4];
    for (i, p) in parts.iter().enumerate() {
        octets[i] = p.parse().ok()?;
    }
    Some((octets, port))
}

/// Perform a UDP DNS packet round trip.
/// Returns (Parser, Header, error).
fn dns_packet_round_trip(
    ns_addr: &syscall::SockaddrIn,
    id: u16,
    query: &dns::Question,
    udp_req: &[u8],
    timeout_secs: u64,
) -> (dns::Parser, dns::Header, error) {
    let fd = syscall::Socket(syscall::AF_INET, syscall::SOCK_DGRAM, syscall::IPPROTO_UDP);
    if fd < 0 {
        return (
            dns::Parser::new(),
            dns::Header::default(),
            errors::New("socket: failed"),
        );
    }

    // Set receive timeout
    let tv: [i64; 2] = [timeout_secs as i64, 0];
    unsafe {
        syscall::syscall6(
            syscall::SYS_SETSOCKOPT,
            fd as usize,
            1,
            20,
            tv.as_ptr() as usize,
            16,
            0,
        );
    }

    let sent = unsafe {
        syscall::syscall6(
            syscall::SYS_SENDTO,
            fd as usize,
            udp_req.as_ptr() as usize,
            udp_req.len(),
            0,
            ns_addr as *const syscall::SockaddrIn as usize,
            core::mem::size_of::<syscall::SockaddrIn>(),
        )
    };
    if sent < 0 {
        unsafe {
            syscall::syscall1(syscall::SYS_CLOSE, fd as usize);
        }
        return (
            dns::Parser::new(),
            dns::Header::default(),
            errors::New("sendto: failed"),
        );
    }

    let mut buf = vec![0u8; MAX_DNS_PACKET_SIZE];
    loop {
        let n = unsafe {
            syscall::syscall6(
                syscall::SYS_RECVFROM,
                fd as usize,
                buf.as_mut_ptr() as usize,
                buf.len(),
                0,
                0,
                0,
            )
        };
        if n == -4 {
            continue;
        } // EINTR — Go auto-retries
        if n < 0 {
            unsafe {
                syscall::syscall1(syscall::SYS_CLOSE, fd as usize);
            }
            return (
                dns::Parser::new(),
                dns::Header::default(),
                errors::New("recvfrom: timeout"),
            );
        }
        let recv = &buf[..n as usize];
        let mut p = dns::Parser::new();
        let (h, e) = p.Start(recv.to_vec());
        if e != errors::nil {
            continue;
        }
        let (q, e) = p.Question();
        if e != errors::nil {
            continue;
        }
        if !check_response(id, query, &h, &q) {
            continue;
        }
        unsafe {
            syscall::syscall1(syscall::SYS_CLOSE, fd as usize);
        }
        return (p, h, errors::nil);
    }
}

/// Read exactly `n` bytes from TCP fd into buf starting at `off`.
fn tcp_read_exact_n(fd: i32, buf: &mut Vec<u8>, n: usize) -> bool {
    let start = buf.len();
    buf.resize(start + n, 0u8);
    let mut off = 0usize;
    while off < n {
        let r = unsafe {
            syscall::syscall3(
                syscall::SYS_READ,
                fd as usize,
                buf.as_mut_ptr() as usize + start + off,
                n - off,
            ) as isize
        };
        if r == -4 {
            continue;
        } // EINTR — Go auto-retries
        if r <= 0 {
            return false;
        }
        off += r as usize;
    }
    true
}

/// Perform a TCP DNS stream round trip.
fn dns_stream_round_trip(
    ns_addr: &syscall::SockaddrIn,
    id: u16,
    query: &dns::Question,
    tcp_req: &[u8],
    timeout_secs: u64,
) -> (dns::Parser, dns::Header, error) {
    let fd = syscall::Socket(
        syscall::AF_INET,
        syscall::SOCK_STREAM | syscall::SOCK_CLOEXEC,
        syscall::IPPROTO_TCP,
    );
    if fd < 0 {
        return (
            dns::Parser::new(),
            dns::Header::default(),
            errors::New("tcp: socket failed"),
        );
    }

    let tv: [i64; 2] = [timeout_secs as i64, 0];
    unsafe {
        syscall::syscall6(
            syscall::SYS_SETSOCKOPT,
            fd as usize,
            1,
            20,
            tv.as_ptr() as usize,
            16,
            0,
        );
        syscall::syscall6(
            syscall::SYS_SETSOCKOPT,
            fd as usize,
            1,
            21,
            tv.as_ptr() as usize,
            16,
            0,
        );
    }

    let cr = syscall::Connect(
        fd,
        ns_addr,
        core::mem::size_of::<syscall::SockaddrIn>() as u32,
    );
    if cr < 0 {
        unsafe {
            syscall::syscall1(syscall::SYS_CLOSE, fd as usize);
        }
        return (
            dns::Parser::new(),
            dns::Header::default(),
            errors::New("tcp: connect failed"),
        );
    }

    let wn = unsafe {
        syscall::syscall3(
            syscall::SYS_WRITE,
            fd as usize,
            tcp_req.as_ptr() as usize,
            tcp_req.len(),
        ) as isize
    };
    if wn < 0 || (wn as usize) < tcp_req.len() {
        unsafe {
            syscall::syscall1(syscall::SYS_CLOSE, fd as usize);
        }
        return (
            dns::Parser::new(),
            dns::Header::default(),
            errors::New("tcp: write failed"),
        );
    }

    // Read 2-byte length prefix. Per Go runtime, retry on EINTR (-4).
    let mut lenbuf = [0u8; 2];
    let mut loff = 0usize;
    while loff < 2 {
        let r = unsafe {
            syscall::syscall3(
                syscall::SYS_READ,
                fd as usize,
                lenbuf.as_mut_ptr() as usize + loff,
                2 - loff,
            ) as isize
        };
        if r == -4 {
            continue;
        } // EINTR — Go auto-retries
        if r <= 0 {
            dns_debug!(
                crate::gostring::string::from_static(
                    "[dns-debug] tcp: read len failed: read returned "
                ) + crate::strconv::Itoa(r as i64)
                    + crate::gostring::string::from_static(" loff=")
                    + crate::strconv::Itoa(loff as i64)
            );
            unsafe {
                syscall::syscall1(syscall::SYS_CLOSE, fd as usize);
            }
            return (
                dns::Parser::new(),
                dns::Header::default(),
                errors::New("tcp: read len failed"),
            );
        }
        loff += r as usize;
    }
    let rlen = ((lenbuf[0] as usize) << 8) | lenbuf[1] as usize;

    let mut rbuf: Vec<u8> = Vec::with_capacity(rlen);
    rbuf.resize(rlen, 0u8);
    let mut roff = 0usize;
    while roff < rlen {
        let r = unsafe {
            syscall::syscall3(
                syscall::SYS_READ,
                fd as usize,
                rbuf.as_mut_ptr() as usize + roff,
                rlen - roff,
            ) as isize
        };
        if r == -4 {
            continue;
        } // EINTR — Go auto-retries
        if r <= 0 {
            unsafe {
                syscall::syscall1(syscall::SYS_CLOSE, fd as usize);
            }
            return (
                dns::Parser::new(),
                dns::Header::default(),
                errors::New("tcp: read body failed"),
            );
        }
        roff += r as usize;
    }
    unsafe {
        syscall::syscall1(syscall::SYS_CLOSE, fd as usize);
    }

    let mut p = dns::Parser::new();
    let (h, e) = p.Start(rbuf);
    if e != errors::nil {
        return (
            dns::Parser::new(),
            dns::Header::default(),
            errCannotUnmarshalDNSMessage.into(),
        );
    }
    let (q, e) = p.Question();
    if e != errors::nil {
        return (
            dns::Parser::new(),
            dns::Header::default(),
            errCannotUnmarshalDNSMessage.into(),
        );
    }
    if !check_response(id, query, &h, &q) {
        return (
            dns::Parser::new(),
            dns::Header::default(),
            errInvalidDNSResponse.into(),
        );
    }
    (p, h, errors::nil)
}

// ─── exchange ──────────────────────────────────────────────────────────────

/// Sends a DNS query to `server` (ip:port). Tries UDP first; falls back to TCP
/// if the TC (truncated) flag is set. Returns the Parser positioned after the
/// question section.
fn exchange(
    server: &str,
    q: dns::Question,
    timeout_secs: u64,
    use_tcp: bool,
    ad: bool,
) -> (dns::Parser, dns::Header, error) {
    let mut q = q;
    q.Class = dns::ClassINET;

    let (id, udp_req, tcp_req, e) = new_request(q.clone(), ad);
    if e != errors::nil {
        return (
            dns::Parser::new(),
            dns::Header::default(),
            errCannotMarshalDNSMessage.into(),
        );
    }

    let (octets, port) = match parse_server_addr(server) {
        Some(v) => v,
        None => {
            return (
                dns::Parser::new(),
                dns::Header::default(),
                errors::New("dns: unsupported server address format"),
            );
        }
    };
    let ns_addr = syscall::SockaddrIn::ipv4(octets, port);

    if use_tcp {
        // TCP only
        let (mut p, h, e) = dns_stream_round_trip(&ns_addr, id, &q, &tcp_req, timeout_secs);
        if e != errors::nil {
            return (p, h, e);
        }
        let e2 = p.SkipQuestion();
        if e2 != dns::ErrSectionDone {
            return (
                dns::Parser::new(),
                dns::Header::default(),
                errInvalidDNSResponse.into(),
            );
        }
        return (p, h, errors::nil);
    }

    // Try UDP first
    let (mut p, h, e) = dns_packet_round_trip(&ns_addr, id, &q, &udp_req, timeout_secs);
    if e != errors::nil {
        dns_debug!(
            crate::gostring::string::from_static("[dns-debug] UDP failed: ")
                + e.Error()
                + crate::gostring::string::from_static(" — trying TCP fallback")
        );
        // UDP failed — try TCP
        let (mut p2, h2, e2) = dns_stream_round_trip(&ns_addr, id, &q, &tcp_req, timeout_secs);
        if e2 != errors::nil {
            return (dns::Parser::new(), dns::Header::default(), e2);
        }
        let e3 = p2.SkipQuestion();
        if e3 != dns::ErrSectionDone {
            return (
                dns::Parser::new(),
                dns::Header::default(),
                errInvalidDNSResponse.into(),
            );
        }
        return (p2, h2, errors::nil);
    }

    let e2 = p.SkipQuestion();
    if e2 != dns::ErrSectionDone {
        return (
            dns::Parser::new(),
            dns::Header::default(),
            errInvalidDNSResponse.into(),
        );
    }

    // UDP truncated → retry over TCP (RFC 5966)
    if h.Truncated {
        let (mut p2, h2, e2) = dns_stream_round_trip(&ns_addr, id, &q, &tcp_req, timeout_secs);
        if e2 != errors::nil {
            // TCP also failed — return what we got from UDP
            return (p, h, errors::nil);
        }
        let e3 = p2.SkipQuestion();
        if e3 != dns::ErrSectionDone {
            return (
                dns::Parser::new(),
                dns::Header::default(),
                errInvalidDNSResponse.into(),
            );
        }
        return (p2, h2, errors::nil);
    }

    (p, h, errors::nil)
}

// ─── checkHeader ───────────────────────────────────────────────────────────

fn check_header(p: &mut dns::Parser, h: &dns::Header) -> error {
    let (rcode, has_add) = extract_extended_rcode(p.clone(), h.clone());

    if rcode == dns::RCodeNameError {
        return errNoSuchHost.into();
    }

    let (_ah, e) = p.AnswerHeader();
    if e != errors::nil && e != dns::ErrSectionDone {
        return errCannotUnmarshalDNSMessage.into();
    }

    // Lame referral: success but no authority, no recursion, no answers
    if rcode == dns::RCodeSuccess
        && !h.Authoritative
        && !h.RecursionAvailable
        && e == dns::ErrSectionDone
        && !has_add
    {
        return errLameReferral.into();
    }

    if rcode != dns::RCodeSuccess && rcode != dns::RCodeNameError {
        if rcode == dns::RCodeServerFailure {
            return errServerTemporarilyMisbehaving.into();
        }
        return errServerMisbehaving.into();
    }

    errors::nil
}

// ─── extractExtendedRCode ──────────────────────────────────────────────────

fn extract_extended_rcode(mut p: dns::Parser, hdr: dns::Header) -> (dns::RCode, bool) {
    p.SkipAllAnswers();
    p.SkipAllAuthorities();
    let mut has_add = false;
    loop {
        let (ahdr, e) = p.AdditionalHeader();
        if e != errors::nil {
            return (hdr.RCode, has_add);
        }
        has_add = true;
        if ahdr.Type == dns::TypeOPT {
            return (ahdr.ExtendedRCode(hdr.RCode), has_add);
        }
        let e2 = p.SkipAdditional();
        if e2 != errors::nil {
            return (hdr.RCode, has_add);
        }
    }
}

// ─── skipToAnswer ──────────────────────────────────────────────────────────

fn skip_to_answer(p: &mut dns::Parser, qtype: dns::Type) -> error {
    loop {
        let (h, e) = p.AnswerHeader();
        if e == dns::ErrSectionDone {
            return errNoSuchHost.into();
        }
        if e != errors::nil {
            return errCannotUnmarshalDNSMessage.into();
        }
        if h.Type == qtype {
            return errors::nil;
        }
        let e2 = p.SkipAnswer();
        if e2 != errors::nil {
            return errCannotUnmarshalDNSMessage.into();
        }
    }
}

// ─── tryOneName ────────────────────────────────────────────────────────────

/// Try a single FQDN against all configured nameservers × attempts.
/// Returns (Parser, server_used, error).
pub fn try_one_name(cfg: &DnsConfig, name: &str, qtype: dns::Type) -> (dns::Parser, String, error) {
    let mut last_err: error = errors::New("dns: no servers");
    let server_offset = cfg.server_offset();
    let s_len = cfg.servers.len() as u32;
    if s_len == 0 {
        return (dns::Parser::new(), String::new(), last_err);
    }

    let (n, e) = dns::NewName(name);
    if e != errors::nil {
        return (
            dns::Parser::new(),
            String::new(),
            errors::New("dns: invalid name"),
        );
    }
    let q = dns::Question {
        Name: n,
        Type: qtype,
        Class: dns::ClassINET,
    };

    let mut i = 0usize;
    while i < cfg.attempts {
        let mut j: u32 = 0;
        while j < s_len {
            let idx = ((server_offset + j) % s_len) as usize;
            let server = &cfg.servers[idx];

            let (mut p, h, e) = exchange(
                server,
                q.clone(),
                cfg.timeout_secs,
                cfg.use_tcp,
                cfg.trust_ad,
            );
            if e != errors::nil {
                last_err = e;
                j += 1;
                continue;
            }

            let e2 = check_header(&mut p, &h);
            if e2 != errors::nil {
                if e2 == errNoSuchHost {
                    return (p, server.clone(), errNoSuchHost.into());
                }
                last_err = e2;
                j += 1;
                continue;
            }

            let e3 = skip_to_answer(&mut p, qtype);
            if e3 != errors::nil {
                if e3 == errNoSuchHost {
                    return (p, server.clone(), errNoSuchHost.into());
                }
                last_err = e3;
                j += 1;
                continue;
            }

            return (p, server.clone(), errors::nil);
        }
        i += 1;
    }
    (dns::Parser::new(), String::new(), last_err)
}

// ─── lookup ────────────────────────────────────────────────────────────────

/// Look up `name` for record type `qtype`, applying search-domain expansion.
pub fn lookup(cfg: &DnsConfig, name: &str, qtype: dns::Type) -> (dns::Parser, String, error) {
    if !is_domain_name(name) {
        return (dns::Parser::new(), String::new(), errNoSuchHost.into());
    }

    let mut last_p = dns::Parser::new();
    let mut last_server = String::new();
    let mut last_err: error = errNoSuchHost.into();

    for fqdn in cfg.name_list(name) {
        let (p, server, e) = try_one_name(cfg, &fqdn, qtype);
        if e == errors::nil {
            return (p, server, errors::nil);
        }
        last_p = p;
        last_server = server;
        last_err = e;
    }
    (last_p, last_server, last_err)
}

// ─── isDomainName (verbatim from Go) ──────────────────────────────────────

fn is_domain_name(s: &str) -> bool {
    if s == "." {
        return true;
    }
    let l = s.len();
    let s = s.as_bytes();
    if l == 0 || l > 254 || (l == 254 && s[l - 1] != b'.') {
        return false;
    }
    let mut last = b'.';
    let mut non_numeric = false;
    let mut part_len = 0usize;
    for i in 0..l {
        let c = s[i];
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

// ─── IPAddr ────────────────────────────────────────────────────────────────

/// A resolved IP address (IPv4 or IPv6).
#[derive(Clone, Debug)]
pub struct IPAddr {
    /// Raw IP bytes — 4 for IPv4, 16 for IPv6.
    pub ip: Vec<u8>,
}

impl IPAddr {
    pub fn is_ipv4(&self) -> bool {
        self.ip.len() == 4
    }
    pub fn as_ipv4(&self) -> Option<[u8; 4]> {
        if self.ip.len() == 4 {
            let mut a = [0u8; 4];
            a.copy_from_slice(&self.ip);
            Some(a)
        } else {
            None
        }
    }
}

// ─── goLookupIPCNAMEOrder ──────────────────────────────────────────────────

/// Perform both A and AAAA queries (sequentially; Goish goroutine channel
/// overhead in no_std is heavier than two sequential syscalls, so we do
/// them one after the other which mirrors Go's `single_request` path).
///
/// Returns (addrs, cname_str, error).
pub fn go_lookup_ip_cname_order(
    cfg: &DnsConfig,
    network: &str, // "ip", "ip4", "ip6", or "CNAME"
    name: &str,
) -> (Vec<IPAddr>, String, error) {
    // Determine which qtypes to query
    let qtypes: &[dns::Type] = match network_ip_version(network) {
        b'4' => &[dns::TypeA],
        b'6' => &[dns::TypeAAAA],
        _ => &[dns::TypeA, dns::TypeAAAA],
    };

    let mut addrs: Vec<IPAddr> = Vec::new();
    let mut cname = String::new();
    let mut last_err: error = errors::nil;

    for fqdn_str in cfg.name_list(name) {
        let fqdn = fqdn_str.as_str();
        let mut got_answer = false;

        for &qtype in qtypes {
            let (mut p, _server, e) = try_one_name(cfg, fqdn, qtype);
            if e != errors::nil {
                // Check if fqdn_str == name + "."
                let name_dot = {
                    let mut s = String::from(name);
                    s.push('.');
                    s
                };
                if last_err == errors::nil || fqdn_str == name_dot {
                    last_err = e;
                }
                continue;
            }

            // Parse answers
            'answer_loop: loop {
                let (h, e) = p.AnswerHeader();
                if e == dns::ErrSectionDone {
                    break 'answer_loop;
                }
                if e != errors::nil {
                    break 'answer_loop;
                }

                match h.Type {
                    dns::TypeA => {
                        let (a, e2) = p.AResource();
                        if e2 != errors::nil {
                            break 'answer_loop;
                        }
                        addrs.push(IPAddr { ip: a.A.to_vec() });
                        if cname.is_empty() && h.Name.Length > 0 {
                            let s = core::str::from_utf8(&h.Name.Data[..h.Name.Length as usize])
                                .unwrap_or("");
                            cname = String::from(s);
                        }
                        got_answer = true;
                    }
                    dns::TypeAAAA => {
                        let (a, e2) = p.AAAAResource();
                        if e2 != errors::nil {
                            break 'answer_loop;
                        }
                        addrs.push(IPAddr {
                            ip: a.AAAA.to_vec(),
                        });
                        if cname.is_empty() && h.Name.Length > 0 {
                            let s = core::str::from_utf8(&h.Name.Data[..h.Name.Length as usize])
                                .unwrap_or("");
                            cname = String::from(s);
                        }
                        got_answer = true;
                    }
                    dns::TypeCNAME => {
                        let (c, e2) = p.CNAMEResource();
                        if e2 != errors::nil {
                            break 'answer_loop;
                        }
                        if cname.is_empty() && c.CNAME.Length > 0 {
                            let s = core::str::from_utf8(&c.CNAME.Data[..c.CNAME.Length as usize])
                                .unwrap_or("");
                            cname = String::from(s);
                        }
                    }
                    _ => {
                        let e2 = p.SkipAnswer();
                        if e2 != errors::nil {
                            break 'answer_loop;
                        }
                    }
                }
            }
        }

        if !addrs.is_empty() {
            break;
        }
        if got_answer {
            break;
        }
    }

    // Sort addrs: IPv4 first, then IPv6 (simplified RFC 6724)
    addrs.sort_by(|a, b| {
        let a4 = if a.ip.len() == 4 { 0 } else { 1 };
        let b4 = if b.ip.len() == 4 { 0 } else { 1 };
        a4.cmp(&b4)
    });

    if addrs.is_empty() && last_err != errors::nil {
        return (Vec::new(), cname, last_err);
    }

    (addrs, cname, errors::nil)
}

fn network_ip_version(network: &str) -> u8 {
    if network.is_empty() {
        return 0;
    }
    let last = network.as_bytes()[network.len() - 1];
    if last == b'4' || last == b'6' {
        last
    } else {
        0
    }
}

// ─── Public API ────────────────────────────────────────────────────────────

/// Get the system DNS config (reads /etc/resolv.conf each call — no caching
/// for simplicity; Go does caching with mtime checking).
pub fn get_system_dns_config() -> DnsConfig {
    dns_read_config("/etc/resolv.conf")
}

/// LookupHost resolves `host` to a list of IP address strings.
/// Returns (["ip1", "ip2", ...], error).
pub fn lookup_host(host: &str) -> (Vec<String>, error) {
    if host.is_empty() {
        return (Vec::new(), errNoSuchHost.into());
    }
    // Already an IP literal?
    if let Some(ip) = parse_ip_literal(host) {
        let s = ip_to_string(&ip);
        return (vec![s], errors::nil);
    }
    let cfg = get_system_dns_config();
    let (addrs, _cname, e) = go_lookup_ip_cname_order(&cfg, "ip", host);
    if e != errors::nil {
        return (Vec::new(), e);
    }
    let strs: Vec<String> = addrs.iter().map(|a| ip_to_string(&a.ip)).collect();
    (strs, errors::nil)
}

/// LookupA resolves `host` to its first IPv4 address.
/// Used by parse.rs::parse_dial_addr.
pub fn lookup_a(host: &str) -> Result<[u8; 4], string> {
    // Already an IPv4 literal?
    if let Some(ip) = parse_ip_literal(host) {
        if ip.len() == 4 {
            let mut a = [0u8; 4];
            a.copy_from_slice(&ip);
            return Ok(a);
        }
    }

    let cfg = get_system_dns_config();
    let (addrs, _cname, e) = go_lookup_ip_cname_order(&cfg, "ip4", host);
    if e != errors::nil {
        dns_debug!(
            crate::gostring::string::from_static("[dns-debug] go_lookup_ip_cname_order err=")
                + e.Error()
                + crate::gostring::string::from_static(" host=")
                + crate::gostring::string::from_bytes(host.as_bytes())
        );
        let msg = e.Error();
        return Err(msg);
    }
    for addr in &addrs {
        if let Some(v4) = addr.as_ipv4() {
            return Ok(v4);
        }
    }
    Err(crate::gostring::string::from_static(
        "net: dns: no such host",
    ))
}

/// Parse an IP literal (IPv4 or IPv6 in bracket form) — no DNS.
fn parse_ip_literal(s: &str) -> Option<Vec<u8>> {
    // Try IPv4
    let parts: Vec<&str> = s.split('.').collect();
    if parts.len() == 4 {
        let mut ok = true;
        let mut octets = [0u8; 4];
        for (i, p) in parts.iter().enumerate() {
            match p.parse::<u8>() {
                Ok(v) => octets[i] = v,
                Err(_) => {
                    ok = false;
                    break;
                }
            }
        }
        if ok {
            return Some(octets.to_vec());
        }
    }
    // IPv6 bracket form or bare — not supported yet
    None
}

fn u8_to_decimal(n: u8, buf: &mut [u8; 3]) -> &[u8] {
    if n >= 100 {
        buf[0] = b'0' + n / 100;
        buf[1] = b'0' + (n / 10) % 10;
        buf[2] = b'0' + n % 10;
        &buf[..3]
    } else if n >= 10 {
        buf[0] = b'0' + n / 10;
        buf[1] = b'0' + n % 10;
        &buf[..2]
    } else {
        buf[0] = b'0' + n;
        &buf[..1]
    }
}

fn ip_to_string(ip: &[u8]) -> String {
    if ip.len() == 4 {
        let mut s = String::new();
        let mut tmp = [0u8; 3];
        s.push_str(core::str::from_utf8(u8_to_decimal(ip[0], &mut tmp)).unwrap_or("0"));
        s.push('.');
        s.push_str(core::str::from_utf8(u8_to_decimal(ip[1], &mut tmp)).unwrap_or("0"));
        s.push('.');
        s.push_str(core::str::from_utf8(u8_to_decimal(ip[2], &mut tmp)).unwrap_or("0"));
        s.push('.');
        s.push_str(core::str::from_utf8(u8_to_decimal(ip[3], &mut tmp)).unwrap_or("0"));
        s
    } else {
        // Very basic IPv6 hex representation
        let mut s = String::new();
        for (i, chunk) in ip.chunks(2).enumerate() {
            if i > 0 {
                s.push(':');
            }
            let v = ((chunk[0] as u16) << 8) | chunk[1] as u16;
            let hex: Vec<u8> = {
                let mut h = Vec::new();
                let digits = b"0123456789abcdef";
                h.push(digits[((v >> 12) & 0xF) as usize]);
                h.push(digits[((v >> 8) & 0xF) as usize]);
                h.push(digits[((v >> 4) & 0xF) as usize]);
                h.push(digits[(v & 0xF) as usize]);
                h
            };
            s.push_str(core::str::from_utf8(&hex).unwrap_or(""));
        }
        s
    }
}
