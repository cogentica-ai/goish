// net::parse — TCPAddr type + "host:port" parsers.
//
// IPv4 literals only in v1. `host` may be empty (binds wildcard for
// Listen) or a dotted-decimal IPv4 (`127.0.0.1`, `0.0.0.0`).
// Hostnames (no DNS in v1) and IPv6 literals (no IPv6 sockaddr yet)
// return errors at the parse boundary.
//
// Public surface: `TCPAddr` is the `net.TCPAddr` Go type but slim.

extern crate alloc;

use alloc::vec::Vec;

use crate::string;
use crate::syscall;
use crate::types::int;

/// `net.TCPAddr`. Slim port — IPv4 only in v1; `Zone` (link-local
/// scope) is omitted.
#[derive(Clone)]
#[allow(non_snake_case)]
pub struct TCPAddr {
    /// 4 IPv4 octets in big-endian (network) byte order from the
    /// user's perspective: `IP[0]` is the high octet (e.g. `127`
    /// for `127.0.0.1`).
    pub IP: [u8; 4],
    pub Port: int,
}

impl TCPAddr {
    pub(crate) const fn zero() -> Self {
        TCPAddr {
            IP: [0, 0, 0, 0],
            Port: 0,
        }
    }

    /// Build from a kernel `sockaddr_in`.
    pub(crate) fn from_sockaddr_in(s: &syscall::SockaddrIn) -> Self {
        // sin_addr is in network byte order. Convert to host order
        // first, then split into octets in big-endian display order.
        let host = syscall::ntohl(s.sin_addr);
        TCPAddr {
            IP: [
                ((host >> 24) & 0xFF) as u8,
                ((host >> 16) & 0xFF) as u8,
                ((host >> 8) & 0xFF) as u8,
                (host & 0xFF) as u8,
            ],
            Port: s.port_host() as int,
        }
    }

    /// `String()` — render as `"a.b.c.d:port"`.
    pub fn String(&self) -> string {
        let mut buf: Vec<u8> = Vec::with_capacity(24);
        push_dec(&mut buf, self.IP[0] as u32);
        buf.push(b'.');
        push_dec(&mut buf, self.IP[1] as u32);
        buf.push(b'.');
        push_dec(&mut buf, self.IP[2] as u32);
        buf.push(b'.');
        push_dec(&mut buf, self.IP[3] as u32);
        buf.push(b':');
        push_dec(&mut buf, self.Port as u32);
        string::from_bytes(&buf)
    }

    /// Network family. Always `"tcp"` in v1.
    pub fn Network(&self) -> string {
        string("tcp")
    }
}

fn push_dec(buf: &mut Vec<u8>, mut n: u32) {
    if n == 0 {
        buf.push(b'0');
        return;
    }
    let mut tmp = [0u8; 10];
    let mut i = 0;
    while n > 0 {
        tmp[i] = b'0' + (n % 10) as u8;
        n /= 10;
        i += 1;
    }
    while i > 0 {
        i -= 1;
        buf.push(tmp[i]);
    }
}

// ─── parsers ─────────────────────────────────────────────────────────

/// Parse a `Listen` address. Empty host means INADDR_ANY; the port
/// must be present (`:0` allowed = kernel picks). Returns a kernel
/// `sockaddr_in` ready for `bind(2)`, or an error message.
pub(crate) fn parse_listen_addr(s: &string) -> Result<syscall::SockaddrIn, string> {
    let bytes = s.as_bytes();
    let (host, port) = split_host_port(bytes)?;
    let addr = if host.is_empty() {
        syscall::INADDR_ANY
    } else {
        let octets = parse_ipv4(host)?;
        ((octets[0] as u32) << 24)
            | ((octets[1] as u32) << 16)
            | ((octets[2] as u32) << 8)
            | (octets[3] as u32)
    };
    Ok(syscall::SockaddrIn {
        sin_family: syscall::AF_INET as u16,
        sin_port: syscall::htons(port),
        sin_addr: syscall::htonl(addr),
        _pad: [0; 8],
    })
}

/// Parse a `Dial` address. Accepts IPv4 literals and DNS hostnames.
/// For hostnames, performs a DNS A-record lookup via /etc/resolv.conf.
pub(crate) fn parse_dial_addr(s: &string) -> Result<syscall::SockaddrIn, string> {
    let bytes = s.as_bytes();
    let (host, port) = split_host_port(bytes)?;
    if host.is_empty() {
        return Err(string("net: dial: missing host"));
    }
    if port == 0 {
        return Err(string("net: dial: port 0 is not valid for dial"));
    }
    // Try IPv4 literal first.
    let addr = match parse_ipv4(host) {
        Ok(octets) => {
            ((octets[0] as u32) << 24)
                | ((octets[1] as u32) << 16)
                | ((octets[2] as u32) << 8)
                | (octets[3] as u32)
        }
        Err(_) => {
            // Not an IPv4 literal — try DNS resolution.
            let hostname = match core::str::from_utf8(host) {
                Ok(s) => s,
                Err(_) => return Err(string("net: invalid hostname (non-UTF8)")),
            };
            match crate::net::dnsclient::lookup_a(hostname) {
                Ok(octets) => {
                    ((octets[0] as u32) << 24)
                        | ((octets[1] as u32) << 16)
                        | ((octets[2] as u32) << 8)
                        | (octets[3] as u32)
                }
                Err(e) => return Err(e),
            }
        }
    };
    Ok(syscall::SockaddrIn {
        sin_family: syscall::AF_INET as u16,
        sin_port: syscall::htons(port),
        sin_addr: syscall::htonl(addr),
        _pad: [0; 8],
    })
}

/// DnsConfig holds parsed /etc/resolv.conf settings used by the DNS resolver.
struct DnsConfig {
    /// Nameserver IP addresses (up to 3), in dotted-decimal form read from resolv.conf.
    nameservers: Vec<[u8; 4]>,
    /// Search domains (for single-label or ndots-below-threshold hostnames).
    search: Vec<Vec<u8>>,
    /// ndots threshold: hostnames with fewer dots than ndots get search domain expansion.
    ndots: usize,
    /// Number of query attempts per nameserver.
    attempts: usize,
}

impl DnsConfig {
    fn default() -> Self {
        DnsConfig {
            nameservers: Vec::new(),
            search: Vec::new(),
            ndots: 1,
            attempts: 2,
        }
    }
}

/// Read and parse /etc/resolv.conf.
fn read_resolv_conf() -> DnsConfig {
    let mut cfg = DnsConfig::default();

    // Read file
    let path = b"/etc/resolv.conf\0";
    let fd = unsafe {
        syscall::syscall3(syscall::SYS_OPEN, path.as_ptr() as usize, 0, 0) as i32
    };
    if fd < 0 {
        return cfg;
    }

    // Read up to 4096 bytes (covers long Kubernetes resolv.conf)
    let mut contents = [0u8; 4096];
    let n = unsafe {
        syscall::syscall3(syscall::SYS_READ, fd as usize, contents.as_mut_ptr() as usize, 4096) as isize
    };
    let _ = unsafe { syscall::syscall1(syscall::SYS_CLOSE, fd as usize) };

    if n <= 0 {
        return cfg;
    }
    let text = &contents[..n as usize];

    for raw_line in text.split(|&b| b == b'\n') {
        let line = trim_ascii(raw_line);
        if line.is_empty() || line[0] == b';' || line[0] == b'#' {
            continue;
        }
        let fields: Vec<&[u8]> = line.split(|&b| b == b' ' || b == b'\t')
            .filter(|f| !f.is_empty())
            .collect();
        if fields.is_empty() {
            continue;
        }

        if fields[0] == b"nameserver" && fields.len() > 1 && cfg.nameservers.len() < 3 {
            if let Ok(octets) = parse_ipv4(fields[1]) {
                cfg.nameservers.push(octets);
            }
        } else if (fields[0] == b"domain" || fields[0] == b"search") && fields.len() > 1 {
            if fields[0] == b"domain" {
                // domain replaces search list with single entry
                cfg.search.clear();
                let mut s = fields[1].to_vec();
                if s.last() != Some(&b'.') {
                    s.push(b'.');
                }
                cfg.search.push(s);
            } else {
                // search sets list
                cfg.search.clear();
                for &sf in &fields[1..] {
                    let mut s = sf.to_vec();
                    if s.last() != Some(&b'.') {
                        s.push(b'.');
                    }
                    cfg.search.push(s);
                }
            }
        } else if fields[0] == b"options" {
            for &opt in &fields[1..] {
                if opt.starts_with(b"ndots:") {
                    let v = &opt[6..];
                    let mut n: usize = 0;
                    for &c in v {
                        if c >= b'0' && c <= b'9' {
                            n = n * 10 + (c - b'0') as usize;
                        }
                    }
                    if n > 15 { n = 15; }
                    cfg.ndots = n;
                } else if opt.starts_with(b"attempts:") {
                    let v = &opt[9..];
                    let mut n: usize = 0;
                    for &c in v {
                        if c >= b'0' && c <= b'9' {
                            n = n * 10 + (c - b'0') as usize;
                        }
                    }
                    if n >= 1 { cfg.attempts = n; }
                }
            }
        }
    }

    cfg
}

/// Write a debug message to stderr using raw syscall (for DNS tracing).
#[allow(dead_code)]
fn dns_debug(msg: &[u8]) {
    unsafe {
        syscall::syscall3(syscall::SYS_WRITE, 2, msg.as_ptr() as usize, msg.len());
    }
}

/// DNS A-record lookup for a hostname.
/// Reads /etc/resolv.conf for nameservers and search domains.
/// Tries UDP first; falls back to TCP if UDP times out or is truncated.
/// Applies ndots-based search domain expansion (matches Go's net package behavior).
fn dns_lookup_a(hostname: &str) -> Result<[u8; 4], string> {
    let cfg = read_resolv_conf();

    if cfg.nameservers.is_empty() {
        // Fallback to 127.0.0.1 if resolv.conf has no nameservers.
        return dns_lookup_a_with_ns([127, 0, 0, 1], hostname, cfg.attempts);
    }

    // Build the list of FQDNs to try (search domain expansion).
    // Mirrors Go's dnsConfig.nameList():
    //   - If hostname ends with '.', use as-is (already absolute).
    //   - If dotCount(hostname) >= ndots, try unsuffixed first, then search list.
    //   - Otherwise, try search list first, then unsuffixed.
    let hostname_bytes = hostname.as_bytes();
    let dot_count = hostname_bytes.iter().filter(|&&b| b == b'.').count();
    let rooted = hostname_bytes.last() == Some(&b'.');

    let fqdns: Vec<Vec<u8>> = if rooted {
        // Already absolute — try once as-is.
        { let mut v: Vec<Vec<u8>> = Vec::new(); v.push(hostname_bytes.to_vec()); v }
    } else {
        let mut list: Vec<Vec<u8>> = Vec::new();
        let has_ndots = dot_count >= cfg.ndots;
        // Absolute form (append '.')
        let mut abs: Vec<u8> = hostname_bytes.to_vec();
        abs.push(b'.');

        if has_ndots {
            list.push(abs.clone());
        }
        // Search domain suffixes
        for sfx in &cfg.search {
            let mut candidate: Vec<u8> = hostname_bytes.to_vec();
            candidate.push(b'.');
            candidate.extend_from_slice(sfx.as_slice());
            // Ensure it ends with '.'
            if candidate.last() != Some(&b'.') {
                candidate.push(b'.');
            }
            list.push(candidate);
        }
        if !has_ndots {
            list.push(abs);
        }
        list
    };

    let mut last_err = string("net: dns: no such host");
    'outer: for fqdn in &fqdns {
        let fqdn_str = match core::str::from_utf8(fqdn.as_slice()) {
            Ok(s) => s,
            Err(_) => continue,
        };
        // Strip trailing dot for label encoding (build_dns_query adds it via root label 0)
        let qname = if fqdn_str.ends_with('.') {
            &fqdn_str[..fqdn_str.len() - 1]
        } else {
            fqdn_str
        };

        for &ns_ip in &cfg.nameservers {
            // Debug: print which FQDN and NS we're querying.
            dns_debug(b"[dns] query fqdn=");
            dns_debug(qname.as_bytes());
            dns_debug(b" ns=");
            let ns_str = [
                b'0' + ns_ip[0] / 100, b'0' + (ns_ip[0] / 10) % 10, b'0' + ns_ip[0] % 10,
                b'.', b'0' + ns_ip[1] / 100, b'0' + (ns_ip[1] / 10) % 10, b'0' + ns_ip[1] % 10,
                b'.', b'0' + ns_ip[2] / 100, b'0' + (ns_ip[2] / 10) % 10, b'0' + ns_ip[2] % 10,
                b'.', b'0' + ns_ip[3] / 100, b'0' + (ns_ip[3] / 10) % 10, b'0' + ns_ip[3] % 10,
            ];
            dns_debug(&ns_str);
            dns_debug(b"\n");
            match dns_lookup_a_with_ns(ns_ip, qname, cfg.attempts) {
                Ok(ip) => {
                    dns_debug(b"[dns] ok fqdn=");
                    dns_debug(qname.as_bytes());
                    dns_debug(b"\n");
                    return Ok(ip);
                }
                Err(ref e) if e == "net: dns: no such host" => {
                    // NXDOMAIN: this FQDN doesn't exist; try next search suffix.
                    dns_debug(b"[dns] nxdomain fqdn=");
                    dns_debug(qname.as_bytes());
                    dns_debug(b"\n");
                    last_err = e.clone();
                    continue 'outer;
                }
                Err(e) => {
                    // Transient error (SERVFAIL, timeout) — try next nameserver.
                    dns_debug(b"[dns] error fqdn=");
                    dns_debug(qname.as_bytes());
                    dns_debug(b" err=");
                    dns_debug(e.as_bytes());
                    dns_debug(b"\n");
                    last_err = e;
                }
            }
        }
    }
    dns_debug(b"[dns] giving up, last_err=");
    dns_debug(last_err.as_bytes());
    dns_debug(b"\n");
    Err(last_err)
}

/// Perform a DNS A-record lookup against a specific nameserver.
/// Tries UDP first; falls back to TCP on timeout or truncation.
fn dns_lookup_a_with_ns(ns_ip: [u8; 4], hostname: &str, attempts: usize) -> Result<[u8; 4], string> {
    let ns_addr = syscall::SockaddrIn::ipv4(ns_ip, 53);
    let ns_addr_size = core::mem::size_of::<syscall::SockaddrIn>();

    // Use a simple query ID derived from the hostname (low 16 bits of XOR hash).
    let mut qid: u16 = 0x1234;
    for (i, &b) in hostname.as_bytes().iter().enumerate() {
        qid = qid.wrapping_add((b as u16).wrapping_mul(i as u16 + 1));
    }
    // Fold in a coarse time value from the monotonic clock for randomness.
    // We use SYS_CLOCK_GETTIME (228 on x86-64) with CLOCK_MONOTONIC (1).
    let mut ts: [i64; 2] = [0, 0];
    unsafe {
        syscall::syscall2(228, 1, ts.as_mut_ptr() as usize);
    }
    qid = qid.wrapping_add(ts[1] as u16);

    let query = build_dns_query_with_id(hostname, qid);
    let mut last_err = string("net: dns: no attempts made");

    for _attempt in 0..attempts.max(1) {
        // ── UDP attempt ─────────────────────────────────────────────────
        let udp_fd = syscall::Socket(syscall::AF_INET, syscall::SOCK_DGRAM, syscall::IPPROTO_UDP);
        if udp_fd >= 0 {
            // Set receive timeout: 3 seconds (SOL_SOCKET=1, SO_RCVTIMEO_OLD=20).
            let timeval: [i64; 2] = [3, 0];
            unsafe {
                syscall::syscall6(
                    syscall::SYS_SETSOCKOPT,
                    udp_fd as usize,
                    1,  // SOL_SOCKET
                    20, // SO_RCVTIMEO_OLD
                    timeval.as_ptr() as usize,
                    16,
                    0,
                );
            }

            let sent = unsafe {
                syscall::syscall6(
                    syscall::SYS_SENDTO,
                    udp_fd as usize,
                    query.as_ptr() as usize,
                    query.len(),
                    0,
                    &ns_addr as *const syscall::SockaddrIn as usize,
                    ns_addr_size,
                )
            };

            if sent >= 0 {
                let mut buf = [0u8; 4096];
                let mut src_addr = syscall::SockaddrIn::any(0);
                let mut src_len: u32 = core::mem::size_of::<syscall::SockaddrIn>() as u32;
                let received = unsafe {
                    syscall::syscall6(
                        syscall::SYS_RECVFROM,
                        udp_fd as usize,
                        buf.as_mut_ptr() as usize,
                        buf.len(),
                        0,
                        &mut src_addr as *mut syscall::SockaddrIn as usize,
                        &mut src_len as *mut u32 as usize,
                    )
                };
                let _ = unsafe { syscall::syscall1(syscall::SYS_CLOSE, udp_fd as usize) };

                if received >= 0 {
                    let resp_len = received as usize;
                    // Check for TC (truncated) bit — fall through to TCP.
                    let truncated = resp_len >= 4 && ((buf[2] >> 1) & 1) != 0;
                    if !truncated {
                        match parse_dns_a_response(&buf[..resp_len], hostname) {
                            Ok(ip) => return Ok(ip),
                            Err(ref e) if e == "net: dns: no such host" => return Err(e.clone()),
                            Err(ref e) if e == "net: dns: server returned error" => {
                                // SERVFAIL — fall through to TCP for this attempt.
                                last_err = e.clone();
                            }
                            Err(e) => { last_err = e; }
                        }
                    }
                    // TC set or SERVFAIL — fall through to TCP.
                } else {
                    // recvfrom error / timeout — fall through to TCP.
                    last_err = string("net: dns: udp timeout");
                    let _ = unsafe { syscall::syscall1(syscall::SYS_CLOSE, udp_fd as usize) };
                }
            } else {
                let _ = unsafe { syscall::syscall1(syscall::SYS_CLOSE, udp_fd as usize) };
                last_err = string("net: dns: sendto failed");
            }
        } else {
            last_err = string("net: dns: socket failed");
        }

        // ── TCP fallback ────────────────────────────────────────────────
        // RFC 7766: DNS over TCP. Framed with 2-byte length prefix.
        let tcp_fd = syscall::Socket(
            syscall::AF_INET,
            syscall::SOCK_STREAM | syscall::SOCK_CLOEXEC,
            syscall::IPPROTO_TCP,
        );
        if tcp_fd < 0 {
            last_err = string("net: dns: tcp socket failed");
            continue;
        }

        // Set connect + receive timeout via SO_RCVTIMEO / SO_SNDTIMEO.
        let tv5: [i64; 2] = [5, 0];
        unsafe {
            // SO_SNDTIMEO_OLD = 21
            syscall::syscall6(
                syscall::SYS_SETSOCKOPT,
                tcp_fd as usize,
                1, 21,
                tv5.as_ptr() as usize,
                16, 0,
            );
            syscall::syscall6(
                syscall::SYS_SETSOCKOPT,
                tcp_fd as usize,
                1, 20,
                tv5.as_ptr() as usize,
                16, 0,
            );
        }

        let cr = syscall::Connect(
            tcp_fd,
            &ns_addr,
            core::mem::size_of::<syscall::SockaddrIn>() as u32,
        );
        if cr < 0 {
            let _ = unsafe { syscall::syscall1(syscall::SYS_CLOSE, tcp_fd as usize) };
            last_err = string("net: dns: tcp connect failed");
            continue;
        }

        // Build TCP-framed query: 2-byte big-endian length prefix.
        let mut tcp_query: Vec<u8> = Vec::with_capacity(query.len() + 2);
        let qlen = query.len() as u16;
        tcp_query.push((qlen >> 8) as u8);
        tcp_query.push((qlen & 0xff) as u8);
        tcp_query.extend_from_slice(&query);

        let wn = unsafe {
            syscall::syscall3(
                syscall::SYS_WRITE,
                tcp_fd as usize,
                tcp_query.as_ptr() as usize,
                tcp_query.len(),
            )
        };
        if wn < 0 || (wn as usize) < tcp_query.len() {
            let _ = unsafe { syscall::syscall1(syscall::SYS_CLOSE, tcp_fd as usize) };
            last_err = string("net: dns: tcp send failed");
            continue;
        }

        // Read 2-byte length prefix.
        let mut lenbuf = [0u8; 2];
        if !tcp_read_exact(tcp_fd, &mut lenbuf) {
            let _ = unsafe { syscall::syscall1(syscall::SYS_CLOSE, tcp_fd as usize) };
            last_err = string("net: dns: tcp read len failed");
            continue;
        }
        let rlen = ((lenbuf[0] as usize) << 8) | (lenbuf[1] as usize);

        // Read the response body.
        let mut rbuf: Vec<u8> = { let mut v = Vec::with_capacity(rlen); v.resize(rlen, 0u8); v };
        if !tcp_read_exact(tcp_fd, &mut rbuf) {
            let _ = unsafe { syscall::syscall1(syscall::SYS_CLOSE, tcp_fd as usize) };
            last_err = string("net: dns: tcp read body failed");
            continue;
        }
        let _ = unsafe { syscall::syscall1(syscall::SYS_CLOSE, tcp_fd as usize) };

        match parse_dns_a_response(&rbuf, hostname) {
            Ok(ip) => {
                dns_debug(b"[dns] tcp ok rlen=");
                let rlen_bytes = [
                    b'0' + ((rbuf.len() / 100) % 10) as u8,
                    b'0' + ((rbuf.len() / 10) % 10) as u8,
                    b'0' + (rbuf.len() % 10) as u8,
                ];
                dns_debug(&rlen_bytes);
                dns_debug(b"\n");
                return Ok(ip);
            }
            Err(ref e) if e == "net: dns: no such host" => {
                dns_debug(b"[dns] tcp nxdomain rlen=");
                let rlen_bytes = [
                    b'0' + ((rbuf.len() / 100) % 10) as u8,
                    b'0' + ((rbuf.len() / 10) % 10) as u8,
                    b'0' + (rbuf.len() % 10) as u8,
                ];
                dns_debug(&rlen_bytes);
                // Print first few bytes of response for debugging.
                dns_debug(b" hdr=");
                if rbuf.len() >= 12 {
                    let hdr = &rbuf[..12];
                    for &b in hdr.iter() {
                        let hi = b >> 4;
                        let lo = b & 0xf;
                        let hex_nibble = |n: u8| if n < 10 { b'0' + n } else { b'a' + n - 10 };
                        dns_debug(&[hex_nibble(hi), hex_nibble(lo)]);
                    }
                }
                dns_debug(b"\n");
                return Err(e.clone());
            }
            Err(e) => { last_err = e; }
        }
    }
    Err(last_err)
}

/// Read exactly `buf.len()` bytes from a TCP fd. Returns false on error.
fn tcp_read_exact(fd: i32, buf: &mut [u8]) -> bool {
    let mut off = 0usize;
    while off < buf.len() {
        let n = unsafe {
            syscall::syscall3(
                syscall::SYS_READ,
                fd as usize,
                buf.as_mut_ptr() as usize + off,
                buf.len() - off,
            )
        };
        if n <= 0 {
            return false;
        }
        off += n as usize;
    }
    true
}

/// Read the first nameserver IP from /etc/resolv.conf.
/// Returns the 4-byte IPv4 octets, or None if not found.
fn read_nameserver() -> Option<[u8; 4]> {
    // Open /etc/resolv.conf
    let path = b"/etc/resolv.conf\0";
    let fd = unsafe {
        syscall::syscall3(syscall::SYS_OPEN, path.as_ptr() as usize, 0, 0) as i32
    };
    if fd < 0 {
        return None;
    }

    let mut contents = [0u8; 512];
    let n = unsafe {
        syscall::syscall3(syscall::SYS_READ, fd as usize, contents.as_mut_ptr() as usize, 512) as isize
    };
    let _ = unsafe { syscall::syscall1(syscall::SYS_CLOSE, fd as usize) };

    if n <= 0 {
        return None;
    }
    let text = &contents[..n as usize];

    // Search for "nameserver <IP>" lines.
    for line in text.split(|&b| b == b'\n') {
        let line = trim_ascii(line);
        if line.starts_with(b"nameserver") {
            let rest = &line[10..]; // skip "nameserver"
            let rest = trim_ascii_left(rest);
            if let Ok(octets) = parse_ipv4(rest) {
                return Some(octets);
            }
        }
    }
    None
}

fn trim_ascii(s: &[u8]) -> &[u8] {
    trim_ascii_right(trim_ascii_left(s))
}

fn trim_ascii_left(s: &[u8]) -> &[u8] {
    let mut i = 0;
    while i < s.len() && (s[i] == b' ' || s[i] == b'\t') {
        i += 1;
    }
    &s[i..]
}

fn trim_ascii_right(s: &[u8]) -> &[u8] {
    let mut i = s.len();
    while i > 0 && (s[i-1] == b' ' || s[i-1] == b'\t' || s[i-1] == b'\r') {
        i -= 1;
    }
    &s[..i]
}

/// Build a minimal DNS query packet for A records with EDNS0.
/// Matches Go's default resolver behavior: RD=1, EDNS0 OPT record (maxDNSPacketSize=1232).
/// The hostname is always treated as FQDN (absolute), bypassing search-domain expansion.
fn build_dns_query(hostname: &str) -> alloc::vec::Vec<u8> {
    build_dns_query_with_id(hostname, 0x1234)
}

/// Build a DNS query packet with a specific 16-bit query ID.
fn build_dns_query_with_id(hostname: &str, id: u16) -> alloc::vec::Vec<u8> {
    let mut pkt: alloc::vec::Vec<u8> = alloc::vec::Vec::new();
    // Header: ID
    pkt.push((id >> 8) as u8); pkt.push((id & 0xff) as u8);
    // Flags: QR=0 (query), OPCODE=0 (standard), RD=1 (recursion desired)
    pkt.push(0x01); pkt.push(0x00);
    // QDCOUNT=1
    pkt.push(0x00); pkt.push(0x01);
    // ANCOUNT=0
    pkt.push(0x00); pkt.push(0x00);
    // NSCOUNT=0
    pkt.push(0x00); pkt.push(0x00);
    // ARCOUNT=1 (for EDNS0 OPT record)
    pkt.push(0x00); pkt.push(0x01);

    // Question QNAME: encode hostname as DNS labels (always FQDN — strip trailing dot if any).
    // e.g. "stefanprodan.github.io" → \x0Cstefanprodan\x06github\x02io\x00
    let host = if hostname.ends_with('.') { &hostname[..hostname.len()-1] } else { hostname };
    for part in host.split('.') {
        if part.is_empty() { continue; }
        let b = part.as_bytes();
        pkt.push(b.len() as u8);
        for &c in b {
            pkt.push(c);
        }
    }
    pkt.push(0); // root label (terminates QNAME)

    // QTYPE = A (1)
    pkt.push(0x00); pkt.push(0x01);
    // QCLASS = IN (1)
    pkt.push(0x00); pkt.push(0x01);

    // EDNS0 OPT record (Go's net package sends this by default, RFC 6891).
    // NAME = root (0x00), TYPE = OPT (0x0029), CLASS = 1232 (payload size),
    // TTL = 0 (extended RCODE + flags), RDLENGTH = 0 (no options).
    pkt.push(0x00);         // NAME = root
    pkt.push(0x00); pkt.push(0x29); // TYPE = OPT (41)
    pkt.push(0x04); pkt.push(0xD0); // CLASS = 1232 (maxDNSPacketSize, matches Go)
    pkt.push(0x00); pkt.push(0x00); pkt.push(0x00); pkt.push(0x00); // TTL = 0
    pkt.push(0x00); pkt.push(0x00); // RDLENGTH = 0

    pkt
}

/// Parse a DNS response and return the first A record's IPv4 address.
fn parse_dns_a_response(buf: &[u8], _hostname: &str) -> Result<[u8; 4], string> {
    // DNS response must be at least 12 bytes (header).
    if buf.len() < 12 {
        return Err(string("net: dns: response too short"));
    }

    // Check QR bit = 1 (response) and RCODE = 0 (no error).
    let flags = ((buf[2] as u16) << 8) | buf[3] as u16;
    let _qr = (flags >> 15) & 1;
    let rcode = flags & 0x000F;
    if rcode != 0 {
        // RCODE=3 = NXDOMAIN (name does not exist)
        // RCODE=2 = SERVFAIL
        if rcode == 3 {
            return Err(string("net: dns: no such host"));
        }
        return Err(string("net: dns: server returned error"));
    }

    let qdcount = ((buf[4] as u16) << 8) | buf[5] as u16;
    let ancount = ((buf[6] as u16) << 8) | buf[7] as u16;

    if ancount == 0 {
        return Err(string("net: dns: no answers in response"));
    }

    // Skip the header (12 bytes).
    let mut pos: usize = 12;

    // Skip questions section: QDCOUNT question entries.
    for _ in 0..qdcount {
        // Skip QNAME (sequence of length-prefixed labels, ending with 0).
        pos = skip_dns_name(buf, pos)?;
        // Skip QTYPE (2) + QCLASS (2).
        pos += 4;
        if pos > buf.len() {
            return Err(string("net: dns: malformed response (questions)"));
        }
    }

    // Parse answers section: look for the first A record (type=1, class=1).
    for _ in 0..ancount {
        // Skip NAME.
        pos = skip_dns_name(buf, pos)?;
        if pos + 10 > buf.len() {
            return Err(string("net: dns: malformed response (answer header)"));
        }
        let rtype = ((buf[pos] as u16) << 8) | buf[pos + 1] as u16;
        let _rclass = ((buf[pos + 2] as u16) << 8) | buf[pos + 3] as u16;
        // TTL (4 bytes) + RDLENGTH (2 bytes)
        let rdlength = ((buf[pos + 8] as u16) << 8) | buf[pos + 9] as u16;
        pos += 10;
        if pos + rdlength as usize > buf.len() {
            return Err(string("net: dns: malformed response (rdata)"));
        }
        if rtype == 1 && rdlength == 4 {
            // A record — 4 bytes IPv4 address.
            let ip = [buf[pos], buf[pos + 1], buf[pos + 2], buf[pos + 3]];
            return Ok(ip);
        }
        pos += rdlength as usize;
    }

    Err(string("net: dns: no A record found in response"))
}

/// Skip a DNS name (labels + compression pointers) starting at `pos`.
/// Returns the position after the name.
fn skip_dns_name(buf: &[u8], mut pos: usize) -> Result<usize, string> {
    loop {
        if pos >= buf.len() {
            return Err(string("net: dns: malformed name"));
        }
        let len = buf[pos];
        if len == 0 {
            // End of name.
            return Ok(pos + 1);
        }
        if (len & 0xC0) == 0xC0 {
            // Compression pointer: 2 bytes total, skip both.
            return Ok(pos + 2);
        }
        // Regular label: skip len bytes + the length byte itself.
        pos += 1 + len as usize;
        if pos > buf.len() {
            return Err(string("net: dns: label out of bounds"));
        }
    }
}

/// Split `"host:port"` on the **last** `:` (so v4 with no v6 brackets
/// works). Returns `(host_bytes, port_u16)` or an error message.
fn split_host_port(bytes: &[u8]) -> Result<(&[u8], u16), string> {
    let colon = match bytes.iter().rposition(|&b| b == b':') {
        Some(i) => i,
        None => return Err(string("net: address missing port")),
    };
    let host = &bytes[..colon];
    let port_str = &bytes[colon + 1..];
    if port_str.is_empty() {
        return Err(string("net: address: empty port"));
    }
    let port = parse_port(port_str)?;
    Ok((host, port))
}

fn parse_port(s: &[u8]) -> Result<u16, string> {
    let mut acc: u32 = 0;
    for &c in s {
        if !c.is_ascii_digit() {
            return Err(string("net: invalid port"));
        }
        acc = acc * 10 + (c - b'0') as u32;
        if acc > 65535 {
            return Err(string("net: port out of range"));
        }
    }
    Ok(acc as u16)
}

fn parse_ipv4(s: &[u8]) -> Result<[u8; 4], string> {
    let mut octets = [0u8; 4];
    let mut idx = 0usize;
    let mut acc: u32 = 0;
    let mut have_digit = false;
    for &c in s {
        if c == b'.' {
            if !have_digit {
                return Err(string("net: invalid IPv4 literal"));
            }
            if idx >= 3 {
                return Err(string("net: invalid IPv4 literal"));
            }
            octets[idx] = acc as u8;
            idx += 1;
            acc = 0;
            have_digit = false;
        } else if c.is_ascii_digit() {
            acc = acc * 10 + (c - b'0') as u32;
            if acc > 255 {
                return Err(string("net: IPv4 octet out of range"));
            }
            have_digit = true;
        } else {
            return Err(string("net: invalid IPv4 literal"));
        }
    }
    if idx != 3 || !have_digit {
        return Err(string("net: invalid IPv4 literal"));
    }
    octets[3] = acc as u8;
    Ok(octets)
}
