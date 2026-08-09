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
