// net/tcpsock — Go 1.25.5 src/net/tcpsock.go.
//
// One `.rs` per `.go` (§33). The TCP socket-option setters live here;
// TCPConn itself and its I/O methods are still declared in net/mod.rs
// and carry no `go: sdk` anchor, so goishlint does not yet see mod.rs
// as holding this file's declarations. Moving them is worth doing and
// is the reason this file exists now rather than later: the setters
// had to go somewhere, and tcpsock.go is where Go declares them.
//
// goishlint reports the rest of tcpsock.go as unported, which it is.
// Of its 32 declarations goish had none of these eighteen before this
// file: SetLinger, SetKeepAlive, SetKeepAlivePeriod, SetNoDelay,
// ReadFrom, WriteTo, SyscallConn, MultipathTCP, ResolveTCPAddr,
// TCPAddrFromAddrPort, AcceptTCP, DialTCP, ListenTCP, roundDurationUp,
// KeepAliveConfig, TCPAddr.AddrPort, isWildcard, opAddr. Four land
// here; the list is the to-do.

#![allow(non_snake_case)]

extern crate alloc;

use crate::errors::{self, error};
use crate::gostring::string;
use crate::net::TCPConn;
use crate::syscall;
use crate::time::Duration;
use crate::types::int;

// go: sdk 1.25.5 net/tcpsock.go:469-471 roundDurationUp
/// Go: "(d + to - 1) / to" — divide, rounding up, because the kernel
/// takes whole seconds and truncating would arm a shorter timer than
/// the caller asked for.
pub(crate) fn roundDurationUp(d: Duration, to: Duration) -> i64 {
    return (d.0 + to.0 - 1) / to.0;
}

impl TCPConn {
    // go: sdk 1.25.5 net/tcpsock.go:222-231 TCPConn.SetLinger
    /// Go: "sec < 0 (the default) … the operating system finishes
    /// sending the data in the background. If sec == 0, the operating
    /// system discards any unsent or unacknowledged data."
    ///
    /// A negative `sec` clears the option (onoff 0); zero and positive
    /// both set it, with `linger` carrying the seconds.
    pub fn SetLinger(&self, sec: int) -> error {
        // Go's syscall.Linger: two int32s, onoff then linger.
        let secs = i32::try_from(sec).unwrap_or(i32::MAX);
        let l: [i32; 2] = if sec >= 0 { [1, secs] } else { [0, 0] };
        let len = core::mem::size_of::<[i32; 2]>() as u32; // goishlint:ignore GOISH005 - socklen_t, a C ABI width, not a Go value
        return self.__setsockopt(
            syscall::SOL_SOCKET,
            syscall::SO_LINGER,
            l.as_ptr() as *const u8,
            len,
        );
    }

    // go: sdk 1.25.5 net/tcpsock.go:234-242 TCPConn.SetKeepAlive
    /// Go: "sets whether the operating system should send keep-alive
    /// messages on the connection."
    pub fn SetKeepAlive(&self, keepalive: bool) -> error {
        return self.__setsockopt_int(
            syscall::SOL_SOCKET,
            syscall::SO_KEEPALIVE,
            if keepalive { 1 } else { 0 },
        );
    }

    // go: sdk 1.25.5 net/tcpsock.go:249-257 TCPConn.SetKeepAlivePeriod
    /// Go: "sets the duration the connection needs to remain idle
    /// before TCP starts sending keepalive probes."
    ///
    /// IDLE only. It calls `setKeepAliveIdle`, which touches
    /// TCP_KEEPIDLE and leaves TCP_KEEPINTVL where it was — measured:
    /// after SetKeepAlivePeriod(30s), KEEPIDLE is 30 and KEEPINTVL is
    /// still 15. A port that sets both, as older Go did, diverges.
    ///
    /// Zero means the default idle, and NEGATIVE is a no-op returning
    /// nil rather than an error (tcpsockopt_unix.go:18-20).
    pub fn SetKeepAlivePeriod(&self, d: Duration) -> error {
        let d = if d.0 == 0 {
            super::dial::defaultTCPKeepAliveIdle
        } else if d.0 < 0 {
            return crate::errors::nil;
        } else {
            d
        };
        // The kernel expects seconds, rounded to the next highest.
        let secs = roundDurationUp(d, crate::time::Second);
        let secs = i32::try_from(secs).unwrap_or(i32::MAX);
        return self.__setsockopt_int(syscall::IPPROTO_TCP, syscall::TCP_KEEPIDLE, secs);
    }

    // go: sdk 1.25.5 net/tcpsock.go:263-271 TCPConn.SetNoDelay
    /// Go: "controls whether the operating system should delay packet
    /// transmission in hopes of sending fewer packets (Nagle's
    /// algorithm). The default is true (no delay)."
    pub fn SetNoDelay(&self, noDelay: bool) -> error {
        return self.__setsockopt_int(
            syscall::IPPROTO_TCP,
            syscall::TCP_NODELAY,
            if noDelay { 1 } else { 0 },
        );
    }
}

// go: sdk 1.25.5 net/tcpsock.go:84-97 ResolveTCPAddr
/// Go: "ResolveTCPAddr returns an address of TCP end point. … If the
/// host in the address parameter is not a literal IP address or the
/// port is not a literal port number, ResolveTCPAddr resolves the
/// address to an address of TCP end point."
///
/// Five behaviours the reference pins, all of them easy to lose:
///
///   * An EMPTY network is accepted and means "tcp" — Go calls it "a
///     hint wildcard for Go 1.0 undocumented behavior".
///   * "tcp4" and "tcp6" are accepted, but the address that comes back
///     still answers "tcp" from Network(): TCPAddr.Network is a
///     constant, not a record of the argument.
///   * "host:" is port 0 and NOT an error, while a bare "host" is
///     "address host: missing port in address". An EMPTY address is
///     ":0".
///   * The port may be a service NAME: "127.0.0.1:http" is port 80.
///   * A host that merely LOOKS like an IP but is not one — 256.0.0.1
///     — is treated as a hostname and fails as a lookup, not as a
///     malformed address.
pub fn ResolveTCPAddr<N: Into<string>, A: Into<string>>(
    network: N,
    address: A,
) -> (crate::nilable<crate::net::TCPAddr>, error) {
    let network: string = network.into();
    let address: string = address.into();
    let netw: &str = network.as_ref();
    match netw {
        "tcp" | "tcp4" | "tcp6" => {}
        // Go: "a hint wildcard for Go 1.0 undocumented behavior".
        "" => {}
        _ => {
            return (
                crate::nilable::nil(),
                errors::Wrap(crate::net::net::UnknownNetworkError(network.clone())),
            );
        }
    }

    // Go: an empty address is the zero end point, not an error.
    if address.Len() == 0 {
        return (
            crate::nilable::new(crate::net::TCPAddr {
                IP: [0, 0, 0, 0],
                Port: int::from(0),
            }),
            crate::errors::nil,
        );
    }

    let (host, port_str, serr) = crate::net::SplitHostPort(address.clone());
    if !serr.IsNil() {
        return (crate::nilable::nil(), serr);
    }

    // The port may be a number or a service name; LookupPort does both
    // and reports "address <p>: invalid port" for an out-of-range one.
    let (port, perr) = crate::net::lookup::LookupPort(string::from_static("tcp"), port_str);
    if !perr.IsNil() {
        return (crate::nilable::nil(), perr);
    }

    // Go: an empty host is the wildcard address, which String() then
    // renders as ":port" rather than "0.0.0.0:port".
    if host.Len() == 0 {
        return (
            crate::nilable::new(crate::net::TCPAddr {
                IP: [0, 0, 0, 0],
                Port: port,
            }),
            crate::errors::nil,
        );
    }

    let ip = crate::net::ParseIP(host.clone());
    if !ip.IsNil() {
        return (
            crate::nilable::new(crate::net::TCPAddr {
                IP: ipv4_octets(&ip),
                Port: port,
            }),
            crate::errors::nil,
        );
    }

    let (addrs, lerr) = crate::net::lookup::LookupHost(host.clone());
    if !lerr.IsNil() {
        return (crate::nilable::nil(), lerr);
    }
    if addrs.len() == 0 {
        return (crate::nilable::nil(), crate::net::net::errNoSuchHost.into());
    }
    let first = addrs.get(0).cloned().unwrap_or(string::from_static(""));
    let rip = crate::net::ParseIP(first);
    if rip.IsNil() {
        return (crate::nilable::nil(), crate::net::net::errNoSuchHost.into());
    }
    return (
        crate::nilable::new(crate::net::TCPAddr {
            IP: ipv4_octets(&rip),
            Port: port,
        }),
        crate::errors::nil,
    );
}

// go: none — goish-only: goish's TCPAddr carries four octets where
// Go's carries an `IP` (a byte slice that may be v4 or v16). This
// narrows one to the other; an IPv6 address has no representation in
// this TCPAddr, which is a known limit of the type rather than of
// this function.
/// The four IPv4 octets of an `IP`, or zeroes.
fn ipv4_octets(ip: &crate::net::IP) -> [u8; 4] {
    let v4 = ip.To4();
    if v4.IsNil() {
        return [0, 0, 0, 0];
    }
    if v4.bytes.len() < 4 {
        return [0, 0, 0, 0];
    }
    return [
        *v4.bytes.get(0).unwrap_or(&0),
        *v4.bytes.get(1).unwrap_or(&0),
        *v4.bytes.get(2).unwrap_or(&0),
        *v4.bytes.get(3).unwrap_or(&0),
    ];
}

// go: sdk 1.25.5 net/tcpsock.go:443-466 ListenTCP
/// Go: "ListenTCP acts like [Listen] for TCP networks. … If the IP
/// field of laddr is nil or an unspecified IP address, ListenTCP
/// listens on all available unicast and anycast IP addresses of the
/// local system. If the Port field of laddr is 0, a port number is
/// automatically chosen."
///
/// A nil `laddr` is the zero TCPAddr, NOT an error — Go writes
/// `laddr = &TCPAddr{}` before listening. An unknown network is an
/// `&OpError{Op: "listen"}` wrapping `UnknownNetworkError`, which
/// renders "listen udp: unknown network udp": the Net field and the
/// wrapped error both name it, which looks redundant and is what Go
/// prints.
pub fn ListenTCP<N: Into<string>>(
    network: N,
    laddr: crate::nilable<crate::net::TCPAddr>,
) -> (crate::nilable<crate::net::Listener>, error) {
    let network: string = network.into();
    let netw: &str = network.as_ref();
    match netw {
        "tcp" | "tcp4" | "tcp6" => {}
        _ => {
            return (
                crate::nilable::nil(),
                listen_op_error(&network, op_addr(&laddr)),
            );
        }
    }
    // Go: "if laddr == nil { laddr = &TCPAddr{} }".
    let addr = match laddr.Try() {
        Some(a) => a.String(),
        None => crate::net::TCPAddr {
            IP: [0, 0, 0, 0],
            Port: int::from(0),
        }
        .String(),
    };
    let (ln, err) = crate::net::Listen(network.clone(), addr);
    if !err.IsNil() {
        return (crate::nilable::nil(), err);
    }
    return (crate::nilable::new(ln), errors::nil);
}

// go: sdk 1.25.5 net/tcpsock.go:317-340 DialTCP
/// Go: "DialTCP acts like [Dial] for TCP networks." A nil `raddr` is
/// `errMissingAddress` — "dial tcp: missing address" — and an unknown
/// network fails before anything is dialled.
pub fn DialTCP<N: Into<string>>(
    network: N,
    laddr: crate::nilable<crate::net::TCPAddr>,
    raddr: crate::nilable<crate::net::TCPAddr>,
) -> (crate::nilable<crate::net::TCPConn>, error) {
    let network: string = network.into();
    let netw: &str = network.as_ref();
    match netw {
        "tcp" | "tcp4" | "tcp6" => {}
        _ => {
            return (
                crate::nilable::nil(),
                dial_op_error(
                    &network,
                    op_addr(&laddr),
                    op_addr(&raddr),
                    errors::Wrap(crate::net::net::UnknownNetworkError(network.clone())),
                ),
            );
        }
    }
    if raddr.IsNil() {
        return (
            crate::nilable::nil(),
            dial_op_error(
                &network,
                op_addr(&laddr),
                None,
                crate::net::net::errMissingAddress.into(),
            ),
        );
    }
    // goish's Dial takes the address in string form; laddr (the local
    // bind) is not honoured — see the note on op_addr.
    let target = raddr.Must().String();
    let (conn, err) = crate::net::Dial(network.clone(), target);
    if !err.IsNil() {
        return (crate::nilable::nil(), err);
    }
    return (crate::nilable::new(conn), errors::nil);
}

// go: none — goish-only: Go's `(*TCPAddr).opAddr` returns a nil `Addr`
// interface for a nil receiver, which is how an OpError prints with no
// address at all. goish's nilable makes the same distinction.
//
// NOTE: DialTCP ignores a non-nil `laddr`. Go binds the local end to
// it; goish's dial path has no bind step, so a caller asking for a
// specific source address silently gets an ephemeral one. That is a
// real gap, recorded here rather than in a smoke because goish has no
// way to observe the bound source address of a dial yet.
/// The `Addr` an OpError should carry for a possibly-nil TCPAddr.
fn op_addr(
    a: &crate::nilable<crate::net::TCPAddr>,
) -> Option<alloc::sync::Arc<dyn crate::net::net::Addr>> {
    return match a.Try() {
        Some(v) => Some(alloc::sync::Arc::new(v.clone())),
        None => None,
    };
}

// go: none — goish-only: the two OpError compositions ListenTCP and
// DialTCP build, named once.
fn listen_op_error(
    network: &string,
    addr: Option<alloc::sync::Arc<dyn crate::net::net::Addr>>,
) -> error {
    return errors::Wrap(crate::net::net::OpError {
        Op: string::from_static("listen"),
        Net: network.clone(),
        Source: None,
        Addr: addr,
        Err: errors::Wrap(crate::net::net::UnknownNetworkError(network.clone())),
    });
}

// go: none — goish-only: see listen_op_error.
fn dial_op_error(
    network: &string,
    source: Option<alloc::sync::Arc<dyn crate::net::net::Addr>>,
    addr: Option<alloc::sync::Arc<dyn crate::net::net::Addr>>,
    err: error,
) -> error {
    return errors::Wrap(crate::net::net::OpError {
        Op: string::from_static("dial"),
        Net: network.clone(),
        Source: source,
        Addr: addr,
        Err: err,
    });
}

impl crate::net::Listener {
    // go: sdk 1.25.5 net/tcpsock.go:363-372 TCPListener.AcceptTCP
    /// Go: "AcceptTCP accepts the next incoming call and returns the
    /// new connection." The error is an `&OpError{Op: "accept"}`
    /// naming the listener, which `Accept` already builds.
    pub fn AcceptTCP(&self) -> (crate::nilable<crate::net::TCPConn>, error) {
        let (conn, err) = self.Accept();
        if !err.IsNil() {
            return (crate::nilable::nil(), err);
        }
        return (crate::nilable::new(conn), errors::nil);
    }
}
