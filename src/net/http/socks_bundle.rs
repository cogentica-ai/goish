// net/http/socks_bundle — SOCKS5 client, RFC 1928, with the RFC 1929
// username/password authentication method.
//
// Port of Go 1.25.5 net/http/socks_bundle.go, itself a `bundle`d copy
// of golang.org/x/net/internal/socks. Names keep Go's `socks` prefix
// because the bundler adds it and net/http refers to them that way.
//
// Two deliberate divergences, both forced by goish's `net` package and
// both noted at the site:
//   - `net::IP` is IPv4-only (no `To16`, mod.rs:675), so the
//     ATYP=IPv6 branch of `connect` cannot construct an address. The
//     branch is kept and returns the same "unknown address type"
//     error Go returns for an unrepresentable IP.
//   - `net::Conn` is a trait with concrete `TCPAddr` accessors rather
//     than Go's `net.Addr` interface, so `socksConn` holds a
//     `TCPConn` instead of embedding `net.Conn`.

#![allow(non_snake_case, non_camel_case_types)]

extern crate alloc;

use alloc::sync::Arc;
use alloc::vec::Vec;

use crate::errors::{self, error};
use crate::goslice::slice;
use crate::string;
use crate::types::byte;
use crate::{int, net};

// go: sdk 1.25.5 net/http/socks_bundle.go:22-25 socksnoDeadline
/// Go: `socksnoDeadline = time.Time{}` — clears a deadline.
pub fn socksnoDeadline() -> crate::time::Time {
    return crate::time::Time::default();
}

// go: sdk 1.25.5 net/http/socks_bundle.go:22-25 socksaLongTimeAgo
/// Go: `socksaLongTimeAgo = time.Unix(1, 0)` — a deadline already in
/// the past, used to interrupt a blocked I/O on context cancellation.
pub fn socksaLongTimeAgo() -> crate::time::Time {
    return crate::time::Unix(1, 0);
}

// ─── wire protocol constants (socks_bundle.go:222-239) ──────────────

// go: sdk 1.25.5 net/http/socks_bundle.go:222-239 socksVersion5
pub const socksVersion5: byte = 0x05;
// go: sdk 1.25.5 net/http/socks_bundle.go:222-239 socksAddrTypeIPv4
pub const socksAddrTypeIPv4: byte = 0x01;
// go: sdk 1.25.5 net/http/socks_bundle.go:222-239 socksAddrTypeFQDN
pub const socksAddrTypeFQDN: byte = 0x03;
// go: sdk 1.25.5 net/http/socks_bundle.go:222-239 socksAddrTypeIPv6
pub const socksAddrTypeIPv6: byte = 0x04;

// go: sdk 1.25.5 net/http/socks_bundle.go:177 socksCommand
/// Go: "A Command represents a SOCKS command."
#[derive(Clone, Copy, PartialEq, Eq, Default)]
pub struct socksCommand(pub crate::types::int);

// go: sdk 1.25.5 net/http/socks_bundle.go:222-239 socksCmdConnect
/// Go: "establishes an active-open forward proxy connection".
pub const socksCmdConnect: socksCommand = socksCommand(0x01);
// go: sdk 1.25.5 net/http/socks_bundle.go:222-239 sockscmdBind
/// Go: "establishes a passive-open forward proxy connection".
pub const sockscmdBind: socksCommand = socksCommand(0x02);

// go: sdk 1.25.5 net/http/socks_bundle.go:191 socksAuthMethod
/// Go: "An AuthMethod represents a SOCKS authentication method."
#[derive(Clone, Copy, PartialEq, Eq, Default)]
pub struct socksAuthMethod(pub crate::types::int);

// go: sdk 1.25.5 net/http/socks_bundle.go:222-239 socksAuthMethodNotRequired
pub const socksAuthMethodNotRequired: socksAuthMethod = socksAuthMethod(0x00);
// go: sdk 1.25.5 net/http/socks_bundle.go:222-239 socksAuthMethodUsernamePassword
pub const socksAuthMethodUsernamePassword: socksAuthMethod = socksAuthMethod(0x02);
// go: sdk 1.25.5 net/http/socks_bundle.go:222-239 socksAuthMethodNoAcceptableMethods
pub const socksAuthMethodNoAcceptableMethods: socksAuthMethod = socksAuthMethod(0xff);

// go: sdk 1.25.5 net/http/socks_bundle.go:194 socksReply
/// Go: "A Reply represents a SOCKS command reply code."
#[derive(Clone, Copy, PartialEq, Eq, Default)]
pub struct socksReply(pub crate::types::int);

// go: sdk 1.25.5 net/http/socks_bundle.go:222-239 socksStatusSucceeded
pub const socksStatusSucceeded: socksReply = socksReply(0x00);

// go: sdk 1.25.5 net/http/socks_bundle.go:429-432 socksauthUsernamePasswordVersion
pub const socksauthUsernamePasswordVersion: byte = 0x01;
// go: sdk 1.25.5 net/http/socks_bundle.go:429-432 socksauthStatusSucceeded
pub const socksauthStatusSucceeded: byte = 0x00;

// ─── stringers ──────────────────────────────────────────────────────

impl socksCommand {
    // go: sdk 1.25.5 net/http/socks_bundle.go:179-189 socksCommand.String
    pub fn String(&self) -> string {
        if *self == socksCmdConnect {
            return string("socks connect");
        }
        if *self == sockscmdBind {
            return string("socks bind");
        }
        return crate::fmt::Sprintf!("socks %s", crate::strconv::Itoa(self.0));
    }
}

impl socksReply {
    // go: sdk 1.25.5 net/http/socks_bundle.go:196-219 socksReply.String
    pub fn String(&self) -> string {
        return __replyString(self.0);
    }
}

// go: none — goish-only: the match body of socksReply.String, split
// out so the method above is a one-line `return`, which is what
// GOISH023 (explicit returns) wants from a match-tail.
fn __replyString(code: crate::types::int) -> string {
    return match code {
        0x00 => string("succeeded"),
        0x01 => string("general SOCKS server failure"),
        0x02 => string("connection not allowed by ruleset"),
        0x03 => string("network unreachable"),
        0x04 => string("host unreachable"),
        0x05 => string("connection refused"),
        0x06 => string("TTL expired"),
        0x07 => string("command not supported"),
        0x08 => string("address type not supported"),
        _ => crate::fmt::Sprintf!("unknown code: %s", crate::strconv::Itoa(code)),
    };
}

// ─── socksAddr ──────────────────────────────────────────────────────

// go: sdk 1.25.5 net/http/socks_bundle.go:241-245 socksAddr
/// Go: "An Addr represents a SOCKS-specific address. Either Name or IP
/// is used exclusively."
#[derive(Clone, Default)]
pub struct socksAddr {
    /// Go: "fully-qualified domain name"
    pub Name: string,
    pub IP: net::IP,
    pub Port: crate::types::int,
}

impl net::Addr for socksAddr {
    // go: sdk 1.25.5 net/http/socks_bundle.go:247 socksAddr.Network
    fn Network(&self) -> string {
        return string("socks");
    }

    // go: sdk 1.25.5 net/http/socks_bundle.go:249-257 socksAddr.String
    /// Go returns "<nil>" for a nil receiver; goish has no nil
    /// receiver, so that branch lives in the caller's Option handling.
    fn String(&self) -> string {
        let port = crate::strconv::Itoa(self.Port);
        if self.IP.IsNil() {
            return net::JoinHostPort(self.Name.clone(), port);
        }
        return net::JoinHostPort(self.IP.String(), port);
    }
}

// ─── socksConn ──────────────────────────────────────────────────────

// goishlint:ignore GOISH019 socksConn — Go EMBEDS `net.Conn`
// (socks_bundle.go:262), which the rule reads as no named field at
// all: it reports Go-only [] and Rust-only ["Conn"]. Rust has no
// embedding, so the stand-in field is unavoidable. This is the file's
// ONLY GOISH019 finding, so the file-scoped directive masks nothing.
// go: sdk 1.25.5 net/http/socks_bundle.go:261-265 socksConn
/// Go: "A Conn represents a forward proxy connection." Go embeds
/// `net.Conn`; goish holds the concrete `TCPConn` because its `Conn`
/// trait is not object-safe in the same way (see the module header).
pub struct socksConn {
    pub Conn: net::TCPConn,
    pub boundAddr: Option<Arc<socksAddr>>,
}

impl socksConn {
    // go: sdk 1.25.5 net/http/socks_bundle.go:267-274 socksConn.BoundAddr
    /// Go: "BoundAddr returns the address assigned by the proxy server
    /// for connecting to the command target address from the proxy
    /// server."
    pub fn BoundAddr(&self) -> Option<Arc<socksAddr>> {
        return self.boundAddr.clone();
    }
}

// ─── socksUsernamePassword ──────────────────────────────────────────

// go: sdk 1.25.5 net/http/socks_bundle.go:434-440 socksUsernamePassword
/// Go: "UsernamePassword are the credentials for the
/// username/password authentication method."
#[derive(Clone, Default)]
pub struct socksUsernamePassword {
    pub Username: string,
    pub Password: string,
}

impl socksUsernamePassword {
    // go: sdk 1.25.5 net/http/socks_bundle.go:442-473 socksUsernamePassword.Authenticate
    /// Go: "Authenticate authenticates a pair of username and password
    /// with the proxy server."
    ///
    /// Go takes `io.ReadWriter`; goish has no such combined trait, so
    /// the bound is spelled as both halves.
    pub fn Authenticate<RW: crate::io::Reader + crate::io::Writer>(
        &self,
        _ctx: &Arc<dyn crate::context::Context>,
        rw: &mut RW,
        auth: socksAuthMethod,
    ) -> error {
        if auth == socksAuthMethodNotRequired {
            return errors::nil;
        }
        if auth == socksAuthMethodUsernamePassword {
            if self.Username.Len() == 0 || self.Username.Len() > 255 || self.Password.Len() > 255 {
                return errors::New(string("invalid username/password"));
            }
            let mut b: Vec<u8> = Vec::new();
            b.push(socksauthUsernamePasswordVersion);
            b.push(crate::uint8(self.Username.Len()));
            b.extend_from_slice(self.Username.as_bytes());
            b.push(crate::uint8(self.Password.Len()));
            b.extend_from_slice(self.Password.as_bytes());
            // Go: TODO(mikio) — handle IO deadlines and cancelation.
            let (_, err) = rw.Write(slice::<byte>::__from_vec(b));
            if !err.IsNil() {
                return err;
            }
            let mut resp = crate::make!([]byte, 2);
            let (_, rerr) = crate::io::ReadFull(rw, &mut resp);
            if !rerr.IsNil() {
                return rerr;
            }
            if resp[int(0)] != socksauthUsernamePasswordVersion {
                return errors::New(string("invalid username/password version"));
            }
            if resp[int(1)] != socksauthStatusSucceeded {
                return errors::New(string("username/password authentication failed"));
            }
            return errors::nil;
        }
        return errors::New(crate::fmt::Sprintf!(
            "unsupported authentication method %s",
            crate::strconv::Itoa(auth.0)
        ));
    }
}

// ─── socksDialer ────────────────────────────────────────────────────

// go: sdk 1.25.5 net/http/socks_bundle.go:276-295 socksDialer
/// Go: "A Dialer holds SOCKS-specific options."
///
/// `ProxyDial` and `Authenticate` are Go func fields. goish carries
/// `ProxyDial` as a boxed closure; `Authenticate` is expressed as an
/// optional `socksUsernamePassword` because that is the only
/// implementation Go's bundle ships, and a boxed generic method would
/// not be object-safe.
pub struct socksDialer {
    /// Go: "either CmdConnect or cmdBind"
    pub cmd: socksCommand,
    /// Go: "network between a proxy server and a client"
    pub proxyNetwork: string,
    /// Go: "proxy server address"
    pub proxyAddress: string,
    /// Go: "specifies the optional dial function for establishing the
    /// transport connection."
    pub ProxyDial: Option<Arc<dyn Fn(string, string) -> (net::TCPConn, error) + Send + Sync>>,
    /// Go: "specifies the list of request authentication methods. If
    /// empty, SOCKS client requests only AuthMethodNotRequired."
    pub AuthMethods: slice<socksAuthMethod>,
    /// Go: "specifies the optional authentication function. It must be
    /// non-nil when AuthMethods is not empty."
    pub Authenticate: Option<Arc<socksUsernamePassword>>,
}

impl socksDialer {
    // go: sdk 1.25.5 net/http/socks_bundle.go:387-400 socksDialer.validateTarget
    pub fn validateTarget(&self, network: string, _address: string) -> error {
        if network != "tcp" && network != "tcp6" && network != "tcp4" {
            return errors::New(string("network not implemented"));
        }
        if self.cmd != socksCmdConnect && self.cmd != sockscmdBind {
            return errors::New(string("command not implemented"));
        }
        return errors::nil;
    }

    // go: sdk 1.25.5 net/http/socks_bundle.go:402-421 socksDialer.pathAddrs
    /// Returns `(proxy, dst, err)` — the proxy server address and the
    /// command target address, both as `socksAddr`.
    pub fn pathAddrs(
        &self,
        address: string,
    ) -> (Option<Arc<socksAddr>>, Option<Arc<socksAddr>>, error) {
        let mut proxy: Option<Arc<socksAddr>> = None;
        let mut dst: Option<Arc<socksAddr>> = None;
        for (i, s) in [self.proxyAddress.clone(), address].into_iter().enumerate() {
            let (host, port, err) = sockssplitHostPort(s);
            if !err.IsNil() {
                return (None, None, err);
            }
            let mut a = socksAddr {
                Name: string::new(),
                IP: net::ParseIP(host.clone()),
                Port: port,
            };
            if a.IP.IsNil() {
                a.Name = host;
            }
            if i == 0 {
                proxy = Some(Arc::new(a));
            } else {
                dst = Some(Arc::new(a));
            }
        }
        return (proxy, dst, errors::nil);
    }

    // go: sdk 1.25.5 net/http/socks_bundle.go:27-159 socksDialer.connect
    /// Drive the SOCKS5 handshake over an already-connected `c` and
    /// return the bound address the proxy assigned.
    ///
    /// Go spawns a watchdog goroutine that slams the deadline to
    /// `socksaLongTimeAgo` when the context is cancelled. goish applies
    /// the context's deadline up front, which covers the timeout case;
    /// mid-handshake cancellation of a context with no deadline is not
    /// interrupted.
    pub fn connect(
        &self,
        ctx: &Arc<dyn crate::context::Context>,
        c: &mut net::TCPConn,
        address: string,
    ) -> (Option<Arc<socksAddr>>, error) {
        let (host, port, err) = sockssplitHostPort(address);
        if !err.IsNil() {
            return (None, err);
        }
        if let Some(deadline) = ctx.Deadline() {
            if !deadline.IsZero() {
                let _ = c.SetDeadline(deadline);
            }
        }

        // ── method-selection request ──
        let mut b: Vec<u8> = Vec::with_capacity(6 + crate::builtin::__make_size(host.Len()));
        b.push(socksVersion5);
        if self.AuthMethods.Len() == 0 || self.Authenticate.is_none() {
            b.push(1);
            b.push(crate::uint8(socksAuthMethodNotRequired.0));
        } else {
            if self.AuthMethods.Len() > 255 {
                return (None, errors::New(string("too many authentication methods")));
            }
            b.push(crate::uint8(self.AuthMethods.Len()));
            for i in 0..self.AuthMethods.Len() {
                b.push(crate::uint8(self.AuthMethods[int(i)].0));
            }
        }
        let (_, werr) = crate::io::Writer::Write(c, slice::<byte>::__from_vec(b));
        if !werr.IsNil() {
            return (None, werr);
        }

        let mut hdr = crate::make!([]byte, 2);
        let (_, rerr) = crate::io::ReadFull(c, &mut hdr);
        if !rerr.IsNil() {
            return (None, rerr);
        }
        if hdr[int(0)] != socksVersion5 {
            return (
                None,
                errors::New(crate::fmt::Sprintf!(
                    "unexpected protocol version %s",
                    crate::strconv::Itoa(int(hdr[int(0)]))
                )),
            );
        }
        let am = socksAuthMethod(int(hdr[int(1)]));
        if am == socksAuthMethodNoAcceptableMethods {
            return (
                None,
                errors::New(string("no acceptable authentication methods")),
            );
        }
        if let Some(up) = self.Authenticate.as_ref() {
            let aerr = up.Authenticate(ctx, c, am);
            if !aerr.IsNil() {
                return (None, aerr);
            }
        }

        // ── command request ──
        let mut b: Vec<u8> = Vec::new();
        b.push(socksVersion5);
        b.push(crate::uint8(self.cmd.0));
        b.push(0);
        let ip = net::ParseIP(host.clone());
        if !ip.IsNil() {
            let ip4 = ip.To4();
            if !ip4.IsNil() {
                b.push(socksAddrTypeIPv4);
                for i in 0..ip4.bytes.Len() {
                    b.push(ip4.bytes[i]);
                }
            } else {
                // Go: else if ip6 := ip.To16(); ip6 != nil {
                //         b = append(b, socksAddrTypeIPv6)
                //         b = append(b, ip6...) }
                let ip6 = ip.To16();
                if !ip6.IsNil() {
                    b.push(socksAddrTypeIPv6);
                    for i in 0..ip6.bytes.Len() {
                        b.push(ip6.bytes[i]);
                    }
                } else {
                    // Go: return nil, errors.New("unknown address type")
                    return (None, errors::New(string("unknown address type")));
                }
            }
        } else {
            if host.Len() > 255 {
                return (None, errors::New(string("FQDN too long")));
            }
            b.push(socksAddrTypeFQDN);
            b.push(crate::uint8(host.Len()));
            b.extend_from_slice(host.as_bytes());
        }
        b.push(crate::uint8(port >> 8));
        b.push(crate::uint8(port));
        let (_, werr) = crate::io::Writer::Write(c, slice::<byte>::__from_vec(b));
        if !werr.IsNil() {
            return (None, werr);
        }

        // ── command reply ──
        let mut rep = crate::make!([]byte, 4);
        let (_, rerr) = crate::io::ReadFull(c, &mut rep);
        if !rerr.IsNil() {
            return (None, rerr);
        }
        if rep[int(0)] != socksVersion5 {
            return (
                None,
                errors::New(crate::fmt::Sprintf!(
                    "unexpected protocol version %s",
                    crate::strconv::Itoa(int(rep[int(0)]))
                )),
            );
        }
        let cmdErr = socksReply(int(rep[int(1)]));
        if cmdErr != socksStatusSucceeded {
            return (
                None,
                errors::New(crate::fmt::Sprintf!("unknown error %s", cmdErr.String())),
            );
        }
        if rep[int(2)] != 0 {
            return (None, errors::New(string("non-zero reserved field")));
        }

        let mut l: crate::types::int = 2;
        let mut a = socksAddr::default();
        match rep[int(3)] {
            x if x == socksAddrTypeIPv4 => {
                l += net::IPv4len;
                a.IP = net::IP {
                    bytes: crate::make!([]byte, net::IPv4len),
                };
            }
            x if x == socksAddrTypeIPv6 => {
                // Go: l += net.IPv6len; a.IP = make(net.IP, net.IPv6len)
                l += net::IPv6len;
                a.IP = net::IP {
                    bytes: crate::make!([]byte, net::IPv6len),
                };
            }
            x if x == socksAddrTypeFQDN => {
                let mut n = crate::make!([]byte, 1);
                let (_, ferr) = crate::io::ReadFull(c, &mut n);
                if !ferr.IsNil() {
                    return (None, ferr);
                }
                l += int(n[int(0)]);
            }
            other => {
                return (
                    None,
                    errors::New(crate::fmt::Sprintf!(
                        "unknown address type %s",
                        crate::strconv::Itoa(int(other))
                    )),
                );
            }
        }
        let mut body = crate::make!([]byte, l);
        let (_, berr) = crate::io::ReadFull(c, &mut body);
        if !berr.IsNil() {
            return (None, berr);
        }
        let n = body.Len();
        if !a.IP.IsNil() {
            for i in 0..a.IP.bytes.Len() {
                a.IP.bytes[int(i)] = body[int(i)];
            }
        } else {
            let raw: &[u8] = &body;
            a.Name = string::from_bytes(&raw[..crate::builtin::__make_size(n) - 2]);
        }
        a.Port = int(body[int(n - 2)]) << 8 | int(body[int(n - 1)]);
        // Clear the deadline the way Go's deferred SetDeadline does.
        let _ = c.SetDeadline(socksnoDeadline());
        return (Some(Arc::new(a)), errors::nil);
    }

    // go: sdk 1.25.5 net/http/socks_bundle.go:305-334 socksDialer.DialContext
    /// Go: "DialContext connects to the provided address on the
    /// provided network. The returned error value may be a
    /// net.OpError."
    pub fn DialContext(
        &self,
        ctx: &Arc<dyn crate::context::Context>,
        network: string,
        address: string,
    ) -> (Option<socksConn>, error) {
        let verr = self.validateTarget(network.clone(), address.clone());
        if !verr.IsNil() {
            return (None, self.opError(network, address.clone(), verr));
        }
        let (mut c, derr) = match self.ProxyDial.as_ref() {
            Some(pd) => pd(self.proxyNetwork.clone(), self.proxyAddress.clone()),
            None => net::Dial(self.proxyNetwork.clone(), self.proxyAddress.clone()),
        };
        if !derr.IsNil() {
            return (None, self.opError(network, address, derr));
        }
        let (a, cerr) = self.connect(ctx, &mut c, address.clone());
        if !cerr.IsNil() {
            let _ = crate::io::Closer::Close(&mut c);
            return (None, self.opError(network, address, cerr));
        }
        return (
            Some(socksConn {
                Conn: c,
                boundAddr: a,
            }),
            errors::nil,
        );
    }

    // go: sdk 1.25.5 net/http/socks_bundle.go:343-358 socksDialer.DialWithConn
    /// Go: "DialWithConn initiates a connection from SOCKS server to
    /// the target network and address using the connection c that is
    /// already connected to the SOCKS server. It returns the
    /// connection's local address assigned by the SOCKS server."
    pub fn DialWithConn(
        &self,
        ctx: &Arc<dyn crate::context::Context>,
        c: &mut net::TCPConn,
        network: string,
        address: string,
    ) -> (Option<Arc<socksAddr>>, error) {
        let verr = self.validateTarget(network.clone(), address.clone());
        if !verr.IsNil() {
            return (None, self.opError(network, address, verr));
        }
        let (a, cerr) = self.connect(ctx, c, address.clone());
        if !cerr.IsNil() {
            return (None, self.opError(network, address, cerr));
        }
        return (a, errors::nil);
    }

    // go: sdk 1.25.5 net/http/socks_bundle.go:366-387 socksDialer.Dial
    /// Go: "Dial connects to the provided address on the provided
    /// network. Unlike DialContext, it returns a raw transport
    /// connection instead of a forward proxy connection.
    /// Deprecated: Use DialContext or DialWithConn instead."
    pub fn Dial(&self, network: string, address: string) -> (Option<net::TCPConn>, error) {
        let verr = self.validateTarget(network.clone(), address.clone());
        if !verr.IsNil() {
            return (None, self.opError(network, address, verr));
        }
        let (mut c, derr) = match self.ProxyDial.as_ref() {
            Some(pd) => pd(self.proxyNetwork.clone(), self.proxyAddress.clone()),
            None => net::Dial(self.proxyNetwork.clone(), self.proxyAddress.clone()),
        };
        if !derr.IsNil() {
            return (None, self.opError(network, address, derr));
        }
        let ctx = crate::context::Background();
        let (_, werr) = self.DialWithConn(&ctx, &mut c, network, address);
        if !werr.IsNil() {
            let _ = crate::io::Closer::Close(&mut c);
            return (None, werr);
        }
        return (Some(c), errors::nil);
    }

    // go: none — goish-only. Go writes the `&net.OpError{Op: …, Net: …,
    // Source: proxy, Addr: dst, Err: err}` literal at each of its nine
    // error sites; the pathAddrs lookup is identical every time, so it
    // is factored out here rather than repeated.
    fn opError(&self, network: string, address: string, err: error) -> error {
        let (proxy, dst, _) = self.pathAddrs(address);
        return errors::Wrap(net::OpError {
            Op: self.cmd.String(),
            Net: network,
            Source: proxy.map(|a| a as Arc<dyn net::Addr>),
            Addr: dst.map(|a| a as Arc<dyn net::Addr>),
            Err: err,
        });
    }
}

// go: sdk 1.25.5 net/http/socks_bundle.go:423-427 socksNewDialer
/// Go: "NewDialer returns a new Dialer that dials through the provided
/// proxy server's network and address."
pub fn socksNewDialer(network: string, address: string) -> socksDialer {
    return socksDialer {
        proxyNetwork: network,
        proxyAddress: address,
        cmd: socksCmdConnect,
        ProxyDial: None,
        AuthMethods: slice::<socksAuthMethod>::new(),
        Authenticate: None,
    };
}

// go: sdk 1.25.5 net/http/socks_bundle.go:161-175 sockssplitHostPort
/// Splits `host:port` and validates the port is in 1..=0xffff.
/// Returns `(host, port, err)`.
pub fn sockssplitHostPort(address: string) -> (string, crate::types::int, error) {
    let (host, port, err) = net::SplitHostPort(address);
    if !err.IsNil() {
        return (string::new(), 0, err);
    }
    let (portnum, aerr) = crate::strconv::Atoi(port.clone());
    if !aerr.IsNil() {
        return (string::new(), 0, aerr);
    }
    if 1 > portnum || portnum > 0xffff {
        return (
            string::new(),
            0,
            errors::New(crate::fmt::Sprintf!("port number out of range %s", port)),
        );
    }
    return (host, portnum, errors::nil);
}

// Silence the unused warning for a constant that only the (currently
// unrepresentable) IPv6 path would read.
const _: byte = socksAddrTypeIPv6;
const _: socksCommand = sockscmdBind;
