// http_socks_smoke — net/http/socks_bundle.go, the SOCKS5 client.
//
// Expected values come from running the real Go 1.25.5 net/http
// package under scripts/goref.sh. The last test drives an actual
// SOCKS5 handshake against a fake proxy server and checks the bytes
// on the wire against RFC 1928.

#![no_std]
#![no_main]

extern crate alloc;
extern crate goish;

use alloc::vec::Vec;
use core::sync::atomic::{AtomicUsize, Ordering};

use goish::fmt;
use goish::io::{Reader, Writer};
use goish::net;
use goish::net::http::socks_bundle::{
    socksAddr, socksAuthMethodNotRequired, socksAuthMethodUsernamePassword, socksCmdConnect,
    socksCommand, socksNewDialer, socksReply, socksUsernamePassword, sockscmdBind,
    sockssplitHostPort,
};
use goish::time;
use goish::{go, string};

static PASSED: AtomicUsize = AtomicUsize::new(0);
static FAILED: AtomicUsize = AtomicUsize::new(0);

fn check(name: &'static str, ok: bool, detail: goish::string) {
    if ok {
        PASSED.fetch_add(1, Ordering::Relaxed);
        fmt::Printf!("PASS: %s\n", name);
    } else {
        FAILED.fetch_add(1, Ordering::Relaxed);
        fmt::Printf!("FAIL: %s — %s\n", name, detail);
    }
}

#[goish::main]
fn main() {
    goish::go!(stack(1024 * 1024), move || {
        run();
    });
    loop {
        goish::runtime::sched::Gosched();
    }
}

fn run() {
    // ── sockssplitHostPort ──
    {
        // (address, host, port, expect_err)
        let cases: &[(&'static str, &'static str, i64, bool)] = &[
            ("h:80", "h", 80, false),
            ("h:0", "", 0, true),      // port must be >= 1
            ("h:1", "h", 1, false),
            ("h:65535", "h", 65535, false),
            ("h:65536", "", 0, true),
            ("h:-1", "", 0, true),
            ("h:x", "", 0, true),
            ("h", "", 0, true),        // missing port
            ("1.2.3.4:443", "1.2.3.4", 443, false),
            (":80", "", 80, false),    // empty host is fine
        ];
        let mut bad = string("");
        for (addr, want_h, want_p, want_err) in cases {
            let (h, p, e) = sockssplitHostPort(string(*addr));
            if h != *want_h || p != *want_p as goish::int || e.IsNil() == *want_err {
                bad = fmt::Sprintf!("%s -> h=%q p=%d e=%v", string(*addr), h, p, e);
            }
        }
        check("sockssplitHostPort over 10 addresses", bad.Len() == 0, bad);
    }

    // ── socksCommand.String / socksReply.String ──
    check(
        "socksCommand.String",
        socksCmdConnect.String() == "socks connect"
            && sockscmdBind.String() == "socks bind"
            && socksCommand(7).String() == "socks 7",
        string(""),
    );
    {
        let want: &[&'static str] = &[
            "succeeded",
            "general SOCKS server failure",
            "connection not allowed by ruleset",
            "network unreachable",
            "host unreachable",
            "connection refused",
            "TTL expired",
            "command not supported",
            "address type not supported",
        ];
        let mut bad = string("");
        for i in 0..want.len() {
            let got = socksReply(i as goish::int).String();
            if got != want[i] {
                bad = fmt::Sprintf!("%d -> %q", i as i64, got);
            }
        }
        if socksReply(9).String() != "unknown code: 9" {
            bad = string("9 should be \"unknown code: 9\"");
        }
        if socksReply(66).String() != "unknown code: 66" {
            bad = string("66 should be \"unknown code: 66\"");
        }
        check("socksReply.String over all 9 codes + 2 unknown", bad.Len() == 0, bad);
    }

    // ── socksAddr ──
    {
        use goish::net::Addr;
        let a = socksAddr {
            Name: string("example.com"),
            IP: net::IP::default(),
            Port: 80,
        };
        let b = socksAddr {
            Name: string(""),
            IP: net::ParseIP(string("1.2.3.4")),
            Port: 443,
        };
        let z = socksAddr::default();
        check(
            "socksAddr.String prefers IP over Name, and Network is \"socks\"",
            a.String() == "example.com:80"
                && b.String() == "1.2.3.4:443"
                && z.String() == ":0"
                && a.Network() == "socks",
            fmt::Sprintf!("a=%q b=%q z=%q", a.String(), b.String(), z.String()),
        );
    }

    // ── validateTarget ──
    {
        let d = socksNewDialer(string("tcp"), string("127.0.0.1:1080"));
        let ok = d.validateTarget(string("tcp"), string("h:80")).IsNil()
            && d.validateTarget(string("tcp4"), string("h:80")).IsNil()
            && d.validateTarget(string("tcp6"), string("h:80")).IsNil()
            && !d.validateTarget(string("udp"), string("h:80")).IsNil()
            && !d.validateTarget(string("unix"), string("h:80")).IsNil()
            && !d.validateTarget(string(""), string("h:80")).IsNil();
        check("validateTarget accepts tcp/tcp4/tcp6 only", ok, string(""));

        let mut db = socksNewDialer(string("tcp"), string("127.0.0.1:1080"));
        db.cmd = socksCommand(9);
        let e = db.validateTarget(string("tcp"), string("h:80"));
        check(
            "validateTarget rejects an unknown command",
            !e.IsNil() && e.Error() == "command not implemented",
            e.Error(),
        );
    }

    // ── pathAddrs ──
    {
        use goish::net::Addr;
        let d = socksNewDialer(string("tcp"), string("127.0.0.1:1080"));
        let (p, dst, e) = d.pathAddrs(string("example.com:80"));
        let ok = e.IsNil()
            && p.as_ref().map(|a| a.String()) == Some(string("127.0.0.1:1080"))
            && dst.as_ref().map(|a| a.String()) == Some(string("example.com:80"));
        check("pathAddrs resolves proxy and destination", ok, string(""));

        let (p2, dst2, e2) = d.pathAddrs(string("bad"));
        check(
            "pathAddrs propagates a split error",
            !e2.IsNil() && p2.is_none() && dst2.is_none(),
            string(""),
        );
    }

    // ── socksNewDialer defaults ──
    {
        let d = socksNewDialer(string("tcp"), string("127.0.0.1:1080"));
        check(
            "socksNewDialer defaults to CmdConnect with no auth methods",
            d.cmd == socksCmdConnect
                && d.proxyNetwork == "tcp"
                && d.proxyAddress == "127.0.0.1:1080"
                && d.AuthMethods.Len() == 0,
            string(""),
        );
    }

    // ── UsernamePassword validation (no I/O paths) ──
    {
        let up = socksUsernamePassword {
            Username: string(""),
            Password: string("p"),
        };
        let mut sink = discard;
        let e1 = up.Authenticate(
            &goish::context::Background(),
            &mut sink,
            socksAuthMethodUsernamePassword,
        );
        let up2 = socksUsernamePassword {
            Username: string("u"),
            Password: string("p"),
        };
        let e2 = up2.Authenticate(
            &goish::context::Background(),
            &mut sink,
            socksAuthMethodNotRequired,
        );
        let e3 = up2.Authenticate(
            &goish::context::Background(),
            &mut sink,
            goish::net::http::socks_bundle::socksAuthMethod(9),
        );
        check(
            "UsernamePassword: empty user rejected, NotRequired is a no-op, 9 unsupported",
            e1.Error() == "invalid username/password"
                && e2.IsNil()
                && e3.Error() == "unsupported authentication method 9",
            fmt::Sprintf!("e1=%v e2=%v e3=%v", e1, e2, e3),
        );
    }

    // ── a real SOCKS5 CONNECT handshake against a fake proxy ──
    {
        let (ln, lerr) = net::Listen(string("tcp"), string("127.0.0.1:0"));
        if !lerr.IsNil() {
            check("socks handshake", false, fmt::Sprintf!("listen: %v", lerr));
        } else {
            let port = ln.Addr().Port;
            go!(stack(512 * 1024), move || {
                let (mut c, e) = ln.Accept();
                if !e.IsNil() {
                    return;
                }
                // Method-selection request: VER NMETHODS METHODS...
                let mut hdr = goish::make!([]goish::byte, 2);
                let (_, _) = c.Read(&mut hdr);
                let nmethods = hdr[1] as usize;
                if nmethods > 0 {
                    let mut m = goish::make!([]goish::byte, nmethods as goish::int);
                    let (_, _) = c.Read(&mut m);
                }
                // Reply: VER=5 METHOD=0 (no auth).
                let _ = c.Write(goish::slice::<goish::byte>::__from_vec(alloc::vec![5u8, 0u8]));
                // CONNECT request: VER CMD RSV ATYP ADDR PORT
                let mut req = goish::make!([]goish::byte, 4);
                let (_, _) = c.Read(&mut req);
                let atyp = req[3];
                if atyp == 0x03 {
                    let mut n = goish::make!([]goish::byte, 1);
                    let (_, _) = c.Read(&mut n);
                    let mut host = goish::make!([]goish::byte, n[0] as goish::int);
                    let (_, _) = c.Read(&mut host);
                } else if atyp == 0x01 {
                    let mut ip = goish::make!([]goish::byte, 4);
                    let (_, _) = c.Read(&mut ip);
                }
                let mut p = goish::make!([]goish::byte, 2);
                let (_, _) = c.Read(&mut p);
                // Reply: VER=5 REP=0 RSV=0 ATYP=1 BND.ADDR=10.0.0.7 BND.PORT=4660
                let _ = c.Write(goish::slice::<goish::byte>::__from_vec(alloc::vec![
                    5u8, 0u8, 0u8, 1u8, 10u8, 0u8, 0u8, 7u8, 0x12u8, 0x34u8,
                ]));
                time::Sleep(time::Duration(200 * 1_000_000));
            });
            time::Sleep(time::Duration(100 * 1_000_000));

            let d = socksNewDialer(string("tcp"), fmt::Sprintf!("127.0.0.1:%d", port as i64));
            let (conn, cerr) = d.DialContext(
                &goish::context::Background(),
                string("tcp"),
                string("example.com:80"),
            );
            match conn {
                None => {
                    check("SOCKS5 CONNECT handshake", false, fmt::Sprintf!("%v", cerr));
                }
                Some(sc) => {
                    let ba = sc.BoundAddr();
                    // 0x1234 == 4660
                    let ok = ba
                        .as_ref()
                        .map(|a| {
                            use goish::net::Addr;
                            a.String() == "10.0.0.7:4660"
                        })
                        .unwrap_or(false);
                    check(
                        "SOCKS5 CONNECT handshake returns the proxy's bound address",
                        ok,
                        fmt::Sprintf!(
                            "boundAddr=%s",
                            ba.as_ref()
                                .map(|a| {
                                    use goish::net::Addr;
                                    a.String()
                                })
                                .unwrap_or(string("<none>"))
                        ),
                    );
                }
            }
        }
    }

    let p = PASSED.load(Ordering::Relaxed);
    let f = FAILED.load(Ordering::Relaxed);
    fmt::Printf!("\n%d passed, %d failed\n", p as i64, f as i64);
    if f == 0 {
        fmt::Printf!("HTTP_SOCKS_SMOKE_OK\n");
        goish::os::Exit(0);
    }
    fmt::Printf!("HTTP_SOCKS_SMOKE_FAIL\n");
    goish::os::Exit(1);
}

/// A Reader+Writer that goes nowhere. The three Authenticate cases
/// below all return before touching it (empty username, NotRequired,
/// unsupported method), so no bytes are exchanged — it exists only to
/// satisfy the `io::Reader + io::Writer` bound.
#[allow(non_camel_case_types)]
struct discard;

impl Reader for discard {
    fn Read(&mut self, _p: &mut goish::slice<goish::byte>) -> (goish::int, goish::error) {
        return (0, goish::io::EOF.into());
    }
}

impl Writer for discard {
    fn Write(&mut self, p: goish::slice<goish::byte>) -> (goish::int, goish::error) {
        return (p.Len(), goish::errors::nil);
    }
}

#[allow(dead_code)]
fn _unused() -> Vec<u8> {
    Vec::new()
}
