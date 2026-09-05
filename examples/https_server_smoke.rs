// https_server_smoke — end-to-end `http.Server.ServeTLS` self-test.
//
// Covers the three things the HTTPS serve loop (src/net/http/server_tls.rs)
// did NOT do before 2026-08-14, each of which the plaintext loop has
// always done:
//
//   1. `Request.TLS` is stamped on every request served over TLS
//      (Go readRequest, server.go:1123), so a handler can tell it is
//      on HTTPS and read the negotiated version/cipher.
//   2. `ReadHeaderTimeout` bounds the wait for the first byte of a
//      request. Without it a peer that completes the handshake and
//      then sends nothing pins the conn goroutine forever — a
//      slowloris hole on the TLS path only.
//   3. `Server.tlsHandshakeTimeout()` (server.go:3571) bounds the
//      handshake itself, so a peer that opens TCP and stalls mid-
//      handshake cannot pin the conn either.
//
// Test 2 is the regression tripwire: before the fix it does not fail,
// it HANGS.

#![no_std]
#![no_main]

extern crate alloc;
extern crate goish;

use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicUsize, Ordering};

use goish::crypto::tls;
use goish::fmt;
use goish::net;
use goish::net::http;
use goish::time;
use goish::{go, string};

// ─── embedded test certificate (RSA-2048, CN=localhost) ─────────────
// Same pair tls_server_smoke.rs embeds; Go embeds one the same way in
// net/http/internal/testcert.

const CERT_PEM: &[u8] = b"-----BEGIN CERTIFICATE-----
MIIDRzCCAi+gAwIBAgIUExsnkkUFaklsYSdfl+loT602qZYwDQYJKoZIhvcNAQEL
BQAwJDEOMAwGA1UECgwFR29pc2gxEjAQBgNVBAMMCWxvY2FsaG9zdDAgFw0yNjA3
MTkxNDAzMDNaGA8yMTI2MDYyNTE0MDMwM1owJDEOMAwGA1UECgwFR29pc2gxEjAQ
BgNVBAMMCWxvY2FsaG9zdDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEB
AL71SKjOEwMD+eKxArRXXzDYEQSZGvOZVsNEzvqO1U3ExcFQE7dT7tONmhkKOj4a
QzwHTSdqN3okuZowKXbBf+zmLtU/yJqVx9X3CJKeXexIHRYjCALBsejooa3RJhiR
3tVvEdNOGsZtiKO/BUWccUseaLqWBm4FF49w+bT4QWcB5abk+vRTMpBDJXY/e6lN
/BY74xBM2KidcHk2jt4QRzd6Ana7/+FI1tTKTPka6yiF99jHXeL55nlNwxmb829d
iT+xhvGDRnL/ko7mQieuVTTdnJIxVJLmRSs/UO47c0UOcGI8vkx88H5phfetmj6x
rVwLrG7cz3P+PR371u8lM7MCAwEAAaNvMG0wHQYDVR0OBBYEFLtTGr0kjsxYion9
b78o00eWI/sSMB8GA1UdIwQYMBaAFLtTGr0kjsxYion9b78o00eWI/sSMA8GA1Ud
EwEB/wQFMAMBAf8wGgYDVR0RBBMwEYIJbG9jYWxob3N0hwR/AAABMA0GCSqGSIb3
DQEBCwUAA4IBAQAu8dsWK1iCB/rbVQJ72vTn9aWFLW4TofxAgktLBJ0nHOHNJ1xS
yHyqCMz7iVhYKw9HsCcAJZxLsZCwHKlGVw2wvNOvOxB+PwVAVI9RNurAOl16djPW
HUODLOteW8fWsjYwBXBDbseVy3Jkq68qA24nOasFSJpj2Ay5L5Z95hEHshl0M4WS
wytOjSWvohLEA+ui2kl9izXjqSainxgR2Fy3JMydG5/hyj9vhN1KMX6z35/C0LuU
pGdh5BY9K5w6njHPtK+euG6V3Orkgj5CXvF77KOP869Fafvlxxi7wBerD29LECog
85yHo8ucdwukzqcy7NoMlnDHf20O8wBEZ56n
-----END CERTIFICATE-----
";

const KEY_PEM: &[u8] = b"-----BEGIN PRIVATE KEY-----
MIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQC+9UiozhMDA/ni
sQK0V18w2BEEmRrzmVbDRM76jtVNxMXBUBO3U+7TjZoZCjo+GkM8B00najd6JLma
MCl2wX/s5i7VP8ialcfV9wiSnl3sSB0WIwgCwbHo6KGt0SYYkd7VbxHTThrGbYij
vwVFnHFLHmi6lgZuBRePcPm0+EFnAeWm5Pr0UzKQQyV2P3upTfwWO+MQTNionXB5
No7eEEc3egJ2u//hSNbUykz5GusohffYx13i+eZ5TcMZm/NvXYk/sYbxg0Zy/5KO
5kInrlU03ZySMVSS5kUrP1DuO3NFDnBiPL5MfPB+aYX3rZo+sa1cC6xu3M9z/j0d
+9bvJTOzAgMBAAECggEAM6OL/w4fKQkZuZpJk3AvLzu2umoW1joossx4NlyKxSmJ
msGnW0OoyW+49L2Fy4Z5mRGWZSq9jtvAjzgn9lPUXsFOd990RY1siWlw2YlW9872
gqZ9g5VSoZvLIQB2j11fB5OuG9i6t98l/LXq3Iy2PGygQJjSa00YNnOEK1KZCRwM
IX7wxcJI1jfSqeF8lTaYGADssPgK+p7m8oQaaZ3zlTtvDh0MoaaLQ5T7IiPy2Xaq
quo9CO9fytnVOnRspqcF4NEqNpxBy7au+CoCuB2V+pL3GdaopZgFQYU8xo900/bA
ai74bVJYb65o3mVrRpjEkKc4o9+ajE/YgYegMqq8VQKBgQDf+GnvislCbhboIXg2
rPIMGdHW89xiUMgewmi0r+pt1i0y70Fxf2sfRls+9QvuGI+Tv/QHZD7NH/EfbEBo
rNTVjbN62xYEXBraRTehpqVVMCuBl5siUNeImHSpjRNL1IzI2WDbcLZIuLj0gJQ+
SZUJXfDku3GLiq3JaTnhaNDC3QKBgQDaREmus7DjKXNjxCHPi7U5aHgbS1L5RtN7
1FQrWawec/hINz4xzyWERm35uelfxd/PzA1bScqjckjmNNAEXtq2ZhdINA+bHSX8
kFyEO8gl9KI/43Ez/rhdjARdPJfqfYUqkpT/A7+UsoQto6Sc6KcKzi/LDtSDFmJJ
b1Gs65x/zwKBgBbWwx69PVa72TQkrZiNvEUFoQNVbMTNzgps8rZyNeqra4KFKVxE
jQzsZMOfw26tLH75lQ3n6AuM1U7KACtsbGu2fnXpv24EYmydoFWoo7VzKwyVBCnU
qpXwTf04OJ6D9zNID3txG/WAeMPeFL/hSwRggv8gKiz7oEsootFcmeU1AoGAaOD1
UtgPQChTxPWilXr5OrujMuJP3W4WAuN1CluNZBivjevVm9OAoH3DLIMTy6xmLhBL
vrjHgSBSPSPVbLQzff+yYkR51zv7W8/2VKfxNaPGLtLYO3bDGlhEZJTQHqHv0hQb
OiqP7SCWeOOwHqGAWqXWu0jF/rNLySOPaHrSeWsCgYAYN6DznwaMUQpyai/BObGf
L41DhsrRVfZpQaLFJUqztgy7+0uWWowmz/3FVTAd6iutAMqHO3KlQpdhpb9dLFJJ
EWyvWmpojOOUhO57GR6qmIZ5aElOpRnQpRv8yXIfO0huzOCe40gtwRxAuPGZQrzc
rTXGcd5XGWoS0+AF8t1cUw==
-----END PRIVATE KEY-----
";

// ─── harness ────────────────────────────────────────────────────────

static PASSED: AtomicUsize = AtomicUsize::new(0);
static FAILED: AtomicUsize = AtomicUsize::new(0);

fn pass(name: &'static str) {
    PASSED.fetch_add(1, Ordering::Relaxed);
    fmt::Printf!("PASS: %s\n", name);
}

fn fail(msg: goish::string) {
    FAILED.fetch_add(1, Ordering::Relaxed);
    fmt::Printf!("FAIL: %s\n", msg);
}

/// Dial the server, send `req` verbatim, read until EOF or `limit`
/// bytes. Returns `(bytes_read_as_string, saw_eof)`.
fn tls_request(port: goish::int, req: &[u8], limit: usize) -> (goish::string, bool) {
    let addr = fmt::Sprintf!("127.0.0.1:%d", port as i64);
    let cfg = tls::Config {
        InsecureSkipVerify: true,
        ServerName: string("localhost"),
        ..Default::default()
    };
    let (mut c, e) = tls::Dial(string("tcp"), addr, &cfg);
    if !e.IsNil() {
        fmt::Printf!("   dial error: %v\n", e);
        return (string(""), false);
    }
    let (_, we) = c.Write(goish::slice::<goish::byte>::__from_vec(req.to_vec()));
    if !we.IsNil() {
        fmt::Printf!("   write error: %v\n", we);
        let _ = c.Close();
        return (string(""), false);
    }
    let mut out: Vec<u8> = Vec::new();
    let mut buf = goish::make!([]goish::byte, 4096);
    let mut eof = false;
    while out.len() < limit {
        let (n, re) = c.Read(&mut buf);
        if n > 0 {
            for i in 0..n {
                out.push(buf[i]);
            }
        }
        if !re.IsNil() {
            eof = true;
            break;
        }
        if n == 0 {
            eof = true;
            break;
        }
    }
    let _ = c.Close();
    (goish::string::from_bytes(&out), eof)
}

/// `tls_request` with an ALPN list. Go's ServeTLS runs its config
/// through `adjustNextProtos`, so an HTTP/1-only server answers
/// "http/1.1" to any client that offers it — and filters "h2" out
/// rather than negotiating a protocol it cannot speak.
fn tls_request_alpn(
    port: goish::int,
    req: &[u8],
    limit: usize,
    protos: &[&'static str],
) -> (goish::string, bool) {
    let addr = fmt::Sprintf!("127.0.0.1:%d", port as i64);
    let mut np = goish::slice::<goish::string>::new();
    for p in protos.iter() {
        np = goish::append!(np, string(*p));
    }
    let cfg = tls::Config {
        InsecureSkipVerify: true,
        ServerName: string("localhost"),
        NextProtos: np,
        ..Default::default()
    };
    let (mut c, e) = tls::Dial(string("tcp"), addr, &cfg);
    if !e.IsNil() {
        fmt::Printf!("   dial error: %v\n", e);
        return (string(""), false);
    }
    let (_, we) = c.Write(goish::slice::<goish::byte>::__from_vec(req.to_vec()));
    if !we.IsNil() {
        let _ = c.Close();
        return (string(""), false);
    }
    let mut out: Vec<u8> = Vec::new();
    let mut buf = goish::make!([]goish::byte, 4096);
    while out.len() < limit {
        let (n, re) = c.Read(&mut buf);
        if n > 0 {
            for i in 0..n {
                out.push(buf[i]);
            }
        }
        if n <= 0 || !re.IsNil() {
            break;
        }
    }
    let _ = c.Close();
    return (goish::string::from_bytes(&out), true);
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
    let (cert, cerr) = tls::X509KeyPair(CERT_PEM, KEY_PEM);
    if !cerr.IsNil() {
        fail(fmt::Sprintf!("X509KeyPair: %v", cerr));
        finish();
    }

    // A handler that reports what it can see about the connection.
    let mux = http::ServeMux::new();
    mux.HandleFunc("/alpn", |w, r| {
        let body = match r.TLS.as_ref() {
            None => string("tls=absent"),
            Some(st) => fmt::Sprintf!("negotiated=%q", st.NegotiatedProtocol),
        };
        let _ = w.Write(goish::convert::bytes(body));
    });
    mux.HandleFunc("/tlsinfo", |w, r| {
        let body = match r.TLS.as_ref() {
            None => string("tls=absent"),
            Some(st) => fmt::Sprintf!(
                "tls=present version=%d complete=%v cipher=%d server_name=%s",
                st.Version as i64,
                st.HandshakeComplete,
                st.CipherSuite as i64,
                st.ServerName
            ),
        };
        let _ = w.Write(goish::convert::bytes(body));
    });

    // The HTTPS loop builds its own context (it does not go through
    // serve_conn), so the two server context keys have to be stamped
    // there separately — and did not used to be at all.
    mux.HandleFunc("/ctx", |w, r| {
        let ctx = r.Context();
        let srv_seen = ctx.Value(http::server::ServerContextKey).is_some();
        let local = match ctx.Value(http::server::LocalAddrContextKey) {
            None => string("absent"),
            Some(v) => match v.downcast_ref::<net::TCPAddr>() {
                None => string("wrong-type"),
                Some(a) => a.String(),
            },
        };
        let _ = w.Write(goish::convert::bytes(fmt::Sprintf!(
            "server=%v local=%s",
            srv_seen,
            local
        )));
    });

    mux.HandleFunc("/panic", |_w, _r| {
        panic!("intentional panic from the /panic route");
    });

    let srv = Arc::new(http::Server {
        Handler: Arc::new(mux),
        TLSConfig: Some(tls::Config {
            Certificates: goish::slice::<tls::Certificate>::__from_vec(alloc::vec![cert]),
            ..Default::default()
        }),
        // Short enough that the slowloris tripwire (test 2) finishes
        // quickly, generous enough that a debug-build RSA-2048
        // handshake on a loaded box still lands inside
        // `tlsHandshakeTimeout()` — which Go derives from exactly
        // these three fields, so it is 3s here too. At 300ms this
        // test reaped its own legitimate clients under load.
        ReadHeaderTimeout: time::Duration(3 * 1_000_000_000),
        ..Default::default()
    });

    let (ln, lerr) = net::Listen(string("tcp"), string("127.0.0.1:0"));
    if !lerr.IsNil() {
        fail(fmt::Sprintf!("net.Listen: %v", lerr));
        finish();
    }
    let port = ln.Addr().Port;

    {
        let srv2 = srv.clone();
        go!(stack(1024 * 1024), move || {
            let _ = srv2.ServeTLS(ln, string(""), string(""));
        });
    }
    // Let the accept loop park.
    time::Sleep(time::Duration(100 * 1_000_000));

    // ── 0. ALPN: the server must offer http/1.1 ──
    //
    // Go's ServeTLS runs its TLS config through `adjustNextProtos`
    // (server.go:3519) before the listener is wrapped. goish had that
    // function ported and anchored and called from nowhere, and never
    // set NextProtos at all, so its HTTPS server advertised no ALPN:
    // every line below came back negotiated="" where Go negotiates
    // http/1.1. A client that inspects ConnectionState, or a peer that
    // requires an ALPN match, sees a different server.
    //
    // The h2 line is the one that matters, and it caught a second
    // defect in the fix itself. `Server::protocols()` faithfully
    // mirrors Go and defaults to HTTP1|HTTP2, so feeding it straight
    // into adjustNextProtos made goish advertise "h2" and NEGOTIATE
    // it — agreeing to speak a protocol it has no implementation of,
    // then parsing the h2 preface with an HTTP/1 parser. This line
    // read negotiated="h2" for one build. Advertising nothing was bad;
    // advertising h2 was worse.
    //
    // The reference is a Go server configured HTTP/1-only, because
    // that is what goish is. Go's default build serves h2 for real and
    // its nethttpomithttp2 build advertises h2 and then hangs up on
    // whoever picks it; neither is a behaviour to copy here.
    {
        let cases: [(&str, &[&'static str], &str); 3] = [
            ("http/1.1 only", &["http/1.1"], "negotiated=\"http/1.1\""),
            ("h2 then http/1.1", &["h2", "http/1.1"], "negotiated=\"http/1.1\""),
            ("no ALPN offered", &[], "negotiated=\"\""),
        ];
        for (name, protos, want) in cases.iter() {
            let (resp, _) = tls_request_alpn(
                port,
                b"GET /alpn HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
                8192,
                protos,
            );
            let s: &str = resp.as_ref();
            if s.contains(*want) {
                PASSED.fetch_add(1, Ordering::Relaxed);
                fmt::Printf!("PASS: ALPN %s -> %s\n", string(*name), string(*want));
            } else {
                fail(fmt::Sprintf!("ALPN %s: want %s got %s", string(*name), string(*want), resp));
            }
        }
    }

    // ── 1. Request.TLS is populated ──
    {
        let (resp, _) = tls_request(
            port,
            b"GET /tlsinfo HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
            8192,
        );
        let s: &str = resp.as_ref();
        if s.contains("tls=present") && s.contains("complete=true") {
            pass("Request.TLS stamped on an HTTPS request");
        } else {
            fail(fmt::Sprintf!("Request.TLS: got %s", resp.clone()));
        }
        // TLS 1.3 == 0x0304 == 772.
        if s.contains("version=772") {
            pass("Request.TLS carries the negotiated version (TLS 1.3)");
        } else {
            fail(fmt::Sprintf!("negotiated version: got %s", resp));
        }
    }

    // ── 1b. the two server context keys reach an HTTPS handler ──
    {
        let (resp, _) = tls_request(
            port,
            b"GET /ctx HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
            8192,
        );
        let s: &str = resp.as_ref();
        if s.contains("server=true") {
            pass("ServerContextKey reaches a handler over HTTPS");
        } else {
            fail(fmt::Sprintf!("ServerContextKey: got %s", resp.clone()));
        }
        let want = fmt::Sprintf!("local=127.0.0.1:%d", port as i64);
        if s.contains(want.as_ref() as &str) {
            pass("LocalAddrContextKey carries the accepting address over HTTPS");
        } else {
            fail(fmt::Sprintf!("LocalAddrContextKey: got %s", resp));
        }
    }

    // ── 1c. the HTTP/1-only gate applies over TLS too ──
    //
    // A TLS conn is exactly where an HTTP/2 preface arrives, so this
    // is the half of the gate that matters. Wire format from
    // scripts/goref.sh against Go 1.25.5.
    {
        let (resp, _) = tls_request(
            port,
            b"GET /tlsinfo HTTP/2.0\r\nHost: localhost\r\n\r\n",
            8192,
        );
        let s: &str = resp.as_ref();
        if s.starts_with("HTTP/1.1 505 HTTP Version Not Supported") && !s.contains("tls=") {
            pass("an HTTP/2.0 request line over TLS is refused with 505");
        } else {
            fail(fmt::Sprintf!("505 over TLS: got %s", resp));
        }
    }

    // ── 1d. OPTIONS * reaches globalOptionsHandler over TLS ──
    {
        let (resp, _) = tls_request(
            port,
            b"OPTIONS * HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
            8192,
        );
        let s: &str = resp.as_ref();
        if s.starts_with("HTTP/1.1 200") {
            pass("OPTIONS * is answered by the global options handler over TLS");
        } else {
            fail(fmt::Sprintf!("OPTIONS * over TLS: got %s", resp));
        }
    }

    // ── 2. ReadHeaderTimeout closes a silent post-handshake conn ──

    // THE TRIPWIRE: before the fix this blocks forever, because the
    // HTTPS loop armed no read deadline at all.
    {
        let addr = fmt::Sprintf!("127.0.0.1:%d", port as i64);
        let cfg = tls::Config {
            InsecureSkipVerify: true,
            ServerName: string("localhost"),
            ..Default::default()
        };
        let (mut c, e) = tls::Dial(string("tcp"), addr, &cfg);
        if !e.IsNil() {
            fail(fmt::Sprintf!("slowloris dial: %v", e));
        } else {
            let start = time::Now();
            // Handshake completed by Dial; send NOTHING and read.
            // The server must close on us once ReadHeaderTimeout
            // (300ms) expires.
            let mut buf = goish::make!([]goish::byte, 64);
            let (_, re) = c.Read(&mut buf);
            let elapsed = time::Since(start);
            let _ = c.Close();
            if re.IsNil() {
                fail(string("silent conn got data instead of being closed"));
            } else if elapsed < time::Duration(20 * 1_000_000_000) {
                pass("ReadHeaderTimeout closes a silent post-handshake conn");
            } else {
                fail(fmt::Sprintf!(
                    "silent conn took %dms to close",
                    elapsed.0 as i64 / 1_000_000
                ));
            }
        }
    }

    // ── 3. the server still serves after reaping the silent conn ──
    {
        let (resp, _) = tls_request(
            port,
            b"GET /tlsinfo HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
            8192,
        );
        let s: &str = resp.as_ref();
        if s.contains("tls=present") {
            pass("server keeps serving after a timed-out conn");
        } else {
            fail(fmt::Sprintf!("post-timeout request: got %s", resp));
        }
    }

    // ── 4. keep-alive: two requests on one TLS conn ──
    {
        let addr = fmt::Sprintf!("127.0.0.1:%d", port as i64);
        let cfg = tls::Config {
            InsecureSkipVerify: true,
            ServerName: string("localhost"),
            ..Default::default()
        };
        let (mut c, e) = tls::Dial(string("tcp"), addr, &cfg);
        if !e.IsNil() {
            fail(fmt::Sprintf!("keep-alive dial: %v", e));
        } else {
            let mut got = 0;
            for _ in 0..2 {
                let (_, we) = c.Write(goish::slice::<goish::byte>::__from_vec(
                    b"GET /tlsinfo HTTP/1.1\r\nHost: localhost\r\n\r\n".to_vec(),
                ));
                if !we.IsNil() {
                    break;
                }
                let mut buf = goish::make!([]goish::byte, 4096);
                let (n, re) = c.Read(&mut buf);
                if !re.IsNil() || n == 0 {
                    break;
                }
                let mut v: Vec<u8> = Vec::new();
                for i in 0..n {
                    v.push(buf[i]);
                }
                let piece = goish::string::from_bytes(&v);
                let ps: &str = piece.as_ref();
                if ps.contains("tls=present") {
                    got += 1;
                }
            }
            let _ = c.Close();
            if got == 2 {
                pass("two keep-alive requests on one TLS conn");
            } else {
                fail(fmt::Sprintf!("keep-alive: %d/2 responses", got as i64));
            }
        }
    }

    // ── 5. a panicking handler closes the conn instead of leaking it ──
    // goish's recovery longjmps to the goroutine entry without running
    // Rust drops, so without the deferred close in `serve_tls_conn`
    // the tls::Conn and its fd are abandoned: the client waits for a
    // response that never comes, and the server leaks a descriptor per
    // panicking request. Bounded by a CLIENT-side read deadline so a
    // regression fails the test instead of hanging CI.
    {
        let addr = fmt::Sprintf!("127.0.0.1:%d", port as i64);
        let cfg = tls::Config {
            InsecureSkipVerify: true,
            ServerName: string("localhost"),
            ..Default::default()
        };
        let (mut c, e) = tls::Dial(string("tcp"), addr, &cfg);
        if !e.IsNil() {
            fail(fmt::Sprintf!("panic-route dial: %v", e));
        } else {
            let _ = c.Write(goish::slice::<goish::byte>::__from_vec(
                b"GET /panic HTTP/1.1\r\nHost: localhost\r\n\r\n".to_vec(),
            ));
            let _ = c.SetReadDeadline(time::Now().Add(time::Duration(8 * 1_000_000_000)));
            let start = time::Now();
            let mut buf = goish::make!([]goish::byte, 64);
            let (n, re) = c.Read(&mut buf);
            let elapsed = time::Since(start);
            let _ = c.Close();
            if !re.IsNil() && n == 0 && elapsed < time::Duration(8 * 1_000_000_000) {
                pass("panicking handler closes the conn (no fd leak, no client hang)");
            } else {
                fail(fmt::Sprintf!(
                    "panic route: n=%d err=%v after %dms",
                    n as i64,
                    re,
                    elapsed.0 as i64 / 1_000_000
                ));
            }
        }
    }

    // ── 6. the server survives the panic and still serves ──
    {
        let (resp, _) = tls_request(
            port,
            b"GET /tlsinfo HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
            8192,
        );
        let s: &str = resp.as_ref();
        if s.contains("tls=present") {
            pass("server survives a panicking HTTPS handler");
        } else {
            fail(fmt::Sprintf!("post-panic request: got %s", resp));
        }
    }

    // ── 7. Shutdown kicks an idle HTTPS keep-alive conn ──
    // The HTTPS loop used to register nothing with the shutdown
    // machinery, so `Shutdown` returned while HTTPS conns were still
    // open and never kicked an idle one. Tripwire: hold an idle
    // keep-alive conn, call Shutdown, and require the peer to observe
    // the close.
    {
        let addr = fmt::Sprintf!("127.0.0.1:%d", port as i64);
        let cfg = tls::Config {
            InsecureSkipVerify: true,
            ServerName: string("localhost"),
            ..Default::default()
        };
        let (mut c, e) = tls::Dial(string("tcp"), addr, &cfg);
        if !e.IsNil() {
            fail(fmt::Sprintf!("shutdown-probe dial: %v", e));
        } else {
            // One request so the conn lands in the idle keep-alive
            // state (no `Connection: close`).
            let _ = c.Write(goish::slice::<goish::byte>::__from_vec(
                b"GET /tlsinfo HTTP/1.1\r\nHost: localhost\r\n\r\n".to_vec(),
            ));
            let mut buf = goish::make!([]goish::byte, 4096);
            let (n, _) = c.Read(&mut buf);
            if n == 0 {
                fail(string("shutdown probe: no response to first request"));
            } else {
                let srv2 = srv.clone();
                go!(stack(1024 * 1024), move || {
                    let _ = srv2.Shutdown(time::Duration(10 * 1_000_000_000));
                });
                let _ = c.SetReadDeadline(time::Now().Add(time::Duration(10 * 1_000_000_000)));
                let start = time::Now();
                let mut b2 = goish::make!([]goish::byte, 64);
                let (n2, re2) = c.Read(&mut b2);
                let elapsed = time::Since(start);
                // Bound well under the 3s idle read deadline: only the
                // Shutdown KICK can close it this fast. Letting the
                // idle timeout do it would take ~3s and fail here.
                if n2 == 0 && !re2.IsNil() && elapsed < time::Duration(1_500 * 1_000_000) {
                    pass("Shutdown kicks an idle HTTPS keep-alive conn");
                } else {
                    fail(fmt::Sprintf!(
                        "shutdown probe: n=%d err=%v after %dms",
                        n2 as i64,
                        re2,
                        elapsed.0 as i64 / 1_000_000
                    ));
                }
            }
            let _ = c.Close();
        }
    }

    finish();
}

fn finish() -> ! {
    let p = PASSED.load(Ordering::Relaxed);
    let f = FAILED.load(Ordering::Relaxed);
    fmt::Printf!("\n%d passed, %d failed\n", p as i64, f as i64);
    if f == 0 {
        fmt::Printf!("HTTPS_SERVER_SMOKE_OK\n");
        goish::os::Exit(0);
    }
    fmt::Printf!("HTTPS_SERVER_SMOKE_FAIL\n");
    goish::os::Exit(1);
}
