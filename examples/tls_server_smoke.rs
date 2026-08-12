// tls_server_smoke — M32 server-side TLS 1.3 handshake, in-process.
//
// The goish TLS *client* (shipped since the https work) handshakes
// against the new goish TLS *server* over a real loopback TCP
// connection — both ends of RFC 8446 exercised in one binary:
//
//   1. X509KeyPair parses the embedded RSA-2048 self-signed pair
//      (PKCS#8 "PRIVATE KEY" block — the OpenSSL 3.x default), and
//      rejects swapped cert/key inputs.
//   2. tls::Listen + tls::Server accept side: three sequential
//      client connections each complete a full TLS 1.3 handshake
//      (X25519, AES-128-GCM, RSA-PSS CertificateVerify) and run a
//      ping/pong round trip.
//   3. A ChaCha20-Poly1305-only client (DialChaCha20Only) negotiates
//      suite 0x1303 against the same server.
//   4. A 40 KiB payload echoes intact — exercises record
//      fragmentation at maxPlaintext (16384) in both directions.
//   5. Four concurrent client goroutines handshake and round-trip
//      against the shared listener.
//
// The cert is a 100-year self-signed localhost cert generated with
// OpenSSL, embedded the same way Go embeds net/http/internal/testcert.
// Clients dial with InsecureSkipVerify (self-signed), which still
// verifies the CertificateVerify signature against the leaf key.
//
// Marker on success: TLS_SERVER_SMOKE_OK <n>/<n>

#![no_std]
#![no_main]

extern crate alloc;
extern crate goish;

use alloc::vec::Vec;
use core::sync::atomic::{AtomicUsize, Ordering};

use goish::fmt;
use goish::crypto::tls;
use alloc::sync::Arc;
use goish::sync::WaitGroup;
use goish::{go, string};

// ─── embedded test certificate (RSA-2048, CN=localhost) ─────────────

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

/// Echo server conn handler: read until '\n', write the line back
/// prefixed with "pong:", then close.
fn serve_echo(mut conn: tls::Conn) {
    let mut line: Vec<u8> = Vec::new();
    loop {
        let mut buf = goish::slice::<goish::byte>::__from_vec(alloc::vec![0u8; 4096]);
        let (n, err) = conn.Read(&mut buf);
        if n > 0 {
            for i in 0..n {
                line.push(buf[i]);
            }
        }
        if !err.IsNil() {
            let _ = conn.Close();
            return;
        }
        if line.last() == Some(&b'\n') {
            break;
        }
    }
    let mut resp: Vec<u8> = Vec::with_capacity(5 + line.len());
    resp.extend_from_slice(b"pong:");
    resp.extend_from_slice(&line);
    let _ = conn.Write(&resp);
    let _ = conn.Close();
}

/// One client round trip: write `payload` + '\n', read back
/// "pong:" + payload + '\n'. Returns true on exact match.
fn client_roundtrip(port: i64, chacha_only: bool, payload: &[u8]) -> bool {
    let cfg = tls::Config {
        InsecureSkipVerify: true,
        ServerName: string("localhost"),
        ..Default::default()
    };
    let addr = fmt::Sprintf!("127.0.0.1:%d", port);
    let (mut conn, err) = if chacha_only {
        tls::DialChaCha20Only(string("tcp"), addr, &cfg)
    } else {
        tls::Dial(string("tcp"), addr, &cfg)
    };
    if !err.IsNil() {
        fmt::Printf!("client dial/handshake error: %v\n", err);
        return false;
    }
    let mut req: Vec<u8> = payload.to_vec();
    req.push(b'\n');
    let (_, werr) = conn.Write(&req);
    if !werr.IsNil() {
        fmt::Printf!("client write error: %v\n", werr);
        return false;
    }
    let mut got: Vec<u8> = Vec::new();
    let want_len = 5 + req.len();
    loop {
        let mut buf = goish::slice::<goish::byte>::__from_vec(alloc::vec![0u8; 8192]);
        let (n, rerr) = conn.Read(&mut buf);
        if n > 0 {
            for i in 0..n {
                got.push(buf[i]);
            }
        }
        if got.len() >= want_len || !rerr.IsNil() {
            break;
        }
    }
    let _ = conn.Close();
    if got.len() != want_len || &got[..5] != b"pong:" || &got[5..] != &req[..] {
        fmt::Printf!(
            "client echo mismatch: got %d bytes, want %d\n",
            got.len() as i64,
            want_len as i64
        );
        return false;
    }
    true
}

// Write `payload\n` to an already-connected tls::Conn and confirm the
// server's `pong:`-prefixed echo comes back.
fn dial_roundtrip(conn: &mut tls::Conn, payload: &[u8]) -> bool {
    let mut req: Vec<u8> = payload.to_vec();
    req.push(b'\n');
    let (_, werr) = conn.Write(&req);
    if !werr.IsNil() {
        return false;
    }
    let mut got: Vec<u8> = Vec::new();
    let want_len = 5 + req.len();
    loop {
        let mut buf = goish::slice::<goish::byte>::__from_vec(alloc::vec![0u8; 8192]);
        let (n, rerr) = conn.Read(&mut buf);
        if n > 0 {
            for i in 0..n {
                got.push(buf[i]);
            }
        }
        if got.len() >= want_len || !rerr.IsNil() {
            break;
        }
    }
    let _ = conn.Close();
    return got.len() == want_len && &got[..5] == b"pong:" && &got[5..] == &req[..];
}

#[goish::main]
fn main() {
    // ── 1. X509KeyPair parsing ──
    let (cert, err) = tls::X509KeyPair(CERT_PEM, KEY_PEM);
    if err.IsNil() && cert.Certificate.Len() == 1 {
        pass("X509KeyPair parses embedded RSA cert+key");
    } else {
        fail(fmt::Sprintf!("X509KeyPair: %v", err));
        fmt::Printf!("TLS_SERVER_SMOKE_FAIL\n");
        goish::os::Exit(1);
    }
    // Swapped inputs must fail.
    let (_, swap_err) = tls::X509KeyPair(KEY_PEM, CERT_PEM);
    if !swap_err.IsNil() {
        pass("X509KeyPair rejects swapped cert/key inputs");
    } else {
        fail(string("X509KeyPair accepted swapped inputs"));
    }

    // ── server ──
    let cfg = tls::Config {
        Certificates: goish::slice::<tls::Certificate>::__from_vec(alloc::vec![cert]),
        ..Default::default()
    };
    let (ln, err) = tls::Listen(string("tcp"), string("127.0.0.1:0"), &cfg);
    if !err.IsNil() {
        fail(fmt::Sprintf!("tls.Listen: %v", err));
        fmt::Printf!("TLS_SERVER_SMOKE_FAIL\n");
        goish::os::Exit(1);
    }
    let port = ln.Addr().Port;
    go!(move || {
        loop {
            let (conn, err) = ln.Accept();
            if !err.IsNil() {
                return;
            }
            go!(move || {
                serve_echo(conn);
            });
        }
    });

    // ── 2. three sequential full handshakes + round trips ──
    let mut seq_ok = true;
    for i in 0..3i64 {
        let payload = fmt::Sprintf!("ping %d", i);
        let ps: &str = payload.as_ref();
        if !client_roundtrip(port, false, ps.as_bytes()) {
            seq_ok = false;
        }
    }
    if seq_ok {
        pass("3 sequential TLS 1.3 handshakes + echo round trips");
    } else {
        fail(string("sequential handshake round trips"));
    }

    // ── 3. ChaCha20-Poly1305-only client ──
    if client_roundtrip(port, true, b"chacha ping") {
        pass("ChaCha20-Poly1305-only client negotiates 0x1303");
    } else {
        fail(string("ChaCha20-only client round trip"));
    }

    // ── 4. 40 KiB payload (record fragmentation both ways) ──
    let big: Vec<u8> = (0..40960u32).map(|i| (i % 251) as u8 + 1).collect();
    if client_roundtrip(port, false, &big) {
        pass("40 KiB echo (fragmented records both directions)");
    } else {
        fail(string("40 KiB fragmented echo"));
    }

    // ── 5. four concurrent client goroutines ──
    static CONC_OK: AtomicUsize = AtomicUsize::new(0);
    let wg = Arc::new(WaitGroup::new());
    for i in 0..4i64 {
        wg.Add(1);
        let wg2 = wg.clone();
        go!(move || {
            let payload = fmt::Sprintf!("conc %d", i);
            let ps: &str = payload.as_ref();
            if client_roundtrip(port, false, ps.as_bytes()) {
                CONC_OK.fetch_add(1, Ordering::Relaxed);
            }
            wg2.Done();
        });
    }
    wg.Wait();
    if CONC_OK.load(Ordering::Relaxed) == 4 {
        pass("4 concurrent client handshakes");
    } else {
        fail(fmt::Sprintf!(
            "concurrent handshakes: %d/4",
            CONC_OK.load(Ordering::Relaxed) as i64
        ));
    }

    // ── 6. the dial surface: tls::Dialer and tls::DialWithDialer ──
    {
        let addr = fmt::Sprintf!("127.0.0.1:%d", port);
        let cfg = tls::Config {
            InsecureSkipVerify: true,
            ServerName: string("localhost"),
            ..Default::default()
        };
        // tls::DialWithDialer with an explicit net.Dialer.
        let nd = goish::net::Dialer::default();
        let (mut c1, e1) =
            tls::DialWithDialer(&nd, string("tcp"), addr.clone(), &cfg);
        let ok1 = e1.IsNil() && dial_roundtrip(&mut c1, b"dialer ping");
        if ok1 {
            pass("tls::DialWithDialer handshakes and round-trips");
        } else {
            fail(fmt::Sprintf!("DialWithDialer: %v", e1));
        }
        // tls::Dialer{Config}.Dial infers nothing extra; Config carries
        // the ServerName + InsecureSkipVerify.
        let d = tls::Dialer {
            Config: Some(cfg.clone()),
            ..Default::default()
        };
        let (mut c2, e2) = d.Dial(string("tcp"), addr);
        let ok2 = e2.IsNil() && dial_roundtrip(&mut c2, b"dialer.Dial ping");
        if ok2 {
            pass("tls::Dialer{Config}.Dial handshakes and round-trips");
        } else {
            fail(fmt::Sprintf!("Dialer.Dial: %v", e2));
        }
    }

    let p = PASSED.load(Ordering::Relaxed);
    let f = FAILED.load(Ordering::Relaxed);
    if f == 0 {
        fmt::Printf!("TLS_SERVER_SMOKE_OK %d/%d\n", p as i64, (p + f) as i64);
        // The accept-loop goroutine blocks in Accept() forever; the
        // goish runtime exits on LIVE_G_COUNT == 0, so exit explicitly.
        goish::os::Exit(0);
    } else {
        fmt::Printf!("TLS_SERVER_SMOKE_FAIL %d failed\n", f as i64);
        goish::os::Exit(1);
    }
}
