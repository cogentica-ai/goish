// https_http_on_https_smoke — plaintext HTTP sent to an HTTPS port.
//
// Reference: Go 1.25.5 net/http, tools/gen_httpsdiag_ref.go.
//
// One of the most common mistakes there is — an `http://` URL against
// an `https://` port — and Go answers it in words rather than dropping
// the connection:
//
//   HTTP/1.0 400 Bad Request\r\n\r\nClient sent an HTTP request to an
//   HTTPS server.\n
//
// goish had `tlsRecordHeaderLooksLikeHTTP` ported and anchored to
// server.go:4087 and called from nowhere, so the peer got a bare close
// and no explanation at all.
//
// The third row is the one that keeps the fix honest. The test is on
// the RECORD HEADER, not on the fact that the handshake failed: a
// genuine TLS record that fails for some other reason gets nothing,
// exactly as in Go. A fix that answered every handshake failure with
// this message would pass the first two rows and be wrong.
#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

use alloc::sync::Arc;
use alloc::vec::Vec;
use goish::goslice::slice;
use goish::gostring::string;
use goish::io::{Closer, Reader, Writer};
use goish::net;
use goish::net::http;
use goish::types::{byte, int};
use goish::{crypto::tls, fmt, go, time};

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

const GO: [&str; 3] = [
    "probe=GET       reply=\"HTTP/1.0 400 Bad Request\\r\\n\\r\\nClient sent an HTTP request to an HTTPS server.\\n\"",
    "probe=POST      reply=\"HTTP/1.0 400 Bad Request\\r\\n\\r\\nClient sent an HTTP request to an HTTPS server.\\n\"",
    "probe=tls-junk  reply=\"\"",
];

fn chk(ln: &mut usize, got: &string) {
    if *ln >= GO.len() {
        fmt::Printf!("[!!] extra line: %q\n", got);
        *ln += 1;
        return;
    }
    if got == GO[*ln] {
        fmt::Printf!("[ok] %s\n", got);
    } else {
        fmt::Printf!("[!!] line %d\n  got  %q\n  want %q\n", *ln as int + 1, got, GO[*ln]);
    }
    *ln += 1;
}

#[goish::main]
fn main() {
    go!(stack(1024 * 1024), move || {
        run();
    });
    loop {
        goish::runtime::sched::Gosched();
    }
}

fn run() {
    let (cert, cerr) = tls::X509KeyPair(
        slice::__from_vec(CERT_PEM.to_vec()),
        slice::__from_vec(KEY_PEM.to_vec()),
    );
    if !cerr.IsNil() {
        fmt::Printf!("[!!] X509KeyPair: %v\n", cerr);
        goish::os::Exit(1);
    }

    let mux = http::ServeMux::new();
    mux.HandleFunc(string::from("/"), |_w, _r| {});
    let mut cfg = tls::Config::default();
    cfg.Certificates = slice::__from_vec(alloc::vec![cert]);
    let mut srv = http::Server::default();
    srv.Handler = Arc::new(mux) as Arc<dyn http::Handler>;
    srv.TLSConfig = Some(cfg);
    let srv = Arc::new(srv);

    let (l, lerr) = net::Listen(string::from("tcp"), string::from("127.0.0.1:0"));
    if !lerr.IsNil() {
        fmt::Printf!("[!!] listen: %v\n", lerr);
        goish::os::Exit(1);
    }
    let addr = l.Addr().String();
    let s2 = srv.clone();
    go!(stack(1024 * 1024), move || {
        let _ = s2.ServeTLS(l, string::from(""), string::from(""));
    });
    time::Sleep(time::Millisecond * 100);

    let probes: [(&str, &[u8]); 3] = [
        ("GET", b"GET / HTTP/1.1\r\nHost: x\r\n\r\n"),
        ("POST", b"POST /x HTTP/1.1\r\nHost: x\r\n\r\n"),
        ("tls-junk", b"\x16\x03\x01\x00\x05junk"),
    ];
    let mut ln_no: usize = 0;
    for (name, probe) in probes.iter() {
        let (mut c, derr) = net::Dial(string::from("tcp"), addr.clone());
        if !derr.IsNil() {
            fmt::Printf!("[!!] dial: %v\n", derr);
            goish::os::Exit(1);
        }
        let _ = c.SetReadDeadline(time::Now().Add(time::Second * 2));
        let _ = c.Write(slice::__from_vec(probe.to_vec()));
        let mut raw: Vec<u8> = Vec::new();
        let mut buf: slice<byte> = slice::__from_vec(alloc::vec![0u8; 512]);
        loop {
            let (n, e) = c.Read(&mut buf);
            if n > 0 {
                raw.extend_from_slice(&buf.as_ref()[..n as usize]);
            }
            if n <= 0 || !e.IsNil() {
                break;
            }
        }
        let _ = c.Close();
        chk(&mut ln_no, &fmt::Sprintf!("probe=%-9s reply=%q",
            string::from(*name), string::from_bytes(&raw)));
    }

    let _ = srv.Close();
    if ln_no != GO.len() {
        fmt::Printf!("[!!] produced %d lines, pinned %d\n", ln_no as int, GO.len() as int);
    }
    goish::os::Exit(0);
}
