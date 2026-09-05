// Response header ORDER on the wire, against Go 1.25.5.
//
// Go does not emit one fixed sequence. chunkWriter.writeHeader writes
// the handler's own header map SORTED via Header.WriteSubset, and then
// writes the headers the SERVER derived through extraHeader.Write, in
// the fixed order Date, Content-Length, Content-Type, Connection,
// Transfer-Encoding (net/http/server.go:1265). Which of the five are
// "derived" depends on what the handler already set, so the wire order
// genuinely differs between responses:
//
//   plain             the server derives Content-Type by sniffing, so
//                     it lands in the extra block AFTER Date.
//   servecontent-ish  the handler sets Content-Type itself, so it
//                     stays in the sorted block BEFORE Date.
//
// Those two rows are the point of this smoke: a single fixed order
// cannot satisfy both, which is why goish snapshots the header at
// header-commit time (respInner.committed) and treats anything added
// afterwards as server-derived.
//
// Only the header KEYS are compared. Values carry a Date and an
// ephemeral port; the order is what is under test.
//
// Reference: scripts/goref.sh net/http, header keys in wire order.
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
use goish::crypto::tls;
use goish::net::http;
use goish::types::byte;
use goish::{fmt, go, time};

const GO: [&str; 6] = [
    "trailer            Trailer, Date, Content-Type, Connection, Transfer-Encoding",
    "plain              Date, Content-Length, Content-Type, Connection",
    "servecontent-ish   Accept-Ranges, Content-Length, Content-Type, Date, Connection",
    "tls-trailer        Trailer, Date, Content-Type, Connection, Transfer-Encoding",
    "tls-plain          Date, Content-Length, Content-Type, Connection",
    "tls-servecontent-ish Accept-Ranges, Content-Length, Content-Type, Date, Connection",
];

fn chk(ln: &mut usize, got: &string) {
    if *ln >= GO.len() {
        fmt::Printf!("[!!] extra line: %q\n", got);
        *ln += 1;
        return;
    }
    let want = string::from(GO[*ln]);
    if got.clone() == want {
        fmt::Printf!("[ok] %s\n", got);
    } else {
        fmt::Printf!("[!!] goish: %q\n", got);
        fmt::Printf!("     go   : %q\n", want);
    }
    *ln += 1;
}

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

#[goish::main]
fn main() {
    go!(stack(1024 * 1024), move || { run(); });
    loop { goish::runtime::sched::Gosched(); }
}

/// The three response shapes, shared by the plain and TLS passes so
/// the two are compared on identical input.
fn handler<W: http::ResponseWriter + goish::goany::HasDynAny + ?Sized>(k: &string, w: &W) {
    if k.clone() == string::from("trailer") {
        w.Header().Set(string::from("Trailer"), string::from("X-Sum"));
        let _ = w.Write(goish::convert::bytes(string::from("body")));
        let (f, ok) = goish::cast!(w, http::Flusher);
        if ok { f.Flush(); }
        w.Header().Set(string::from("X-Sum"), string::from("42"));
    } else if k.clone() == string::from("servecontent-ish") {
        // The handler sets Content-Type and Content-Length itself, so
        // they stay in the sorted block instead of the extra block.
        w.Header().Set(string::from("Accept-Ranges"), string::from("bytes"));
        w.Header().Set(string::from("Content-Type"), string::from("text/plain"));
        w.Header().Set(string::from("Content-Length"), string::from("4"));
        let _ = w.Write(goish::convert::bytes(string::from("body")));
    } else {
        let _ = w.Write(goish::convert::bytes(string::from("body")));
    }
}

/// The response header KEYS in wire order. Values carry a Date and an
/// ephemeral port; the order is what is under test.
fn header_keys(raw: &[u8]) -> string {
    let txt = string::from_bytes(raw);
    let mut out = string::new();
    let mut first = true;
    for line in goish::strings::Split(txt, string::from("\r\n")).iter() {
        if line.Len() == 0 { break; }
        if goish::strings::HasPrefix(line.clone(), string::from("HTTP/")) { continue; }
        let (k, _, _) = goish::strings::Cut(line.clone(), string::from(":"));
        if !first { out = out + string::from(", "); }
        out = out + k;
        first = false;
    }
    return out;
}

fn run() {
    let mut ln: usize = 0;
    for kind in ["trailer", "plain", "servecontent-ish"].iter() {
        let mux = http::ServeMux::new();
        let k = string::from(*kind);
        mux.HandleFunc(string::from("/"), move |w, _r| { handler(&k, w); });
        let mut srv = http::Server::default();
        srv.Handler = Arc::new(mux) as Arc<dyn http::Handler>;
        let srv = Arc::new(srv);
        let (l, _) = net::Listen(string::from("tcp"), string::from("127.0.0.1:0"));
        let addr = l.Addr().String();
        let s2 = srv.clone();
        go!(stack(512 * 1024), move || { let _ = s2.Serve(l); });
        time::Sleep(time::Millisecond * 50);
        let (mut c, _) = net::Dial(string::from("tcp"), addr);
        let _ = c.SetReadDeadline(time::Now().Add(time::Second * 2));
        let _ = c.Write(goish::convert::bytes(string::from(
            "GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")));
        let mut raw: Vec<u8> = Vec::new();
        let mut buf: slice<byte> = slice::__from_vec(alloc::vec![0u8; 512]);
        loop {
            let (n, e) = c.Read(&mut buf);
            if n > 0 { raw.extend_from_slice(&buf.as_ref()[..n as usize]); }
            if n <= 0 || !e.IsNil() { break; }
        }
        let _ = c.Close(); let _ = srv.Close();
        let line = fmt::Sprintf!("%-18s %s", string::from(*kind), header_keys(&raw));
        chk(&mut ln, &line);
    }

    // The same three shapes over TLS. server_tls.rs builds response
    // heads in its OWN two call sites, not through the plain server's,
    // so an ordering fix applied to one and not the other is invisible
    // to every row above — which is exactly what happened while this
    // smoke was being written.
    let (cert, cerr) = tls::X509KeyPair(CERT_PEM, KEY_PEM);
    if !cerr.IsNil() {
        fmt::Printf!("[!!] X509KeyPair: %v\n", cerr);
        goish::os::Exit(1);
    }
    for kind in ["trailer", "plain", "servecontent-ish"].iter() {
        let mux = http::ServeMux::new();
        let k = string::from(*kind);
        mux.HandleFunc(string::from("/"), move |w, _r| { handler(&k, w); });
        let srv = Arc::new(http::Server {
            Handler: Arc::new(mux) as Arc<dyn http::Handler>,
            TLSConfig: Some(tls::Config {
                Certificates: goish::slice::<tls::Certificate>::__from_vec(
                    alloc::vec![cert.clone()]),
                ..Default::default()
            }),
            ..Default::default()
        });
        let (l, _) = net::Listen(string::from("tcp"), string::from("127.0.0.1:0"));
        let addr = l.Addr().String();
        let s2 = srv.clone();
        go!(stack(1024 * 1024), move || {
            let _ = s2.ServeTLS(l, string::from(""), string::from(""));
        });
        time::Sleep(time::Millisecond * 100);
        let cfg = tls::Config {
            InsecureSkipVerify: true,
            ServerName: string::from("localhost"),
            ..Default::default()
        };
        let (mut c, de) = tls::Dial(string::from("tcp"), addr, &cfg);
        if !de.IsNil() {
            fmt::Printf!("[!!] tls dial: %v\n", de);
            ln += 1;
            let _ = srv.Close();
            continue;
        }
        let _ = c.Write(goish::convert::bytes(string::from(
            "GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")));
        let mut raw: Vec<u8> = Vec::new();
        let mut buf: slice<byte> = slice::__from_vec(alloc::vec![0u8; 512]);
        loop {
            let (n, e) = c.Read(&mut buf);
            if n > 0 { raw.extend_from_slice(&buf.as_ref()[..n as usize]); }
            if n <= 0 || !e.IsNil() { break; }
        }
        let _ = c.Close(); let _ = srv.Close();
        let line = fmt::Sprintf!("tls-%-14s %s", string::from(*kind), header_keys(&raw));
        chk(&mut ln, &line);
    }
    if ln != GO.len() {
        fmt::Printf!("[!!] line count mismatch with the Go reference\n");
    }
    goish::os::Exit(0);
}
