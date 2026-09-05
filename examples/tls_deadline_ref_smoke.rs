//! Pinned against Go 1.25.5: a TLS read that times out must NOT kill
//! the connection.
//!
//! goish latched it. `readRecordOrCCS` called `c.in.setErrorLocked(err)`
//! unconditionally, and Go guards that call:
//!
//!     if e, ok := err.(net.Error); !ok || !e.Temporary() {
//!         c.in.setErrorLocked(err)
//!     }
//!
//! Storing the error LATCHES it — every later read on the connection
//! returns it. A read DEADLINE is a temporary net.Error, so Go does
//! not latch it, which is what lets a caller poll with a deadline,
//! clear it and carry on: the standard "wait a bit, then wait
//! properly" idiom every keep-alive loop is built on. goish dropped
//! the condition, so the FIRST timeout killed the connection for good.
//!
//! The second line is what catches it. A smoke that only checked the
//! timeout error would have passed throughout: line one was already
//! correct.
//!
//! Two more things this pins, both fixed in the same commit and both
//! reached only once the guard was right:
//!
//!   * `permanentError.Timeout()` forwards to the wrapped net.Error
//!     instead of returning false. It answered false on a note saying
//!     goish had no net.Error interface; it has one.
//!   * `setErrorLocked` wraps a net.Error in permanentError, as Go
//!     does — which is now reachable only for a NON-temporary one,
//!     exactly Go's design: a permanent fault is marked permanent, a
//!     timeout is not a fault.
//!
//! The server handshakes and then stays silent for three seconds, so
//! the first read must time out and the second must block until the
//! close. Addresses are ephemeral and rewritten to ADDR.
//!
//! Reference generated with:
//!   CGO_ENABLED=0 scripts/goref.sh crypto/tls <tlstimeout_ref_test.go>
#![no_std]
#![no_main]
#![allow(non_snake_case)]
extern crate alloc;
extern crate goish;
use alloc::sync::Arc;
use goish::crypto::tls;
use goish::io::Reader;
use goish::net::net as gnet;
use goish::types::byte;
use goish::{errors, fmt, go, make, net, string, time};

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
    goish::go!(stack(2 * 1024 * 1024), move || {
        run();
    });
    loop {
        goish::runtime::sched::Gosched();
    }
}

fn run() {
    let (cert, cerr) = tls::X509KeyPair(CERT_PEM, KEY_PEM);
    if !cerr.IsNil() {
        fmt::Printf!("setup cert: %v\n", cerr);
        goish::os::Exit(1);
    }
    let scfg = tls::Config {
        Certificates: goish::slice::<tls::Certificate>::__from_vec(alloc::vec![cert]),
        ..Default::default()
    };
    let (ln, lerr) = tls::Listen(string("tcp"), string("127.0.0.1:0"), &scfg);
    if !lerr.IsNil() {
        fmt::Printf!("setup listen: %v\n", lerr);
        goish::os::Exit(1);
    }
    let addr = ln.Addr().String();

    // Server: handshake, then say nothing at all.
    let lnc = Arc::new(ln);
    let lns = lnc.clone();
    go!(stack(1024 * 1024), move || {
        let (mut c, e) = lns.Accept();
        if e.IsNil() {
            let _ = c.Handshake();
            time::Sleep(time::Duration(3_000_000_000));
            let _ = goish::io::Closer::Close(&mut c);
        }
    });
    time::Sleep(time::Duration(100_000_000));

    let ccfg = tls::Config {
        InsecureSkipVerify: true,
        ServerName: string("localhost"),
        ..Default::default()
    };
    let (mut conn, derr) = tls::Dial(string("tcp"), addr, &ccfg);
    if !derr.IsNil() {
        fmt::Printf!("setup dial: %v\n", derr);
        goish::os::Exit(1);
    }

    // A read that must time out: the peer handshook and then went quiet.
    let _ = conn.SetReadDeadline(time::Now().Add(time::Duration(300_000_000)));
    let mut buf = make!([]byte, 16);
    let (n, rerr) = conn.Read(&mut buf);
    show("tls-read-deadline", n, rerr);

    // A SECOND read, with no deadline: is the connection dead?
    let _ = conn.SetReadDeadline(time::Time::default());
    let (n2, rerr2) = conn.Read(&mut buf);
    show("tls-read-again ", n2, rerr2);

    let failed = unsafe { FAILED };
    let n = GO.len() as i64;
    if failed == 0 {
        fmt::Printf!("tls read deadline: %d/%d match Go\n", n, n);
        goish::os::Exit(0);
    }
    fmt::Printf!("FAIL: %d/%d diverge\n", failed, n);
    goish::os::Exit(1);
}

/// Go's output, verbatim.
const GO: [&str; 2] = [
    "tls-read-deadline n=0 err_nil=false net.Error=true Timeout=true Temporary=true msg=\"read tcp ADDR->ADDR: i/o timeout\"",
    "tls-read-again  n=0 err_nil=false net.Error=false Timeout=false Temporary=false msg=\"EOF\"",
];

static mut FAILED: i64 = 0;
static mut LINE: usize = 0;

/// Compare one rendered line against the Go reference, in order.
fn chk(got: string) {
    let i = unsafe { LINE };
    unsafe { LINE += 1 };
    let want = string::from_static(GO[i]);
    if got == want {
        return;
    }
    fmt::Printf!("DIFF go   : %s\n", want);
    fmt::Printf!("     goish: %s\n", got);
    unsafe { FAILED += 1 };
}

fn show(tag: &'static str, n: goish::int, err: goish::error) {
    let (ne, ok) = errors::AsIface::<goish::d!(gnet::Error)>(&err);
    let msg = if err.IsNil() {
        string("<nil>")
    } else {
        err.Error()
    };
    // 127.0.0.1:NNNNN -> ADDR, as the Go reference's regexp does.
    let raw: &str = msg.as_ref();
    let mut out = alloc::string::String::new();
    let b = raw.as_bytes();
    let mut i = 0usize;
    while i < b.len() {
        if raw[i..].starts_with("127.0.0.1:") {
            let mut k = i + 10;
            while k < b.len() && b[k].is_ascii_digit() {
                k += 1;
            }
            out.push_str("ADDR");
            i = k;
            continue;
        }
        out.push(b[i] as char);
        i += 1;
    }
    chk(fmt::Sprintf!(
        "%s n=%d err_nil=%v net.Error=%v Timeout=%v Temporary=%v msg=%q",
        string::from_static(tag),
        n as i64,
        err.IsNil(),
        ok,
        ok && ne.Timeout(),
        ok && ne.Temporary(),
        string::from_bytes(out.as_bytes())
    ));
}
