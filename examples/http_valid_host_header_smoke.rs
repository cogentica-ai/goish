// net/http: the Host header was written to the wire unvalidated.
//
// Go's Request.write runs the Host through httpguts.ValidHostHeader
// before writing the `Host:` line, and its comment says exactly why:
// "Validate that the Host header is a valid header in general, but
// don't validate the host itself. This is sufficient to avoid header or
// request smuggling via the Host field."
//
// goish wrote req.Host verbatim. MEASURED, not theorised — a probe
// setting Host to "evil.com\r\nX-Injected: yes" produced
//
//     GET /p HTTP/1.1
//     Host: evil.com
//     X-Injected: yes
//     User-Agent: Go-http-client/1.1
//
// Request.Host is public API, so any caller taking a hostname from
// untrusted input — a proxy, a multi-tenant router, a redirect target —
// injected arbitrary headers into its own request.
//
// Two tables. The first is EVERY byte 0..255 on its own; the second is
// the shapes a Host actually takes, including the injection attempts
// and the ones that must still be ACCEPTED. Both came from Go 1.25.5's
// own httpguts.ValidHostHeader, run inside a writable GOROOT copy
// (scripts/goref.sh net/http) because the package is vendored and
// cannot be imported from outside. Committed as
// examples/testdata/valid_host_header_ref.txt.
//
// The accepting rows carry the weight here. A validator that rejected
// everything would stop the injection and break every request; "[::1]",
// "[fe80::1%25eth0]:80", "under_score.example" and
// "a!b$c&d'e(f)g*h+i,j;k=l" are all legal Hosts that must survive.
#![no_std]
#![no_main]
#![allow(non_snake_case)]
extern crate alloc;
extern crate goish;

use goish::fmt;
use goish::gostring::string;
use goish::net::http;
use goish::types::int;

const REF: &str = include_str!("testdata/valid_host_header_ref.txt");

static mut PASS: int = 0;
static mut FAIL: int = 0;

fn chk(what: string, got: bool, want: bool) {
    unsafe {
        if got == want {
            PASS += 1;
        } else {
            FAIL += 1;
            fmt::Printf!("FAIL %s: got %v want %v\n", what, got, want);
        }
    }
}

// A named case, passed as raw bytes so the escaping is not retyped.
fn hostcase(name: &'static str, raw: &[u8], want: bool) {
    let h = string::from_bytes(raw);
    chk(
        string::from_static("case ") + string::from_bytes(name.as_bytes()),
        http::http::ValidHostHeader(&h),
        want,
    );
}

#[goish::main]
fn main() {
    // ── every single byte, from Go's table ────────────────────────
    let mut rows: int = 0;
    for line in REF.split('\n') {
        let line = line.trim();
        if !line.starts_with("byte ") {
            continue;
        }
        let mut it = line[5..].split(' ');
        let b: int = it.next().unwrap_or("").parse::<i64>().unwrap_or(-1);
        let want = it.next().unwrap_or("") == "true";
        if b < 0 || b > 255 {
            continue;
        }
        rows += 1;
        let h = string::from_bytes(&[b as u8]);
        chk(
            fmt::Sprintf!("byte %v", b),
            http::http::ValidHostHeader(&h),
            want,
        );
    }
    if rows != 256 {
        fmt::Printf!("FAIL byte table ran %v rows, expected 256\n", rows);
        unsafe {
            FAIL += 1;
        }
    }

    // ── the real shapes, and the injections ───────────────────────
    hostcase("", &[], true);
    hostcase("example.com", &[0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x2e, 0x63, 0x6f, 0x6d], true);
    hostcase("example.com:8080", &[0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x2e, 0x63, 0x6f, 0x6d, 0x3a, 0x38, 0x30, 0x38, 0x30], true);
    hostcase("EXAMPLE.com", &[0x45, 0x58, 0x41, 0x4d, 0x50, 0x4c, 0x45, 0x2e, 0x63, 0x6f, 0x6d], true);
    hostcase("127.0.0.1", &[0x31, 0x32, 0x37, 0x2e, 0x30, 0x2e, 0x30, 0x2e, 0x31], true);
    hostcase("127.0.0.1:443", &[0x31, 0x32, 0x37, 0x2e, 0x30, 0x2e, 0x30, 0x2e, 0x31, 0x3a, 0x34, 0x34, 0x33], true);
    hostcase("[::1]", &[0x5b, 0x3a, 0x3a, 0x31, 0x5d], true);
    hostcase("[::1]:443", &[0x5b, 0x3a, 0x3a, 0x31, 0x5d, 0x3a, 0x34, 0x34, 0x33], true);
    hostcase("[fe80::1%25eth0]:80", &[0x5b, 0x66, 0x65, 0x38, 0x30, 0x3a, 0x3a, 0x31, 0x25, 0x32, 0x35, 0x65, 0x74, 0x68, 0x30, 0x5d, 0x3a, 0x38, 0x30], true);
    hostcase("xn--bcher-kva.example", &[0x78, 0x6e, 0x2d, 0x2d, 0x62, 0x63, 0x68, 0x65, 0x72, 0x2d, 0x6b, 0x76, 0x61, 0x2e, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65], true);
    hostcase("under_score.example", &[0x75, 0x6e, 0x64, 0x65, 0x72, 0x5f, 0x73, 0x63, 0x6f, 0x72, 0x65, 0x2e, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65], true);
    hostcase("a~b.example", &[0x61, 0x7e, 0x62, 0x2e, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65], true);
    hostcase("a!b$c&d'e(f)g*h+i,j;k=l", &[0x61, 0x21, 0x62, 0x24, 0x63, 0x26, 0x64, 0x27, 0x65, 0x28, 0x66, 0x29, 0x67, 0x2a, 0x68, 0x2b, 0x69, 0x2c, 0x6a, 0x3b, 0x6b, 0x3d, 0x6c], true);
    hostcase("evil.com\r\nX-Injected: yes", &[0x65, 0x76, 0x69, 0x6c, 0x2e, 0x63, 0x6f, 0x6d, 0x0d, 0x0a, 0x58, 0x2d, 0x49, 0x6e, 0x6a, 0x65, 0x63, 0x74, 0x65, 0x64, 0x3a, 0x20, 0x79, 0x65, 0x73], false);
    hostcase("evil.com\nX-Injected: yes", &[0x65, 0x76, 0x69, 0x6c, 0x2e, 0x63, 0x6f, 0x6d, 0x0a, 0x58, 0x2d, 0x49, 0x6e, 0x6a, 0x65, 0x63, 0x74, 0x65, 0x64, 0x3a, 0x20, 0x79, 0x65, 0x73], false);
    hostcase("evil.com\rX-Injected: yes", &[0x65, 0x76, 0x69, 0x6c, 0x2e, 0x63, 0x6f, 0x6d, 0x0d, 0x58, 0x2d, 0x49, 0x6e, 0x6a, 0x65, 0x63, 0x74, 0x65, 0x64, 0x3a, 0x20, 0x79, 0x65, 0x73], false);
    hostcase("evil.com X-Injected", &[0x65, 0x76, 0x69, 0x6c, 0x2e, 0x63, 0x6f, 0x6d, 0x20, 0x58, 0x2d, 0x49, 0x6e, 0x6a, 0x65, 0x63, 0x74, 0x65, 0x64], false);
    hostcase("evil.com\tfoo", &[0x65, 0x76, 0x69, 0x6c, 0x2e, 0x63, 0x6f, 0x6d, 0x09, 0x66, 0x6f, 0x6f], false);
    hostcase("evil.com/path", &[0x65, 0x76, 0x69, 0x6c, 0x2e, 0x63, 0x6f, 0x6d, 0x2f, 0x70, 0x61, 0x74, 0x68], false);
    hostcase("evil.com?q=1", &[0x65, 0x76, 0x69, 0x6c, 0x2e, 0x63, 0x6f, 0x6d, 0x3f, 0x71, 0x3d, 0x31], false);
    hostcase("evil.com#frag", &[0x65, 0x76, 0x69, 0x6c, 0x2e, 0x63, 0x6f, 0x6d, 0x23, 0x66, 0x72, 0x61, 0x67], false);
    hostcase("evil.com<U+0000>", &[0x65, 0x76, 0x69, 0x6c, 0x2e, 0x63, 0x6f, 0x6d, 0x00], false);
    hostcase("host with space", &[0x68, 0x6f, 0x73, 0x74, 0x20, 0x77, 0x69, 0x74, 0x68, 0x20, 0x73, 0x70, 0x61, 0x63, 0x65], false);
    hostcase("h<U+00E9>llo.example", &[0x68, 0xc3, 0xa9, 0x6c, 0x6c, 0x6f, 0x2e, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65], false);

    // ── the WIRING, not just the predicate ────────────────────────
    //
    // 280 green rows above prove ValidHostHeader is right. They say
    // nothing about whether the request writer CALLS it — which is the
    // half that was actually broken. These four drive
    // serialize_request_head and read the bytes it produced.
    {
        let (req, _e) = http::NewRequest(
            string::from_static("GET"),
            string::from_static("http://example.com/p"),
            string::from_static(""),
        );
        let mut bad = req.clone();
        bad.Host = string::from_bytes(b"evil.com\r\nX-Injected: yes");

        // Direct: Go zeroes the Host rather than truncating it, because
        // "sending an altered header field opens a smuggling vector".
        let (head, _tw, e1) = http::client::serialize_request_head(&bad, &bad.Host.clone(), false);
        let hb: &[u8] = &head;
        let wire = string::from_bytes(hb);
        chk(
            string::from_static("direct: no error"),
            e1.IsNil(),
            true,
        );
        chk(
            string::from_static("direct: the injected header is NOT on the wire"),
            goish::strings::Contains(wire.clone(), string::from_static("X-Injected")),
            false,
        );
        chk(
            string::from_static("direct: the Host line is emptied, not truncated"),
            goish::strings::Contains(wire, string::from_static("Host: \r\n")),
            true,
        );

        // Through a proxy: Go returns an error instead, since an empty
        // Host is useless to the proxy.
        let (_h2, _tw2, e2) =
            http::client::serialize_request_head(&bad, &bad.Host.clone(), true);
        chk(
            string::from_static("proxy: refused with Go's message"),
            e2.Error() == string::from_static("http: invalid Host header"),
            true,
        );
    }

    unsafe {
        let (pass, fail) = (PASS, FAIL);
        if pass + fail != 284 {
            fmt::Printf!("FAIL ran %v checks, expected 284\n", pass + fail);
            FAIL += 1;
        }
        let fail = FAIL;
        fmt::Printf!(
            "http_valid_host_header_smoke: %v checks, %v failed\n",
            pass + fail,
            fail
        );
        if fail > 0 {
            goish::syscall::Exit(1);
        }
    }
}
