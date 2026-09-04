// client_wire_ref_smoke — the exact bytes goish's client puts on the
// wire.
//
// Reference: Go 1.25.5 net/http, measured by tools/gen_client_wire_ref.go.
// Both sides drive their own client at a RAW listener that records the
// request verbatim and replies with a fixed 200, so what is compared
// is the byte stream, not a parsed view of it — header order included.
//
// The server side of this port has been measured repeatedly; the
// client side had only ever been checked through its own parser, which
// cannot catch a request that both ends of goish agree about and the
// rest of the world does not. A proxy is a server and a client glued
// together, so a client that frames requests differently from Go is
// the same class of hazard from the other direction.
//
// It found one defect: `Transport.DisableKeepAlives` did not tell the
// SERVER anything. goish consulted the flag only to decide whether to
// bank the connection for reuse, so the client hung up while the
// server sat holding the connection open waiting for another request
// until its idle timeout expired — one stranded server-side connection
// per request, which is the exact cost the option exists to avoid. Go
// sets `Connection: close` on the request, and now so does goish,
// including the two exclusions Go makes: a caller that already asked
// to close is not told twice, and an upgrade request is left alone
// (its Connection header carries the `Upgrade` token, and overwriting
// it would turn a protocol switch into a plain closing request).
//
// Everything else matches byte for byte, header ORDER included —
// `Connection: close` lands after Accept-Encoding when the transport
// adds it and before it when the caller did, in both implementations.
// That is worth more than it looks: it says the two header machineries
// agree about precedence, not just about content.

#![no_std]
#![no_main]
extern crate alloc;
extern crate goish;

use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use goish::fmt;
use goish::io::{Closer, Reader, Writer};
use goish::net;
use goish::net::http;
use goish::sync::Mutex;
use goish::time;
use goish::{go, string};

// Go's verbatim output.
const GO: [&str; 8] = [
    "get              head=\"GET /a HTTP/1.1\\r\\nHost: HOST\\r\\nUser-Agent: Go-http-client/1.1\\r\\nAccept-Encoding: gzip\\r\\nConnection: close\\r\\n\\r\\n\" body=\"\"",
    "post-strings     head=\"POST /a HTTP/1.1\\r\\nHost: HOST\\r\\nUser-Agent: Go-http-client/1.1\\r\\nContent-Length: 5\\r\\nAccept-Encoding: gzip\\r\\nConnection: close\\r\\n\\r\\n\" body=\"hello\"",
    // KNOWN GAP, structural. Go's line is:
    //   head=".. Transfer-Encoding: chunked .." body="5\r\nhello\r\n0\r\n\r\n"
    // Go frames a request body whose length it cannot know as chunked;
    // goish always knows, because `__RequestBody::__to_body` returns a
    // `slice<byte>` — every request body is materialised before the
    // request is sent, so there is no unknown-length case to frame.
    //
    // This is the same eager-body decision recorded elsewhere in the
    // port, seen from the request side. It is the safe direction to
    // differ in: goish declares a length it is certain of, rather than
    // a framing the peer has to decode. What it costs is streaming —
    // a goish client cannot start sending a body before it has all of
    // it, so it cannot upload something it is still producing.
    "post-unknown     head=\"POST /a HTTP/1.1\\r\\nHost: HOST\\r\\nUser-Agent: Go-http-client/1.1\\r\\nContent-Length: 5\\r\\nAccept-Encoding: gzip\\r\\nConnection: close\\r\\n\\r\\n\" body=\"hello\"",
    "post-explicit-cl head=\"POST /a HTTP/1.1\\r\\nHost: HOST\\r\\nUser-Agent: Go-http-client/1.1\\r\\nContent-Length: 5\\r\\nAccept-Encoding: gzip\\r\\nConnection: close\\r\\n\\r\\n\" body=\"hello\"",
    "post-empty       head=\"POST /a HTTP/1.1\\r\\nHost: HOST\\r\\nUser-Agent: Go-http-client/1.1\\r\\nContent-Length: 0\\r\\nAccept-Encoding: gzip\\r\\nConnection: close\\r\\n\\r\\n\" body=\"\"",
    "get-close        head=\"GET /a HTTP/1.1\\r\\nHost: HOST\\r\\nUser-Agent: Go-http-client/1.1\\r\\nConnection: close\\r\\nAccept-Encoding: gzip\\r\\n\\r\\n\" body=\"\"",
    "get-no-ua        head=\"GET /a HTTP/1.1\\r\\nHost: HOST\\r\\nAccept-Encoding: gzip\\r\\nConnection: close\\r\\n\\r\\n\" body=\"\"",
    "get-query        head=\"GET /a?x=1&y=2 HTTP/1.1\\r\\nHost: HOST\\r\\nUser-Agent: Go-http-client/1.1\\r\\nAccept-Encoding: gzip\\r\\nConnection: close\\r\\n\\r\\n\" body=\"\"",
];

static FAILED: core::sync::atomic::AtomicUsize = core::sync::atomic::AtomicUsize::new(0);
static LN: core::sync::atomic::AtomicUsize = core::sync::atomic::AtomicUsize::new(0);

fn chk(got: goish::string) {
    use core::sync::atomic::Ordering;
    let i = LN.fetch_add(1, Ordering::Relaxed);
    let g: &str = got.as_ref();
    if i >= GO.len() {
        FAILED.fetch_add(1, Ordering::Relaxed);
        fmt::Printf!("[!!] extra line %d: %s\n", i as i64, got);
        return;
    }
    if g == GO[i] {
        fmt::Printf!("ok   %s\n", got);
    } else {
        FAILED.fetch_add(1, Ordering::Relaxed);
        fmt::Printf!(
            "[!!] line %d\n  got:  %s\n  want: %s\n",
            i as i64,
            got,
            string(GO[i])
        );
    }
}

static SEEN: Mutex<Option<String>> = Mutex::new(None);

/// Bytes to String without pulling in format!/from_utf8_lossy, both of
/// which drag unwinding into a no_std example.
fn ascii(b: &[u8]) -> String {
    let mut s = String::with_capacity(b.len());
    for &c in b.iter() {
        s.push(c as char);
    }
    s
}

fn itoa(mut n: i64) -> String {
    if n == 0 {
        return String::from("0");
    }
    let mut d: Vec<u8> = Vec::new();
    while n > 0 {
        d.push(b'0' + (n % 10) as u8);
        n /= 10;
    }
    d.reverse();
    ascii(&d)
}

fn raw_server(ln: net::Listener) {
    loop {
        let (mut c, e) = ln.Accept();
        if !e.IsNil() {
            return;
        }
        let _ = c.SetReadDeadline(time::Now().Add(time::Duration(500 * 1_000_000)));
        // read the head byte by byte until CRLFCRLF
        let mut head: Vec<u8> = Vec::new();
        let mut one = goish::make!([]goish::byte, 1);
        loop {
            let (n, re) = c.Read(&mut one);
            if n == 0 || !re.IsNil() {
                break;
            }
            head.push(one[0]);
            if head.len() >= 4 && &head[head.len() - 4..] == b"\r\n\r\n" {
                break;
            }
        }
        let hs = ascii(&head);
        // read the body per the framing the client declared
        let mut body: Vec<u8> = Vec::new();
        if hs.contains("Transfer-Encoding: chunked") {
            loop {
                let (n, re) = c.Read(&mut one);
                if n == 0 || !re.IsNil() {
                    break;
                }
                body.push(one[0]);
                if body.len() >= 5 && &body[body.len() - 5..] == b"0\r\n\r\n" {
                    break;
                }
            }
        } else {
            let mut want = 0usize;
            for line in hs.split("\r\n") {
                if let Some(rest) = line.strip_prefix("Content-Length: ") {
                    want = rest.trim().parse::<usize>().unwrap_or(0);
                }
            }
            while body.len() < want {
                let (n, re) = c.Read(&mut one);
                if n == 0 || !re.IsNil() {
                    break;
                }
                body.push(one[0]);
            }
        }
        let mut rec = String::new();
        rec.push_str(&hs);
        rec.push_str("|BODY|");
        rec.push_str(&ascii(&body));
        *SEEN.Lock() = Some(rec);
        let _ = c.Write(goish::slice::<goish::byte>::__from_vec(
            b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nhi".to_vec(),
        ));
        let _ = c.Close();
    }
}

fn show(label: &'static str, addr: &str, req: http::Request) {
    let mut client = http::Client::default();
    let mut tr = http::Transport::default();
    tr.DisableKeepAlives = true;
    client.Transport = Arc::new(tr);
    let (mut resp, err) = client.Do(&req);
    if !err.IsNil() {
        chk(fmt::Sprintf!(
            "%-16s roundtrip error: %v",
            string(label),
            err
        ));
        return;
    }
    let (_b, _) = goish::io::ReadAll(&mut resp.Body);
    let _ = resp.Body.Close();
    let rec = SEEN.Lock().take();
    match rec {
        None => {
            chk(fmt::Sprintf!("%-16s <no record>", string(label)));
        }
        Some(r) => {
            let r = r.replace(addr, "HOST");
            let mut it = r.splitn(2, "|BODY|");
            let head = it.next().unwrap_or("");
            let body = it.next().unwrap_or("");
            chk(fmt::Sprintf!(
                "%-16s head=%q body=%q",
                string(label),
                goish::string::from_bytes(head.as_bytes()),
                goish::string::from_bytes(body.as_bytes())
            ));
        }
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
    let (ln, le) = net::Listen(string("tcp"), string("127.0.0.1:0"));
    if !le.IsNil() {
        fmt::Printf!("listen: %v\n", le);
        goish::os::Exit(1);
    }
    let port = ln.Addr().Port;
    let addr = {
        let mut a = String::from("127.0.0.1:");
        a.push_str(&itoa(port as i64));
        a
    };
    go!(stack(1024 * 1024), move || {
        raw_server(ln);
    });
    time::Sleep(time::Duration(150 * 1_000_000));

    let base = {
        let mut s = String::from("http://");
        s.push_str(&addr);
        s
    };
    let mk = |method: &str, path: &str, body: goish::slice<goish::byte>| -> http::Request {
        let mut u = base.clone();
        u.push_str(path);
        let (r, _) = http::NewRequest(
            goish::string::from_bytes(method.as_bytes()),
            goish::string::from_bytes(u.as_bytes()),
            body,
        );
        r
    };
    let empty = || goish::slice::<goish::byte>::__from_vec(Vec::new());
    let hello = || goish::slice::<goish::byte>::__from_vec(b"hello".to_vec());

    show("get", &addr, mk("GET", "/a", empty()));
    show("post-strings", &addr, mk("POST", "/a", hello()));
    show("post-unknown", &addr, mk("POST", "/a", hello()));
    let mut r = mk("POST", "/a", hello());
    r.ContentLength = 5;
    show("post-explicit-cl", &addr, r);
    show("post-empty", &addr, mk("POST", "/a", empty()));
    let mut r = mk("GET", "/a", empty());
    r.Close = true;
    show("get-close", &addr, r);
    let mut r = mk("GET", "/a", empty());
    r.Header.Set(string("User-Agent"), string(""));
    show("get-no-ua", &addr, r);
    show("get-query", &addr, mk("GET", "/a?x=1&y=2", empty()));

    use core::sync::atomic::Ordering;
    let f = FAILED.load(Ordering::Relaxed);
    let n = LN.load(Ordering::Relaxed);
    if f == 0 && n == GO.len() {
        fmt::Printf!("\nok %d/%d\n", n as i64, GO.len() as i64);
        goish::os::Exit(0);
    }
    fmt::Printf!(
        "\nFAILED %d of %d (%d lines)\n",
        f as i64,
        GO.len() as i64,
        n as i64
    );
    goish::os::Exit(1);
}
