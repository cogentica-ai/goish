// server_options_ref_smoke — two Server knobs, and who answers.
//
// Reference: Go 1.25.5 net/http, measured by
// tools/gen_server_options_ref.go. Every GO[] line is Go's verbatim
// output.
//
// Both fields work in goish; this is coverage, not a fix. It exists
// because a config knob is the easiest thing in a port to accept and
// then ignore — the caller sets it, nothing complains, and nothing
// happens. That failure has already happened once here
// (Transport.Proxy, 3bb7775), so the Server's knobs are worth pinning
// by BEHAVIOUR rather than by reading the code that consumes them.
//
// DisableGeneralOptionsHandler is measured through WHO ANSWERS, not
// through the status code, because both answers are 200 and only the
// body separates them:
//
//   default   — Go's own general handler replies, body EMPTY
//   disabled  — the request reaches the handler, body "handler saw
//               OPTIONS *"
//
// A port that ignored the flag would pass a status-code test in both
// directions. `OPTIONS /p` is the control: a path is never the general
// handler's business, so it reaches the user handler either way.
//
// MaxHeaderBytes is measured either side of the SLOP. Go bounds the
// header block at MaxHeaderBytes + 4096, not at MaxHeaderBytes, so a
// 6 KB header passes under a cap of 8000 and is refused under 1000 —
// the same request, the same body, two caps. A port that applied the
// cap without the slop would refuse the first as well, and one that
// forgot the cap would accept the second.
//
// The 431 is pinned with its body, because Go answers this one with a
// status line AND a body rather than closing.

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
use goish::{go, string, time};

// Go's verbatim output.
const GO: [&str; 5] = [
    "options-star-default         HTTP/1.1 200 OK          body=\"\"",
    "options-star-disabled        HTTP/1.1 200 OK          body=\"handler saw OPTIONS *\"",
    "options-path                 HTTP/1.1 200 OK          body=\"handler saw OPTIONS /p\"",
    "maxheader-under              HTTP/1.1 200 OK          body=\"handler saw GET /p\"",
    "maxheader-over               HTTP/1.1 431 Request Header Fields Too Large body=\"431 Request Header Fields Too Large\"",
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
            goish::string(GO[i])
        );
    }
}

fn raw(srv: Arc<http::Server>, req: &str) -> goish::string {
    let (ln, le) = net::Listen(string("tcp"), string("127.0.0.1:0"));
    if !le.IsNil() {
        return string("listen error");
    }
    let port = ln.Addr().Port;
    {
        let s2 = srv.clone();
        go!(stack(1024 * 1024), move || {
            let _ = s2.Serve(ln);
        });
    }
    time::Sleep(time::Duration(80 * 1_000_000));

    let addr = fmt::Sprintf!("127.0.0.1:%d", port as i64);
    let (mut c, e) = net::Dial(string("tcp"), addr);
    if !e.IsNil() {
        return string("dial error");
    }
    let _ = c.SetReadDeadline(time::Now().Add(time::Duration(700 * 1_000_000)));
    let _ = c.Write(goish::slice::<goish::byte>::__from_vec(
        req.as_bytes().to_vec(),
    ));
    let mut out: Vec<u8> = Vec::new();
    let mut buf = goish::make!([]goish::byte, 4096);
    while out.len() < 4096 {
        let (n, re) = c.Read(&mut buf);
        if n > 0 {
            for i in 0..n {
                out.push(buf[i]);
            }
        }
        if !re.IsNil() || n == 0 {
            break;
        }
    }
    let _ = c.Close();
    let s = goish::string::from_bytes(&out);
    let rs: &str = s.as_ref();
    let status = match rs.find("\r\n") {
        Some(i) if i > 0 => &rs[..i],
        _ => rs,
    };
    let body = match rs.find("\r\n\r\n") {
        Some(i) => &rs[i + 4..],
        None => "",
    };
    fmt::Sprintf!(
        "%-24s body=%q",
        goish::string::from_bytes(status.as_bytes()),
        goish::string::from_bytes(body.as_bytes())
    )
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

fn mkh() -> Arc<dyn http::Handler> {
    Arc::new(http::HandlerFunc(
        move |w: &(dyn http::ResponseWriter + Send + Sync + 'static), r: &http::Request| {
            let _ = w.Write(goish::convert::bytes(fmt::Sprintf!(
                "handler saw %s %s",
                r.Method,
                r.URL.Path
            )));
        },
    ))
}

fn run() {
    let star = "OPTIONS * HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n";
    chk(fmt::Sprintf!(
        "%-28s %s",
        string("options-star-default"),
        raw(
            Arc::new(http::Server {
                Handler: mkh(),
                ..Default::default()
            }),
            star
        )
    ));
    chk(fmt::Sprintf!(
        "%-28s %s",
        string("options-star-disabled"),
        raw(
            Arc::new(http::Server {
                Handler: mkh(),
                DisableGeneralOptionsHandler: true,
                ..Default::default()
            }),
            star
        )
    ));
    chk(fmt::Sprintf!(
        "%-28s %s",
        string("options-path"),
        raw(
            Arc::new(http::Server {
                Handler: mkh(),
                ..Default::default()
            }),
            "OPTIONS /p HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n"
        )
    ));

    let mut big = String::from("GET /p HTTP/1.1\r\nHost: x\r\nX-Pad: ");
    for _ in 0..6000 {
        big.push('a');
    }
    big.push_str("\r\nConnection: close\r\n\r\n");
    chk(fmt::Sprintf!(
        "%-28s %s",
        string("maxheader-under"),
        raw(
            Arc::new(http::Server {
                Handler: mkh(),
                MaxHeaderBytes: 8000,
                ..Default::default()
            }),
            &big
        )
    ));
    chk(fmt::Sprintf!(
        "%-28s %s",
        string("maxheader-over"),
        raw(
            Arc::new(http::Server {
                Handler: mkh(),
                MaxHeaderBytes: 1000,
                ..Default::default()
            }),
            &big
        )
    ));

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
