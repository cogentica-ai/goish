// server_hooks_ref_smoke — BaseContext, ConnContext and ErrorLog.
//
// Reference: Go 1.25.5 net/http, measured by
// tools/gen_server_hooks_ref.go. Every GO[] line is Go's verbatim
// output.
//
// Three Server hooks, measured by whether they actually take effect
// rather than by whether the field is read somewhere. That distinction
// is the whole point: Transport.Proxy had four readers and was still
// ignored (3bb7775), so counting references proves nothing.
//
// It found one. ErrorLog was accepted and then bypassed for exactly
// the messages a handler provokes — a superfluous WriteHeader, a
// WriteHeader after Hijack, a Content-Length beside a
// Transfer-Encoding. Those three sites called the package logger
// directly, because goish's `response` has no server pointer to reach
// `c.server.logf` through; the serve loop now hands it the logger.
//
// The consequence was quiet and awkward: an application that set
// ErrorLog to capture server complaints into its own pipeline got
// them on the process's default logger instead — outside its
// structured logging, its shipping, and any redaction it applies.
// Nothing failed; the messages simply came out somewhere else. Note
// that `Server.logf` already existed and was already correct — the
// panic-recovery path uses it. Only the response-side sites went
// around it, which is why "is ErrorLog read?" answered yes.
//
// BaseContext and ConnContext were already right and are pinned with
// it, because a value injected at the listener and one injected per
// connection have to BOTH reach the handler: the second derives from
// the first, so a port that dropped the base would still show a conn
// value, and the single line here distinguishes that.

#![no_std]
#![no_main]
extern crate alloc;
extern crate goish;

use alloc::sync::Arc;
use alloc::vec::Vec;
use goish::context;
use goish::fmt;
use goish::io::{Closer, Reader, Writer};
use goish::net;
use goish::net::http;
use goish::{go, string, time};

// Go's verbatim output.
const GO: [&str; 2] = [
    "handler-ctx      base=\"B\" conn=\"C\"",
    "errorlog         errorlog-used=true mentions-superfluous=true",
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

#[derive(Clone)]
struct SharedBuf(Arc<goish::sync::Mutex<Vec<goish::byte>>>);
impl goish::io::Writer for SharedBuf {
    fn Write(&mut self, p: goish::slice<goish::byte>) -> (goish::int, goish::errors::error) {
        let v = p.clone().__into_vec();
        let n = v.len() as i64;
        self.0.Lock().extend_from_slice(&v);
        (n, goish::errors::nil)
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
    let logbuf = SharedBuf(Arc::new(goish::sync::Mutex::new(Vec::new())));
    let logger = Arc::new(goish::log::New(
        alloc::boxed::Box::new(logbuf.clone()),
        string(""),
        0,
    ));

    let h: Arc<dyn http::Handler> = Arc::new(http::HandlerFunc(
        move |w: &(dyn http::ResponseWriter + Send + Sync + 'static), r: &http::Request| {
            let base = match r.Context().Value(&"base") {
                Some(v) => match v.downcast_ref::<goish::string>() {
                    Some(s) => s.clone(),
                    None => string(""),
                },
                None => string(""),
            };
            let conn = match r.Context().Value(&"conn") {
                Some(v) => match v.downcast_ref::<goish::string>() {
                    Some(s) => s.clone(),
                    None => string(""),
                },
                None => string(""),
            };
            let _ = w.Write(goish::convert::bytes(fmt::Sprintf!(
                "base=%q conn=%q",
                base,
                conn
            )));
            w.WriteHeader(200);
            w.WriteHeader(201);
        },
    ));

    let srv = Arc::new(http::Server {
        Handler: h,
        BaseContext: Some(Arc::new(|_ln: &net::Listener| {
            context::WithValue(context::Background(), "base", string("B"))
        })),
        ConnContext: Some(Arc::new(
            |ctx: Arc<dyn context::Context>, _c: &net::TCPConn| {
                context::WithValue(ctx, "conn", string("C"))
            },
        )),
        ErrorLog: Some(logger),
        ..Default::default()
    });

    let (ln, le) = net::Listen(string("tcp"), string("127.0.0.1:0"));
    if !le.IsNil() {
        fmt::Printf!("listen: %v\n", le);
        goish::os::Exit(1);
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
    let (mut c, _e) = net::Dial(string("tcp"), addr);
    let _ = c.SetReadDeadline(time::Now().Add(time::Duration(700 * 1_000_000)));
    let _ = c.Write(goish::slice::<goish::byte>::__from_vec(
        b"GET /p HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n".to_vec(),
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
    let raw = goish::string::from_bytes(&out);
    let rs: &str = raw.as_ref();
    let body = match rs.find("\r\n\r\n") {
        Some(i) => &rs[i + 4..],
        None => "",
    };
    chk(fmt::Sprintf!(
        "%-16s %s",
        string("handler-ctx"),
        goish::string::from_bytes(body.as_bytes())
    ));

    time::Sleep(time::Duration(80 * 1_000_000));
    let logged = goish::string::from_bytes(&logbuf.0.Lock().clone());
    let ls: &str = logged.as_ref();
    chk(fmt::Sprintf!(
        "%-16s errorlog-used=%v mentions-superfluous=%v",
        string("errorlog"),
        ls.len() > 0,
        ls.contains("superfluous")
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
