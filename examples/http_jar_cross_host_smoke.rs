// http_jar_cross_host_smoke — a cookie must not follow a redirect to a
// DIFFERENT host.
//
// Reference: Go 1.25.5 net/http, tools/gen_jarredirect_ref.go.
//
// http_client_jar_smoke covers the jar across a SAME-host redirect,
// including a cookie set by the 302 itself. This is the other half and
// the one with teeth: when a 302 sends the client somewhere else, the
// first host's cookies must stay behind.
//
// If they did not, any site able to redirect a logged-in client would
// receive its session cookie — the shape of a credential leak rather
// than a formatting bug. And the failure is invisible from the client
// side: the request succeeds either way.
//
// "localhost" and "127.0.0.1" are different hosts for cookie purposes
// even though both resolve here, which is what lets this run without
// DNS or a second machine. The jar stores a host-only cookie for
// "localhost"; 127.0.0.1 is a different host and gets nothing.
//
// The same-host row is the control. Without it a jar that simply never
// sent cookies would pass the row that matters.
#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

use alloc::sync::Arc;
use core::sync::atomic::{AtomicI32, Ordering};
use goish::gostring::string;
use goish::net;
use goish::net::http;
use goish::net::http::cookiejar;
use goish::sync::Mutex;
use goish::types::int;
use goish::{fmt, go, time};

const GO: [&str; 3] = [
    "after-set        jar-has-sid=true",
    "same-host-hop    cookie=\"A-echo:sid=secret\"",
    "cross-host-hop   cookie=\"\"",
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

static PORT_B: AtomicI32 = AtomicI32::new(0);

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
    let seen: Arc<Mutex<alloc::vec::Vec<string>>> = Arc::new(Mutex::new(alloc::vec::Vec::new()));

    // Host B, reached as 127.0.0.1.
    let muxb = http::ServeMux::new();
    let sb = seen.clone();
    muxb.HandleFunc(string::from("/"), move |w, r| {
        sb.Lock().push(r.Header.Get(string::from("Cookie")));
        let _ = goish::io::Writer::Write(&mut ResponseAdapter(w), goish::convert::bytes(string::from("B")));
    });
    let mut srvb = http::Server::default();
    srvb.Handler = Arc::new(muxb) as Arc<dyn http::Handler>;
    let srvb = Arc::new(srvb);
    let (lb, _) = net::Listen(string::from("tcp"), string::from("127.0.0.1:0"));
    PORT_B.store(lb.Addr().Port as i32, Ordering::Release);
    let b2 = srvb.clone();
    go!(stack(512 * 1024), move || {
        let _ = b2.Serve(lb);
    });

    // Host A, reached as localhost.
    let muxa = http::ServeMux::new();
    let sa = seen.clone();
    muxa.HandleFunc(string::from("/"), move |w, r| {
        let p = r.URL.Path.clone();
        if p == "/set" {
            let mut ck = http::Cookie::default();
            ck.Name = string::from("sid");
            ck.Value = string::from("secret");
            ck.Path = string::from("/");
            http::SetCookie(w, &ck);
            return;
        }
        if p == "/same" {
            http::Redirect(w, r, string::from("/echo"), 302);
            return;
        }
        if p == "/echo" {
            sa.Lock()
                .push(string::from("A-echo:") + r.Header.Get(string::from("Cookie")));
            return;
        }
        if p == "/cross" {
            let target = string::from("http://127.0.0.1:")
                + goish::strconv::Itoa(PORT_B.load(Ordering::Acquire) as i64)
                + string::from("/");
            http::Redirect(w, r, target, 302);
            return;
        }
    });
    let mut srva = http::Server::default();
    srva.Handler = Arc::new(muxa) as Arc<dyn http::Handler>;
    let srva = Arc::new(srva);
    let (la, _) = net::Listen(string::from("tcp"), string::from("127.0.0.1:0"));
    let port_a = la.Addr().Port;
    let a2 = srva.clone();
    go!(stack(512 * 1024), move || {
        let _ = a2.Serve(la);
    });
    time::Sleep(time::Millisecond * 80);

    let (jar, _) = cookiejar::New(None);
    let mut c = http::Client::default();
    c.Jar = Some(jar.clone() as Arc<dyn http::CookieJar>);
    c.Timeout = time::Second * 5;
    let base = string::from("http://localhost:") + goish::strconv::Itoa(port_a as i64);

    let mut ln: usize = 0;

    let (req, _) = http::NewRequest("GET", base.clone() + string::from("/set"), goish::nil);
    let (mut resp, err) = c.Do(&req);
    if !err.IsNil() {
        fmt::Printf!("[!!] /set: %v\n", err);
        goish::os::Exit(1);
    }
    let _ = goish::io::Closer::Close(&mut resp.Body);
    let (u, _) = goish::net::url::Parse(base.clone() + string::from("/"));
    let cks = jar.Cookies(&u);
    let has = goish::len(&cks) > 0;
    chk(&mut ln, &fmt::Sprintf!("after-set        jar-has-sid=%v", has));

    let (req, _) = http::NewRequest("GET", base.clone() + string::from("/same"), goish::nil);
    let (mut resp, _) = c.Do(&req);
    let _ = goish::io::Closer::Close(&mut resp.Body);
    let got = seen.Lock().pop().unwrap_or(string::new());
    chk(&mut ln, &fmt::Sprintf!("same-host-hop    cookie=%q", got));

    let (req, _) = http::NewRequest("GET", base + string::from("/cross"), goish::nil);
    let (mut resp, _) = c.Do(&req);
    let _ = goish::io::Closer::Close(&mut resp.Body);
    let got = seen.Lock().pop().unwrap_or(string::new());
    chk(&mut ln, &fmt::Sprintf!("cross-host-hop   cookie=%q", got));

    if ln != GO.len() {
        fmt::Printf!("[!!] produced %d lines, pinned %d\n", ln as int, GO.len() as int);
    }
    goish::os::Exit(0);
}

struct ResponseAdapter<'a>(&'a (dyn http::ResponseWriter + Send + Sync + 'static));
impl goish::io::Writer for ResponseAdapter<'_> {
    fn Write(&mut self, p: goish::goslice::slice<goish::types::byte>) -> (int, goish::errors::error) {
        return http::ResponseWriter::Write(self.0, p);
    }
}
